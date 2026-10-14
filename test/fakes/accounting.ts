// In-memory accounting sources for the reconciler. Each source answers with exactly what the read
// adapters produce: upstream-shaped JSON (test/fakes/*/responses.ts) passed through the adapters' own
// parsers. Every scripted behaviour names the upstream source it imitates.
import { createHash } from 'node:crypto';
import { loadSource, type ClnAccountEvent, type ClnSendPay, type LndPaymentsPage } from '../helpers/adapter-interfaces.js';
import { accountEvent, sendpay } from './cln/responses.js';
import { payment } from './lnd/responses.js';

const LND = 'https://github.com/lightningnetwork/lnd/blob/v0.21.4-beta/';
const CLN = 'https://github.com/ElementsProject/lightning/blob/v26.06.9/';

export const behaviours = {
  // ListPaymentsRequest: index_offset is exclusive, payments are returned oldest first unless `reversed`,
  // at most max_payments per page; include_incomplete=false returns only SUCCEEDED payments.
  // ListPaymentsResponse: first_index_offset / last_index_offset are the payment_index of the first and last
  // payment of the page, used as the next index_offset.
  'listpayments-page': { source: `${LND}lnrpc/lightning.proto#L4400-L4472; ${LND}rpcserver.go#L6983-L7030` },
  // Payment.value_msat is the amount delivered (sum of the HTLC amounts minus fees), fee_msat the total fee of
  // the settled HTLCs, creation_time_ns the creation time in nanoseconds since the epoch.
  'listpayments-payment': { source: `${LND}lnrpc/lightning.proto#L4293-L4398` },
  // A pagination bug that keeps answering full pages (lnd#9410), or a page whose last_index_offset does not move.
  'listpayments-hostile': { source: 'https://github.com/lightningnetwork/lnd/issues/9410' },
  // listsendpays: one entry per part (partid, groupid); amount_msat is the amount delivered to the destination,
  // amount_sent_msat the amount sent including fees; created_at in seconds; payment_hash filters the list.
  'listsendpays': { source: `${CLN}doc/schemas/listsendpays.json` },
  // bkpr-listaccountevents: a `channel` event tagged `invoice` per payment part, with payment_id = payment hash,
  // part_id, fees_msat (routing fees paid) and is_rebalance; timestamp in seconds.
  'bkpr-listaccountevents': { source: `${CLN}doc/schemas/bkpr-listaccountevents.json; ${CLN}plugins/bkpr/account_entry.c; ${CLN}plugins/bkpr/incomestmt.c` },
} as const satisfies Record<string, { source: string }>;

export interface PageRequest { indexOffset: bigint; maxPayments: number; includeIncomplete: boolean }
export interface LndAccountingApi { listPayments(request: PageRequest): Promise<LndPaymentsPage> }
export interface ClnAccountingApi {
  listSendPays(filter?: { paymentHash?: string }): Promise<ClnSendPay[]>;
  listAccountEvents(): Promise<ClnAccountEvent[]>;
}

interface LndTypes { parsePaymentsPage(body: Record<string, unknown>): LndPaymentsPage }
interface ClnTypes { parseSendPay(body: Record<string, unknown>): ClnSendPay; parseAccountEvent(body: Record<string, unknown>): ClnAccountEvent }

/** A payment hash and the preimage that proves it. */
export function preimagePair(seed: string): { preimage: string; hash: string } {
  const preimage = createHash('sha256').update(`preimage:${seed}`).digest('hex');
  return { preimage, hash: createHash('sha256').update(Buffer.from(preimage, 'hex')).digest('hex') };
}

export interface LndPaymentSpec {
  readonly seed: string; readonly status: 'SUCCEEDED' | 'FAILED' | 'IN_FLIGHT';
  readonly valueMsat: bigint; readonly feeMsat: bigint; readonly creationTimeNs: bigint;
}

/** One upstream Payment JSON (behaviour listpayments-payment). */
export function lndPaymentJson(spec: LndPaymentSpec, index: bigint): Record<string, unknown> {
  const { preimage, hash } = preimagePair(spec.seed);
  const succeeded = spec.status === 'SUCCEEDED';
  return payment({
    payment_hash: hash, payment_preimage: succeeded ? preimage : '0'.repeat(64), status: spec.status,
    value_msat: spec.valueMsat.toString(), value_sat: (spec.valueMsat / 1000n).toString(), value: (spec.valueMsat / 1000n).toString(),
    fee_msat: spec.feeMsat.toString(), fee_sat: (spec.feeMsat / 1000n).toString(), fee: (spec.feeMsat / 1000n).toString(),
    creation_time_ns: spec.creationTimeNs.toString(), creation_date: (spec.creationTimeNs / 1_000_000_000n).toString(),
    payment_index: index.toString(), failure_reason: spec.status === 'FAILED' ? 'FAILURE_REASON_NO_ROUTE' : 'FAILURE_REASON_NONE',
    htlcs: succeeded ? [{ attempt_id: (index * 10n).toString(), status: 'SUCCEEDED' }] : [],
  });
}

/** ListPayments over a fixed payment list, payment_index 1..n in list order (behaviour listpayments-page). */
export async function fakeLndAccounting(payments: readonly LndPaymentSpec[]): Promise<{ api: LndAccountingApi; requests: PageRequest[] }> {
  const types = await loadSource<LndTypes>('node-lnd/types.ts');
  const rows = payments.map((spec, i) => ({ spec, json: lndPaymentJson(spec, BigInt(i + 1)), index: BigInt(i + 1) }));
  const requests: PageRequest[] = [];
  return {
    requests,
    api: {
      listPayments(request) {
        requests.push({ ...request });
        const page = rows
          .filter(row => row.index > request.indexOffset && (request.includeIncomplete || row.spec.status === 'SUCCEEDED'))
          .slice(0, request.maxPayments);
        const first = page[0]?.index ?? 0n;
        const last = page.at(-1)?.index ?? 0n;
        return Promise.resolve(types.parsePaymentsPage({
          payments: page.map(row => row.json), first_index_offset: first.toString(), last_index_offset: last.toString(),
        }));
      },
    },
  };
}

/**
 * ListPayments that never runs out (behaviour listpayments-hostile): every request gets a full page of
 * SUCCEEDED payments for hashes nobody asked about. `advancing` moves last_index_offset by the page size;
 * `stuck` answers last_index_offset equal to the requested index_offset.
 */
export async function endlessLndAccounting(mode: 'advancing' | 'stuck'): Promise<{ api: LndAccountingApi; requests: PageRequest[] }> {
  const types = await loadSource<LndTypes>('node-lnd/types.ts');
  const requests: PageRequest[] = [];
  return {
    requests,
    api: {
      listPayments(request) {
        requests.push({ ...request });
        if (requests.length > 1000) return Promise.reject(new Error('fake: more than 1000 ListPayments requests'));
        const size = BigInt(request.maxPayments);
        const start = request.indexOffset + 1n;
        const payments: Record<string, unknown>[] = [];
        for (let i = 0n; i < size; i++) {
          const index = start + i;
          payments.push(payment({
            payment_hash: createHash('sha256').update(`foreign:${index.toString()}`).digest('hex'), status: 'SUCCEEDED',
            payment_index: index.toString(), value_msat: '1000', fee_msat: '1', creation_time_ns: '1760000000000000000',
          }));
        }
        const last = mode === 'advancing' ? request.indexOffset + size : request.indexOffset;
        return Promise.resolve(types.parsePaymentsPage({ payments, first_index_offset: start.toString(), last_index_offset: last.toString() }));
      },
    },
  };
}

/**
 * ListPayments answering the given pages in order, each payment with an explicit payment_index (behaviour
 * listpayments-hostile: lnd#9410 pagination bugs repeat a payment within or across pages).
 */
export async function scriptedLndPages(pages: readonly (readonly { spec: LndPaymentSpec; index: bigint }[])[]): Promise<{ api: LndAccountingApi; requests: PageRequest[] }> {
  const types = await loadSource<LndTypes>('node-lnd/types.ts');
  const requests: PageRequest[] = [];
  return {
    requests,
    api: {
      listPayments(request) {
        requests.push({ ...request });
        const page = pages[requests.length - 1] ?? [];
        return Promise.resolve(types.parsePaymentsPage({
          payments: page.map(row => lndPaymentJson(row.spec, row.index)),
          first_index_offset: (page[0]?.index ?? 0n).toString(), last_index_offset: (page.at(-1)?.index ?? 0n).toString(),
        }));
      },
    },
  };
}

export interface ClnPartSpec {
  readonly seed: string; readonly partid: number; readonly status: 'pending' | 'complete' | 'failed';
  /** null: amount_msat absent ("if known", listsendpays.json). */
  readonly amountMsat: bigint | null; readonly amountSentMsat: bigint; readonly createdAt: number;
}

export interface ClnEventSpec {
  readonly seed: string; readonly partId: number; readonly feesMsat: bigint | null;
  readonly debitMsat: bigint; readonly creditMsat: bigint; readonly timestamp: number; readonly account: string;
}

/**
 * listsendpays (filtered by payment_hash) and bkpr-listaccountevents over fixed lists. `ignoreFilter` makes
 * listsendpays answer every part whatever payment_hash was asked (a hostile or buggy answer).
 */
export async function fakeClnAccounting(parts: readonly ClnPartSpec[], events: readonly ClnEventSpec[], options: { ignoreFilter?: boolean } = {}): Promise<{ api: ClnAccountingApi; requests: string[] }> {
  const types = await loadSource<ClnTypes>('node-cln/types.ts');
  const requests: string[] = [];
  const sendpays = parts.map((part, i) => {
    const { preimage, hash } = preimagePair(part.seed);
    const body = sendpay({
      created_index: i + 1, id: i + 1, updated_index: i + 1, payment_hash: hash, groupid: 1, partid: part.partid, status: part.status,
      amount_msat: Number(part.amountMsat ?? 0n), amount_sent_msat: Number(part.amountSentMsat), created_at: part.createdAt,
      label: `fluxwarden-${part.seed}`, ...(part.status === 'complete' ? { payment_preimage: preimage, completed_at: part.createdAt + 2 } : {}),
    });
    if (part.amountMsat === null) delete body['amount_msat'];
    return body;
  });
  const ledger = events.map(event => {
    const body = accountEvent({
      account: event.account, payment_id: preimagePair(event.seed).hash, part_id: event.partId,
      debit_msat: Number(event.debitMsat), credit_msat: Number(event.creditMsat), timestamp: event.timestamp,
    });
    if (event.feesMsat === null) delete body['fees_msat'];
    else body['fees_msat'] = Number(event.feesMsat);
    return body;
  });
  return {
    requests,
    api: {
      listSendPays(filter) {
        requests.push(`listsendpays:${filter?.paymentHash ?? '*'}`);
        const rows = sendpays.filter(row => options.ignoreFilter === true || filter?.paymentHash === undefined || row['payment_hash'] === filter.paymentHash);
        return Promise.resolve(rows.map(row => types.parseSendPay(row)));
      },
      listAccountEvents() {
        requests.push('bkpr-listaccountevents');
        return Promise.resolve(ledger.map(row => types.parseAccountEvent(row)));
      },
    },
  };
}
