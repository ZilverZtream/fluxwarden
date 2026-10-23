import type { StoredJournal } from '../core/ledger.js';
import { CLEARING_UNASSIGNED, EXPENSE_ROUTING_FEES, RECON_DIFFERENCE } from '../ledger/accounts.js';
import type { Journal, JournalLine } from '../ledger/postings.js';

/**
 * Comparison of the ledger with node accounting (SPEC.md §9.4, §9.5 step 4). Node answers arrive through
 * structural ports that the read adapters satisfy; this module never talks to a node itself.
 */

export type ExecutionStatus =
  | 'CLAIMED' | 'PREFLIGHT' | 'SUBMITTING' | 'IN_FLIGHT' | 'VERIFIED_SUCCESS' | 'VERIFIED_FAILURE' | 'UNKNOWN' | 'CANCELLED';

export interface ReconExecution {
  readonly id: string;
  /** The node name, the `<node>` segment of channel accounts. */
  readonly node: string;
  /** 64 lowercase hex. */
  readonly paymentHash: string;
  readonly status: ExecutionStatus;
}

export interface AccountingPayment {
  readonly paymentHash: string;
  readonly valueMsat: bigint;
  readonly feeMsat: bigint;
  readonly status: string;
  readonly creationTimeNs: bigint;
  readonly paymentIndex: bigint;
}

export interface AccountingPaymentsPage {
  readonly payments: readonly AccountingPayment[];
  readonly lastIndexOffset: bigint;
}

export interface AccountingSendPay {
  readonly id: string;
  readonly paymentHash: string;
  readonly status: string;
  readonly amountMsat: bigint | null;
  readonly amountSentMsat: bigint;
  readonly createdAt: number;
}

export interface AccountingEvent {
  readonly account: string;
  readonly type: string;
  readonly tag: string;
  readonly creditMsat: bigint;
  readonly debitMsat: bigint;
  readonly timestamp: number;
  readonly feesMsat: bigint | null;
  readonly paymentId: string | null;
  readonly partId: number | null;
}

/** Structurally the LND read API method of the same name. */
export interface LndAccountingApi {
  listPayments(request: { indexOffset: bigint; maxPayments: number; includeIncomplete: boolean }): Promise<AccountingPaymentsPage>;
}

/** Structurally the CLN read API methods of the same names. */
export interface ClnAccountingApi {
  listSendPays(filter?: { paymentHash?: string }): Promise<readonly AccountingSendPay[]>;
  listAccountEvents(): Promise<readonly AccountingEvent[]>;
}

export type AccountingSource =
  | { readonly node: string; readonly implementation: 'lnd'; readonly api: LndAccountingApi }
  | { readonly node: string; readonly implementation: 'cln'; readonly api: ClnAccountingApi };

/** Half-open [sinceMs, untilMs), unix milliseconds. */
export interface ReconcileWindow {
  readonly sinceMs: number;
  readonly untilMs: number;
}

export type ComparisonSource = 'listpayments' | 'listsendpays' | 'bkpr';

export interface Comparison {
  readonly executionId: string;
  readonly node: string;
  readonly source: ComparisonSource;
  readonly ledgerPrincipalMsat: bigint;
  /** Null for the bookkeeper, which reports fees only, and when the node has no record. */
  readonly nodePrincipalMsat: bigint | null;
  readonly ledgerFeeMsat: bigint;
  /** Null when the node has no record. */
  readonly nodeFeeMsat: bigint | null;
}

export type DifferenceKind = 'fee' | 'principal' | 'missing-on-node' | 'missing-in-ledger' | 'incomplete';

export interface Difference {
  readonly kind: DifferenceKind;
  readonly node: string;
  readonly executionId: string | null;
  readonly source: ComparisonSource;
  readonly ledgerMsat: bigint | null;
  readonly nodeMsat: bigint | null;
  /** Set for an incomplete read only. */
  readonly reason: string | null;
}

export interface NodeReadStatus {
  readonly node: string;
  readonly status: 'compared' | 'incomplete' | 'unavailable';
  readonly reason: string | null;
  readonly requests: number;
}

export interface AccountingReport {
  readonly nodes: NodeReadStatus[];
  readonly comparisons: Comparison[];
  readonly differences: Difference[];
  /** RECON_DIFFERENCE journals to post. */
  readonly journals: Journal[];
}

/** LND ListPayments page size, and the page bound after which the read is reported incomplete (SPEC.md §9.4). */
export const PAGE_SIZE = 500;
export const MAX_PAGES = 200;

interface NodeRecord {
  /** Null for the bookkeeper. */
  readonly principalMsat: bigint | null;
  readonly feeMsat: bigint;
  /** Whether the record's time lies in the window. */
  readonly inWindow: boolean;
  /** Why the node's figures for this hash cannot be used, or null. */
  readonly unusable: string | null;
}

interface LedgerSide {
  readonly principalMsat: bigint;
  readonly feeMsat: bigint;
  readonly inWindow: boolean;
}

interface SourceRead {
  readonly source: ComparisonSource;
  readonly records: ReadonlyMap<string, NodeRecord>;
  /** Whether a record is a payment success, from which a missing ledger journal is inferred. */
  readonly success: boolean;
}

interface NodeRead {
  readonly status: NodeReadStatus;
  readonly reads: readonly SourceRead[];
  /** The source whose read did not complete. */
  readonly failedSource: ComparisonSource | null;
}

const NS_PER_MS = 1_000_000n;

/** The settle journal of each execution: principal into channels, fee expensed, and whether it falls in the window. */
function ledgerSides(journals: readonly StoredJournal[], window: ReconcileWindow): Map<string, LedgerSide> {
  const sides = new Map<string, LedgerSide>();
  for (const journal of journals) {
    if (journal.eventType !== 'REBALANCE_SETTLED' || journal.executionId === null) continue;
    let principalMsat = 0n;
    let feeMsat = 0n;
    for (const line of journal.lines) {
      if (line.account.startsWith('channel:') || line.account === CLEARING_UNASSIGNED) principalMsat += line.debitMsat;
      else if (line.account === EXPENSE_ROUTING_FEES) feeMsat += line.debitMsat;
    }
    const inWindow = journal.occurredAt >= window.sinceMs && journal.occurredAt < window.untilMs;
    sides.set(journal.executionId, { principalMsat, feeMsat, inWindow });
  }
  for (const journal of journals) {
    if (journal.eventType !== 'RECON_DIFFERENCE' || journal.executionId === null || journal.reference !== `fee-reported:${journal.executionId}`) continue;
    const side = sides.get(journal.executionId);
    if (side !== undefined) {
      const reported = journal.lines.filter(line => line.account === EXPENSE_ROUTING_FEES).reduce((sum, line) => sum + line.debitMsat, 0n);
      sides.set(journal.executionId, { ...side, feeMsat: side.feeMsat + reported });
    }
  }
  return sides;
}

function secondsInWindow(seconds: number, window: ReconcileWindow): boolean {
  const ms = seconds * 1000;
  return ms >= window.sinceMs && ms < window.untilMs;
}

function addRecord(records: Map<string, NodeRecord>, hash: string, record: NodeRecord): void {
  const previous = records.get(hash);
  if (previous === undefined) {
    records.set(hash, record);
    return;
  }
  records.set(hash, {
    principalMsat: previous.principalMsat === null || record.principalMsat === null ? null : previous.principalMsat + record.principalMsat,
    feeMsat: previous.feeMsat + record.feeMsat,
    inWindow: previous.inWindow || record.inWindow,
    unusable: previous.unusable ?? record.unusable,
  });
}

/**
 * ListPayments from index 0 in pages of 500, SUCCEEDED only, each page continuing at the previous page's
 * last_index_offset. A short page ends the read; a full page that does not advance, or the 200th full page,
 * ends it as incomplete (lnd#9410).
 */
async function readLnd(node: string, api: LndAccountingApi, hashes: ReadonlySet<string>, window: ReconcileWindow): Promise<NodeRead> {
  const records = new Map<string, NodeRecord>();
  const seen = new Set<bigint>();
  const sinceNs = BigInt(window.sinceMs) * NS_PER_MS;
  const untilNs = BigInt(window.untilMs) * NS_PER_MS;
  let indexOffset = 0n;
  let requests = 0;
  const finish = (status: 'compared' | 'incomplete', reason: string | null): NodeRead => ({
    status: { node, status, reason, requests },
    reads: [{ source: 'listpayments', records, success: true }],
    failedSource: status === 'compared' ? null : 'listpayments',
  });
  for (;;) {
    let page: AccountingPaymentsPage;
    requests += 1;
    try {
      page = await api.listPayments({ indexOffset, maxPayments: PAGE_SIZE, includeIncomplete: false });
    } catch {
      return { status: { node, status: 'unavailable', reason: 'node-error', requests }, reads: [], failedSource: 'listpayments' };
    }
    for (const payment of page.payments) {
      if (payment.status !== 'SUCCEEDED' || !hashes.has(payment.paymentHash) || seen.has(payment.paymentIndex)) continue;
      seen.add(payment.paymentIndex);
      addRecord(records, payment.paymentHash, {
        principalMsat: payment.valueMsat, feeMsat: payment.feeMsat,
        inWindow: payment.creationTimeNs >= sinceNs && payment.creationTimeNs < untilNs, unusable: null,
      });
    }
    if (page.payments.length < PAGE_SIZE) return finish('compared', null);
    if (page.lastIndexOffset <= indexOffset) return finish('incomplete', 'offset-not-advancing');
    if (requests >= MAX_PAGES) return finish('incomplete', 'page-limit');
    indexOffset = page.lastIndexOffset;
  }
}

/**
 * listsendpays per payment hash (complete parts: delivered amount and amount_sent − amount as the fee), and,
 * when an execution is compared, one bkpr-listaccountevents (channel events tagged invoice: fees_msat).
 */
async function readCln(node: string, api: ClnAccountingApi, hashes: ReadonlySet<string>, bookkeeper: boolean, window: ReconcileWindow): Promise<NodeRead> {
  let requests = 0;
  const sendpays = new Map<string, NodeRecord>();
  try {
    for (const hash of [...hashes].sort()) {
      requests += 1;
      const parts = await api.listSendPays({ paymentHash: hash });
      const seen = new Set<string>();
      for (const part of parts) {
        if (part.status !== 'complete' || part.paymentHash !== hash || seen.has(part.id)) continue;
        seen.add(part.id);
        const inWindow = secondsInWindow(part.createdAt, window);
        // amount_msat is optional ("if known"): without it the fee is unknown, never zero. A part that delivered
        // more than it sent is an impossible answer. Neither is compared or posted.
        if (part.amountMsat === null) addRecord(sendpays, hash, { principalMsat: null, feeMsat: 0n, inWindow, unusable: 'amount-unknown' });
        else if (part.amountMsat > part.amountSentMsat) addRecord(sendpays, hash, { principalMsat: null, feeMsat: 0n, inWindow, unusable: 'amount-exceeds-sent' });
        else addRecord(sendpays, hash, { principalMsat: part.amountMsat, feeMsat: part.amountSentMsat - part.amountMsat, inWindow, unusable: null });
      }
    }
  } catch {
    return { status: { node, status: 'unavailable', reason: 'node-error', requests }, reads: [], failedSource: 'listsendpays' };
  }
  const reads: SourceRead[] = [{ source: 'listsendpays', records: sendpays, success: true }];
  if (bookkeeper) {
    const events = new Map<string, NodeRecord>();
    requests += 1;
    try {
      const seen = new Set<string>();
      for (const event of await api.listAccountEvents()) {
        if (event.type !== 'channel' || event.tag !== 'invoice' || event.paymentId === null || !hashes.has(event.paymentId)) continue;
        // A duplicated bookkeeper event (cln#9487, cln#5557) counts once.
        const key = [event.account, event.paymentId, String(event.partId), event.debitMsat.toString(), event.creditMsat.toString(), String(event.timestamp)].join('|');
        if (seen.has(key)) continue;
        seen.add(key);
        addRecord(events, event.paymentId, { principalMsat: null, feeMsat: event.feesMsat ?? 0n, inWindow: secondsInWindow(event.timestamp, window), unusable: null });
      }
    } catch {
      return { status: { node, status: 'unavailable', reason: 'node-error', requests }, reads, failedSource: 'bkpr' };
    }
    reads.unshift({ source: 'bkpr', records: events, success: false });
  }
  return { status: { node, status: 'compared', reason: null, requests }, reads, failedSource: null };
}

const debit = (account: string, msat: bigint): JournalLine => ({ account, debitMsat: msat, creditMsat: 0n });
const credit = (account: string, msat: bigint): JournalLine => ({ account, debitMsat: 0n, creditMsat: msat });

/** Brings the expensed fee to the node's fee (d = node − ledger) against recon:difference. */
function feeJournal(executionId: string, reference: string, ledgerFeeMsat: bigint, nodeFeeMsat: bigint, occurredAt: number): Journal {
  const d = nodeFeeMsat - ledgerFeeMsat;
  return {
    eventType: 'RECON_DIFFERENCE', reference, executionId, occurredAt,
    lines: d > 0n ? [debit(EXPENSE_ROUTING_FEES, d), credit(RECON_DIFFERENCE, d)] : [debit(RECON_DIFFERENCE, -d), credit(EXPENSE_ROUTING_FEES, -d)],
  };
}

interface FeeCorrections { readonly expensedMsat: bigint; readonly count: number }

/**
 * The fee corrections already posted for an execution: the net amount across sources and how many
 * references belong to the requested source.
 * there are. The first carries the reference `<execution>:fee:<source>`, the n-th `<execution>:fee:<source>:<n>`,
 * so a node answer that changes again is corrected again, and an unchanged answer posts nothing.
 */
function feeCorrections(journals: readonly StoredJournal[], executionId: string, source: ComparisonSource): FeeCorrections {
  const base = `${executionId}:fee:${source}`;
  let expensedMsat = 0n;
  let count = 0;
  for (const journal of journals) {
    if (journal.eventType !== 'RECON_DIFFERENCE' || journal.executionId !== executionId) continue;
    const ownReference = journal.reference === base || (journal.reference.startsWith(`${base}:`) && /^[1-9][0-9]*$/.test(journal.reference.slice(base.length + 1)));
    const feeReference = journal.reference === `fee-attribution-offset:${executionId}` || ['listpayments', 'listsendpays', 'bkpr'].some(name => {
      const prefix = `${executionId}:fee:${name}`;
      return journal.reference === prefix || (journal.reference.startsWith(`${prefix}:`) && /^[1-9][0-9]*$/.test(journal.reference.slice(prefix.length + 1)));
    });
    if (!feeReference) continue;
    if (ownReference) count += 1;
    for (const line of journal.lines) if (line.account === EXPENSE_ROUTING_FEES) expensedMsat += line.debitMsat - line.creditMsat;
  }
  return { expensedMsat, count };
}

const compareText = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

function compareNullable(a: string | null, b: string | null): number {
  if (a === null) return b === null ? 0 : -1;
  return b === null ? 1 : compareText(a, b);
}

export async function reconcileAccounting(input: {
  window: ReconcileWindow; journals: readonly StoredJournal[]; executions: readonly ReconExecution[];
  sources: readonly AccountingSource[]; occurredAt: number;
  /** Absolute fees selected by the same source arbitration as the report; persistence rebases them at commit time. */
  observeFee?: (observation: { executionId: string; reference: string; feeMsat: bigint; occurredAt: number }) => void;
}): Promise<AccountingReport> {
  const sides = ledgerSides(input.journals, input.window);
  const nodes: NodeReadStatus[] = [];
  const comparisons: Comparison[] = [];
  const differences: Difference[] = [];
  const journals: Journal[] = [];
  const corrected = new Set<string>();
  for (const source of input.sources) {
    const executions = input.executions.filter(execution => execution.node === source.node);
    const compared = executions.filter(execution => sides.get(execution.id)?.inWindow === true);
    const hashes = new Set(executions.map(execution => execution.paymentHash));
    const read = source.implementation === 'lnd'
      ? await readLnd(source.node, source.api, hashes, input.window)
      : await readCln(source.node, source.api, hashes, compared.length > 0, input.window);
    nodes.push(read.status);
    if (read.failedSource !== null) {
      differences.push({ kind: 'incomplete', node: source.node, executionId: null, source: read.failedSource, ledgerMsat: null, nodeMsat: null, reason: read.status.reason });
    }
    const expected: readonly ComparisonSource[] = source.implementation === 'lnd' ? ['listpayments'] : ['bkpr', 'listsendpays'];
    for (const execution of compared) {
      const side = sides.get(execution.id);
      if (side === undefined) continue;
      for (const name of expected) {
        const corrections = feeCorrections(input.journals, execution.id, name);
        const expensedMsat = side.feeMsat + corrections.expensedMsat;
        const sourceRead = read.reads.find(item => item.source === name);
        const found = sourceRead?.records.get(execution.paymentHash);
        const record = found?.unusable === null ? found : undefined;
        comparisons.push({
          executionId: execution.id, node: source.node, source: name, ledgerPrincipalMsat: side.principalMsat,
          nodePrincipalMsat: name === 'bkpr' ? null : record?.principalMsat ?? null, ledgerFeeMsat: expensedMsat, nodeFeeMsat: record?.feeMsat ?? null,
        });
        const base = { node: source.node, executionId: execution.id, source: name, reason: null };
        if (found !== undefined && record === undefined) {
          differences.push({ ...base, kind: 'incomplete', ledgerMsat: null, nodeMsat: null, reason: found.unusable });
          continue;
        }
        if (record === undefined) {
          // A record on a page that was never read is not missing.
          if (read.failedSource === null) differences.push({ ...base, kind: 'missing-on-node', ledgerMsat: side.principalMsat, nodeMsat: null });
          continue;
        }
        if (record.principalMsat !== null && record.principalMsat !== side.principalMsat) {
          differences.push({ ...base, kind: 'principal', ledgerMsat: side.principalMsat, nodeMsat: record.principalMsat });
        }
        if (record.feeMsat !== expensedMsat) {
          differences.push({ ...base, kind: 'fee', ledgerMsat: expensedMsat, nodeMsat: record.feeMsat });
        }
        {
          // Accounting sources describe one economic fee. Keep every observation in the report, but use the first
          // differing observation for the adjustment; conflicting sources cannot repeatedly undo each other's fees.
          if (corrected.has(execution.id)) continue;
          if (record.feeMsat === side.feeMsat && corrections.count === 0
            && read.reads.some(other => {
              const observed = other.records.get(execution.paymentHash);
              return observed?.unusable === null && observed.feeMsat !== record.feeMsat;
            })) continue;
          corrected.add(execution.id);
          input.observeFee?.({ executionId: execution.id, reference: `${execution.id}:fee:${name}`, feeMsat: record.feeMsat, occurredAt: input.occurredAt });
          if (record.feeMsat !== expensedMsat) {
            const reference = corrections.count === 0 ? `${execution.id}:fee:${name}` : `${execution.id}:fee:${name}:${String(corrections.count + 1)}`;
            journals.push(feeJournal(execution.id, reference, expensedMsat, record.feeMsat, input.occurredAt));
          }
        }
      }
    }
    for (const execution of executions) {
      if (sides.has(execution.id)) continue;
      for (const sourceRead of read.reads) {
        const record = sourceRead.records.get(execution.paymentHash);
        if (!sourceRead.success || record === undefined || !record.inWindow) continue;
        differences.push({
          kind: 'missing-in-ledger', node: source.node, executionId: execution.id, source: sourceRead.source,
          ledgerMsat: null, nodeMsat: record.principalMsat, reason: null,
        });
      }
    }
  }
  comparisons.sort((a, b) => compareText(a.executionId, b.executionId) || compareText(a.source, b.source) || compareText(a.node, b.node));
  differences.sort((a, b) => compareText(a.node, b.node) || compareNullable(a.executionId, b.executionId)
    || compareText(a.source, b.source) || compareText(a.kind, b.kind));
  return { nodes, comparisons, differences, journals };
}
