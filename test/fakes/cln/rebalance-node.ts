// A stateful fake of Core Lightning v26.06.9 (clnrest) for CLN-M of SPEC §4.4 / §5.4 C6 / §9.3, serving every
// call a plan, an execution and a reconciliation make. Each answer uses a behaviour id of fake-cln.ts, which
// names the upstream source it imitates. Node facts relied on here:
// - invoice takes our preimage and answers its SHA-256 as payment_hash (doc/schemas/invoice.json#L9-L178);
// - sendpay answers `pending`; once the HTLC settles, waitsendpay and listsendpays answer `complete` with the
//   preimage, amount_msat = delivered principal, amount_sent_msat = principal + fee (doc/schemas/sendpay.json,
//   waitsendpay.json#L49-L204, listsendpays.json);
// - a settled rebalance moves our local balance on S down by principal + fee and on T up by the principal;
//   spendable and receivable move with it (listpeerchannels.json to_us_msat, spendable_msat, receivable_msat);
// - bookkeeper records the fee paid as fees_msat on the channel event tagged `invoice`, with is_rebalance
//   (doc/schemas/bkpr-listaccountevents.json; plugins/bkpr/account_entry.c, SPEC §9.4);
// - delinvoice ... unpaid fails with 906 for a paid invoice and 905 for an unknown label (doc/schemas/delinvoice.json).
import { createHash, randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { FakeServer, Identity, TlsMaterial } from '../https.js';
import { askrene, type LayerState } from './askrene.js';
import { startFakeCln, type ClnContext, type ClnHandler, type FakeCln } from './fake-cln.js';
import { accountEvent, channelDirection, clnInvoice, CLN_PUBKEY, getinfo, getroutesAnswer, pathHop, peerChannel, sendpay } from './responses.js';
import { syntheticInvoice } from '../../helpers/cp004-invoice.js';

export const SELF = CLN_PUBKEY; // CLN-M
export const LND_R = `02${'71'.repeat(32)}`; // out-peer over channel 2
export const CLN_R = `02${'72'.repeat(32)}`; // in-peer over channel 5
export const S = '102x1x0'; // channel 2, CLN-M <-> LND-R
export const CH3 = '103x1x0'; // channel 3, LND-R <-> CLN-R
export const T = '105x1x0'; // channel 5, CLN-R <-> CLN-M
export const HEIGHT = 812;
export const PRINCIPAL = 100_000_000n;
export const FEE = 202_101n;
export const PAYMENT_SECRET = '9c'.repeat(32);

/** Balances before the rebalance (msat). */
export const BEFORE = {
  [S]: { total: 2_000_000_000n, toUs: 1_880_000_000n, spendable: 1_820_000_000n, receivable: 100_000_000n },
  [T]: { total: 2_500_000_000n, toUs: 400_000_000n, spendable: 350_000_000n, receivable: 2_000_000_000n },
} as const;

/** Commands that settle to our own invoice without hops or create credentials; a rebalance never calls them. */
export const FORBIDDEN = ['xpay', 'pay', 'renepay', 'keysend', 'injectpaymentonion', 'sendonion', 'createrune', 'withdraw'];
/** Calls that move funds or change invoices on the node. */
export const MUTATING = ['invoice', 'sendpay', 'delinvoice', ...FORBIDDEN];

export interface RebalanceState {
  /** Network getinfo reports (FluxWarden must refuse anything but regtest, INV-15). */
  network: string;
  /** Node id getinfo reports. */
  id: string;
  /** What sendpay does: settle the payment, or settle it and drop the connection before any answer byte. */
  sendpay: 'settle' | 'lose-answer';
  /** While true, every call is answered by closing the connection (the node is unreachable). */
  unreachable: boolean;
  /** Fee bookkeeper reports for the settled payment (default the route fee). */
  bkprFeeMsat: bigint;
  readonly layers: LayerState;
  /** payment_hash -> preimage hex of each invoice created. */
  readonly invoices: Map<string, { preimage: string; label: string; status: 'unpaid' | 'paid' | 'deleted'; amount: bigint }>;
  /** Hashes sendpay accepted, in order; a hash here is a payment the node made. */
  readonly sent: string[];
  /** Seconds since the epoch at which the payment settled. */
  settledAt: number | null;
}

export interface RebalanceCln { fake: FakeCln; state: RebalanceState; runeFile: string; rune: string; url: string }

const asBig = (value: bigint): number => Number(value);

function channels(state: RebalanceState): Record<string, unknown>[] {
  const settled = state.settledAt !== null;
  const moved = (scid: typeof S | typeof T): { toUs: bigint; spendable: bigint; receivable: bigint; total: bigint } => {
    const base = BEFORE[scid];
    if (!settled) return base;
    const delta = scid === S ? -(PRINCIPAL + FEE) : PRINCIPAL;
    return { total: base.total, toUs: base.toUs + delta, spendable: base.spendable + delta, receivable: base.receivable - delta };
  };
  const s = moved(S);
  const t = moved(T);
  const updates = (remote: { base: number; ppm: number; delta: number }): Record<string, unknown> => ({
    local: { htlc_minimum_msat: 0, htlc_maximum_msat: 4950000000, cltv_expiry_delta: 6, fee_base_msat: 7, fee_proportional_millionths: 7 },
    remote: { htlc_minimum_msat: 1, htlc_maximum_msat: 4950000000, cltv_expiry_delta: remote.delta, fee_base_msat: remote.base, fee_proportional_millionths: remote.ppm },
  });
  return [
    peerChannel({
      peer_id: LND_R, short_channel_id: S, channel_id: '21'.repeat(32), funding_txid: '2f'.repeat(32), direction: 0,
      total_msat: asBig(s.total), to_us_msat: asBig(s.toUs), max_to_us_msat: asBig(s.toUs), spendable_msat: asBig(s.spendable), receivable_msat: asBig(s.receivable),
      fee_base_msat: 7, fee_proportional_millionths: 7, updates: updates({ base: 3, ppm: 3, delta: 3 }),
    }),
    // CLN-R charges 1,000 msat + 1,000 ppm with CLTV delta 34 for forwarding to us over T (SPEC §4.4).
    peerChannel({
      peer_id: CLN_R, short_channel_id: T, channel_id: '25'.repeat(32), funding_txid: '5f'.repeat(32), direction: 0,
      total_msat: asBig(t.total), to_us_msat: asBig(t.toUs), max_to_us_msat: asBig(t.toUs), spendable_msat: asBig(t.spendable), receivable_msat: asBig(t.receivable),
      fee_base_msat: 7, fee_proportional_millionths: 7, updates: updates({ base: 1000, ppm: 1000, delta: 34 }),
    }),
  ];
}

// listchannels: one entry per direction, policy set by `source` (doc/schemas/listchannels.json). LND-R forwards over
// channel 3 at 1,000 msat + 1,000 ppm with CLTV delta 80; CLN-R over channel 5 at 1,000 + 1,000 ppm, delta 34.
const DIRECTIONS = [
  channelDirection({ scid: S, source: SELF, destination: LND_R, base: 7, ppm: 7, delay: 6 }),
  channelDirection({ scid: S, source: LND_R, destination: SELF, base: 3, ppm: 3, delay: 3 }),
  channelDirection({ scid: CH3, source: LND_R, destination: CLN_R, base: 1000, ppm: 1000, delay: 80 }),
  channelDirection({ scid: CH3, source: CLN_R, destination: LND_R, base: 5, ppm: 5, delay: 6 }),
  channelDirection({ scid: T, source: CLN_R, destination: SELF, base: 1000, ppm: 1000, delay: 34 }),
  channelDirection({ scid: T, source: SELF, destination: CLN_R, base: 7, ppm: 7, delay: 6 }),
];

// getroutes from LND-R to CLN-R under the layer: one part over channel 3 (doc/schemas/getroutes.json#L87-L233).
const ROUTES = getroutesAnswer([{ amount: 100_101_000, finalCltv: 52, path: [
  pathHop({ scidDir: `${CH3}/0`, nodeIn: LND_R, nodeOut: CLN_R, amountIn: 100_202_101, amountOut: 100_101_000, cltvIn: 132, cltvOut: 52 }),
] }]);

const hashParam = (context: ClnContext): string | null => typeof context.params['payment_hash'] === 'string' ? context.params['payment_hash'] : null;

export async function startRebalanceCln(dir: string, open: FakeServer[], over: Partial<Pick<RebalanceState, 'network' | 'id' | 'sendpay' | 'bkprFeeMsat'>> & { identity?: Identity; tls?: TlsMaterial } = {}): Promise<RebalanceCln> {
  const rune = randomBytes(48).toString('base64url');
  const runeFile = join(dir, `${randomBytes(4).toString('hex')}.rune`);
  writeFileSync(runeFile, `${rune}\n`, { mode: 0o600 });
  const layers = askrene();
  const state: RebalanceState = {
    network: over.network ?? 'regtest', id: over.id ?? SELF, sendpay: over.sendpay ?? 'settle', unreachable: false,
    bkprFeeMsat: over.bkprFeeMsat ?? FEE, layers: layers.state, invoices: new Map(), sent: [], settledAt: null,
  };

  const payment = (hash: string): Record<string, unknown> => {
    const invoice = state.invoices.get(hash);
    const complete = state.settledAt !== null && invoice !== undefined;
    return sendpay({
      payment_hash: hash, status: complete ? 'complete' : 'pending', amount_msat: asBig(PRINCIPAL), amount_sent_msat: asBig(PRINCIPAL + FEE),
      destination: SELF, label: invoice?.label ?? 'unknown', created_at: state.settledAt ?? Math.floor(Date.now() / 1000), groupid: 1,
      ...(complete ? { payment_preimage: invoice.preimage, completed_at: state.settledAt } : {}),
    });
  };

  const settle = (hash: string): void => {
    state.sent.push(hash);
    const invoice = state.invoices.get(hash);
    if (invoice !== undefined && invoice.amount === PRINCIPAL) {
      invoice.status = 'paid';
      state.settledAt = Math.floor(Date.now() / 1000);
    }
  };

  const reachable = (handler: ClnHandler): ClnHandler => (context, cln) => {
    if (state.unreachable) { cln.reset(context, 'connection-reset'); return; }
    handler(context, cln);
  };

  const methods: Record<string, ClnHandler> = {
    ...layers.methods,
    getinfo: (c, f) => { f.result(c, 'getinfo', getinfo({ id: state.id, network: state.network, blockheight: HEIGHT, alias: 'cln-m' })); },
    listpeerchannels: (c, f) => {
      const peer = c.params['id'];
      const scid = c.params['short_channel_id'];
      f.result(c, 'listpeerchannels', { channels: channels(state).filter(ch => (peer === undefined || ch['peer_id'] === peer) && (scid === undefined || ch['short_channel_id'] === scid)) });
    },
    listchannels: (c, f) => {
      const scid = c.params['short_channel_id'];
      const source = c.params['source'];
      f.result(c, 'listchannels', { channels: DIRECTIONS.filter(d => (scid === undefined || d['short_channel_id'] === scid) && (source === undefined || d['source'] === source)) });
    },
    getroutes: (c, f) => { f.result(c, 'getroutes', ROUTES); },
    invoice: (c, f) => {
      const preimage = String(c.params['preimage']);
      const hash = createHash('sha256').update(Buffer.from(preimage, 'hex')).digest('hex');
      const amount = BigInt(String(c.params['amount_msat']).replace(/msat$/, ''));
      state.invoices.set(hash, { preimage, label: String(c.params['label']), status: 'unpaid', amount });
      f.result(c, 'invoice', { payment_hash: hash, payment_secret: PAYMENT_SECRET, bolt11: syntheticInvoice(hash), expires_at: Math.floor(Date.now() / 1000) + 3600, created_index: state.invoices.size });
    },
    sendpay: (c, f) => {
      const hash = hashParam(c) ?? '';
      settle(hash);
      if (state.sendpay === 'lose-answer') { state.unreachable = true; f.reset(c, 'connection-reset'); return; }
      f.result(c, 'sendpay', sendpay({ payment_hash: hash, status: 'pending', amount_msat: asBig(PRINCIPAL), amount_sent_msat: asBig(PRINCIPAL + FEE), destination: SELF }));
    },
    waitsendpay: (c, f) => {
      const hash = hashParam(c) ?? '';
      if (!state.sent.includes(hash)) { f.rpcError(c, 'waitsendpay-no-such-payment', 208, `Never attempted payment for '${hash}'`); return; }
      f.result(c, 'waitsendpay-complete', payment(hash));
    },
    listsendpays: (c, f) => {
      const hash = hashParam(c);
      const hashes = hash === null ? state.sent : state.sent.filter(sent => sent === hash);
      f.result(c, 'listsendpays', { payments: hashes.map(payment) });
    },
    listpays: (c, f) => { f.result(c, 'listpays', { pays: [] }); },
    listhtlcs: (c, f) => {
      // Native receiver receipts for the exact transfers this fake actually
      // applied to T, independently of the route supplied by the caller.
      // CLN v26.06.9 listhtlcs.json: completed incoming terminal state and SCID.
      const history = state.sent.filter(hash => state.invoices.get(hash)?.status === 'paid').map((hash, index) => ({
        created_index: index + 1, updated_index: index + 1, short_channel_id: T, id: index,
        expiry: HEIGHT + 18, direction: 'in', amount_msat: asBig(PRINCIPAL), payment_hash: hash,
        state: 'SENT_REMOVE_ACK_REVOCATION',
      }));
      const start = Number(c.params['start'] ?? 0);
      const limit = Number(c.params['limit'] ?? history.length);
      f.result(c, 'listhtlcs', { htlcs: history.filter(row => row.created_index >= start).slice(0, limit) });
    },
    listinvoices: (c, f) => {
      const hash = hashParam(c);
      const label = c.params['label'];
      const rows = [...state.invoices.entries()].filter(([h, inv]) => inv.status !== 'deleted' && (hash === null || h === hash) && (label === undefined || inv.label === label));
      f.result(c, 'listinvoices', { invoices: rows.map(([h, inv]) => clnInvoice({
        payment_hash: h, label: inv.label, status: inv.status, amount_msat: asBig(inv.amount),
        ...(inv.status === 'paid' ? { amount_received_msat: asBig(inv.amount), paid_at: state.settledAt, payment_preimage: inv.preimage } : {}),
      })) });
    },
    delinvoice: (c, f) => {
      const label = String(c.params['label']);
      const entry = [...state.invoices.entries()].find(([, inv]) => inv.label === label && inv.status !== 'deleted');
      if (entry === undefined) { f.rpcError(c, 'delinvoice-not-found', 905, 'Unknown invoice'); return; }
      if (entry[1].status === 'paid') { f.rpcError(c, 'delinvoice-status-mismatch', 906, 'Invoice status is paid not unpaid', { current_status: 'paid', expected_status: 'unpaid' }); return; }
      entry[1].status = 'deleted';
      f.result(c, 'delinvoice', clnInvoice({ payment_hash: entry[0], label, status: 'unpaid' }));
    },
    'bkpr-listaccountevents': (c, f) => {
      const events = state.settledAt === null ? [] : state.sent.filter(hash => state.invoices.get(hash)?.status === 'paid').flatMap(hash => [
        accountEvent({ account: '21'.repeat(32), tag: 'invoice', debit_msat: asBig(PRINCIPAL), credit_msat: 0, fees_msat: Number(state.bkprFeeMsat), payment_id: hash, part_id: 0, timestamp: state.settledAt, is_rebalance: true }),
        accountEvent({ account: '25'.repeat(32), tag: 'invoice', debit_msat: 0, credit_msat: asBig(PRINCIPAL), fees_msat: 0, payment_id: hash, part_id: 0, timestamp: state.settledAt, is_rebalance: true }),
      ]);
      f.result(c, 'bkpr-listaccountevents', { events });
    },
    ...Object.fromEntries(FORBIDDEN.map(name => [name, ((c, f) => { f.rpcError(c, 'xpay-or-pay', -32601, `Unknown command '${name}'`); }) satisfies ClnHandler])),
  };

  const fake = await startFakeCln({
    rune,
    ...(over.identity === undefined ? {} : { identity: over.identity }),
    ...(over.tls === undefined ? {} : { tls: over.tls }),
    methods: Object.fromEntries(Object.entries(methods).map(([name, handler]) => [name, reachable(handler)])),
  });
  open.push(fake);
  return { fake, state, runeFile, rune, url: `https://${fake.host}:${String(fake.port)}` };
}

/** Methods the fake served, in order. */
export const methodsOf = (fake: FakeCln): string[] => fake.calls.map(call => call.method);
/** Parameters of each call of `method`. */
export const callsOf = (fake: FakeCln, method: string): Record<string, unknown>[] => fake.calls.filter(call => call.method === method).map(call => call.params);
