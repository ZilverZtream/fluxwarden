/*
Interface: src/core/normalize.ts (pure; imports only src/core). Raw node JSON goes in as plain parsed objects.

  export type Confidence = 'NODE_REPORTED' | 'DERIVED_ESTIMATE';
  export type ChannelState = 'ACTIVE' | 'INACTIVE' | 'PENDING' | 'CLOSING' | 'UNKNOWN';
  export interface NormalizeContext {
    readonly nodeId: string;          // FluxWarden node id (ULID)
    readonly observedAt: number;      // unix ms of the observation
    readonly blockHeight: number;     // node block height at the observation
  }
  export type LndPendingKind = 'pending_open' | 'waiting_close' | 'pending_force_closing';
  export interface NormalizedChannel {
    readonly nodeId: string;
    readonly channelKey: string;      // LND: chan_id as a decimal string; CLN: short_channel_id, else channel_id
    readonly scid: string | null;     // "<block>x<tx>x<out>"; LND derives it from chan_id (block = id >> 40,
                                      // tx = (id >> 16) & 0xFFFFFF, out = id & 0xFFFF); null when unknown
    readonly peerPubkey: string;
    readonly fundingOutpoint: string | null; // LND channel_point; CLN `${funding_txid}:${funding_outnum}`; null or ''
                                             // for a CLN channel not yet committed (no funding fields reported)
    readonly state: ChannelState;
    readonly nodeState: string;       // raw state text (CLN state; LND 'active' | 'inactive' | the pending kind)
    readonly opener: 'local' | 'remote';
    readonly capacityMsat: bigint;
    readonly localBalanceMsat: bigint;
    readonly remoteBalanceMsat: bigint;
    readonly spendableMsat: bigint;
    readonly receivableMsat: bigint;
    readonly confidence: Confidence;  // applies to spendable and receivable
    readonly caveat: string | null;   // CLN: the node's own "estimate" wording for both values
    readonly localReserveMsat: bigint;
    readonly remoteReserveMsat: bigint;
    readonly pendingOutMsat: bigint;
    readonly pendingInMsat: bigint;
    readonly pendingHtlcCount: number;
    readonly localMaxPendingAmtMsat: bigint | null;  // uint64, kept exact (LND local_constraints)
    readonly remoteMaxPendingAmtMsat: bigint | null; // uint64, kept exact (LND remote_constraints)
    readonly observedAt: number;
    readonly blockHeight: number;
    readonly provenance: Readonly<Record<string, string>>; // raw input fields used, keyed by dotted path
                                                          // (e.g. 'local_constraints.chan_reserve_sat'), values as decimal text
  }
  export function normalizeLndChannel(raw: unknown, ctx: NormalizeContext): NormalizedChannel;          // ListChannels channels[i]
  export function normalizeLndPendingChannel(kind: LndPendingKind, raw: unknown, ctx: NormalizeContext): NormalizedChannel;
                                                                   // PendingChannels <kind>_channels[i] (the outer object with `channel`)
  export function normalizeClnChannel(raw: unknown, ctx: NormalizeContext): NormalizedChannel;          // listpeerchannels channels[i]

Malformed input (wrong type, negative or out-of-range amount, unsafe JSON number) throws ProtocolError from src/core/errors.ts.

LND arithmetic (SPEC §4.2), all LND amounts in sat × 1000:
  fee buffer (sat) = floor(2 × fee_per_kw × (commit_weight + 172) / 1000)
    lnd v0.21.4-beta lnwallet/channel.go CalcFeeBuffer: (2 × feePerKw).FeeForWeight(commitWeight + input.HTLCWeight);
    lnwallet/chainfee/rates.go FeeForWeight rounds down (feePerKw × wu / 1000);
    input/size.go HTLCWeight = 4 × HTLCSize = 4 × (8 + 1 + P2WSHSize 34) = 172.
  anchor reserve (sat) = 660 (2 × 330) for anchor commitment types (ANCHORS, SCRIPT_ENFORCED_LEASE, SIMPLE_TAPROOT,
    SIMPLE_TAPROOT_OVERLAY, TAPROOT alias SIMPLE_TAPROOT_FINAL), else 0 (LEGACY, STATIC_REMOTE_KEY).
  spendable  = max(0, local_balance  − local_constraints.chan_reserve_sat  − (initiator  ? buffer + anchors : 0))
  receivable = max(0, remote_balance − remote_constraints.chan_reserve_sat − (!initiator ? buffer + anchors : 0))
  Opener check for the side that did not open (lnd lnwallet/channel.go availableCommitmentBalance 9321-9375): if
    opener balance − opener reserve < floor(fee_per_kw × 172 / 1000) sat, that side's figure is
    min(figure, (own dust_limit_sat + timeout fee) × 1000 − 1, (other dust_limit_sat + success fee) × 1000 − 1) msat,
    where "own" is the side's own commitment (spendable: local_constraints; receivable: remote_constraints), the fees
    are 0 for anchor types and floor(fee_per_kw × 663 / 1000), floor(fee_per_kw × 703 / 1000) sat otherwise.
  Reserves are required: a channel with neither *_constraints.chan_reserve_sat nor the deprecated field is malformed.
  Pending HTLCs are not subtracted: local_balance already excludes outgoing in-flight HTLCs. Field names: lnd v0.21.4-beta lnrpc/lightning.proto Channel, ChannelConstraints, HTLC.
CLN (v26.06 doc/schemas/listpeerchannels.json): spendable_msat and receivable_msat as reported, refused (ProtocolError)
  when to_us_msat > total_msat, spendable_msat > to_us_msat or receivable_msat > total_msat − to_us_msat. Entries of an
  uncommitted channel (OPENINGD, DUALOPEND_OPEN_INIT) carry no channel_id or funding fields and may lack amounts: they
  normalize as PENDING with zero spendable and receivable, missing amounts read as 0, and a key unique per peer.
*/
import { describe, expect, it } from 'vitest';
import { loadCore } from '../helpers/cp004-reference.js';

type ChannelState = 'ACTIVE' | 'INACTIVE' | 'PENDING' | 'CLOSING' | 'UNKNOWN';
interface NormalizeContext { readonly nodeId: string; readonly observedAt: number; readonly blockHeight: number }
interface NormalizedChannel {
  readonly nodeId: string; readonly channelKey: string; readonly scid: string | null; readonly peerPubkey: string;
  readonly fundingOutpoint: string | null; readonly state: ChannelState; readonly nodeState: string; readonly opener: 'local' | 'remote';
  readonly capacityMsat: bigint; readonly localBalanceMsat: bigint; readonly remoteBalanceMsat: bigint;
  readonly spendableMsat: bigint; readonly receivableMsat: bigint; readonly confidence: 'NODE_REPORTED' | 'DERIVED_ESTIMATE';
  readonly caveat: string | null; readonly localReserveMsat: bigint; readonly remoteReserveMsat: bigint;
  readonly pendingOutMsat: bigint; readonly pendingInMsat: bigint; readonly pendingHtlcCount: number;
  readonly localMaxPendingAmtMsat: bigint | null; readonly remoteMaxPendingAmtMsat: bigint | null;
  readonly observedAt: number; readonly blockHeight: number; readonly provenance: Readonly<Record<string, string>>;
}
interface Normalize {
  normalizeLndChannel(raw: unknown, ctx: NormalizeContext): NormalizedChannel;
  normalizeLndPendingChannel(kind: 'pending_open' | 'waiting_close' | 'pending_force_closing', raw: unknown, ctx: NormalizeContext): NormalizedChannel;
  normalizeClnChannel(raw: unknown, ctx: NormalizeContext): NormalizedChannel;
}

const load = (): Promise<Normalize> => loadCore<Normalize>('normalize');
const ctx: NormalizeContext = { nodeId: '01JZ8Q5W3K6Y2N4R7T9V1X3Z5B', observedAt: 1_760_000_123_456, blockHeight: 1_234 };
const PEER = `02${'ab'.repeat(32)}`;
const TXID = 'c3'.repeat(32);
const UINT64_MAX_TEXT = '18446744073709551615';

function protocolError(run: () => unknown, what: string): void {
  let caught: unknown;
  try { run(); } catch (error) { caught = error; }
  expect(caught, what).toBeInstanceOf(Error);
  expect((caught as Error).name, what).toBe('ProtocolError');
}

// LND REST (protojson, proto field names, int64/uint64 as strings, defaults emitted). Shapes follow
// lnd v0.21.4-beta lnrpc/lightning.proto Channel; the values are constructed for these tests.
interface LndOptions {
  initiator: boolean; commitmentType: string; local: string; remote: string; feePerKw: string; commitWeight: string;
  localReserve: string; remoteReserve: string; active?: boolean; htlcs?: { incoming: boolean; amount: string }[];
  deprecatedReserves?: boolean; chanId?: string; localDust?: string; remoteDust?: string;
}
function lndChannel(o: LndOptions): Record<string, unknown> {
  const constraints = (reserve: string, dust: string): Record<string, unknown> => ({
    csv_delay: 144, chan_reserve_sat: reserve, dust_limit_sat: dust, max_pending_amt_msat: '990000000', min_htlc_msat: '1', max_accepted_htlcs: 483,
  });
  return {
    active: o.active ?? true, remote_pubkey: PEER, channel_point: `${TXID}:0`, chan_id: o.chanId ?? '123145302376448',
    capacity: '1000000', local_balance: o.local, remote_balance: o.remote, commit_fee: '2810', commit_weight: o.commitWeight,
    fee_per_kw: o.feePerKw, unsettled_balance: String((o.htlcs ?? []).reduce((sum, h) => sum + Number(h.amount), 0)),
    total_satoshis_sent: '0', total_satoshis_received: '0', num_updates: '12',
    pending_htlcs: (o.htlcs ?? []).map((h, i) => ({
      incoming: h.incoming, amount: h.amount, hash_lock: 'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=', expiration_height: 1400,
      htlc_index: String(i), forwarding_channel: '0', forwarding_htlc_index: '0', locked_in: true,
    })),
    csv_delay: 144, private: false, initiator: o.initiator, chan_status_flags: 'ChanStatusDefault',
    local_chan_reserve_sat: o.deprecatedReserves === false ? '0' : o.localReserve,
    remote_chan_reserve_sat: o.deprecatedReserves === false ? '0' : o.remoteReserve,
    static_remote_key: false, commitment_type: o.commitmentType, lifetime: '100', uptime: '100', close_address: '',
    push_amount_sat: '0', thaw_height: 0, local_constraints: constraints(o.localReserve, o.localDust ?? '354'), remote_constraints: constraints(o.remoteReserve, o.remoteDust ?? '354'),
    alias_scids: [], zero_conf: false, zero_conf_confirmed_scid: '0', peer_alias: '', peer_scid_alias: '0', memo: '', custom_channel_data: '',
  };
}

// Channel A: we opened an anchors channel, with one outgoing and one incoming HTLC pending.
const channelA = lndChannel({
  initiator: true, commitmentType: 'ANCHORS', local: '600000', remote: '396530', feePerKw: '2501', commitWeight: '1124',
  localReserve: '10000', remoteReserve: '10000', htlcs: [{ incoming: false, amount: '50000' }, { incoming: true, amount: '20000' }],
});
// Channel B: the same figures from the peer's side; the peer opened.
const channelB = lndChannel({
  initiator: false, commitmentType: 'ANCHORS', local: '300000', remote: '686530', feePerKw: '2501', commitWeight: '1124',
  localReserve: '10000', remoteReserve: '10000',
});

describe('LND derived spendable and receivable', () => {
  it('CP-014/B1 initiator pays the fee buffer and anchors from spendable; pending HTLCs are not subtracted again', async () => {
    const n = (await load()).normalizeLndChannel(channelA, ctx);
    // buffer = floor(2 × 2501 × (1124 + 172) / 1000) = floor(6,482,592 / 1000) = 6,482 sat (a round-up gives 6,483)
    // spendable = 600,000 − 10,000 (local_constraints) − 6,482 − 660 = 582,858 sat = 582,858,000 msat
    expect(n.spendableMsat).toBe(582_858_000n);
    // receivable: we are the initiator, so the peer pays no buffer: 396,530 − 10,000 = 386,530 sat
    expect(n.receivableMsat).toBe(386_530_000n);
    expect(n.confidence).toBe('DERIVED_ESTIMATE');
    expect(n.opener).toBe('local');
    expect(n.localBalanceMsat).toBe(600_000_000n);
    expect(n.remoteBalanceMsat).toBe(396_530_000n);
    expect(n.capacityMsat).toBe(1_000_000_000n);
    expect(n.localReserveMsat).toBe(10_000_000n);
    expect(n.remoteReserveMsat).toBe(10_000_000n);
    // pending_htlcs: amount is sat; incoming=false is outgoing
    expect(n.pendingOutMsat).toBe(50_000_000n);
    expect(n.pendingInMsat).toBe(20_000_000n);
    expect(n.pendingHtlcCount).toBe(2);
  });

  it('CP-014/B1 non-initiator spendable carries no fee buffer while receivable carries the peer\'s buffer and anchors', async () => {
    const n = (await load()).normalizeLndChannel(channelB, ctx);
    // spendable = 300,000 − 10,000 = 290,000 sat (the peer opened, so we pay no commitment fee)
    expect(n.spendableMsat).toBe(290_000_000n);
    // receivable = 686,530 − 10,000 − 6,482 − 660 = 669,388 sat
    expect(n.receivableMsat).toBe(669_388_000n);
    expect(n.opener).toBe('remote');
    expect(n.confidence).toBe('DERIVED_ESTIMATE');
  });

  it('CP-014/B1 a non-anchor initiator channel deducts the fee buffer without the anchor reserve', async () => {
    const raw = lndChannel({
      initiator: true, commitmentType: 'STATIC_REMOTE_KEY', local: '500000', remote: '499000', feePerKw: '253', commitWeight: '724',
      localReserve: '5000', remoteReserve: '5000',
    });
    const n = (await load()).normalizeLndChannel(raw, ctx);
    // buffer = floor(2 × 253 × (724 + 172) / 1000) = floor(453,376 / 1000) = 453 sat; no anchors
    // spendable = 500,000 − 5,000 − 453 = 494,547 sat
    expect(n.spendableMsat).toBe(494_547_000n);
    // receivable = 499,000 − 5,000 = 494,000 sat
    expect(n.receivableMsat).toBe(494_000_000n);
  });

  it('CP-014/B1 the lease commitment type builds on anchors and deducts the anchor reserve', async () => {
    const raw = lndChannel({
      initiator: true, commitmentType: 'SCRIPT_ENFORCED_LEASE', local: '500000', remote: '499000', feePerKw: '253', commitWeight: '1124',
      localReserve: '5000', remoteReserve: '5000',
    });
    // buffer = floor(2 × 253 × 1296 / 1000) = floor(655.776) = 655; spendable = 500,000 − 5,000 − 655 − 660 = 493,685 sat
    expect((await load()).normalizeLndChannel(raw, ctx).spendableMsat).toBe(493_685_000n);
  });

  it('CP-014/B1 reserves come from local_constraints and remote_constraints, not the deprecated fields', async () => {
    const raw = lndChannel({
      initiator: false, commitmentType: 'STATIC_REMOTE_KEY', local: '300000', remote: '600000', feePerKw: '253', commitWeight: '724',
      localReserve: '12345', remoteReserve: '23456', deprecatedReserves: false,
    });
    const n = (await load()).normalizeLndChannel(raw, ctx);
    // spendable = 300,000 − 12,345 = 287,655 sat (deprecated local_chan_reserve_sat reads 0 here)
    expect(n.spendableMsat).toBe(287_655_000n);
    expect(n.localReserveMsat).toBe(12_345_000n);
    // receivable = 600,000 − 23,456 − floor(2 × 253 × 896 / 1000) = 600,000 − 23,456 − 453 = 576,091 sat
    expect(n.receivableMsat).toBe(576_091_000n);
    expect(n.remoteReserveMsat).toBe(23_456_000n);
  });

  it('CP-014/B1 boundary: spendable is zero at reserve + buffer + anchors and one sat above it', async () => {
    const normalize = await load();
    // fee_per_kw 1000, commit_weight 1124: buffer = floor(2 × 1000 × 1296 / 1000) = 2,592 sat
    // threshold = 10,000 + 2,592 + 660 = 13,252 sat
    const at = (local: string): bigint => normalize.normalizeLndChannel(lndChannel({
      initiator: true, commitmentType: 'ANCHORS', local, remote: '900000', feePerKw: '1000', commitWeight: '1124',
      localReserve: '10000', remoteReserve: '10000',
    }), ctx).spendableMsat;
    expect(at('13251')).toBe(0n);
    expect(at('13252')).toBe(0n);
    expect(at('13253')).toBe(1_000n);
    expect(at('0')).toBe(0n);
  });

  it('CP-014/B1 receivable is clamped to zero when the remote balance is below its reserve', async () => {
    const n = (await load()).normalizeLndChannel(lndChannel({
      initiator: true, commitmentType: 'ANCHORS', local: '980000', remote: '9999', feePerKw: '253', commitWeight: '1124',
      localReserve: '10000', remoteReserve: '10000',
    }), ctx);
    expect(n.receivableMsat).toBe(0n);
    expect(n.remoteBalanceMsat).toBe(9_999_000n);
  });

  it('CP-014/B1 wrong types and negative amounts are protocol errors', async () => {
    const normalize = await load();
    protocolError(() => normalize.normalizeLndChannel({ ...channelA, local_balance: true }, ctx), 'boolean local_balance');
    protocolError(() => normalize.normalizeLndChannel({ ...channelA, local_balance: '-1' }, ctx), 'negative local_balance');
    protocolError(() => normalize.normalizeLndChannel({ ...channelA, local_constraints: 'x' }, ctx), 'constraints not an object');
    protocolError(() => normalize.normalizeLndChannel(null, ctx), 'null channel');
  });
});

describe('CLN reported spendable and receivable', () => {
  // listpeerchannels entry shaped after the CLN v26.06 doc/schemas/listpeerchannels.json example (clnrest sends msat as numbers).
  const cln = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
    peer_id: PEER, peer_connected: true, reestablished: true,
    channel_type: { bits: [12, 22], names: ['static_remotekey/even', 'anchors/even'] },
    updates: {
      local: { htlc_minimum_msat: 0, htlc_maximum_msat: 990000000, cltv_expiry_delta: 6, fee_base_msat: 1, fee_proportional_millionths: 10 },
      remote: { htlc_minimum_msat: 0, htlc_maximum_msat: 990000000, cltv_expiry_delta: 6, fee_base_msat: 1, fee_proportional_millionths: 10 },
    },
    state: 'CHANNELD_NORMAL', feerate: { perkw: 3755, perkb: 15020 }, owner: 'channeld', short_channel_id: '109x1x1', direction: 1,
    channel_id: 'd1'.repeat(32), funding_txid: TXID, funding_outnum: 1, private: false, opener: 'local',
    features: ['option_static_remotekey', 'option_anchors'],
    funding: { local_funds_msat: 1000000000, remote_funds_msat: 0, pushed_msat: 0 },
    to_us_msat: 390492790, min_to_us_msat: 390492790, max_to_us_msat: 1000000000, total_msat: 1000000000,
    fee_base_msat: 1, fee_proportional_millionths: 10, dust_limit_msat: 546000,
    their_reserve_msat: 10000000, our_reserve_msat: 10000000, spendable_msat: 363951708, receivable_msat: 599507210,
    minimum_htlc_in_msat: 0, minimum_htlc_out_msat: 0, maximum_htlc_out_msat: 990000000, their_to_self_delay: 5, our_to_self_delay: 5,
    max_accepted_htlcs: 483, status: ['CHANNELD_NORMAL:Channel ready for use.'],
    htlcs: [
      { direction: 'out', id: 17, amount_msat: 4000082, expiry: 181, payment_hash: 'aa'.repeat(32), state: 'SENT_ADD_ACK_REVOCATION' },
      { direction: 'in', id: 3, amount_msat: 1000000, expiry: 190, payment_hash: 'bb'.repeat(32), state: 'RCVD_ADD_ACK_REVOCATION' },
    ],
    ...over,
  });

  it('CP-014/B2 spendable_msat and receivable_msat pass through exactly, tagged NODE_REPORTED with the node\'s caveat', async () => {
    const n = (await load()).normalizeClnChannel(cln(), ctx);
    expect(n.spendableMsat).toBe(363_951_708n);
    expect(n.receivableMsat).toBe(599_507_210n);
    expect(n.confidence).toBe('NODE_REPORTED');
    // Wording quoted from CLN v26.06 doc/schemas/listpeerchannels.json.
    expect(n.caveat).toContain('can be wrong because adding HTLCs requires an increase in fees paid to onchain miners');
    expect(n.caveat).toContain('An estimate of the total peer could send through channel.');
    expect(n.localBalanceMsat).toBe(390_492_790n);
    // remote = total_msat − to_us_msat = 1,000,000,000 − 390,492,790 = 609,507,210
    expect(n.remoteBalanceMsat).toBe(609_507_210n);
    expect(n.capacityMsat).toBe(1_000_000_000n);
    expect(n.localReserveMsat).toBe(10_000_000n);
    expect(n.remoteReserveMsat).toBe(10_000_000n);
    expect(n.opener).toBe('local');
    // htlcs[] summed by direction; spendable already accounts for them on the node side and is not reduced again
    expect(n.pendingOutMsat).toBe(4_000_082n);
    expect(n.pendingInMsat).toBe(1_000_000n);
    expect(n.pendingHtlcCount).toBe(2);
  });

  it('CP-014/B2 msat-suffixed amount strings read the same as numbers', async () => {
    const n = (await load()).normalizeClnChannel(cln({ spendable_msat: '363951708msat', receivable_msat: '599507210msat', to_us_msat: '390492790msat' }), ctx);
    expect(n.spendableMsat).toBe(363_951_708n);
    expect(n.receivableMsat).toBe(599_507_210n);
    expect(n.localBalanceMsat).toBe(390_492_790n);
  });

  it('CP-014/B2 a channel without short_channel_id is keyed by channel_id with no scid', async () => {
    const raw = cln({ state: 'CHANNELD_AWAITING_LOCKIN' });
    delete raw['short_channel_id'];
    const n = (await load()).normalizeClnChannel(raw, ctx);
    expect(n.scid).toBeNull();
    expect(n.channelKey).toBe('d1'.repeat(32));
  });

  it('CP-014/B2 malformed CLN amounts are protocol errors', async () => {
    const normalize = await load();
    protocolError(() => normalize.normalizeClnChannel(cln({ spendable_msat: -1 }), ctx), 'negative spendable');
    protocolError(() => normalize.normalizeClnChannel(cln({ spendable_msat: 1.5 }), ctx), 'fractional spendable');
    protocolError(() => normalize.normalizeClnChannel(cln({ receivable_msat: 2 ** 64 }), ctx), 'unsafe number');
    protocolError(() => normalize.normalizeClnChannel(cln({ opener: 'nobody' }), ctx), 'unknown opener');
  });

  describe('CLN state mapping', () => {
    // lightningd/channel.h (v26.06): channel_state_can_add_htlc = {CHANNELD_NORMAL, CHANNELD_AWAITING_SPLICE};
    // channel_state_pre_open = {CHANNELD_AWAITING_LOCKIN, DUALOPEND_*}; channel_state_closing = {CHANNELD_SHUTTING_DOWN,
    // CLOSINGD_SIGEXCHANGE, CLOSINGD_COMPLETE, AWAITING_UNILATERAL, FUNDING_SPEND_SEEN, ONCHAIN}; OPENINGD is an
    // uncommitted channel still being negotiated. Every value of the schema's state enum is pinned.
    const table: [string, ChannelState][] = [
      ['OPENINGD', 'PENDING'],
      ['CHANNELD_AWAITING_LOCKIN', 'PENDING'],
      ['CHANNELD_NORMAL', 'ACTIVE'],
      ['CHANNELD_SHUTTING_DOWN', 'CLOSING'],
      ['CLOSINGD_SIGEXCHANGE', 'CLOSING'],
      ['CLOSINGD_COMPLETE', 'CLOSING'],
      ['AWAITING_UNILATERAL', 'CLOSING'],
      ['FUNDING_SPEND_SEEN', 'CLOSING'],
      ['ONCHAIN', 'CLOSING'],
      ['DUALOPEND_OPEN_INIT', 'PENDING'],
      ['DUALOPEND_AWAITING_LOCKIN', 'PENDING'],
      ['CHANNELD_AWAITING_SPLICE', 'ACTIVE'],
      ['DUALOPEND_OPEN_COMMITTED', 'PENDING'],
      ['DUALOPEND_OPEN_COMMIT_READY', 'PENDING'],
    ];
    it.each(table)('CP-014/B4 CLN state %s maps to %s with the raw text kept', async (raw, expected) => {
      const n = (await load()).normalizeClnChannel(cln({ state: raw }), ctx);
      expect(n.state).toBe(expected);
      expect(n.nodeState).toBe(raw);
    });

    it('CP-014/B4 a usable CLN channel whose peer is disconnected is INACTIVE', async () => {
      const normalize = await load();
      expect(normalize.normalizeClnChannel(cln({ peer_connected: false }), ctx).state).toBe('INACTIVE');
      expect(normalize.normalizeClnChannel(cln({ state: 'CHANNELD_AWAITING_SPLICE', peer_connected: false }), ctx).state).toBe('INACTIVE');
      expect(normalize.normalizeClnChannel(cln({ state: 'ONCHAIN', peer_connected: false }), ctx).state).toBe('CLOSING');
    });

    it('CP-014/B4 an unknown CLN state maps to UNKNOWN instead of failing or passing as usable', async () => {
      const n = (await load()).normalizeClnChannel(cln({ state: 'CHANNELD_FUTURE_STATE' }), ctx);
      expect(n.state).toBe('UNKNOWN');
      expect(n.nodeState).toBe('CHANNELD_FUTURE_STATE');
    });
  });
});

describe('LND state mapping', () => {
  // ListChannels lists open channels with `active`; PendingChannels lists pending_open, waiting_close and
  // pending_force_closing channels (lnd v0.21.4-beta lnrpc/lightning.proto PendingChannelsResponse).
  const pendingInner = (initiator: string): Record<string, unknown> => ({
    remote_node_pub: PEER, channel_point: `${TXID}:2`, capacity: '500000', local_balance: '496530', remote_balance: '0',
    local_chan_reserve_sat: '5000', remote_chan_reserve_sat: '5000', initiator, commitment_type: 'ANCHORS',
    num_forwarding_packages: '0', chan_status_flags: '', private: false, memo: '', custom_channel_data: '',
  });

  it('CP-014/B4 open LND channels map active to ACTIVE and inactive to INACTIVE', async () => {
    const normalize = await load();
    const active = normalize.normalizeLndChannel(channelA, ctx);
    expect(active.state).toBe('ACTIVE');
    expect(active.nodeState).toBe('active');
    const inactive = normalize.normalizeLndChannel({ ...channelA, active: false }, ctx);
    expect(inactive.state).toBe('INACTIVE');
    expect(inactive.nodeState).toBe('inactive');
  });

  it('CP-014/B4 pending LND channels map to PENDING or CLOSING and offer no liquidity', async () => {
    const normalize = await load();
    const open = normalize.normalizeLndPendingChannel('pending_open', {
      channel: pendingInner('INITIATOR_LOCAL'), commit_fee: '2810', commit_weight: '1124', fee_per_kw: '2500',
      funding_expiry_blocks: 2010, confirmations_until_active: 3, confirmation_height: 0,
    }, ctx);
    expect(open.state).toBe('PENDING');
    expect(open.opener).toBe('local');
    expect(open.fundingOutpoint).toBe(`${TXID}:2`);
    expect(open.scid).toBeNull();
    expect(open.localBalanceMsat).toBe(496_530_000n);
    expect(open.spendableMsat).toBe(0n);
    expect(open.receivableMsat).toBe(0n);
    const waiting = normalize.normalizeLndPendingChannel('waiting_close', {
      channel: pendingInner('INITIATOR_REMOTE'), limbo_balance: '496530', commitments: {}, closing_txid: 'ee'.repeat(32),
      closing_tx_hex: '', blocks_til_close_confirmed: 0, close_height: 0,
    }, ctx);
    expect(waiting.state).toBe('CLOSING');
    expect(waiting.opener).toBe('remote');
    expect(waiting.spendableMsat).toBe(0n);
    const forced = normalize.normalizeLndPendingChannel('pending_force_closing', {
      channel: pendingInner('INITIATOR_LOCAL'), closing_txid: 'ef'.repeat(32), limbo_balance: '496530', maturity_height: 1500,
      blocks_til_maturity: 144, recovered_balance: '0', pending_htlcs: [], anchor: 'LIMBO',
    }, ctx);
    expect(forced.state).toBe('CLOSING');
    expect(forced.receivableMsat).toBe(0n);
  });

  it('CP-014/B1 a pending LND channel without its reserve fields is a protocol error, not a zero reserve', async () => {
    const normalize = await load();
    // PendingChannelsResponse.PendingChannel carries local_chan_reserve_sat and remote_chan_reserve_sat (tags 6, 7);
    // REST emits them even when zero, so a missing one is a malformed answer (SPEC §5.6).
    for (const key of ['local_chan_reserve_sat', 'remote_chan_reserve_sat']) {
      const inner = Object.fromEntries(Object.entries(pendingInner('INITIATOR_LOCAL')).filter(([name]) => name !== key));
      protocolError(() => normalize.normalizeLndPendingChannel('pending_open', {
        channel: inner, commit_fee: '2810', commit_weight: '1124', fee_per_kw: '2500',
        funding_expiry_blocks: 2010, confirmations_until_active: 3, confirmation_height: 0,
      }, ctx), `pending channel without ${key}`);
    }
  });
});

describe('uint64 limits, identity and observation fields', () => {
  it('CP-014/B3 max_pending_amt_msat = 2^64 − 1 round-trips exactly and never reads as −1', async () => {
    const raw = lndChannel({
      initiator: true, commitmentType: 'ANCHORS', local: '600000', remote: '396530', feePerKw: '2501', commitWeight: '1124',
      localReserve: '10000', remoteReserve: '10000',
    });
    const local = raw['local_constraints'] as Record<string, unknown>;
    const remote = raw['remote_constraints'] as Record<string, unknown>;
    local['max_pending_amt_msat'] = UINT64_MAX_TEXT;
    remote['max_pending_amt_msat'] = UINT64_MAX_TEXT;
    const n = (await load()).normalizeLndChannel(raw, ctx);
    expect(n.localMaxPendingAmtMsat).toBe(18_446_744_073_709_551_615n);
    expect(n.remoteMaxPendingAmtMsat).toBe(18_446_744_073_709_551_615n);
    expect(n.provenance['local_constraints.max_pending_amt_msat']).toBe(UINT64_MAX_TEXT);
    expect(JSON.stringify(n.provenance)).not.toContain('"-1"');
    // the sentinel does not disturb the money figures (same as channel A: 582,858 sat)
    expect(n.spendableMsat).toBe(582_858_000n);
  });

  it('CP-014/B3 uint64 values beyond 2^64 − 1, negative, or as unsafe JSON numbers are protocol errors', async () => {
    const normalize = await load();
    const withLimit = (value: unknown): Record<string, unknown> => {
      const raw = lndChannel({
        initiator: true, commitmentType: 'ANCHORS', local: '600000', remote: '396530', feePerKw: '2501', commitWeight: '1124',
        localReserve: '10000', remoteReserve: '10000',
      });
      (raw['local_constraints'] as Record<string, unknown>)['max_pending_amt_msat'] = value;
      return raw;
    };
    protocolError(() => normalize.normalizeLndChannel(withLimit('18446744073709551616'), ctx), '2^64');
    protocolError(() => normalize.normalizeLndChannel(withLimit('-1'), ctx), '-1');
    protocolError(() => normalize.normalizeLndChannel(withLimit(Number(UINT64_MAX_TEXT)), ctx), 'unsafe number');
  });

  it('CP-014/B5 LND identity: chan_id is the decimal key, scid is derived, outpoint is channel_point, observation copied', async () => {
    const n = (await load()).normalizeLndChannel(channelA, ctx);
    // 123145302376448 = 112 × 2^40 + 1 × 2^16 + 0 → block 112, tx 1, output 0
    expect(n.channelKey).toBe('123145302376448');
    expect(n.scid).toBe('112x1x0');
    expect(n.fundingOutpoint).toBe(`${TXID}:0`);
    expect(n.peerPubkey).toBe(PEER);
    expect(n.nodeId).toBe(ctx.nodeId);
    expect(n.observedAt).toBe(1_760_000_123_456);
    expect(n.blockHeight).toBe(1_234);
  });

  it('CP-014/B5 an LND alias chan_id above 2^63 stays an exact unsigned key', async () => {
    // 16000000x0x1 = 16,000,000 × 2^40 + 1 = 17,592,186,044,416,000,001 > 2^63 = 9,223,372,036,854,775,808
    const n = (await load()).normalizeLndChannel({ ...channelA, chan_id: '17592186044416000001' }, ctx);
    expect(n.channelKey).toBe('17592186044416000001');
    expect(n.scid).toBe('16000000x0x1');
  });

  // lnd v0.21.4-beta rpcserver.go createRPCOpenChannel: ChanId is the channel's ShortChannelID, which for a zero-conf
  // channel is its alias; ZeroConf = IsZeroConf(), ZeroConfConfirmedScid = ZeroConfRealScid() (0 until confirmed).
  // The planner needs the real SCID (SPEC §4.6), so an alias is never decoded into a block/tx/output scid.
  it('CP-014/B5 a zero-conf channel takes its scid from zero_conf_confirmed_scid, and has none until it confirms', async () => {
    const normalize = await load();
    const alias = '17592186044416000001'; // 16000000x0x1, an lnd alias SCID
    const unconfirmed = normalize.normalizeLndChannel({ ...channelA, chan_id: alias, zero_conf: true, zero_conf_confirmed_scid: '0' }, ctx);
    expect(unconfirmed.scid).toBeNull();
    expect(unconfirmed.channelKey).toBe(alias);
    // confirmed at 112x1x0 = 123,145,302,376,448
    const confirmed = normalize.normalizeLndChannel({ ...channelA, chan_id: alias, zero_conf: true, zero_conf_confirmed_scid: '123145302376448' }, ctx);
    expect(confirmed.scid).toBe('112x1x0');
    expect(confirmed.channelKey).toBe(alias);
  });

  it('CP-014/B5 CLN identity: short_channel_id key, funding_txid:funding_outnum outpoint, observation copied', async () => {
    const raw = {
      peer_id: PEER, peer_connected: true, state: 'CHANNELD_NORMAL', short_channel_id: '109x1x1', channel_id: 'd1'.repeat(32),
      funding_txid: TXID, funding_outnum: 1, opener: 'remote', features: [], to_us_msat: 1000, total_msat: 1000000,
      our_reserve_msat: 0, their_reserve_msat: 0, spendable_msat: 0, receivable_msat: 0, htlcs: [],
    };
    const n = (await load()).normalizeClnChannel(raw, { ...ctx, blockHeight: 777 });
    expect(n.channelKey).toBe('109x1x1');
    expect(n.scid).toBe('109x1x1');
    expect(n.fundingOutpoint).toBe(`${TXID}:1`);
    expect(n.opener).toBe('remote');
    expect(n.blockHeight).toBe(777);
    expect(n.observedAt).toBe(ctx.observedAt);
    expect(n.pendingHtlcCount).toBe(0);
  });
});

describe('arithmetic properties', () => {
  // Deterministic LCG (Numerical Recipes constants) so failures reproduce.
  function lcg(seed: number): () => number {
    let state = seed >>> 0;
    return () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state; };
  }

  // Independent model of lnd v0.21.4-beta lnwallet/channel.go availableBalance (9210-9241: the minimum over the local
  // and remote commitment views) and availableCommitmentBalance (9250-9378) for the side that did not open the
  // channel, from ListChannels fields, in msat. computeView (4851-4862) adds the stored commitment fee back to the
  // opener's balance, so "opener balance + fee − opener reserve < fee(commit weight) + fee(172 wu)" reduces to
  // "opener balance − opener reserve < floor(fee_per_kw × 172 / 1000)". When it holds, each view caps the other side
  // at dust_limit + HTLC fee − 1 msat; the HTLC fee is 0 for anchor and taproot types (lnwallet/commitment.go
  // HtlcTimeoutFee / HtlcSuccessFee) and floor(fee_per_kw × 663 / 1000) (timeout) or × 703 (success) otherwise
  // (input/size.go HtlcTimeoutWeight 663, HtlcSuccessWeight 703).
  function lndNonOpenerAvailable(o: {
    balance: bigint; reserve: bigint; openerBalance: bigint; openerReserve: bigint; feePerKw: bigint; anchored: boolean;
    ownDust: bigint; otherDust: bigint;
  }): bigint {
    const ours = o.balance > o.reserve ? (o.balance - o.reserve) * 1000n : 0n;
    if (!(o.openerBalance - o.openerReserve < (o.feePerKw * 172n) / 1000n)) return ours;
    const timeoutFee = o.anchored ? 0n : (o.feePerKw * 663n) / 1000n;
    const successFee = o.anchored ? 0n : (o.feePerKw * 703n) / 1000n;
    const ownView = (o.ownDust + timeoutFee) * 1000n - 1n;
    const otherView = (o.otherDust + successFee) * 1000n - 1n;
    return [ours, ownView, otherView].reduce((a, b) => (a < b ? a : b));
  }

  it('CP-014/B6 spendable and receivable stay within the balances and never exceed what lnd itself would allow, over 2,000 random channels', async () => {
    const normalize = await load();
    const next = lcg(20261013);
    const types = ['ANCHORS', 'STATIC_REMOTE_KEY', 'SCRIPT_ENFORCED_LEASE', 'LEGACY', 'SIMPLE_TAPROOT', 'TAPROOT'];
    for (let i = 0; i < 2000; i += 1) {
      const capacity = 20_000 + (next() % 16_000_000);
      const local = next() % (capacity + 1);
      const remote = capacity - local;
      const commitmentType = types[next() % types.length] ?? 'ANCHORS';
      const raw = lndChannel({
        initiator: next() % 2 === 0, commitmentType,
        local: String(local), remote: String(remote), feePerKw: String(253 + (next() % 50_000)), commitWeight: String(724 + (next() % 30_000)),
        localReserve: String(next() % (Math.floor(capacity / 50) + 1)), remoteReserve: String(next() % (Math.floor(capacity / 50) + 1)),
        localDust: String(354 + (next() % 300)), remoteDust: String(354 + (next() % 300)),
      });
      const n = normalize.normalizeLndChannel(raw, ctx);
      const label = JSON.stringify({ i, local, remote, initiator: raw['initiator'], commitmentType });
      expect(n.spendableMsat >= 0n, label).toBe(true);
      expect(n.receivableMsat >= 0n, label).toBe(true);
      expect(n.spendableMsat <= BigInt(local) * 1000n, label).toBe(true);
      expect(n.receivableMsat <= BigInt(remote) * 1000n, label).toBe(true);
      const lc = raw['local_constraints'] as Record<string, string>;
      const rc = raw['remote_constraints'] as Record<string, string>;
      const common = { feePerKw: BigInt(raw['fee_per_kw'] as string), anchored: !['STATIC_REMOTE_KEY', 'LEGACY'].includes(commitmentType) };
      if (raw['initiator'] === true) {
        // the peer's view of its own channel: our receivable is its spendable
        expect(n.receivableMsat, label).toBe(lndNonOpenerAvailable({
          ...common, balance: BigInt(remote), reserve: BigInt(rc['chan_reserve_sat'] ?? ''), openerBalance: BigInt(local),
          openerReserve: BigInt(lc['chan_reserve_sat'] ?? ''), ownDust: BigInt(rc['dust_limit_sat'] ?? ''), otherDust: BigInt(lc['dust_limit_sat'] ?? ''),
        }));
      } else {
        expect(n.spendableMsat, label).toBe(lndNonOpenerAvailable({
          ...common, balance: BigInt(local), reserve: BigInt(lc['chan_reserve_sat'] ?? ''), openerBalance: BigInt(remote),
          openerReserve: BigInt(rc['chan_reserve_sat'] ?? ''), ownDust: BigInt(lc['dust_limit_sat'] ?? ''), otherDust: BigInt(rc['dust_limit_sat'] ?? ''),
        }));
      }
    }
  });

  it('CP-014/B6 raising the reserve or the fee rate never raises spendable', async () => {
    const normalize = await load();
    const spend = (reserve: number, feePerKw: number): bigint => normalize.normalizeLndChannel(lndChannel({
      initiator: true, commitmentType: 'ANCHORS', local: '400000', remote: '590000', feePerKw: String(feePerKw), commitWeight: '1124',
      localReserve: String(reserve), remoteReserve: '10000',
    }), ctx).spendableMsat;
    let previous = spend(0, 253);
    for (const reserve of [1, 9_999, 10_000, 10_001, 390_000]) {
      const value = spend(reserve, 253);
      expect(value <= previous).toBe(true);
      previous = value;
    }
    expect(spend(10_000, 1_000) > spend(10_000, 50_000)).toBe(true);
  });
});

describe('LND non-opener remote check', () => {
  // lnd v0.21.4-beta lnwallet/channel.go availableCommitmentBalance 9321-9375: when we did not open the channel and the
  // opener cannot pay the commitment fee for one more HTLC above its reserve, lnd reports our balance as just below
  // the smallest non-dust HTLC (dust_limit + HTLC fee − 1 msat), and availableBalance (9226-9240) takes the smaller of
  // the local-commitment view (local_constraints.dust_limit_sat, HTLC-timeout fee) and the remote-commitment view
  // (remote_constraints.dust_limit_sat, HTLC-success fee). computeView (4851-4862) adds the opener's stored commitment
  // fee back first, so the trigger is: opener balance − opener reserve < floor(fee_per_kw × 172 / 1000) sat.
  const peerOpened = (over: Partial<LndOptions>): Record<string, unknown> => lndChannel({
    initiator: false, commitmentType: 'ANCHORS', local: '970000', remote: '10200', feePerKw: '2500', commitWeight: '1124',
    localReserve: '10000', remoteReserve: '10000', localDust: '573', remoteDust: '354', ...over,
  });

  it('CP-014/B1 non-initiator spendable is capped below the smaller non-dust HTLC when the opener cannot pay one more HTLC fee', async () => {
    const n = (await load()).normalizeLndChannel(peerOpened({}), ctx);
    // fee(172 wu) = floor(2,500 × 172 / 1000) = 430 sat; opener: 10,200 − 10,000 = 200 < 430 → capped.
    // anchors: HTLC fees 0; local view 573 × 1000 − 1 = 572,999; remote view 354 × 1000 − 1 = 353,999 → 353,999 msat
    // (without the cap: 970,000 − 10,000 = 960,000 sat)
    expect(n.spendableMsat).toBe(353_999n);
    expect(n.confidence).toBe('DERIVED_ESTIMATE');
  });

  it('CP-014/B1 boundary: the cap applies at 429 sat above the opener reserve and not at 430', async () => {
    const normalize = await load();
    expect(normalize.normalizeLndChannel(peerOpened({ remote: '10430' }), ctx).spendableMsat).toBe(960_000_000n);
    expect(normalize.normalizeLndChannel(peerOpened({ remote: '10429' }), ctx).spendableMsat).toBe(353_999n);
  });

  it('CP-014/B1 the non-anchor cap adds the HTLC-timeout and HTLC-success fees per view', async () => {
    const n = (await load()).normalizeLndChannel(peerOpened({
      commitmentType: 'STATIC_REMOTE_KEY', feePerKw: '253', commitWeight: '724', local: '500000', localReserve: '5000',
      remote: '5040', remoteReserve: '5000', localDust: '400', remoteDust: '354',
    }), ctx);
    // fee(172) = floor(253 × 172 / 1000) = floor(43.516) = 43; opener 5,040 − 5,000 = 40 < 43 → capped.
    // timeout fee floor(253 × 663 / 1000) = 167; success fee floor(253 × 703 / 1000) = 177.
    // local view (400 + 167) × 1000 − 1 = 566,999; remote view (354 + 177) × 1000 − 1 = 530,999 → 530,999 msat
    expect(n.spendableMsat).toBe(530_999n);
  });

  it('CP-014/B1 a balance already below the cap is kept', async () => {
    const n = (await load()).normalizeLndChannel(peerOpened({ local: '10300' }), ctx);
    // 10,300 − 10,000 = 300 sat = 300,000 msat < 353,999 (lnd keeps ourBalance when it is below the non-dust amount)
    expect(n.spendableMsat).toBe(300_000n);
  });

  it('CP-014/B1 receivable mirrors the check when we opened and cannot pay one more HTLC fee', async () => {
    const normalize = await load();
    const weOpened = (local: string): Record<string, unknown> => lndChannel({
      initiator: true, commitmentType: 'ANCHORS', local, remote: '960000', feePerKw: '2500', commitWeight: '1124',
      localReserve: '10000', remoteReserve: '10000', localDust: '573', remoteDust: '354',
    });
    // our 10,200 − 10,000 = 200 < 430 → the peer's spendable toward us is capped: its own view uses its dust limit
    // (remote_constraints 354), its view of our commitment uses ours (573): min(353,999, 572,999) = 353,999 msat
    expect(normalize.normalizeLndChannel(weOpened('10200'), ctx).receivableMsat).toBe(353_999n);
    // 10,430 − 10,000 = 430, not below 430: receivable = 960,000 − 10,000 = 950,000 sat
    expect(normalize.normalizeLndChannel(weOpened('10430'), ctx).receivableMsat).toBe(950_000_000n);
  });
});

describe('LND commitment types and integer bounds', () => {
  // lnd v0.21.4-beta lnwallet/reservation.go CommitmentType.HasAnchors (88-100): anchors for ANCHORS,
  // SCRIPT_ENFORCED_LEASE and every taproot type. lnrpc/lightning.proto CommitmentType declares TAPROOT = 7 first and
  // SIMPLE_TAPROOT_FINAL = 7 as its alias, so REST JSON names a production taproot channel TAPROOT.
  it.each(['SIMPLE_TAPROOT', 'SIMPLE_TAPROOT_OVERLAY', 'TAPROOT', 'SIMPLE_TAPROOT_FINAL'])('CP-014/B1 %s channels deduct the anchor reserve', async type => {
    const n = (await load()).normalizeLndChannel(lndChannel({
      initiator: true, commitmentType: type, local: '500000', remote: '499000', feePerKw: '253', commitWeight: '1124',
      localReserve: '5000', remoteReserve: '5000',
    }), ctx);
    // buffer floor(2 × 253 × 1296 / 1000) = 655; spendable = 500,000 − 5,000 − 655 − 660 = 493,685 sat
    expect(n.spendableMsat).toBe(493_685_000n);
  });

  it('CP-014/B3 a sat amount converts to msat only while the product stays within 2^63 − 1', async () => {
    const normalize = await load();
    // floor((2^63 − 1) / 1000) = 9,223,372,036,854,775 sat → 9,223,372,036,854,775,000 msat fits; one sat more does not
    const huge = (sat: string): Record<string, unknown> => ({
      ...lndChannel({
        initiator: false, commitmentType: 'ANCHORS', local: sat, remote: '0', feePerKw: '253', commitWeight: '1124',
        localReserve: '0', remoteReserve: '0',
      }),
      capacity: '9223372036854775',
    });
    expect(normalize.normalizeLndChannel(huge('9223372036854775'), ctx).localBalanceMsat).toBe(9_223_372_036_854_775_000n);
    protocolError(() => normalize.normalizeLndChannel(huge('9223372036854776'), ctx), 'local_balance × 1000 > 2^63 − 1');
  });

  it('CP-014/B3 pending HTLC totals are bounded per direction', async () => {
    const normalize = await load();
    // two incoming HTLCs of 5,000,000,000,000,000 sat: each 5 × 10^18 msat fits, the sum 10^19 msat > 2^63 − 1
    const raw = lndChannel({
      initiator: true, commitmentType: 'ANCHORS', local: '600000', remote: '396530', feePerKw: '2501', commitWeight: '1124',
      localReserve: '10000', remoteReserve: '10000',
      htlcs: [{ incoming: true, amount: '5000000000000000' }, { incoming: true, amount: '5000000000000000' }],
    });
    protocolError(() => normalize.normalizeLndChannel(raw, ctx), 'incoming total overflow');
  });

  it('CP-014/B5 the scid transaction index uses all 24 bits', async () => {
    // 700000x70000x1 = 700,000 × 2^40 + 70,000 × 2^16 + 1 = 769,658,144,030,720,001 (index above 2^16)
    const n = (await load()).normalizeLndChannel({ ...channelA, chan_id: '769658144030720001' }, ctx);
    expect(n.scid).toBe('700000x70000x1');
  });

  it('CP-014/B1 a channel without its reserve fields is a protocol error, not a zero reserve', async () => {
    const normalize = await load();
    const noLocal: Record<string, unknown> = { ...channelA };
    delete noLocal['local_constraints'];
    delete noLocal['local_chan_reserve_sat'];
    protocolError(() => normalize.normalizeLndChannel(noLocal, ctx), 'no local reserve field');
    const noRemoteReserve: Record<string, unknown> = {
      ...channelA, remote_constraints: { csv_delay: 144, dust_limit_sat: '354', max_pending_amt_msat: '990000000', min_htlc_msat: '1', max_accepted_htlcs: 483 },
    };
    delete noRemoteReserve['remote_chan_reserve_sat'];
    protocolError(() => normalize.normalizeLndChannel(noRemoteReserve, ctx), 'constraints without chan_reserve_sat');
  });
});

describe('CLN bounds and uncommitted channels', () => {
  const base = {
    peer_id: PEER, peer_connected: true, state: 'CHANNELD_NORMAL', short_channel_id: '109x1x1', channel_id: 'd1'.repeat(32),
    funding_txid: TXID, funding_outnum: 1, opener: 'local', features: [], to_us_msat: 390492790, total_msat: 1000000000,
    our_reserve_msat: 10000000, their_reserve_msat: 10000000, spendable_msat: 363951708, receivable_msat: 599507210, htlcs: [],
  };

  it('CP-014/B6 CLN to_us_msat may equal total_msat but not exceed it', async () => {
    const normalize = await load();
    expect(normalize.normalizeClnChannel({ ...base, to_us_msat: 1000000000, spendable_msat: 0, receivable_msat: 0 }, ctx).remoteBalanceMsat).toBe(0n);
    protocolError(() => normalize.normalizeClnChannel({ ...base, to_us_msat: 1000000001, spendable_msat: 0, receivable_msat: 0 }, ctx), 'to_us = total + 1');
  });

  it('CP-014/B6 CLN spendable above to_us_msat or receivable above total_msat − to_us_msat is refused', async () => {
    const normalize = await load();
    expect(normalize.normalizeClnChannel({ ...base, spendable_msat: 390492790 }, ctx).spendableMsat).toBe(390_492_790n);
    protocolError(() => normalize.normalizeClnChannel({ ...base, spendable_msat: 390492791 }, ctx), 'spendable = to_us + 1');
    // remote = 1,000,000,000 − 390,492,790 = 609,507,210
    expect(normalize.normalizeClnChannel({ ...base, receivable_msat: 609507210 }, ctx).receivableMsat).toBe(609_507_210n);
    protocolError(() => normalize.normalizeClnChannel({ ...base, receivable_msat: 609507211 }, ctx), 'receivable = remote + 1');
  });

  // CLN v26.06.9 lightningd/opening_control.c json_add_uncommitted_channel (31-75): an OPENINGD entry has only
  // peer_id, peer_connected, channel_type, state, owner, opener "local", status, to_us_msat, total_msat and features.
  // lightningd/dual_open_control.c json_add_unsaved_channel (107-167): a DUALOPEND_OPEN_INIT entry has peer_id,
  // peer_connected, channel_type, state, owner, opener, lost_state, status and features, plus to_us_msat and
  // total_msat only when we are the initiator. doc/schemas/listpeerchannels.json requires only state, opener,
  // features, peer_connected and peer_id.
  const channelType = { bits: [12, 22], names: ['static_remotekey/even', 'anchors/even'] };

  it('CP-014/B4 an OPENINGD entry without channel_id or funding fields is a PENDING channel with no liquidity', async () => {
    const n = (await load()).normalizeClnChannel({
      peer_id: PEER, peer_connected: true, channel_type: channelType, state: 'OPENINGD', owner: 'lightning_openingd', opener: 'local',
      status: ['Funding channel'], to_us_msat: 1000000000, total_msat: 1000000000, features: ['option_static_remotekey', 'option_anchors'],
    }, ctx);
    expect(n.state).toBe('PENDING');
    expect(n.nodeState).toBe('OPENINGD');
    expect(n.opener).toBe('local');
    expect(n.scid).toBeNull();
    expect(n.fundingOutpoint ?? '').toBe('');
    expect(n.channelKey.length).toBeGreaterThan(0);
    expect(n.capacityMsat).toBe(1_000_000_000n);
    expect(n.localBalanceMsat).toBe(1_000_000_000n);
    expect(n.remoteBalanceMsat).toBe(0n);
    expect(n.spendableMsat).toBe(0n);
    expect(n.receivableMsat).toBe(0n);
    expect(n.pendingHtlcCount).toBe(0);
  });

  it('CP-014/B4 a DUALOPEND_OPEN_INIT entry opened by the peer, without amounts, is a PENDING channel with zero figures', async () => {
    const normalize = await load();
    const other = `03${'ef'.repeat(32)}`;
    const entry = (peer: string): Record<string, unknown> => ({
      peer_id: peer, peer_connected: true, channel_type: channelType, state: 'DUALOPEND_OPEN_INIT', owner: 'lightning_dualopend',
      opener: 'remote', lost_state: false, status: [], features: ['option_static_remotekey', 'option_anchors'],
    });
    const n = normalize.normalizeClnChannel(entry(PEER), ctx);
    expect(n.state).toBe('PENDING');
    expect(n.opener).toBe('remote');
    expect(n.scid).toBeNull();
    expect(n.fundingOutpoint ?? '').toBe('');
    expect(n.capacityMsat).toBe(0n);
    expect(n.localBalanceMsat).toBe(0n);
    expect(n.spendableMsat).toBe(0n);
    expect(n.receivableMsat).toBe(0n);
    // two uncommitted channels with different peers never share a key
    expect(normalize.normalizeClnChannel(entry(other), ctx).channelKey).not.toBe(n.channelKey);
  });
});

describe('LND non-opener arithmetic at its edges', () => {
  // Same lnd v0.21.4-beta sources as the non-opener remote check above (channel.go 9226-9375, commitment.go
  // HtlcTimeoutFee / HtlcSuccessFee, input/size.go weights 172, 663, 703; FeeForWeight floors to whole sat).
  it('CP-014/B1 the extra-HTLC fee is floored to whole sat before the opener comparison', async () => {
    const normalize = await load();
    const raw = (remote: string): Record<string, unknown> => lndChannel({
      initiator: false, commitmentType: 'ANCHORS', local: '970000', remote, feePerKw: '2501', commitWeight: '1124',
      localReserve: '10000', remoteReserve: '10000', localDust: '573', remoteDust: '354',
    });
    // fee(172) = floor(2,501 × 172 / 1000) = floor(430.172) = 430 sat = 430,000 msat (not 430,172 msat).
    // opener 10,430 − 10,000 = 430 sat, not below 430 → uncapped 960,000 sat; 10,429 → capped at 353,999 msat.
    expect(normalize.normalizeLndChannel(raw('10430'), ctx).spendableMsat).toBe(960_000_000n);
    expect(normalize.normalizeLndChannel(raw('10429'), ctx).spendableMsat).toBe(353_999n);
  });

  it('CP-014/B1 the own-commitment view uses the HTLC-timeout weight 663 when it binds', async () => {
    const n = (await load()).normalizeLndChannel(lndChannel({
      initiator: false, commitmentType: 'STATIC_REMOTE_KEY', feePerKw: '253', commitWeight: '724', local: '500000', localReserve: '5000',
      remote: '5040', remoteReserve: '5000', localDust: '354', remoteDust: '400',
    }), ctx);
    // opener 40 < 43 → capped. local view (354 + floor(253 × 663 / 1000) = 167) = 521 → 520,999;
    // remote view (400 + floor(253 × 703 / 1000) = 177) = 577 → 576,999 → 520,999 msat (with 703 for both: 530,999)
    expect(n.spendableMsat).toBe(520_999n);
  });

  it('CP-014/B1 the receivable cap takes the peer\'s own commitment from remote_constraints and ours from local_constraints', async () => {
    const n = (await load()).normalizeLndChannel(lndChannel({
      initiator: true, commitmentType: 'STATIC_REMOTE_KEY', feePerKw: '253', commitWeight: '724', local: '5040', localReserve: '5000',
      remote: '500000', remoteReserve: '5000', localDust: '400', remoteDust: '354',
    }), ctx);
    // we opened and 5,040 − 5,000 = 40 < 43 → the peer's figure is capped:
    // its own commitment (remote_constraints dust 354 + timeout fee 167) = 521 → 520,999;
    // our commitment (local_constraints dust 400 + success fee 177) = 577 → 576,999 → receivable 520,999 msat
    // (sides swapped: min(400 + 167, 354 + 177) = 531 → 530,999)
    expect(n.receivableMsat).toBe(520_999n);
  });

  it('CP-014/B1 a cap below zero is clamped to zero, never −1 msat', async () => {
    const raw = lndChannel({
      initiator: false, commitmentType: 'ANCHORS', local: '970000', remote: '10200', feePerKw: '2500', commitWeight: '1124',
      localReserve: '10000', remoteReserve: '10000',
    });
    // Only the deprecated reserve fields: no dust limit is known, so the dust term reads 0 and 0 + 0 − 1 msat would be −1.
    delete raw['local_constraints'];
    delete raw['remote_constraints'];
    const n = (await load()).normalizeLndChannel(raw, ctx);
    expect(n.spendableMsat).toBe(0n);
  });
});

describe('CLN entries without a channel_id', () => {
  it('CP-014/B4 an uncommitted entry with to_us_msat above total_msat is a protocol error', async () => {
    const normalize = await load();
    const entry = (toUs: number): Record<string, unknown> => ({
      peer_id: PEER, peer_connected: true, state: 'OPENINGD', owner: 'lightning_openingd', opener: 'local',
      to_us_msat: toUs, total_msat: 1000000000, features: [],
    });
    expect(normalize.normalizeClnChannel(entry(1000000000), ctx).localBalanceMsat).toBe(1_000_000_000n);
    protocolError(() => normalize.normalizeClnChannel(entry(1000000001), ctx), 'uncommitted to_us = total + 1');
  });

  // CLN v26.06.9 lightningd/peer_control.c json_add_peerchannels (2978-2989): only the uncommitted channel (OPENINGD)
  // and channels in channel_state_uncommitted() (lightningd/channel.h: DUALOPEND_OPEN_INIT alone) are listed without
  // channel_id; every other state goes through json_add_channel, which always reports it.
  const withoutChannelId = (state: string): Record<string, unknown> => ({
    peer_id: PEER, peer_connected: true, state, opener: 'local', to_us_msat: 0, total_msat: 1000000, features: [],
  });

  it('CP-014/B4 an open or closing state without channel_id is a protocol error, not an uncommitted channel', async () => {
    const normalize = await load();
    for (const state of ['CHANNELD_NORMAL', 'CHANNELD_SHUTTING_DOWN', 'ONCHAIN']) {
      protocolError(() => normalize.normalizeClnChannel(withoutChannelId(state), ctx), `${state} without channel_id`);
    }
  });

  it('CP-014/B4 a committed pending state without channel_id is a protocol error too', async () => {
    const normalize = await load();
    for (const state of ['CHANNELD_AWAITING_LOCKIN', 'DUALOPEND_OPEN_COMMITTED', 'DUALOPEND_OPEN_COMMIT_READY', 'DUALOPEND_AWAITING_LOCKIN']) {
      protocolError(() => normalize.normalizeClnChannel(withoutChannelId(state), ctx), `${state} without channel_id`);
    }
  });
});
