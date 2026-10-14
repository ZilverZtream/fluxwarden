import { ProtocolError } from './errors.js';
import { array, asObject, boolean, enumName, identifier, integer, optionalObject, smallInteger, string, type JsonObject } from './json.js';
import { MAX_INT64, MSAT_PER_SAT } from './money.js';
import { chanIdToScid } from './scid.js';

/** Whether a liquidity figure was reported by the node or derived by FluxWarden from other fields. */
export type Confidence = 'NODE_REPORTED' | 'DERIVED_ESTIMATE';
export type ChannelState = 'ACTIVE' | 'INACTIVE' | 'PENDING' | 'CLOSING' | 'UNKNOWN';
export type LndPendingKind = 'pending_open' | 'waiting_close' | 'pending_force_closing';

export interface NormalizeContext {
  readonly nodeId: string;
  /** Unix milliseconds of the observation. */
  readonly observedAt: number;
  /** The node's block height at the observation. */
  readonly blockHeight: number;
}

export interface NormalizedChannel {
  readonly nodeId: string;
  /** LND: `chan_id` as decimal text (the funding outpoint while pending); CLN: `short_channel_id`, else `channel_id`, else `uncommitted:<peer_id>`. */
  readonly channelKey: string;
  /** `<block>x<tx>x<output>`, or null when the channel has none yet. */
  readonly scid: string | null;
  readonly peerPubkey: string;
  /** LND `channel_point`; CLN `funding_txid:funding_outnum`; '' while CLN has not committed to a funding transaction. */
  readonly fundingOutpoint: string;
  readonly state: ChannelState;
  /** The node's own state text. */
  readonly nodeState: string;
  readonly opener: 'local' | 'remote';
  readonly capacityMsat: bigint;
  readonly localBalanceMsat: bigint;
  readonly remoteBalanceMsat: bigint;
  readonly spendableMsat: bigint;
  readonly receivableMsat: bigint;
  /** Applies to spendableMsat and receivableMsat. */
  readonly confidence: Confidence;
  readonly caveat: string | null;
  readonly localReserveMsat: bigint;
  readonly remoteReserveMsat: bigint;
  readonly pendingOutMsat: bigint;
  readonly pendingInMsat: bigint;
  readonly pendingHtlcCount: number;
  /** uint64, kept exact: LND reports 2^64 - 1 for "no limit". */
  readonly localMaxPendingAmtMsat: bigint | null;
  readonly remoteMaxPendingAmtMsat: bigint | null;
  readonly observedAt: number;
  readonly blockHeight: number;
  /** The raw input fields used, keyed by dotted path, values as decimal or plain text. */
  readonly provenance: Readonly<Record<string, string>>;
}

/** Quoted from CLN v26.06 doc/schemas/listpeerchannels.json (spendable_msat, receivable_msat). */
export const CLN_ESTIMATE_CAVEAT =
  'spendable_msat: An estimate of the total we could send through channel (can be wrong because adding HTLCs requires an increase in fees paid to onchain miners, and onchain fees change dynamically according to onchain activity). ' +
  'receivable_msat: An estimate of the total peer could send through channel.';

/** lnd v0.21.4-beta input/size.go: HTLCWeight = 4 × HTLCSize = 4 × (8 + 1 + P2WSHSize 34) = 172. */
const LND_HTLC_WEIGHT = 172n;
/** Two anchor outputs of 330 sat each, paid by the opener (lnd lnwallet/channel.go, anchorSize). */
const LND_ANCHOR_RESERVE_SAT = 660n;

/** lnrpc/lightning.proto CommitmentType, in proto order. */
const LND_COMMITMENT_TYPES = [
  'UNKNOWN_COMMITMENT_TYPE', 'LEGACY', 'STATIC_REMOTE_KEY', 'ANCHORS', 'SCRIPT_ENFORCED_LEASE', 'SIMPLE_TAPROOT', 'SIMPLE_TAPROOT_OVERLAY', 'TAPROOT',
] as const;
/** Commitment types without anchor outputs. Unknown types are treated as anchored, which never overstates spendable. */
const LND_UNANCHORED = new Set(['LEGACY', 'STATIC_REMOTE_KEY']);

/** lnrpc/lightning.proto Initiator, in proto order. */
const LND_INITIATORS = ['INITIATOR_UNKNOWN', 'INITIATOR_LOCAL', 'INITIATOR_REMOTE', 'INITIATOR_BOTH'] as const;

/** CLN v26.06 lightningd/channel.h state groups; every value of the listpeerchannels state enum. */
const CLN_STATES: ReadonlyMap<string, ChannelState> = new Map<string, ChannelState>([
  ['OPENINGD', 'PENDING'],
  ['CHANNELD_AWAITING_LOCKIN', 'PENDING'],
  ['DUALOPEND_OPEN_INIT', 'PENDING'],
  ['DUALOPEND_OPEN_COMMITTED', 'PENDING'],
  ['DUALOPEND_OPEN_COMMIT_READY', 'PENDING'],
  ['DUALOPEND_AWAITING_LOCKIN', 'PENDING'],
  ['CHANNELD_NORMAL', 'ACTIVE'],
  ['CHANNELD_AWAITING_SPLICE', 'ACTIVE'],
  ['CHANNELD_SHUTTING_DOWN', 'CLOSING'],
  ['CLOSINGD_SIGEXCHANGE', 'CLOSING'],
  ['CLOSINGD_COMPLETE', 'CLOSING'],
  ['AWAITING_UNILATERAL', 'CLOSING'],
  ['FUNDING_SPEND_SEEN', 'CLOSING'],
  ['ONCHAIN', 'CLOSING'],
]);

/** States in which CLN lists a channel it has not committed to yet, without channel_id or funding outpoint. */

/** Collects the raw fields a figure was computed from. */
class Provenance {
  readonly fields: Record<string, string> = {};

  amount(source: JsonObject, key: string, path: string = key): bigint {
    const value = integer(source, key);
    this.fields[path] = value.toString();
    return value;
  }

  sat(source: JsonObject, key: string, path: string = key): bigint {
    const msat = this.amount(source, key, path) * MSAT_PER_SAT;
    if (msat > MAX_INT64) throw new ProtocolError(`${path} is out of range`);
    return msat;
  }

  uint64(source: JsonObject, key: string, path: string): bigint {
    const value = BigInt(identifier(source, key));
    this.fields[path] = value.toString();
    return value;
  }

  text(path: string, value: string): string {
    this.fields[path] = value;
    return value;
  }
}

/** Refuses a field that is absent; proto3 defaults are taken only for optional fields (SPEC.md §5.6). */
function present(source: JsonObject, key: string, path: string): JsonObject {
  if (source[key] === undefined || source[key] === null) throw new ProtocolError(`${path} is missing`);
  return source;
}

function required(source: JsonObject, key: string): string {
  const value = string(source, key);
  if (value === '') throw new ProtocolError(`${key} is missing`);
  return value;
}

function clampedDifference(value: bigint, minus: bigint): bigint {
  return value > minus ? value - minus : 0n;
}

/**
 * The real SCID of an open LND channel. For a zero-conf channel `chan_id` is an alias (rpcserver.go
 * createRPCOpenChannel), so the confirmed SCID is used, and none exists before confirmation.
 */
function lndScid(channel: JsonObject, chanId: string, p: Provenance): string | null {
  if (!boolean(channel, 'zero_conf')) return chanIdToScid(chanId);
  p.text('zero_conf', 'true');
  return chanIdToScid(p.text('zero_conf_confirmed_scid', identifier(channel, 'zero_conf_confirmed_scid')));
}

/** lnd v0.21.4-beta input/size.go HtlcTimeoutWeight and HtlcSuccessWeight (second-level HTLC transactions). */
const LND_HTLC_TIMEOUT_WEIGHT = 663n;
const LND_HTLC_SUCCESS_WEIGHT = 703n;

/**
 * lnd v0.21.4-beta lnwallet/channel.go CalcFeeBuffer: the fee of the commitment plus one more HTLC at twice
 * the current fee rate; chainfee FeeForWeight rounds down. In sat.
 */
function lndFeeBufferSat(feePerKw: bigint, commitWeight: bigint): bigint {
  return (2n * feePerKw * (commitWeight + LND_HTLC_WEIGHT)) / 1000n;
}

interface LndSide {
  readonly reserve: bigint;
  /** Dust limit of this side's commitment, in msat; 0 when only the deprecated reserve field is present. */
  readonly dust: bigint;
  readonly max: bigint | null;
}

function lndSide(channel: JsonObject, p: Provenance, constraintsKey: string, deprecatedKey: string): LndSide {
  const constraints = optionalObject(channel, constraintsKey);
  if (constraints === undefined) return { reserve: p.sat(present(channel, deprecatedKey, deprecatedKey), deprecatedKey), dust: 0n, max: null };
  const reservePath = `${constraintsKey}.chan_reserve_sat`;
  return {
    reserve: p.sat(present(constraints, 'chan_reserve_sat', reservePath), 'chan_reserve_sat', reservePath),
    dust: p.sat(constraints, 'dust_limit_sat', `${constraintsKey}.dust_limit_sat`),
    max: p.uint64(constraints, 'max_pending_amt_msat', `${constraintsKey}.max_pending_amt_msat`),
  };
}

/**
 * What the side that did not open can add (lnd v0.21.4-beta lnwallet/channel.go availableCommitmentBalance and
 * availableBalance). If the opener's balance above its reserve is below the fee of one more HTLC
 * (floor(fee_per_kw × 172 / 1000) sat; computeView adds the commitment fee back first, so it cancels), lnd reports
 * just below the smallest non-dust HTLC, the smaller over the two commitment views: own dust limit plus the
 * HTLC-timeout fee, and the other side's dust limit plus the HTLC-success fee, less 1 msat. Anchor and taproot
 * types pay no second-level HTLC fee from the commitment.
 */
function nonOpenerAvailable(free: bigint, opener: { balance: bigint; reserve: bigint }, own: LndSide, other: LndSide,
  feePerKw: bigint, anchored: boolean): bigint {
  const htlcFeeMsat = (feePerKw * LND_HTLC_WEIGHT) / 1000n * MSAT_PER_SAT;
  if (opener.balance - opener.reserve >= htlcFeeMsat) return free;
  const timeoutFee = anchored ? 0n : (feePerKw * LND_HTLC_TIMEOUT_WEIGHT) / 1000n * MSAT_PER_SAT;
  const successFee = anchored ? 0n : (feePerKw * LND_HTLC_SUCCESS_WEIGHT) / 1000n * MSAT_PER_SAT;
  const smallest = [own.dust + timeoutFee - 1n, other.dust + successFee - 1n].reduce((x, y) => (x < y ? x : y), free);
  return smallest < 0n ? 0n : smallest;
}

/**
 * An open channel from LND ListChannels (lnrpc/lightning.proto Channel, REST JSON). LND has no per-channel
 * spendable figure, so spendable and receivable are derived (SPEC.md §4.2): the balance less the side's reserve
 * and, for the side that opened the channel and pays the commitment fee, the fee buffer and anchor reserve.
 * In-flight HTLCs are not subtracted: LND's balances already exclude them.
 *
 * The side that did not open can only add an HTLC the opener can pay the extra commitment fee for; otherwise
 * its figure is capped just below one non-dust HTLC, as lnd does (nonOpenerAvailable). For the committed state the
 * result never exceeds what lnd accepts; updates not yet committed (a fee update, new HTLCs) can lower lnd's
 * figure for a moment. docs/architecture.md gives the formula and its margin.
 */
export function normalizeLndChannel(raw: unknown, ctx: NormalizeContext): NormalizedChannel {
  const channel = asObject(raw, 'channel');
  const p = new Provenance();
  const chanId = identifier(channel, 'chan_id');
  p.text('chan_id', chanId);
  const active = boolean(channel, 'active');
  const initiator = boolean(channel, 'initiator');
  p.text('initiator', String(initiator));
  const commitmentType = enumName(channel, 'commitment_type', LND_COMMITMENT_TYPES);
  p.text('commitment_type', commitmentType);
  const capacity = p.sat(channel, 'capacity');
  const local = p.sat(channel, 'local_balance');
  const remote = p.sat(channel, 'remote_balance');
  const feePerKw = p.amount(channel, 'fee_per_kw');
  const commitWeight = p.amount(channel, 'commit_weight');
  const localSide = lndSide(channel, p, 'local_constraints', 'local_chan_reserve_sat');
  const remoteSide = lndSide(channel, p, 'remote_constraints', 'remote_chan_reserve_sat');

  const anchored = !LND_UNANCHORED.has(commitmentType);
  const openerCost = (lndFeeBufferSat(feePerKw, commitWeight) + (anchored ? LND_ANCHOR_RESERVE_SAT : 0n)) * MSAT_PER_SAT;
  const localFree = clampedDifference(local, localSide.reserve);
  const remoteFree = clampedDifference(remote, remoteSide.reserve);
  const spendable = initiator
    ? clampedDifference(localFree, openerCost)
    : nonOpenerAvailable(localFree, { balance: remote, reserve: remoteSide.reserve }, localSide, remoteSide, feePerKw, anchored);
  const receivable = initiator
    ? nonOpenerAvailable(remoteFree, { balance: local, reserve: localSide.reserve }, remoteSide, localSide, feePerKw, anchored)
    : clampedDifference(remoteFree, openerCost);

  let pendingOut = 0n;
  let pendingIn = 0n;
  const htlcs = array(channel, 'pending_htlcs');
  for (const entry of htlcs) {
    const htlc = asObject(entry, 'pending_htlcs[]');
    const amount = integer(htlc, 'amount') * MSAT_PER_SAT;
    if (boolean(htlc, 'incoming')) pendingIn += amount;
    else pendingOut += amount;
  }
  if (pendingOut > MAX_INT64 || pendingIn > MAX_INT64) throw new ProtocolError('pending_htlcs total is out of range');

  return {
    nodeId: ctx.nodeId,
    channelKey: chanId,
    scid: lndScid(channel, chanId, p),
    peerPubkey: required(channel, 'remote_pubkey'),
    fundingOutpoint: required(channel, 'channel_point'),
    state: active ? 'ACTIVE' : 'INACTIVE',
    nodeState: active ? 'active' : 'inactive',
    opener: initiator ? 'local' : 'remote',
    capacityMsat: capacity,
    localBalanceMsat: local,
    remoteBalanceMsat: remote,
    spendableMsat: spendable,
    receivableMsat: receivable,
    confidence: 'DERIVED_ESTIMATE',
    caveat: null,
    localReserveMsat: localSide.reserve,
    remoteReserveMsat: remoteSide.reserve,
    pendingOutMsat: pendingOut,
    pendingInMsat: pendingIn,
    pendingHtlcCount: htlcs.length,
    localMaxPendingAmtMsat: localSide.max,
    remoteMaxPendingAmtMsat: remoteSide.max,
    observedAt: ctx.observedAt,
    blockHeight: ctx.blockHeight,
    provenance: p.fields,
  };
}

/**
 * A channel from LND PendingChannels (the outer entry of `pending_open_channels`, `waiting_close_channels` or
 * `pending_force_closing_channels`). A pending channel carries no usable liquidity in either direction.
 */
export function normalizeLndPendingChannel(kind: LndPendingKind, raw: unknown, ctx: NormalizeContext): NormalizedChannel {
  const outer = asObject(raw, kind);
  const channel = asObject(outer['channel'], `${kind}.channel`);
  const p = new Provenance();
  const initiator = enumName(channel, 'initiator', LND_INITIATORS);
  p.text('channel.initiator', initiator);
  let opener: 'local' | 'remote';
  if (initiator === 'INITIATOR_LOCAL') opener = 'local';
  else if (initiator === 'INITIATOR_REMOTE') opener = 'remote';
  else throw new ProtocolError(`channel.initiator ${initiator} is not a single opener`);
  const fundingOutpoint = required(channel, 'channel_point');

  return {
    nodeId: ctx.nodeId,
    channelKey: fundingOutpoint,
    scid: null,
    peerPubkey: required(channel, 'remote_node_pub'),
    fundingOutpoint,
    state: kind === 'pending_open' ? 'PENDING' : 'CLOSING',
    nodeState: kind,
    opener,
    capacityMsat: p.sat(channel, 'capacity', 'channel.capacity'),
    localBalanceMsat: p.sat(channel, 'local_balance', 'channel.local_balance'),
    remoteBalanceMsat: p.sat(channel, 'remote_balance', 'channel.remote_balance'),
    spendableMsat: 0n,
    receivableMsat: 0n,
    confidence: 'DERIVED_ESTIMATE',
    caveat: null,
    localReserveMsat: p.sat(present(channel, 'local_chan_reserve_sat', 'channel.local_chan_reserve_sat'), 'local_chan_reserve_sat', 'channel.local_chan_reserve_sat'),
    remoteReserveMsat: p.sat(present(channel, 'remote_chan_reserve_sat', 'channel.remote_chan_reserve_sat'), 'remote_chan_reserve_sat', 'channel.remote_chan_reserve_sat'),
    pendingOutMsat: 0n,
    pendingInMsat: 0n,
    pendingHtlcCount: 0,
    localMaxPendingAmtMsat: null,
    remoteMaxPendingAmtMsat: null,
    observedAt: ctx.observedAt,
    blockHeight: ctx.blockHeight,
    provenance: p.fields,
  };
}

function clnState(state: string, peerConnected: boolean): ChannelState {
  const mapped = CLN_STATES.get(state) ?? 'UNKNOWN';
  return mapped === 'ACTIVE' && !peerConnected ? 'INACTIVE' : mapped;
}

/**
 * States CLN lists without channel_id: the uncommitted channel and channel_state_uncommitted() (lightningd/channel.h).
 * Every other state goes through json_add_channel, which always reports it (lightningd/peer_control.c).
 */
const UNCOMMITTED_CLN_STATES: ReadonlySet<string> = new Set(['OPENINGD', 'DUALOPEND_OPEN_INIT']);

/**
 * A channel CLN is still negotiating (OPENINGD, DUALOPEND_OPEN_INIT): lightningd/opening_control.c
 * json_add_uncommitted_channel and dual_open_control.c json_add_unsaved_channel list it without channel_id or
 * funding outpoint, and with to_us_msat and total_msat only when known. It is keyed by peer, has no outpoint and
 * nothing can be sent or received through it yet.
 */
function uncommittedClnChannel(channel: JsonObject, ctx: NormalizeContext, p: Provenance, state: string, opener: 'local' | 'remote'): NormalizedChannel {
  const peerPubkey = required(channel, 'peer_id');
  const total = p.amount(channel, 'total_msat');
  const toUs = p.amount(channel, 'to_us_msat');
  if (toUs > total) throw new ProtocolError('to_us_msat exceeds total_msat');
  return {
    nodeId: ctx.nodeId,
    channelKey: `uncommitted:${peerPubkey}`,
    scid: null,
    peerPubkey,
    fundingOutpoint: '',
    state: 'PENDING',
    nodeState: state,
    opener,
    capacityMsat: total,
    localBalanceMsat: toUs,
    remoteBalanceMsat: total - toUs,
    spendableMsat: 0n,
    receivableMsat: 0n,
    confidence: 'NODE_REPORTED',
    caveat: CLN_ESTIMATE_CAVEAT,
    localReserveMsat: 0n,
    remoteReserveMsat: 0n,
    pendingOutMsat: 0n,
    pendingInMsat: 0n,
    pendingHtlcCount: 0,
    localMaxPendingAmtMsat: null,
    remoteMaxPendingAmtMsat: null,
    observedAt: ctx.observedAt,
    blockHeight: ctx.blockHeight,
    provenance: p.fields,
  };
}

/**
 * A channel from CLN listpeerchannels (v26.06 doc/schemas/listpeerchannels.json). CLN reports spendable and
 * receivable itself; both are passed through with the node's own caveat that they are estimates.
 */
export function normalizeClnChannel(raw: unknown, ctx: NormalizeContext): NormalizedChannel {
  const channel = asObject(raw, 'channel');
  const p = new Provenance();
  const state = required(channel, 'state');
  p.text('state', state);
  const peerConnected = boolean(channel, 'peer_connected');
  const openerText = required(channel, 'opener');
  if (openerText !== 'local' && openerText !== 'remote') throw new ProtocolError(`opener ${openerText} is not local or remote`);
  p.text('opener', openerText);

  const shortChannelId = string(channel, 'short_channel_id');
  if (shortChannelId !== '' && !/^(0|[1-9][0-9]{0,7})x(0|[1-9][0-9]{0,7})x(0|[1-9][0-9]{0,4})$/.test(shortChannelId)) {
    throw new ProtocolError('short_channel_id is malformed');
  }
  if (string(channel, 'channel_id') === '' && UNCOMMITTED_CLN_STATES.has(state)) {
    return uncommittedClnChannel(channel, ctx, p, state, openerText);
  }
  const channelId = required(channel, 'channel_id');
  const fundingTxid = required(channel, 'funding_txid');
  const fundingOutnum = smallInteger(channel, 'funding_outnum');

  const total = p.amount(channel, 'total_msat');
  const toUs = p.amount(channel, 'to_us_msat');
  if (toUs > total) throw new ProtocolError('to_us_msat exceeds total_msat');

  let pendingOut = 0n;
  let pendingIn = 0n;
  const htlcs = array(channel, 'htlcs');
  for (const entry of htlcs) {
    const htlc = asObject(entry, 'htlcs[]');
    const amount = integer(htlc, 'amount_msat');
    const direction = string(htlc, 'direction');
    if (direction === 'in') pendingIn += amount;
    else if (direction === 'out') pendingOut += amount;
    else throw new ProtocolError(`htlcs[].direction ${direction} is not in or out`);
  }
  if (pendingOut > MAX_INT64 || pendingIn > MAX_INT64) throw new ProtocolError('htlcs total is out of range');

  // A reported figure above the balance it is drawn from is not a channel CLN can have: the answer is refused.
  const remoteBalance = total - toUs;
  const spendable = p.amount(channel, 'spendable_msat');
  const receivable = p.amount(channel, 'receivable_msat');
  if (spendable > toUs) throw new ProtocolError('spendable_msat exceeds to_us_msat');
  if (receivable > remoteBalance) throw new ProtocolError('receivable_msat exceeds total_msat - to_us_msat');

  return {
    nodeId: ctx.nodeId,
    channelKey: shortChannelId === '' ? channelId : shortChannelId,
    scid: shortChannelId === '' ? null : shortChannelId,
    peerPubkey: required(channel, 'peer_id'),
    fundingOutpoint: `${fundingTxid}:${String(fundingOutnum)}`,
    state: clnState(state, peerConnected),
    nodeState: state,
    opener: openerText,
    capacityMsat: total,
    localBalanceMsat: toUs,
    remoteBalanceMsat: remoteBalance,
    spendableMsat: spendable,
    receivableMsat: receivable,
    confidence: 'NODE_REPORTED',
    caveat: CLN_ESTIMATE_CAVEAT,
    localReserveMsat: p.amount(channel, 'our_reserve_msat'),
    remoteReserveMsat: p.amount(channel, 'their_reserve_msat'),
    pendingOutMsat: pendingOut,
    pendingInMsat: pendingIn,
    pendingHtlcCount: htlcs.length,
    localMaxPendingAmtMsat: null,
    remoteMaxPendingAmtMsat: null,
    observedAt: ctx.observedAt,
    blockHeight: ctx.blockHeight,
    provenance: p.fields,
  };
}
