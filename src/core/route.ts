// Validation of a candidate circular route (checks V1..V12). Pure: every figure is recomputed
// from the hops, and totals a node reports are accepted only when they equal the recomputed ones.
import type { Msat } from './money.js';
import { channelExcluded } from './scid.js';

export type Implementation = 'lnd' | 'cln';

/** The forwarding policy of a hop's channel, as set by the node that sends on it. */
export interface HopPolicy {
  readonly baseFeeMsat: Msat;
  readonly feePpm: bigint;
  readonly cltvExpiryDelta: number;
  readonly minHtlcMsat: Msat;
  readonly maxHtlcMsat: Msat | null;
}

/**
 * One hop, with hop-end semantics: the HTLC on channel `scid` that reaches `nodeIdOut` carries
 * `amountOutMsat` and expires at the absolute height `cltvOut`. `policy` is null for the first
 * hop, which is our own channel and charges no fee.
 */
export interface RouteHop {
  readonly scid: string;
  readonly nodeIdOut: string;
  readonly amountOutMsat: Msat;
  readonly cltvOut: number;
  readonly policy: HopPolicy | null;
}

export interface CandidateRoute {
  readonly hops: readonly RouteHop[];
  readonly parts: number;
  readonly totalAmountMsat: Msat;
  readonly totalFeeMsat: Msat;
  readonly totalTimeLock: number;
  readonly builtAtHeight: number;
}

export type ValidatedRoute = CandidateRoute & { readonly __brand: 'validated-route' };

export interface RouteConstraints {
  readonly selfPubkey: string;
  readonly implementation: Implementation;
  readonly sourceScid: string;
  readonly targetScid: string;
  readonly outPeer: string;
  readonly inPeer: string;
  readonly principalMsat: Msat;
  /** Approved caps, never above the policy's. */
  readonly maxFeeMsat: Msat;
  readonly maxCltvDelta: number;
  readonly finalCltvDelta: number;
  readonly blockHeight: number;
  readonly excludeChannels?: readonly string[];
}

/** A node's answer that no acceptable route exists; `reason` is the node's text, for display only. */
export interface NoRoute {
  readonly kind: 'no-route';
  readonly code: 'NO_FEASIBLE_ROUTE' | 'FEE_CEILING_EXCEEDED' | 'SINGLE_PATH_UNAVAILABLE';
  readonly reason: string;
}

export function isNoRoute(result: CandidateRoute | NoRoute): result is NoRoute {
  return 'kind' in result;
}

export type ChannelState = 'ACTIVE' | 'INACTIVE' | 'PENDING' | 'CLOSING' | 'UNKNOWN';

/** Our own view of one of our channels, from the newest snapshot. */
export interface RouteChannel {
  readonly channelKey: string;
  readonly scid: string | null;
  readonly peerPubkey: string;
  readonly state: ChannelState;
  readonly spendableMsat: Msat;
  readonly receivableMsat: Msat;
}

export interface EffectivePolicy {
  readonly maxFeeMsat: Msat;
  readonly maxFeePpm: bigint;
  readonly exemptFeeMsat: Msat;
  readonly maxCltvDelta: number;
  readonly minChannelReserveMsat: Msat;
}

export type RefusalCode = 'NO_FEASIBLE_ROUTE' | 'REPEATED_CHANNEL' | 'FEE_CEILING_EXCEEDED' | 'PPM_CEILING_EXCEEDED'
  | 'CLTV_DELTA_UNSAFE' | 'SINGLE_PATH_UNAVAILABLE' | 'SAME_PEER' | 'FIRST_HOP_SPENDABLE' | 'RESERVE_FLOOR' | 'LAST_HOP_RECEIVABLE';

export type RouteCheck = 'V1' | 'V2' | 'V3' | 'V4' | 'V5' | 'V6' | 'V7' | 'V8' | 'V9' | 'V10' | 'V11' | 'V12';

export type RouteVerdict =
  | { readonly ok: true; readonly route: ValidatedRoute; readonly feeMsat: Msat; readonly feePpm: bigint; readonly cltvDelta: number; readonly padding: 1 | 3 }
  | { readonly ok: false; readonly code: RefusalCode; readonly check: RouteCheck };

/** Blocks LND's SendPaymentV2 adds to the route's timelock. */
const LND_BLOCK_PADDING = 3;
/** lightningd sends each HTLC at network height + 1 + its cltv_out delta (lightningd/pay.c send_payment). */
const CLN_BLOCK_PADDING = 1;

function refuse(code: RefusalCode, check: RouteCheck): RouteVerdict {
  return { ok: false, code, check };
}

/** Inputs that are not whole numbers of the expected kind fail the check that uses them (never pass it). */
function isBig(value: unknown): value is bigint {
  return typeof value === 'bigint';
}

function isBlocks(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function minBig(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}

/** Fee a forwarding node charges for an outgoing amount: base + floor(amount × ppm / 10^6). */
function forwardingFee(amountOut: bigint, policy: HopPolicy): bigint {
  return policy.baseFeeMsat + (amountOut * policy.feePpm) / 1_000_000n;
}

/**
 * Runs V1..V12 in order and returns the first failure. Fee and CLTV caps are the lower of the
 * approved caps and the policy's.
 */
export function validateRoute(route: CandidateRoute, c: RouteConstraints, channels: readonly RouteChannel[], policy: EffectivePolicy): RouteVerdict {
  const hops = route.hops;
  if (hops.some(hop => channelExcluded(hop.scid, c.excludeChannels)
    || channels.some(channel => channel.scid === hop.scid && channelExcluded(channel.channelKey, c.excludeChannels)))) return refuse('NO_FEASIBLE_ROUTE', 'V1');
  const first = hops[0];
  const last = hops[hops.length - 1];
  const principal: bigint = c.principalMsat;
  const source = channels.find(channel => channel.scid === c.sourceScid);
  const target = channels.find(channel => channel.scid === c.targetScid);

  // V1: out over S to the out-peer, back over T from the in-peer to us.
  if (first === undefined || last === undefined || hops.length < 2 || !isBig(principal) || principal <= 0n) return refuse('NO_FEASIBLE_ROUTE', 'V1');
  const beforeLast = hops[hops.length - 2];
  if (first.scid !== c.sourceScid || first.nodeIdOut !== c.outPeer) return refuse('NO_FEASIBLE_ROUTE', 'V1');
  if (last.scid !== c.targetScid || last.nodeIdOut !== c.selfPubkey || beforeLast?.nodeIdOut !== c.inPeer) return refuse('NO_FEASIBLE_ROUTE', 'V1');
  if ((source !== undefined && source.peerPubkey !== c.outPeer) || (target !== undefined && target.peerPubkey !== c.inPeer)) return refuse('NO_FEASIBLE_ROUTE', 'V1');

  // V2: no channel twice, in either direction.
  if (new Set(hops.map(hop => hop.scid)).size !== hops.length) return refuse('REPEATED_CHANNEL', 'V2');

  // V3, V4: F recomputed from the first hop; ppm rounded up; the exemption never relaxes the absolute cap.
  if (!isBig(first.amountOutMsat) || !isBig(c.maxFeeMsat) || !isBig(policy.maxFeeMsat)) return refuse('FEE_CEILING_EXCEEDED', 'V3');
  const fee: bigint = first.amountOutMsat - principal;
  const ppm = (fee * 1_000_000n + principal - 1n) / principal;
  if (fee > minBig(c.maxFeeMsat, policy.maxFeeMsat)) return refuse('FEE_CEILING_EXCEEDED', 'V3');
  if (!isBig(policy.exemptFeeMsat) || !isBig(policy.maxFeePpm)) return refuse('PPM_CEILING_EXCEEDED', 'V4');
  if (fee > policy.exemptFeeMsat && ppm > policy.maxFeePpm) return refuse('PPM_CEILING_EXCEEDED', 'V4');

  // V5: Δ from the first hop's expiry, plus padding; every expiry a whole block height that never
  // rises along the route; the reported total timelock is the first hop's expiry (the first HTLC is sent with it).
  const padding = c.implementation === 'lnd' ? LND_BLOCK_PADDING : CLN_BLOCK_PADDING;
  if (![c.blockHeight, c.finalCltvDelta, c.maxCltvDelta, policy.maxCltvDelta, route.totalTimeLock].every(isBlocks) || !hops.every(hop => isBlocks(hop.cltvOut))) return refuse('CLTV_DELTA_UNSAFE', 'V5');
  const delta = first.cltvOut - c.blockHeight;
  if (delta + padding > Math.min(c.maxCltvDelta, policy.maxCltvDelta)) return refuse('CLTV_DELTA_UNSAFE', 'V5');
  if (route.totalTimeLock !== first.cltvOut) return refuse('CLTV_DELTA_UNSAFE', 'V5');
  for (let i = 1; i < hops.length; i += 1) {
    const previous = hops[i - 1];
    const hop = hops[i];
    if (previous === undefined || hop === undefined || hop.cltvOut > previous.cltvOut) return refuse('CLTV_DELTA_UNSAFE', 'V5');
  }
  if (last.cltvOut - c.blockHeight < c.finalCltvDelta) return refuse('CLTV_DELTA_UNSAFE', 'V5');

  // V6: exactly one part.
  if (route.parts !== 1) return refuse('SINGLE_PATH_UNAVAILABLE', 'V6');

  // V7: distinct peers at both ends.
  if (c.outPeer === c.inPeer) return refuse('SAME_PEER', 'V7');

  // V8, V9: our own view of both channels.
  if (source === undefined || target === undefined) return refuse('NO_FEASIBLE_ROUTE', 'V12');
  if (!isBig(source.spendableMsat) || !isBig(policy.minChannelReserveMsat)) return refuse('FIRST_HOP_SPENDABLE', 'V8');
  if (!isBig(target.receivableMsat)) return refuse('LAST_HOP_RECEIVABLE', 'V9');
  const outgoing = principal + fee;
  if (source.spendableMsat < outgoing) return refuse('FIRST_HOP_SPENDABLE', 'V8');
  if (source.spendableMsat - outgoing < policy.minChannelReserveMsat) return refuse('RESERVE_FLOOR', 'V8');
  if (target.receivableMsat < principal) return refuse('LAST_HOP_RECEIVABLE', 'V9');

  // V10: every forwarder takes exactly its policy fee, the final hop delivers P, amounts within HTLC limits.
  if (last.amountOutMsat !== principal || fee < 0n) return refuse('NO_FEASIBLE_ROUTE', 'V10');
  if (route.totalAmountMsat !== first.amountOutMsat || route.totalFeeMsat !== fee) return refuse('NO_FEASIBLE_ROUTE', 'V10');
  for (let i = 1; i < hops.length; i += 1) {
    const previous = hops[i - 1];
    const hop = hops[i];
    const hopPolicy = hop?.policy;
    if (previous === undefined || hop === undefined || hopPolicy === null || hopPolicy === undefined) return refuse('NO_FEASIBLE_ROUTE', 'V10');
    if (hopPolicy.baseFeeMsat < 0n || hopPolicy.feePpm < 0n) return refuse('NO_FEASIBLE_ROUTE', 'V10');
    if (hop.amountOutMsat <= 0n || previous.amountOutMsat - hop.amountOutMsat !== forwardingFee(hop.amountOutMsat, hopPolicy)) return refuse('NO_FEASIBLE_ROUTE', 'V10');
    if (hop.amountOutMsat < hopPolicy.minHtlcMsat || (hopPolicy.maxHtlcMsat !== null && hop.amountOutMsat > hopPolicy.maxHtlcMsat)) return refuse('NO_FEASIBLE_ROUTE', 'V10');
  }

  // V11: no reverse edges: the route never passes through our own node before its last hop.
  if (hops.slice(0, -1).some(hop => hop.nodeIdOut === c.selfPubkey)) return refuse('REPEATED_CHANNEL', 'V11');

  // V12: both of our channels are open in the newest snapshot.
  if (source.state !== 'ACTIVE' || target.state !== 'ACTIVE') return refuse('NO_FEASIBLE_ROUTE', 'V12');

  return { ok: true, route: route as ValidatedRoute, feeMsat: fee as Msat, feePpm: ppm, cltvDelta: delta, padding };
}
