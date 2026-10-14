/*
 * Interface: route assessment (read-only) for both adapters, against the core validator.
 *
 * src/core/route.ts (pure, from the route validation work; used exactly as exported there):
 *   HopPolicy, RouteHop (hop-end: the HTLC on `scid` reaching `nodeIdOut` carries `amountOutMsat` and
 *   expires at absolute height `cltvOut`; `policy` is the forwarding policy of that channel as set by
 *   the node sending on it, null for the first hop), CandidateRoute, RouteConstraints, RouteChannel,
 *   EffectivePolicy, RouteVerdict, validateRoute(route, constraints, channels, policy).
 *
 * Both adapters answer `CandidateRoute | NoRoute`:
 *   interface NoRoute { readonly kind: 'no-route'; readonly code: 'NO_FEASIBLE_ROUTE' | 'FEE_CEILING_EXCEEDED'
 *     | 'SINGLE_PATH_UNAVAILABLE'; readonly reason: string }   // reason: node text, display only
 *   Any other failure rejects (LndError, ClnError, ProtocolError, TransportError, CapabilityUnsupported);
 *   only the answers named below become a NoRoute. `builtAtHeight` = constraints.blockHeight;
 *   `parts` = 1; totals are recomputed from the hops (first hop amount, first hop cltv).
 *
 * src/node-lnd/routes.ts   new LndRouteApi(rest: LndRest)
 *   buildCircularRoute(c: RouteConstraints): Promise<CandidateRoute | NoRoute>
 *   1. POST /v1/graph/routes/{c.selfPubkey}/0 with exactly these body fields (int64/uint64 as decimal
 *      strings, int32/uint32 as numbers, bytes as standard base64):
 *        amt_msat: P; final_cltv_delta: c.finalCltvDelta; fee_limit: { fixed_msat: c.maxFeeMsat };
 *        outgoing_chan_ids: [chan_id of c.sourceScid]; last_hop_pubkey: c.inPeer;
 *        cltv_limit: c.maxCltvDelta - 3; ignored_pairs: [{from: outPeer, to: self}, {from: self, to: inPeer}];
 *        use_mission_control: true.
 *      chan_id = block << 40 | tx << 16 | output of the `BxTxO` scid.
 *   2. The answer has exactly one route, else ProtocolError. gRPC 2 "unable to find a path to
 *      destination" (also LND's answer when every path is over the fee limit) -> NoRoute NO_FEASIBLE_ROUTE.
 *   3. Hop k of the answer becomes RouteHop k: scid from chan_id; nodeIdOut = pub_key;
 *      amountOutMsat = amt_to_forward_msat + fee_msat; cltvOut = total_time_lock for k = 0, else the
 *      previous hop's expiry. Only the `_msat` fields are read (the sat fields are removed in 0.22).
 *   4. For every hop after the first, GET /v1/graph/edge/{chan_id}: the policy of the node that sends
 *      on it (node1_policy when node1_pub is the previous hop's pub_key, else node2_policy):
 *      baseFeeMsat = fee_base_msat, feePpm = fee_rate_milli_msat, cltvExpiryDelta = time_lock_delta,
 *      minHtlcMsat = min_htlc, maxHtlcMsat = max_htlc_msat.
 *   No other path is ever requested (no /v2/router/* call).
 *
 * src/node-cln/routes.ts   new ClnRouteApi(rest: ClnRest, options?: { profile?: 'v26.06' | 'v26.04' })
 *   buildCircularRoute(c: RouteConstraints, request: { layer: string; excludeScids: readonly string[] }):
 *     Promise<CandidateRoute | NoRoute>
 *   Calls (CLN method names; other reads such as listpeerchannels and listchannels in any order):
 *     askrene-create-layer {layer}; askrene-disable-node {layer, node: self};
 *     askrene-update-channel {layer, short_channel_id_dir: `${scid}/0` and `${scid}/1`, enabled: false}
 *       for every excluded scid; getroutes {source: outPeer, destination: inPeer,
 *       amount_msat: P + inFee, layers: ['xpay', layer], maxfee_msat: c.maxFeeMsat - inFee,
 *       final_cltv: inDelta + c.finalCltvDelta, maxdelay: c.maxCltvDelta - 1 (CLN padding 1, D52;
 *       askrene includes final_cltv in maxdelay, pinned mcf.c:1409, D57),
 *       maxparts: 1}; askrene-remove-layer {layer}.
 *     inFee / inDelta: the in-peer's policy for channel T, listpeerchannels `updates.remote`.
 *   askrene-remove-layer runs on every exit after a successful create, including errors; a failed
 *   create (another layer of that name exists) rejects without getroutes and without removing it.
 *   Never calls xpay, pay, sendpay or any other payment command.
 *   getroutes 205 -> NoRoute NO_FEASIBLE_ROUTE; 206 -> FEE_CEILING_EXCEEDED; more than one route ->
 *   SINGLE_PATH_UNAVAILABLE. Path items without `node_id_out` -> CapabilityUnsupported unless the
 *   v26.04 profile is declared, which reads next_node_id instead.
 *   Assembly: [out-hop over S to outPeer (policy null)] + path + [in-hop over T to self]; amounts and
 *   cltvs recomputed backwards from P and blockHeight + finalCltvDelta with the in-peer policy for T
 *   and the listchannels direction whose `source` is the hop's sending node for each path hop;
 *   askrene's own amounts and cltvs are not used.
 */
import { loadSource } from './adapter-interfaces.js';
import type { LndRest, ClnRest } from './adapter-interfaces.js';

export interface HopPolicy { baseFeeMsat: bigint; feePpm: bigint; cltvExpiryDelta: number; minHtlcMsat: bigint; maxHtlcMsat: bigint | null }
export interface RouteHop { scid: string; nodeIdOut: string; amountOutMsat: bigint; cltvOut: number; policy: HopPolicy | null }
export interface CandidateRoute { hops: RouteHop[]; parts: number; totalAmountMsat: bigint; totalFeeMsat: bigint; totalTimeLock: number; builtAtHeight: number }
export interface RouteConstraints {
  selfPubkey: string; implementation: 'lnd' | 'cln'; sourceScid: string; targetScid: string; outPeer: string; inPeer: string;
  principalMsat: bigint; maxFeeMsat: bigint; maxCltvDelta: number; finalCltvDelta: number; blockHeight: number;
}
export interface RouteChannel { channelKey: string; scid: string | null; peerPubkey: string; state: 'ACTIVE' | 'INACTIVE' | 'PENDING' | 'CLOSING' | 'UNKNOWN'; spendableMsat: bigint; receivableMsat: bigint }
export interface EffectivePolicy { maxFeeMsat: bigint; maxFeePpm: bigint; exemptFeeMsat: bigint; maxCltvDelta: number; minChannelReserveMsat: bigint }
export type RouteVerdict =
  | { ok: true; route: CandidateRoute; feeMsat: bigint; feePpm: bigint; cltvDelta: number; padding: number }
  | { ok: false; code: string; check: string };
export interface NoRoute { kind: 'no-route'; code: 'NO_FEASIBLE_ROUTE' | 'FEE_CEILING_EXCEEDED' | 'SINGLE_PATH_UNAVAILABLE'; reason: string }

export interface RouteModule { validateRoute: (route: CandidateRoute, c: RouteConstraints, channels: readonly RouteChannel[], policy: EffectivePolicy) => RouteVerdict }
export interface LndRoutesModule { LndRouteApi: new (rest: LndRest) => { buildCircularRoute: (c: RouteConstraints) => Promise<CandidateRoute | NoRoute> } }
export interface ClnRouteRequest { layer: string; excludeScids: readonly string[] }
export interface ClnRoutesModule {
  ClnRouteApi: new (rest: ClnRest, options?: { profile?: 'v26.06' | 'v26.04' }) => {
    buildCircularRoute: (c: RouteConstraints, request: ClnRouteRequest) => Promise<CandidateRoute | NoRoute>;
  };
}

export const loadRoute = (): Promise<RouteModule> => loadSource<RouteModule>('core/route.ts');
export const loadLndRoutes = (): Promise<LndRoutesModule> => loadSource<LndRoutesModule>('node-lnd/routes.ts');
export const loadClnRoutes = (): Promise<ClnRoutesModule> => loadSource<ClnRoutesModule>('node-cln/routes.ts');

export function isCandidate(result: CandidateRoute | NoRoute): result is CandidateRoute {
  return !('kind' in result);
}

/** The policy example of SPEC §7.1 as the validator takes it. */
export const POLICY: EffectivePolicy = { maxFeeMsat: 300_000n, maxFeePpm: 2_500n, exemptFeeMsat: 5_000n, maxCltvDelta: 144, minChannelReserveMsat: 50_000_000n };
