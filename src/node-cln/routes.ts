// Route assessment over clnrest, read calls only: a per-assessment askrene layer, getroutes between the
// two peers, and the full circular route assembled around that path (Core Lightning v26.06,
// doc/schemas/getroutes.json and askrene-*.json). No payment command is reachable from here.
import { CapabilityUnsupported } from '../core/capabilities.js';
import { ClnError, ProtocolError } from '../core/errors.js';
import type { JsonObject } from '../core/json.js';
import { hopFee, type Msat } from '../core/money.js';
import type { CandidateRoute, HopPolicy, NoRoute, RouteConstraints, RouteHop } from '../core/route.js';
import { lightningdRefused, type ClnRest } from './rest.js';
import { asObject, count, msat, objects, optionalString, text } from './types.js';

/** getroutes errors, common/jsonrpc_errors.h: no route, and every route over maxfee_msat. */
const PAY_ROUTE_NOT_FOUND = 205;
const PAY_ROUTE_TOO_EXPENSIVE = 206;
const CLN_BLOCK_PADDING = 1;

const PUBKEY = /^0[23][0-9a-f]{64}$/;
const SCID = /^[0-9]+x[0-9]+x[0-9]+$/;
const SCID_DIR = /^([0-9]+x[0-9]+x[0-9]+)\/[01]$/;

export type ClnRouteProfile = 'v26.06' | 'v26.04';

export interface ClnRouteRequest {
  /** A layer name no other assessment uses. */
  readonly layer: string;
  /** Channels neither direction of which may be used. */
  readonly excludeScids: readonly string[];
}

interface PathItem {
  readonly scid: string;
  readonly sender: string;
  readonly nodeIdOut: string;
}

interface PolicyKeys { readonly base: string; readonly ppm: string; readonly delta: string; readonly min: string; readonly max: string }

const REMOTE_UPDATE: PolicyKeys = { base: 'fee_base_msat', ppm: 'fee_proportional_millionths', delta: 'cltv_expiry_delta', min: 'htlc_minimum_msat', max: 'htlc_maximum_msat' };
const CHANNEL_DIRECTION: PolicyKeys = { base: 'base_fee_millisatoshi', ppm: 'fee_per_millionth', delta: 'delay', min: 'htlc_minimum_msat', max: 'htlc_maximum_msat' };

function pubkey(value: string, what: string): string {
  if (!PUBKEY.test(value)) throw new ProtocolError(`${what} is not a public key`);
  return value;
}

/** A forwarding policy from listpeerchannels updates.remote or a listchannels direction. */
function policyFrom(source: JsonObject, keys: PolicyKeys): HopPolicy {
  const max = source[keys.max];
  return {
    baseFeeMsat: msat(source, keys.base) as Msat,
    feePpm: BigInt(count(source, keys.ppm)),
    cltvExpiryDelta: count(source, keys.delta),
    minHtlcMsat: msat(source, keys.min) as Msat,
    maxHtlcMsat: max === undefined || max === null ? null : msat(source, keys.max) as Msat,
  };
}

function noRoute(error: unknown): NoRoute | null {
  if (!(error instanceof ClnError)) return null;
  if (error.code === PAY_ROUTE_NOT_FOUND) return { kind: 'no-route', code: 'NO_FEASIBLE_ROUTE', reason: error.message };
  if (error.code === PAY_ROUTE_TOO_EXPENSIVE) return { kind: 'no-route', code: 'FEE_CEILING_EXCEEDED', reason: error.message };
  return null;
}

export class ClnRouteApi {
  readonly #rest: ClnRest;
  readonly #profile: ClnRouteProfile;

  constructor(rest: ClnRest, options: { profile?: ClnRouteProfile } = {}) {
    this.#rest = rest;
    this.#profile = options.profile ?? 'v26.06';
  }

  /**
   * One getroutes from the out-peer to the in-peer under a fresh layer that disables our own node and the
   * excluded channels, then the circular route around it with amounts and CLTVs recomputed backwards from
   * the nodes' own policies; askrene's figures are not used. Validation is the caller's (core validateRoute).
   */
  async buildCircularRoute(c: RouteConstraints, request: ClnRouteRequest): Promise<CandidateRoute | NoRoute> {
    if (!PUBKEY.test(c.selfPubkey) || !PUBKEY.test(c.outPeer) || !PUBKEY.test(c.inPeer)) throw new RangeError('route constraints name an invalid public key');
    if (request.layer === '' || request.excludeScids.some(scid => !SCID.test(scid))) throw new RangeError('invalid layer name or excluded channel');

    const inPolicy = await this.#inPeerPolicy(c);
    const principal = c.principalMsat;
    const inFee = hopFee(principal, inPolicy.baseFeeMsat, inPolicy.feePpm);
    const maxFee = c.maxFeeMsat - inFee;
    if (maxFee < 0n) return { kind: 'no-route', code: 'FEE_CEILING_EXCEEDED', reason: 'the in-peer fee alone exceeds the fee cap' };
    const finalCltv = inPolicy.cltvExpiryDelta + c.finalCltvDelta;
    // Decision D52: lightningd sends each HTLC one block above the route's delta (height + 1 + cltv_out).
    // D57: Core Lightning v26.06.9 plugins/askrene/child/mcf.c includes finalcltv in maxdelay.
    const maxDelay = c.maxCltvDelta - CLN_BLOCK_PADDING;
    if (maxDelay <= finalCltv) return { kind: 'no-route', code: 'NO_FEASIBLE_ROUTE', reason: 'the in-peer CLTV delta leaves no room under the CLTV cap' };

    const answer = await this.#withLayer(c.selfPubkey, request, () => this.#rest.call('getroutes', {
      source: c.outPeer,
      destination: c.inPeer,
      amount_msat: (principal + inFee).toString(),
      layers: ['xpay', request.layer],
      maxfee_msat: maxFee.toString(),
      final_cltv: finalCltv,
      maxdelay: maxDelay,
      maxparts: 1,
    }));
    if (answer instanceof Error) {
      const refusal = noRoute(answer);
      if (refusal === null) throw answer;
      return refusal;
    }

    const routes = objects(answer, 'routes');
    if (routes.length === 0) throw new ProtocolError('getroutes answered no route');
    if (routes.length > 1) return { kind: 'no-route', code: 'SINGLE_PATH_UNAVAILABLE', reason: `getroutes answered ${String(routes.length)} parts` };
    const path = this.#path(asObject(routes[0], 'routes[0]'), c.outPeer);
    return this.#assemble(c, path, inPolicy);
  }

  /** The in-peer's policy for forwarding to us over the target channel: listpeerchannels updates.remote. */
  async #inPeerPolicy(c: RouteConstraints): Promise<HopPolicy> {
    const channels = objects(await this.#rest.call('listpeerchannels', { id: c.inPeer }), 'channels');
    const target = channels.filter(channel => optionalString(channel, 'short_channel_id') === c.targetScid);
    const channel = target[0];
    if (target.length !== 1 || channel === undefined) throw new ProtocolError('target channel is not listed exactly once by listpeerchannels');
    if (text(channel, 'peer_id') !== c.inPeer) throw new ProtocolError('target channel belongs to another peer');
    const updates = asObject(channel['updates'], 'updates');
    return policyFrom(asObject(updates['remote'], 'updates.remote'), REMOTE_UPDATE);
  }

  /**
   * Creates the layer, disables our node and both directions of every excluded channel, runs `work`, and
   * removes the layer whatever happened. A create that lightningd refuses rejects untouched: the name may be
   * another assessment's layer; a create whose answer was lost is followed by a removal. The work's own error is returned for the caller to classify; a failure to set up
   * or remove the layer rejects, a removal failure only when nothing failed first.
   */
  async #withLayer(self: string, request: ClnRouteRequest, work: () => Promise<JsonObject>): Promise<JsonObject | Error> {
    const layer = request.layer;
    try {
      await this.#rest.call('askrene-create-layer', { layer });
    } catch (error) {
      // lightningd refused the name: it may be another assessment's layer, which is left alone. Any other failure
      // (a cut or an unreadable answer) may have created the layer, so it is removed before the error is reported.
      if (!lightningdRefused(error)) await this.#rest.call('askrene-remove-layer', { layer }).catch(() => undefined);
      throw error;
    }
    let outcome: JsonObject | Error | undefined;
    let failure: { readonly error: unknown } | undefined;
    try {
      await this.#rest.call('askrene-disable-node', { layer, node: self });
      for (const scid of request.excludeScids) {
        for (const direction of [0, 1]) {
          await this.#rest.call('askrene-update-channel', { layer, short_channel_id_dir: `${scid}/${String(direction)}`, enabled: false });
        }
      }
      try {
        outcome = await work();
      } catch (error) {
        if (noRoute(error) === null) throw error;
        outcome = error as Error;
      }
    } catch (error) {
      failure = { error };
    }
    try {
      await this.#rest.call('askrene-remove-layer', { layer });
    } catch (error) {
      failure ??= { error };
    }
    if (failure !== undefined) throw failure.error;
    if (outcome === undefined) throw new ProtocolError('getroutes gave no answer');
    return outcome;
  }

  #path(route: JsonObject, outPeer: string): PathItem[] {
    const items = objects(route, 'path');
    if (items.length === 0) throw new ProtocolError('getroutes answered an empty path');
    let sender = outPeer;
    return items.map(item => {
      const match = SCID_DIR.exec(text(item, 'short_channel_id_dir'));
      if (match === null) throw new ProtocolError('short_channel_id_dir is malformed');
      let nodeIdOut: string;
      if (this.#profile === 'v26.04') {
        nodeIdOut = pubkey(text(item, 'next_node_id'), 'next_node_id');
      } else {
        const out = optionalString(item, 'node_id_out');
        if (out === null) throw new CapabilityUnsupported('getroutes path items lack node_id_out; declare the v26.04 profile for this node', ['ASKRENE_LAYER_ROUTING']);
        nodeIdOut = pubkey(out, 'node_id_out');
        const into = optionalString(item, 'node_id_in');
        if (into !== null && into !== sender) throw new ProtocolError('getroutes path is not contiguous');
      }
      const entry: PathItem = { scid: match[1] ?? '', sender, nodeIdOut };
      sender = nodeIdOut;
      return entry;
    });
  }

  /** The policy `sender` sets for forwarding over `scid`: the listchannels direction whose source it is. */
  async #directionPolicy(scid: string, sender: string): Promise<HopPolicy> {
    const directions = objects(await this.#rest.call('listchannels', { short_channel_id: scid }), 'channels')
      .filter(entry => optionalString(entry, 'short_channel_id') === scid && optionalString(entry, 'source') === sender);
    const direction = directions[0];
    if (directions.length !== 1 || direction === undefined) throw new ProtocolError(`listchannels has no single direction of ${scid} from the sending node`);
    return policyFrom(direction, CHANNEL_DIRECTION);
  }

  /** Out-hop over S, the path, in-hop over T; figures recomputed backwards from P and blockHeight + finalCltvDelta. */
  async #assemble(c: RouteConstraints, path: readonly PathItem[], inPolicy: HopPolicy): Promise<CandidateRoute> {
    const policies: HopPolicy[] = [];
    for (const item of path) policies.push(await this.#directionPolicy(item.scid, item.sender));

    let next: RouteHop = { scid: c.targetScid, nodeIdOut: c.selfPubkey, amountOutMsat: c.principalMsat, cltvOut: c.blockHeight + c.finalCltvDelta, policy: inPolicy };
    const reversed: RouteHop[] = [next];
    // The hop before `next` carries what its receiver forwards plus that receiver's fee, and expires
    // the receiver's CLTV delta later.
    const before = (scid: string, nodeIdOut: string, policy: HopPolicy | null): RouteHop => {
      const forwarder = next.policy;
      if (forwarder === null) throw new ProtocolError('route hop has no forwarding policy');
      return {
        scid,
        nodeIdOut,
        amountOutMsat: (next.amountOutMsat + hopFee(next.amountOutMsat, forwarder.baseFeeMsat, forwarder.feePpm)) as Msat,
        cltvOut: next.cltvOut + forwarder.cltvExpiryDelta,
        policy,
      };
    };
    for (let i = path.length - 1; i >= 0; i -= 1) {
      const item = path[i];
      const policy = policies[i];
      if (item === undefined || policy === undefined) throw new ProtocolError('route hop is missing');
      next = before(item.scid, item.nodeIdOut, policy);
      reversed.push(next);
    }
    const first = before(c.sourceScid, c.outPeer, null);
    return {
      hops: [first, ...reversed.reverse()],
      parts: 1,
      totalAmountMsat: first.amountOutMsat,
      totalFeeMsat: (first.amountOutMsat - c.principalMsat) as Msat,
      totalTimeLock: first.cltvOut,
      builtAtHeight: c.blockHeight,
    };
  }
}
