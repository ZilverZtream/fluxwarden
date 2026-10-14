// Route assessment over LND's REST interface, read calls only: QueryRoutes for the path and GetChanInfo
// for each forwarding policy (lnrpc/lightning.proto and lightning.yaml at v0.21.4-beta).
import { hexToBase64 } from '../core/encoding.js';
import { LndError, ProtocolError } from '../core/errors.js';
import { array, asObject, identifier, integer, optionalObject, smallInteger, string, type JsonObject } from '../core/json.js';
import type { Msat } from '../core/money.js';
import type { CandidateRoute, HopPolicy, NoRoute, RouteConstraints, RouteHop } from '../core/route.js';
import { chanIdToScid, scidToChanId } from '../core/scid.js';
import type { LndRest } from './rest.js';

/** Blocks kept back from cltv_limit for the padding LND's send path adds to the route's timelock. */
const SEND_PADDING = 3;

/** errNoPathFound (routing/payment_session.go); also the answer when every path is over the fee limit. */
const NO_PATH = 'unable to find a path to destination';
const GRPC_UNKNOWN = 2;

const PUBKEY = /^0[23][0-9a-f]{64}$/;

interface LndHop {
  readonly chanId: string;
  readonly pubKey: string;
  readonly forwardMsat: bigint;
  readonly feeMsat: bigint;
  readonly expiry: number;
}

function pubkey(source: JsonObject, key: string): string {
  const value = string(source, key);
  if (!PUBKEY.test(value)) throw new ProtocolError(`${key} is not a public key`);
  return value;
}

/** Only the msat fields are read; amt_to_forward, fee and chan_capacity are removed in 0.22. */
function parseHop(value: unknown, index: number): LndHop {
  const hop = asObject(value, `hops[${String(index)}]`);
  return {
    chanId: identifier(hop, 'chan_id'),
    pubKey: pubkey(hop, 'pub_key'),
    forwardMsat: integer(hop, 'amt_to_forward_msat'),
    feeMsat: integer(hop, 'fee_msat'),
    expiry: smallInteger(hop, 'expiry'),
  };
}

function parsePolicy(policy: JsonObject): HopPolicy {
  const max = integer(policy, 'max_htlc_msat');
  return {
    baseFeeMsat: integer(policy, 'fee_base_msat') as Msat,
    feePpm: integer(policy, 'fee_rate_milli_msat'),
    cltvExpiryDelta: smallInteger(policy, 'time_lock_delta'),
    minHtlcMsat: integer(policy, 'min_htlc') as Msat,
    maxHtlcMsat: max === 0n ? null : max as Msat,
  };
}

export class LndRouteApi {
  readonly #rest: LndRest;

  constructor(rest: LndRest) {
    this.#rest = rest;
  }

  /**
   * One QueryRoutes from our node back to itself, out over the source channel and in from the in-peer,
   * normalized to hop-end amounts and expiries. Validation is the caller's (core validateRoute).
   */
  async buildCircularRoute(c: RouteConstraints): Promise<CandidateRoute | NoRoute> {
    if (!PUBKEY.test(c.selfPubkey) || !PUBKEY.test(c.outPeer) || !PUBKEY.test(c.inPeer)) throw new RangeError('route constraints name an invalid public key');
    const cltvLimit = c.maxCltvDelta - SEND_PADDING;
    if (!Number.isSafeInteger(cltvLimit) || cltvLimit <= 0) throw new RangeError('max CLTV delta leaves no room for the send padding');
    // The path amount is in sat and overrides the body, so it stays 0 and the msat amount travels in the body.
    const body = {
      amt_msat: c.principalMsat.toString(),
      final_cltv_delta: c.finalCltvDelta,
      fee_limit: { fixed_msat: c.maxFeeMsat.toString() },
      outgoing_chan_ids: [scidToChanId(c.sourceScid)],
      last_hop_pubkey: hexToBase64(c.inPeer),
      cltv_limit: cltvLimit,
      ignored_pairs: [
        { from: hexToBase64(c.outPeer), to: hexToBase64(c.selfPubkey) },
        { from: hexToBase64(c.selfPubkey), to: hexToBase64(c.inPeer) },
      ],
      use_mission_control: true,
    };
    let answer: JsonObject;
    try {
      answer = await this.#rest.call('POST', `/v1/graph/routes/${c.selfPubkey}/0`, body);
    } catch (error) {
      if (error instanceof LndError && error.grpcCode === GRPC_UNKNOWN && error.message.includes(NO_PATH)) {
        return { kind: 'no-route', code: 'NO_FEASIBLE_ROUTE', reason: error.message };
      }
      throw error;
    }
    const routes = array(answer, 'routes');
    if (routes.length !== 1) throw new ProtocolError(`QueryRoutes answered ${String(routes.length)} routes, expected one`);
    const route = asObject(routes[0], 'routes[0]');
    const lndHops = array(route, 'hops').map(parseHop);
    if (lndHops.length === 0) throw new ProtocolError('QueryRoutes answered a route without hops');
    const totalTimeLock = smallInteger(route, 'total_time_lock');

    const hops: RouteHop[] = [];
    for (let k = 0; k < lndHops.length; k += 1) {
      const hop = lndHops[k];
      if (hop === undefined) throw new ProtocolError('route hop is missing');
      const scid = chanIdToScid(hop.chanId);
      if (scid === null) throw new ProtocolError('route hop names channel id 0');
      const previous = k === 0 ? undefined : lndHops[k - 1];
      const policy = previous === undefined ? null : await this.#sendingPolicy(hop.chanId, previous.pubKey);
      hops.push({
        scid,
        nodeIdOut: hop.pubKey,
        amountOutMsat: (hop.forwardMsat + hop.feeMsat) as Msat,
        cltvOut: previous === undefined ? totalTimeLock : previous.expiry,
        policy,
      });
    }
    const first = hops[0];
    const last = hops[hops.length - 1];
    if (first === undefined || last === undefined) throw new ProtocolError('route hop is missing');
    return {
      hops,
      parts: 1,
      totalAmountMsat: first.amountOutMsat,
      totalFeeMsat: (first.amountOutMsat - last.amountOutMsat) as Msat,
      totalTimeLock: first.cltvOut,
      builtAtHeight: c.blockHeight,
    };
  }

  /** GetChanInfo: the policy set by `sender`, the node that forwards over the channel (null when it has none). */
  async #sendingPolicy(chanId: string, sender: string): Promise<HopPolicy | null> {
    const edge = await this.#rest.call('GET', `/v1/graph/edge/${chanId}`);
    if (identifier(edge, 'channel_id') !== chanId) throw new ProtocolError('channel edge answer names another channel');
    const side = string(edge, 'node1_pub') === sender ? 'node1_policy' : 'node2_policy';
    const policy = optionalObject(edge, side);
    return policy === undefined ? null : parsePolicy(policy);
  }
}
