import { atLeast, CapabilityUnsupported, checkIdentity, checkPubkey, recordOnline, type NodeCapability, type ProbeContext, type ProbeResult } from '../core/capabilities.js';
import { ambiguousStatus, LndError, TransportError } from '../core/errors.js';
import { parseInfo } from './types.js';
import type { LndRest } from './rest.js';

/** gRPC codes for a service the node does not run: NotFound from the gateway's unregistered route, Unimplemented. */
const SERVICE_ABSENT: ReadonlySet<number> = new Set([5, 12]);

/** Lightning service calls present in every LND version FluxWarden reads. */
const BASE: readonly NodeCapability[] = ['CHANNEL_READ', 'PAYMENT_READ', 'INVOICE_CREATE', 'INVOICE_CANCEL', 'FORWARDING_READ'];

/** `outgoing_chan_ids` and SendToRouteV2's `payment_addr` requirement start in 0.21 (release-notes-0.21.0.md). */
const ROUTE_CONTROL_SINCE = [0, 21] as const;

/**
 * An LND version as GetInfo reports it: "<major>.<minor>.<patch>[-<pre-release>][ commit=<id>]"
 * (build/version.go, rpcserver.go GetInfo). Anything else is unknown.
 */
export function parseLndVersion(raw: string): [number, number, number] | null {
  const match = /^([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,4})(?:-[0-9A-Za-z.]+)?(?: commit=\S*)?$/.exec(raw);
  if (match === null) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

/**
 * Connect-time probe: GetInfo for identity and network, then a router call that cannot answer
 * NotFound while the router service runs (GetMissionControlConfig), so a NotFound or
 * Unimplemented there means the service is absent, not that something was not found.
 * GetMissionControlConfig needs offchain:read (routerrpc/router_server.go macPermissions),
 * which FluxWarden's macaroon already holds for ListChannels and TrackPaymentV2.
 */
export async function probeLnd(rest: LndRest, context: ProbeContext): Promise<ProbeResult> {
  return (await probeLndWithAlias(rest, context)).result;
}

/** probeLnd, also returning the alias the identity call reported. */
export async function probeLndWithAlias(rest: LndRest, context: ProbeContext): Promise<{ result: ProbeResult; alias: string }> {
  const body = await rest.call('GET', '/v1/getinfo');
  await checkPubkey(body['identity_pubkey'], body['version'], context);
  const info = parseInfo(body);
  await checkIdentity('lnd', { pubkey: info.identityPubkey, network: info.network, version: info.version }, context);
  const version = parseLndVersion(info.version);
  if (version === null) throw new CapabilityUnsupported(`unknown LND version format ${JSON.stringify(info.version.slice(0, 80))}`);
  let router = true;
  try {
    await rest.call('GET', '/v2/router/mccfg');
  } catch (error) {
    if (!(error instanceof LndError) || error.grpcCode === undefined || !SERVICE_ABSENT.has(error.grpcCode)) throw error;
    // A gateway or proxy status relaying the code is the proxy's answer: the router was not reached.
    if (ambiguousStatus(error.httpStatus)) throw new TransportError(`router probe answered by a proxy with HTTP ${String(error.httpStatus)}`, 'response');
    router = false;
  }
  const capabilities = new Set<NodeCapability>(BASE);
  if (router) capabilities.add('PAYMENT_TRACK');
  if (router && atLeast(version, ROUTE_CONTROL_SINCE)) capabilities.add('EXPLICIT_ROUTE_CONTROL');
  const result = await recordOnline({
    pubkey: info.identityPubkey, network: info.network, version: info.version, blockHeight: info.blockHeight, syncedToChain: info.syncedToChain,
  }, capabilities, context);
  return { result, alias: info.alias };
}
