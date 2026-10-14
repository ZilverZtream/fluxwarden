import { atLeast, CapabilityUnsupported, checkIdentity, checkPubkey, recordOnline, type NodeCapability, type ProbeContext, type ProbeResult } from '../core/capabilities.js';
import { ambiguousStatus, ClnError, TransportError } from '../core/errors.js';
import type { ClnRest } from './rest.js';
import { parseClnVersion, parseInfo } from './types.js';

/** JSON-RPC "method not found": the plugin that would provide the command is not running (lightningd/jsonrpc.c). */
const METHOD_NOT_FOUND = -32601;

/** lightningd built-in commands present in every CLN version FluxWarden reads. */
const BASE: readonly NodeCapability[] = ['CHANNEL_READ', 'PAYMENT_READ', 'PAYMENT_TRACK', 'INVOICE_CREATE', 'INVOICE_CANCEL'];

/** Since v26.06 sendpay accepts getroutes path items with hop-end fields (CHANGELOG [26.06], #9110). */
const LAYER_ROUTING_SINCE = [26, 6] as const;

/** Connect-time probe: getinfo for identity and network, then askrene-listlayers, a read-only askrene command. */
export async function probeCln(rest: ClnRest, context: ProbeContext): Promise<ProbeResult> {
  return (await probeClnWithAlias(rest, context)).result;
}

/** Whether getinfo carries neither sync warning (doc/schemas/getinfo.json warning_bitcoind_sync, warning_lightningd_sync). */
export function clnSynced(info: { warningBitcoindSync: string | null; warningLightningdSync: string | null }): boolean {
  return info.warningBitcoindSync === null && info.warningLightningdSync === null;
}

/** probeCln, also returning the alias the identity call reported. */
export async function probeClnWithAlias(rest: ClnRest, context: ProbeContext): Promise<{ result: ProbeResult; alias: string }> {
  const body = await rest.call('getinfo');
  await checkPubkey(body['id'], body['version'], context);
  const info = parseInfo(body);
  await checkIdentity('cln', { pubkey: info.id, network: info.network, version: info.version }, context);
  const version = parseClnVersion(info.version);
  if (version === null) throw new CapabilityUnsupported(`unknown CLN version format ${JSON.stringify(info.version.slice(0, 80))}`);
  let askrene = true;
  try {
    await rest.call('askrene-listlayers');
  } catch (error) {
    if (!(error instanceof ClnError) || error.code !== METHOD_NOT_FOUND) throw error;
    if (ambiguousStatus(error.httpStatus)) throw new TransportError(`askrene probe answered by a proxy with HTTP ${String(error.httpStatus)}`, 'response');
    askrene = false;
  }
  const capabilities = new Set<NodeCapability>(BASE);
  if (askrene && atLeast([version.year, version.month, version.patch], LAYER_ROUTING_SINCE)) capabilities.add('ASKRENE_LAYER_ROUTING');
  const result = await recordOnline({
    pubkey: info.id, network: info.network, version: info.version, blockHeight: info.blockheight, syncedToChain: clnSynced(info),
  }, capabilities, context);
  return { result, alias: info.alias };
}
