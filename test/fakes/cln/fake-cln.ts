// Scripted fake of Core Lightning v26.06.9's clnrest plugin. Every answer is a named behaviour
// with the upstream source it imitates; a request served without one is a harness failure.
import type { ServerResponse } from 'node:http';
import { type FakeServer, type Identity, type RecordedRequest, startHttpsFake } from '../https.js';

const CLN = 'https://github.com/ElementsProject/lightning/blob/v26.06.9/';
const REST = `${CLN}plugins/rest-plugin/src/`;

export const behaviours = {
  'rpc-result': { source: `${REST}main.rs#L149-L151; ${REST}handlers.rs#L228-L291; ${REST}handlers.rs#L463-L520 (201 Created with the JSON result)` },
  'rpc-error': { source: `${REST}handlers.rs#L279-L288; ${REST}structs.rs#L38-L54; ${CLN}cln-rpc/src/primitives.rs#L1110-L1117 (body {code, message, data})` },
  'unknown-command': { source: `${REST}handlers.rs#L282-L285; ${CLN}lightningd/jsonrpc.c#L1078 (JSONRPC2_METHOD_NOT_FOUND -32601)` },
  'rune-missing': { source: `${REST}shared.rs#L16-L27 (403, code 1501); ${CLN}common/jsonrpc_errors.h#L138` },
  'rune-invalid': { source: `${REST}shared.rs#L50-L58 (401, code 1502); ${CLN}common/jsonrpc_errors.h#L139` },
  'getinfo': { source: `${CLN}doc/schemas/getinfo.json#L1-L431` },
  'listpeerchannels': { source: `${CLN}doc/schemas/listpeerchannels.json#L1-L1876` },
  'listsendpays': { source: `${CLN}doc/schemas/listsendpays.json#L1-L453` },
  'listpays': { source: `${CLN}doc/schemas/listpays.json#L1-L300` },
  'listinvoices': { source: `${CLN}doc/schemas/listinvoices.json#L1-L408` },
  'listhtlcs': { source: `${CLN}doc/schemas/listhtlcs.json#L12-L157 (readonly completed HTLC history and bounded index/start/limit)` },
  'bkpr-listaccountevents': { source: `${CLN}doc/schemas/bkpr-listaccountevents.json#L1-L355` },
  'askrene-listlayers': { source: `${CLN}doc/schemas/askrene-listlayers.json#L1-L441` },
  'msat-string': { source: 'https://github.com/ElementsProject/lightning/blob/v26.06.9/doc/schemas/listpeerchannels.json#L182 (type msat, which some interfaces render as "<n>msat", cln#9283)' },
  'no-answer': { source: 'https://www.rfc-editor.org/rfc/rfc9112#section-9.5 (a server may hold a connection without answering)' },
  'proxy-status': { source: 'https://www.rfc-editor.org/rfc/rfc9110#section-15.6.3 (502 from a gateway in front of clnrest); https://www.rfc-editor.org/rfc/rfc9110#section-15.5.5 (404 from a proxy or a wrong path)' + '; ' + 'https://www.rfc-editor.org/rfc/rfc9110#section-15.6.3 (502 from a gateway in front of clnrest, no lightningd body); https://www.rfc-editor.org/rfc/rfc9110#section-15.6.5 (504)' },
  'oversized-body': { source: `${REST}handlers.rs#L463-L520 (answers are not bounded on the server side)` },
  'askrene-create-layer': { source: `${CLN}plugins/askrene/askrene.c#L1349-L1387; ${CLN}doc/schemas/askrene-create-layer.json#L10-L309` + '; ' + `${CLN}doc/schemas/askrene-create-layer.json#L10-L307 (request layer, response layers[])` },
  'askrene-layer-exists': { source: `${CLN}plugins/askrene/askrene.c#L1371-L1376 (a non-persistent layer of the same name: -32602 "Layer already exists")` },
  'askrene-disable-node': { source: `${CLN}plugins/askrene/askrene.c#L1325-L1347; ${CLN}doc/schemas/askrene-disable-node.json#L10-L50` + '; ' + `${CLN}doc/schemas/askrene-disable-node.json#L10-L48 (request layer and node, empty response)` },
  'askrene-update-channel': { source: `${CLN}plugins/askrene/askrene.c#L1092-L1125; ${CLN}doc/schemas/askrene-update-channel.json#L10-L83` + '; ' + `${CLN}doc/schemas/askrene-update-channel.json#L10-L81 (request layer, short_channel_id_dir, enabled, empty response)` },
  'askrene-remove-layer': { source: `${CLN}plugins/askrene/askrene.c#L1389-L1407; ${CLN}doc/schemas/askrene-remove-layer.json#L10-L40` + '; ' + `${CLN}doc/schemas/askrene-remove-layer.json#L10-L38 (request layer, empty response)` },
  'askrene-unknown-layer': { source: `${CLN}plugins/askrene/askrene.c#L133-L150 (param_known_layer: -32602 "Unknown layer")` },
  'getroutes': { source: `${CLN}doc/schemas/getroutes.json#L19-L233; ${CLN}CHANGELOG.md#L207 (node_id_in, node_id_out, amount_in_msat, amount_out_msat, cltv_in, cltv_out)` + '; ' + `${CLN}doc/schemas/getroutes.json#L19-L86 (request); ${CLN}doc/schemas/getroutes.json#L87-L233 (path items short_channel_id_dir, node_id_in, node_id_out, amount_in_msat, amount_out_msat, cltv_in, cltv_out since v26.06)` },
  'getroutes-legacy': { source: `${CLN}CHANGELOG.md#L233 (next_node_id, amount_msat and delay are node_id_out, amount_in_msat and cltv_in); ${CLN}doc/schemas/getroutes.json#L196-L229` },
  'getroutes-no-route': { source: `${CLN}doc/schemas/getroutes.json#L234-L240; ${CLN}common/jsonrpc_errors.h#L40; ${CLN}plugins/askrene/askrene.c#L748` + '; ' + `${CLN}common/jsonrpc_errors.h#L40 (PAY_ROUTE_NOT_FOUND 205); ${CLN}doc/schemas/getroutes.json#L234-L255` },
  'getroutes-too-expensive': { source: `${CLN}doc/schemas/getroutes.json#L234-L240; ${CLN}common/jsonrpc_errors.h#L41` },
  'getroutes-excessive-delays': { source: `${CLN}plugins/askrene/child/mcf.c#L1409-L1416 (finalcltv + flows_worst_delay > maxdelay returns error 206)` },
  'listchannels': { source: `${CLN}doc/schemas/listchannels.json#L14-L189 (one entry per direction, keyed by source)` + '; ' + `${CLN}doc/schemas/listchannels.json#L38-L170 (channels[] source, destination, short_channel_id, direction, base_fee_millisatoshi, fee_per_millionth, delay)` },
  'malformed': { source: `${REST}handlers.rs#L463-L520 (only serialised JSON is a clnrest answer, so anything else is not CLN's)` },
  'invoice': { source: `${CLN}doc/schemas/invoice.json#L9-L105 (request amount_msat, label, description, expiry, preimage, cltv); ${CLN}doc/schemas/invoice.json#L106-L178 (response payment_hash, payment_secret, bolt11, expires_at, created_index)` },
  'sendpay': { source: `${CLN}doc/schemas/sendpay.json#L151-L351 (response status pending, or complete when already sent previously); ${CLN}lightningd/pay.c#L1417-L1470 (param_route_hops); ${CLN}lightningd/pay.c#L786-L790 (first HTLC expiry = network height + 1 + route[0] cltv_out); ${CLN}lightningd/pay.c#L1212-L1246 (onion expiries = network height + 1 + cltv_out)` },
  'sendpay-first-hop-refused': { source: `${CLN}lightningd/pay.c#L1113-L1151 (PAY_TRY_OTHER_ROUTE 204 when no channel to the first peer is found or the HTLC could not be added, both before wallet_add_payment at L1153, so no payment is stored)` },
  'sendpay-params-refused': { source: `${CLN}lightningd/pay.c#L1580-L1596 (json_sendpay param_check fails before any payment is stored or sent); ${CLN}common/jsonrpc_errors.h#L14 (JSONRPC2_INVALID_PARAMS -32602)` },
  'sendpay-already-complete': { source: `${CLN}lightningd/pay.c#L928-L955 (check_progress returns a complete payment with the same amount and destination as the succeeded payment, cln#9517)` },
  'waitsendpay-complete': { source: `${CLN}doc/schemas/waitsendpay.json#L49-L204 (response status complete, amount_msat, amount_sent_msat, payment_preimage)` },
  'waitsendpay-timeout': { source: `${CLN}doc/schemas/waitsendpay.json#L23-L30 (timeout, 200 when the payment has neither succeeded nor failed); ${CLN}common/jsonrpc_errors.h#L35 (PAY_IN_PROGRESS 200)` },
  'waitsendpay-failure': { source: `${CLN}doc/schemas/waitsendpay.json#L205-L234 (errors -1, 202, 203, 204, 209); ${CLN}common/jsonrpc_errors.h#L35-L44` },
  'waitsendpay-no-such-payment': { source: `${CLN}doc/schemas/waitsendpay.json#L205-L234 (208 a payment for payment_hash was never made); ${CLN}common/jsonrpc_errors.h#L43` },
  'delinvoice': { source: `${CLN}doc/schemas/delinvoice.json#L9-L273 (request label and status, response the deleted invoice)` },
  'delinvoice-status-mismatch': { source: `${CLN}doc/schemas/delinvoice.json#L274-L293 (906 status does not match, data current_status and expected_status); ${CLN}common/jsonrpc_errors.h#L104` },
  'delinvoice-not-found': { source: `${CLN}doc/schemas/delinvoice.json#L274-L293 (905 no invoice with that label); ${CLN}common/jsonrpc_errors.h#L103` },
  'xpay-or-pay': { source: `${CLN}plugins/xpay/xpay.c#L1833 (Self-pay shortcut); ${CLN}plugins/pay.c#L477 (selfpay, never called by a rebalance, registered so that a call is recorded)` },
  'connection-reset': { source: 'https://www.rfc-editor.org/rfc/rfc9112#section-9.6 (the connection closes after the request arrived and before any response byte)' },
} as const satisfies Record<string, { source: string }>;

export type BehaviourId = keyof typeof behaviours;

export interface ClnContext { readonly request: RecordedRequest; readonly response: ServerResponse; readonly params: Record<string, unknown> }
export type ClnHandler = (context: ClnContext, fake: FakeCln) => void;

export interface FakeCln extends FakeServer {
  readonly served: { method: string; behaviour: BehaviourId }[];
  /** Parameters of each call that passed the rune check, in order. */
  readonly calls: { method: string; params: Record<string, unknown> }[];
  result: (context: ClnContext, behaviour: BehaviourId, value: unknown) => void;
  rpcError: (context: ClnContext, behaviour: BehaviourId, code: number, message: string, data?: unknown) => void;
  raw: (context: ClnContext, behaviour: BehaviourId, status: number, body: string) => void;
  /** Closes the connection after the whole request arrived, without any response byte. */
  reset: (context: ClnContext, behaviour: BehaviourId) => void;
  hold: (context: ClnContext, behaviour: BehaviourId) => void;
}

export async function startFakeCln(options: { rune: string; methods: Partial<Record<string, ClnHandler>>; identity?: Identity; tls?: import('../https.js').TlsMaterial }): Promise<FakeCln> {
  const served: { method: string; behaviour: BehaviourId }[] = [];
  const calls: { method: string; params: Record<string, unknown> }[] = [];
  const holder: { fake?: FakeCln } = {};
  const send = (context: ClnContext, behaviour: BehaviourId, status: number, body: string): void => {
    served.push({ method: context.request.url, behaviour });
    context.response.writeHead(status, { 'Content-Type': 'application/json' });
    context.response.end(body);
  };
  const methods = {
    result: (context: ClnContext, behaviour: BehaviourId, value: unknown) => { send(context, behaviour, 201, JSON.stringify(value)); },
    rpcError: (context: ClnContext, behaviour: BehaviourId, code: number, message: string, data: unknown = null) => {
      send(context, behaviour, code === -32601 ? 404 : 500, JSON.stringify({ code, message, data }));
    },
    raw: (context: ClnContext, behaviour: BehaviourId, status: number, body: string) => { send(context, behaviour, status, body); },
    reset: (context: ClnContext, behaviour: BehaviourId) => { served.push({ method: context.request.url, behaviour }); context.response.socket?.destroy(); },
    hold: (context: ClnContext, behaviour: BehaviourId) => { served.push({ method: context.request.url, behaviour }); },
  };
  const server = await startHttpsFake((request, response) => {
    const method = /^\/v1\/([^/?]+)$/.exec(request.url.split('?')[0] ?? '')?.[1] ?? '';
    let params: Record<string, unknown> = {};
    try {
      const parsed: unknown = request.body === '' ? {} : JSON.parse(request.body);
      if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) params = parsed as Record<string, unknown>;
    } catch { params = {}; }
    const context: ClnContext = { request, response, params };
    const rune = request.headers['rune'];
    if (rune === undefined) { send(context, 'rune-missing', 403, JSON.stringify({ code: 1501, message: 'Not authorized: Missing rune', data: null })); return; }
    if (rune !== options.rune) { send(context, 'rune-invalid', 401, JSON.stringify({ code: 1502, message: 'Rune is not valid', data: null })); return; }
    const handler = options.methods[method];
    if (handler === undefined || holder.fake === undefined || request.method !== 'POST') { methods.rpcError(context, 'unknown-command', -32601, `Unknown command '${method}'`); return; }
    calls.push({ method, params });
    handler(context, holder.fake);
  }, options.identity, options.tls);
  const fake: FakeCln = { ...server, served, calls, ...methods, requests: server.requests, connections: server.connections, close: server.close, host: server.host, port: server.port };
  holder.fake = fake;
  return fake;
}
