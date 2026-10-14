// Scripted fake of LND v0.21.4-beta's REST gateway (grpc-gateway v2.16.0). Every answer the
// fake can give is a named behaviour with the upstream source it imitates; a request served
// without a registered behaviour is a harness failure.
import type { ServerResponse } from 'node:http';
import { type FakeServer, type Identity, type RecordedRequest, startHttpsFake } from '../https.js';

const LND = 'https://github.com/lightningnetwork/lnd/blob/v0.21.4-beta/';
const GATEWAY = 'https://github.com/grpc-ecosystem/grpc-gateway/blob/v2.16.0/';
const GATEWAY_V1 = 'https://github.com/grpc-ecosystem/grpc-gateway/blob/v1.16.0/';

export const behaviours = {
  'getinfo': { source: `${LND}lnrpc/lightning.yaml#L45-L46; ${LND}lnrpc/lightning.proto#L1920-L2001; ${LND}rpcserver.go#L3419-L3424` },
  'listchannels': { source: `${LND}lnrpc/lightning.yaml#L53-L54; ${LND}lnrpc/lightning.proto#L1383-L1588` },
  'pendingchannels': { source: `${LND}lnrpc/lightning.yaml#L51-L52; ${LND}lnrpc/lightning.proto#L2728-L2969` },
  'listpayments': { source: `${LND}lnrpc/lightning.yaml#L93-L94; ${LND}lnrpc/lightning.proto#L4293-L4472; ${LND}rpcserver.go#L6983-L7030` },
  'forwardinghistory': { source: `${LND}lnrpc/lightning.yaml#L125-L127; ${LND}lnrpc/lightning.proto#L4718-L4813; ${LND}rpcserver.go#L7587-L7640` },
  'lookupinvoice': { source: `${LND}lnrpc/lightning.yaml#L83-L84; ${LND}rpcserver.go#L5911-L5945; ${LND}lnrpc/lightning.proto#L3820-L4028` },
  'lookupinvoice-not-found': { source: `${LND}rpcserver.go#L5939-L5945; ${LND}invoices/errors.go#L79` },
  'lookupinvoice-bad-hash': { source: `${LND}rpcserver.go#L5922-L5935` },
  'trackpayment-stream': { source: `${LND}lnrpc/routerrpc/router.yaml#L9-L10; ${GATEWAY}runtime/handler.go#L19-L80` },
  'trackpayment-not-initiated': { source: `${LND}lnrpc/routerrpc/router_server.go#L1545-L1546; ${GATEWAY}runtime/handler.go#L203-L208` },
  'stream-error-frame': { source: `${GATEWAY}runtime/handler.go#L203-L227` },
  'stream-error-frame-legacy': { source: `${GATEWAY_V1}runtime/handler.go#L183-L212 (errorChunk with grpc_code, http_code, message, http_status); https://github.com/lightningnetwork/lnd/issues/5237` },
  'stream-code-message-frame': { source: 'https://github.com/lightningnetwork/lnd/issues/6751 (send and track answer {code, message} inside the stream)' },
  'stream-blank-lines': { source: `${GATEWAY}runtime/handler.go#L40-L46 (the delimiter is configurable, and an empty line carries no message)` },
  'stream-stall': { source: 'https://github.com/alexbosworth/lightning/issues/133 (a gateway keeps the connection open and stops forwarding frames)' },
  'stream-cut': { source: `${GATEWAY}runtime/handler.go#L19-L80 (one flushed chunk per message); https://www.rfc-editor.org/rfc/rfc9112#section-7.1 (an unterminated chunked body)` },
  'track-hash-type-mismatch': { source: `${LND}lnrpc/routerrpc/router.pb.gw.go#L63-L81; ${GATEWAY}runtime/convert.go#L181-L190` },
  'track-hash-length': { source: `${LND}lntypes/hash.go#L25-L29; ${LND}lnrpc/routerrpc/router_server.go#L1519-L1522` },
  'router-mccfg': { source: `${LND}lnrpc/routerrpc/router.yaml#L24-L25; ${LND}lnrpc/routerrpc/router_server.go#L119-L122` },
  'grpc-error': { source: `${GATEWAY}runtime/errors.go#L36-L75 (HTTPStatusFromCode, body google.rpc.Status); ${LND}lnrpc/rpc_utils.go#L47-L50 (EmitUnpopulated)` },
  'route-not-found': { source: `${GATEWAY}runtime/mux.go#L451; ${GATEWAY}runtime/errors.go#L170-L180` },
  'method-not-allowed': { source: `${GATEWAY}runtime/mux.go#L445; ${GATEWAY}runtime/errors.go#L170-L180` },
  'macaroon-missing': { source: `${LND}macaroons/service.go#L354-L362` },
  'macaroon-permission-denied': { source: `${LND}macaroons/service.go#L235-L254; https://github.com/go-macaroon-bakery/macaroon-bakery/blob/v2.0.1/bakery/error.go#L16-L18` },
  'macaroon-mismatch': { source: `${LND}macaroons/service.go#L185-L260 (ValidateMacaroon, CheckMacAuth: plain errors reach the gateway as gRPC 2)` },
  'proxy-status': { source: 'https://www.rfc-editor.org/rfc/rfc9110#section-15.6.3 (502 from a gateway relaying the upstream body); https://www.rfc-editor.org/rfc/rfc9110#section-15.6.5 (504); https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2 (401); https://www.rfc-editor.org/rfc/rfc9110#section-15.5.4 (403)' },
  'oversized-body': { source: `${GATEWAY}runtime/handler.go#L19-L80 (bodies and stream messages are unbounded on the server side)` },
  'no-answer': { source: 'https://www.rfc-editor.org/rfc/rfc9112#section-9.5 (a server may hold a connection without answering)' },
  'non-json': { source: `${LND}lnd.go#L975-L995 (only the JSON marshaler is registered, so anything else is not LND's answer)` },
  'addinvoice': { source: `${LND}lnrpc/lightning.yaml#L78-L80; ${LND}lnrpc/lightning.proto#L3820-L3870 (Invoice request: memo, r_preimage, value_msat, expiry); ${LND}lnrpc/lightning.proto#L4134-L4158 (AddInvoiceResponse r_hash, payment_request, add_index, payment_addr)` },
  'sendtoroute-attempt': { source: `${LND}lnrpc/routerrpc/router.yaml#L16-L18; ${LND}lnrpc/routerrpc/router_server.go#L1081-L1128 (the stored HTLCAttempt is returned even when the send also failed); ${LND}lnrpc/lightning.proto#L4368-L4400` },
  'sendtoroute-already-exists': { source: `${LND}lnrpc/routerrpc/router_server.go#L1130-L1144 (ErrPaymentExists, ErrPaymentInFlight, ErrAlreadyPaid -> codes.AlreadyExists); ${LND}payments/db/errors.go#L6-L15` },
  'sendtoroute-refused': { source: `${LND}lnrpc/routerrpc/router_server.go#L1084-L1086 (plain error before any attempt -> gRPC 2 Unknown)` },
  'sendpayment-v2': { source: `${LND}lnrpc/routerrpc/router.yaml#L6-L8 (never called by a rebalance, registered so that a call is recorded and refused)` },
  'cancelinvoice': { source: `${LND}lnrpc/invoicesrpc/invoices.yaml#L8-L10; ${LND}lnrpc/invoicesrpc/invoices_server.go#L318-L334 (empty CancelInvoiceResp); ${LND}invoices/invoiceregistry.go#L1455-L1505 (already canceled is success, and an ACCEPTED invoice is left as it is while success is returned)` },
  'cancelinvoice-settled': { source: `${LND}invoices/update_invoice.go#L671-L673; ${LND}invoices/errors.go#L9-L11 (invoice already settled, a plain error -> gRPC 2)` },
  'cancelinvoice-not-found': { source: `${LND}invoices/errors.go#L77-L79 (unable to locate invoice, a plain error -> gRPC 2)` },
  'reset-after-request': { source: 'https://www.rfc-editor.org/rfc/rfc9112#section-9.6 (the connection closes after the request arrived and before any response byte)' },
  'queryroutes': { source: `${LND}lnrpc/lightning.yaml#L105-L109; ${LND}lnrpc/lightning.proto#L3242-L3254 (one route); ${LND}lnrpc/routerrpc/router_backend.go#L207-L237` },
  'queryroutes-no-path': { source: `${LND}routing/payment_session.go#L87-L88 (errNoPathFound text); ${LND}routing/pathfind.go#L823-L825 (a path over the fee limit is dropped, so the answer is the same); ${LND}lnrpc/routerrpc/router_backend.go#L218-L221 (a plain error, gRPC 2)` },
  'queryroutes-bad-body': { source: `${LND}lnrpc/lightning.pb.gw.go#L1721-L1723 (body decode failure is InvalidArgument); ${LND}lnrpc/rpc_utils.go#L55-L57 (unknown fields are not discarded)` },
  'queryroutes-amount': { source: `${LND}lnrpc/lightning.pb.gw.go#L1742-L1750 (the path amt overrides the body); ${LND}lnrpc/marshall_utils.go#L58-L61 (sat and msat are mutually exclusive)` },
  'getchaninfo': { source: `${LND}lnrpc/lightning.yaml#L101-L102; ${LND}lnrpc/lightning.proto#L3481-L3496 (RoutingPolicy); ${LND}lnrpc/lightning.proto#L3530-L3558 (ChannelEdge)` },
} as const satisfies Record<string, { source: string }>;

export type BehaviourId = keyof typeof behaviours;

/** HTTPStatusFromCode, grpc-gateway v2.16.0 runtime/errors.go#L36-L75. */
export function httpStatusFromCode(code: number): number {
  const table: Record<number, number> = { 0: 200, 1: 499, 2: 500, 3: 400, 4: 504, 5: 404, 6: 409, 7: 403, 8: 429, 9: 400, 10: 409, 11: 400, 12: 501, 13: 500, 14: 503, 15: 500, 16: 401 };
  return table[code] ?? 500;
}

export interface LndContext {
  readonly request: RecordedRequest;
  readonly response: ServerResponse;
  readonly query: URLSearchParams;
  /** Decoded path parameters; `payment_hash` and `r_hash_str` arrive as 64 hex characters after LND's own checks. */
  readonly params: Readonly<Record<string, string>>;
}

export type LndRoute = (context: LndContext, fake: FakeLnd) => void;

export interface FakeLnd extends FakeServer {
  readonly served: { url: string; behaviour: BehaviourId }[];
  answer: (context: LndContext, behaviour: BehaviourId, body: unknown) => void;
  grpcError: (context: LndContext, behaviour: BehaviourId, code: number, message: string) => void;
  raw: (context: LndContext, behaviour: BehaviourId, status: number, body: string) => void;
  /** Writes each chunk as its own write, then ends the chunked body or cuts the connection. */
  /** `hold` keeps the connection open after the chunks without ending the body; `intervalMs` spaces the writes. */
  stream: (context: LndContext, behaviour: BehaviourId, chunks: readonly (string | Buffer)[], end: 'finish' | 'cut' | 'hold', intervalMs?: number) => void;
  hold: (context: LndContext, behaviour: BehaviourId) => void;
  /** Closes the connection after the whole request arrived, without any response byte. */
  reset: (context: LndContext, behaviour: BehaviourId) => void;
}

const templates: readonly (readonly [string, string])[] = [
  ['GET', '/v1/getinfo'], ['GET', '/v1/channels'], ['GET', '/v1/channels/pending'], ['GET', '/v1/payments'],
  ['POST', '/v1/switch'], ['GET', '/v1/invoice/{r_hash_str}'], ['GET', '/v2/router/track/{payment_hash}'],
  ['GET', '/v2/router/mccfg'], ['POST', '/v1/invoices'], ['POST', '/v2/router/route/send'], ['POST', '/v2/router/send'],
  ['POST', '/v2/invoices/cancel'], ['POST', '/v1/graph/routes/{pub_key}/{amt}'], ['GET', '/v1/graph/edge/{chan_id}'],
  ['POST', '/v2/router/route'],
];

function match(template: string, path: string): Record<string, string> | null {
  const want = template.split('/'), got = path.split('/');
  if (want.length !== got.length) return null;
  const params: Record<string, string> = {};
  for (const [index, part] of want.entries()) {
    const value = got[index] ?? '';
    if (part.startsWith('{')) { if (value === '') return null; params[part.slice(1, -1)] = value; } else if (part !== value) return null;
  }
  return params;
}

const STD = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const URL_SAFE = /^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=)?$/;

/** runtime.Bytes: Go's padded StdEncoding, then padded URLEncoding (grpc-gateway v2.16.0 runtime/convert.go#L181-L190). */
function gatewayBytes(value: string): Buffer | null {
  if (STD.test(value)) return Buffer.from(value, 'base64');
  if (URL_SAFE.test(value)) return Buffer.from(value, 'base64url');
  return null;
}

export async function startFakeLnd(options: { macaroonHex: string; routes: Partial<Record<string, LndRoute>>; identity?: Identity }): Promise<FakeLnd> {
  const served: { url: string; behaviour: BehaviourId }[] = [];
  const holder: { fake?: FakeLnd } = {};
  const attribute = (context: LndContext, behaviour: BehaviourId): void => { served.push({ url: context.request.url, behaviour }); };
  const send = (context: LndContext, behaviour: BehaviourId, status: number, body: string): void => {
    attribute(context, behaviour);
    context.response.writeHead(status, { 'Content-Type': 'application/json' });
    context.response.end(body);
  };
  const methods = {
    answer: (context: LndContext, behaviour: BehaviourId, body: unknown) => { send(context, behaviour, 200, JSON.stringify(body)); },
    grpcError: (context: LndContext, behaviour: BehaviourId, code: number, message: string) => {
      send(context, behaviour, httpStatusFromCode(code), JSON.stringify({ code, message, details: [] }));
    },
    raw: (context: LndContext, behaviour: BehaviourId, status: number, body: string) => { send(context, behaviour, status, body); },
    stream: (context: LndContext, behaviour: BehaviourId, chunks: readonly (string | Buffer)[], end: 'finish' | 'cut' | 'hold', intervalMs = 0) => {
      attribute(context, behaviour);
      const response = context.response;
      response.writeHead(200, { 'Content-Type': 'application/json', 'Transfer-Encoding': 'chunked' });
      response.flushHeaders();
      const write = async (): Promise<void> => {
        for (const chunk of chunks) {
          if (response.destroyed) return;
          await new Promise<void>(resolve => { response.write(chunk, () => { resolve(); }); });
          await new Promise<void>(resolve => { if (intervalMs > 0) setTimeout(resolve, intervalMs); else setImmediate(resolve); });
        }
        if (end === 'finish') response.end();
        else if (end === 'cut') setTimeout(() => { response.socket?.destroy(); }, 20);
      };
      void write();
    },
    hold: (context: LndContext, behaviour: BehaviourId) => { attribute(context, behaviour); },
    reset: (context: LndContext, behaviour: BehaviourId) => { attribute(context, behaviour); context.response.socket?.destroy(); },
  };
  const server = await startHttpsFake((request, response) => {
    const url = new URL(request.url, 'https://fake.invalid');
    // Legacy unescaping: Go decodes the whole path before the mux splits it (runtime/mux.go#L311).
    let path: string;
    try { path = decodeURIComponent(url.pathname); } catch { path = url.pathname; }
    const base: LndContext = { request, response, query: url.searchParams, params: {} };
    let found: { method: string; template: string; params: Record<string, string> } | undefined;
    let otherMethod = false;
    for (const [method, template] of templates) {
      const params = match(template, path);
      if (params === null) continue;
      if (method === request.method) { found = { method, template, params }; break; }
      otherMethod = true;
    }
    if (found === undefined) {
      if (otherMethod) methods.grpcError(base, 'method-not-allowed', 12, 'Method Not Allowed');
      else methods.grpcError(base, 'route-not-found', 5, 'Not Found');
      return;
    }
    const params = { ...found.params };
    let trackHash: Buffer | undefined;
    if (found.template.endsWith('{payment_hash}')) {
      // The gateway converts the path parameter before the RPC runs (router.pb.gw.go#L63-L81).
      const bytes = gatewayBytes(params['payment_hash'] ?? '');
      if (bytes === null) { methods.grpcError(base, 'track-hash-type-mismatch', 3, 'type mismatch, parameter: payment_hash, error: illegal base64 data at input byte 0'); return; }
      trackHash = bytes;
    }
    const macaroon = request.headers['grpc-metadata-macaroon'];
    if (macaroon === undefined) { methods.grpcError(base, 'macaroon-missing', 2, 'expected 1 macaroon, got 0'); return; }
    if (macaroon !== options.macaroonHex) { methods.grpcError(base, 'macaroon-mismatch', 2, 'verification failed: signature mismatch after caveat verification'); return; }
    if (trackHash !== undefined) {
      if (trackHash.length !== 32) { methods.grpcError(base, 'track-hash-length', 2, `invalid hash length of ${String(trackHash.length)}, want 32`); return; }
      params['payment_hash'] = trackHash.toString('hex');
    }
    if (found.template.endsWith('{r_hash_str}')) {
      const text = params['r_hash_str'] ?? '';
      if (!/^(?:[0-9a-fA-F]{2})*$/.test(text)) { methods.grpcError(base, 'lookupinvoice-bad-hash', 2, 'encoding/hex: invalid byte'); return; }
      if (text.length !== 64) { methods.grpcError(base, 'lookupinvoice-bad-hash', 2, `payment hash must be exactly 32 bytes, is instead ${String(text.length / 2)}`); return; }
      params['r_hash_str'] = text.toLowerCase();
    }
    const context: LndContext = { ...base, params };
    const route = options.routes[`${found.method} ${found.template}`];
    if (route === undefined || holder.fake === undefined) { methods.grpcError(context, 'route-not-found', 5, 'Not Found'); return; }
    route(context, holder.fake);
  }, options.identity);
  const fake: FakeLnd = { ...server, served, ...methods, requests: server.requests, connections: server.connections, close: server.close, host: server.host, port: server.port };
  holder.fake = fake;
  return fake;
}

/** QueryRoutesRequest field names, lnrpc/lightning.proto#L3086-L3213 at v0.21.4-beta (tags 3 and 14 reserved). */
const QUERY_ROUTES_FIELDS: ReadonlySet<string> = new Set([
  'pub_key', 'amt', 'amt_msat', 'final_cltv_delta', 'fee_limit', 'ignored_nodes', 'ignored_edges', 'source_pub_key',
  'use_mission_control', 'ignored_pairs', 'cltv_limit', 'dest_custom_records', 'last_hop_pubkey', 'route_hints',
  'blinded_payment_paths', 'dest_features', 'time_pref', 'outgoing_chan_ids',
]);

/** protojson bytes: standard or URL-safe base64, padded or not (google.golang.org/protobuf encoding/protojson decode.go). */
export function protoBytes(value: unknown): Buffer | null {
  if (typeof value !== 'string') return null;
  if (/^[A-Za-z0-9+/]*={0,2}$/.test(value) && value.replace(/=+$/, '').length % 4 !== 1) return Buffer.from(value, 'base64');
  if (/^[A-Za-z0-9_-]*={0,2}$/.test(value) && value.replace(/=+$/, '').length % 4 !== 1) return Buffer.from(value, 'base64url');
  return null;
}

/**
 * Decodes a POST /v1/graph/routes body as the gateway does before the RPC runs: an unknown field (for
 * example the singular `outgoing_chan_id`, removed in 0.21) is InvalidArgument, a path amount together
 * with `amt_msat` is refused, and a pubkey in a bytes field must decode to 33 bytes. Answers the
 * refusal itself and returns null, or returns the decoded body.
 */
export function queryRoutesRequest(context: LndContext, fake: FakeLnd): Record<string, unknown> | null {
  let body: unknown;
  try { body = context.request.body === '' ? {} : JSON.parse(context.request.body); } catch { body = undefined; }
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    fake.grpcError(context, 'queryroutes-bad-body', 3, 'proto: syntax error (line 1:1): unexpected token');
    return null;
  }
  const fields = body as Record<string, unknown>;
  for (const key of Object.keys(fields)) {
    if (!QUERY_ROUTES_FIELDS.has(key)) { fake.grpcError(context, 'queryroutes-bad-body', 3, `proto: (line 1:2): unknown field "${key}"`); return null; }
  }
  const amtMsat = fields['amt_msat'];
  if (context.params['amt'] !== '0' && amtMsat !== undefined && amtMsat !== '0' && amtMsat !== 0) {
    fake.grpcError(context, 'queryroutes-amount', 2, 'sat and msat arguments are mutually exclusive');
    return null;
  }
  const vertex = (value: unknown): boolean => protoBytes(value)?.length === 33;
  const pairs = Array.isArray(fields['ignored_pairs']) ? fields['ignored_pairs'] as unknown[] : [];
  const pairOk = pairs.every(pair => pair !== null && typeof pair === 'object' && vertex((pair as Record<string, unknown>)['from']) && vertex((pair as Record<string, unknown>)['to']));
  if ((fields['last_hop_pubkey'] !== undefined && !vertex(fields['last_hop_pubkey'])) || !pairOk) {
    fake.grpcError(context, 'queryroutes-bad-body', 2, 'invalid vertex length');
    return null;
  }
  return fields;
}
