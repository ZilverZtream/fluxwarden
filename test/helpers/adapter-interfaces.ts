/*
 * Interface: node adapters (transport, read API, identity pinning and capability probe).
 *
 * Tests load the product modules by path, so each case fails on its own while a module is
 * missing. Amounts are bigint (the core `Msat` brand is a bigint); uint64 identifiers are
 * decimal text; every field keeps the unit upstream names it (`...Sat`, `...Msat`).
 *
 * src/core/errors.ts (existing classes unchanged; three classes added)
 *   class TlsError extends TransportError   certificate or hostname verification failed;
 *     constructor(message: string, options?: { cause?: unknown })   phase is always 'connect'
 *   class AuthError extends Error            the node or a proxy refused the credential
 *     readonly httpStatus: number | undefined
 *     readonly code: number | undefined      CLN error code (1501 missing rune, 1502 invalid rune)
 *   class ClnError extends Error             lightningd answered a JSON-RPC error through clnrest
 *     readonly code: number | undefined; readonly httpStatus: number
 *   transportFailure(error, phase): TlsError only in phase 'connect' for a TLS code, else TransportError(phase)
 *   isTlsFailureCode(code: unknown): boolean  true for certificate and host-name verification codes;
 *     false for ERR_TLS_HANDSHAKE_TIMEOUT and socket errors (those are TransportError 'connect')
 *
 * src/node-lnd/rest.ts
 *   openLndRest(options: LndRestOptions): Promise<LndRest>
 *     Reads the certificate and the macaroon by path. An empty file or one over 64 KiB
 *     (65536 bytes) rejects before any connection. The macaroon is sent as lowercase hex in
 *     `Grpc-Metadata-macaroon`; TLS trusts only the pinned certificate, verifies the host name
 *     and keeps `rejectUnauthorized: true` whatever NODE_TLS_REJECT_UNAUTHORIZED says.
 *     `timeoutMs` bounds a unary call (default 30000). `streamConnectTimeoutMs` (default 10000)
 *     bounds only the time to a TLS session for a stream; `streamDeadlineMs` is every stream's
 *     client deadline, after which it ends with TransportError 'response' (alexbosworth/lightning#133).
 *   Phases: no TLS session -> 'connect'; after the request was written (timeout, early close) -> 'response'.
 *   LndRest.call: 200 + JSON object -> the object. TLS verification failure -> TlsError.
 *     No TLS session -> TransportError 'connect'. Timeout or cut after the TLS session ->
 *     TransportError with notDelivered false. 401/403, and LND's macaroon rejections (HTTP 500
 *     gRPC 2 "verification failed: ...", "permission denied", "expected 1 macaroon, got 0")
 *     -> AuthError. Only 200 is a result. Any other status with a
 *     `{code, message}` body -> LndError(message, code, transport status); the body's
 *     `http_code` never replaces the transport status. A 200 body that is not a JSON object,
 *     or a body over 16 MiB -> ProtocolError.
 *   LndRest.stream: 200 -> newline-delimited `{"result": m}` (m handed to onMessage in order)
 *     or `{"error": {code, message}}` (LndError, httpStatus undefined). A line over 16 MiB
 *     (16777216 bytes, newline excluded) -> ProtocolError. Blank lines are skipped. In-stream
 *     `{"error": {grpc_code, message}}` and `{code, message}` lines are LndError too (lnd#5237,
 *     lnd#6751). Peer error text is bounded (under 2000 characters). A connection that ends before the
 *     server finishes the response -> TransportError with notDelivered false. A non-200
 *     answer is one error body `{"error": {...}}` or `{code, message}` -> LndError with the status.
 *     A stream resolves 'stopped' (the handler stopped it), 'ended' (the server finished the body)
 *     or 'aborted' (the caller's signal). The macaroon rule applies only to HTTP 500 with gRPC 2;
 *     a repeated payment_index, null for a required field and a chain name other than exactly
 *     "bitcoin" are ProtocolError. Timeouts must be positive integers (checked before any connection).
 *
 * src/node-lnd/api.ts   new LndReadApi(rest: LndRest), methods below (LndApi).
 *   lookupInvoice: GET /v1/invoice/{64 lowercase hex}. trackPayment: GET
 *   /v2/router/track/{padded URL-safe base64 of the hash}. listPayments: GET /v1/payments with
 *   include_incomplete, index_offset and max_payments. forwardingHistory: POST /v1/switch.
 *   Preimages are never returned: payments carry `preimageMatchesHash` instead (an all-zero
 *   preimage is absent), and an invoice's `r_preimage` is not read. Hostile answers are
 *   ProtocolError: a repeated chan_id; a LookupInvoice or TrackPayment answer naming another
 *   hash; GetInfo chains entries that disagree or name a chain other than bitcoin; a channel
 *   missing capacity, local_balance, remote_balance, local_constraints, remote_constraints or
 *   their chan_reserve_sat (the gateway emits every field, so absence is never a zero). int32
 *   fields such as blocks_til_maturity keep negative values.
 *
 * src/node-cln/rest.ts
 *   openClnRest(options: ClnRestOptions): Promise<ClnRest>
 *     Same file, TLS and timeout rules as LND. The rune file's text, trimmed, is the `rune`
 *     header. ClnRest.call(method, params) sends POST /v1/<method> with a JSON object body.
 *     clnrest answers 201 with the result object. 401/403 -> AuthError(code from the body).
 *     Other statuses with `{code, message}` -> ClnError. Malformed or schema-violating
 *     answers -> ProtocolError (also from the read API).
 *
 * src/node-cln/api.ts   new ClnReadApi(rest: ClnRest), methods below (ClnApi). Amounts are
 *   accepted as JSON safe integers or as "<digits>msat" strings, below 2^63. ProtocolError for:
 *   a missing schema-required field (getinfo id/version/blockheight/network, listsendpays
 *   created_at, listinvoices expires_at/created_index, events timestamp); a committed channel
 *   (any state but OPENINGD) missing to_us_msat, total_msat, spendable_msat, receivable_msat,
 *   our_reserve_msat or their_reserve_msat, decided by state and not by funding_txid (null is
 *   missing); a repeated short_channel_id, sendpay id or invoice label; with a label filter an
 *   invoice naming another label; with a paymentHash
 *   filter, any entry naming another hash; a state that is not an upper-case state name
 *   (/^[A-Z][A-Z0-9_]{0,63}$/). `stateKnown` is false for a state name outside the listpeerchannels enum. The rune file must hold exactly one printable token (0x21-0x7e).
 * src/node-cln/types.ts parseClnVersion(raw): { year, month, patch } | null
 *
 * src/core/capabilities.ts (see Capabilities below)
 * src/node-lnd/probe.ts  probeLnd(rest: LndRest, context: ProbeContext): Promise<ProbeResult>
 *   Requests in order: GET /v1/getinfo, then GET /v2/router/mccfg (a router call that cannot
 *   answer NotFound when the router service is present). Checks after the first request, in
 *   this order, with no further call when one fails:
 *     1. pubkey != expectedPubkey (checked even when chains[] is malformed), or a supported network whose normalized name != expectedNetwork
 *        -> IdentityRefusal (exit 5, step 'identity') with one QUARANTINED store update, even
 *        when the reported network is unsupported;
 *     2. context.mutating and the raw network is not exactly "regtest" (supported or not)
 *        -> IdentityRefusal (exit 5, step 'network-lock');
 *     3. network not one of SPEC 4.7's supported strings (LND mainnet, testnet, testnet4, signet,
 *        regtest; CLN bitcoin = mainnet, testnet, testnet4, signet, regtest; exact, case-sensitive)
 *        -> CapabilityUnsupported (exit 3).
 *   A read probe on any supported network that matches the configuration succeeds.
 *   Version below 0.21 or a router answer of gRPC 5/12 from LND itself -> no
 *   EXPLICIT_ROUTE_CONTROL. A 502/504 (a proxy relaying {code: 5}) or any other failure of the
 *   router call fails the probe without an ONLINE update.
 *   An unparseable version -> CapabilityUnsupported (exit 3).
 * src/node-cln/probe.ts  probeCln(rest: ClnRest, context: ProbeContext): Promise<ProbeResult>
 *   Requests in order: getinfo, then askrene-listlayers. Same identity rules. Version below
 *   v26.06 or askrene answering lightningd code -32601 -> no ASKRENE_LAYER_ROUTING; a code-less
 *   proxy answer fails the probe without an ONLINE update.
 *   A successful probe writes one ONLINE store update carrying the raw version string, the raw
 *   network, the sorted capability list and the injected time.
 */
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { repoRoot } from './cli.js';

export async function loadSource<T>(path: string): Promise<T> {
  return await import(pathToFileURL(join(repoRoot, 'src', path)).href) as T;
}

type ErrorClass<T extends Error, A extends unknown[]> = new (...args: A) => T;

export interface AdapterErrors {
  LndError: ErrorClass<Error & { grpcCode: number | undefined; httpStatus: number | undefined; notFound: boolean }, [string, number | undefined, number | undefined]>;
  TransportError: ErrorClass<Error & { phase: string; notDelivered: boolean }, [string, 'connect' | 'request' | 'response']>;
  ProtocolError: ErrorClass<Error, [string]>;
  TlsError: ErrorClass<Error & { phase: string; notDelivered: boolean }, [string]>;
  AuthError: ErrorClass<Error & { httpStatus: number | undefined; code: number | undefined }, [string]>;
  ClnError: ErrorClass<Error & { code: number | undefined; httpStatus: number }, [string]>;
  definiteRefusal: (error: unknown) => boolean;
  isTlsFailureCode: (code: unknown) => boolean;
  transportFailure: (error: unknown, phase: 'connect' | 'request' | 'response') => Error & { phase: string; notDelivered: boolean };
}

export interface LndRestOptions {
  host: string; port: number; tlsCertPath: string; macaroonPath: string;
  timeoutMs?: number; streamConnectTimeoutMs?: number; streamDeadlineMs?: number;
}
export type StreamDecision = 'continue' | 'stop';
export type StreamEnd = 'stopped' | 'ended' | 'aborted';
export interface LndRest {
  call: (method: 'GET' | 'POST', path: string, body?: unknown) => Promise<Record<string, unknown>>;
  stream: (method: 'GET' | 'POST', path: string, body: unknown, onMessage: (result: Record<string, unknown>) => StreamDecision, signal?: AbortSignal) => Promise<StreamEnd>;
}
export interface LndRestModule { openLndRest: (options: LndRestOptions) => Promise<LndRest> }

export interface LndInfo {
  identityPubkey: string; alias: string; version: string; commitHash: string; network: string;
  blockHeight: number; blockHash: string; syncedToChain: boolean; syncedToGraph: boolean;
}
export interface LndConstraints {
  csvDelay: number; chanReserveSat: bigint; dustLimitSat: bigint; maxPendingAmtMsat: bigint; minHtlcMsat: bigint; maxAcceptedHtlcs: number;
}
export interface LndHtlc {
  incoming: boolean; amountSat: bigint; hashLock: string; expirationHeight: number;
  htlcIndex: string; forwardingChannel: string; forwardingHtlcIndex: string; lockedIn: boolean;
}
export interface LndChannel {
  active: boolean; remotePubkey: string; channelPoint: string; chanId: string;
  capacitySat: bigint; localBalanceSat: bigint; remoteBalanceSat: bigint; commitFeeSat: bigint;
  commitWeight: bigint; feePerKw: bigint; unsettledBalanceSat: bigint; initiator: boolean; private: boolean;
  pendingHtlcs: LndHtlc[]; localConstraints: LndConstraints; remoteConstraints: LndConstraints;
}
export type LndInitiator = 'INITIATOR_UNKNOWN' | 'INITIATOR_LOCAL' | 'INITIATOR_REMOTE' | 'INITIATOR_BOTH';
export interface LndPendingChannel {
  remoteNodePub: string; channelPoint: string; capacitySat: bigint; localBalanceSat: bigint; remoteBalanceSat: bigint;
  localChanReserveSat: bigint; remoteChanReserveSat: bigint; initiator: LndInitiator;
}
export interface LndPendingChannels {
  totalLimboBalanceSat: bigint;
  pendingOpenChannels: { channel: LndPendingChannel; commitFeeSat: bigint; commitWeight: bigint; feePerKw: bigint; confirmationsUntilActive: number }[];
  waitingCloseChannels: { channel: LndPendingChannel; limboBalanceSat: bigint; closingTxid: string }[];
  pendingForceClosingChannels: { channel: LndPendingChannel; closingTxid: string; limboBalanceSat: bigint; maturityHeight: number; blocksTilMaturity: number }[];
}
export interface LndPayment {
  paymentHash: string; valueMsat: bigint; feeMsat: bigint;
  status: 'UNKNOWN' | 'IN_FLIGHT' | 'SUCCEEDED' | 'FAILED' | 'INITIATED';
  failureReason: string; creationTimeNs: bigint; paymentIndex: bigint; preimageMatchesHash: boolean;
  htlcs: { attemptId: string; status: 'IN_FLIGHT' | 'SUCCEEDED' | 'FAILED' }[];
}
export interface LndPaymentsPage { payments: LndPayment[]; firstIndexOffset: bigint; lastIndexOffset: bigint }
export interface LndForwardingEvent { timestampNs: bigint; chanIdIn: string; chanIdOut: string; amtInMsat: bigint; amtOutMsat: bigint; feeMsat: bigint }
export interface LndForwardingPage { events: LndForwardingEvent[]; lastOffsetIndex: number }
export interface LndInvoice {
  rHash: string; memo: string; valueMsat: bigint; amtPaidMsat: bigint;
  state: 'OPEN' | 'SETTLED' | 'CANCELED' | 'ACCEPTED';
  creationDate: bigint; settleDate: bigint; expiry: bigint; cltvExpiry: bigint;
  addIndex: bigint; settleIndex: bigint; paymentRequest: string;
}
export interface LndApi {
  getInfo: () => Promise<LndInfo>;
  listChannels: () => Promise<LndChannel[]>;
  pendingChannels: () => Promise<LndPendingChannels>;
  listPayments: (request: { indexOffset: bigint; maxPayments: number; includeIncomplete: boolean }) => Promise<LndPaymentsPage>;
  forwardingHistory: (request: { startTime: bigint; endTime: bigint; indexOffset: number; numMaxEvents: number }) => Promise<LndForwardingPage>;
  lookupInvoice: (paymentHash: string) => Promise<LndInvoice>;
  trackPayment: (paymentHash: string, onUpdate: (payment: LndPayment) => StreamDecision, signal?: AbortSignal) => Promise<StreamEnd>;
}
export interface LndApiModule { LndReadApi: new (rest: LndRest) => LndApi }

export interface ClnRestOptions { host: string; port: number; tlsCertPath: string; runePath: string; timeoutMs?: number }
export interface ClnRest { call: (method: string, params?: Record<string, unknown>) => Promise<Record<string, unknown>> }
export interface ClnRestModule { openClnRest: (options: ClnRestOptions) => Promise<ClnRest> }

export interface ClnInfo {
  id: string; alias: string; version: string; blockheight: number; network: string;
  warningBitcoindSync: string | null; warningLightningdSync: string | null;
}
export interface ClnHtlc {
  direction: 'in' | 'out'; id: string; amountMsat: bigint; expiry: number; paymentHash: string;
  state: string; status: string | null; localTrimmed: boolean;
}
export interface ClnPeerChannel {
  peerId: string; peerConnected: boolean; state: string; stateKnown: boolean; shortChannelId: string | null; channelId: string | null;
  fundingTxid: string | null; fundingOutnum: number | null; opener: 'local' | 'remote'; private: boolean;
  totalMsat: bigint | null; toUsMsat: bigint | null; spendableMsat: bigint | null; receivableMsat: bigint | null;
  ourReserveMsat: bigint | null; theirReserveMsat: bigint | null; feeBaseMsat: bigint; feeProportionalMillionths: number;
  minimumHtlcOutMsat: bigint; maximumHtlcOutMsat: bigint; htlcs: ClnHtlc[];
}
export interface ClnSendPay {
  id: string; groupid: string; partid: string; paymentHash: string; status: 'pending' | 'complete' | 'failed';
  amountMsat: bigint | null; amountSentMsat: bigint; createdAt: number; completedAt: number | null;
  label: string | null; destination: string | null; createdIndex: string; preimageMatchesHash: boolean;
}
export interface ClnPay {
  paymentHash: string; status: 'pending' | 'complete' | 'failed'; amountMsat: bigint | null; amountSentMsat: bigint | null;
  numberOfParts: number | null; createdAt: number; completedAt: number | null; label: string | null; preimageMatchesHash: boolean;
}
export interface ClnInvoice {
  label: string; paymentHash: string; status: 'unpaid' | 'paid' | 'expired'; amountMsat: bigint | null;
  amountReceivedMsat: bigint | null; expiresAt: number; paidAt: number | null; payIndex: string | null;
  createdIndex: string; description: string | null;
}
export interface ClnAccountEvent {
  account: string; type: 'onchain_fee' | 'chain' | 'channel'; tag: string; creditMsat: bigint; debitMsat: bigint;
  currency: string; timestamp: number; feesMsat: bigint | null; isRebalance: boolean | null; paymentId: string | null; partId: number | null;
}
export interface ClnLayer {
  layer: string; persistent: boolean; disabledNodes: string[]; disabledChannels: string[];
  channelUpdates: { shortChannelIdDir: string; enabled: boolean | null; feeBaseMsat: bigint | null; feeProportionalMillionths: number | null; cltvExpiryDelta: number | null }[];
}
export interface ClnApi {
  getInfo: () => Promise<ClnInfo>;
  listPeerChannels: () => Promise<ClnPeerChannel[]>;
  listSendPays: (filter?: { paymentHash?: string }) => Promise<ClnSendPay[]>;
  listPays: (filter?: { paymentHash?: string }) => Promise<ClnPay[]>;
  listInvoices: (filter?: { paymentHash?: string; label?: string }) => Promise<ClnInvoice[]>;
  listAccountEvents: () => Promise<ClnAccountEvent[]>;
  listLayers: () => Promise<ClnLayer[]>;
}
export interface ClnApiModule { ClnReadApi: new (rest: ClnRest) => ClnApi }
export interface ClnTypesModule { parseClnVersion: (raw: string) => { year: number; month: number; patch: number } | null }

/*
 * Capabilities (src/core/capabilities.ts)
 *   type NodeCapability = 'CHANNEL_READ' | 'PAYMENT_READ' | 'PAYMENT_TRACK' | 'INVOICE_CREATE' | 'INVOICE_CANCEL'
 *     | 'FORWARDING_READ' | 'BOOKKEEPER_READ' | 'EXPLICIT_ROUTE_CONTROL' | 'ASKRENE_LAYER_ROUTING'
 *   REQUIRED_CAPABILITIES.lnd includes EXPLICIT_ROUTE_CONTROL and PAYMENT_TRACK;
 *   REQUIRED_CAPABILITIES.cln includes ASKRENE_LAYER_ROUTING.
 *   requireCapabilities(available, needed) throws CapabilityUnsupported listing every missing
 *   capability (in `needed` order) in `missing` and in its message.
 */
export type NodeCapability =
  | 'CHANNEL_READ' | 'PAYMENT_READ' | 'PAYMENT_TRACK' | 'INVOICE_CREATE' | 'INVOICE_CANCEL'
  | 'FORWARDING_READ' | 'BOOKKEEPER_READ' | 'EXPLICIT_ROUTE_CONTROL' | 'ASKRENE_LAYER_ROUTING';
export interface NodeIdentity { pubkey: string; network: string; version: string; blockHeight: number; syncedToChain: boolean }
export interface ProbeResult { identity: NodeIdentity; capabilities: ReadonlySet<NodeCapability> }
export interface NodeProbeUpdate {
  nodeId: string; state: 'ONLINE' | 'QUARANTINED'; observedVersion: string | null; observedNetwork: string | null;
  capabilities: readonly NodeCapability[]; probedAtMs: number;
}
export interface NodeProbeStore { recordProbe: (update: NodeProbeUpdate) => Promise<void> }
export type NetworkType = 'regtest' | 'signet' | 'testnet' | 'testnet4' | 'mainnet';
export interface ProbeContext {
  nodeId: string; expectedPubkey: string; expectedNetwork: NetworkType; mutating: boolean;
  store: NodeProbeStore; nowMs: () => number;
}
export interface CapabilitiesModule {
  REQUIRED_CAPABILITIES: { lnd: readonly NodeCapability[]; cln: readonly NodeCapability[] };
  CapabilityUnsupported: ErrorClass<Error & { code: 'CAPABILITY_UNSUPPORTED'; exitCode: number; missing: readonly NodeCapability[] }, [string]>;
  IdentityRefusal: ErrorClass<Error & { step: 'identity' | 'network-lock'; exitCode: number }, [string]>;
  requireCapabilities: (available: ReadonlySet<NodeCapability>, needed: readonly NodeCapability[]) => void;
}
export interface LndProbeModule { probeLnd: (rest: LndRest, context: ProbeContext) => Promise<ProbeResult> }
export interface ClnProbeModule { probeCln: (rest: ClnRest, context: ProbeContext) => Promise<ProbeResult> }

export const loadErrors = (): Promise<AdapterErrors> => loadSource<AdapterErrors>('core/errors.ts');
export const loadLndRest = (): Promise<LndRestModule> => loadSource<LndRestModule>('node-lnd/rest.ts');
export const loadLndApi = (): Promise<LndApiModule> => loadSource<LndApiModule>('node-lnd/api.ts');
export const loadClnRest = (): Promise<ClnRestModule> => loadSource<ClnRestModule>('node-cln/rest.ts');
export const loadClnApi = (): Promise<ClnApiModule> => loadSource<ClnApiModule>('node-cln/api.ts');
export const loadClnTypes = (): Promise<ClnTypesModule> => loadSource<ClnTypesModule>('node-cln/types.ts');
export const loadCapabilities = (): Promise<CapabilitiesModule> => loadSource<CapabilitiesModule>('core/capabilities.ts');
export const loadLndProbe = (): Promise<LndProbeModule> => loadSource<LndProbeModule>('node-lnd/probe.ts');
export const loadClnProbe = (): Promise<ClnProbeModule> => loadSource<ClnProbeModule>('node-cln/probe.ts');

/** Rejection captured as a value, so a test can assert its class and fields. */
export async function rejection(promise: Promise<unknown>): Promise<unknown> {
  try { await promise; } catch (error) { return error; }
  throw new Error('expected the call to reject');
}

/** JSON with bigint as decimal text, to search adapter output for leaked bytes. */
export function serialise(value: unknown): string {
  const text = JSON.stringify(value, (_key, item: unknown) => typeof item === 'bigint' ? item.toString() : item) as string | undefined;
  return typeof text === 'string' ? text : '';
}
