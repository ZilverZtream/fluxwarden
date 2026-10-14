/*
Interface: dispatch, node execution adapters, the reconciler and `actions status`.

Builds on test/helpers/cp028-executor.ts (claimExecution, prepareExecution, executions.transition / renewLease, fenced
writes, VerifiedApproval, ExecutionPolicy, CircularRoute, RouteRequest, NormalizedChannel as FakeChannel). The input of
dispatch is a claimed, preflighted execution: status PREFLIGHT, payment_hash NULL, its route recorded, and the fence epoch
the preflight returned.

Shared port (the SPEC §5.1 LightningNodeAdapter methods the executor and the reconciler use; INV-02: nothing else reaches
the mutating ones):

  ExecutionAdapter = {
    listChannels(): Promise<readonly NormalizedChannel[]>;
    createInvoice(amountMsat: bigint, preimage: Uint8Array, label: string, expirySeconds: number): Promise<InvoiceResult>;
    sendOnRoute(route: CircularRoute, paymentHash: string, paymentSecret: string, onDispatched?: () => void): Promise<PaymentObservation>;
    observePayment(paymentHash: string, mode?: 'track' | 'sweep'): Promise<PaymentObservation>;
    invoiceState(paymentHash: string): Promise<'OPEN' | 'SETTLED' | 'CANCELED' | 'NOT_FOUND'>;
    cancelUnpaidInvoice(paymentHash: string, label: string): Promise<'CANCELED' | 'ALREADY_PAID' | 'NOT_FOUND'>;
  }
  InvoiceResult = { paymentHash: string; paymentSecret: string;  (both 64 lowercase hex) finalCltvDelta: number }
  PaymentObservation (preimages never leave the adapter; only whether SHA-256(preimage) = hash, ARCHITECTURE §4.1):
    | { kind: 'SUCCEEDED'; preimageMatchesHash: boolean; feeMsat: bigint; htlcCount: number; settledChannelKey: string | null }
    | { kind: 'FAILED'; reason: string; local: boolean; htlcsInFlight: number }
    | { kind: 'IN_FLIGHT' }                 // LND IN_FLIGHT and INITIATED, LND FAILED with an HTLC in flight, CLN pending
    | { kind: 'NOT_FOUND' }                 // the node has no record of the hash
    | { kind: 'AMBIGUOUS'; cause: string }  // the answer was lost or unreadable after the request may have left
  `onDispatched` is called once, as soon as the request bytes have been written (SPEC §5.3 L8, §8.2 SUBMITTING -> IN_FLIGHT).
  `mode` 'sweep' reads the payer side from the node's list (LND ListPayments include_incomplete, CLN listsendpays), never
  from a live stream (SPEC §8.4 restart sweep); 'track' (the default) may use TrackPaymentV2 / waitsendpay.

src/core/execution.ts (pure)
  proveRegtest(configured: string, handshake: { network: string; ... }): RegtestProof | null
    a proof only when both the configured network and the network of the observed handshake are exactly 'regtest'
    (INV-15).
  approveRoute(route: CircularRoute, terms: { sourceChannelKey; targetChannelKey; principalMsat }, approval, policy,
               proof: RegtestProof): { route: ApprovedRoute } | { refusal: string }
    a value that proveRegtest did not return -> { refusal: 'network-lock' }; then the dispatch route checks under the
    approved caps (S first, T last, principal, fee and ppm caps, CLTV).

src/executor/dispatch.ts
  dispatchExecution(deps: DispatchDeps, input: DispatchInput): Promise<DispatchOutcome>
  input.route must be a route returned by approveRoute; any other value (a plain or copied route object) -> exit 5,
  step 'network-lock', no node call and no write.
  DispatchDeps = { db: ExecDatabase; adapter: ExecutionAdapter; workerId: string; leaseMs: number;
                   randomBytes: (size: number) => Uint8Array; stopSignal: AbortSignal; attemptDeadlineMs: number;
                   invoiceExpirySeconds: number; deltaToleranceMsat: bigint; alert: (alert: Alert) => void }
  DispatchInput = { executionId: string; fenceEpoch: bigint; route: CircularRoute; approval: VerifiedApproval; policy: ExecutionPolicy }
  DispatchOutcome = { executionId: string; exit: 0 | 5 | 6 | 7 | 8 | 9; step: string | null }
  Alert = { kind: 'INVARIANT_BREACH' | 'fee-mismatch' | 'delta-mismatch' | 'stuck-in-flight'; executionId: string; code: string }
  Steps, in order (SPEC §8.3 P5-P7, §5.3 L1-L9, §5.4 C1/C8-C10, §6.4, §10.1 interrupts, §10.3 AE9-AE13):
    D0 an input whose fence epoch no longer matches the row -> exit 5, step 'lease-lost', and no node call at all (INV-18).
       A PREFLIGHT row that already holds a payment hash (a worker died after D3/D4 and the row was re-claimed) never gets
       a second hash (INV-05): either the stored invoice is reused for the one send under that hash, or it is closed
       (cancelUnpaidInvoice(stored hash, label)) and the row moves to CANCELLED, exit 5; never an exception, never a row
       left in PREFLIGHT. A stored invoice that the cancel reports ALREADY_PAID is evidence that money moved under that
       hash (SPEC §8.2): the row follows the success path (resolved from observePayment, D8), never CANCELLED, never
       re-sent (INV-19).
    D1 stopSignal aborted -> fenced PREFLIGHT -> CANCELLED, error_code 'INTERRUPTED'; exit 6, step 'INTERRUPTED'; no node call.
    D2 listChannels() once: the baseline local balances of route.sourceChannelKey and route.targetChannelKey.
    D3 preimage = randomBytes(32); payment_hash = SHA-256(preimage) persisted by a fenced write while the row stays PREFLIGHT.
       The preimage is never written to the database.
    D4 createInvoice(route.principalMsat, preimage, `fluxwarden-${executionId}`, invoiceExpirySeconds). A rejection, or an
       answer naming another hash -> cancelUnpaidInvoice(hash, label), fenced PREFLIGHT -> CANCELLED, exit 5; nothing is sent.
    D5 stopSignal aborted -> cancelUnpaidInvoice(hash, label), fenced PREFLIGHT -> CANCELLED 'INTERRUPTED', exit 6.
    D5b the route's final CLTV delta (last hop expiry - (hops[0].expiry - totalTimelockDelta)) below the invoice's
       finalCltvDelta -> cancelUnpaidInvoice, CANCELLED, exit 5, step 'CLTV_DELTA_UNSAFE' (SPEC §5.3 L3, ARCHITECTURE §3 8.8).
    D6 renewLease (fenced) immediately before the send, then D5 again, then fenced PREFLIGHT -> SUBMITTING with route_json and
       submitted_at (database clock). A fenced write affecting zero rows before the send -> exit 5, step 'lease-lost', and
       no further node call.
    D7 exactly one sendOnRoute(route, hash, paymentSecret, onDispatched); onDispatched -> fenced SUBMITTING -> IN_FLIGHT. The
       wait is bounded by attemptDeadlineMs and by stopSignal; either ends it -> fenced -> UNKNOWN, exit 7, step 'OUTCOME_UNKNOWN'.
       After the send nothing but evidence ends the execution: never a second send, never CANCELLED, never VERIFIED_FAILURE
       without a node FAILED answer. Any node answer (SUCCEEDED or FAILED) proves the request reached the node, so the row
       passes SUBMITTING -> IN_FLIGHT before its terminal state even when onDispatched was never called (SPEC §8.2).
    D8 SUCCEEDED with preimageMatchesHash -> fenced -> VERIFIED_SUCCESS, actual_fee_msat = feeMsat (reservation CONSUMED with
       that fee, also above the reservation). Result checks (SPEC §8.7, SECURITY INV-03, INV-17):
         htlcCount !== 1 (0 included)     -> alert INVARIANT_BREACH code 'SINGLE_PATH_UNAVAILABLE', exit 8
         feeMsat > approval.approvedMaxFeeMsat -> alert INVARIANT_BREACH code 'FEE_ABOVE_CAP', exit 8
         feeMsat !== route.totalFeeMsat (within the cap) -> alert 'fee-mismatch' code 'FEE_MISMATCH', exit 9
       then listChannels() once more: |ΔS + (P + feeMsat)| <= deltaToleranceMsat and |ΔT − P| <= deltaToleranceMsat ->
       delta_status 'MATCH', else 'MISMATCH' with alert 'delta-mismatch' code 'DELTA_MISMATCH', exit 9. Exit 8 outranks 9;
       a clean success exits 0 with step null. The status stays VERIFIED_SUCCESS in every case.
       SUCCEEDED without preimageMatchesHash -> fenced -> UNKNOWN, alert INVARIANT_BREACH code 'PREIMAGE_MISMATCH', exit 8.
    D9 FAILED with htlcsInFlight 0 -> cancelUnpaidInvoice(hash, label): 'CANCELED' -> fenced -> VERIFIED_FAILURE with
       error_code = reason (reservation RELEASED), exit 5, step = reason; 'ALREADY_PAID' -> observePayment(hash) and D8 on
       SUCCEEDED, else UNKNOWN exit 7.
       cancelUnpaidInvoice answering 'NOT_FOUND' or rejecting -> UNKNOWN exit 7.
    D10 FAILED with HTLCs in flight, IN_FLIGHT, NOT_FOUND, AMBIGUOUS, or a rejection of sendOnRoute -> fenced -> UNKNOWN,
       exit 7, step 'OUTCOME_UNKNOWN'; no cancelUnpaidInvoice. The lease is checked before cancelUnpaidInvoice: a worker
       whose row was taken over during the wait makes no further node call (exit 7, 'lease-lost'). A fenced write affecting zero rows after the send -> exit 7,
       step 'lease-lost', no further node call and nothing written over the new holder.

src/node-lnd/execute.ts   new LndExecutionAdapter(rest: LndRest, options: { trackDeadlineMs: number })
  createInvoice: POST /v1/invoices {memo: label, r_preimage: base64(preimage), value_msat: decimal, expiry: decimal}.
    r_hash must equal SHA-256(preimage), else ProtocolError. paymentSecret = hex(payment_addr). finalCltvDelta from the
    returned payment_request (BOLT 11 `c`, 18 when absent).
  sendOnRoute: exactly one POST /v2/router/route/send {payment_hash: base64, route} and never POST /v2/router/send.
    route: total_amt_msat = hops[0].amountOutMsat, total_time_lock = hops[0].expiry, and per hop i (lnd route.Hop,
    routerrpc/router_backend.go UnmarshallHopWithPubkey): chan_id = channelKey, pub_key = nodeOut,
    amt_to_forward_msat = hops[i+1].amountOutMsat (last: its own amount), expiry = hops[i+1].expiry (last: its own);
    the last hop alone carries mpp_record {payment_addr: base64(paymentSecret), total_amt_msat: principal} and no hop sets
    the blinded-only top-level total_amt_msat; skip_temp_err is never true.
    Answer handling: an HTLCAttempt (SUCCEEDED or FAILED) or a gRPC refusal is confirmed by TrackPaymentV2 and mapped as
    observePayment; a refusal whose TrackPaymentV2 answers NotFound -> FAILED reason 'REJECTED_BEFORE_INITIATION', local
    true. A cut, a timeout, a 502/504 or a stream that ends without a terminal status -> AMBIGUOUS.
  observePayment ('track'): GET /v2/router/track/{base64url hash}; the latest Payment record received before a terminal
    status, the end of the stream or the deadline decides: SUCCEEDED with a matching preimage -> SUCCEEDED
    (failure_reason ignored), htlcCount = htlcs with status SUCCEEDED, feeMsat = fee_msat; FAILED with no HTLC IN_FLIGHT
    -> FAILED reason = failure_reason name; FAILED with an HTLC IN_FLIGHT, IN_FLIGHT, INITIATED -> IN_FLIGHT; gRPC 5 ->
    NOT_FOUND; no record or an unreadable answer -> AMBIGUOUS. (sendOnRoute, unlike observePayment, needs a terminal
    record: a stream that ends while the payment is still in flight leaves it AMBIGUOUS.)
  cancelUnpaidInvoice: POST /v2/invoices/cancel {payment_hash: base64}, then GET /v1/invoice/{hex}: CANCELED -> 'CANCELED',
    SETTLED -> 'ALREADY_PAID'; "invoice already settled" -> 'ALREADY_PAID'; "unable to locate invoice" -> 'NOT_FOUND'.

src/node-cln/execute.ts   new ClnExecutionAdapter(rest: ClnRest, options: { ownId: string; waitChunkSeconds: number; attemptDeadlineMs: number })
  createInvoice: invoice {amount_msat, label, description, expiry, preimage: hex}; payment_hash must equal SHA-256(preimage).
  findCircularRoute(req: RouteRequest): getinfo, listpeerchannels, askrene-create-layer {layer: 'fluxwarden-…' fresh per
    call}, askrene-disable-node {layer, node: ownId}, getroutes {source: out peer of S, destination: in peer of T,
    amount_msat: P + in-hop fee, layers: ['xpay', layer], maxfee_msat: maxFeeMsat − in-hop fee, final_cltv: in-hop CLTV
    delta + 18, maxdelay: maxCltvDelta − 18 − in-hop CLTV delta, maxparts: 1}, listchannels for each middle hop, and
    askrene-remove-layer {layer} exactly once on every path (success, refusal, error, cut). In-hop policy: T's
    listpeerchannels updates.remote. Amounts and CLTVs are recomputed backwards from the final CLTV 18 (SPEC §5.4 C6);
    no route -> { refusal: 'NO_FEASIBLE_ROUTE' }; more than one route -> { refusal: 'SINGLE_PATH_UNAVAILABLE' }.
    V5 with CLN block padding 1 (Decision D52: lightningd sends each HTLC at network height + 1 + cltv_out): a route with
    delta + 1 > maxCltvDelta -> { refusal: 'CLTV_DELTA_UNSAFE' }, and getroutes maxdelay = maxCltvDelta - 1 - 18 - in-hop
    delta. The layer is removed also when askrene-create-layer itself was cut after the request was written.
  sendOnRoute: exactly one sendpay {route, payment_hash, payment_secret, amount_msat: P}; never xpay or pay; no
    partid, groupid, maxfee or maxdelay. route[i] = {short_channel_id_dir: `${scid}/${dir}` (BOLT 7: dir 0 when the
    sending node's id sorts below the receiving node's), node_id_out, amount_out_msat, cltv_out: hops[i].expiry − (route
    build height = hops[0].expiry − totalTimelockDelta)} (lightningd/pay.c send_payment adds network height + 1).
    onDispatched before the first waitsendpay. Then waitsendpay {payment_hash, timeout: 1..waitChunkSeconds} repeated:
    Only a lightningd JSON-RPC error (clnrest non-2xx with a JSON body carrying a numeric `code`) is a node answer; a
    502/504, a non-JSON body or a JSON body without `code` from sendpay or waitsendpay is a transport failure -> AMBIGUOUS
    (INV-04, ARCHITECTURE A14). sendpay 204 is returned before any HTLC and before the payment is stored
    (lightningd/pay.c L1113-L1151, wallet_add_payment at L1153): with no listsendpays record and the invoice unpaid ->
    FAILED reason 'REJECTED_BEFORE_INITIATION', local true.
    complete with a matching preimage, the asked payment_hash and amount_msat = P exactly -> SUCCEEDED, feeMsat = amount_sent_msat − amount_msat,
    htlcCount = complete entries of listsendpays {payment_hash}; complete with another amount -> AMBIGUOUS; 200 -> wait
    again until attemptDeadlineMs, then AMBIGUOUS; 208 -> NOT_FOUND; −1/202/203/204/209 -> FAILED only when listsendpays
    reports failed and listinvoices does not report the invoice paid, else AMBIGUOUS; a transport error -> AMBIGUOUS.
    A sendpay answer with status complete (a replayed completed payment, cln#9517) is handled like a waitsendpay complete.
  observePayment: listsendpays {payment_hash}; invoiceState: listinvoices {payment_hash} (paid -> SETTLED, unpaid -> OPEN,
    expired -> CANCELED, none -> NOT_FOUND); cancelUnpaidInvoice: delinvoice {label, status: 'unpaid'} -> 'CANCELED';
    906 -> listinvoices {label}: paid -> 'ALREADY_PAID', still unpaid -> ProtocolError (rejects); 905 -> 'NOT_FOUND'.
    observePayment with complete parts reports preimageMatchesHash true only when every complete part's preimage matches.
    observePayment when every part is failed confirms with waitsendpay {payment_hash, timeout: 1}: 200 -> IN_FLIGHT;
    -1/202/203/204/209 -> FAILED; complete -> never FAILED; anything else -> AMBIGUOUS.
    A gateway status (408, 499, 502, 503, 504) is never lightningd's answer, even with a JSON `code` in its body.
    sendpay -32602 (JSONRPC2_INVALID_PARAMS: parameters refused while parsing, before anything is sent or stored;
    lightningd/pay.c json_sendpay param_check, common/jsonrpc_errors.h L14) with no listsendpays record and the invoice
    unpaid -> FAILED 'REJECTED_BEFORE_INITIATION'. A waitsendpay code outside the documented set -> AMBIGUOUS.
    askrene-create-layer failing without lightningd's coded refusal (a cut, a gateway status, a 500 without `code`)
    is followed by askrene-remove-layer of that name.

src/reconciler/index.ts
  reconcile(deps: ReconcileDeps, options: { startup: boolean }): Promise<ReconcileReport>
  ReconcileDeps = { db: ExecDatabase; adapters: ReadonlyMap<string, ExecutionAdapter> (keyed by nodes.id); workerId: string;
                    leaseMs: number; notFoundWindowMs: number; escalateAfterMs: number; confirmIntervalMs: number;
                    deltaToleranceMsat?: bigint; alert: (alert: Alert) => void }
  ReconcileReport = { exit: 0 | 7 | 8; unresolved: readonly string[] }
  Candidates: UNKNOWN; SUBMITTING and IN_FLIGHT whose lease expired (database clock), first moved to UNKNOWN (fenced). With
  startup true, the same candidates read with observePayment(hash, 'sweep'). A row whose lease is still live is never
  taken, in the startup sweep as in a regular pass (INV-13): no write and no node call for its hash. Each candidate is taken with a
  fenced lease, then decided by the first matching rule (SPEC §8.4, §8.5):
    SUCCEEDED + preimageMatchesHash, or invoiceState SETTLED -> VERIFIED_SUCCESS (actual_fee_msat = feeMsat when reported),
      then the result checks of dispatch D8 against the stored approval and route: htlcCount !== 1 -> alert
      INVARIANT_BREACH 'SINGLE_PATH_UNAVAILABLE'; feeMsat > approvals.max_fee_msat -> INVARIANT_BREACH 'FEE_ABOVE_CAP';
      both report exit 8 (a fee equal to the cap is within it); feeMsat !== planned_fee_msat within the cap ->
      'fee-mismatch' 'FEE_MISMATCH' (exit 9 when nothing else outranks it). The status stays VERIFIED_SUCCESS.
      Delta verification (SPEC §8.7 step 5) against the local balances dispatch recorded at SUBMITTING and one fresh
      listChannels: |ΔS + (P + feeMsat)| and |ΔT − P| within deltaToleranceMsat -> delta_status MATCH; otherwise
      MISMATCH with alert 'delta-mismatch' 'DELTA_MISMATCH' (exit 9). A missing deltaToleranceMsat means zero
      tolerance, never a skipped check.
      CLN two-observation rule: any non-FAILED observation between two FAILED ones resets it (the next FAILED is a new
      first observation).
    SUCCEEDED without a matching preimage -> stays; alert INVARIANT_BREACH 'PREIMAGE_MISMATCH'; report exit 8
    FAILED on a CLN node (nodes.implementation 'cln') counts only when a FAILED observation of the same hash recorded at
      least confirmIntervalMs earlier agrees (SPEC §5.4 status mapping: listsendpays can swing or lag); the first one is
      recorded and the row stays UNKNOWN with its reservation HELD and nothing cancelled. LND FAILED counts at once.
    FAILED with htlcsInFlight 0 and the invoice not SETTLED -> cancelUnpaidInvoice: 'CANCELED' -> VERIFIED_FAILURE with
      error_code = reason; 'ALREADY_PAID' -> observePayment again and the success rule
    FAILED with HTLCs in flight, IN_FLIGHT, AMBIGUOUS, a rejected read -> stays
    NOT_FOUND -> cancelUnpaidInvoice first, then observePayment again: 'ALREADY_PAID' -> VERIFIED_SUCCESS (our invoice
      is paid) whatever the payer side says; still NOT_FOUND, the cancel answered 'CANCELED' and submitted_at at least
      notFoundWindowMs ago -> VERIFIED_FAILURE error_code 'NOT_SENT'; a cancel that failed, or anything else -> stays
  An execution still non-terminal after the pass whose submitted_at is older than escalateAfterMs raises exactly one
  alert 'stuck-in-flight' (code 'STUCK') in that pass. exit: 8 on a preimage mismatch, else 7 when any candidate stays
  SUBMITTING / IN_FLIGHT / UNKNOWN, else 0. The reconciler never calls createInvoice or sendOnRoute.

src/commands/actions.ts (no node calls; the CLI writes `output` and exits with `exitCode`)
  actionsStatus(input: { databasePath: string; executionId: string; json: boolean }): { exitCode: number; output: string }
    JSON: one document plus "\n" valid against schemas/output/actions-status.json, command 'actions status', result
    { execution_id, status, fence_epoch (decimal text), lease_expires_at, payment_hash, route (parsed route_json or null),
      planned_fee_msat, actual_fee_msat, delta_status, error_code, events: [{ from, to, at }] in insertion order }.
    Exit (SPEC §10.3 AS3, §10.2): VERIFIED_SUCCESS 0, VERIFIED_FAILURE / CANCELLED 5, SUBMITTING / IN_FLIGHT / UNKNOWN 7
    (a mutating RPC may have reached the node); CLAIMED / PREFLIGHT 0, nothing has been sent; unknown id -> 2 (ok
    false, error.code 2). Text output for SUBMITTING / IN_FLIGHT / UNKNOWN, and only for them, carries the line
    "outcome unknown — run `fluxwarden reconcile`; do not retry".
  watchActionsStatus(input: { databasePath; executionId; pollMs: number; signal: AbortSignal }, emit: (line: string) => void): Promise<{ exitCode: number }>
    --watch --json: polls until a terminal status or the signal; emits one JSON object line per execution_events row in
    insertion order, {"event": "transition", "execution_id", "from", "to", "at"}, then the actionsStatus JSON document as the
    last line. Exit as actionsStatus; interrupted -> 6.
  renderExecuteOutcome(outcome: DispatchOutcome, json: boolean): { exitCode: number; output: string }
    exit 7 -> JSON error {code: 7, step: 'OUTCOME_UNKNOWN', message: "outcome unknown — run `fluxwarden reconcile`; do not retry"}
    with command 'actions execute'; the text form carries the same message.
*/
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { repoRoot } from './cli.js';
import {
  dbNow, PRINCIPAL, seedProposal, ulid,
  type Base, type CircularRoute, type ExecDatabase, type ExecutionPolicy, type ExecutionStatus, type FakeChannel, type RouteRequest,
  type VerifiedApproval, type ProposalOptions,
} from './cp028-executor.js';
import type { ClnRest, LndRest } from './adapter-interfaces.js';

export type PaymentObservation =
  | { readonly kind: 'SUCCEEDED'; readonly preimageMatchesHash: boolean; readonly feeMsat: bigint; readonly htlcCount: number; readonly settledChannelKey: string | null }
  | { readonly kind: 'FAILED'; readonly reason: string; readonly local: boolean; readonly htlcsInFlight: number }
  | { readonly kind: 'IN_FLIGHT' }
  | { readonly kind: 'NOT_FOUND' }
  | { readonly kind: 'AMBIGUOUS'; readonly cause: string };

export interface InvoiceResult { readonly paymentHash: string; readonly paymentSecret: string; readonly finalCltvDelta: number }
export type InvoiceState = 'OPEN' | 'SETTLED' | 'CANCELED' | 'NOT_FOUND';
export type CancelResult = 'CANCELED' | 'ALREADY_PAID' | 'NOT_FOUND';

export interface ExecutionAdapter {
  listChannels(): Promise<readonly FakeChannel[]>;
  createInvoice(amountMsat: bigint, preimage: Uint8Array, label: string, expirySeconds: number): Promise<InvoiceResult>;
  sendOnRoute(route: CircularRoute, paymentHash: string, paymentSecret: string, onDispatched?: () => void): Promise<PaymentObservation>;
  observePayment(paymentHash: string, mode?: 'track' | 'sweep'): Promise<PaymentObservation>;
  invoiceState(paymentHash: string): Promise<InvoiceState>;
  cancelUnpaidInvoice(paymentHash: string, label: string): Promise<CancelResult>;
}

export interface Alert { readonly kind: string; readonly executionId: string; readonly code: string }

export interface DispatchDeps {
  readonly db: ExecDatabase;
  readonly adapter: ExecutionAdapter;
  readonly workerId: string;
  readonly leaseMs: number;
  readonly randomBytes: (size: number) => Uint8Array;
  readonly stopSignal: AbortSignal;
  readonly attemptDeadlineMs: number;
  readonly invoiceExpirySeconds: number;
  readonly deltaToleranceMsat: bigint;
  readonly alert: (alert: Alert) => void;
}

export interface DispatchInput {
  readonly executionId: string;
  readonly fenceEpoch: bigint;
  readonly route: CircularRoute;
  readonly approval: VerifiedApproval;
  readonly policy: ExecutionPolicy;
}

export interface DispatchOutcome { readonly executionId: string; readonly exit: number; readonly step: string | null }

export interface DispatchModule { readonly dispatchExecution: (deps: DispatchDeps, input: DispatchInput) => Promise<DispatchOutcome> }

export interface LndExecutionAdapter {
  createInvoice(amountMsat: bigint, preimage: Uint8Array, label: string, expirySeconds: number): Promise<InvoiceResult>;
  sendOnRoute(route: CircularRoute, paymentHash: string, paymentSecret: string, onDispatched?: () => void): Promise<PaymentObservation>;
  observePayment(paymentHash: string, mode?: 'track' | 'sweep'): Promise<PaymentObservation>;
  invoiceState(paymentHash: string): Promise<InvoiceState>;
  cancelUnpaidInvoice(paymentHash: string, label: string): Promise<CancelResult>;
}
export interface LndExecuteModule { readonly LndExecutionAdapter: new (rest: LndRest, options: { trackDeadlineMs: number }) => LndExecutionAdapter }

export interface ClnExecutionAdapter extends LndExecutionAdapter {
  findCircularRoute(req: RouteRequest): Promise<CircularRoute | { readonly refusal: string }>;
}
export interface ClnExecuteModule {
  readonly ClnExecutionAdapter: new (rest: ClnRest, options: { ownId: string; waitChunkSeconds: number; attemptDeadlineMs: number }) => ClnExecutionAdapter;
}

export interface ReconcileDeps {
  readonly db: ExecDatabase;
  readonly adapters: ReadonlyMap<string, ExecutionAdapter>;
  readonly workerId: string;
  readonly leaseMs: number;
  readonly notFoundWindowMs: number;
  readonly escalateAfterMs: number;
  readonly confirmIntervalMs: number;
  readonly deltaToleranceMsat?: bigint;
  readonly alert: (alert: Alert) => void;
}
export interface ReconcileReport { readonly exit: number; readonly unresolved: readonly string[] }
export interface ReconcilerModule { readonly reconcile: (deps: ReconcileDeps, options: { startup: boolean }) => Promise<ReconcileReport> }

export interface CommandResult { readonly exitCode: number; readonly output: string }
export interface ActionsModule {
  readonly actionsStatus: (input: { databasePath: string; executionId: string; json: boolean }) => CommandResult;
  readonly watchActionsStatus: (input: { databasePath: string; executionId: string; pollMs: number; signal: AbortSignal }, emit: (line: string) => void) => Promise<{ exitCode: number }>;
  readonly renderExecuteOutcome: (outcome: DispatchOutcome, json: boolean) => CommandResult;
}

const load = async <T>(relative: string): Promise<T> => await import(pathToFileURL(join(repoRoot, relative)).href) as T;
export const loadDispatch = (): Promise<DispatchModule> => load<DispatchModule>('src/executor/dispatch.ts');
export const loadLndExecute = (): Promise<LndExecuteModule> => load<LndExecuteModule>('src/node-lnd/execute.ts');
export const loadClnExecute = (): Promise<ClnExecuteModule> => load<ClnExecuteModule>('src/node-cln/execute.ts');
export const loadReconciler = (): Promise<ReconcilerModule> => load<ReconcilerModule>('src/reconciler/index.ts');
export const loadActions = (): Promise<ActionsModule> => load<ActionsModule>('src/commands/actions.ts');

export interface RegtestProofLike { readonly network: 'regtest' }
export interface ExecutionCoreModule {
  readonly proveRegtest: (configured: string, handshake: { network: string; pubkey: string; version: string; synced: boolean }) => RegtestProofLike | null;
  readonly approveRoute: (route: CircularRoute, terms: { sourceChannelKey: string; targetChannelKey: string; principalMsat: bigint },
    approval: VerifiedApproval, policy: ExecutionPolicy, proof: RegtestProofLike) => { readonly route: CircularRoute } | { readonly refusal: string };
}
export const loadExecutionCore = (): Promise<ExecutionCoreModule> => load<ExecutionCoreModule>('src/core/execution.ts');

export const sha256 = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
export const OUTCOME_UNKNOWN_MESSAGE = 'outcome unknown — run `fluxwarden reconcile`; do not retry';
export const labelOf = (executionId: string): string => `fluxwarden-${executionId}`;

function withRaw<T>(path: string, work: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(path, { readBigInts: true, timeout: 5_000 });
  try { return work(db); } finally { db.close(); }
}

export interface SeedExecution {
  readonly proposalOptions?: ProposalOptions;
  readonly status: ExecutionStatus;
  readonly fenceEpoch?: bigint;
  /** Lease expiry relative to the database clock: positive is in the future. */
  readonly leaseInMs?: number;
  readonly paymentHash?: string | null;
  /** submitted_at relative to the database clock, in milliseconds before now; null leaves it NULL. */
  readonly submittedAgoMs?: number | null;
  readonly route?: CircularRoute | null;
  readonly plannedFeeMsat?: bigint | null;
}

/** An execution of a fresh approved proposal in the given state, with a HELD reservation of the approved maximum fee. */
export function seedExecution(base: Base, seed: SeedExecution): { executionId: string; approval: VerifiedApproval } {
  const approval = seedProposal(base, seed.proposalOptions);
  const now = dbNow(base.path);
  const executionId = ulid();
  withRaw(base.path, db => {
    db.prepare(`INSERT INTO executions (id, proposal_id, approval_id, worker_id, fence_epoch, lease_expires_at, status, payment_hash, route_json,
        planned_fee_msat, submitted_at, created_at, updated_at) VALUES (?, ?, ?, 'worker-a', ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(executionId, approval.proposalId, approval.approvalId, seed.fenceEpoch ?? 3n, now + (seed.leaseInMs ?? 60_000), seed.status,
        seed.paymentHash ?? null, seed.route === undefined || seed.route === null ? null : routeJson(seed.route),
        seed.plannedFeeMsat ?? null, seed.submittedAgoMs === undefined || seed.submittedAgoMs === null ? null : now - seed.submittedAgoMs,
        now - 120_000, now - 1_000);
    db.prepare(`INSERT INTO budget_reservations (id, execution_id, period_start, reserved_msat, consumed_msat, state) VALUES (?, ?, ?, ?, NULL, 'HELD')`)
      .run(ulid(), executionId, now - 120_000, approval.approvedMaxFeeMsat);
  });
  return { executionId, approval };
}

export function routeJson(route: CircularRoute): string {
  return JSON.stringify(route, (_key, value: unknown) => typeof value === 'bigint' ? value.toString() : value);
}

export interface FullRow {
  readonly status: string; readonly fence_epoch: bigint; readonly payment_hash: string | null; readonly route_json: string | null;
  readonly actual_fee_msat: bigint | null; readonly delta_status: string | null; readonly error_code: string | null;
  readonly submitted_at: bigint | null; readonly worker_id: string | null;
}

export function rowOf(path: string, executionId: string): FullRow {
  const row = withRaw(path, db => db.prepare(`SELECT status, fence_epoch, payment_hash, route_json, actual_fee_msat, delta_status, error_code,
      submitted_at, worker_id FROM executions WHERE id = ?`).get(executionId) as FullRow | undefined);
  if (row === undefined) throw new Error(`no execution ${executionId}`);
  return row;
}

/** Transitions (from_status != to_status) recorded for an execution, as "FROM>TO". */
export function transitionsOf(path: string, executionId: string): string[] {
  return withRaw(path, db => (db.prepare('SELECT from_status, to_status FROM execution_events WHERE execution_id = ? ORDER BY id')
    .all(executionId) as unknown as { from_status: string | null; to_status: string }[])
    .filter(e => e.from_status !== e.to_status).map(e => `${e.from_status ?? ''}>${e.to_status}`));
}

export function reservationState(path: string, executionId: string): { state: string; consumed: bigint | null } {
  const row = withRaw(path, db => db.prepare('SELECT state, consumed_msat FROM budget_reservations WHERE execution_id = ?').get(executionId) as
    { state: string; consumed_msat: bigint | null } | undefined);
  if (row === undefined) throw new Error(`no reservation for ${executionId}`);
  return { state: row.state, consumed: row.consumed_msat };
}

/** Every text and blob cell of every table, to search the database for a value that must not be stored. */
export function databaseText(path: string): string {
  return withRaw(path, db => {
    const tables = (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as unknown as { name: string }[]).map(t => t.name);
    return tables.map(table => JSON.stringify(db.prepare(`SELECT * FROM "${table}"`).all(),
      (_key, value: unknown) => typeof value === 'bigint' ? value.toString() : value instanceof Uint8Array ? Buffer.from(value).toString('hex') : value)).join('\n');
  });
}

/** Applies raw SQL to the database (test setup and racing writers only). */
export function exec(path: string, sql: string, ...params: (string | number | bigint | null)[]): void {
  withRaw(path, db => { db.prepare(sql).run(...params); });
}

export { PRINCIPAL };
