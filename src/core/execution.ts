import type { NormalizedChannel } from './normalize.js';

export type ExecutionStatus =
  | 'CLAIMED' | 'PREFLIGHT' | 'SUBMITTING' | 'IN_FLIGHT' | 'VERIFIED_SUCCESS' | 'VERIFIED_FAILURE' | 'UNKNOWN' | 'CANCELLED';

/**
 * Status changes a fenced write may make. A row stays in PREFLIGHT while preflight records the live route; re-claims
 * and lease renewals keep the status and are not transitions.
 */
const TRANSITIONS: Readonly<Record<ExecutionStatus, readonly ExecutionStatus[]>> = {
  CLAIMED: ['PREFLIGHT', 'CANCELLED'],
  PREFLIGHT: ['PREFLIGHT', 'SUBMITTING', 'CANCELLED'],
  SUBMITTING: ['IN_FLIGHT', 'UNKNOWN', 'VERIFIED_FAILURE'],
  IN_FLIGHT: ['VERIFIED_SUCCESS', 'VERIFIED_FAILURE', 'UNKNOWN'],
  UNKNOWN: ['VERIFIED_SUCCESS', 'VERIFIED_FAILURE'],
  VERIFIED_SUCCESS: [],
  VERIFIED_FAILURE: [],
  CANCELLED: [],
};

export function transitionAllowed(from: ExecutionStatus, to: ExecutionStatus): boolean {
  return TRANSITIONS[from].includes(to);
}

/** Statuses a worker may re-claim once the lease has expired: nothing has been sent yet. */
export const RECLAIMABLE: readonly ExecutionStatus[] = ['CLAIMED', 'PREFLIGHT'];

export type NetworkType = 'regtest' | 'signet' | 'testnet' | 'testnet4' | 'mainnet';

export type NodeCapability =
  | 'CHANNEL_READ' | 'PAYMENT_READ' | 'INVOICE_CREATE' | 'INVOICE_CANCEL' | 'ROUTE_QUERY_PINNED' | 'SEND_TO_ROUTE' | 'PAYMENT_TRACK'
  | 'BOOKKEEPER_READ';

/** The terms an operator approval carries (SECURITY §4.1). Times are unix milliseconds. */
export interface ApprovalTerms {
  readonly approvalId: string;
  readonly proposalId: string;
  readonly keyId: string;
  readonly nonce: string;
  readonly proposalDigest: string;
  readonly policySha256: string;
  readonly approvedMaxFeeMsat: bigint;
  readonly approvedMaxCltvDelta: number;
  readonly expiresAt: number;
}

declare const verified: unique symbol;

/**
 * Approval terms whose token passed every verification step of SECURITY §4.1 against the configured public keys.
 * The executor accepts nothing else, so an unverified record, or one signed by a key no longer configured, cannot
 * reach a claim. Only approval verification marks terms as verified (src/approval/verified.ts).
 */
export type VerifiedApproval = ApprovalTerms & { readonly [verified]: true };

/** The validated active policy as execution uses it; durations in milliseconds. */
export interface ExecutionPolicy {
  readonly sha256: string;
  readonly network: string;
  readonly maxFeeMsat: bigint;
  readonly maxFeePpm: bigint;
  readonly exemptFeeMsat: bigint;
  readonly maxCltvDelta: number;
  readonly minChannelReserveMsat: bigint;
  readonly budget: { readonly msat: bigint; readonly periodMs: number };
  readonly cooldownAfterFailureMs: number;
  readonly cooldownAfterSuccessMs: number;
  readonly maxInFlight: number;
  readonly maxSnapshotAgeMs: number;
}

export interface RouteHop {
  readonly channelKey: string;
  readonly nodeOut: string;
  readonly amountOutMsat: bigint;
  readonly expiry: number;
}

export interface CircularRoute {
  readonly sourceChannelKey: string;
  readonly targetChannelKey: string;
  readonly outPeer: string;
  readonly inPeer: string;
  readonly principalMsat: bigint;
  readonly hops: readonly RouteHop[];
  readonly totalFeeMsat: bigint;
  readonly feePpmCeil: bigint;
  readonly totalTimelockDelta: number;
  readonly parts: number;
}

export interface RouteRequest {
  readonly sourceChannelKey: string;
  readonly targetChannelKey: string;
  readonly principalMsat: bigint;
  readonly maxFeeMsat: bigint;
  readonly maxFeePpm: bigint;
  readonly exemptFeeMsat: bigint;
  readonly maxCltvDelta: number;
}

export interface NodeHandshake {
  readonly pubkey: string;
  readonly network: string;
  readonly version: string;
  readonly synced: boolean;
}

/** The node adapter methods execution uses up to dispatch. Only the last three change node state. */
export interface PreflightAdapter {
  handshake(): Promise<NodeHandshake>;
  capabilities(): ReadonlySet<NodeCapability>;
  listChannels(): Promise<readonly NormalizedChannel[]>;
  findCircularRoute(req: RouteRequest): Promise<CircularRoute | { readonly refusal: string }>;
  createInvoice(...args: never[]): Promise<unknown>;
  sendOnRoute(...args: never[]): Promise<unknown>;
  cancelUnpaidInvoice(...args: never[]): Promise<unknown>;
}

/**
 * What a node reports about one payment hash. Preimages never leave the adapter: only whether one hashing to the
 * payment hash was reported.
 */
export type PaymentObservation =
  | { readonly kind: 'SUCCEEDED'; readonly preimageMatchesHash: boolean; readonly feeMsat: bigint; readonly htlcCount: number; readonly settledChannelKey: string | null }
  | { readonly kind: 'FAILED'; readonly reason: string; readonly local: boolean; readonly htlcsInFlight: number }
  /** LND IN_FLIGHT and INITIATED, LND FAILED with an HTLC in flight, CLN pending. */
  | { readonly kind: 'IN_FLIGHT' }
  /** The node has no record of the hash. */
  | { readonly kind: 'NOT_FOUND' }
  /** The answer was lost or unreadable after the request may have reached the node. */
  | { readonly kind: 'AMBIGUOUS'; readonly cause: string };

export interface InvoiceResult {
  /** 64 lowercase hex characters. */
  readonly paymentHash: string;
  /** 64 lowercase hex characters. */
  readonly paymentSecret: string;
  readonly finalCltvDelta: number;
}

export type InvoiceState = 'OPEN' | 'SETTLED' | 'CANCELED' | 'NOT_FOUND';
export type CancelResult = 'CANCELED' | 'ALREADY_PAID' | 'NOT_FOUND';

/**
 * The node adapter methods the executor and the reconciler use from dispatch on. `onDispatched` runs once, as soon as
 * the payment request has been written. `mode` 'sweep' reads the payer side from the node's payment list, never from a
 * live stream.
 */
export interface ExecutionAdapter {
  listChannels(): Promise<readonly NormalizedChannel[]>;
  createInvoice(amountMsat: bigint, preimage: Uint8Array, label: string, expirySeconds: number): Promise<InvoiceResult>;
  sendOnRoute(route: CircularRoute, paymentHash: string, paymentSecret: string, onDispatched?: () => void): Promise<PaymentObservation>;
  observePayment(paymentHash: string, mode?: 'track' | 'sweep'): Promise<PaymentObservation>;
  invoiceState(paymentHash: string): Promise<InvoiceState>;
  cancelUnpaidInvoice(paymentHash: string, label: string): Promise<CancelResult>;
}

export type AlertKind = 'INVARIANT_BREACH' | 'fee-mismatch' | 'delta-mismatch' | 'stuck-in-flight';

export interface Alert {
  readonly kind: AlertKind;
  readonly executionId: string;
  readonly code: string;
}

/** The invoice label of an execution; CLN deletes the invoice by it. */
export function invoiceLabel(executionId: string): string {
  return `fluxwarden-${executionId}`;
}

declare const regtestBrand: unique symbol;

/** Evidence, taken from a node handshake, that both the configured and the node-reported network are exactly regtest (INV-15). */
export interface RegtestProof {
  readonly network: 'regtest';
  readonly [regtestBrand]: true;
}

const regtestProofs = new WeakSet();

/**
 * The only constructor of a RegtestProof: derived from the handshake the node answered, and only when its network and
 * the configured network are both exactly `regtest`.
 */
export function proveRegtest(configuredNetwork: string, handshake: NodeHandshake): RegtestProof | null {
  if (configuredNetwork !== 'regtest' || handshake.network !== 'regtest') return null;
  const proof = Object.freeze({ network: 'regtest' }) as RegtestProof;
  regtestProofs.add(proof);
  return proof;
}

declare const approvedBrand: unique symbol;

/** A frozen live route that passed the dispatch checks under the approved caps on a node proven to be on regtest. */
export type ApprovedRoute = CircularRoute & { readonly [approvedBrand]: true };

const approvedRoutes = new WeakSet();

/** Whether `route` is a value approveRoute returned (and therefore unchanged since). */
export function isApprovedRoute(route: unknown): route is ApprovedRoute {
  return typeof route === 'object' && route !== null && approvedRoutes.has(route);
}

/** What the stored proposal fixes about a route. */
export interface RouteTerms {
  readonly sourceChannelKey: string;
  readonly targetChannelKey: string;
  readonly principalMsat: bigint;
}

/** What the node and its newest snapshot add: our pubkey, the implementation's send padding, the state of S and T. */
export interface RouteContext {
  readonly nodePubkey: string;
  readonly implementation: 'lnd' | 'cln';
  readonly channels: readonly NormalizedChannel[];
}

function ppmCeil(feeMsat: bigint, principalMsat: bigint): bigint {
  return (feeMsat * 1_000_000n + principalMsat - 1n) / principalMsat;
}

/**
 * Blocks the node adds above the route's delta when it sends: CLN sends at height + 1 + cltv_out (Decision D52); an
 * LND route's delta already carries its padding (SPEC §5.1 CircularRoute).
 */
function sendPadding(implementation: 'lnd' | 'cln'): number {
  return implementation === 'cln' ? 1 : 0;
}

type Verdict = { readonly route: ApprovedRoute } | { readonly refusal: string };

function contextRefusal(route: CircularRoute, terms: RouteTerms, policy: ExecutionPolicy, context: RouteContext): string | null {
  const first = route.hops[0];
  const last = route.hops[route.hops.length - 1];
  if (first === undefined || last === undefined) return 'NO_FEASIBLE_ROUTE';
  // V1 back to our node; V11 not through it before the end.
  if (last.nodeOut !== context.nodePubkey) return 'NO_FEASIBLE_ROUTE';
  if (route.hops.slice(0, -1).some(hop => hop.nodeOut === context.nodePubkey)) return 'REPEATED_CHANNEL';
  // V8, V9, V12 against our newest view of S and T.
  const source = context.channels.find(channel => channel.channelKey === terms.sourceChannelKey);
  const target = context.channels.find(channel => channel.channelKey === terms.targetChannelKey);
  if (source === undefined || target === undefined || source.peerPubkey !== route.outPeer || target.peerPubkey !== route.inPeer) return 'NO_FEASIBLE_ROUTE';
  if (source.spendableMsat < first.amountOutMsat) return 'FIRST_HOP_SPENDABLE';
  if (source.spendableMsat - first.amountOutMsat < policy.minChannelReserveMsat) return 'RESERVE_FLOOR';
  if (target.receivableMsat < terms.principalMsat) return 'LAST_HOP_RECEIVABLE';
  if (source.state !== 'ACTIVE' || target.state !== 'ACTIVE') return 'NO_FEASIBLE_ROUTE';
  return null;
}

/**
 * Route validation (SPEC §5.5) of the live route before dispatch, on the facts a circular route carries, under the
 * approved caps: V1 S first and T last, V2 no repeated channel, V3/V4 fee and ppm caps with the fee recomputed from
 * the hops and the route's totals agreeing with it, V5 the approved CLTV delta with expiries that never rise, V6 one
 * part, V7 distinct peers, V10 amounts that never rise and deliver exactly P. With the node context also V1/V11 against
 * our pubkey, the CLN send padding in V5, and V8/V9/V12 against our channels. The only constructor of an ApprovedRoute,
 * which needs a RegtestProof from proveRegtest; the route returned is a frozen copy.
 */
export function approveRoute(
  route: CircularRoute, terms: RouteTerms, approval: VerifiedApproval, policy: ExecutionPolicy, regtest: RegtestProof, context?: RouteContext,
): Verdict {
  // A value shaped like a proof but not made by proveRegtest is refused.
  if (!regtestProofs.has(regtest)) return { refusal: 'network-lock' };
  const hops = route.hops;
  const first = hops[0];
  const last = hops[hops.length - 1];
  const beforeLast = hops[hops.length - 2];
  const principal = terms.principalMsat;
  if (first === undefined || last === undefined || beforeLast === undefined || principal <= 0n) return { refusal: 'NO_FEASIBLE_ROUTE' };
  // V1
  if (route.sourceChannelKey !== terms.sourceChannelKey || first.channelKey !== terms.sourceChannelKey || first.nodeOut !== route.outPeer) return { refusal: 'NO_FEASIBLE_ROUTE' };
  if (route.targetChannelKey !== terms.targetChannelKey || last.channelKey !== terms.targetChannelKey || beforeLast.nodeOut !== route.inPeer) return { refusal: 'NO_FEASIBLE_ROUTE' };
  if (route.principalMsat !== principal) return { refusal: 'NO_FEASIBLE_ROUTE' };
  // V2
  if (new Set(hops.map(hop => hop.channelKey)).size !== hops.length) return { refusal: 'REPEATED_CHANNEL' };
  // V3, V4: F from the hops; the route's own totals must agree with it.
  const fee = first.amountOutMsat - principal;
  if (fee < 0n || route.totalFeeMsat !== fee || route.feePpmCeil !== ppmCeil(fee, principal)) return { refusal: 'NO_FEASIBLE_ROUTE' };
  if (fee > approval.approvedMaxFeeMsat || fee > policy.maxFeeMsat) return { refusal: 'FEE_CEILING_EXCEEDED' };
  if (fee > policy.exemptFeeMsat && ppmCeil(fee, principal) > policy.maxFeePpm) return { refusal: 'PPM_CEILING_EXCEEDED' };
  // V5, and V10 for what each node passes on.
  const padding = context === undefined ? 0 : sendPadding(context.implementation);
  const cap = Math.min(approval.approvedMaxCltvDelta, policy.maxCltvDelta);
  if (!Number.isSafeInteger(route.totalTimelockDelta) || route.totalTimelockDelta <= 0 || route.totalTimelockDelta + padding > cap) return { refusal: 'CLTV_DELTA_UNSAFE' };
  for (let i = 1; i < hops.length; i += 1) {
    const previous = hops[i - 1];
    const hop = hops[i];
    if (previous === undefined || hop === undefined || hop.expiry > previous.expiry) return { refusal: 'CLTV_DELTA_UNSAFE' };
    if (hop.amountOutMsat > previous.amountOutMsat) return { refusal: 'NO_FEASIBLE_ROUTE' };
  }
  if (last.expiry <= first.expiry - route.totalTimelockDelta) return { refusal: 'CLTV_DELTA_UNSAFE' };
  // V6, V7, V10 final amount.
  if (route.parts !== 1) return { refusal: 'SINGLE_PATH_UNAVAILABLE' };
  if (route.outPeer === route.inPeer) return { refusal: 'SAME_PEER' };
  if (last.amountOutMsat !== principal) return { refusal: 'NO_FEASIBLE_ROUTE' };
  const refusal = context === undefined ? null : contextRefusal(route, terms, policy, context);
  if (refusal !== null) return { refusal };
  const approved = Object.freeze({ ...route, hops: Object.freeze(route.hops.map(hop => Object.freeze({ ...hop }))) }) as ApprovedRoute;
  approvedRoutes.add(approved);
  return { route: approved };
}
