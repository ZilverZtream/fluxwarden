import type { VerifiedApproval } from '../approval/verified.js';
import { LndError, ProtocolError, TransportError } from '../core/errors.js';
import {
  approveRoute, invoiceLabel, proveRegtest, sourceReserveFloor,
  type ApprovedRoute, type CancelResult, type CircularRoute, type ExecutionAdapter, type ExecutionPolicy, type InvoiceState, type NodeCapability, type PreflightAdapter,
} from '../core/execution.js';
import type { NormalizedChannel } from '../core/normalize.js';
import { PersistenceError, type Database, type ExecutionPlan } from '../persistence/index.js';
import { cooldownActive } from './budget.js';
import { claimHeld } from './claim.js';

export interface PreflightDeps {
  readonly db: Database;
  readonly adapter: PreflightAdapter;
  readonly workerId: string;
  readonly leaseMs: number;
}

export interface PreflightInput {
  readonly approval: VerifiedApproval;
  readonly policy: ExecutionPolicy;
  /** key_ids of the currently configured approval keys. */
  readonly approvalKeyIds: readonly string[];
}

export type PreflightOutcome =
  | { readonly kind: 'READY'; readonly executionId: string; readonly fenceEpoch: bigint; readonly route: ApprovedRoute }
  | { readonly kind: 'CANCELLED' | 'REFUSED'; readonly executionId: string | null; readonly exit: number; readonly step: string };

/** Capabilities a circular rebalance needs from claim to outcome; bookkeeping is optional. */
const EXECUTION_CAPABILITIES: readonly NodeCapability[] = [
  'CHANNEL_READ', 'PAYMENT_READ', 'INVOICE_CREATE', 'INVOICE_CANCEL', 'ROUTE_QUERY_PINNED', 'SEND_TO_ROUTE', 'PAYMENT_TRACK',
];

/** Route refusal codes a node answer may carry into an execution's error code; anything else is NO_FEASIBLE_ROUTE. */
const ROUTE_REFUSALS: ReadonlySet<string> = new Set([
  'NO_FEASIBLE_ROUTE', 'FEE_CEILING_EXCEEDED', 'PPM_CEILING_EXCEEDED', 'CLTV_DELTA_UNSAFE', 'RESERVE_FLOOR', 'SINGLE_PATH_UNAVAILABLE',
  'REPEATED_CHANNEL', 'SAME_PEER', 'FIRST_HOP_SPENDABLE', 'LAST_HOP_RECEIVABLE',
]);

const REGTEST = 'regtest';

/** Attempts to write the cancellation after a failure, each bounded by the database busy timeout. */
const CANCEL_ATTEMPTS = 3;

interface Refusal { readonly exit: number; readonly step: string }

function ppmCeil(feeMsat: bigint, principalMsat: bigint): bigint {
  return (feeMsat * 1_000_000n + principalMsat - 1n) / principalMsat;
}

/**
 * The route validation list (SPEC §5.5) on the live route and the fresh snapshot of S and T, under the approved caps.
 * F is recomputed from the hop amounts. Returns the refusal code, or null when the route may be used.
 */
function routeRefusal(
  route: CircularRoute, plan: ExecutionPlan, source: NormalizedChannel, target: NormalizedChannel,
  approval: VerifiedApproval, policy: ExecutionPolicy,
): string | null {
  const principal = plan.principalMsat;
  const first = route.hops[0];
  const last = route.hops[route.hops.length - 1];
  // V6
  if (route.parts !== 1 || route.principalMsat !== principal) return 'SINGLE_PATH_UNAVAILABLE';
  // V1
  if (first === undefined || last === undefined || route.hops.length < 3) return 'NO_FEASIBLE_ROUTE';
  if (route.sourceChannelKey !== plan.sourceChannelKey || first.channelKey !== plan.sourceChannelKey) return 'NO_FEASIBLE_ROUTE';
  if (route.targetChannelKey !== plan.targetChannelKey || last.channelKey !== plan.targetChannelKey) return 'NO_FEASIBLE_ROUTE';
  if (first.nodeOut !== source.peerPubkey || route.outPeer !== source.peerPubkey) return 'NO_FEASIBLE_ROUTE';
  if (last.nodeOut !== plan.nodePubkey || route.inPeer !== target.peerPubkey) return 'NO_FEASIBLE_ROUTE';
  // V12 for the channels FluxWarden observes itself
  if (source.state !== 'ACTIVE' || target.state !== 'ACTIVE') return 'NO_FEASIBLE_ROUTE';
  // V2 and V11: no channel twice, and no hop back to us before the last one
  if (new Set(route.hops.map(hop => hop.channelKey)).size !== route.hops.length) return 'REPEATED_CHANNEL';
  if (route.hops.slice(0, -1).some(hop => hop.nodeOut === plan.nodePubkey)) return 'REPEATED_CHANNEL';
  // V7
  if (route.outPeer === route.inPeer) return 'SAME_PEER';
  // V10 and V3: the final hop delivers P, amounts never grow along the path, F = first-hop amount - P
  if (last.amountOutMsat !== principal) return 'NO_FEASIBLE_ROUTE';
  for (let i = 1; i < route.hops.length; i += 1) {
    const before = route.hops[i - 1];
    const hop = route.hops[i];
    if (before === undefined || hop === undefined || hop.amountOutMsat > before.amountOutMsat) return 'NO_FEASIBLE_ROUTE';
  }
  const fee = first.amountOutMsat - principal;
  if (fee !== route.totalFeeMsat) return 'NO_FEASIBLE_ROUTE';
  if (fee > approval.approvedMaxFeeMsat || fee > policy.maxFeeMsat) return 'FEE_CEILING_EXCEEDED';
  // V4
  if (fee > policy.exemptFeeMsat && ppmCeil(fee, principal) > policy.maxFeePpm) return 'PPM_CEILING_EXCEEDED';
  // V5
  if (!Number.isSafeInteger(route.totalTimelockDelta) || route.totalTimelockDelta < 0) return 'CLTV_DELTA_UNSAFE';
  if (route.totalTimelockDelta > approval.approvedMaxCltvDelta || route.totalTimelockDelta > policy.maxCltvDelta) return 'CLTV_DELTA_UNSAFE';
  for (let i = 1; i < route.hops.length; i += 1) {
    const before = route.hops[i - 1];
    const hop = route.hops[i];
    if (before === undefined || hop === undefined || before.expiry < hop.expiry) return 'CLTV_DELTA_UNSAFE';
  }
  // V8 and V9 on the fresh snapshot
  if (source.spendableMsat < principal + fee) return 'FIRST_HOP_SPENDABLE';
  if (source.spendableMsat - (principal + fee) < sourceReserveFloor(policy)) return 'RESERVE_FLOOR';
  if (target.receivableMsat < principal) return 'LAST_HOP_RECEIVABLE';
  return null;
}

function routeJson(route: CircularRoute): string {
  return JSON.stringify(route, (_key, value: unknown) => typeof value === 'bigint' ? value.toString() : value);
}

function leaseLost(error: unknown): boolean {
  return error instanceof PersistenceError && error.code === 'LEASE_LOST';
}

/** A node call that failed: transport, TLS, authentication or protocol trouble is exit 4 (SPEC §5.2 H2, §10.2). */
function nodeFailure(error: unknown): Refusal {
  if (error instanceof TransportError || error instanceof ProtocolError || error instanceof LndError) return { exit: 4, step: 'NODE_UNREACHABLE' };
  return { exit: 8, step: 'internal' };
}

/**
 * Claims the execution and runs preflight: the regtest lock, node identity, chain sync, capabilities, cooldowns, a fresh
 * snapshot of S and T, the reserve floor and full validation of a live route under the approved caps. A failed check or
 * a failed node call cancels the execution (reservation released) before any mutating node call; a passing preflight
 * records the live route and leaves the row in PREFLIGHT. Every write is fenced and renews the lease, and the worker
 * stops at the first sign that its lease was taken over.
 */
export async function prepareExecution(deps: PreflightDeps, input: PreflightInput): Promise<PreflightOutcome> {
  const { db, adapter, workerId, leaseMs } = deps;
  const { approval, policy, approvalKeyIds } = input;

  // INV-15: the configured network is checked before anything is written or any node is asked.
  if (policy.network !== REGTEST) return { kind: 'REFUSED', executionId: null, exit: 5, step: 'network-lock' };

  const claim = claimHeld(db, { approval, policy, approvalKeyIds, workerId, leaseMs });
  if (!claim.ok) {
    const cancelled = claim.step === 'BUDGET_EXHAUSTED' || claim.step === 'COOLDOWN_ACTIVE';
    return { kind: cancelled ? 'CANCELLED' : 'REFUSED', executionId: claim.executionId, exit: claim.exit, step: claim.step };
  }
  const { executionId } = claim;
  let epoch = claim.fenceEpoch;
  const lost: PreflightOutcome = { kind: 'REFUSED', executionId, exit: 5, step: 'lease-lost' };

  const fenced = (write: () => bigint): boolean => {
    try {
      epoch = write();
      return true;
    } catch (error) {
      if (leaseLost(error)) return false;
      throw error;
    }
  };
  let status: 'CLAIMED' | 'PREFLIGHT' = claim.status === 'PREFLIGHT' ? 'PREFLIGHT' : 'CLAIMED';
  const held = (): boolean => db.executions.holds(executionId, epoch);
  const cancel = (refusal: Refusal): PreflightOutcome =>
    fenced(() => db.executions.transition(executionId, epoch, status, 'CANCELLED', { errorCode: refusal.step }))
      ? { kind: 'CANCELLED', executionId, exit: refusal.exit, step: refusal.step }
      : lost;
  const refuse = (step: string, exit = 5): PreflightOutcome => cancel({ exit, step });

  try {
    if (status === 'CLAIMED') {
      if (!fenced(() => db.executions.transition(executionId, epoch, 'CLAIMED', 'PREFLIGHT', { leaseMs }))) return lost;
      status = 'PREFLIGHT';
    }
    const plan = db.executions.plan(executionId);
    if (plan === null) throw new Error(`execution ${executionId} has no proposal channels`);

    const identity = await adapter.handshake();
    if (!held()) return lost;
    if (identity.pubkey !== plan.nodePubkey) return refuse('identity');
    const regtest = proveRegtest(policy.network, identity);
    if (regtest === null) return refuse('network-lock');
    if (!identity.synced) return refuse('chain-sync');

    const capabilities = adapter.capabilities();
    if (EXECUTION_CAPABILITIES.some(capability => !capabilities.has(capability))) return refuse('CAPABILITY_UNSUPPORTED', 3);

    if (cooldownActive(db.now(), db.budget.lastTerminal(plan.sourceChannelId, plan.targetChannelId), policy)) return refuse('COOLDOWN_ACTIVE');

    const channels = await adapter.listChannels();
    if (!held()) return lost;
    const fresh = (channel: NormalizedChannel | undefined): channel is NormalizedChannel =>
      channel !== undefined && Math.abs(db.now() - channel.observedAt) <= policy.maxSnapshotAgeMs;
    const source = channels.find(channel => channel.channelKey === plan.sourceChannelKey);
    const target = channels.find(channel => channel.channelKey === plan.targetChannelKey);
    if (!fresh(source) || !fresh(target)) return refuse('STALE_SNAPSHOT');
    if (source.spendableMsat - (plan.principalMsat + approval.approvedMaxFeeMsat) < sourceReserveFloor(policy)) return refuse('RESERVE_FLOOR');

    const answer = await adapter.findCircularRoute({
      sourceChannelKey: plan.sourceChannelKey,
      targetChannelKey: plan.targetChannelKey,
      principalMsat: plan.principalMsat,
      maxFeeMsat: approval.approvedMaxFeeMsat,
      maxFeePpm: policy.maxFeePpm,
      exemptFeeMsat: policy.exemptFeeMsat,
      maxCltvDelta: approval.approvedMaxCltvDelta,
      ...(policy.excludeChannels === undefined ? {} : { excludeChannels: policy.excludeChannels }),
    }, { db, executionId, fenceEpoch: epoch });
    if (!held()) return lost;
    if (!fresh(source) || !fresh(target)) return refuse('STALE_SNAPSHOT');
    if ('refusal' in answer) return refuse(ROUTE_REFUSALS.has(answer.refusal) ? answer.refusal : 'NO_FEASIBLE_ROUTE');
    const refusal = routeRefusal(answer, plan, source, target, approval, policy);
    if (refusal !== null) return refuse(refusal);
    const approved = approveRoute(answer, plan, approval, policy, regtest, { nodePubkey: plan.nodePubkey, implementation: plan.implementation, channels });
    if ('refusal' in approved) return refuse(approved.refusal);

    if (db.executions.authorityLapsed(executionId)) return refuse('APPROVAL_INVALID');
    const recorded = fenced(() => db.executions.transition(executionId, epoch, 'PREFLIGHT', 'PREFLIGHT', {
      routeJson: routeJson(answer), plannedFeeMsat: answer.totalFeeMsat, leaseMs,
    }));
    if (!recorded) return lost;
    return { kind: 'READY', executionId, fenceEpoch: epoch, route: approved.route };
  } catch (error) {
    return abandon(error);
  }

  /**
   * Nothing has been sent, so any failure after the claim cancels the execution and releases its reservation. A locked
   * database is retried a bounded number of times (each attempt waits out the busy timeout); if the cancellation still
   * cannot be written, the original error is raised and the row is left to lease expiry.
   */
  function abandon(error: unknown): PreflightOutcome {
    const refusal = error instanceof PersistenceError ? { exit: 8, step: 'internal' } : nodeFailure(error);
    for (let attempt = 0; attempt < CANCEL_ATTEMPTS; attempt += 1) {
      try {
        return held() ? cancel(refusal) : lost;
      } catch (retry) {
        if (!(retry instanceof PersistenceError && retry.code === 'BUSY')) break;
      }
    }
    throw error;
  }
}

/**
 * Restart sweep: every CLAIMED/PREFLIGHT execution whose lease has expired and whose approval or proposal has expired
 * by the database clock is taken over with a fenced lease. A persisted invoice is looked up and closed using the
 * admitted adapter for its node before cancellation; paid evidence goes to observation-only recovery instead.
 * Ambiguous cleanup remains pending. A row another worker takes first is left to that worker.
 */
export async function recoverPreflight(deps: Pick<PreflightDeps, 'db' | 'workerId' | 'leaseMs'> & {
  /** Already admitted for the persisted node's identity and regtest network, as in ordinary reconciliation. */
  readonly adapter?: Pick<ExecutionAdapter, 'invoiceState' | 'cancelUnpaidInvoice'>;
  /** Admitted adapters keyed by nodes.id for a multi-node recovery pass. */
  readonly adapters?: ReadonlyMap<string, Pick<ExecutionAdapter, 'invoiceState' | 'cancelUnpaidInvoice'>>;
}): Promise<{ cancelled: readonly string[] }> {
  const { db, workerId, leaseMs } = deps;
  const cancelled: string[] = [];
  try {
    for (const executionId of db.executions.lapsedClaims()) {
      const hash = db.executions.view(executionId)?.paymentHash ?? null;
      let adapter: Pick<ExecutionAdapter, 'invoiceState' | 'cancelUnpaidInvoice'> | undefined;
      if (hash !== null) {
        const plan = db.executions.plan(executionId);
        const node = plan === null ? undefined : db.nodes.list().find(entry => entry.expectedPubkey === plan.nodePubkey && entry.implementation === plan.implementation);
        adapter = deps.adapters === undefined ? deps.adapter : node === undefined ? undefined : deps.adapters.get(node.id);
        // Leave the expired lease available to a later pass admitted for this invoice's node.
        if (node === undefined || adapter === undefined) continue;
      }
      const held = db.executions.takeOver(executionId, workerId, leaseMs);
      if (held === null) continue;
      if (hash !== null) {
        if (adapter === undefined || held.status !== 'PREFLIGHT') continue;
        let invoice: InvoiceState;
        try { invoice = await adapter.invoiceState(hash); } catch { continue; }
        if (invoice === 'SETTLED') {
          db.executions.recordPaidIntent(executionId, held.fenceEpoch, hash);
          continue;
        }
        if (!db.executions.holds(executionId, held.fenceEpoch)) continue;
        if (invoice === 'OPEN') {
          let closed: CancelResult;
          try { closed = await adapter.cancelUnpaidInvoice(hash, invoiceLabel(executionId)); } catch { continue; }
          if (closed === 'ALREADY_PAID') {
            db.executions.recordPaidIntent(executionId, held.fenceEpoch, hash);
            continue;
          }
          if (!db.executions.holds(executionId, held.fenceEpoch)) continue;
        }
      }
      db.executions.transition(executionId, held.fenceEpoch, held.status, 'CANCELLED', { errorCode: 'APPROVAL_INVALID' });
      cancelled.push(executionId);
    }
  } catch (error) {
    throw error instanceof Error ? error : new Error(String(error));
  }
  return { cancelled };
}
