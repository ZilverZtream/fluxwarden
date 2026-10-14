import { createHash } from 'node:crypto';
import {
  invoiceLabel, isApprovedRoute,
  type Alert, type ApprovedRoute, type CancelResult, type CircularRoute, type ExecutionAdapter, type ExecutionPolicy, type ExecutionStatus, type InvoiceResult, type PaymentObservation,
} from '../core/execution.js';
import type { VerifiedApproval } from '../approval/verified.js';
import { ExitCode } from '../core/exit-codes.js';
import type { NormalizedChannel } from '../core/normalize.js';
import { PersistenceError, type Database, type DeltaStatus, type TransitionFields } from '../persistence/index.js';

export interface DispatchDeps {
  readonly db: Database;
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

/**
 * A claimed, preflighted execution: PREFLIGHT, its live route recorded at `fenceEpoch`. The route type can only be
 * built by approveRoute, which needs the RegtestProof of the preflight network check.
 */
export interface DispatchInput {
  readonly executionId: string;
  readonly fenceEpoch: bigint;
  readonly route: ApprovedRoute;
  readonly approval: VerifiedApproval;
  readonly policy: ExecutionPolicy;
}

export interface DispatchOutcome {
  readonly executionId: string;
  readonly exit: number;
  readonly step: string | null;
}

export const OUTCOME_UNKNOWN = 'OUTCOME_UNKNOWN';
const INTERRUPTED = 'INTERRUPTED';
const LEASE_LOST = 'lease-lost';
const PREIMAGE_BYTES = 32;
const PAID_BEFORE_SUBMISSION = 'PAID_BEFORE_SUBMISSION';

class LeaseLost extends Error {
  constructor() {
    super('the execution lease was lost');
    this.name = 'LeaseLost';
  }
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function routeJson(route: CircularRoute): string {
  return JSON.stringify(route, (_key, value: unknown) => typeof value === 'bigint' ? value.toString() : value);
}

/** Blocks between the route's build height and the expiry of the HTLC that reaches us: what our invoice may ask for. */
function finalDelta(route: CircularRoute): number {
  const first = route.hops[0];
  const last = route.hops[route.hops.length - 1];
  if (first === undefined || last === undefined) return 0;
  return last.expiry - (first.expiry - route.totalTimelockDelta);
}

function absolute(value: bigint): bigint {
  return value < 0n ? -value : value;
}

function localBalance(channels: readonly NormalizedChannel[] | null, channelKey: string): bigint | null {
  const channel = channels?.find(entry => entry.channelKey === channelKey);
  return channel === undefined ? null : channel.localBalanceMsat;
}

type WaitResult =
  | { readonly kind: 'answer'; readonly observation: PaymentObservation }
  | { readonly kind: 'rejected' }
  | { readonly kind: 'deadline' }
  | { readonly kind: 'stopped' };

/**
 * Waits for the send's answer, bounded by the attempt deadline and the stop signal. The send itself is never
 * cancelled: whatever it reports after the bound is ignored here and left to the reconciler.
 */
function boundedWait(send: Promise<PaymentObservation>, deadlineMs: number, signal: AbortSignal): Promise<WaitResult> {
  return new Promise<WaitResult>(resolve => {
    let done = false;
    const finish = (result: WaitResult): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      resolve(result);
    };
    const onAbort = (): void => { finish({ kind: 'stopped' }); };
    const timer = setTimeout(() => { finish({ kind: 'deadline' }); }, deadlineMs);
    if (signal.aborted) { onAbort(); return; }
    signal.addEventListener('abort', onAbort, { once: true });
    send.then(observation => { finish({ kind: 'answer', observation }); }, () => { finish({ kind: 'rejected' }); });
  });
}

/**
 * Drives one preflighted execution from intent to outcome (SPEC §8.3 P5-P7): the preimage hash is stored before the
 * invoice and before any payment byte, the lease is re-asserted immediately before the one send, and from the send on
 * only node evidence ends the execution. Every state write is fenced; a write that finds the row taken over stops the
 * worker without any further node call. An ambiguous outcome is left UNKNOWN for the reconciler; nothing is ever sent
 * twice.
 */
export async function dispatchExecution(deps: DispatchDeps, input: DispatchInput): Promise<DispatchOutcome> {
  const { db, adapter, stopSignal } = deps;
  const { executionId, route, approval } = input;
  const label = invoiceLabel(executionId);
  let epoch = input.fenceEpoch;
  const outcome = (exit: number, step: string | null): DispatchOutcome => ({ executionId, exit, step });

  const fenced = (from: ExecutionStatus, to: ExecutionStatus, fields?: TransitionFields): void => {
    try {
      epoch = db.executions.transition(executionId, epoch, from, to, fields);
    } catch (error) {
      if (error instanceof PersistenceError && error.code === 'LEASE_LOST') throw new LeaseLost();
      throw error;
    }
  };

  // Before the send: a lost lease means nothing was sent and nothing more may be done (exit 5).
  let hash: string | null = null;
  let paid = false;
  const admitPaid = (stored: string): void => {
    deps.alert({ kind: 'INVARIANT_BREACH', executionId, code: PAID_BEFORE_SUBMISSION });
    try {
      epoch = db.executions.recordPaidIntent(executionId, epoch, stored, { routeJson: routeJson(route) });
    } catch (error) {
      if (error instanceof PersistenceError && error.code === 'LEASE_LOST') throw new LeaseLost();
      throw error;
    }
    paid = true;
  };
  const closeInvoice = async (): Promise<boolean> => {
    if (hash === null) return false;
    if (!db.executions.holds(executionId, epoch)) throw new LeaseLost();
    try {
      return await adapter.cancelUnpaidInvoice(hash, label) === 'ALREADY_PAID';
    } catch {
      // Nothing was sent; an invoice that could not be closed only expires.
      return false;
    }
  };
  // Read through a function: the signal can change during any await.
  const stopped = (): boolean => stopSignal.aborted;
  type PreparedPayment = { readonly paymentHash: string; readonly paymentSecret: string; readonly baseline: readonly NormalizedChannel[] | null };
  const paidPreparation = (baseline: readonly NormalizedChannel[] | null): PreparedPayment => {
    if (hash === null) throw new Error('a paid observation needs its stored payment hash');
    admitPaid(hash);
    return { paymentHash: hash, paymentSecret: '', baseline };
  };
  const interrupt = async (): Promise<DispatchOutcome | PreparedPayment> => {
    if (await closeInvoice()) return paidPreparation(null);
    fenced('PREFLIGHT', 'CANCELLED', { errorCode: INTERRUPTED });
    return outcome(ExitCode.INTERRUPTED, INTERRUPTED);
  };
  /**
   * A worker stopped after the hash was stored (SPEC §8.3 crash point after P5). Its preimage is gone, so the intent
   * cannot be completed and is never retried with another hash: the stored invoice is closed and the execution
   * cancelled. Nothing was sent for it. If our invoice turns out paid, money moved under this hash: the row takes the
   * success path on the node's evidence (SPEC §8.2, §8.4) with an INVARIANT_BREACH alert, and is never left in PREFLIGHT.
   */
  const abandonIntent = async (stored: string): Promise<DispatchOutcome | 'paid'> => {
    let closed: CancelResult | null;
    try {
      closed = await adapter.cancelUnpaidInvoice(stored, label);
    } catch {
      closed = null;
    }
    if (closed === 'ALREADY_PAID') {
      // The payment exists already: max_in_flight cannot refuse it.
      admitPaid(stored);
      return 'paid';
    }
    fenced('PREFLIGHT', 'CANCELLED', { errorCode: 'INTENT_INCOMPLETE' });
    return outcome(ExitCode.SAFETY_REFUSAL, 'INTENT_INCOMPLETE');
  };
  /** P5-P6 for a fresh intent: preimage, stored hash, invoice, lease re-assertion, fenced SUBMITTING. */
  const intend = async (): Promise<DispatchOutcome | PreparedPayment> => {
    if (stopped()) return await interrupt();

    let baseline: readonly NormalizedChannel[] | null;
    try {
      baseline = await adapter.listChannels();
    } catch {
      baseline = null;
    }

    const preimage = deps.randomBytes(PREIMAGE_BYTES);
    if (preimage.length !== PREIMAGE_BYTES) throw new Error('the random source returned a preimage of the wrong length');
    hash = sha256(preimage);
    fenced('PREFLIGHT', 'PREFLIGHT', { paymentHash: hash });

    let invoice: InvoiceResult | null;
    try {
      invoice = await adapter.createInvoice(route.principalMsat, preimage, label, deps.invoiceExpirySeconds);
    } catch {
      invoice = null;
    }
    if (!db.executions.holds(executionId, epoch)) return outcome(ExitCode.SAFETY_REFUSAL, LEASE_LOST);
    if (invoice === null || invoice.paymentHash !== hash) {
      if (await closeInvoice()) return paidPreparation(baseline);
      fenced('PREFLIGHT', 'CANCELLED', { errorCode: invoice === null ? 'INVOICE_UNCONFIRMED' : 'INVOICE_HASH_MISMATCH' });
      return outcome(ExitCode.SAFETY_REFUSAL, invoice === null ? 'INVOICE_UNCONFIRMED' : 'INVOICE_HASH_MISMATCH');
    }
    if (finalDelta(route) < invoice.finalCltvDelta) {
      if (await closeInvoice()) return paidPreparation(baseline);
      fenced('PREFLIGHT', 'CANCELLED', { errorCode: 'CLTV_DELTA_UNSAFE' });
      return outcome(ExitCode.SAFETY_REFUSAL, 'CLTV_DELTA_UNSAFE');
    }

    if (stopped()) return await interrupt();
    try {
      epoch = db.executions.renewLease(executionId, epoch, deps.leaseMs);
    } catch (error) {
      if (error instanceof PersistenceError && error.code === 'LEASE_LOST') throw new LeaseLost();
      throw error;
    }
    if (stopped()) return await interrupt();
    let submitted: { status: 'SUBMITTING' | 'CANCELLED'; fenceEpoch: bigint };
    try {
      const sourceLocalMsat = localBalance(baseline, route.sourceChannelKey);
      const targetLocalMsat = localBalance(baseline, route.targetChannelKey);
      submitted = db.executions.submit(executionId, epoch, input.policy.maxInFlight, deps.leaseMs, {
        routeJson: routeJson(route),
        ...(sourceLocalMsat === null || targetLocalMsat === null ? {} : { baseline: { sourceLocalMsat, targetLocalMsat } }),
      });
    } catch (error) {
      if (error instanceof PersistenceError && error.code === 'LEASE_LOST') throw new LeaseLost();
      throw error;
    }
    epoch = submitted.fenceEpoch;
    if (submitted.status === 'CANCELLED') {
      if (await closeInvoice()) return paidPreparation(baseline);
      return outcome(ExitCode.SAFETY_REFUSAL, db.executions.view(executionId)?.errorCode ?? 'BUDGET_EXHAUSTED');
    }
    return { paymentHash: hash, paymentSecret: invoice.paymentSecret, baseline };
  };

  let prepared: { readonly paymentHash: string; readonly paymentSecret: string; readonly baseline: readonly NormalizedChannel[] | null };
  // INV-15 and route validation: only a route approveRoute returned, under a RegtestProof, is ever dispatched.
  if (!isApprovedRoute(route)) return outcome(ExitCode.SAFETY_REFUSAL, 'network-lock');
  try {
    if (!db.executions.holds(executionId, epoch)) return outcome(ExitCode.SAFETY_REFUSAL, LEASE_LOST);
    const stored = db.executions.view(executionId)?.paymentHash ?? null;
    if (stored !== null) {
      const abandoned = await abandonIntent(stored);
      if (abandoned !== 'paid') return abandoned;
      paid = true;
      prepared = { paymentHash: stored, paymentSecret: '', baseline: null };
    } else {
      const intent = await intend();
      if ('exit' in intent) return intent;
      prepared = intent;
    }
  } catch (error) {
    if (error instanceof LeaseLost) return outcome(ExitCode.SAFETY_REFUSAL, LEASE_LOST);
    throw error;
  }
  const { paymentSecret, baseline } = prepared;

  // From here on the payment may have reached the node: a lost lease leaves the row to its new holder (exit 7).
  const paymentHash = prepared.paymentHash;
  // Shared with the onDispatched callback, which may run at any point of the wait.
  const state: { status: ExecutionStatus; leaseLost: boolean; waiting: boolean } = { status: paid ? 'UNKNOWN' : 'SUBMITTING', leaseLost: false, waiting: true };
  const write = (to: ExecutionStatus, fields?: TransitionFields): void => {
    fenced(state.status, to, fields);
    state.status = to;
  };
  const onDispatched = (): void => {
    if (!state.waiting || state.leaseLost || state.status !== 'SUBMITTING') return;
    try {
      write('IN_FLIGHT');
    } catch (error) {
      if (error instanceof LeaseLost) { state.leaseLost = true; return; }
      throw error;
    }
  };

  try {
    let send: Promise<PaymentObservation>;
    try {
      // A paid invoice found on re-claim is resolved from the node's record; nothing is sent.
      send = paid ? adapter.observePayment(paymentHash) : adapter.sendOnRoute(route, paymentHash, paymentSecret, onDispatched);
    } catch (error) {
      send = Promise.reject(error instanceof Error ? error : new Error(String(error)));
    }
    const result = await boundedWait(send, deps.attemptDeadlineMs, stopSignal);
    state.waiting = false;
    if (state.leaseLost) return outcome(ExitCode.OUTCOME_UNKNOWN, LEASE_LOST);

    const unknown = (): DispatchOutcome => {
      if (state.status !== 'UNKNOWN') write('UNKNOWN');
      return paid ? outcome(ExitCode.INVARIANT_BREACH, PAID_BEFORE_SUBMISSION) : outcome(ExitCode.OUTCOME_UNKNOWN, OUTCOME_UNKNOWN);
    };
    if (result.kind !== 'answer') return unknown();
    // A payment record on the node shows that the request reached it.
    const kind = result.observation.kind;
    if (state.status === 'SUBMITTING' && (kind === 'SUCCEEDED' || kind === 'FAILED' || kind === 'IN_FLIGHT')) write('IN_FLIGHT');

    const verifySuccess = async (feeMsat: bigint, htlcCount: number, settledChannelKey: string | null): Promise<DispatchOutcome> => {
      write('VERIFIED_SUCCESS', { actualFeeMsat: feeMsat, deltaStatus: 'PENDING', settledChannelKey });
      let exit: number = paid ? ExitCode.INVARIANT_BREACH : ExitCode.SUCCESS;
      let step: string | null = paid ? PAID_BEFORE_SUBMISSION : null;
      const raise = (kind: Alert['kind'], code: string, codeExit: number): void => {
        deps.alert({ kind, executionId, code });
        // Exit numbers are labels, not severity: a reconciliation alert cannot replace an invariant breach.
        if (exit !== ExitCode.INVARIANT_BREACH && (codeExit === ExitCode.INVARIANT_BREACH || codeExit > exit)) {
          exit = codeExit;
          step = code;
        }
      };
      if (htlcCount !== 1) raise('INVARIANT_BREACH', 'SINGLE_PATH_UNAVAILABLE', ExitCode.INVARIANT_BREACH);
      if (feeMsat > approval.approvedMaxFeeMsat) raise('INVARIANT_BREACH', 'FEE_ABOVE_CAP', ExitCode.INVARIANT_BREACH);
      else if (feeMsat !== route.totalFeeMsat) raise('fee-mismatch', 'FEE_MISMATCH', ExitCode.RECONCILIATION_ALERT);

      let after: readonly NormalizedChannel[] | null;
      try {
        after = await adapter.listChannels();
      } catch {
        after = null;
      }
      const delta = settledChannelKey === null ? 'PENDING' : deltaStatus(baseline, after, route, feeMsat, deps.deltaToleranceMsat);
      if (delta !== 'PENDING') {
        try {
          epoch = db.executions.recordDelta(executionId, epoch, delta);
        } catch (error) {
          if (error instanceof PersistenceError && error.code === 'LEASE_LOST') return outcome(ExitCode.OUTCOME_UNKNOWN, LEASE_LOST);
          throw error;
        }
      }
      if (delta === 'MISMATCH') raise('delta-mismatch', 'DELTA_MISMATCH', ExitCode.RECONCILIATION_ALERT);
      if (delta === 'PENDING' && exit !== ExitCode.INVARIANT_BREACH) raise('delta-mismatch', 'DELTA_UNVERIFIED', ExitCode.RECONCILIATION_ALERT);
      return outcome(exit, step);
    };

    const succeeded = async (observation: Extract<PaymentObservation, { kind: 'SUCCEEDED' }>): Promise<DispatchOutcome> => {
      if (!observation.preimageMatchesHash) {
        if (state.status !== 'UNKNOWN') write('UNKNOWN');
        deps.alert({ kind: 'INVARIANT_BREACH', executionId, code: 'PREIMAGE_MISMATCH' });
        return outcome(ExitCode.INVARIANT_BREACH, 'PREIMAGE_MISMATCH');
      }
      return await verifySuccess(observation.feeMsat, observation.htlcCount, observation.settledChannelKey);
    };

    const observation = result.observation;
    switch (observation.kind) {
      case 'SUCCEEDED':
        return await succeeded(observation);
      case 'FAILED': {
        // Our invoice already paid before this read: a conflicting payer answer cannot authorize another closure.
        if (paid) return unknown();
        if (observation.htlcsInFlight !== 0) return unknown();
        if (!db.executions.holds(executionId, epoch)) throw new LeaseLost();
        let closed: CancelResult;
        try {
          closed = await adapter.cancelUnpaidInvoice(paymentHash, label);
        } catch {
          return unknown();
        }
        if (closed === 'CANCELED') {
          write('VERIFIED_FAILURE', { errorCode: observation.reason });
          return outcome(ExitCode.SAFETY_REFUSAL, observation.reason);
        }
        if (closed === 'ALREADY_PAID') {
          if (!db.executions.holds(executionId, epoch)) throw new LeaseLost();
          let again: PaymentObservation;
          try {
            again = await adapter.observePayment(paymentHash);
          } catch {
            return unknown();
          }
          if (again.kind === 'SUCCEEDED') return await succeeded(again);
        }
        return unknown();
      }
      case 'IN_FLIGHT':
      case 'NOT_FOUND':
      case 'AMBIGUOUS':
        return unknown();
    }
  } catch (error) {
    if (error instanceof LeaseLost) return outcome(ExitCode.OUTCOME_UNKNOWN, LEASE_LOST);
    throw error;
  }
}

/**
 * SPEC §8.7 step 5: the source lost P + F and the target gained P, each within the tolerance. PENDING when either
 * snapshot is missing a channel.
 */
function deltaStatus(
  before: readonly NormalizedChannel[] | null, after: readonly NormalizedChannel[] | null, route: CircularRoute, feeMsat: bigint, tolerance: bigint,
): DeltaStatus {
  const sourceBefore = localBalance(before, route.sourceChannelKey);
  const targetBefore = localBalance(before, route.targetChannelKey);
  const sourceAfter = localBalance(after, route.sourceChannelKey);
  const targetAfter = localBalance(after, route.targetChannelKey);
  if (sourceBefore === null || targetBefore === null || sourceAfter === null || targetAfter === null) return 'PENDING';
  const sourceOff = absolute(sourceAfter - sourceBefore + route.principalMsat + feeMsat);
  const targetOff = absolute(targetAfter - targetBefore - route.principalMsat);
  return sourceOff <= tolerance && targetOff <= tolerance ? 'MATCH' : 'MISMATCH';
}
