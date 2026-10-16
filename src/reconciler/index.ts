import { invoiceLabel, reportedFeeBreach, type Alert, type ExecutionAdapter, type ExecutionStatus, type PaymentObservation } from '../core/execution.js';
import { ExitCode } from '../core/exit-codes.js';
import type { NormalizedChannel } from '../core/normalize.js';
import { PersistenceError, type Database, type DeltaStatus, type TransitionFields, type UnresolvedExecution } from '../persistence/index.js';
import { cleanupRoutingLayers } from './routing-layers.js';

export interface ReconcileDeps {
  readonly db: Database;
  /** Execution adapters keyed by nodes.id. */
  readonly adapters: ReadonlyMap<string, ExecutionAdapter>;
  readonly workerId: string;
  readonly leaseMs: number;
  /** A NOT_FOUND payment counts as never sent only this long after its submission (SPEC §8.5). */
  readonly notFoundWindowMs: number;
  /** An execution unresolved this long after its submission raises stuck-in-flight (SPEC §8.6). */
  readonly escalateAfterMs: number;
  /**
   * On a CLN node a FAILED payer record counts only when a FAILED read at least this long before agrees (SPEC §5.4:
   * listsendpays can swing between failed and pending or lag).
   */
  readonly confirmIntervalMs: number;
  /** Delta verification tolerance (SPEC §8.7 step 5); absent means zero tolerance, never a skipped check. */
  readonly deltaToleranceMsat?: bigint;
  readonly alert: (alert: Alert) => void;
  readonly nodeIds?: ReadonlySet<string>;
}

export interface ReconcileReport {
  readonly exit: number;
  /** Executions still SUBMITTING, IN_FLIGHT or UNKNOWN after the pass. */
  readonly unresolved: readonly string[];
}

const UNRESOLVED: ReadonlySet<ExecutionStatus> = new Set(['SUBMITTING', 'IN_FLIGHT', 'UNKNOWN']);

type Decision =
  /** `htlcCount` and `feeMsat` are null when only our settled invoice proves the payment. */
  | { readonly kind: 'success'; readonly feeMsat: bigint | null; readonly htlcCount: number | null; readonly settledChannelKey: string | null }
  | { readonly kind: 'failure'; readonly errorCode: string }
  | { readonly kind: 'stay'; readonly breach: boolean };

const STAY: Decision = { kind: 'stay', breach: false };
const BY_INVOICE: Decision = { kind: 'success', feeMsat: null, htlcCount: null, settledChannelKey: null };

class LeaseLost extends Error {}

async function read<T>(work: () => Promise<T>): Promise<T | null> {
  try {
    return await work();
  } catch {
    return null;
  }
}

function fromRecord(observation: Extract<PaymentObservation, { kind: 'SUCCEEDED' }>): Decision {
  return observation.preimageMatchesHash
    ? { kind: 'success', feeMsat: observation.feeMsat, htlcCount: observation.htlcCount, settledChannelKey: observation.settledChannelKey }
    : { kind: 'stay', breach: true };
}

/**
 * Decides one execution from node evidence only (SPEC §8.4, §8.5). Only reads and the receiver-side closure of our own
 * invoice are used: the reconciler never creates an invoice and never sends.
 */
interface Judge {
  readonly mode: 'track' | 'sweep';
  readonly notFoundWindowMs: number;
  /** Whether a FAILED payer record with no HTLC in flight is confirmed; records the observation otherwise. */
  readonly failureConfirmed: () => boolean;
  /** Called with the first payer observation of the pass. */
  readonly observed: (observation: PaymentObservation) => void;
}

async function decide(adapter: ExecutionAdapter, row: UnresolvedExecution, hash: string, judge: Judge): Promise<Decision> {
  const { mode, notFoundWindowMs } = judge;
  const label = invoiceLabel(row.executionId);
  const observe = async (): Promise<PaymentObservation> =>
    await read(() => adapter.observePayment(hash, mode)) ?? { kind: 'AMBIGUOUS', cause: 'the payment could not be read' };
  // Our invoice paid: the HTLC reached us over the target channel and our own node released the preimage.
  const paid = (observation: PaymentObservation): Decision => observation.kind === 'SUCCEEDED' ? fromRecord(observation) : BY_INVOICE;

  const first = await observe();
  judge.observed(first);
  if (first.kind === 'SUCCEEDED') return fromRecord(first);
  const invoice = await read(() => adapter.invoiceState(hash));
  if (invoice === 'SETTLED') return BY_INVOICE;

  if (first.kind === 'FAILED' && first.htlcsInFlight === 0 && invoice !== null) {
    if (!judge.failureConfirmed()) return STAY;
    const closed = await read(() => adapter.cancelUnpaidInvoice(hash, label));
    if (closed === 'CANCELED' || (row.implementation === 'cln' && invoice === 'NOT_FOUND' && closed === 'NOT_FOUND')) {
      return { kind: 'failure', errorCode: first.reason };
    }
    if (closed === 'ALREADY_PAID') return paid(await observe());
    return STAY;
  }

  if (first.kind === 'NOT_FOUND') {
    const closed = await read(() => adapter.cancelUnpaidInvoice(hash, label));
    if (closed === null) return STAY;
    const again = await observe();
    if (closed === 'ALREADY_PAID') return paid(again);
    if (again.kind === 'SUCCEEDED') return fromRecord(again);
    if (again.kind === 'NOT_FOUND' && row.submittedAgeMs !== null && row.submittedAgeMs >= notFoundWindowMs) return { kind: 'failure', errorCode: 'NOT_SENT' };
    return STAY;
  }

  return STAY;
}

function localBalance(channels: readonly NormalizedChannel[] | null, channelKey: string): bigint | null {
  return channels?.find(channel => channel.channelKey === channelKey)?.localBalanceMsat ?? null;
}

function absolute(value: bigint): bigint {
  return value < 0n ? -value : value;
}

/**
 * One reconciler pass. Candidates are UNKNOWN executions and SUBMITTING / IN_FLIGHT executions whose lease has
 * expired; a live lease belongs to a worker that may still be waiting for its payment and is never taken over. The
 * startup sweep reads the payer side from the node's payment list instead of a live stream. Each candidate is taken
 * under the reconciler's own fenced lease, moved to UNKNOWN if a worker left it SUBMITTING or IN_FLIGHT, and resolved
 * only on evidence. A resolved success gets the result checks of SPEC §8.7.
 */
export async function reconcile(deps: ReconcileDeps, options: { startup: boolean }): Promise<ReconcileReport> {
  const { db } = deps;
  const mode = options.startup ? 'sweep' : 'track';
  const unresolved: string[] = [];
  let breach = false;
  let mismatch = false;

  let pendingAttribution = 0;
  const candidates = db.executions.unresolved().filter(row => (deps.nodeIds === undefined || deps.nodeIds.has(row.nodeId)) &&
    (row.status === 'VERIFIED_SUCCESS' ? pendingAttribution++ < 100 : row.status === 'UNKNOWN' || row.leaseExpired));
  for (const row of candidates) {
    const held = db.executions.takeUnresolved(row.executionId, row.fenceEpoch, deps.workerId, deps.leaseMs);
    if (held === null) continue;
    let epoch = held.fenceEpoch;
    let status = held.status;
    const write = (to: ExecutionStatus, fields?: TransitionFields): void => {
      try {
        epoch = db.executions.transition(row.executionId, epoch, status, to, fields);
        status = to;
      } catch (error) {
        if (error instanceof PersistenceError && error.code === 'LEASE_LOST') throw new LeaseLost();
        throw error;
      }
    };
    const raise = (kind: Alert['kind'], code: string): void => { deps.alert({ kind, executionId: row.executionId, code }); };
    const note = (observation: 'FAILED' | 'CLEARED'): void => {
      try {
        epoch = db.executions.noteObservation(row.executionId, epoch, observation);
      } catch (error) {
        if (error instanceof PersistenceError && error.code === 'LEASE_LOST') throw new LeaseLost();
        throw error;
      }
    };

    try {
      if (status === 'VERIFIED_SUCCESS') {
        const adapter = deps.adapters.get(row.nodeId);
        const observed = adapter === undefined || row.paymentHash === null ? null : await read(() => adapter.observePayment(row.paymentHash ?? '', mode));
        if (observed?.kind !== 'SUCCEEDED' || !observed.preimageMatchesHash) {
          mismatch = true;
          if (!breach) raise('delta-mismatch', 'DELTA_UNVERIFIED');
          continue;
        }
        if (observed.htlcCount !== 1) { breach = true; raise('INVARIANT_BREACH', 'SINGLE_PATH_UNAVAILABLE'); }
        if (reportedFeeBreach(observed.feeMsat, row)) { breach = true; raise('INVARIANT_BREACH', 'FEE_ABOVE_CAP'); }
        else if (row.plannedFeeMsat !== null && observed.feeMsat !== row.plannedFeeMsat) {
          mismatch = true;
          raise('fee-mismatch', 'FEE_MISMATCH');
        }
        epoch = db.executions.recoverSettlement(row.executionId, epoch, observed.settledChannelKey, observed.feeMsat);
        if (observed.settledChannelKey === null || adapter === undefined) {
          mismatch = true;
          if (!breach) raise('delta-mismatch', 'DELTA_UNVERIFIED');
        } else {
          const delta = await verifyDelta(deps, adapter, row.executionId, observed.settledChannelKey, observed.feeMsat);
          if (delta !== null) epoch = db.executions.recordDelta(row.executionId, epoch, delta);
          if (delta !== 'MATCH') { mismatch = true; if (!breach) raise('delta-mismatch', delta === 'MISMATCH' ? 'DELTA_MISMATCH' : 'DELTA_UNVERIFIED'); }
        }
        continue;
      }
      if (status !== 'UNKNOWN') write('UNKNOWN');
      const adapter = deps.adapters.get(row.nodeId);
      const decision = adapter === undefined || row.paymentHash === null
        ? STAY
        : await decide(adapter, row, row.paymentHash, {
          mode,
          notFoundWindowMs: deps.notFoundWindowMs,
          failureConfirmed: () => {
            if (row.implementation !== 'cln') return true;
            const since = db.executions.failedSinceMs(row.executionId);
            if (since !== null) return since >= deps.confirmIntervalMs;
            note('FAILED');
            return false;
          },
          observed: observation => {
            const failedRead = observation.kind === 'FAILED' && observation.htlcsInFlight === 0;
            if (row.implementation === 'cln' && !failedRead && db.executions.failedSinceMs(row.executionId) !== null) note('CLEARED');
          },
        });
      if (decision.kind === 'success') {
        write('VERIFIED_SUCCESS', decision.feeMsat === null
          ? { feeUnreported: true, deltaStatus: 'PENDING' }
          : { actualFeeMsat: decision.feeMsat, deltaStatus: 'PENDING', settledChannelKey: decision.settledChannelKey });
        if (decision.htlcCount !== null && decision.htlcCount !== 1) { breach = true; raise('INVARIANT_BREACH', 'SINGLE_PATH_UNAVAILABLE'); }
        if (decision.feeMsat !== null && reportedFeeBreach(decision.feeMsat, row)) {
          breach = true;
          raise('INVARIANT_BREACH', 'FEE_ABOVE_CAP');
        } else if (decision.feeMsat !== null && row.plannedFeeMsat !== null && decision.feeMsat !== row.plannedFeeMsat) {
          mismatch = true;
          raise('fee-mismatch', 'FEE_MISMATCH');
        }
        if (decision.settledChannelKey === null) { mismatch = true; if (!breach) raise('delta-mismatch', 'DELTA_UNVERIFIED'); }
        if (adapter !== undefined && decision.feeMsat !== null && decision.settledChannelKey !== null) {
          const delta = await verifyDelta(deps, adapter, row.executionId, decision.settledChannelKey, decision.feeMsat);
          if (delta !== null) {
            try {
              epoch = db.executions.recordDelta(row.executionId, epoch, delta);
            } catch (error) {
              if (error instanceof PersistenceError && error.code === 'LEASE_LOST') throw new LeaseLost();
              throw error;
            }
          }
          if (delta !== 'MATCH') { mismatch = true; raise('delta-mismatch', delta === 'MISMATCH' ? 'DELTA_MISMATCH' : 'DELTA_UNVERIFIED'); }
        }
      } else if (decision.kind === 'failure') {
        write('VERIFIED_FAILURE', { errorCode: decision.errorCode });
      } else if (decision.breach) {
        breach = true;
        raise('INVARIANT_BREACH', 'PREIMAGE_MISMATCH');
      }
    } catch (error) {
      if (!(error instanceof LeaseLost)) throw error;
      // Another reconciler or worker holds the row now; it is theirs to resolve.
      continue;
    }

    if (UNRESOLVED.has(status)) {
      unresolved.push(row.executionId);
      if (row.submittedAgeMs !== null && row.submittedAgeMs > deps.escalateAfterMs) raise('stuck-in-flight', 'STUCK');
    }
  }

  await cleanupRoutingLayers(deps);
  const exit = breach ? ExitCode.INVARIANT_BREACH
    : unresolved.length > 0 ? ExitCode.OUTCOME_UNKNOWN
      : mismatch ? ExitCode.RECONCILIATION_ALERT : ExitCode.SUCCESS;
  return { exit, unresolved };
}

/**
 * SPEC §8.7 step 5 against the balances recorded before the send, with zero tolerance unless one is configured; null
 * when there is no recorded baseline or no fresh channel list to compare with.
 */
async function verifyDelta(deps: ReconcileDeps, adapter: ExecutionAdapter, executionId: string, settledChannelKey: string, feeMsat: bigint): Promise<DeltaStatus | null> {
  const tolerance = deps.deltaToleranceMsat ?? 0n;
  const baseline = deps.db.executions.baseline(executionId);
  const plan = deps.db.executions.plan(executionId);
  if (baseline === null || plan === null) return null;
  if (settledChannelKey !== plan.targetChannelKey) return null;
  const channels = await read(() => adapter.listChannels());
  const source = localBalance(channels, plan.sourceChannelKey);
  const target = localBalance(channels, settledChannelKey);
  if (source === null || target === null) return null;
  const sourceOff = absolute(source - baseline.sourceLocalMsat + plan.principalMsat + feeMsat);
  const targetOff = absolute(target - baseline.targetLocalMsat - plan.principalMsat);
  return sourceOff <= tolerance && targetOff <= tolerance ? 'MATCH' : 'MISMATCH';
}
