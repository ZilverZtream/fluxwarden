/*
Interface: test/helpers/cp030-execution.ts (src/reconciler/index.ts reconcile, ReconcileDeps, ExecutionAdapter).

Rules under test: SPEC §8.4 (candidates, evidence table, restart sweep from the node's list), §8.5 (NotFound is not UNKNOWN:
cancel the invoice first, then NOT_SENT only after the creation window), §8.6 (stuck escalation), §6.5 (SUBMITTING /
IN_FLIGHT / UNKNOWN are the reconciler's, nothing is ever re-sent), §6.6 (reservation CONSUMED / RELEASED / HELD);
SECURITY INV-04 (only evidence leaves UNKNOWN), INV-05 / INV-19 (no re-send: an execution that reached SUBMITTING never
goes back to CLAIMED), INV-13 (the reconciler writes under its own fenced lease); ARCHITECTURE §8.3 (evidence: a preimage
or our settled invoice proves success whatever failure reason the payer record carries, lnd#8884, cln#9096; FAILED with an
HTLC in flight is not terminal, lnd#8975).
*/
import { randomBytes } from 'node:crypto';
import { expect, it, vi } from 'vitest';
import { failed, never, ScriptedExecutionNode, succeeded, type ExecutionScript } from '../fakes/execution-node.js';
import { circularRoute } from '../fakes/preflight-node.js';
import {
  APPROVED_MAX_FEE, loadPersistence, PRINCIPAL, scratchDb, seedBase, sleep, type Base, type ExecutionStatus, type FakeChannel,
} from '../helpers/cp028-executor.js';
import { balances, prepare, ROUTE_FEE, S_BEFORE, settled, T_BEFORE } from '../helpers/cp030-dispatch.js';
import {
  exec, labelOf, loadReconciler, reservationState, rowOf, seedExecution,
  type Alert, type InvoiceState, type PaymentObservation, type ReconcileDeps, type ReconcileReport,
} from '../helpers/cp030-execution.js';

interface Evidence { readonly payer: PaymentObservation[]; readonly invoice?: InvoiceState; readonly cancel?: 'CANCELED' | 'ALREADY_PAID' | 'NOT_FOUND' }

interface Seeded { readonly executionId: string; readonly hash: string }
interface FailedObservationStore {
  failedSinceMs(executionId: string): number | null;
  noteObservation(executionId: string, fenceEpoch: bigint, observation: 'FAILED' | 'CLEARED'): bigint;
}

async function world(prefix: string, options: { implementation?: 'lnd' | 'cln'; confirmIntervalMs?: number; failedObservationAgeMs?: () => number } = {}) {
  const p = await loadPersistence();
  const { reconcile } = await loadReconciler();
  const path = scratchDb(prefix);
  const base = seedBase(p, path, undefined, { implementation: options.implementation ?? 'lnd' });
  const evidence = new Map<string, Evidence>();
  const reads = new Map<string, number>();
  const script: Partial<ExecutionScript> = {
    observe: hash => {
      const e = evidence.get(hash);
      const index = reads.get(hash) ?? 0;
      reads.set(hash, index + 1);
      const list = e?.payer ?? [];
      return Promise.resolve(list[Math.min(index, list.length - 1)] ?? { kind: 'AMBIGUOUS', cause: 'no evidence scripted' });
    },
    invoiceState: hash => Promise.resolve(evidence.get(hash)?.invoice ?? 'OPEN'),
    cancel: hash => Promise.resolve(evidence.get(hash)?.cancel ?? 'CANCELED'),
  };
  const node = new ScriptedExecutionNode(script);
  const alerts: Alert[] = [];
  const seed = (status: ExecutionStatus, e: Evidence | null, over: { leaseInMs?: number; submittedAgoMs?: number } = {}): Seeded => {
    const hash = randomBytes(32).toString('hex');
    const route = circularRoute(base.sourceKey, base.targetKey, 150_000n, 80);
    const { executionId } = seedExecution(base, {
      // A previously completed success includes its exact fee, receiver receipt,
      // consumed reservation and terminal journals. A bare success row with
      // NULL fee is intentionally recoverable under SPEC §6.2, rather than this fixture.
      status: status === 'VERIFIED_SUCCESS' ? 'IN_FLIGHT' : status,
      paymentHash: status === 'CLAIMED' ? null : hash, route, plannedFeeMsat: 150_000n,
      leaseInMs: over.leaseInMs ?? -5_000, submittedAgoMs: status === 'CLAIMED' ? null : (over.submittedAgoMs ?? 300_000),
    });
    if (status === 'VERIFIED_SUCCESS') {
      const completed = p.openDatabase(path, { readOnly: false });
      try {
        completed.executions.transition(executionId, 3n, 'IN_FLIGHT', 'VERIFIED_SUCCESS', {
          actualFeeMsat: 150_000n, settledChannelKey: base.targetKey, deltaStatus: 'MATCH',
        });
      } finally { completed.close(); }
    }
    if (e !== null) evidence.set(hash, e);
    return { executionId, hash };
  };
  const run = async (startup = false): Promise<ReconcileReport> => {
    const db = p.openDatabase(path, { readOnly: false });
    let restoreAge: (() => void) | undefined;
    try {
      const controlledAge = options.failedObservationAgeMs;
      if (controlledAge !== undefined) {
        const store = db.executions as typeof db.executions & FailedObservationStore;
        const readAge = store.failedSinceMs.bind(store);
        const wrapper = vi.spyOn(store, 'failedSinceMs').mockImplementation(executionId => {
          const persistedAge = readAge(executionId);
          return persistedAge === null ? null : controlledAge();
        });
        restoreAge = () => { wrapper.mockRestore(); };
      }
      return await reconcile({
        db, adapters: new Map([[base.nodeId, node]]), workerId: 'reconciler', leaseMs: 60_000,
        notFoundWindowMs: 120_000, escalateAfterMs: 3_600_000, confirmIntervalMs: options.confirmIntervalMs ?? 60_000, alert: alert => { alerts.push(alert); },
      }, { startup });
    } finally { restoreAge?.(); db.close(); }
  };
  /** Calls the node received for one payment hash. */
  const callsFor = (hash: string): string[] => node.calls.filter(c => c.args[0] === hash).map(c => c.name);
  return { path, base, node, alerts, seed, run, callsFor };
}

type World = Awaited<ReturnType<typeof world>>;

/** B7: whatever the evidence, the reconciler never moves funds. */
function expectNoFundMovement(w: World): void {
  expect(w.node.fundMovingCalls()).toEqual([]);
}

it('CP-032/B1 a worker killed after the send: IN_FLIGHT with an expired lease and an in-flight payer record becomes UNKNOWN', async () => {
  const w = await world('killed-inflight');
  const e = w.seed('IN_FLIGHT', { payer: [{ kind: 'IN_FLIGHT' }] });
  const report = await w.run();
  expect(rowOf(w.path, e.executionId).status).toBe('UNKNOWN');
  expect(report.exit).toBe(7);
  expect(report.unresolved).toContain(e.executionId);
  expect(reservationState(w.path, e.executionId).state).toBe('HELD');
  expectNoFundMovement(w);
});

it('CP-032/B1 a crash between SUBMITTING and IN_FLIGHT: SUBMITTING with an expired lease becomes UNKNOWN, never re-sent', async () => {
  const w = await world('killed-submitting');
  const e = w.seed('SUBMITTING', { payer: [{ kind: 'IN_FLIGHT' }] });
  await w.run();
  expect(rowOf(w.path, e.executionId).status).toBe('UNKNOWN');
  expectNoFundMovement(w);
});

it('CP-032/B1 an IN_FLIGHT execution whose worker still holds the lease is left alone in a regular pass', async () => {
  const w = await world('live-lease');
  const e = w.seed('IN_FLIGHT', { payer: [succeeded(150_000n, 1, true, w.base.targetKey)] }, { leaseInMs: 60_000 });
  const before = rowOf(w.path, e.executionId);
  await w.run();
  expect(rowOf(w.path, e.executionId)).toEqual(before);
  expect(w.callsFor(e.hash)).toEqual([]);
});

it('CP-032/B2 a matching preimage resolves UNKNOWN to VERIFIED_SUCCESS with the node-reported fee', async () => {
  const w = await world('success');
  // The node reports the planned route fee: SPEC §8.7 step 3 makes any other fee a fee-mismatch (exit 9).
  const e = w.seed('UNKNOWN', { payer: [succeeded(150_000n, 1, true, w.base.targetKey)] });
  const report = await w.run();
  const row = rowOf(w.path, e.executionId);
  expect(row.status).toBe('VERIFIED_SUCCESS');
  expect(row.actual_fee_msat).toBe(150_000n);
  expect(reservationState(w.path, e.executionId)).toEqual({ state: 'CONSUMED', consumed: 150_000n });
  expect(w.node.count('cancelUnpaidInvoice')).toBe(0);
  // SPEC 8.7 and SECURITY INV-07: this fixture has no pre-send balance
  // baseline. Paid truth remains verified while its channel delta is pending.
  expect(row.delta_status).toBe('PENDING');
  expect(report.exit).toBe(9);
  expect(w.alerts.map(alert => alert.code)).toContain('DELTA_UNVERIFIED');
  expect(report.unresolved).toEqual([]);
});

it('CP-032/B2 our settled invoice proves success even while the payer record still shows the payment in flight', async () => {
  const w = await world('settled-invoice');
  const e = w.seed('UNKNOWN', { payer: [{ kind: 'IN_FLIGHT' }], invoice: 'SETTLED' });
  await w.run();
  expect(rowOf(w.path, e.executionId).status).toBe('VERIFIED_SUCCESS');
  expect(w.node.count('cancelUnpaidInvoice')).toBe(0);
});

it('CP-032/B2 a terminal failure with no HTLC in flight: invoice cancelled, then VERIFIED_FAILURE with the reason', async () => {
  const w = await world('failure');
  const e = w.seed('UNKNOWN', { payer: [failed('FAILURE_REASON_NO_ROUTE')], invoice: 'OPEN' });
  await w.run();
  const row = rowOf(w.path, e.executionId);
  expect(row.status).toBe('VERIFIED_FAILURE');
  expect(row.error_code).toBe('FAILURE_REASON_NO_ROUTE');
  expect(w.node.named('cancelUnpaidInvoice').map(c => c.args)).toEqual([[e.hash, labelOf(e.executionId)]]);
  expect(reservationState(w.path, e.executionId).state).toBe('RELEASED');
  expectNoFundMovement(w);
});

it('CP-032/B2 a FAILED payer record while our invoice is SETTLED is a success, never a failure', async () => {
  const w = await world('failed-but-settled');
  const e = w.seed('UNKNOWN', { payer: [failed('FAILURE_REASON_TIMEOUT')], invoice: 'SETTLED' });
  await w.run();
  expect(rowOf(w.path, e.executionId).status).toBe('VERIFIED_SUCCESS');
});

for (const [name, payer] of [
  ['FAILED with an HTLC still in flight', failed('FAILURE_REASON_TIMEOUT', 1)],
  ['IN_FLIGHT (LND INITIATED or IN_FLIGHT, CLN pending)', { kind: 'IN_FLIGHT' } as const],
  ['an ambiguous read', { kind: 'AMBIGUOUS', cause: 'stream ended without a record' } as const],
] as const) {
  it(`CP-032/B2 ${name} stays UNKNOWN with nothing cancelled`, async () => {
    const w = await world(`stay-${String(name.length)}`);
    const e = w.seed('UNKNOWN', { payer: [payer] });
    const report = await w.run();
    expect(rowOf(w.path, e.executionId).status).toBe('UNKNOWN');
    expect(w.node.count('cancelUnpaidInvoice')).toBe(0);
    expect(reservationState(w.path, e.executionId).state).toBe('HELD');
    expect(report.exit).toBe(7);
    expectNoFundMovement(w);
  });
}

it('CP-032/B2 a preimage that does not hash to the payment hash stays UNKNOWN with INVARIANT_BREACH, exit 8', async () => {
  const w = await world('bad-preimage');
  const e = w.seed('UNKNOWN', { payer: [succeeded(150_000n, 1, false)] });
  const report = await w.run();
  expect(rowOf(w.path, e.executionId).status).toBe('UNKNOWN');
  expect(w.alerts).toContainEqual({ kind: 'INVARIANT_BREACH', executionId: e.executionId, code: 'PREIMAGE_MISMATCH' });
  expect(report.exit).toBe(8);
});

it('CP-032/B3 a cancel answered "already paid" fetches the payment again and resolves with its preimage', async () => {
  const w = await world('already-paid');
  const e = w.seed('UNKNOWN', { payer: [failed('FAILURE_REASON_TIMEOUT'), succeeded(150_000n, 1, true, w.base.targetKey)], invoice: 'OPEN', cancel: 'ALREADY_PAID' });
  await w.run();
  const row = rowOf(w.path, e.executionId);
  expect(row.status).toBe('VERIFIED_SUCCESS');
  expect(row.actual_fee_msat).toBe(150_000n);
  expect(w.callsFor(e.hash).filter(name => name === 'observePayment')).toHaveLength(2);
});

it('CP-032/B4 NOT_FOUND past the creation window: invoice cancelled first, re-read, then VERIFIED_FAILURE NOT_SENT (never back to CLAIMED)', async () => {
  const w = await world('notfound-old');
  const e = w.seed('UNKNOWN', { payer: [{ kind: 'NOT_FOUND' }] }, { submittedAgoMs: 130_000 });
  await w.run();
  const row = rowOf(w.path, e.executionId);
  expect(row.status).toBe('VERIFIED_FAILURE');
  expect(row.error_code).toBe('NOT_SENT');
  const calls = w.callsFor(e.hash);
  expect(calls.filter(name => name === 'cancelUnpaidInvoice')).toHaveLength(1);
  // SPEC §8.5 steps 1-2: the payer side is read again after the invoice can no longer be paid.
  expect(calls.lastIndexOf('observePayment')).toBeGreaterThan(calls.indexOf('cancelUnpaidInvoice'));
  expectNoFundMovement(w);
});

it('CP-032/B4 NOT_FOUND inside the creation window stays UNKNOWN for the operator, with the invoice cancelled', async () => {
  const w = await world('notfound-young');
  const e = w.seed('UNKNOWN', { payer: [{ kind: 'NOT_FOUND' }] }, { submittedAgoMs: 30_000 });
  const report = await w.run();
  expect(rowOf(w.path, e.executionId).status).toBe('UNKNOWN');
  expect(w.callsFor(e.hash).filter(name => name === 'cancelUnpaidInvoice')).toHaveLength(1);
  expect(report.unresolved).toContain(e.executionId);
  expectNoFundMovement(w);
});

it('CP-032/B4 NOT_FOUND whose invoice cancel answers "already paid" is a success, not NOT_SENT', async () => {
  const w = await world('notfound-paid');
  const e = w.seed('UNKNOWN', { payer: [{ kind: 'NOT_FOUND' }, succeeded(150_000n, 1, true, w.base.targetKey)], cancel: 'ALREADY_PAID' }, { submittedAgoMs: 130_000 });
  await w.run();
  expect(rowOf(w.path, e.executionId).status).toBe('VERIFIED_SUCCESS');
});

it('CP-032/B5 the startup sweep resolves the unresolved executions from the node list and leaves live leases, terminal and unsent rows alone', async () => {
  const w = await world('sweep');
  const unknown = w.seed('UNKNOWN', { payer: [succeeded(150_000n, 1, true, w.base.targetKey)] });
  const inflight = w.seed('IN_FLIGHT', { payer: [failed('FAILURE_REASON_INCORRECT_PAYMENT_DETAILS')], invoice: 'OPEN' }, { leaseInMs: 60_000 });
  const submitting = w.seed('SUBMITTING', { payer: [succeeded(150_000n, 1, true, w.base.targetKey)] }, { leaseInMs: 60_000 });
  const terminal = w.seed('VERIFIED_SUCCESS', { payer: [failed('FAILURE_REASON_ERROR')] });
  const claimed = w.seed('CLAIMED', null, { leaseInMs: 60_000 });
  const expired = w.seed('IN_FLIGHT', { payer: [failed('FAILURE_REASON_INCORRECT_PAYMENT_DETAILS')], invoice: 'OPEN' }, { leaseInMs: -5_000 });
  const inflightBefore = rowOf(w.path, inflight.executionId);
  const submittingBefore = rowOf(w.path, submitting.executionId);
  const terminalBefore = rowOf(w.path, terminal.executionId);
  const claimedBefore = rowOf(w.path, claimed.executionId);
  await w.run(true);
  expect(rowOf(w.path, unknown.executionId).status).toBe('VERIFIED_SUCCESS');
  // INV-13: a live lease belongs to a worker that may still be tracking the payment; the sweep does not take it.
  expect(rowOf(w.path, inflight.executionId)).toEqual(inflightBefore);
  expect(rowOf(w.path, submitting.executionId)).toEqual(submittingBefore);
  expect(w.callsFor(inflight.hash)).toEqual([]);
  expect(w.callsFor(submitting.hash)).toEqual([]);
  expect(rowOf(w.path, expired.executionId).status).toBe('VERIFIED_FAILURE');
  expect(rowOf(w.path, terminal.executionId)).toEqual(terminalBefore);
  expect(rowOf(w.path, claimed.executionId)).toEqual(claimedBefore);
  expect(w.callsFor(terminal.hash)).toEqual([]);
  // SPEC §8.4: a restart reads ListPayments / listsendpays, not a live stream (TrackPayments does not replay terminal states).
  const modes = w.node.named('observePayment').map(c => c.args[1]);
  expect(modes.length).toBeGreaterThanOrEqual(2);
  expect(modes.every(mode => mode === 'sweep')).toBe(true);
  expectNoFundMovement(w);
});

it('CP-032/B7 across every evidence class in one pass the reconciler calls neither createInvoice nor sendOnRoute', async () => {
  const w = await world('no-mutation');
  w.seed('UNKNOWN', { payer: [succeeded(150_000n, 1, true, w.base.targetKey)] });
  w.seed('UNKNOWN', { payer: [failed('FAILURE_REASON_NO_ROUTE')] });
  w.seed('UNKNOWN', { payer: [{ kind: 'NOT_FOUND' }] }, { submittedAgoMs: 130_000 });
  w.seed('UNKNOWN', { payer: [{ kind: 'IN_FLIGHT' }] });
  w.seed('IN_FLIGHT', { payer: [{ kind: 'AMBIGUOUS', cause: 'reset' }] });
  w.seed('SUBMITTING', { payer: [failed('FAILURE_REASON_TIMEOUT', 2)] });
  await w.run();
  await w.run(true);
  expectNoFundMovement(w);
  expect(w.node.count('observePayment')).toBeGreaterThanOrEqual(6);
});

it('CP-032/B8 an UNKNOWN older than escalate_after raises stuck-in-flight exactly once in the pass; a younger one does not', async () => {
  const w = await world('stuck');
  const old = w.seed('UNKNOWN', { payer: [{ kind: 'IN_FLIGHT' }] }, { submittedAgoMs: 2 * 3_600_000 });
  const young = w.seed('UNKNOWN', { payer: [{ kind: 'IN_FLIGHT' }] }, { submittedAgoMs: 600_000 });
  const resolvedOld = w.seed('UNKNOWN', { payer: [succeeded(150_000n, 1, true, w.base.targetKey)] }, { submittedAgoMs: 2 * 3_600_000 });
  const report = await w.run();
  expect(w.alerts.filter(a => a.kind === 'stuck-in-flight')).toEqual([{ kind: 'stuck-in-flight', executionId: old.executionId, code: 'STUCK' }]);
  expect(w.alerts.some(a => a.kind === 'stuck-in-flight' && (a.executionId === young.executionId || a.executionId === resolvedOld.executionId))).toBe(false);
  expect(w.alerts).toContainEqual(expect.objectContaining({ executionId: resolvedOld.executionId, code: 'DELTA_UNVERIFIED' }));
  expect(rowOf(w.path, old.executionId).status).toBe('UNKNOWN');
  expect(rowOf(w.path, young.executionId).status).toBe('UNKNOWN');
  expect(rowOf(w.path, resolvedOld.executionId).status).toBe('VERIFIED_SUCCESS');
  expect(report.exit).toBe(7);
});

// Repair round: result checks on a reconciled success, NOT_FOUND closure, CLN failed confirmation.

it('CP-032/B2 a reconciled success with two settled HTLCs stays VERIFIED_SUCCESS and raises INVARIANT_BREACH, exit 8', async () => {
  const w = await world('rec-two-htlcs');
  const e = w.seed('UNKNOWN', { payer: [succeeded(150_000n, 2)] });
  const report = await w.run();
  expect(rowOf(w.path, e.executionId).status).toBe('VERIFIED_SUCCESS');
  expect(w.alerts).toContainEqual({ kind: 'INVARIANT_BREACH', executionId: e.executionId, code: 'SINGLE_PATH_UNAVAILABLE' });
  expect(report.exit).toBe(8);
});

it('CP-032/B2 a reconciled success with a fee above the approved cap raises INVARIANT_BREACH (FEE_ABOVE_CAP), exit 8', async () => {
  const w = await world('rec-fee-cap');
  const e = w.seed('UNKNOWN', { payer: [succeeded(APPROVED_MAX_FEE + 1n)] });
  const report = await w.run();
  const row = rowOf(w.path, e.executionId);
  expect(row.status).toBe('VERIFIED_SUCCESS');
  expect(row.actual_fee_msat).toBe(APPROVED_MAX_FEE + 1n);
  expect(w.alerts).toContainEqual({ kind: 'INVARIANT_BREACH', executionId: e.executionId, code: 'FEE_ABOVE_CAP' });
  expect(report.exit).toBe(8);
});

it('CP-032/B2 a reconciled success whose fee differs from the planned route fee within the cap is a fee-mismatch, exit 9', async () => {
  const w = await world('rec-fee-mismatch');
  const e = w.seed('UNKNOWN', { payer: [succeeded(160_000n, 1, true, w.base.targetKey)] });
  const report = await w.run();
  expect(rowOf(w.path, e.executionId).status).toBe('VERIFIED_SUCCESS');
  expect(w.alerts).toContainEqual({ kind: 'fee-mismatch', executionId: e.executionId, code: 'FEE_MISMATCH' });
  expect(w.alerts.filter(a => a.kind === 'INVARIANT_BREACH')).toEqual([]);
  expect(report.exit).toBe(9);
});

it('CP-032/B4 NOT_FOUND whose cancel answers "already paid" is a success even when the payer side still has no record', async () => {
  const w = await world('notfound-paid-norecord');
  const e = w.seed('UNKNOWN', { payer: [{ kind: 'NOT_FOUND' }, { kind: 'NOT_FOUND' }], cancel: 'ALREADY_PAID' }, { submittedAgoMs: 130_000 });
  await w.run();
  const row = rowOf(w.path, e.executionId);
  // SPEC §8.5 step 1: an invoice the node reports paid sends the execution down the success path; it is never NOT_SENT.
  expect(row.status).toBe('VERIFIED_SUCCESS');
  expect(row.error_code).toBeNull();
});

it('CP-032/B4 NOT_FOUND past the window whose invoice cancel fails stays UNKNOWN: the invoice was not closed', async () => {
  const w = await world('notfound-cancel-fails');
  const e = w.seed('UNKNOWN', { payer: [{ kind: 'NOT_FOUND' }] }, { submittedAgoMs: 130_000 });
  w.node.script.cancel = () => Promise.reject(new Error('CancelInvoice answer lost'));
  const report = await w.run();
  expect(rowOf(w.path, e.executionId).status).toBe('UNKNOWN');
  expect(reservationState(w.path, e.executionId).state).toBe('HELD');
  expect(report.unresolved).toContain(e.executionId);
});

it('CP-032/B2 on a CLN node one listsendpays failed is not terminal; a second failed one interval later is', async () => {
  let observationAgeMs = 0;
  const w = await world('cln-failed-twice', { implementation: 'cln', confirmIntervalMs: 2000, failedObservationAgeMs: () => observationAgeMs });
  // Control the existing age-read port; native database work cannot establish an observation inside the interval.
  const e = w.seed('UNKNOWN', { payer: [failed('SENDPAY_FAILED')], invoice: 'OPEN' });
  await w.run();
  // SPEC §5.4: listsendpays can swing between failed and pending or lag; a single read decides nothing.
  expect(rowOf(w.path, e.executionId).status).toBe('UNKNOWN');
  expect(w.node.count('cancelUnpaidInvoice')).toBe(0);
  expect(reservationState(w.path, e.executionId).state).toBe('HELD');
  await w.run();
  expect(rowOf(w.path, e.executionId).status).toBe('UNKNOWN');
  await sleep(2100);
  observationAgeMs = 2100;
  await w.run();
  expect(rowOf(w.path, e.executionId).status).toBe('VERIFIED_FAILURE');
  expect(w.node.count('cancelUnpaidInvoice')).toBe(1);
});

it('CP-032/B2 real fenced FAILED observations age with the database clock and CLEARED removes their age', async () => {
  const w = await world('cln-real-observation-age');
  const e = w.seed('UNKNOWN', null, { leaseInMs: 60_000 });
  const p = await loadPersistence();
  const db = p.openDatabase(w.path, { readOnly: false });
  try {
    const store = db.executions as typeof db.executions & FailedObservationStore;
    expect(store.failedSinceMs(e.executionId)).toBeNull();
    const fence = store.noteObservation(e.executionId, rowOf(w.path, e.executionId).fence_epoch, 'FAILED');
    const initialAge = store.failedSinceMs(e.executionId);
    expect(initialAge).not.toBeNull();
    expect(initialAge).toBeGreaterThanOrEqual(0);
    expect(rowOf(w.path, e.executionId).fence_epoch).toBe(fence);
    await sleep(2100);
    expect(store.failedSinceMs(e.executionId)).toBeGreaterThanOrEqual(2000);
    const clearedFence = store.noteObservation(e.executionId, fence, 'CLEARED');
    expect(rowOf(w.path, e.executionId).fence_epoch).toBe(clearedFence);
    expect(store.failedSinceMs(e.executionId)).toBeNull();
    expect(rowOf(w.path, e.executionId).status).toBe('UNKNOWN');
    expect(reservationState(w.path, e.executionId).state).toBe('HELD');
    expectNoFundMovement(w);
  } finally { db.close(); }
});

// Round 3: reconciled result checks at their boundaries, the CLN reset, and delta verification after a dispatch.

it('CP-032/B2 a reconciled success with no settled HTLC is not single-path: INVARIANT_BREACH, exit 8', async () => {
  const w = await world('rec-zero-htlcs');
  const e = w.seed('UNKNOWN', { payer: [succeeded(150_000n, 0)] });
  const report = await w.run();
  expect(w.alerts).toContainEqual({ kind: 'INVARIANT_BREACH', executionId: e.executionId, code: 'SINGLE_PATH_UNAVAILABLE' });
  expect(report.exit).toBe(8);
});

it('CP-032/B2 a reconciled fee exactly at the approved cap is within it: a fee-mismatch against the route fee (exit 9), no breach', async () => {
  const w = await world('rec-fee-at-cap');
  const e = w.seed('UNKNOWN', { payer: [succeeded(APPROVED_MAX_FEE, 1, true, w.base.targetKey)] });
  const report = await w.run();
  expect(w.alerts.filter(a => a.kind === 'INVARIANT_BREACH')).toEqual([]);
  expect(w.alerts).toContainEqual({ kind: 'fee-mismatch', executionId: e.executionId, code: 'FEE_MISMATCH' });
  expect(report.exit).toBe(9);
});

it('CP-032/B2 on a CLN node an observation between two failed ones resets the rule: failed, in flight, failed decides nothing', async () => {
  const w = await world('cln-reset', { implementation: 'cln', confirmIntervalMs: 200 });
  const e = w.seed('UNKNOWN', { payer: [failed('PAY_TRY_OTHER_ROUTE'), { kind: 'IN_FLIGHT' }, failed('PAY_TRY_OTHER_ROUTE')], invoice: 'OPEN' });
  await w.run();
  await sleep(250);
  // The payer side swung back to pending (SPEC §5.4, cln#9036): the first failed read no longer counts.
  await w.run();
  await sleep(250);
  // A failed read one interval after the pending one is a new first observation, not a confirmation.
  await w.run();
  expect(rowOf(w.path, e.executionId).status).toBe('UNKNOWN');
  expect(w.node.count('cancelUnpaidInvoice')).toBe(0);
  await sleep(250);
  await w.run();
  expect(rowOf(w.path, e.executionId).status).toBe('VERIFIED_FAILURE');
});

/**
 * A dispatch that ends UNKNOWN at its deadline (its baseline recorded at SUBMITTING), then a reconcile that finds the
 * payment settled and reads the channel balances `after` (SPEC §8.7 step 5 applies to every SUCCEEDED resolution).
 */
async function settledLater(prefix: string, after: (base: Base) => FakeChannel[], tolerance: bigint | null, fee = 150_000n) {
  const r = await prepare(prefix, { attemptDeadlineMs: 150, script: () => ({ send: c => { c.onDispatched?.(); return never(); } }) });
  expect((await r.run()).exit).toBe(7);
  exec(r.path, 'UPDATE executions SET lease_expires_at = 0 WHERE id = ?', r.executionId);
  const node = new ScriptedExecutionNode({ observe: () => Promise.resolve(succeeded(fee, 1, true, r.base.targetKey)), before: () => after(r.base), after: () => after(r.base) });
  const alerts: Alert[] = [];
  const p = await loadPersistence();
  const { reconcile } = await loadReconciler();
  const db = p.openDatabase(r.path, { readOnly: false });
  const deps: ReconcileDeps = {
    db, adapters: new Map([[r.base.nodeId, node]]), workerId: 'reconciler', leaseMs: 60_000, notFoundWindowMs: 120_000,
    escalateAfterMs: 3_600_000, confirmIntervalMs: 60_000, alert: alert => { alerts.push(alert); },
    ...(tolerance === null ? {} : { deltaToleranceMsat: tolerance }),
  };
  let report: ReconcileReport;
  try { report = await reconcile(deps, { startup: false }); } finally { db.close(); }
  return { r, alerts, report, row: rowOf(r.path, r.executionId) };
}

it('CP-032/B2 a reconciled success whose channels moved by exactly P + F and P is delta MATCH, exit 0', async () => {
  const s = await settledLater('rec-delta-match', base => settled(base, ROUTE_FEE)(), 1_000n);
  expect(s.row.status).toBe('VERIFIED_SUCCESS');
  expect(s.row.delta_status).toBe('MATCH');
  expect(s.alerts).toEqual([]);
  expect(s.report.exit).toBe(0);
});

it('CP-032/B2 a reconciled success whose target channel was not credited is delta MISMATCH with an alert, exit 9', async () => {
  const s = await settledLater('rec-delta-mismatch', base => balances(base, S_BEFORE - PRINCIPAL - ROUTE_FEE, T_BEFORE), 1_000n);
  expect(s.row.status).toBe('VERIFIED_SUCCESS');
  expect(s.row.delta_status).toBe('MISMATCH');
  expect(s.alerts).toContainEqual({ kind: 'delta-mismatch', executionId: s.r.executionId, code: 'DELTA_MISMATCH' });
  expect(s.report.exit).toBe(9);
});

it('CP-032/B2 without a configured tolerance the delta check still runs at zero tolerance: one msat off is a MISMATCH', async () => {
  const off = await settledLater('rec-delta-notol-off', base => balances(base, S_BEFORE - PRINCIPAL - ROUTE_FEE + 1n, T_BEFORE + PRINCIPAL), null);
  expect(off.row.delta_status).toBe('MISMATCH');
  expect(off.report.exit).toBe(9);
  const exact = await settledLater('rec-delta-notol-exact', base => settled(base, ROUTE_FEE)(), null);
  expect(exact.row.delta_status).toBe('MATCH');
  expect(exact.report.exit).toBe(0);
});
