/*
Interface: test/helpers/cp030-execution.ts (dispatchExecution D7-D10).

Rules under test: SECURITY INV-04 (an unacknowledged or dropped mutating RPC is neither success nor failure; only the
reconciler leaves UNKNOWN), INV-19 (never sent again), INV-18 (zero affected rows after the send: stop, write nothing over
the new holder); SPEC §8.2 (SUBMITTING/IN_FLIGHT -> UNKNOWN on an ambiguous answer, transport loss or lost lease), §10.1
(an interrupt after the mutating RPC may have reached the node leaves the execution to the reconciler, exit 7), §10.3 AE11.
*/
import { expect, it } from 'vitest';
import { never, succeeded } from '../fakes/execution-node.js';
import { sleep } from '../helpers/cp028-executor.js';
import { exec, reservationState, rowOf, transitionsOf } from '../helpers/cp030-execution.js';
import { prepare, ROUTE_FEE } from '../helpers/cp030-dispatch.js';

type Prepared = Awaited<ReturnType<typeof prepare>>;

/** UNKNOWN as SPEC §8.2 defines it: nothing concluded, nothing closed, budget still held, one send. */
function expectUnknown(r: Prepared, outcome: { exit: number; step: string | null }): void {
  expect(outcome).toEqual({ executionId: r.executionId, exit: 7, step: 'OUTCOME_UNKNOWN' });
  const row = rowOf(r.path, r.executionId);
  expect(row.status).toBe('UNKNOWN');
  expect(row.error_code).toBeNull();
  expect(row.actual_fee_msat).toBeNull();
  expect(reservationState(r.path, r.executionId).state).toBe('HELD');
  expect(r.node.count('sendOnRoute')).toBe(1);
  expect(r.node.count('cancelUnpaidInvoice')).toBe(0);
  expect(transitionsOf(r.path, r.executionId)).toEqual(['PREFLIGHT>SUBMITTING', 'SUBMITTING>IN_FLIGHT', 'IN_FLIGHT>UNKNOWN']);
}

it('CP-032/B1 an answer lost after the request was written is UNKNOWN (exit 7), never a failure and never a retry', async () => {
  const r = await prepare('ambiguous', { script: () => ({ send: c => { c.onDispatched?.(); return Promise.resolve({ kind: 'AMBIGUOUS', cause: 'reset after write' }); } }) });
  expectUnknown(r, await r.run());
});

it('CP-032/B1 a transport rejection of the send after the request was written is UNKNOWN', async () => {
  const r = await prepare('reject', { script: () => ({ send: c => { c.onDispatched?.(); return Promise.reject(Object.assign(new Error('socket hang up'), { phase: 'response' })); } }) });
  expectUnknown(r, await r.run());
});

it('CP-032/B1 a payer record still in flight after the send is UNKNOWN', async () => {
  const r = await prepare('inflight', { script: () => ({ send: c => { c.onDispatched?.(); return Promise.resolve({ kind: 'IN_FLIGHT' }); } }) });
  expectUnknown(r, await r.run());
});

it('CP-032/B1 NOT_FOUND straight after the send is UNKNOWN for the reconciler, not a failure', async () => {
  const r = await prepare('notfound', { script: () => ({ send: c => { c.onDispatched?.(); return Promise.resolve({ kind: 'NOT_FOUND' }); } }) });
  expectUnknown(r, await r.run());
});

it('CP-032/B1 a send that never answers ends at the attempt deadline as UNKNOWN', async () => {
  const r = await prepare('deadline', { attemptDeadlineMs: 200, script: () => ({ send: c => { c.onDispatched?.(); return never(); } }) });
  const started = Date.now();
  const outcome = await r.run();
  expect(Date.now() - started).toBeLessThan(5_000);
  expectUnknown(r, outcome);
});

it('CP-032/B1 a stop request after dispatch leaves the execution UNKNOWN for the reconciler (exit 7), never cancelled or failed', async () => {
  const stop = new AbortController();
  const r = await prepare('stop-late', {
    signal: stop.signal, attemptDeadlineMs: 60_000,
    script: () => ({ send: c => { c.onDispatched?.(); setTimeout(() => { stop.abort(); }, 50); return never(); } }),
  });
  const started = Date.now();
  const outcome = await r.run();
  expect(Date.now() - started).toBeLessThan(5_000);
  expectUnknown(r, outcome);
});

it('CP-032/B1 a lease lost while the payment is in flight: the late answer is not written over the new holder (exit 7, lease-lost)', async () => {
  let release: (() => void) | undefined;
  const r = await prepare('lease-inflight', {
    script: () => ({
      send: async c => {
        c.onDispatched?.();
        await new Promise<void>(resolve => { release = resolve; });
        return succeeded(ROUTE_FEE);
      },
    }),
  });
  const running = r.run();
  for (let i = 0; i < 100 && release === undefined; i += 1) await sleep(10);
  await sleep(30);
  // The reconciler took the row after the worker's lease expired (SPEC §6.5): UNKNOWN under a newer fence.
  exec(r.path, "UPDATE executions SET status = 'UNKNOWN', fence_epoch = fence_epoch + 1, worker_id = 'reconciler' WHERE id = ?", r.executionId);
  const taken = rowOf(r.path, r.executionId);
  release?.();
  const outcome = await running;
  expect(outcome).toEqual({ executionId: r.executionId, exit: 7, step: 'lease-lost' });
  expect(rowOf(r.path, r.executionId)).toEqual(taken);
  expect(r.node.names()).toEqual(['listChannels', 'createInvoice', 'sendOnRoute']);
});

it('CP-032/B1 a lease lost while the payment is in flight: a late FAILED answer makes no invoice cancel and no other node call', async () => {
  let release: (() => void) | undefined;
  const r = await prepare('lease-failed', {
    script: () => ({
      send: async c => {
        c.onDispatched?.();
        await new Promise<void>(resolve => { release = resolve; });
        return { kind: 'FAILED', reason: 'FAILURE_REASON_NO_ROUTE', local: false, htlcsInFlight: 0 };
      },
    }),
  });
  const running = r.run();
  for (let i = 0; i < 100 && release === undefined; i += 1) await sleep(10);
  await sleep(30);
  exec(r.path, "UPDATE executions SET status = 'UNKNOWN', fence_epoch = fence_epoch + 1, worker_id = 'reconciler' WHERE id = ?", r.executionId);
  const taken = rowOf(r.path, r.executionId);
  release?.();
  const outcome = await running;
  // INV-18: the new holder (the reconciler) closes the receiver side; this worker only stops.
  expect(outcome).toEqual({ executionId: r.executionId, exit: 7, step: 'lease-lost' });
  expect(rowOf(r.path, r.executionId)).toEqual(taken);
  expect(r.node.names()).toEqual(['listChannels', 'createInvoice', 'sendOnRoute']);
});
