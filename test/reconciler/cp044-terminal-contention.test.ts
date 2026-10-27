// Oracle: audit F05; SPEC 8.4/INV-13: fencing loss is contention, and the pass continues.
import { randomBytes } from 'node:crypto';
import { expect, it } from 'vitest';
import { ScriptedExecutionNode, succeeded } from '../fakes/execution-node.js';
import { circularRoute, fakeChannel } from '../fakes/preflight-node.js';
import { IN_PEER, OUT_PEER, PRINCIPAL, loadPersistence, scratchDb, seedBase } from '../helpers/cp028-executor.js';
import { exec, loadReconciler, reservationState, rowOf, seedExecution } from '../helpers/cp030-execution.js';
import type { Database } from '../../src/persistence/index.js';

function barrier() {
  let enter!: () => void, release!: () => void;
  const entered = new Promise<void>(resolve => { enter = resolve; });
  const released = new Promise<void>(resolve => { release = resolve; });
  return { entered, release, wait: async () => { enter(); await released; } };
}

for (const stage of ['payer-observation', 'channel-observation'] as const) {
  it(`CP-044/F05 terminal recovery loses its fence during ${stage} and continues without overwriting the winner`, async () => {
    const p = await loadPersistence(), path = scratchDb('cp044-contention'), base = seedBase(p, path);
    const route = circularRoute(base.sourceKey, base.targetKey, 150_000n, 80);
    const first = seedExecution(base, { status: 'PREFLIGHT', route, plannedFeeMsat: 150_000n, paymentHash: randomBytes(32).toString('hex') });
    const second = seedExecution(base, { status: 'UNKNOWN', paymentHash: randomBytes(32).toString('hex'), submittedAgoMs: 300_000 });
    const portA = p.openDatabase(path, { readOnly: false }), portB = p.openDatabase(path, { readOnly: false });
    const a = portA as unknown as Database, b = portB as unknown as Database;
    const blocked = barrier();
    // Two real recovery workers share SQLite. The barrier is on their public node adapter,
    // and the expiry mutation represents elapsed lease time without a timing-dependent sleep.
    const laterReads: string[] = [];
    const after = () => [fakeChannel(base.sourceKey, OUT_PEER, { localBalanceMsat: 500_000_000n - PRINCIPAL - 150_000n }),
      fakeChannel(base.targetKey, IN_PEER, { localBalanceMsat: 300_000_000n + PRINCIPAL })];
    const nodeA = new ScriptedExecutionNode({
      observe: async hash => {
        if (hash !== rowOf(path, first.executionId).payment_hash) { laterReads.push(hash); return { kind: 'IN_FLIGHT' }; }
        if (stage === 'payer-observation') await blocked.wait();
        return succeeded(150_000n, 1, true, base.targetKey);
      },
      before: after, after,
    });
    if (stage === 'channel-observation') {
      nodeA.listChannels = async () => { await blocked.wait(); return after(); };
    }
    const nodeB = new ScriptedExecutionNode({ observe: () => Promise.resolve(succeeded(150_000n, 1, true, base.targetKey)), before: after, after });
    const { reconcile } = await loadReconciler();
    const common = { leaseMs: 60_000, notFoundWindowMs: 120_000, escalateAfterMs: 3_600_000, confirmIntervalMs: 1_000,
      deltaToleranceMsat: 0n, alert: () => undefined };
    let stalePass: Promise<unknown> | undefined;
    try {
      let epoch = a.executions.submit(first.executionId, 3n, 10, 60_000,
        { baseline: { sourceLocalMsat: 500_000_000n, targetLocalMsat: 300_000_000n } }).fenceEpoch;
      epoch = a.executions.transition(first.executionId, epoch, 'SUBMITTING', 'IN_FLIGHT');
      a.executions.transition(first.executionId, epoch, 'IN_FLIGHT', 'VERIFIED_SUCCESS', { feeUnreported: true, deltaStatus: 'PENDING' });
      // Sort the unrelated candidate after the terminal row without relying on random ULID order.
      const candidates = a.executions.unresolved();
      const terminal = candidates.find(row => row.executionId === first.executionId);
      const later = candidates.find(row => row.executionId === second.executionId);
      if (terminal === undefined || later === undefined) throw new Error('fixture recovery candidates missing');
      const orderedPort = { ...portA, executions: { ...portA.executions, unresolved: () => [terminal, later] } };
      stalePass = reconcile({ ...common, db: orderedPort, adapters: new Map([[base.nodeId, nodeA]]), workerId: 'stale-worker' }, { startup: true });
      // Attach a rejection handler before the other worker advances, preserving the rejection for assertions.
      const result = stalePass.then(report => ({ report }), (error: unknown) => ({ error }));
      await blocked.entered;
      exec(path, 'UPDATE executions SET lease_expires_at = 0 WHERE id = ?', first.executionId);
      const winnerView = b.executions.view(first.executionId);
      if (winnerView === null) throw new Error('fixture winner cannot read execution');
      const winner = b.executions.takeUnresolved(first.executionId, winnerView.fenceEpoch, 'winning-worker', 60_000);
      if (winner === null) throw new Error('fixture takeover refused');
      let winningEpoch = b.executions.recoverSettlement(first.executionId, winner.fenceEpoch, base.targetKey, 150_000n);
      // Exercise the other worker's adapter read as well as its fenced writes.
      await nodeB.listChannels();
      winningEpoch = b.executions.recordDelta(first.executionId, winningEpoch, 'MATCH');
      const winningRow = rowOf(path, first.executionId), winningReservation = reservationState(path, first.executionId);
      expect(winningRow.fence_epoch).toBe(winningEpoch);
      blocked.release();
      const settled = await result;
      const failureCode = 'error' in settled
        ? typeof settled.error === 'object' && settled.error !== null && 'code' in settled.error ? settled.error.code : 'unexpected-rejection'
        : null;
      expect.soft(failureCode).toBeNull();
      expect.soft(laterReads.length).toBe(1);
      expect.soft(rowOf(path, first.executionId)).toEqual(winningRow);
      expect(reservationState(path, first.executionId)).toEqual(winningReservation);
    } finally { blocked.release(); await stalePass?.catch(() => undefined); a.close(); b.close(); }
  });
}
