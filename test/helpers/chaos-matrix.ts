// Interface: existing public executor, reconciler, route validator and persistence ports.
// Faults and expected outcomes are SPEC §11.6; the wire fakes cite the pinned node sources.
import { randomBytes } from 'node:crypto';
import { expect } from 'vitest';
import { circularRoute, FakePreflightNode, type Script } from '../fakes/preflight-node.js';
import { ScriptedExecutionNode } from '../fakes/execution-node.js';
import { APPROVAL_KEYS, loadPersistence, loadPreflight, policyFor, scratchDb, seedBase, seedProposal, execByProposal, reservationsOf, type Base, type ExecutionPolicy, type ExecutionStatus } from './cp028-executor.js';
import { loadReconciler, seedExecution, rowOf, reservationState, type Alert, type PaymentObservation } from './cp030-execution.js';
import { loadRoute, POLICY, type CandidateRoute, type RouteConstraints, type RouteChannel } from './route-interfaces.js';

export async function preflight(id: string, script: (base: Base) => Partial<Script> = () => ({}), overrides: Partial<ExecutionPolicy> = {}) {
  const p = await loadPersistence(), { prepareExecution } = await loadPreflight();
  const path = scratchDb(id), base = seedBase(p, path), approval = seedProposal(base), policy = policyFor(base, overrides);
  const node = new FakePreflightNode(base.sourceKey, base.targetKey, script(base));
  const db = p.openDatabase(path, { readOnly: false });
  try {
    const outcome = await prepareExecution({ db, adapter: node, workerId: 'matrix', leaseMs: 60_000 }, { approval, policy, approvalKeyIds: APPROVAL_KEYS });
    return { path, base, approval, node, outcome, row: execByProposal(path, approval.proposalId) };
  } finally { db.close(); }
}

export function cancelled(r: Awaited<ReturnType<typeof preflight>>, code: string, exit = 5): void {
  expect(r.row).toBeDefined();
  if (!r.row) throw new Error('execution missing');
  expect(r.outcome).toEqual({ kind: 'CANCELLED', executionId: r.row.id, exit, step: code });
  expect(r.row.status).toBe('CANCELLED');
  expect(r.row.error_code).toBe(code);
  expect(r.row.payment_hash).toBeNull();
  expect(reservationsOf(r.path, r.row.id).map(x => x.state)).toEqual(['RELEASED']);
  expect(r.node.mutatingCalls()).toEqual([]);
}

export async function reconciliation(id: string, observations: PaymentObservation[], options: { status?: ExecutionStatus; ageMs?: number; invoice?: 'OPEN' | 'SETTLED'; confirmIntervalMs?: number } = {}) {
  const p = await loadPersistence(), { reconcile } = await loadReconciler();
  const path = scratchDb(id), base = seedBase(p, path), hash = randomBytes(32).toString('hex');
  const { executionId } = seedExecution(base, { status: options.status ?? 'UNKNOWN', paymentHash: hash,
    route: circularRoute(base.sourceKey, base.targetKey, 150_000n, 80), plannedFeeMsat: 150_000n,
    leaseInMs: -5_000, submittedAgoMs: options.ageMs ?? 300_000 });
  let index = 0;
  const node = new ScriptedExecutionNode({ observe: () => Promise.resolve(observations[Math.min(index++, observations.length - 1)] ?? { kind: 'IN_FLIGHT' }), invoiceState: () => Promise.resolve(options.invoice ?? 'OPEN') });
  const alerts: Alert[] = [];
  const run = async (startup = false) => {
    const db = p.openDatabase(path, { readOnly: false });
    try { return await reconcile({ db, adapters: new Map([[base.nodeId, node]]), workerId: 'matrix-reconcile', leaseMs: 60_000,
      notFoundWindowMs: 120_000, escalateAfterMs: 3_600_000, confirmIntervalMs: options.confirmIntervalMs ?? 0,
      alert: a => { alerts.push(a); } }, { startup }); } finally { db.close(); }
  };
  return { path, base, executionId, hash, node, alerts, run, row: () => rowOf(path, executionId), reservation: () => reservationState(path, executionId) };
}

// SPEC §4.4: 1000 + floor(amount * 1000 / 1e6), backwards from 100,000,000 msat.
export function routeWorld() {
  const self = `03${'cd'.repeat(32)}`, a = `02${'aa'.repeat(32)}`, b = `02${'bb'.repeat(32)}`;
  const route: CandidateRoute = { parts: 1, builtAtHeight: 500, totalTimeLock: 632, totalAmountMsat: 100_202_101n, totalFeeMsat: 202_101n,
    hops: [
      { scid: '112x1x0', nodeIdOut: a, amountOutMsat: 100_202_101n, cltvOut: 632, policy: null },
      { scid: '336x1x0', nodeIdOut: b, amountOutMsat: 100_101_000n, cltvOut: 552, policy: { baseFeeMsat: 1000n, feePpm: 1000n, cltvExpiryDelta: 80, minHtlcMsat: 1n, maxHtlcMsat: null } },
      { scid: '224x1x0', nodeIdOut: self, amountOutMsat: 100_000_000n, cltvOut: 518, policy: { baseFeeMsat: 1000n, feePpm: 1000n, cltvExpiryDelta: 34, minHtlcMsat: 1n, maxHtlcMsat: null } },
    ] };
  const constraints: RouteConstraints = { selfPubkey: self, implementation: 'lnd', sourceScid: '112x1x0', targetScid: '224x1x0', outPeer: a, inPeer: b,
    principalMsat: 100_000_000n, maxFeeMsat: 300_000n, maxCltvDelta: 144, finalCltvDelta: 18, blockHeight: 500 };
  const channels: RouteChannel[] = [
    { channelKey: '112x1x0', scid: '112x1x0', peerPubkey: a, state: 'ACTIVE', spendableMsat: 500_000_000n, receivableMsat: 500_000_000n },
    { channelKey: '224x1x0', scid: '224x1x0', peerPubkey: b, state: 'ACTIVE', spendableMsat: 500_000_000n, receivableMsat: 500_000_000n },
  ];
  const validate = async () => (await loadRoute()).validateRoute(route, constraints, channels, POLICY);
  return { route, constraints, channels, validate };
}

export function journalTypes(path: string, executionId: string): string[] {
  // Independent read-only SQL oracle; no expectations derived from the production ledger implementation.
  const { DatabaseSync } = process.getBuiltinModule('node:sqlite');
  const db = new DatabaseSync(path, { readOnly: true });
  try { return (db.prepare('SELECT event_type FROM ledger_journals WHERE execution_id = ? ORDER BY event_type').all(executionId) as { event_type: string }[]).map(r => r.event_type); }
  finally { db.close(); }
}
