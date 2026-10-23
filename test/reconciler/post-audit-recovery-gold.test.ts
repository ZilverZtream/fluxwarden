// SPEC Approval, execution and recovery: reconcile stored hashes without resending;
// test/helpers/cp030-execution.ts D8 and recovery success rule specify measured deltas.
// Independent audit AUDIT-06/10 supplies the unavailable-read and 101-row witnesses.
import { createHash } from 'node:crypto';
import { expect, it } from 'vitest';
import { ScriptedExecutionNode, succeeded } from '../fakes/execution-node.js';
import { balances, prepare, ROUTE_FEE, S_BEFORE, T_BEFORE } from '../helpers/cp030-dispatch.js';
import { loadActions, loadReconciler, PRINCIPAL, reservationState, rowOf, seedExecution } from '../helpers/cp030-execution.js';
import { loadLedger } from '../helpers/cp037-ledger.js';
import { rows } from '../helpers/cpw-cli.js';

for (const [label, extraReceipt, expectedDelta, expectedExit] of [
  ['matching', 0n, 'MATCH', 0],
  ['different', 2_000n, 'MISMATCH', 9],
] as const) {
  it(`CP-032/AUDIT-06 terminal paid PENDING balance verification retries and persists a ${label} measurement`, async () => {
    const r = await prepare(`post-audit-pending-${label}`, {
      script: () => ({ after: () => { throw new Error('temporary balance read failure'); } }),
    });
    expect((await r.run()).exit).toBe(9);
    expect(rowOf(r.path, r.executionId)).toMatchObject({ status: 'VERIFIED_SUCCESS', delta_status: 'PENDING' });
    expect(reservationState(r.path, r.executionId)).toEqual({ state: 'CONSUMED', consumed: 150_000n });
    const beforeJournals = rows(r.path, 'SELECT * FROM ledger_journals ORDER BY id');
    const current = () => balances(r.base, S_BEFORE - PRINCIPAL - ROUTE_FEE, T_BEFORE + PRINCIPAL + extraReceipt);
    const recovered = new ScriptedExecutionNode({ before: current, after: current,
      observe: () => Promise.resolve(succeeded(ROUTE_FEE, 1, true, r.base.targetKey)),
      invoiceState: () => Promise.resolve('SETTLED') });
    const { reconcile } = await loadReconciler();
    const db = r.p.openDatabase(r.path, { readOnly: false });
    try {
      const report = await reconcile({ db, adapters: new Map([[r.base.nodeId, recovered]]), workerId: 'pending-recovery',
        leaseMs: 60_000, notFoundWindowMs: 120_000, escalateAfterMs: 3_600_000, confirmIntervalMs: 1_000,
        deltaToleranceMsat: 1_000n, alert: () => undefined }, { startup: true });
      expect.soft(rowOf(r.path, r.executionId)).toMatchObject({ status: 'VERIFIED_SUCCESS', delta_status: expectedDelta,
        actual_fee_msat: 150_000n });
      expect.soft(recovered.count('listChannels'), 'a later node measurement must actually be read').toBeGreaterThan(0);
      expect.soft(report.exit).toBe(expectedExit);
    } finally { db.close(); }
    // A fresh read-only command must see the result after the recovery connection closes.
    const { actionsStatus } = await loadActions();
    const status = JSON.parse(actionsStatus({ databasePath: r.path, executionId: r.executionId, json: true }).output) as { result: unknown };
    expect.soft(status.result)
      .toMatchObject({ status: 'VERIFIED_SUCCESS', delta_status: expectedDelta });
    expect(rows(r.path, 'SELECT * FROM ledger_journals ORDER BY id')).toEqual(beforeJournals);
    expect(reservationState(r.path, r.executionId)).toEqual({ state: 'CONSUMED', consumed: 150_000n });
    expect(recovered.fundMovingCalls()).toEqual([]);
    expect(r.node.count('sendOnRoute')).toBe(1);
  });
}

it('CP-032/AUDIT-10 bounded recovery passes reach the 101st attribution despite 100 persistently unresolved predecessors', async () => {
  const r = await prepare('post-audit-attribution-fairness');
  const ids: string[] = [];
  const hashes: string[] = [];
  let lastHash: string | undefined;
  const db = r.p.openDatabase(r.path, { readOnly: false });
  try {
    for (let i = 0; i < 101; i++) {
      const hash = createHash('sha256').update(`post-audit-attribution-${String(i)}`).digest('hex');
      const seeded = seedExecution(r.base, { status: 'UNKNOWN', paymentHash: hash, route: r.route, plannedFeeMsat: ROUTE_FEE });
      db.executions.transition(seeded.executionId, 3n, 'UNKNOWN', 'VERIFIED_SUCCESS', {
        actualFeeMsat: ROUTE_FEE, settledChannelKey: null, deltaStatus: 'PENDING' });
      ids.push(seeded.executionId); hashes.push(hash);
    }
    // Use the public candidate ordering, not fixture insertion order: ULIDs made
    // within one millisecond need not have the same order as insertion.
    const candidates = (db as unknown as { executions: { unresolved(): { paymentHash: string }[] } }).executions.unresolved();
    expect(candidates).toHaveLength(101);
    lastHash = candidates[100]?.paymentHash;
  } finally { db.close(); }
  const lastId = lastHash === undefined ? undefined : ids[hashes.indexOf(lastHash)];
  if (lastHash === undefined || lastId === undefined) throw new Error('101-row fixture is incomplete');
  const seen = new Set<string>();
  const node = new ScriptedExecutionNode({ observe: hash => {
    seen.add(hash);
    return Promise.resolve(succeeded(ROUTE_FEE, 1, true, hash === lastHash ? r.base.targetKey : null));
  }, invoiceState: () => Promise.resolve('SETTLED') });
  const { reconcile } = await loadReconciler();
  // Reopen the database and change worker identity between passes, as a daemon restart does.
  // Three passes allow bounded work while ruling out a permanently repeated first-100 slice.
  for (let pass = 0; pass < 3; pass++) {
    const next = r.p.openDatabase(r.path, { readOnly: false });
    try {
      await reconcile({ db: next, adapters: new Map([[r.base.nodeId, node]]), workerId: `fair-recovery-${String(pass)}`,
        leaseMs: 60_000, notFoundWindowMs: 120_000, escalateAfterMs: 3_600_000, confirmIntervalMs: 1_000,
        alert: () => undefined }, { startup: true });
    } finally { next.close(); }
  }
  expect.soft(seen.has(lastHash), 'later attributions must eventually receive a node observation').toBe(true);
  const m = await loadLedger();
  const book = m.openDatabase(r.path, { readOnly: true });
  try {
    const settled = book.ledger.journals().filter(journal => journal.executionId === lastId && journal.eventType === 'REBALANCE_SETTLED');
    expect.soft(settled).toHaveLength(1);
    // INV-08/09: recovery attributes the principal with a correction; the
    // original unassigned SETTLED journal remains append-only.
    expect.soft(settled[0]?.lines[0]?.account).toBe('clearing:unassigned');
    expect.soft(book.ledger.balances().get(`channel:lnd-r:${r.base.targetKey}:local`)).toBe(100_000_000n);
    expect.soft(book.ledger.balances().get('clearing:unassigned')).toBe(10_000_000_000n);
  } finally { book.close(); }
  expect(node.fundMovingCalls()).toEqual([]);
  expect(rowOf(r.path, lastId).status).toBe('VERIFIED_SUCCESS');
});
