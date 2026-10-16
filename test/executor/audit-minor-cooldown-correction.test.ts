// Interface: dispatch, ordinary attribution reconciliation, and claim admission on the existing SQLite ports.
import { expect, it } from 'vitest';
import { succeeded } from '../fakes/execution-node.js';
import { APPROVAL_KEYS, dbNow, loadClaim, PRINCIPAL, raw, seedProposal, sleep } from '../helpers/cp028-executor.js';
import { balances, prepare, ROUTE_FEE, S_BEFORE, T_BEFORE } from '../helpers/cp030-dispatch.js';
import { loadReconciler, rowOf } from '../helpers/cp030-execution.js';
import { loadLedger } from '../helpers/cp037-ledger.js';

it('CP-035/B3 REG-PERS018 recovering terminal attribution keeps the original success cooldown time', async () => {
  const r = await prepare('cooldown-attribution', { script: ({ base }) => ({ settledChannelKey: null,
    after: () => balances(base, S_BEFORE - PRINCIPAL - ROUTE_FEE, T_BEFORE) }) });
  expect((await r.run()).exit).toBe(9);
  expect(rowOf(r.path, r.executionId).status).toBe('VERIFIED_SUCCESS');
  const original = raw(r.path);
  let terminalAt: number;
  try { terminalAt = Number((original.prepare("SELECT min(at) AS at FROM execution_events WHERE execution_id = ? AND to_status = 'VERIFIED_SUCCESS'").get(r.executionId) as { at: bigint }).at); }
  finally { original.close(); }
  // Let the original one-second cooldown expire on the real database clock.
  while (dbNow(r.path) <= terminalAt + 1_500) await sleep(50);
  r.node.script.observe = () => Promise.resolve(succeeded(ROUTE_FEE, 1, true, r.base.targetKey));
  r.node.script.after = () => balances(r.base, S_BEFORE - PRINCIPAL - ROUTE_FEE, T_BEFORE + PRINCIPAL);
  const { reconcile } = await loadReconciler();
  const { claimExecution } = await loadClaim();
  const db = r.p.openDatabase(r.path, { readOnly: false });
  try {
    await reconcile({ db, adapters: new Map([[r.base.nodeId, r.node]]), workerId: 'attribution-recovery', leaseMs: 60_000,
      notFoundWindowMs: 120_000, escalateAfterMs: 3_600_000, confirmIntervalMs: 60_000, deltaToleranceMsat: 1_000n,
      alert: () => undefined }, { startup: false });
    expect(rowOf(r.path, r.executionId)).toMatchObject({ status: 'VERIFIED_SUCCESS', delta_status: 'MATCH' });
    const events = raw(r.path);
    try {
      const corrected = events.prepare('SELECT updated_at FROM executions WHERE id = ?').get(r.executionId) as { updated_at: bigint };
      expect(Number(corrected.updated_at)).toBeGreaterThan(terminalAt + 1_000);
      const history = events.prepare("SELECT from_status, to_status, at FROM execution_events WHERE execution_id = ? AND to_status = 'VERIFIED_SUCCESS' ORDER BY id").all(r.executionId) as { from_status: string; to_status: string; at: bigint }[];
      expect(Number(history[0]?.at)).toBe(terminalAt);
    } finally { events.close(); }
    const m = await loadLedger();
    const book = m.openDatabase(r.path, { readOnly: true });
    try {
      expect(book.ledger.balances().get(`channel:lnd-r:${r.base.targetKey}:local`)).toBe(PRINCIPAL);
      expect(book.ledger.balances().get('clearing:unassigned') ?? 0n).toBe(0n);
    } finally { book.close(); }
    const approval = seedProposal(r.base);
    const outcome = claimExecution(db, { approval, policy: { ...r.input.policy, cooldownAfterSuccessMs: 1_000 },
      approvalKeyIds: APPROVAL_KEYS, workerId: 'next-worker', leaseMs: 60_000 });
    expect(outcome.ok).toBe(true);
    expect(r.node.count('sendOnRoute')).toBe(1);
  } finally { db.close(); }
});
