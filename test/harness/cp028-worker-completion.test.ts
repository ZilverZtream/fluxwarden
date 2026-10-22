// Node 22.23.2 child_process "close"/"exit": exit may precede the closure of stdio.
// https://nodejs.org/download/release/v22.23.2/docs/api/child_process.html#event-close
// Pause real stdout after readiness, then resume at exit: claim results remain in the
// real pipe until after exit. No worker output or claim result is substituted.
import { expect, it } from 'vitest';
import {
  loadPersistence, policyFor, raceClaims, raw, scratchDb, seedBase, seedProposal,
} from '../helpers/cp028-executor.js';

it('CP-028/worker-completion retains every real claim outcome when final stdout is consumed after exit', async () => {
  const path = scratchDb('late-worker-stdout');
  const base = seedBase(await loadPersistence(), path);
  const policy = policyFor(base, { budget: { msat: 1_000_000_000n, periodMs: 86_400_000 } });
  const inputs = Array.from({ length: 25 }, () => ({ approval: seedProposal(base), policy }));
  const exited = new Set<string>();
  const resultAfterExit = new Set<string>();
  const results = await raceClaims(path, [{ workerId: 'worker-a', inputs }, { workerId: 'worker-b', inputs }], children => {
    children.forEach((child, index) => {
      const workerId = index === 0 ? 'worker-a' : 'worker-b';
      child.stdout.pause();
      child.stdout.on('data', () => {
        if (exited.has(workerId)) resultAfterExit.add(workerId);
      });
      child.once('exit', () => {
        exited.add(workerId);
        child.stdout.resume();
      });
    });
  });
  expect([...resultAfterExit].sort(), 'both real pipes deliver their final output after exit').toEqual(['worker-a', 'worker-b']);
  expect(results.map(result => result.workerId)).toEqual(['worker-a', 'worker-b']);
  for (const result of results) expect(result.outcomes, 'all 25 results survive pipe draining').toHaveLength(25);
  const [a, b] = results;
  if (a === undefined || b === undefined) throw new Error('missing worker result');
  const check = raw(path);
  try {
    inputs.forEach((input, index) => {
      const left = a.outcomes[index];
      const right = b.outcomes[index];
      if (left === undefined || right === undefined) throw new Error(`missing outcome ${String(index)}`);
      const winners = [left, right].filter(outcome => outcome.ok);
      expect(winners, `proposal ${String(index)}`).toHaveLength(1);
      const winner = winners[0];
      if (winner === undefined) throw new Error('no winner');
      expect(winner.fenceEpoch).toBe(1n);
      expect(left.ok ? right : left).toEqual({ ok: false, exit: 5, step: 'claimed-elsewhere', executionId: winner.executionId });
      expect(check.prepare('SELECT id, status, fence_epoch, worker_id FROM executions WHERE proposal_id = ?').all(input.approval.proposalId))
        .toEqual([{ id: winner.executionId, status: 'CLAIMED', fence_epoch: 1n, worker_id: left.ok ? 'worker-a' : 'worker-b' }]);
      expect(check.prepare("SELECT count(*) AS n FROM budget_reservations WHERE execution_id = ? AND state = 'HELD'").get(winner.executionId))
        .toEqual({ n: 1n });
    });
    expect(check.prepare('SELECT count(*) AS n FROM executions').get()).toEqual({ n: 25n });
  } finally { check.close(); }
}, 90_000);
