/*
Interface: test/helpers/cp028-executor.ts (claimExecution). Worker processes load the built modules dist/executor/claim.js
and dist/persistence/index.js (`npm run build` first; `npm test` builds through pretest).

Rule under test: SPEC §6.4 and SECURITY INV-13: two workers in separate processes claiming the same proposal at the same
moment; exactly one claim succeeds, the loser's conditional writes match zero rows and it is told claimed-elsewhere
(SPEC §10.3 AE4, chaos row T-06).
*/
import { existsSync } from 'node:fs';
import { expect, it } from 'vitest';
import {
  builtClaim, builtPersistence, loadPersistence, policyFor, raceClaims, raw, scratchDb, seedBase, seedProposal,
} from '../helpers/cp028-executor.js';

it('CP-028/B2 two worker processes race for each of 25 proposals: exactly one claim per proposal, the loser gets claimed-elsewhere and zero rows', async () => {
  expect(existsSync(builtClaim), 'built executor module').toBe(true);
  expect(existsSync(builtPersistence), 'built persistence module').toBe(true);
  const p = await loadPersistence();
  const path = scratchDb('race');
  const base = seedBase(p, path);
  const policy = policyFor(base, { budget: { msat: 1_000_000_000n, periodMs: 86_400_000 } });
  const inputs = Array.from({ length: 25 }, () => ({ approval: seedProposal(base), policy }));

  const results = await raceClaims(path, [{ workerId: 'worker-a', inputs }, { workerId: 'worker-b', inputs }]);
  const [a, b] = results;
  if (a === undefined || b === undefined) throw new Error('missing worker result');

  const check = raw(path);
  try {
    inputs.forEach((input, i) => {
      const left = a.outcomes[i];
      const right = b.outcomes[i];
      if (left === undefined || right === undefined) throw new Error(`missing outcome ${String(i)}`);
      const winners = [left, right].filter(o => o.ok);
      expect(winners, `proposal ${String(i)}`).toHaveLength(1);
      const winner = winners[0];
      const loser = left.ok ? right : left;
      if (winner === undefined) throw new Error('no winner');
      expect(winner.fenceEpoch).toBe(1n);
      expect(loser).toEqual({ ok: false, exit: 5, step: 'claimed-elsewhere', executionId: winner.executionId });
      const rows = check.prepare('SELECT id, status, fence_epoch, worker_id FROM executions WHERE proposal_id = ?').all(input.approval.proposalId) as
        { id: string; status: string; fence_epoch: bigint; worker_id: string }[];
      // One row, still at epoch 1: a loser whose re-claim had matched would have moved the epoch to 2.
      expect(rows).toEqual([{ id: winner.executionId, status: 'CLAIMED', fence_epoch: 1n, worker_id: left.ok ? 'worker-a' : 'worker-b' }]);
      const held = check.prepare("SELECT count(*) AS n FROM budget_reservations WHERE execution_id = ? AND state = 'HELD'").get(winner.executionId) as { n: bigint };
      expect(held.n).toBe(1n);
    });
    const total = check.prepare('SELECT count(*) AS n FROM executions').get() as { n: bigint };
    expect(total.n).toBe(25n);
  } finally { check.close(); }
}, 90_000);
