// Interface: existing execution/preflight ports and task-owned SQLite fixtures in cp028-executor.ts.
import { beforeAll, expect, it } from 'vitest';
import { FakePreflightNode, fakeChannel } from '../fakes/preflight-node.js';
import { APPROVAL_KEYS, dbNow, execByProposal, IN_PEER, loadPersistence, loadPreflight, OUT_PEER, policyFor,
  prepareEmptyDatabaseFixture, raw, reservationsOf, scratchDb, seedBase, seedProposal } from '../helpers/cp028-executor.js';

let emptyDatabase: string;
beforeAll(async () => { emptyDatabase = prepareEmptyDatabaseFixture(await loadPersistence()); });

for (const side of ['source', 'target'] as const) {
  it(`CP-029/B1 REG-EXEC012 refuses a future ${side} snapshot before route discovery (INV-06)`, async () => {
    const p = await loadPersistence();
    const path = scratchDb(`future-${side}`);
    const base = seedBase(p, path, emptyDatabase);
    const approval = seedProposal(base);
    const fake = new FakePreflightNode(base.sourceKey, base.targetKey, { channels: () => [
      fakeChannel(base.sourceKey, OUT_PEER, { observedAt: dbNow(path) + (side === 'source' ? 120_000 : -1_000) }),
      fakeChannel(base.targetKey, IN_PEER, { observedAt: dbNow(path) + (side === 'target' ? 120_000 : -1_000) }),
    ] });
    const db = p.openDatabase(path, { readOnly: false });
    try {
      const { prepareExecution } = await loadPreflight();
      const outcome = await prepareExecution({ db, adapter: fake, workerId: 'worker', leaseMs: 60_000 }, { approval, policy: policyFor(base), approvalKeyIds: APPROVAL_KEYS });
      const row = execByProposal(path, approval.proposalId);
      expect(outcome).toEqual({ kind: 'CANCELLED', executionId: row?.id, exit: 5, step: 'STALE_SNAPSHOT' });
      expect(row?.status).toBe('CANCELLED');
      expect(reservationsOf(path, row?.id ?? '').map(r => r.state)).toEqual(['RELEASED']);
      expect(fake.calls).not.toContain('findCircularRoute');
      expect(fake.mutatingCalls()).toEqual([]);
    } finally { db.close(); }
  });
}

for (const mismatch of [false, true]) {
  it(`CP-029/B1 REG-EXEC014 ${mismatch ? 'persists quarantine for a mismatching identity' : 'retains a usable pinned identity'} (INV-12)`, async () => {
    const p = await loadPersistence();
    const path = scratchDb('identity-state');
    const base = seedBase(p, path, emptyDatabase);
    const approval = seedProposal(base);
    const fake = new FakePreflightNode(base.sourceKey, base.targetKey, mismatch ? { pubkey: `03${'ee'.repeat(32)}` } : {});
    const db = p.openDatabase(path, { readOnly: false });
    try {
      const { prepareExecution } = await loadPreflight();
      const outcome = await prepareExecution({ db, adapter: fake, workerId: 'worker', leaseMs: 60_000 }, { approval, policy: policyFor(base), approvalKeyIds: APPROVAL_KEYS });
      if (mismatch) expect(outcome).toEqual({ kind: 'CANCELLED', executionId: execByProposal(path, approval.proposalId)?.id, exit: 5, step: 'identity' });
      else expect(outcome.kind).toBe('READY');
      expect(fake.mutatingCalls()).toEqual([]);
    } finally { db.close(); }
    const reopened = raw(path);
    try { expect(reopened.prepare('SELECT state FROM nodes WHERE id = ?').get(base.nodeId)).toEqual({ state: mismatch ? 'QUARANTINED' : 'ONLINE' }); }
    finally { reopened.close(); }
  });
}

