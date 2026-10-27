// Oracle: audit F01 and quarantine runbook: a replacement never inherits attempts or history.
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { ScriptedExecutionNode } from '../fakes/execution-node.js';
import { NODE_PUBKEY, loadPersistence, raw, scratchDb, seedBase, type ExecutionStatus } from '../helpers/cp028-executor.js';
import { loadReconciler, reservationState, rowOf, seedExecution } from '../helpers/cp030-execution.js';
import { repoRoot } from '../helpers/cli.js';
import type { Database, ProbeRecordResult } from '../../src/persistence/index.js';

for (const change of ['pubkey', 'implementation'] as const) {
  for (const status of ['CLAIMED', 'PREFLIGHT', 'IN_FLIGHT', 'UNKNOWN', 'VERIFIED_FAILURE', 'VERIFIED_SUCCESS'] as const) {
    it(`CP-044/F01 ${change} replacement preserves ${status} original identity and never resolves its hash`, async () => {
      const p = await loadPersistence(), path = scratchDb('cp044-identity'), base = seedBase(p, path);
      const terminal = status === 'VERIFIED_FAILURE' || status === 'VERIFIED_SUCCESS';
      const seedStatus: ExecutionStatus = terminal ? 'IN_FLIGHT' : status;
      const { executionId } = seedExecution(base, { status: seedStatus, paymentHash: status === 'CLAIMED' ? null : randomBytes(32).toString('hex'),
        submittedAgoMs: 300_000, leaseInMs: 60_000 });
      const port = p.openDatabase(path, { readOnly: false });
      const db = port as unknown as Database;
      const replacement = new ScriptedExecutionNode({ observe: () => Promise.resolve({ kind: 'NOT_FOUND' }),
        invoiceState: () => Promise.resolve('NOT_FOUND'), cancel: () => Promise.resolve('NOT_FOUND') });
      try {
        if (terminal) db.executions.transition(executionId, 3n, 'IN_FLIGHT', status,
          status === 'VERIFIED_SUCCESS' ? { actualFeeMsat: 0n, settledChannelKey: base.targetKey, deltaStatus: 'MATCH' } : { errorCode: 'NO_ROUTE' });
        const originalReservation = reservationState(path, executionId);
        let probe: ProbeRecordResult | undefined;
        try {
          probe = db.nodes.recordProbe({ name: 'lnd-r', implementation: change === 'implementation' ? 'cln' : 'lnd',
            expectedPubkey: change === 'pubkey' ? `02${'ef'.repeat(32)}` : NODE_PUBKEY,
            state: 'ONLINE', observedVersion: change === 'implementation' ? 'v26.06.9' : '0.21.4-beta', capabilities: [] });
        } catch {
          // F01 permits rejecting incompatible reconfiguration. The observable safety assertions below still apply.
        }
        expect.soft(db.executions.plan(executionId)).toMatchObject({ nodePubkey: NODE_PUBKEY, implementation: 'lnd' });
        const { reconcile } = await loadReconciler();
        await reconcile({ db: port, adapters: new Map(probe !== undefined && 'id' in probe ? [[probe.id, replacement]] : []),
          workerId: 'replacement-recovery', leaseMs: 60_000, notFoundWindowMs: 120_000,
          escalateAfterMs: 3_600_000, confirmIntervalMs: 1_000, alert: () => undefined }, { startup: true });
        expect.soft(replacement.count('observePayment')).toBe(0);
        expect.soft(replacement.count('invoiceState')).toBe(0);
        expect.soft(replacement.count('cancelUnpaidInvoice')).toBe(0);
        expect.soft(rowOf(path, executionId).status).toBe(status);
        expect(reservationState(path, executionId)).toEqual(originalReservation);
      } finally { db.close(); }
    });
  }
}

it('CP-044/F01 an unchanged identity accepts refreshed probe metadata without changing history', async () => {
  const p = await loadPersistence(), path = scratchDb('cp044-identity-control'), base = seedBase(p, path);
  const { executionId } = seedExecution(base, { status: 'UNKNOWN', paymentHash: randomBytes(32).toString('hex') });
  const db = p.openDatabase(path, { readOnly: false }) as Database;
  try {
    expect(db.nodes.recordProbe({ name: 'lnd-r', implementation: 'lnd', expectedPubkey: NODE_PUBKEY,
      state: 'ONLINE', observedVersion: '0.21.4-beta', capabilities: ['CHANNEL_READ'] })).toMatchObject({ id: base.nodeId, quarantined: false });
    expect(db.executions.plan(executionId)).toMatchObject({ nodePubkey: NODE_PUBKEY, implementation: 'lnd' });
    expect(db.nodes.list().find(node => node.id === base.nodeId)?.capabilities).toEqual(['CHANNEL_READ']);
    expect(reservationState(path, executionId).state).toBe('HELD');
  } finally { db.close(); }
});

for (const change of ['pubkey', 'implementation'] as const) {
  it(`CP-044/F01 upgrade refuses unverifiable legacy provenance after an old ${change} overwrite`, async () => {
    const p = await loadPersistence(), path = scratchDb('cp044-legacy-identity');
    // Frozen schema4 from audited 143019c; deliberately do not create the
    // fixture with the candidate migration code. There is no route or historic
    // node identity in these records from which the original pin can be proved.
    const base = seedBase(p, path, join(repoRoot, 'labs/fixtures/cp044/legacy-schema4-empty.sqlite3'));
    const { executionId } = seedExecution(base, { status: 'UNKNOWN', paymentHash: randomBytes(32).toString('hex'),
      submittedAgoMs: 300_000, route: null });
    const replacementPubkey = change === 'pubkey' ? `02${'ef'.repeat(32)}` : NODE_PUBKEY;
    const originalReservation = reservationState(path, executionId);
    const old = raw(path);
    try {
      // Exact SQL effect of the old nodes.recordProbe implementation (audit
      // F01). No current admission API is used to manufacture an old overwrite.
      old.prepare('UPDATE nodes SET expected_pubkey = ?, implementation = ? WHERE id = ?')
        .run(replacementPubkey, change === 'implementation' ? 'cln' : 'lnd', base.nodeId);
      expect(old.prepare('PRAGMA user_version').get()?.['user_version']).toBe(4n);
      expect(old.prepare('PRAGMA integrity_check').get()?.['integrity_check']).toBe('ok');
      expect(old.prepare('PRAGMA foreign_key_check').all()).toEqual([]);
    } finally { old.close(); }
    const replacement = new ScriptedExecutionNode({ observe: () => Promise.resolve({ kind: 'NOT_FOUND' }),
      invoiceState: () => Promise.resolve('NOT_FOUND'), cancel: () => Promise.resolve('NOT_FOUND') });
    let port: ReturnType<typeof p.openDatabase> | undefined;
    let refusal: unknown = null;
    try { port = p.openDatabase(path, { readOnly: false }); } catch (error) { refusal = error; }
    try {
      if (port === undefined) {
        const reason = refusal instanceof Error ? refusal.message : '';
        expect(reason).toMatch(/identity|provenance|legacy|quarantin|unverifi/i);
      } else {
        const { reconcile } = await loadReconciler();
        const report = await reconcile({ db: port, adapters: new Map([[base.nodeId, replacement]]), workerId: 'legacy-recovery',
          leaseMs: 60_000, notFoundWindowMs: 120_000, escalateAfterMs: 3_600_000, confirmIntervalMs: 1_000,
          alert: () => undefined }, { startup: true });
        expect.soft(report.exit).not.toBe(0);
      }
      expect.soft(replacement.count('observePayment')).toBe(0);
      expect.soft(replacement.count('invoiceState')).toBe(0);
      expect.soft(replacement.count('cancelUnpaidInvoice')).toBe(0);
      expect.soft(rowOf(path, executionId).status).toBe('UNKNOWN');
      expect(reservationState(path, executionId)).toEqual(originalReservation);
    } finally { port?.close(); }
  });
}
