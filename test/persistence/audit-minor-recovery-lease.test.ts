// Interface: the existing takeUnresolved persistence port; authority and lease time come from SQLite (INV-13/18).
import { expect, it } from 'vitest';
import { loadPersistence, raw, scratchDb, seedBase } from '../helpers/cp028-executor.js';
import { seedExecution } from '../helpers/cp030-execution.js';
import { loadSrc } from '../helpers/load-src.js';

interface RecoveryPersistence {
  readonly openDatabase: (path: string, options: { readOnly: boolean }) => { close(): void; executions: {
    takeUnresolved(id: string, fenceEpoch: bigint, worker: string, leaseMs: number): { executionId: string; fenceEpoch: bigint } | null;
  } };
}

it('CP-028/B3 REG-PERS002 a second recovery worker cannot preempt an existing recovery lease', async () => {
  const p = await loadPersistence();
  const path = scratchDb('recovery-lease');
  const base = seedBase(p, path);
  const seeded = seedExecution(base, { status: 'UNKNOWN', leaseInMs: -1_000, paymentHash: 'ab'.repeat(32) });
  const { openDatabase } = await loadSrc<RecoveryPersistence>('persistence/index.ts');
  const db = openDatabase(path, { readOnly: false });
  try {
    const first = db.executions.takeUnresolved(seeded.executionId, 3n, 'recovery-first', 60_000);
    expect(first).toMatchObject({ executionId: seeded.executionId, fenceEpoch: 4n });
    const inspection = raw(path);
    try {
      const before = inspection.prepare('SELECT worker_id, fence_epoch, lease_expires_at FROM executions WHERE id = ?').get(seeded.executionId);
      expect(db.executions.takeUnresolved(seeded.executionId, 4n, 'recovery-second', 60_000)).toBeNull();
      expect(inspection.prepare('SELECT worker_id, fence_epoch, lease_expires_at FROM executions WHERE id = ?').get(seeded.executionId)).toEqual(before);
    } finally { inspection.close(); }
  } finally { db.close(); }
});
