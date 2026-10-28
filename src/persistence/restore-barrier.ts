import type { DatabaseSync } from 'node:sqlite';
import { PersistenceError } from './errors.js';
import { bigintColumn, immediate, textColumn } from './sql.js';
import { assertNodeIdentity } from './node-identity.js';
import { assertRecoveryResolved } from './recovery-state.js';

export function assertStateAdmitted(db: DatabaseSync): void {
  // MySQL: same.
  if (db.prepare('SELECT 1 FROM restore_barrier WHERE id = 1 AND pending = 1').get() !== undefined) {
    throw new PersistenceError('RESTORE_PENDING', 'restore: full successful reconciliation of every restored node is required before approval or execution');
  }
}

export function installRestoreBarrier(db: DatabaseSync): void {
  immediate(db, () => {
    // MySQL: ON DUPLICATE KEY UPDATE fence_epoch = fence_epoch + 1, pending = 1.
    db.prepare(`INSERT INTO restore_barrier VALUES (1,1,1) ON CONFLICT(id)
      DO UPDATE SET fence_epoch = fence_epoch + 1, pending = 1`).run();
    // No configuration acknowledgement can remove a required historical node.
    // MySQL: INSERT IGNORE ... SELECT.
    db.prepare(`INSERT INTO restore_required_nodes SELECT id, implementation, expected_pubkey FROM nodes
      WHERE 1 ON CONFLICT(node_id) DO NOTHING`).run();
  });
}

export function completeRestore(db: DatabaseSync, nodeIds: readonly string[]): void {
  immediate(db, () => {
    // MySQL: same, SELECT ... FOR UPDATE.
    const gate = db.prepare('SELECT fence_epoch FROM restore_barrier WHERE id = 1 AND pending = 1').get();
    if (gate === undefined) return;
    const required = db.prepare(`SELECT r.node_id FROM restore_required_nodes r JOIN nodes n ON n.id = r.node_id
      WHERE n.implementation = r.implementation AND n.expected_pubkey = r.pubkey AND n.state = 'ONLINE'`).all();
    // MySQL: same.
    const total = db.prepare('SELECT count(*) AS n FROM restore_required_nodes').get();
    if (total === undefined || BigInt(required.length) !== bigintColumn(total, 'n')) return;
    for (const row of required) {
      const id = textColumn(row, 'node_id');
      if (!nodeIds.includes(id)) return;
      assertNodeIdentity(db, id);
    }
    assertRecoveryResolved(db);
    // The full successful pass is the authority; a selected-node pass never calls this operation.
    // MySQL: same. A competing admission completion cannot replace the expected barrier epoch.
    const changed = db.prepare('UPDATE restore_barrier SET pending = 0, fence_epoch = fence_epoch + 1 WHERE id = 1 AND fence_epoch = ?')
      .run(bigintColumn(gate, 'fence_epoch'));
    if (changed.changes === 0n || changed.changes === 0) throw new PersistenceError('LEASE_LOST', 'restore: admission barrier changed during reconciliation');
  });
}
