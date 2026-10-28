import type { DatabaseSync } from 'node:sqlite';
import { PersistenceError } from './errors.js';

/** Called inside the admission transaction: a live lease is ownership, never conclusive recovery evidence. */
export function assertRecoveryResolved(db: DatabaseSync, nodeId?: string): void {
  // MySQL: same, with SELECT ... FOR UPDATE inside the admission transaction.
  const pending = db.prepare(`SELECT 1 FROM executions e JOIN liquidity_proposals p ON p.id = e.proposal_id
    WHERE e.status IN ('CLAIMED','PREFLIGHT','SUBMITTING','IN_FLIGHT','UNKNOWN')
      ${nodeId === undefined ? '' : 'AND p.node_id = ?'} LIMIT 1`).get(...(nodeId === undefined ? [] : [nodeId]));
  if (pending !== undefined) {
    throw new PersistenceError(nodeId === undefined ? 'RESTORE_PENDING' : 'RECOVERY_PENDING',
      'recovery: unresolved executions must reach a conclusive outcome before admission');
  }
}
