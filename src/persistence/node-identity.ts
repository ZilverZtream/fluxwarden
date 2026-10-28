import type { DatabaseSync } from 'node:sqlite';
import { PersistenceError } from './errors.js';

/** A legacy mutable node row is evidence of its current configuration, never proof of its original identity. */
export function assertNodeIdentity(db: DatabaseSync, nodeId: string): void {
  // MySQL: same. A binding exists only for nodes first inserted after the provenance migration.
  const bound = db.prepare(`SELECT 1 AS bound FROM nodes n JOIN node_identity_bindings b ON b.node_id = n.id
    AND b.implementation = n.implementation AND b.pubkey = n.expected_pubkey WHERE n.id = ?`).get(nodeId);
  if (bound === undefined) {
    throw new PersistenceError('NODE_IDENTITY_UNVERIFIED', 'identity: the original node binding is unverified; preserve history and reservations pending recovery from trusted evidence');
  }
}

export function assertExecutionIdentity(db: DatabaseSync, executionId: string): void {
  // MySQL: same.
  const row = db.prepare(`SELECT p.node_id FROM executions e JOIN liquidity_proposals p ON p.id = e.proposal_id
    WHERE e.id = ?`).get(executionId);
  if (row !== undefined && typeof row['node_id'] === 'string') assertNodeIdentity(db, row['node_id']);
}
