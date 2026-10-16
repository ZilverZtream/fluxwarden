import type { DatabaseSync } from 'node:sqlite';
import type { RoutingLayerClaim, RoutingLayerOwnership } from '../core/execution.js';
import { PersistenceError } from './errors.js';
import { bigintColumn, checkedCount, DB_NOW, newUlid, textColumn } from './sql.js';

export type { RoutingLayerClaim } from '../core/execution.js';

export interface PendingRoutingLayer extends RoutingLayerClaim {
  readonly nodeId: string;
  readonly layer: string;
}

export interface RoutingLayersRepository extends RoutingLayerOwnership {
  /** At most 100 terminal-owned pending resources per pass, selected by the last cleanup attempt. */
  pending(nodeIds?: readonly string[]): readonly PendingRoutingLayer[];
  take(row: PendingRoutingLayer, workerId: string, leaseMs: number): bigint | null;
  complete(id: string, fenceEpoch: bigint): void;
  retryLater(id: string, fenceEpoch: bigint): void;
}

const TERMINAL = "('VERIFIED_SUCCESS','VERIFIED_FAILURE','CANCELLED')";
const TERMINAL_OWNER = `EXISTS (SELECT 1 FROM executions e WHERE e.id = routing_layers.execution_id AND e.status IN ${TERMINAL})`;

function changed(changes: number | bigint): void {
  if (changes !== 1 && changes !== 1n) throw new PersistenceError('LEASE_LOST', 'routing layer ownership changed');
}

export function routingLayersRepository(db: DatabaseSync, writable: (what: string) => void, run: <T>(work: () => T) => T): RoutingLayersRepository {
  return {
    prepareAcquisition(executionId, fenceEpoch, nodePubkey, layer) {
      writable('routing layer ownership');
      if (layer.length === 0 || layer.length > 128) throw new PersistenceError('OUT_OF_RANGE', 'invalid routing layer identity');
      const nodeId = run(() => {
        // MySQL: same SELECT and NOW(6). No resource is owned until the native create succeeds.
        const owner = db.prepare(`SELECT n.id FROM executions e
          JOIN liquidity_proposals p ON p.id = e.proposal_id JOIN nodes n ON n.id = p.node_id
          WHERE e.id = ? AND e.fence_epoch = ? AND e.status = 'PREFLIGHT' AND e.lease_expires_at > ${DB_NOW}
            AND n.implementation = 'cln' AND n.expected_pubkey = ?`)
          .get(executionId, fenceEpoch, nodePubkey);
        if (owner === undefined) throw new PersistenceError('LEASE_LOST', 'routing layer acquisition has no current execution ownership');
        return textColumn(owner, 'id');
      });
      let recorded: RoutingLayerClaim | undefined;
      return () => {
        writable('routing layer ownership');
        if (recorded !== undefined) return recorded;
        recorded = run(() => {
          const id = newUlid();
          // MySQL: same INSERT and NOW(6). This exact receipt cannot renew or mutate execution authority.
          // A delayed successful reply remains a fact after its initiating lease expires or is reclaimed.
          const result = db.prepare(`INSERT INTO routing_layers
            (id, node_id, layer, execution_id, acquired_fence_epoch, fence_epoch, state, acquired_at)
            VALUES (?, ?, ?, ?, ?, 1, 'PENDING', ${DB_NOW})`)
            .run(id, nodeId, layer, executionId, fenceEpoch);
          changed(result.changes);
          return { id, fenceEpoch: 1n };
        });
        return recorded;
      };
    },

    removedImmediately(claim, executionId, fenceEpoch) {
      writable('routing layer cleanup');
      run(() => {
        // MySQL: same, with NOW(6); both the resource and its assessment authority are fenced.
        const result = db.prepare(`UPDATE routing_layers SET state = 'CLEANED', fence_epoch = fence_epoch + 1, completed_at = ${DB_NOW}
          WHERE id = ? AND fence_epoch = ? AND execution_id = ? AND acquired_fence_epoch = ? AND state = 'PENDING'
            AND EXISTS (SELECT 1 FROM executions e WHERE e.id = ? AND e.fence_epoch = ?
              AND e.status = 'PREFLIGHT' AND e.lease_expires_at > ${DB_NOW})`)
          .run(claim.id, claim.fenceEpoch, executionId, fenceEpoch, executionId, fenceEpoch);
        changed(result.changes);
      });
    },

    pending: nodeIds => run(() => {
      if (nodeIds?.length === 0) return [];
      // MySQL: same; a failed resource moves behind older unattempted work rather than monopolising the bound.
      const rows = db.prepare(`SELECT r.id, r.node_id, r.layer, r.fence_epoch FROM routing_layers r
        JOIN executions e ON e.id = r.execution_id
        WHERE r.state = 'PENDING' AND e.status IN ${TERMINAL}
          AND (r.lease_expires_at IS NULL OR r.lease_expires_at <= ${DB_NOW})
          ${nodeIds === undefined ? '' : `AND r.node_id IN (${nodeIds.map(() => '?').join(',')})`}
        ORDER BY coalesce(r.last_attempt_at, r.acquired_at), r.id LIMIT 100`).all(...(nodeIds ?? []));
      return rows.map(row => ({ id: textColumn(row, 'id'), nodeId: textColumn(row, 'node_id'),
        layer: textColumn(row, 'layer'), fenceEpoch: bigintColumn(row, 'fence_epoch') }));
    }),

    take(row, workerId, leaseMs) {
      writable('routing layer cleanup lease');
      if (checkedCount(leaseMs, 'routing layer lease') === 0) throw new PersistenceError('OUT_OF_RANGE', 'invalid routing layer lease');
      return run(() => {
        // MySQL: same CAS and NOW(6). Terminal execution states are absorbing.
        const result = db.prepare(`UPDATE routing_layers SET fence_epoch = fence_epoch + 1, worker_id = ?,
          lease_expires_at = ${DB_NOW} + ?, last_attempt_at = ${DB_NOW}
          WHERE id = ? AND fence_epoch = ? AND state = 'PENDING'
            AND (lease_expires_at IS NULL OR lease_expires_at <= ${DB_NOW}) AND ${TERMINAL_OWNER}`)
          .run(workerId, leaseMs, row.id, row.fenceEpoch);
        return result.changes === 1 || result.changes === 1n ? row.fenceEpoch + 1n : null;
      });
    },

    complete(id, fenceEpoch) {
      writable('routing layer cleanup');
      run(() => {
        // MySQL: same CAS and NOW(6); stale cleanup workers cannot acknowledge another worker's resource.
        const result = db.prepare(`UPDATE routing_layers SET state = 'CLEANED', fence_epoch = fence_epoch + 1,
          completed_at = ${DB_NOW}, lease_expires_at = NULL, worker_id = NULL
          WHERE id = ? AND fence_epoch = ? AND state = 'PENDING' AND lease_expires_at > ${DB_NOW} AND ${TERMINAL_OWNER}`)
          .run(id, fenceEpoch);
        changed(result.changes);
      });
    },

    retryLater(id, fenceEpoch) {
      writable('routing layer cleanup');
      run(() => {
        // MySQL: same CAS and NOW(6); failure releases only this cleanup lease and preserves ownership.
        const result = db.prepare(`UPDATE routing_layers SET fence_epoch = fence_epoch + 1, lease_expires_at = NULL, worker_id = NULL
          WHERE id = ? AND fence_epoch = ? AND state = 'PENDING' AND lease_expires_at > ${DB_NOW} AND ${TERMINAL_OWNER}`)
          .run(id, fenceEpoch);
        changed(result.changes);
      });
    },
  };
}
