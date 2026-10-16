import type { ExecutionAdapter } from '../core/execution.js';
import { PersistenceError, type Database } from '../persistence/index.js';

const COMPLETE: ReadonlySet<string> = new Set(['REMOVED', 'NOT_FOUND']);

/** One bounded pass over durable terminal-owned resources; payment state is never changed here. */
export async function cleanupRoutingLayers(deps: {
  readonly db: Database;
  readonly adapters: ReadonlyMap<string, ExecutionAdapter>;
  readonly workerId: string;
  readonly leaseMs: number;
  readonly nodeIds?: ReadonlySet<string>;
}): Promise<void> {
  const store = deps.db.routingLayers;
  const rows = store.pending(deps.nodeIds === undefined ? undefined : [...deps.nodeIds]);
  for (const row of rows) {
    const adapter = deps.adapters.get(row.nodeId);
    if (adapter?.removeRoutingLayer === undefined) continue;
    const epoch = store.take(row, deps.workerId, deps.leaseMs);
    if (epoch === null) continue;
    let removed = false;
    try {
      const result = await adapter.removeRoutingLayer(row.layer);
      removed = COMPLETE.has(result);
    } catch {
      // A missing acknowledgement cannot complete ownership; a later pass can prove native absence.
    }
    try {
      if (removed) store.complete(row.id, epoch);
      else store.retryLater(row.id, epoch);
    } catch (error) {
      if (!(error instanceof PersistenceError && error.code === 'LEASE_LOST')) throw error;
    }
  }
}
