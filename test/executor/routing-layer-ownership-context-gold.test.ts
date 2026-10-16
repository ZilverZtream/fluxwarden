/*
 * ARCHITECTURE 8.2 and SECURITY INV-13/18: normal execution preflight conveys
 * its existing execution and current fence to the execution-owned assessment.
 * Public assessment extension: findCircularRoute(request, ownership?: {
 *   db: ExecDatabase; executionId: string; fenceEpoch: bigint
 * }). Standalone assessment remains permitted without execution ownership.
 */
import { expect, it } from 'vitest';
import { circularRoute, fakeChannel, FakePreflightNode } from '../fakes/preflight-node.js';
import {
  APPROVAL_KEYS, dbNow, execById, IN_PEER, loadPersistence, loadPreflight, OUT_PEER, policyFor,
  scratchDb, seedBase, seedProposal, type ExecDatabase, type ExecRow, type PreflightAdapter, type RouteRequest,
} from '../helpers/cp028-executor.js';
import { exec, reservationState, rowOf } from '../helpers/cp030-execution.js';

interface Ownership { db: ExecDatabase; executionId: string; fenceEpoch: bigint }
interface Observation { ownership: Ownership | undefined; row: ExecRow | undefined; dbNow: number }

for (const routeAnswer of ['ready', 'refused'] as const) {
  it(`CP-029/REG-REC008 normal ${routeAnswer} preflight supplies live execution ownership before route assessment`, async () => {
    const p = await loadPersistence(), path = scratchDb(`owned-preflight-${routeAnswer}`);
    const seeded = seedBase(p, path), sourceKey = '102x1x0', targetKey = '105x1x0';
    exec(path, "UPDATE nodes SET name='cln-m', implementation='cln' WHERE id=?", seeded.nodeId);
    exec(path, 'UPDATE channels SET channel_key=?, scid=? WHERE id=?', sourceKey, sourceKey, seeded.sourceChannelId);
    exec(path, 'UPDATE channels SET channel_key=?, scid=? WHERE id=?', targetKey, targetKey, seeded.targetChannelId);
    const base = { ...seeded, sourceKey, targetKey }, approval = seedProposal(base), policy = policyFor(base);
    const route = circularRoute(sourceKey, targetKey, 150_000n, 80);
    const node = new FakePreflightNode(sourceKey, targetKey, { version: 'v26.06.9',
      channels: () => [fakeChannel(sourceKey, OUT_PEER, { nodeId: base.nodeId, scid: sourceKey }),
        fakeChannel(targetKey, IN_PEER, { nodeId: base.nodeId, scid: targetKey })],
      route: () => routeAnswer === 'refused' ? { refusal: 'NO_FEASIBLE_ROUTE' }
        : { ...route, hops: route.hops.map((hop, index) => index === 1 ? { ...hop, channelKey: '103x1x0' } : hop) },
    });
    const observed: Observation[] = [];
    const adapter: PreflightAdapter = {
      handshake: () => node.handshake(), capabilities: () => node.capabilities(), listChannels: () => node.listChannels(),
      findCircularRoute: (request: RouteRequest, ownership?: Ownership) => {
        observed.push({ ownership, row: ownership === undefined ? undefined : execById(path, ownership.executionId), dbNow: dbNow(path) });
        return node.findCircularRoute(request);
      },
      createInvoice: () => node.createInvoice(), sendOnRoute: () => node.sendOnRoute(), cancelUnpaidInvoice: () => node.cancelUnpaidInvoice(),
    };
    const db = p.openDatabase(path, { readOnly: false });
    try {
      const { prepareExecution } = await loadPreflight();
      const result = await prepareExecution({ db, adapter, workerId: 'owned-preflight', leaseMs: 60_000 },
        { approval, policy, approvalKeyIds: APPROVAL_KEYS });
      // Normal route handling is independently valid even before the ownership extension exists.
      expect(result).toMatchObject(routeAnswer === 'ready' ? { kind: 'READY' }
        : { kind: 'CANCELLED', exit: 5, step: 'NO_FEASIBLE_ROUTE' });
      expect(node.routeRequests).toEqual([{ sourceChannelKey: sourceKey, targetChannelKey: targetKey,
        principalMsat: 100_000_000n, maxFeeMsat: 200_000n, maxFeePpm: 2_500n, exemptFeeMsat: 5_000n, maxCltvDelta: 100 }]);
      expect(node.mutatingCalls()).toEqual([]);
      expect(observed).toHaveLength(1);
      const call = observed[0];
      expect(call?.ownership, 'ordinary execution assessment receives its fenced ownership context').toBeDefined();
      if (call?.ownership === undefined || call.row === undefined) return;
      expect(call.ownership.db).toBe(db);
      expect(call.ownership.executionId).toBe(result.executionId);
      expect(call.ownership.fenceEpoch).toBe(call.row.fence_epoch);
      expect(call.row).toMatchObject({ status: 'PREFLIGHT', worker_id: 'owned-preflight', payment_hash: null });
      expect(Number(call.row.lease_expires_at) - call.dbNow).toBeGreaterThan(0);
      expect(rowOf(path, call.ownership.executionId).status).toBe(routeAnswer === 'ready' ? 'PREFLIGHT' : 'CANCELLED');
      expect(reservationState(path, call.ownership.executionId)).toEqual({ state: routeAnswer === 'ready' ? 'HELD' : 'RELEASED', consumed: null });
    } finally { db.close(); }
  });
}
