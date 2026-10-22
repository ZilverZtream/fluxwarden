/*
 * ARCHITECTURE 8.2 layer cleanup and SECURITY INV-13/18.
 * Minimal public extensions to the existing assessment and recovery ports:
 *   ClnExecutionAdapter.findCircularRoute(request, ownership?: {
 *     db: ExecDatabase; executionId: string; fenceEpoch: bigint
 *   }): Promise<CircularRoute | { refusal: string }>
 *   ExecutionAdapter.removeRoutingLayer?(layer: string): Promise<'REMOVED' | 'NOT_FOUND'>
 * Ownership follows an exact successful acquisition under the current execution fence.
 * Normal reconcile recovers pending terminal-owned cleanup across new DB/adapters.
 * Neither a layer name nor a refused create conveys ownership. No storage shape is prescribed.
 * Native answers follow the existing v26.06.9 askrene fake and getroutes response fixtures.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { channelDirection, getinfo, getroutesAnswer, pathHop, peerChannel } from '../fakes/cln/responses.js';
import { loadErrors, loadSource, type ClnRest } from '../helpers/adapter-interfaces.js';
import {
  APPROVAL_KEYS, claimed, dbNow, execById, IN_PEER, loadClaim, loadPersistence, NODE_PUBKEY, OUT_PEER, policyFor,
  scratchDb, seedBase, seedProposal, sleep, type CircularRoute, type ExecDatabase, type RouteRequest,
} from '../helpers/cp028-executor.js';
import {
  exec, loadReconciler, reservationState, rowOf, type ClnExecutionAdapter, type ExecutionAdapter,
} from '../helpers/cp030-execution.js';

const S = '102x1x0', M = '103x1x0', T = '105x1x0';
const UNRELATED = ['operator-routing', 'fluxwarden-preexisting-opaque'];
const REQUEST: RouteRequest = { sourceChannelKey: S, targetChannelKey: T, principalMsat: 100_000_000n,
  maxFeeMsat: 300_000n, maxFeePpm: 2_500n, exemptFeeMsat: 5_000n, maxCltvDelta: 100 };
interface Ownership { db: ExecDatabase; executionId: string; fenceEpoch: bigint }
interface OwnedAdapter extends ClnExecutionAdapter {
  findCircularRoute(request: RouteRequest, ownership?: Ownership): Promise<CircularRoute | { readonly refusal: string }>;
  removeRoutingLayer(layer: string): Promise<'REMOVED' | 'NOT_FOUND'>;
}
interface OwnedModule { ClnExecutionAdapter: new (rest: ClnRest,
  options: { ownId: string; waitChunkSeconds: number; attemptDeadlineMs: number }) => OwnedAdapter }
type Removal = 'ok' | 'reject' | 'absent-then-reject';
type Layer = { disabledNodes: string[]; channelUpdates: Record<string, unknown>[] };

async function nativeLayers() {
  const errors = await loadErrors();
  const layers = new Map<string, Layer>(UNRELATED.map(name => [name, { disabledNodes: [], channelUpdates: [] }]));
  const acquired: string[] = [], collisions: string[] = [];
  const calls: { method: string; params: Record<string, unknown> }[] = [];
  const model = { removal: 'ok' as Removal, collision: false, emptyRoute: false,
    afterAcquire: undefined as (() => Promise<void>) | undefined };
  const rpcError = (message: string) => Object.assign(new errors.ClnError(message), { code: -32602, httpStatus: 500 });
  const layerJson = (name: string, layer: Layer) => ({ layer: name, persistent: false,
    disabled_nodes: layer.disabledNodes, disabled_channels: [], created_channels: [], channel_updates: layer.channelUpdates,
    constraints: [], biases: [], node_biases: [] });
  const rest: ClnRest = { call: (method, params = {}) => {
    calls.push({ method, params });
    const name = String(params['layer']);
    switch (method) {
      case 'getinfo': return Promise.resolve(getinfo({ id: NODE_PUBKEY }));
      case 'listpeerchannels': return Promise.resolve({ channels: [
        peerChannel({ peer_id: OUT_PEER, short_channel_id: S, opener: 'local', spendable_msat: 400_000_000, receivable_msat: 400_000_000 }),
        peerChannel({ peer_id: IN_PEER, short_channel_id: T, channel_id: '79'.repeat(32), funding_txid: '9b'.repeat(32),
          spendable_msat: 400_000_000, receivable_msat: 400_000_000,
          updates: {
            local: { htlc_minimum_msat: 0, htlc_maximum_msat: 4_950_000_000, cltv_expiry_delta: 6, fee_base_msat: 1, fee_proportional_millionths: 10 },
            remote: { htlc_minimum_msat: 1, htlc_maximum_msat: 4_950_000_000, cltv_expiry_delta: 34, fee_base_msat: 1_000, fee_proportional_millionths: 1_000 },
          } }),
      ] });
      case 'askrene-create-layer': {
        if (model.collision || layers.has(name)) {
          if (!layers.has(name)) layers.set(name, { disabledNodes: [], channelUpdates: [] });
          collisions.push(name);
          return Promise.reject(rpcError('Layer already exists'));
        }
        const layer = { disabledNodes: [], channelUpdates: [] };
        layers.set(name, layer); acquired.push(name);
        if (model.afterAcquire !== undefined) return model.afterAcquire().then(() => ({ layers: [layerJson(name, layer)] }));
        return Promise.resolve({ layers: [layerJson(name, layer)] });
      }
      case 'askrene-disable-node': {
        const layer = layers.get(name);
        if (layer === undefined) return Promise.reject(rpcError('layer: Unknown layer'));
        layer.disabledNodes.push(String(params['node']));
        return Promise.resolve({});
      }
      case 'askrene-update-channel': {
        const layer = layers.get(name);
        if (layer === undefined) return Promise.reject(rpcError('layer: Unknown layer'));
        layer.channelUpdates.push({ ...params });
        return Promise.resolve({});
      }
      case 'askrene-listlayers': return Promise.resolve({ layers: [...layers].map(([key, layer]) => layerJson(key, layer)) });
      case 'askrene-remove-layer': {
        if (!layers.has(name)) return Promise.reject(rpcError('layer: Unknown layer'));
        if (model.removal === 'reject') return Promise.reject(new errors.TransportError('ordinary cleanup response unavailable', 'response'));
        layers.delete(name);
        if (model.removal === 'absent-then-reject') return Promise.reject(new errors.TransportError('ordinary cleanup acknowledgement unavailable', 'response'));
        return Promise.resolve({});
      }
      case 'getroutes': return Promise.resolve(getroutesAnswer(model.emptyRoute ? [] : [{ amount: 100_101_000, finalCltv: 52,
        path: [pathHop({ scidDir: `${M}/0`, nodeIn: OUT_PEER, nodeOut: IN_PEER,
          amountIn: 100_202_101, amountOut: 100_101_000, cltvIn: 86, cltvOut: 52 })] }]));
      case 'listchannels': return Promise.resolve({ channels: [
        channelDirection({ scid: M, source: OUT_PEER, destination: IN_PEER, base: 1_000, ppm: 1_000, delay: 34 }),
        channelDirection({ scid: M, source: IN_PEER, destination: OUT_PEER, base: 7, ppm: 7, delay: 9 }),
      ] });
      default: return Promise.reject(new Error(`unexpected ordinary native call: ${method}`));
    }
  } };
  const module = await loadSource<OwnedModule>('node-cln/execute.ts');
  const adapter = () => new module.ClnExecutionAdapter(rest, { ownId: NODE_PUBKEY, waitChunkSeconds: 1, attemptDeadlineMs: 1_000 });
  const removals = () => calls.filter(call => call.method === 'askrene-remove-layer').map(call => String(call.params['layer']));
  const noMoney = () => { expect(calls.filter(call => /^(?:invoice|sendpay|xpay|pay)$/.test(call.method))).toEqual([]); };
  const unrelatedRemain = () => { for (const layer of UNRELATED) expect(layers.has(layer)).toBe(true); };
  return { layers, acquired, collisions, calls, model, adapter, removals, noMoney, unrelatedRemain };
}

async function fixture() {
  const p = await loadPersistence(), path = scratchDb('routing-layer-lifecycle');
  const seeded = seedBase(p, path);
  exec(path, "UPDATE nodes SET implementation='cln', name='cln-m' WHERE id=?", seeded.nodeId);
  exec(path, 'UPDATE channels SET channel_key=?, scid=? WHERE id=?', S, S, seeded.sourceChannelId);
  exec(path, 'UPDATE channels SET channel_key=?, scid=? WHERE id=?', T, T, seeded.targetChannelId);
  const base = { ...seeded, sourceKey: S, targetKey: T };
  const approval = seedProposal(base, { approvedMaxFeeMsat: 300_000n });
  const db = p.openDatabase(path, { readOnly: false });
  const claim = await loadClaim();
  let executionId: string;
  try {
    const owned = claimed(claim.claimExecution(db, { approval, policy: policyFor(base), approvalKeyIds: APPROVAL_KEYS,
      workerId: 'assessor', leaseMs: 600_000 }));
    executionId = owned.executionId;
    db.executions.transition(executionId, owned.fenceEpoch, 'CLAIMED', 'PREFLIGHT', { leaseMs: 600_000 });
  } finally { db.close(); }
  const native = await nativeLayers();
  const assess = async (owned = true, leaseMs?: number) => {
    const assessmentDb = p.openDatabase(path, { readOnly: false });
    try {
      let fenceEpoch = rowOf(path, executionId).fence_epoch;
      if (leaseMs !== undefined) fenceEpoch = assessmentDb.executions.renewLease(executionId, fenceEpoch, leaseMs);
      const context = { db: assessmentDb, executionId, fenceEpoch };
      return await native.adapter().findCircularRoute(REQUEST, owned ? context : undefined);
    } finally { assessmentDb.close(); }
  };
  const cancel = () => {
    const terminalDb = p.openDatabase(path, { readOnly: false });
    try { terminalDb.executions.transition(executionId, rowOf(path, executionId).fence_epoch, 'PREFLIGHT', 'CANCELLED'); }
    finally { terminalDb.close(); }
  };
  const reclaimAndCancel = () => {
    const freshDb = p.openDatabase(path, { readOnly: false });
    try {
      const current = claimed(claim.claimExecution(freshDb, { approval, policy: policyFor(base), approvalKeyIds: APPROVAL_KEYS,
        workerId: 'terminal-controller', leaseMs: 60_000 }));
      expect(current.executionId).toBe(executionId);
      freshDb.executions.transition(executionId, current.fenceEpoch, 'PREFLIGHT', 'CANCELLED');
    } finally { freshDb.close(); }
  };
  const recover = async (startup = false) => {
    const freshDb = p.openDatabase(path, { readOnly: false }), fresh = native.adapter();
    const adapter: ExecutionAdapter & Pick<OwnedAdapter, 'removeRoutingLayer'> = {
      listChannels: () => Promise.resolve([]),
      createInvoice: (...args) => fresh.createInvoice(...args), sendOnRoute: (...args) => fresh.sendOnRoute(...args),
      observePayment: (...args) => fresh.observePayment(...args), invoiceState: (...args) => fresh.invoiceState(...args),
      cancelUnpaidInvoice: (...args) => fresh.cancelUnpaidInvoice(...args), removeRoutingLayer: layer => fresh.removeRoutingLayer(layer),
    };
    const { reconcile } = await loadReconciler();
    try { return await reconcile({ db: freshDb, adapters: new Map([[base.nodeId, adapter]]), workerId: 'recovery',
      leaseMs: 60_000, notFoundWindowMs: 120_000, escalateAfterMs: 3_600_000, confirmIntervalMs: 60_000,
      alert: () => undefined }, { startup }); }
    finally { freshDb.close(); }
  };
  const truth = (status: 'PREFLIGHT' | 'CANCELLED') => {
    expect(rowOf(path, executionId)).toMatchObject({ status, payment_hash: null, submitted_at: null, actual_fee_msat: null });
    expect(reservationState(path, executionId)).toEqual({ state: status === 'PREFLIGHT' ? 'HELD' : 'RELEASED', consumed: null });
    native.noMoney(); native.unrelatedRemain();
  };
  // Cleanup errors may fail assessment; actual successful native acquisition is the ownership evidence.
  const leavePending = async (owned = true) => {
    native.model.removal = 'reject';
    await assess(owned).catch(() => undefined);
    expect(native.acquired).toHaveLength(1);
    const layer = native.acquired[0];
    if (layer === undefined) throw new Error('ordinary assessment acquired no layer');
    expect(native.layers.has(layer)).toBe(true);
    expect(native.removals()).toEqual([layer]);
    truth('PREFLIGHT');
    return layer;
  };
  return { path, executionId, native, assess, cancel, reclaimAndCancel, recover, truth, leavePending };
}

it('CP-032/REG-REC008 successful immediate cleanup leaves no duplicate terminal recovery', async () => {
  const f = await fixture(), route = await f.assess();
  // SPEC 4.4 backwards fees: 1000 + ceil(P*1000/1e6) twice; CLN deltas 34+34+18.
  expect(route).toMatchObject({ totalFeeMsat: 202_101n, totalTimelockDelta: 86, principalMsat: 100_000_000n });
  expect(f.native.acquired).toHaveLength(1);
  expect(f.native.removals()).toEqual(f.native.acquired);
  expect([...f.native.layers.keys()].sort()).toEqual([...UNRELATED].sort());
  f.cancel(); await f.recover(); await f.recover(true);
  expect(f.native.removals()).toEqual(f.native.acquired);
  f.truth('CANCELLED');
});

it('CP-032/REG-REC008 failed immediate cleanup survives fresh database and adapter recovery exactly once', async () => {
  const f = await fixture(), layer = await f.leavePending();
  f.cancel(); f.native.model.removal = 'ok';
  await f.recover();
  expect(f.native.layers.has(layer)).toBe(false);
  expect(f.native.removals()).toEqual([layer, layer]);
  await f.recover(true);
  expect(f.native.removals()).toEqual([layer, layer]);
  f.truth('CANCELLED');
});

it('CP-032/REG-REC008 failed recovery remains pending for a bounded later startup retry', async () => {
  const f = await fixture(), layer = await f.leavePending();
  f.cancel(); await f.recover();
  expect(f.native.layers.has(layer)).toBe(true);
  expect(f.native.removals()).toEqual([layer, layer]);
  f.native.model.removal = 'ok'; await f.recover(true);
  expect(f.native.layers.has(layer)).toBe(false);
  expect(f.native.removals()).toEqual([layer, layer, layer]);
  await f.recover(); expect(f.native.removals()).toEqual([layer, layer, layer]);
  f.truth('CANCELLED');
}, 60_000);

it('CP-032/REG-REC008 ambiguous removal retains pending cleanup until conclusive native absence', async () => {
  const f = await fixture(), layer = await f.leavePending();
  f.cancel(); f.native.model.removal = 'absent-then-reject'; await f.recover();
  expect(f.native.layers.has(layer)).toBe(false);
  expect(f.native.removals()).toEqual([layer, layer]);
  f.native.model.removal = 'ok'; await f.recover(true);
  const afterAbsence = f.native.removals();
  expect(afterAbsence.every(name => name === layer)).toBe(true);
  expect(afterAbsence.length).toBeLessThanOrEqual(3);
  await f.recover(); expect(f.native.removals()).toEqual(afterAbsence);
  f.truth('CANCELLED');
});

it('CP-032/REG-REC008 recovery preserves a proven layer while its execution remains active', async () => {
  const f = await fixture(), layer = await f.leavePending();
  f.native.model.removal = 'ok'; await f.recover(); await f.recover(true);
  expect(f.native.layers.has(layer)).toBe(true);
  expect(f.native.removals()).toEqual([layer]);
  f.truth('PREFLIGHT');
});

describe('refused routing layer creation fixture', () => {
  let f: Awaited<ReturnType<typeof fixture>>;
  let preparedAt: number, prepMs: number;
  beforeAll(async () => {
    preparedAt = performance.now();
    f = await fixture(); f.native.model.collision = true;
    await loadReconciler();
    prepMs = performance.now() - preparedAt;
  }, 30_000);
  it('CP-032/REG-REC008 refused create confers no ownership of a preexisting colliding layer', async () => {
    const started = performance.now();
    try {
      await f.assess().catch(() => undefined);
      expect(f.native.acquired).toEqual([]);
      expect(f.native.collisions).toHaveLength(1);
      for (const layer of f.native.collisions) expect(f.native.layers.has(layer)).toBe(true);
      expect(f.native.removals()).toEqual([]);
      f.cancel(); await f.recover(); await f.recover(true);
      for (const layer of f.native.collisions) expect(f.native.layers.has(layer)).toBe(true);
      expect(f.native.removals()).toEqual([]);
      f.truth('CANCELLED');
    } finally {
      console.log(JSON.stringify({ case: 'refused-layer-create', prepMs, caseMs: performance.now() - started, totalMs: performance.now() - preparedAt }));
    }
  });
});

it('CP-032/REG-REC008 standalone assessment does not grant unrelated execution cleanup authority', async () => {
  const f = await fixture(), layer = await f.leavePending(false);
  f.cancel(); f.native.model.removal = 'ok'; await f.recover(); await f.recover(true);
  expect(f.native.layers.has(layer)).toBe(true);
  expect(f.native.removals()).toEqual([layer]);
  f.truth('CANCELLED');
});

it('CP-032/REG-SRC007 successful create reply after lease expiry retains exact cleanup ownership', async () => {
  const PUBLIC_TEST_LEASE_MS = 10_000;
  const f = await fixture();
  const observed: { phase: 'begin' | 'reply'; expiry: number; at: number; status: string; fence: bigint }[] = [];
  f.native.model.removal = 'reject';
  f.native.model.afterAcquire = async () => {
    const begin = execById(f.path, f.executionId), expiry = Number(begin.lease_expires_at);
    observed.push({ phase: 'begin', expiry, at: dbNow(f.path), status: begin.status, fence: begin.fence_epoch });
    // Ordinary delayed native reply; the original public lease expires on the
    // real database clock. No execution deadline or ownership row is rewritten.
    const deadline = performance.now() + PUBLIC_TEST_LEASE_MS + 2_000;
    while (dbNow(f.path) <= expiry) {
      if (performance.now() >= deadline) throw new Error('SETUP_ERROR: database lease did not expire during the bounded native reply');
      await sleep(20);
    }
    const reply = execById(f.path, f.executionId);
    observed.push({ phase: 'reply', expiry: Number(reply.lease_expires_at), at: dbNow(f.path), status: reply.status, fence: reply.fence_epoch });
  };
  await f.assess(true, PUBLIC_TEST_LEASE_MS).catch(() => undefined);
  expect(observed.map(row => row.phase), 'both native await boundaries were reached').toEqual(['begin', 'reply']);
  const begin = observed[0], reply = observed[1];
  if (begin === undefined || reply === undefined) throw new Error('SETUP_ERROR: native create boundaries unavailable');
  expect(begin.status).toBe('PREFLIGHT');
  expect(begin.expiry, 'native create was initiated with a live database lease').toBeGreaterThan(begin.at);
  expect(reply.expiry).toBe(begin.expiry);
  expect(reply.expiry, 'successful create reply arrives after that same lease expired').toBeLessThan(reply.at);
  expect(reply.fence).toBe(begin.fence);
  expect(f.native.acquired).toHaveLength(1);
  const layer = f.native.acquired[0];
  if (layer === undefined) throw new Error('SETUP_ERROR: native create did not acquire its requested layer');
  expect(f.native.layers.has(layer)).toBe(true);
  expect(f.native.removals()).toEqual([layer]);
  expect(f.native.calls.filter(call => ['askrene-disable-node', 'askrene-update-channel'].includes(call.method)),
    'expired authority permits cleanup of the acquired resource without further route mutation').toEqual([]);
  expect(Number(execById(f.path, f.executionId).lease_expires_at), 'recording acquisition never revives the expired execution lease').toBe(begin.expiry);
  f.truth('PREFLIGHT');
  await f.recover();
  expect(f.native.layers.has(layer)).toBe(true);
  expect(f.native.removals(), 'active execution resource remains untouched during reconciliation').toEqual([layer]);
  f.reclaimAndCancel(); f.native.model.removal = 'ok';
  await f.recover(true);
  expect(f.native.layers.has(layer), 'fresh terminal recovery retains proof of the acquired native identity').toBe(false);
  expect(f.native.removals()).toEqual([layer, layer]);
  await f.recover();
  expect(f.native.removals()).toEqual([layer, layer]);
  f.truth('CANCELLED');
}, 60_000);
