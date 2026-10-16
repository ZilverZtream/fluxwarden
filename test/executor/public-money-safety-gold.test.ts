/* Independent regression oracles: SECURITY INV-03/INV-06, §4.2; SPEC §8.3/§8.7.
 * Only local fake adapter ports and real SQLite are used. Clock tests deliberately keep
 * approval and lease lifetimes much longer than the delayed node answers.
 */
import { createHash } from 'node:crypto';
import { afterEach, expect, it, vi } from 'vitest';
import { FakePreflightNode, circularRoute, fakeChannel } from '../fakes/preflight-node.js';
import { succeeded } from '../fakes/execution-node.js';
import {
  APPROVAL_KEYS, IN_PEER, OUT_PEER, dbNow, execById, loadPersistence, loadPreflight,
  policyFor, raw, reservationsOf, scratchDb, seedBase, seedProposal, sleep, ulid,
} from '../helpers/cp028-executor.js';
import { S_BEFORE, T_BEFORE, PREIMAGE } from '../helpers/cp030-dispatch.js';
import { loadDispatch, loadExecutionCore, loadReconciler, rowOf, seedExecution, type Alert } from '../helpers/cp030-execution.js';
import { ScriptedExecutionNode } from '../fakes/execution-node.js';

afterEach(() => { vi.restoreAllMocks(); });

// Real elapsed time is essential here: SQLite's clock must advance while Date.now is frozen.
for (const phase of ['route-and-invoice', 'invoice', 'baseline'] as const) {
  it(`PUB001/${phase} refuses snapshots that expire during awaited preparation, with a live lease and approval`, async () => {
    const p = await loadPersistence();
    const path = scratchDb(`pub001-${phase}`);
    const base = seedBase(p, path);
    const approval = seedProposal(base, { approvalTtlMs: 600_000, proposalTtlMs: 900_000 });
    const policy = policyFor(base, { maxSnapshotAgeMs: 1_000 });
    const db = p.openDatabase(path, { readOnly: false });
    const observedAt = dbNow(path);
    vi.spyOn(Date, 'now').mockReturnValue(observedAt);
    const channels = [fakeChannel(base.sourceKey, OUT_PEER, { observedAt }), fakeChannel(base.targetKey, IN_PEER, { observedAt })];
    const preflight = new FakePreflightNode(base.sourceKey, base.targetKey, {
      channels: () => channels,
      during: phase === 'route-and-invoice' ? { findCircularRoute: () => sleep(1_500) } : {},
    });
    const node = new ScriptedExecutionNode({ before: () => channels, after: () => channels });
    const invoice = node.script.invoice;
    node.script.invoice = async (...args) => {
      await sleep(phase === 'route-and-invoice' ? 2_000 : phase === 'invoice' ? 1_500 : 0);
      return await invoice(...args);
    };
    const list = node.listChannels.bind(node);
    if (phase === 'baseline') node.listChannels = async () => { await sleep(1_500); return await list(); };
    try {
      const { prepareExecution } = await loadPreflight();
      const ready = await prepareExecution({ db, adapter: preflight, workerId: 'snapshot-worker', leaseMs: 60_000 }, { approval, policy, approvalKeyIds: APPROVAL_KEYS });
      let outcome: { exit: number; step: string | null };
      if (ready.kind === 'READY') {
        const { dispatchExecution } = await loadDispatch();
        outcome = await dispatchExecution({ db, adapter: node, workerId: 'snapshot-worker', leaseMs: 60_000,
          randomBytes: () => Uint8Array.from(PREIMAGE), stopSignal: new AbortController().signal,
          attemptDeadlineMs: 5_000, invoiceExpirySeconds: 300, deltaToleranceMsat: 0n, alert: () => undefined,
        }, { ...ready, approval, policy });
      } else outcome = ready;
      // These controls exclude expiry or lease-loss as explanations for a refusal.
      expect(approval.expiresAt - dbNow(path)).toBeGreaterThan(500_000);
      if (ready.executionId === null) throw new Error('the independently valid approval was not claimed');
      expect(Number(execById(path, ready.executionId).lease_expires_at) - dbNow(path)).toBeGreaterThan(30_000);
      expect(dbNow(path) - observedAt).toBeGreaterThanOrEqual(1_400);
      expect.soft(node.count('sendOnRoute'), 'expired snapshots must never authorize payment').toBe(0);
      expect.soft(outcome).toMatchObject({ exit: 5, step: 'STALE_SNAPSHOT' });
      expect.soft(rowOf(path, ready.executionId).status).toBe('CANCELLED');
      expect.soft(reservationsOf(path, ready.executionId)[0]?.state).toBe('RELEASED');
    } finally { db.close(); }
  });
}

it('PUB001/db-clock fresh snapshots remain usable when the host clock jumps forward', async () => {
  const p = await loadPersistence();
  const path = scratchDb('pub001-host-clock');
  const base = seedBase(p, path);
  const approval = seedProposal(base);
  const policy = policyFor(base, { maxSnapshotAgeMs: 1_000 });
  const db = p.openDatabase(path, { readOnly: false });
  try {
    const { prepareExecution } = await loadPreflight();
    const observedAt = dbNow(path);
    vi.spyOn(Date, 'now').mockReturnValue(observedAt + 86_400_000);
    const node = new FakePreflightNode(base.sourceKey, base.targetKey, { channels: () => [
      fakeChannel(base.sourceKey, OUT_PEER, { observedAt }), fakeChannel(base.targetKey, IN_PEER, { observedAt }),
    ] });
    const ready = await prepareExecution({ db, adapter: node, workerId: 'clock-control', leaseMs: 60_000 }, { approval, policy, approvalKeyIds: APPROVAL_KEYS });
    expect(ready.kind, 'step' in ready ? `preflight step: ${ready.step}` : undefined).toBe('READY');
    expect(node.mutatingCalls()).toEqual([]);
  } finally { db.close(); }
});

const PRINCIPAL = 1_000_000n;
const CAP = 10_000n;
const PLANNED_FEE = 500n;

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonical(entry)}`).join(',')}}`;
  return JSON.stringify(value);
}

// SECURITY §4.2: ceil(1500 * 1e6 / 1e6) = 1500 > 1000 ppm,
// although 1500 < the signed absolute limit of 10000. The exemption is explicitly zero.
for (const pathKind of ['dispatch', 'unknown-track', 'unknown-startup', 'late-attribution'] as const) {
  for (const [label, actualFee, expectedExit] of [['ppm-breach', 1_500n, 8], ['ppm-boundary', 1_000n, 9]] as const) {
    it(`PUB002/${pathKind}/${label} checks the reported fee against the persisted ppm ceiling and preserves paid truth`, async () => {
      const p = await loadPersistence();
      const path = scratchDb(`pub002-${pathKind}-${label}`);
      const seededBase = seedBase(p, path);
      const policyJson = canonical({ version: 3, network: 'regtest',
        fees: { max_fee_msat: '10000', max_fee_ppm: 1000, exempt_fee_msat: '0' }, routing: { max_cltv_delta: 144 },
        amounts: { min_channel_reserve_msat: '50000000', max_principal_msat: '1000000', min_principal_msat: '1000000' },
        budget: { msat: '2000000', period: 86400 }, cooldown_after_failure: 3600, cooldown_after_success: 1800,
        max_in_flight: 1, max_snapshot_age: 60, proposal_ttl: 900, approval_max_ttl: 600,
        demand: { mode: 'targets', horizon: 21600, burst_factor: '1.4', ewma: { bucket_seconds: 3600, alpha: '0.35', min_samples: 12 } },
        targets: {}, exclude_channels: [],
      });
      const base = { ...seededBase, policyVersionId: ulid(), policySha256: createHash('sha256').update(policyJson).digest('hex') };
      const setup = raw(path);
      try {
        setup.prepare(`INSERT INTO policy_versions (id, version_no, policy_sha256, policy_canonical_json, author, created_at)
          VALUES (?, 4, ?, ?, 'operator', ?)`)
          .run(base.policyVersionId, base.policySha256, policyJson, dbNow(path));
      } finally { setup.close(); }
      const route = circularRoute(base.sourceKey, base.targetKey, PLANNED_FEE, 80, PRINCIPAL);
      const seeded = seedExecution(base, { status: 'PREFLIGHT', fenceEpoch: 3n, route, plannedFeeMsat: PLANNED_FEE,
        proposalOptions: { approvedMaxFeeMsat: CAP } });
      const proposalSetup = raw(path);
      try { proposalSetup.prepare('UPDATE liquidity_proposals SET principal_msat = ?, max_fee_msat = ?, max_fee_ppm = 1000 WHERE id = ?')
        .run(PRINCIPAL, CAP, seeded.approval.proposalId); }
      finally { proposalSetup.close(); }
      const policy = policyFor(base, { maxFeeMsat: CAP, maxFeePpm: 1_000n, exemptFeeMsat: 0n });
      const { proveRegtest, approveRoute } = await loadExecutionCore();
      const proof = proveRegtest('regtest', { pubkey: '03' + 'cd'.repeat(32), network: 'regtest', version: '0.21.4-beta', synced: true });
      if (proof === null) throw new Error('regtest proof refused');
      const approved = approveRoute(route, route, seeded.approval, policy, proof);
      if (!('route' in approved)) throw new Error(`within-cap route refused: ${approved.refusal}`);
      const node = new ScriptedExecutionNode({
        before: () => [fakeChannel(base.sourceKey, OUT_PEER, { localBalanceMsat: S_BEFORE }), fakeChannel(base.targetKey, IN_PEER, { localBalanceMsat: T_BEFORE })],
        after: () => [fakeChannel(base.sourceKey, OUT_PEER, { localBalanceMsat: S_BEFORE - PRINCIPAL - actualFee }),
          fakeChannel(base.targetKey, IN_PEER, { localBalanceMsat: T_BEFORE + PRINCIPAL })],
        send: context => { context.onDispatched?.(); return Promise.resolve(pathKind === 'dispatch'
          ? succeeded(actualFee, 1, true, base.targetKey) : { kind: 'IN_FLIGHT' }); },
        observe: () => Promise.resolve(succeeded(actualFee, 1, true, base.targetKey)),
      });
      const s = { p, path, base, ...seeded, node, alerts: [] as Alert[] };
      const { dispatchExecution } = await loadDispatch();
      const dispatchDb = p.openDatabase(path, { readOnly: false });
      let first;
      try { first = await dispatchExecution({ db: dispatchDb, adapter: node, workerId: 'fee-worker', leaseMs: 60_000,
        randomBytes: () => Uint8Array.from(PREIMAGE), stopSignal: new AbortController().signal,
        attemptDeadlineMs: 5_000, invoiceExpirySeconds: 300, deltaToleranceMsat: 0n, alert: alert => { s.alerts.push(alert); },
      }, { executionId: s.executionId, fenceEpoch: 3n, route: approved.route, approval: seeded.approval, policy }); }
      finally { dispatchDb.close(); }
      let exit = first.exit;
      if (pathKind !== 'dispatch') {
        expect(first.exit).toBe(7);
        if (pathKind === 'late-attribution') {
          // A real receiver receipt proves settlement before the payer fee is available.
          s.node.script.observe = () => Promise.resolve({ kind: 'IN_FLIGHT' });
          s.node.script.invoiceState = () => Promise.resolve('SETTLED');
        }
        const { reconcile } = await loadReconciler();
        const db = s.p.openDatabase(s.path, { readOnly: false });
        const deps = { db, adapters: new Map([[s.base.nodeId, s.node]]), workerId: 'fee-recovery', leaseMs: 60_000,
          notFoundWindowMs: 120_000, escalateAfterMs: 600_000, confirmIntervalMs: 1_000, deltaToleranceMsat: 0n,
          alert: (alert: Alert) => { s.alerts.push(alert); } };
        try {
          if (pathKind === 'late-attribution') {
            await reconcile(deps, { startup: true });
            expect(rowOf(s.path, s.executionId).status).toBe('VERIFIED_SUCCESS');
            s.node.script.observe = () => Promise.resolve(succeeded(actualFee, 1, true, s.base.targetKey));
            s.alerts.length = 0;
          }
          exit = (await reconcile(deps, { startup: pathKind !== 'unknown-track' })).exit;
        } finally { db.close(); }
      }
      expect.soft(exit).toBe(expectedExit);
      expect.soft(s.alerts.some(alert => alert.kind === 'INVARIANT_BREACH')).toBe(expectedExit === 8);
      expect(rowOf(s.path, s.executionId)).toMatchObject({ status: 'VERIFIED_SUCCESS', actual_fee_msat: actualFee });
      expect(reservationsOf(s.path, s.executionId)[0]).toMatchObject({ state: 'CONSUMED', consumed_msat: actualFee });
      expect(s.node.count('sendOnRoute')).toBe(1);
    });
  }
}
