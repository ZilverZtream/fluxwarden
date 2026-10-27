/*
Interface: test/helpers/cp028-executor.ts (prepareExecution, recoverPreflight, PreflightAdapter); TransportError and
ProtocolError of src/core/errors.ts. The kill test's worker
process loads the built modules dist/executor/preflight.js and dist/persistence/index.js.

Rules under test: SPEC §8.3 P1-P4, §10.3 AE3-AE8 (step ids and exit codes), §5.2 H3/H4/H7 (identity, network-lock,
chain-sync), §5.5 V1/V3/V5, §6.5 and §10.4 DM4 (expired CLAIMED/PREFLIGHT leases); SECURITY INV-02 (no dispatch without a
stored verified approval), INV-03 (approved caps), INV-06 (snapshot age on the database clock), INV-10 (capabilities fail
closed, exit 3), INV-14 (reserve floor), INV-15 (regtest lock); chaos rows T-01, T-02, T-07.
*/
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { beforeAll, expect, it } from 'vitest';
import { circularRoute, EXECUTION_CAPABILITIES, fakeChannel, FakePreflightNode, type Script } from '../fakes/preflight-node.js';
import { childEnv, repoRoot } from '../helpers/cli.js';
import {
  APPROVAL_KEYS, APPROVED_MAX_FEE, PRINCIPAL, dbNow, builtPersistence, claimed, codeOf, eventsOf, execById, execByProposal, force, IN_PEER, loadClaim,
  loadPersistence, loadPreflight, OUT_PEER, policyFor, prepareEmptyDatabaseFixture, reservationsOf, scratchDb, seedBase, seedProposal, seedTerminal, sleep, ulid,
  NODE_PUBKEY, preflightWithHash, scalar, type Base, type ExecutionPolicy, type ExecRow, type PreflightOutcome, type ProposalOptions, type VerifiedApproval,
} from '../helpers/cp028-executor.js';

const LEASE = 60_000;
const builtPreflight = join(repoRoot, 'dist', 'executor', 'preflight.js');
let emptyDatabase: string;
beforeAll(async () => { emptyDatabase = prepareEmptyDatabaseFixture(await loadPersistence()); });

interface Scenario {
  readonly script?: (base: Base) => Partial<Script>;
  readonly policy?: (base: Base) => Partial<ExecutionPolicy>;
  readonly proposal?: ProposalOptions;
  readonly approval?: (approval: VerifiedApproval) => VerifiedApproval;
  readonly before?: (base: Base) => void;
  readonly keys?: readonly string[];
}

/** Ordinary admitted snapshots use the production controller's database clock.
 * Explicit snapshot ages supplied by clock-boundary cases remain authoritative. */
function admittedChannel(base: Base, key: string, peer: string, fields: Partial<ReturnType<typeof fakeChannel>> = {}) {
  return fakeChannel(key, peer, { observedAt: dbNow(base.path), ...fields });
}

async function scenario(prefix: string, s: Scenario = {}) {
  const p = await loadPersistence();
  const { prepareExecution } = await loadPreflight();
  const path = scratchDb(prefix);
  const base = seedBase(p, path, emptyDatabase);
  s.before?.(base);
  const stored = seedProposal(base, s.proposal ?? {});
  const approval = s.approval?.(stored) ?? stored;
  const policy = policyFor(base, s.policy?.(base) ?? {});
  const fake = new FakePreflightNode(base.sourceKey, base.targetKey, {
    channels: () => [admittedChannel(base, base.sourceKey, OUT_PEER), admittedChannel(base, base.targetKey, IN_PEER)],
    ...s.script?.(base),
  });
  const db = p.openDatabase(path, { readOnly: false });
  let outcome: PreflightOutcome;
  try {
    outcome = await prepareExecution({ db, adapter: fake, workerId: 'worker-a', leaseMs: LEASE }, { approval, policy, approvalKeyIds: s.keys ?? APPROVAL_KEYS });
  } finally { db.close(); }
  const row = execByProposal(path, stored.proposalId);
  return { path, base, approval, policy, fake, outcome, row };
}

/** A cancelled preflight: the outcome, the stored row, the released reservation and no mutating node call. */
function expectCancelled(r: { path: string; fake: FakePreflightNode; outcome: PreflightOutcome; row: ExecRow | undefined }, exit: number, step: string): void {
  expect(r.row, step).toBeDefined();
  if (r.row === undefined) return;
  expect(r.outcome, step).toEqual({ kind: 'CANCELLED', executionId: r.row.id, exit, step });
  expect(r.row.status, step).toBe('CANCELLED');
  expect(r.row.error_code, step).toBe(step);
  expect(r.row.payment_hash, step).toBeNull();
  expect(reservationsOf(r.path, r.row.id).map(x => x.state), step).toEqual(['RELEASED']);
  expect(r.fake.mutatingCalls(), step).toEqual([]);
}

/** A refusal decided before any node call: no node call at all, and nothing left holding budget or awaiting work. */
function expectRefusedBeforeNode(r: { path: string; fake: FakePreflightNode; outcome: PreflightOutcome; row: ExecRow | undefined }, step: string): void {
  expect(r.fake.calls, step).toEqual([]);
  expect(r.outcome.kind === 'READY' ? undefined : { exit: r.outcome.exit, step: r.outcome.step }, step).toEqual({ exit: 5, step });
  if (r.row !== undefined) {
    expect(r.row.status, step).toBe('CANCELLED');
    expect(r.row.error_code, step).toBe(step);
    expect(reservationsOf(r.path, r.row.id).filter(x => x.state === 'HELD'), step).toEqual([]);
  }
}

it('CP-029/B1 an expired approval is refused before any node call (APPROVAL_INVALID, exit 5)', async () => {
  expectRefusedBeforeNode(await scenario('expired', { proposal: { approvalTtlMs: -1_000 } }), 'APPROVAL_INVALID');
});

it('CP-029/B1 an approval record looser than the stored approval is refused before any node call', async () => {
  // The stored, signed caps bind (SPEC §7.7): a caller cannot raise them.
  expectRefusedBeforeNode(await scenario('looser', { approval: a => ({ ...a, approvedMaxFeeMsat: 300_000n }) }), 'APPROVAL_INVALID');
});

it('CP-029/B1 an approval that is not stored can never claim: no execution row and no node call (INV-02)', async () => {
  const r = await scenario('unstored', { approval: a => ({ ...a, approvalId: ulid(), nonce: 'ab'.repeat(32) }) });
  expectRefusedBeforeNode(r, 'APPROVAL_INVALID');
  expect(r.row).toBeUndefined();
});

it('CP-029/B1 a changed active policy digest is refused before any node call (POLICY_CHANGED, exit 5)', async () => {
  expectRefusedBeforeNode(await scenario('policy', { policy: () => ({ sha256: 'ef'.repeat(32) }) }), 'POLICY_CHANGED');
});

it('CP-029/B1 a configured network other than regtest is refused before the claim: no row, no node call, the proposal stays executable (INV-15, T-01)', async () => {
  const r = await scenario('confnet', { policy: () => ({ network: 'mainnet' }) });
  expect(r.outcome).toEqual({ kind: 'REFUSED', executionId: null, exit: 5, step: 'network-lock' });
  expect(r.row).toBeUndefined();
  expect(r.fake.calls).toEqual([]);
  expect(scalar(r.path, 'SELECT count(*) AS v FROM budget_reservations')).toBe(0n);
  // With the configuration corrected, the same approval still executes.
  const p = await loadPersistence();
  const { claimExecution } = await loadClaim();
  const db = p.openDatabase(r.path, { readOnly: false });
  try {
    claimed(claimExecution(db, { approval: r.approval, policy: policyFor(r.base), approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-b', leaseMs: LEASE }));
  } finally { db.close(); }
});

it('CP-029/B1 an approval signed by a key no longer configured cannot claim: no row and no node call (SECURITY §4.1)', async () => {
  const r = await scenario('removed-key', { keys: ['6b'.repeat(16)] });
  expectRefusedBeforeNode(r, 'APPROVAL_INVALID');
  expect(r.row).toBeUndefined();
});

it('CP-029/B1 the budget refusal cancels with BUDGET_EXHAUSTED before any node call', async () => {
  const r = await scenario('budget', { policy: () => ({ budget: { msat: APPROVED_MAX_FEE - 1n, periodMs: 86_400_000 } }) });
  expect(r.fake.calls).toEqual([]);
  const row = r.row;
  if (row === undefined) throw new Error('SPEC §6.6: an exhausted budget leaves the execution CANCELLED');
  expect(r.outcome).toEqual({ kind: 'CANCELLED', executionId: row.id, exit: 5, step: 'BUDGET_EXHAUSTED' });
  expect(row.status).toBe('CANCELLED');
  expect(row.error_code).toBe('BUDGET_EXHAUSTED');
  expect(reservationsOf(r.path, row.id).filter(x => x.state !== 'RELEASED')).toEqual([]);
});

for (const network of ['signet', 'testnet', 'testnet4', 'mainnet'] as const) {
  it(`CP-029/B1 a node reporting ${network} cancels with network-lock, exit 5, and no mutating call (INV-15)`, async () => {
    expectCancelled(await scenario(`net-${network}`, { script: () => ({ network }) }), 5, 'network-lock');
  });
}

it('CP-029/B1 a node whose pubkey differs from the pinned one cancels with identity, exit 5', async () => {
  expectCancelled(await scenario('identity', { script: () => ({ pubkey: `03${'ee'.repeat(32)}` }) }), 5, 'identity');
});

it('CP-029/B1 a node not synced to the chain cancels with chain-sync, exit 5', async () => {
  expectCancelled(await scenario('sync', { script: () => ({ synced: false }) }), 5, 'chain-sync');
});

it('CP-029/B1 each missing execution capability cancels with CAPABILITY_UNSUPPORTED, exit 3 (INV-10)', async () => {
  for (const missing of ['INVOICE_CREATE', 'INVOICE_CANCEL', 'ROUTE_QUERY_PINNED', 'SEND_TO_ROUTE', 'PAYMENT_TRACK'] as const) {
    const capabilities = new Set(EXECUTION_CAPABILITIES.filter(c => c !== missing));
    const r = await scenario(`cap-${missing}`, { script: () => ({ capabilities }) });
    expectCancelled(r, 3, 'CAPABILITY_UNSUPPORTED');
    expect(r.fake.calls, missing).not.toContain('findCircularRoute');
  }
});

// Snapshot ages 500 ms either side of max_snapshot_age (60 s): the outcome does not depend on a few ms of scheduling.
for (const side of ['source', 'target'] as const) {
  it(`CP-029/B1 a ${side} snapshot observed max_snapshot_age + 500 ms ago cancels with STALE_SNAPSHOT (INV-06, T-02)`, async () => {
    const r = await scenario(`stale-${side}`, {
      script: base => ({ channels: () => [
        fakeChannel(base.sourceKey, OUT_PEER, side === 'source' ? { observedAt: Date.now() - 60_500 } : {}),
        fakeChannel(base.targetKey, IN_PEER, side === 'target' ? { observedAt: Date.now() - 60_500 } : {}),
      ] }),
    });
    expectCancelled(r, 5, 'STALE_SNAPSHOT');
    expect(r.fake.calls).not.toContain('findCircularRoute');
  });
}

it('CP-029/B1 snapshots observed max_snapshot_age - 500 ms ago are fresh enough', async () => {
  const r = await scenario('fresh-edge', {
    script: base => ({ channels: () => [
      fakeChannel(base.sourceKey, OUT_PEER, { observedAt: Date.now() - 59_500 }), fakeChannel(base.targetKey, IN_PEER, { observedAt: Date.now() - 59_500 }),
    ] }),
  });
  expect(r.outcome.kind).toBe('READY');
});

it('CP-029/B1 a source left below the reserve floor by principal plus fee cancels with RESERVE_FLOOR; exactly at the floor passes (INV-14)', async () => {
  // Floor 50,000,000 + principal 100,000,000 + approved max fee 200,000 (route fee 200,000, so V8 and INV-14 agree).
  const atFloor = 50_000_000n + PRINCIPAL + APPROVED_MAX_FEE;
  const script = (spendable: bigint) => (base: Base): Partial<Script> => ({
    channels: () => [admittedChannel(base, base.sourceKey, OUT_PEER, { spendableMsat: spendable }), admittedChannel(base, base.targetKey, IN_PEER)],
    route: () => circularRoute(base.sourceKey, base.targetKey, APPROVED_MAX_FEE, 80),
  });
  expectCancelled(await scenario('floor-below', { script: script(atFloor - 1n) }), 5, 'RESERVE_FLOOR');
  const pass = await scenario('floor-at', { script: script(atFloor) });
  expect(pass.outcome.kind).toBe('READY');
});

it('CP-029/B1 a failure cooldown on the channel pair cancels with COOLDOWN_ACTIVE and no mutating call', async () => {
  const r = await scenario('cooldown', { before: base => { seedTerminal(base, { status: 'VERIFIED_FAILURE', agoMs: 600_000 }); } });
  const row = r.row;
  if (row === undefined) throw new Error('no execution row');
  expect(r.outcome).toEqual({ kind: 'CANCELLED', executionId: row.id, exit: 5, step: 'COOLDOWN_ACTIVE' });
  expect(row.status).toBe('CANCELLED');
  expect(row.error_code).toBe('COOLDOWN_ACTIVE');
  expect(reservationsOf(r.path, row.id).filter(x => x.state !== 'RELEASED')).toEqual([]);
  expect(r.fake.mutatingCalls()).toEqual([]);
});

it('CP-029/B1 a cooldown that starts after the claim is caught by the preflight re-check', async () => {
  let base: Base | undefined;
  const r = await scenario('cooldown-late', {
    before: b => { base = b; },
    script: () => ({ during: { handshake: () => { if (base !== undefined) seedTerminal(base, { status: 'VERIFIED_FAILURE', agoMs: 0 }); } } }),
  });
  expectCancelled(r, 5, 'COOLDOWN_ACTIVE');
});

it('CP-029/B1 an approval that expires during preflight cancels with APPROVAL_INVALID and no mutating call', async () => {
  // The TTL leaves the claim ample time; the route query then does not answer until the database clock has passed the
  // stored expiry, so the approval is expired at that step whatever the machine load.
  let path = '';
  const r = await scenario('expiring', {
    proposal: { approvalTtlMs: 4_000 },
    before: base => { path = base.path; },
    script: () => ({ during: { findCircularRoute: async () => {
      const expiresAt = Number(scalar(path, 'SELECT max(expires_at) AS v FROM approvals'));
      while (dbNow(path) <= expiresAt) await sleep(50);
    } } }),
  });
  expectCancelled(r, 5, 'APPROVAL_INVALID');
});

it('CP-029/B2 a passing preflight stays PREFLIGHT with no payment hash, records the live route and calls no mutating method', async () => {
  const r = await scenario('pass');
  const row = r.row;
  if (row === undefined) throw new Error('no execution row');
  const route = circularRoute(r.base.sourceKey, r.base.targetKey, 150_000n, 80);
  expect(r.outcome).toEqual({ kind: 'READY', executionId: row.id, fenceEpoch: row.fence_epoch, route });
  expect(row.status).toBe('PREFLIGHT');
  expect(row.payment_hash).toBeNull();
  expect(row.route_json).not.toBeNull();
  expect(row.planned_fee_msat).toBe(150_000n);
  expect(row.error_code).toBeNull();
  expect(eventsOf(r.path, row.id).map(e => e.to_status).slice(0, 2)).toEqual(['CLAIMED', 'PREFLIGHT']);
  expect(reservationsOf(r.path, row.id).map(x => ({ state: x.state, reserved: x.reserved_msat }))).toEqual([{ state: 'HELD', reserved: APPROVED_MAX_FEE }]);
  expect(r.fake.mutatingCalls()).toEqual([]);
  // A CLN-only capability (BOOKKEEPER_READ) is not required: the default node is LND-like and passes.
  expect(r.fake.script.capabilities.has('BOOKKEEPER_READ')).toBe(false);
});

it('CP-029/B3 restart recovery cancels expired-lease CLAIMED/PREFLIGHT rows whose approval expired and leaves every other row alone, with no node call', async () => {
  const p = await loadPersistence();
  const { claimExecution } = await loadClaim();
  const { recoverPreflight } = await loadPreflight();
  const path = scratchDb('recover');
  const base = seedBase(p, path);
  const db = p.openDatabase(path, { readOnly: false });
  try {
    const policy = policyFor(base);
    const make = (ttl: number, leaseMs: number) => {
      const approval = seedProposal(base, { approvalTtlMs: ttl });
      return { approval, ...claimed(claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'dead-worker', leaseMs })) };
    };
    const preflightExpired = make(1_500, LEASE);
    const preflightLive = make(1_500, LEASE);
    const preflightValid = make(600_000, LEASE);
    const submitting = make(1_500, LEASE);
    const claimedExpired = make(1_500, LEASE);
    const epochs = new Map<string, bigint>();
    for (const x of [preflightExpired, preflightLive, preflightValid, submitting]) {
      epochs.set(x.executionId, db.executions.transition(x.executionId, x.fenceEpoch, 'CLAIMED', 'PREFLIGHT'));
    }
    epochs.set(claimedExpired.executionId, claimedExpired.fenceEpoch);
    force(path, submitting.executionId, { status: 'SUBMITTING' });
    for (const x of [preflightExpired, preflightValid, submitting, claimedExpired]) force(path, x.executionId, { leaseAgoMs: 1_000 });
    await sleep(1_800);
    const untouched = [preflightLive, preflightValid, submitting].map(x => execById(path, x.executionId));

    const fake = new FakePreflightNode(base.sourceKey, base.targetKey);
    const report = await recoverPreflight({ db, adapter: fake, workerId: 'recovery', leaseMs: LEASE });
    expect([...report.cancelled].sort()).toEqual([preflightExpired.executionId, claimedExpired.executionId].sort());
    expect(fake.calls).toEqual([]);
    for (const x of [preflightExpired, claimedExpired]) {
      const row = execById(path, x.executionId);
      const old = epochs.get(x.executionId) ?? 0n;
      expect(row.status).toBe('CANCELLED');
      expect(row.error_code).toBe('APPROVAL_INVALID');
      expect(row.fence_epoch > old).toBe(true);
      expect(reservationsOf(path, x.executionId).map(r => r.state)).toEqual(['RELEASED']);
      // The dead worker's epoch no longer writes.
      expect(codeOf(() => db.executions.transition(x.executionId, old, 'PREFLIGHT', 'SUBMITTING'))).toBe('LEASE_LOST');
    }
    expect([preflightLive, preflightValid, submitting].map(x => execById(path, x.executionId))).toEqual(untouched);
    // T-07: the expired lease with a valid approval is re-claimed with the next epoch.
    expect(claimExecution(db, { approval: preflightValid.approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-b', leaseMs: LEASE }))
      .toEqual({ ok: true, executionId: preflightValid.executionId, fenceEpoch: (epochs.get(preflightValid.executionId) ?? 0n) + 1n });
  } finally { db.close(); }
}, 30_000);

// A worker process that claims, enters preflight and is killed while its handshake is pending. Every adapter call is
// printed before it happens.
const DOOMED_WORKER = `
const [preflightUrl, persistenceUrl, dbPath] = process.argv.slice(1);
const revive = (_k, v) => typeof v === 'string' && v.startsWith('bigint:') ? BigInt(v.slice(7)) : v;
const { openDatabase } = await import(persistenceUrl);
const { prepareExecution } = await import(preflightUrl);
const db = openDatabase(dbPath, { readOnly: false });
const log = name => process.stdout.write('call:' + name + '\\n');
const keepAlive = setInterval(() => {}, 1000);
const adapter = {
  handshake: () => { log('handshake'); return new Promise(() => {}); },
  capabilities: () => { log('capabilities'); return new Set(); },
  listChannels: async () => { log('listChannels'); return []; },
  findCircularRoute: async () => { log('findCircularRoute'); return { refusal: 'NO_FEASIBLE_ROUTE' }; },
  createInvoice: async () => { log('createInvoice'); throw new Error('unreachable'); },
  sendOnRoute: async () => { log('sendOnRoute'); throw new Error('unreachable'); },
  cancelUnpaidInvoice: async () => { log('cancelUnpaidInvoice'); throw new Error('unreachable'); },
};
process.stdout.write('worker-ready\\n');
try {
  const serialized = await new Promise((resolve, reject) => {
    let text = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => { text += chunk; });
    process.stdin.once('end', () => { resolve(text); });
    process.stdin.once('error', reject);
  });
  const input = JSON.parse(serialized, revive);
  const outcome = await prepareExecution({ db, adapter, workerId: 'doomed', leaseMs: 500 }, input);
  process.stdout.write('outcome:' + JSON.stringify({ kind: outcome.kind, exit: outcome.exit, step: outcome.step }) + '\\n');
  process.exitCode = 1;
} catch (error) {
  process.stderr.write('worker-error:' + String(error?.name) + ':' + String(error?.code) + '\\n');
  process.exitCode = 1;
} finally { clearInterval(keepAlive); db.close(); }
`;

it('CP-029/B3 a worker killed in PREFLIGHT leaves nothing sent; after restart its row is CANCELLED and the reservation released (T-07)', async () => {
  expect(existsSync(builtPreflight), 'built preflight module').toBe(true);
  const p = await loadPersistence();
  const { recoverPreflight } = await loadPreflight();
  const path = scratchDb('killed');
  const base = seedBase(p, path, emptyDatabase);
  const policy = policyFor(base);
  let approval: VerifiedApproval | undefined;
  let acquiredFence: bigint | undefined;
  const child = spawn(process.execPath, ['--no-warnings', '--input-type=module', '-e', DOOMED_WORKER,
    pathToFileURL(builtPreflight).href, pathToFileURL(builtPersistence).href, path], {
    env: childEnv(), shell: false, windowsHide: true, stdio: 'pipe',
  });
  let out = '';
  let err = '';
  try {
    await new Promise<void>((resolve, reject) => {
      const rejectSetup: (error: Error) => void = reject;
      child.stdout.on('data', (chunk: Buffer) => {
        out += chunk.toString();
        if (out.includes('worker-ready\n') && approval === undefined) {
          try {
            // SPEC §6.5: start the unchanged authority lifetime after imports and native database admission.
            approval = seedProposal(base, { approvalTtlMs: 1_500 });
            const input = JSON.stringify({ approval, policy, approvalKeyIds: APPROVAL_KEYS }, (_k, v: unknown) => typeof v === 'bigint' ? `bigint:${v.toString()}` : v);
            child.stdin.end(input);
          } catch (error) { rejectSetup(error as Error); }
        }
        if (out.includes('outcome:')) reject(new Error(`worker refused before its pending handshake: ${out}`));
        if (out.includes('call:handshake')) resolve();
      });
      child.stderr.on('data', (chunk: Buffer) => { err += chunk.toString(); });
      child.once('error', reject);
      child.stdin.once('error', reject);
      child.once('exit', status => { reject(new Error(`worker exited ${String(status)} before its handshake: ${out} ${err}`)); });
    });
    if (approval === undefined) throw new Error('worker never received fresh authority');
    const row = execByProposal(path, approval.proposalId);
    expect(row?.status).toBe('PREFLIGHT');
    expect(row?.worker_id).toBe('doomed');
    if (row === undefined) throw new Error('worker did not acquire its execution');
    acquiredFence = row.fence_epoch;
    expect(reservationsOf(path, row.id).map(r => r.state)).toEqual(['HELD']);
    child.kill('SIGKILL');
    await new Promise<void>(resolve => { if (child.exitCode !== null || child.signalCode !== null) resolve(); else child.once('exit', () => { resolve(); }); });
  } finally { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }

  await sleep(1_800);
  const db = p.openDatabase(path, { readOnly: false });
  try {
    const fake = new FakePreflightNode(base.sourceKey, base.targetKey);
    const report = await recoverPreflight({ db, adapter: fake, workerId: 'recovery', leaseMs: LEASE });
    const row = execByProposal(path, approval.proposalId);
    if (row === undefined) throw new Error('no execution row');
    expect(report.cancelled).toEqual([row.id]);
    expect(row.status).toBe('CANCELLED');
    expect(row.fence_epoch).toBeGreaterThan(acquiredFence);
    expect(row.payment_hash).toBeNull();
    expect(reservationsOf(path, row.id).map(r => r.state)).toEqual(['RELEASED']);
    expect(fake.calls).toEqual([]);
    expect(out.split('\n').filter(line => /^call:(?:createInvoice|sendOnRoute|cancelUnpaidInvoice)$/.test(line))).toEqual([]);
  } finally { db.close(); }
}, 30_000);

it('CP-029/B4 preflight asks the node for a live route under the approved caps and records a different route that satisfies them', async () => {
  const r = await scenario('live-route', {
    script: base => ({ route: () => circularRoute(base.sourceKey, base.targetKey, APPROVED_MAX_FEE - 1_000n, 100) }),
  });
  expect(r.fake.routeRequests).toEqual([{
    sourceChannelKey: r.base.sourceKey, targetChannelKey: r.base.targetKey, principalMsat: PRINCIPAL,
    maxFeeMsat: APPROVED_MAX_FEE, maxFeePpm: 2500n, exemptFeeMsat: 5_000n, maxCltvDelta: 100,
  }]);
  expect(r.outcome.kind).toBe('READY');
  expect(r.row?.planned_fee_msat).toBe(APPROVED_MAX_FEE - 1_000n);
  expect(r.fake.mutatingCalls()).toEqual([]);
});

it('CP-029/B4 a live route above the approved fee cap (though under the proposal cap) cancels with FEE_CEILING_EXCEEDED (INV-03)', async () => {
  expectCancelled(await scenario('fee', {
    script: base => ({ route: () => circularRoute(base.sourceKey, base.targetKey, APPROVED_MAX_FEE + 1n, 80) }),
  }), 5, 'FEE_CEILING_EXCEEDED');
});

it('CP-029/B4 a live route above the approved CLTV cap (though under the proposal cap) cancels with CLTV_DELTA_UNSAFE', async () => {
  expectCancelled(await scenario('cltv', {
    script: base => ({ route: () => circularRoute(base.sourceKey, base.targetKey, 150_000n, 101) }),
  }), 5, 'CLTV_DELTA_UNSAFE');
});

it('CP-029/B4 a live route that does not leave over the source channel cancels with NO_FEASIBLE_ROUTE', async () => {
  expectCancelled(await scenario('v1', {
    script: base => ({ route: () => circularRoute('999999999999', base.targetKey, 150_000n, 80) }),
  }), 5, 'NO_FEASIBLE_ROUTE');
});

it('CP-029/B4 a node refusal of the live route cancels with the refusal code', async () => {
  expectCancelled(await scenario('noroute', { script: () => ({ route: () => ({ refusal: 'NO_FEASIBLE_ROUTE' }) }) }), 5, 'NO_FEASIBLE_ROUTE');
});

interface NodeErrors {
  readonly TransportError: new (message: string, phase: 'connect' | 'request' | 'response') => Error;
  readonly ProtocolError: new (message: string) => Error;
  readonly LndError: new (message: string, grpcCode: number | undefined, httpStatus: number | undefined) => Error;
}

async function nodeErrors(): Promise<NodeErrors> {
  return await import(pathToFileURL(join(repoRoot, 'src/core/errors.ts')).href) as NodeErrors;
}

const throwingCases = [
  { call: 'handshake', error: 'transport', exit: 4, step: 'NODE_UNREACHABLE' },
  { call: 'listChannels', error: 'protocol', exit: 4, step: 'NODE_UNREACHABLE' },
  { call: 'findCircularRoute', error: 'transport', exit: 4, step: 'NODE_UNREACHABLE' },
  { call: 'handshake', error: 'lnd', exit: 4, step: 'NODE_UNREACHABLE' },
  { call: 'findCircularRoute', error: 'lnd', exit: 4, step: 'NODE_UNREACHABLE' },
  { call: 'listChannels', error: 'unexpected', exit: 8, step: 'internal' },
] as const;

for (const c of throwingCases) {
  it(`CP-029/B1 a ${c.error} error thrown by ${c.call} cancels the execution (exit ${String(c.exit)}, ${c.step}) and releases the reservation`, async () => {
    // SPEC §5.2 H2 and §10.2: transport or protocol failure exit 4; §10.3 AE5 "still CANCELLED"; §6.6 every exit path releases.
    const errors = await nodeErrors();
    const make = (): Error => c.error === 'transport' ? new errors.TransportError('connection reset', 'response')
      : c.error === 'protocol' ? new errors.ProtocolError('malformed listpeerchannels answer')
        // gRPC 16 Unauthenticated through the REST gateway (HTTP 401): an authentication failure, SPEC §5.2 H2.
        : c.error === 'lnd' ? new errors.LndError('verification failed: signature mismatch after caveat verification', 16, 401)
          : new Error('adapter bug');
    const r = await scenario(`throw-${c.call}-${c.error}`, { script: () => ({ during: { [c.call]: () => { throw make(); } } }) });
    expectCancelled(r, c.exit, c.step);
  });
}

/** The default live route with one change. */
function withRoute(change: (route: ReturnType<typeof circularRoute>, base: Base) => ReturnType<typeof circularRoute>) {
  return (base: Base): Partial<Script> => ({ route: () => change(circularRoute(base.sourceKey, base.targetKey, 150_000n, 80), base) });
}

it('CP-029/B4 a live route that uses the source channel twice cancels with REPEATED_CHANNEL (V2)', async () => {
  expectCancelled(await scenario('v2', {
    script: withRoute((route, base) => ({ ...route, hops: route.hops.map((hop, i) => i === 1 ? { ...hop, channelKey: base.sourceKey } : hop) })),
  }), 5, 'REPEATED_CHANNEL');
});

it('CP-029/B4 a live route whose out-peer is its in-peer (S and T both to one peer) cancels with SAME_PEER (V7)', async () => {
  // Two channels to the same peer: the circle leaves and returns through that one node (lnd#4698).
  expectCancelled(await scenario('v7', {
    script: base => ({
      channels: () => [admittedChannel(base, base.sourceKey, OUT_PEER), admittedChannel(base, base.targetKey, OUT_PEER)],
      route: () => ({
        ...circularRoute(base.sourceKey, base.targetKey, 300n, 80),
        inPeer: OUT_PEER,
        hops: [
          { channelKey: base.sourceKey, nodeOut: OUT_PEER, amountOutMsat: PRINCIPAL + 300n, expiry: 580 },
          { channelKey: '481036337152', nodeOut: IN_PEER, amountOutMsat: PRINCIPAL + 200n, expiry: 560 },
          { channelKey: '592705486848', nodeOut: OUT_PEER, amountOutMsat: PRINCIPAL + 100n, expiry: 540 },
          { channelKey: base.targetKey, nodeOut: NODE_PUBKEY, amountOutMsat: PRINCIPAL, expiry: 518 },
        ],
      }),
    }),
  }), 5, 'SAME_PEER');
});

it('CP-029/B4 a live route that passes back through our node before the last hop cancels with REPEATED_CHANNEL (V11)', async () => {
  expectCancelled(await scenario('v11', {
    script: base => ({ route: () => ({
      ...circularRoute(base.sourceKey, base.targetKey, 300n, 80),
      hops: [
        { channelKey: base.sourceKey, nodeOut: OUT_PEER, amountOutMsat: PRINCIPAL + 300n, expiry: 580 },
        { channelKey: '481036337152', nodeOut: NODE_PUBKEY, amountOutMsat: PRINCIPAL + 200n, expiry: 560 },
        { channelKey: '592705486848', nodeOut: IN_PEER, amountOutMsat: PRINCIPAL + 100n, expiry: 540 },
        { channelKey: base.targetKey, nodeOut: NODE_PUBKEY, amountOutMsat: PRINCIPAL, expiry: 518 },
      ],
    }) }),
  }), 5, 'REPEATED_CHANNEL');
});

it('CP-029/B4 a target whose fresh receivable is below the principal cancels with LAST_HOP_RECEIVABLE; exactly the principal passes (V9, INV-14)', async () => {
  const script = (receivable: bigint) => (base: Base): Partial<Script> => ({
    channels: () => [admittedChannel(base, base.sourceKey, OUT_PEER), admittedChannel(base, base.targetKey, IN_PEER, { receivableMsat: receivable })],
  });
  expectCancelled(await scenario('v9-below', { script: script(PRINCIPAL - 1n) }), 5, 'LAST_HOP_RECEIVABLE');
  expect((await scenario('v9-at', { script: script(PRINCIPAL) })).outcome.kind).toBe('READY');
});

it('CP-029/B4 the fee is recomputed from the hops: a node total under the approved cap does not hide hop amounts above it (V3)', async () => {
  // Hops carry 250,000 msat of fee (first-hop amount minus principal); the node reports 150,000; approved cap 200,000.
  // A node-total implementation would return READY. V3 (fee from the hops, over the cap) and V10 (first-hop amount is not
  // P + the stated fee) both fail here, so either refusal proves the hops decide.
  const r = await scenario('fee-hops', {
    script: base => ({ route: () => ({ ...circularRoute(base.sourceKey, base.targetKey, 250_000n, 80), totalFeeMsat: 150_000n, feePpmCeil: 1_500n }) }),
  });
  const step = r.outcome.kind === 'READY' ? 'READY' : r.outcome.step;
  expect(['FEE_CEILING_EXCEEDED', 'NO_FEASIBLE_ROUTE']).toContain(step);
  expectCancelled(r, 5, step);
});

type Route = ReturnType<typeof circularRoute>;
const STRANGER = `03${'99'.repeat(32)}`;

/** One defect in the default live route (fee 150,000 msat, delta 80, three hops) per case; every other check passes. */
const routeDefects: readonly { name: string; step: string; change: (route: Route, base: Base) => Route }[] = [
  {
    name: 'its second hop delivers back to our node before the last hop (V11)', step: 'REPEATED_CHANNEL',
    change: route => ({ ...route, hops: route.hops.map((hop, i) => i === 1 ? { ...hop, nodeOut: NODE_PUBKEY } : hop) }),
  },
  {
    name: 'a hop expiry grows along the path (V5)', step: 'CLTV_DELTA_UNSAFE',
    change: route => ({ ...route, hops: route.hops.map((hop, i) => i === 1 ? { ...hop, expiry: (route.hops[0]?.expiry ?? 0) + 1 } : hop) }),
  },
  {
    name: 'its first hop delivers to a node other than the peer of S (V1)', step: 'NO_FEASIBLE_ROUTE',
    change: route => ({ ...route, hops: route.hops.map((hop, i) => i === 0 ? { ...hop, nodeOut: STRANGER } : hop) }),
  },
  {
    name: 'its stated in-peer is not the peer of T (V1)', step: 'NO_FEASIBLE_ROUTE',
    change: route => ({ ...route, inPeer: STRANGER }),
  },
  {
    name: 'its last hop delivers 1 msat more than the principal (V10)', step: 'NO_FEASIBLE_ROUTE',
    change: route => ({ ...route, hops: route.hops.map((hop, i) => i === 2 ? { ...hop, amountOutMsat: PRINCIPAL + 1n } : hop) }),
  },
  {
    name: 'an amount grows by 1 msat along the path (V10)', step: 'NO_FEASIBLE_ROUTE',
    change: route => ({ ...route, hops: route.hops.map((hop, i) => i === 1 ? { ...hop, amountOutMsat: (route.hops[0]?.amountOutMsat ?? 0n) + 1n } : hop) }),
  },
  {
    // Hops carry 150,000 msat of fee (under the 200,000 cap); the node states 100,000.
    name: 'its stated total fee differs from the fee its hops carry (V10)', step: 'NO_FEASIBLE_ROUTE',
    change: route => ({ ...route, totalFeeMsat: 100_000n, feePpmCeil: 1_000n }),
  },
];

for (const d of routeDefects) {
  it(`CP-029/B4 a live route where ${d.name} cancels with ${d.step} and no mutating call`, async () => {
    const r = await scenario(`defect-${d.step}-${String(routeDefects.indexOf(d))}`, {
      script: base => ({ route: () => d.change(circularRoute(base.sourceKey, base.targetKey, 150_000n, 80), base) }),
    });
    expectCancelled(r, 5, d.step);
    expect(r.row?.route_json).toBeNull();
  });
}

it('CP-029/B4 a target channel that is not ACTIVE in the fresh snapshot cancels with NO_FEASIBLE_ROUTE (V12)', async () => {
  expectCancelled(await scenario('v12-target', {
    script: base => ({ channels: () => [admittedChannel(base, base.sourceKey, OUT_PEER), admittedChannel(base, base.targetKey, IN_PEER, { state: 'INACTIVE', nodeState: 'inactive' })] }),
  }), 5, 'NO_FEASIBLE_ROUTE');
});

it('CP-029/B1 an approval that expires after its proposal is refused at claim (APPROVAL_INVALID), with no row and no node call', async () => {
  // SECURITY §4.1 step 7 / SPEC §7.7: expires_at no later than the proposal's expires_at.
  const r = await scenario('approval-outlives', { proposal: { proposalTtlMs: 300_000, approvalTtlMs: 600_000 } });
  expectRefusedBeforeNode(r, 'APPROVAL_INVALID');
  expect(r.row).toBeUndefined();
});

it('CP-029/B2 the payment hash is write-once: a second write with a different hash is refused and the first hash stays', async () => {
  const p = await loadPersistence();
  const claimModule = await loadClaim();
  const path = scratchDb('hash-once');
  const base = seedBase(p, path);
  const db = p.openDatabase(path, { readOnly: false });
  try {
    const x = preflightWithHash(db, claimModule, base, policyFor(base));
    const row = execById(path, x.executionId);
    expect(row.payment_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(codeOf(() => db.executions.transition(x.executionId, x.fenceEpoch, 'PREFLIGHT', 'PREFLIGHT', { paymentHash: 'cd'.repeat(32) }))).toBe('INVALID_TRANSITION');
    expect(execById(path, x.executionId)).toEqual(row);
  } finally { db.close(); }
});

// Holds the database write lock from another process for a fixed time, as a concurrent writer would.
const LOCKER = `
import { DatabaseSync } from 'node:sqlite';
const db = new DatabaseSync(process.argv[1]);
db.exec('BEGIN IMMEDIATE');
process.stdout.write('locked\\n');
setTimeout(() => { db.exec('COMMIT'); db.close(); process.exit(0); }, Number(process.argv[2]));
`;

it('CP-029/B1 a busy database during preflight never strands the execution in PREFLIGHT with its reservation held (SPEC §6.6)', async () => {
  const p = await loadPersistence();
  const { prepareExecution } = await loadPreflight();
  const path = scratchDb('busy');
  const base = seedBase(p, path);
  const approval = seedProposal(base);
  const policy = policyFor(base);
  const db = p.openDatabase(path, { readOnly: false, busyTimeoutMs: 300 });
  let locker: ReturnType<typeof spawn> | undefined;
  try {
    const fake = new FakePreflightNode(base.sourceKey, base.targetKey, {
      channels: () => [admittedChannel(base, base.sourceKey, OUT_PEER), admittedChannel(base, base.targetKey, IN_PEER)],
      during: {
        // The lock outlives one busy timeout (300 ms) but not two.
        findCircularRoute: () => new Promise<void>((resolve, reject) => {
          const child = spawn(process.execPath, ['--no-warnings', '--input-type=module', '-e', LOCKER, path, '450'],
            { env: childEnv(), shell: false, windowsHide: true, stdio: 'pipe' });
          locker = child;
          let out = '';
          child.stdout.on('data', (chunk: Buffer) => { out += chunk.toString(); if (out.includes('locked')) resolve(); });
          child.once('exit', status => { if (!out.includes('locked')) reject(new Error(`locker exited ${String(status)}`)); });
        }),
      },
    });
    const outcome = await prepareExecution({ db, adapter: fake, workerId: 'worker-a', leaseMs: LEASE }, { approval, policy, approvalKeyIds: APPROVAL_KEYS });
    await new Promise<void>(resolve => { if (locker === undefined || locker.exitCode !== null) resolve(); else locker.once('exit', () => { resolve(); }); });
    const row = execByProposal(path, approval.proposalId);
    if (row === undefined) throw new Error('no execution row');
    const states = reservationsOf(path, row.id).map(x => x.state);
    if (outcome.kind === 'READY') {
      expect(row.status).toBe('PREFLIGHT');
      expect(row.route_json).not.toBeNull();
      expect(row.fence_epoch).toBe(outcome.fenceEpoch);
      expect(states).toEqual(['HELD']);
    } else {
      expect(outcome).toEqual({ kind: 'CANCELLED', executionId: row.id, exit: 8, step: 'internal' });
      expect(row.status).toBe('CANCELLED');
      expect(states).toEqual(['RELEASED']);
    }
    expect(fake.mutatingCalls()).toEqual([]);
  } finally {
    db.close();
    if (locker !== undefined && locker.exitCode === null) locker.kill();
  }
}, 30_000);
