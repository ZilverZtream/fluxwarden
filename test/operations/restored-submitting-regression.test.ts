/*
 * SEC-044-001: D29 requires restored uncertainty to keep admission blocked.
 * A still-live copied lease is not terminal node evidence. Genuine approvals,
 * normal preflight, hash persistence and submit create this state; no SQL writes,
 * clock replacement or lease edits are used. The unchanged public lease is60s.
 * Existing CLN fake answers cite pinned schemas in rebalance-node.ts; this is
 * Docker-free product coverage, not a duplicate-payment or native-node claim.
 */
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { callsOf, methodsOf, MUTATING, SELF } from '../fakes/cln/rebalance-node.js';
import { approve, approvalMessage, bytesOf, demo, plan, prepareDemoFixtures, rec, rows, verifiesWith, type DemoFixtures } from '../helpers/cpw-cli.js';
import { makeOwnerOnlyDir } from '../helpers/cp015-persistence.js';
import { runCli, writeFullConfig } from '../helpers/cpw-cli.js';
import { prepareMoneySafetyAlertKey, registerMoneySafetyCredentials } from '../helpers/public-money-safety.js';
import { runPrivateStateCopy } from '../helpers/private-state-copy.js';
import { publishSentinel } from '../helpers/output.js';
import { testRoot } from '../helpers/env.js';
import { repoRoot } from '../helpers/cli.js';
import type { Msat } from '../../src/core/money.js';
import type { ProposalTerms } from '../../src/approval/types.js';
import type { ExecutionPolicy } from '../../src/core/execution.js';

const servers: FakeServer[] = [];
let fixtures: DemoFixtures;
beforeAll(async () => { fixtures = await prepareDemoFixtures(); });
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });

const publicModule = (name: string): string => pathToFileURL(join(repoRoot, 'dist', name)).href;
const digest = (bytes: Uint8Array | string): string => createHash('sha256').update(bytes).digest('hex');
const retainedTables = ['approvals', 'executions', 'execution_events', 'budget_reservations', 'ledger_journals', 'ledger_lines'];
const retained = (database: string): Record<string, string> => Object.fromEntries(retainedTables.map(table => [table,
  digest(JSON.stringify(rows(database, `SELECT * FROM ${table}`), (_key, value: unknown) => typeof value === 'bigint' ? value.toString() : value))]));

function admission(database: string): Record<string, unknown> {
  const child = spawnSync(process.execPath, [join(repoRoot, 'test/helpers/restored-admission.mjs'), database], {
    cwd: repoRoot, env: process.env, encoding: 'utf8', shell: false, windowsHide: true, timeout: 20_000,
  });
  expect(child.status).toBe(0);
  return rec(JSON.parse(child.stdout) as unknown);
}

async function submitting() {
  const d = await demo(servers, { fixtures });
  registerMoneySafetyCredentials([d.key.keyFile, d.cln.runeFile]);
  await prepareMoneySafetyAlertKey(d.database);
  const proposalId = String((await plan(d))['proposal_id']);
  await approve(d, proposalId);
  const [{ openDatabase }, { configStage }, { activePolicy, controller }, { handshake }, { resolveConnection },
    { verifiedStoredApproval }, { policySha256 }, { prepareExecution }] = await Promise.all([
    import(publicModule('persistence/index.js')) as Promise<typeof import('../../src/persistence/index.js')>,
    import(publicModule('commands/stages.js')) as Promise<typeof import('../../src/commands/stages.js')>,
    import(publicModule('commands/workflow.js')) as Promise<typeof import('../../src/commands/workflow.js')>,
    import(publicModule('commands/handshake.js')) as Promise<typeof import('../../src/commands/handshake.js')>,
    import(publicModule('cli/connect.js')) as Promise<typeof import('../../src/cli/connect.js')>,
    import(publicModule('approval/verify.js')) as Promise<typeof import('../../src/approval/verify.js')>,
    import(publicModule('policy/canonical.js')) as Promise<typeof import('../../src/policy/canonical.js')>,
    import(publicModule('executor/preflight.js')) as Promise<typeof import('../../src/executor/preflight.js')>,
  ]);
  const db = openDatabase(d.database, { readOnly: false, mustExist: true });
  try {
    const config = configStage(d.config), policy = activePolicy(config), proposal = db.proposals.find(proposalId.replace(/^prop_/, ''));
    if (!proposal || proposal.sourceChannelKey === null || proposal.targetChannelKey === null || proposal.principalMsat === null ||
        proposal.maxFeeMsat === null || proposal.maxFeePpm === null || proposal.maxCltvDelta === null) throw new Error('public approved rebalance missing');
    const terms: ProposalTerms = { id: proposal.id, nodePubkey: proposal.nodePubkey, sourceChannelKey: proposal.sourceChannelKey,
      targetChannelKey: proposal.targetChannelKey, principalMsat: proposal.principalMsat as Msat, maxFeeMsat: proposal.maxFeeMsat as Msat,
      maxFeePpm: proposal.maxFeePpm, exemptFeeMsat: policy.fees.exempt_fee_msat, maxCltvDelta: proposal.maxCltvDelta,
      policySha256: proposal.policySha256, expiresAt: proposal.expiresAt };
    const stored = db.commandData.approvals.listByProposal(proposal.id)[0];
    if (!stored) throw new Error('CLI approval missing');
    const nonce = bytesOf(stored.nonce, 32), signature = bytesOf(stored.signature, 64);
    if (!nonce || !signature) throw new Error('CLI approval encoding invalid');
    // Independent Ed25519 verification of the actual CLI approval (SECURITY §4.1).
    expect(verifiesWith(d.key.publicKey, approvalMessage({ digest: proposal.digest, policySha256: proposal.policySha256,
      maxFeeMsat: stored.max_fee_msat, maxCltvDelta: stored.max_cltv_delta, expiresAt: BigInt(stored.expires_at), nonce, keyId: stored.key_id }), signature)).toBe(true);
    const approval = verifiedStoredApproval({ keys: config.approvalKeys, proposal: terms, now: db.now(),
      policy: { sha256: policySha256(policy), maxFeeMsat: policy.fees.max_fee_msat, maxCltvDelta: policy.routing.max_cltv_delta,
        approvalMaxTtlSeconds: policy.approval_max_ttl, maxSnapshotAgeSeconds: policy.max_snapshot_age } }, db.commandData.approvals);
    const node = config.nodes.find(entry => entry.name === 'cln-m'); if (!node) throw new Error('owned node missing');
    const session = await handshake(db, node, resolveConnection(node, {}, {}));
    const native = await controller(node, config, session, db);
    const executionPolicy: ExecutionPolicy = { sha256: policySha256(policy), network: policy.network,
      maxFeeMsat: policy.fees.max_fee_msat, maxFeePpm: BigInt(policy.fees.max_fee_ppm), exemptFeeMsat: policy.fees.exempt_fee_msat,
      maxCltvDelta: policy.routing.max_cltv_delta, minChannelReserveMsat: policy.amounts.min_channel_reserve_msat,
      budget: { msat: policy.budget.msat, periodMs: policy.budget.period * 1000 },
      cooldownAfterFailureMs: policy.cooldown_after_failure * 1000, cooldownAfterSuccessMs: policy.cooldown_after_success * 1000,
      maxInFlight: policy.max_in_flight, maxSnapshotAgeMs: policy.max_snapshot_age * 1000, excludeChannels: policy.exclude_channels };
    const ready = await prepareExecution({ db, adapter: native.adapter, workerId: 'original-submitting-owner', leaseMs: 60_000 },
      { approval, policy: executionPolicy, approvalKeyIds: config.approvalKeys.map(key => key.keyId) });
    if (ready.kind !== 'READY') throw new Error('normal public preflight refused valid fixture');
    const preimage = randomBytes(32), paymentHash = digest(preimage);
    publishSentinel(testRoot('FLUXWARDEN_SENTINEL_DIR'), `restored-submitting-${paymentHash}.bin`, preimage);
    const epoch = db.executions.transition(ready.executionId, ready.fenceEpoch, 'PREFLIGHT', 'PREFLIGHT',
      { paymentHash, plannedFeeMsat: 202_101n });
    const invoice = await native.adapter.createInvoice(100_000_000n, preimage, `fw-${ready.executionId}`, 3600);
    expect(invoice.paymentHash).toBe(paymentHash);
    const beforeSubmit = db.now();
    const submitted = db.executions.submit(ready.executionId, epoch, executionPolicy.maxInFlight, 60_000,
      { baseline: { sourceLocalMsat: 1_880_000_000n, targetLocalMsat: 400_000_000n } }, executionPolicy);
    expect(submitted.status).toBe('SUBMITTING');
    const view = db.executions.view(ready.executionId); if (!view) throw new Error('submitted intent missing');
    expect(view.status).toBe('SUBMITTING'); expect(view.paymentHash).toBe(paymentHash);
    expect(view.leaseExpiresAt).toBeGreaterThan(db.now());
    expect(view.leaseExpiresAt).toBeGreaterThanOrEqual(beforeSubmit + 60_000);
    expect(view.leaseExpiresAt).toBeLessThanOrEqual(db.now() + 60_000);
    expect(rows(d.database, 'SELECT state,reserved_msat,consumed_msat FROM budget_reservations'))
      .toEqual([{ state: 'HELD', reserved_msat: 300000, consumed_msat: null }]);
    // The actual transitions own journal publication. Preserve their output
    // unchanged; never manufacture a SENT entry just to make a fixture pass.
    expect((await d.run(['--json', 'ledger', 'verify'])).status).toBe(0);
    const originalHistory = retained(d.database);
    expect(callsOf(d.cln.fake, 'sendpay')).toHaveLength(0);
    return { d, db, executionId: ready.executionId, proposalId, paymentHash, originalHistory, view,
      settleOriginal: () => native.adapter.sendOnRoute(ready.route, paymentHash, invoice.paymentSecret, undefined, `fw-${ready.executionId}`) };
  } catch (error) { db.close(); throw error; }
}

async function restore(fixture: Awaited<ReturnType<typeof submitting>>) {
  const { d } = fixture, out = join(d.dir, 'backup'), destination = join(d.dir, 'destination');
  expect((await runPrivateStateCopy({ operation: 'backup', bundle: out, config: d.config,
    sourcePath: join(dirname(d.database), 'outbox.key'), path: join(out, 'outbox.key') })).status).toBe(0);
  mkdirSync(destination, { mode: 0o700 }); makeOwnerOnlyDir(destination);
  const database = join(destination, 'state', 'restored.db'), alertDir = join(dirname(database), 'alerts');
  const config = writeFullConfig(destination, { database, alertDir, policy: d.policy,
    node: { name: 'cln-m', url: d.cln.url, runeFile: d.cln.runeFile, expectedPubkey: SELF }, approvalKeys: [d.key] });
  expect((await runPrivateStateCopy({ operation: 'restore', bundle: out, config,
    sourcePath: join(out, 'outbox.key'), path: join(dirname(database), 'outbox.key') })).status).toBe(0);
  expect(retained(database)).toEqual(fixture.originalHistory);
  const restored = rows(database, 'SELECT status,payment_hash,fence_epoch,lease_expires_at FROM executions')[0];
  expect(restored).toMatchObject({ status: 'SUBMITTING', payment_hash: fixture.paymentHash,
    fence_epoch: Number(fixture.view.fenceEpoch), lease_expires_at: fixture.view.leaseExpiresAt });
  expect(Number(restored?.['lease_expires_at'])).toBeGreaterThan(fixture.db.now());
  expect(admission(database)).toEqual({ admitted: false, code: 'RESTORE_PENDING' });
  return { database, config };
}

describe('restored live SUBMITTING ownership', () => {
  it('CP-044/SEC-044-001 restored live SUBMITTING cannot clear admission through a zero-work full reconcile; conclusive same-hash recovery never resends', async () => {
    const f = await submitting();
    try {
      const destination = await restore(f), beforeCalls = methodsOf(f.d.cln.fake).filter(method => MUTATING.includes(method));
      const reconciled = await runCli(['--json', 'reconcile', '--config', destination.config]);
      expect([0, 5, 7]).toContain(reconciled.status);
      expect(rows(destination.database, 'SELECT payment_hash FROM executions')).toEqual([{ payment_hash: f.paymentHash }]);
      expect(rows(destination.database, 'SELECT state,consumed_msat FROM budget_reservations')).toEqual([{ state: 'HELD', consumed_msat: null }]);
      expect(methodsOf(f.d.cln.fake).filter(method => MUTATING.includes(method))).toEqual(beforeCalls);
      // Each observation uses a new OS process. A green accounting pass alone
      // cannot grant authority while copied live execution ownership is unresolved.
      expect(admission(destination.database)).toEqual({ admitted: false, code: 'RESTORE_PENDING' });
      expect(admission(destination.database)).toEqual({ admitted: false, code: 'RESTORE_PENDING' });
      expect((await runCli(['--json', 'liquidity', 'approve', f.proposalId, '--key', f.d.key.keyFile, '--config', destination.config])).status).toBe(5);
      expect((await runCli(['--json', 'actions', 'execute', f.proposalId, '--require-regtest', '--config', destination.config])).status).toBe(5);
      // The original owner supplies exactly one original-hash send; restored
      // reconciliation is never the actor that sends or creates another invoice.
      await f.settleOriginal();
      while (f.db.now() <= (f.view.leaseExpiresAt ?? 0)) await new Promise<void>(accept => { setTimeout(accept, 100); });
      const recovered = await runCli(['--json', 'reconcile', '--config', destination.config]);
      expect(recovered.status).toBe(0);
      expect(rows(destination.database, 'SELECT status,payment_hash,actual_fee_msat FROM executions'))
        .toEqual([{ status: 'VERIFIED_SUCCESS', payment_hash: f.paymentHash, actual_fee_msat: 202101 }]);
      expect(rows(destination.database, 'SELECT state,consumed_msat FROM budget_reservations')).toEqual([{ state: 'CONSUMED', consumed_msat: 202101 }]);
      expect(admission(destination.database)).toEqual({ admitted: true });
      expect(callsOf(f.d.cln.fake, 'sendpay')).toHaveLength(1);
      expect(callsOf(f.d.cln.fake, 'invoice')).toHaveLength(1);
      expect((await runCli(['--json', 'ledger', 'verify', '--config', destination.config])).status).toBe(0);
    } finally { f.db.close(); }
  }, 120_000);

  it('CP-044/SEC-044-001-quarantine corrected original pin cannot lift quarantine or restored admission while copied SUBMITTING remains unresolved', async () => {
    const f = await submitting();
    try {
      const destination = await restore(f);
      f.d.cln.state.id = `02${'d7'.repeat(32)}`;
      expect((await runCli(['--json', 'nodes', 'inspect', 'cln-m', '--config', destination.config])).status).toBe(5);
      f.d.cln.state.id = SELF;
      const before = retained(destination.database), events = rows(destination.database, 'SELECT * FROM execution_events');
      const beforeCalls = methodsOf(f.d.cln.fake).filter(method => MUTATING.includes(method));
      const recovered = await runCli(['--json', 'nodes', 'recover', 'cln-m', '--config', destination.config]);
      expect([5, 7]).toContain(recovered.status);
      expect(rows(destination.database, 'SELECT state,expected_pubkey FROM nodes')).toEqual([{ state: 'QUARANTINED', expected_pubkey: SELF }]);
      expect(rows(destination.database, 'SELECT payment_hash FROM executions')).toEqual([{ payment_hash: f.paymentHash }]);
      expect(rows(destination.database, 'SELECT state,consumed_msat FROM budget_reservations')).toEqual([{ state: 'HELD', consumed_msat: null }]);
      const after = retained(destination.database);
      for (const table of ['approvals', 'ledger_journals', 'ledger_lines']) expect(after[table]).toBe(before[table]);
      const afterEvents = rows(destination.database, 'SELECT * FROM execution_events');
      for (const event of events) expect(afterEvents).toContainEqual(event);
      expect(Number(rows(destination.database, 'SELECT fence_epoch FROM executions')[0]?.['fence_epoch'])).toBeGreaterThanOrEqual(Number(f.view.fenceEpoch));
      expect(admission(destination.database)).toEqual({ admitted: false, code: 'RESTORE_PENDING' });
      expect(methodsOf(f.d.cln.fake).filter(method => MUTATING.includes(method))).toEqual(beforeCalls);
      expect(callsOf(f.d.cln.fake, 'sendpay')).toHaveLength(0);
    } finally { f.db.close(); }
  }, 120_000);
});
