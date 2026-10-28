/*
 * Public operational contract: October 26 audit Additional requirements 1–3,
 * approved D29 before these tests: state backup --out, state restore --from,
 * nodes recover <name>. Expected financial values are the SPEC §9.3 worked
 * rebalance, exercised through the existing recorded CLN fake. No new fake RPCs.
 * Operator procedures use these commands, never the fixture's SQL inspection.
 */
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, readlinkSync, renameSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, relative } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { MUTATING, methodsOf, SELF, startRebalanceCln } from '../fakes/cln/rebalance-node.js';
import { approve, copyDemoFixture, demo, jsonDocument, plan, prepareDemoFixtures, rec, rows, type Demo, type DemoFixtures, type Run } from '../helpers/cpw-cli.js';
import { certificatePath } from '../fakes/https.js';
import { runCli, writeConfig, type NodeEntry } from '../helpers/cp016-cli.js';
import { makeOwnerOnlyDir, expectOwnerOnly } from '../helpers/cp015-persistence.js';
import { declareFixturePaths } from '../helpers/capture-fixture.js';
import { prepareMoneySafetyAlertKey, registerMoneySafetyCredentials } from '../helpers/public-money-safety.js';
import { runPrivateStateCopy } from '../helpers/private-state-copy.js';
import { publishSentinel } from '../helpers/output.js';
import { testRoot } from '../helpers/env.js';

const servers: FakeServer[] = [];
let fixtures: DemoFixtures;
beforeAll(async () => { fixtures = await prepareDemoFixtures(); });
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });

const hash = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
const fingerprint = (path: string): string => hash(readFileSync(path));
const coreTables = ['nodes', 'channels', 'channel_snapshots', 'policy_versions', 'liquidity_proposals', 'approvals',
  'executions', 'execution_events', 'budget_reservations', 'ledger_journals', 'ledger_lines', 'account_balances'];

function inventory(root: string): string[] {
  return readdirSync(root).flatMap(name => {
    const path = join(root, name), info = lstatSync(path);
    if (info.isSymbolicLink()) throw new Error('operational bundle contains a link');
    return info.isDirectory() ? inventory(path) : [path];
  });
}

function book(database: string): Record<string, string> {
  return Object.fromEntries(coreTables.map(table => {
    const values = rows(database, `SELECT * FROM ${table}`)
      .map(row => JSON.stringify(row, (_key, value: unknown) => typeof value === 'bigint' ? value.toString() : value)).sort();
    return [table, hash(Buffer.from(values.join('\n')))];
  }));
}

function privateDir(path: string): void {
  mkdirSync(path, { mode: 0o700 });
  makeOwnerOnlyDir(path);
}

function result(run: Run, code: number): Record<string, unknown> {
  // Do not print arbitrary command output: backup output must never expose key material.
  expect(run.status).toBe(code);
  const doc = jsonDocument(run);
  if (code === 0) expect(doc['error']).toBeNull();
  else expect(rec(doc['error'])['code']).toBe(code);
  return doc;
}

async function backup(d: Demo, label: string): Promise<string> {
  const out = join(d.dir, label);
  result(await runPrivateStateCopy({ operation: 'backup', bundle: out, config: d.config,
    sourcePath: join(dirname(d.database), 'outbox.key'), path: join(out, 'outbox.key') }), 0);
  const files = inventory(out);
  for (const file of files) expectOwnerOnly(file, 'file');
  // Prospective typed output custody supplies SOURCE recognition; copies are never INPUT.
  return out;
}

const nodeEntry = (d: Demo): NodeEntry => ({ name: 'cln-m', implementation: 'cln', url: d.cln.url,
  tlsCert: certificatePath('node'), credential: d.cln.runeFile, expectedPubkey: SELF });

function restoredConfig(d: Demo, label: string, nodes = [nodeEntry(d)]): { config: string; database: string; alertDir: string; state: string } {
  const configDir = join(d.dir, label);
  privateDir(configDir);
  // Destination root is absent. The restore command creates it privately.
  const state = join(configDir, 'state'), database = join(state, 'restored.db'), alertDir = join(state, 'alerts');
  const config = writeConfig(configDir, { database, policy: d.policy, nodes });
  // Approval keys are public; preserve the original configured verification authority.
  writeFileSync(config, `${readFileSync(config, 'utf8')}approval_keys:\n  - key_id: "${d.key.keyId}"\n    public_key: "${d.key.publicKey}"\nalert_dir: "${alertDir.replace(/\\/g, '/')}"\n`);
  return { config, database, alertDir, state };
}

async function fixture(unknown = true): Promise<{ d: Demo; proposal: string; execution: string | null; runId: string }> {
  const d = await demo(servers, { fixtures, fake: { sendpay: unknown ? 'lose-answer' : 'settle' } });
  registerMoneySafetyCredentials([d.key.keyFile, d.cln.runeFile]);
  await prepareMoneySafetyAlertKey(d.database);
  // Independent HMAC oracle from the published signed-effect format: canonical
  // sorted [field,value] pairs. This is an authentic retained alert archive.
  const fields: Record<string, string | number> = { kind: 'stuck-in-flight', idempotencyKey: 'operational-fixture', subject: 'owned-synthetic-attempt',
    state: 'UNKNOWN', raisedAt: Date.now(), suppressed: 0 };
  const pairs = Object.keys(fields).sort().map(key => [key, fields[key]]);
  const hmacSha256 = createHmac('sha256', readFileSync(join(dirname(d.database), 'outbox.key'))).update(JSON.stringify(pairs)).digest('hex');
  writeFileSync(join(d.dir, 'alerts', 'operational-fixture.json'), `${JSON.stringify({ ...fields, hmacSha256 })}\n`, { mode: 0o600 });
  // Produce a real public run record before creating an uncertain attempt.
  const recon = result(await d.run(['--json', 'reconcile', '--node', 'cln-m']), 0);
  const runId = String(rec(recon['result'])['run_id']);
  d.rewrite({ attemptDeadline: '1s' });
  const proposal = String((await plan(d))['proposal_id']);
  await approve(d, proposal);
  if (!unknown) return { d, proposal, execution: null, runId };
  result(await d.run(['--json', 'actions', 'execute', proposal, '--require-regtest']), 7);
  const execution = String(rows(d.database, 'SELECT id FROM executions')[0]?.['id']);
  expect(rows(d.database, 'SELECT status, payment_hash, fence_epoch FROM executions')).toMatchObject([{ status: 'UNKNOWN' }]);
  expect(rows(d.database, 'SELECT state, reserved_msat FROM budget_reservations')).toEqual([{ state: 'HELD', reserved_msat: 300000 }]);
  return { d, proposal, execution, runId };
}

describe('operational state recovery', () => {
  it('CP-044/OPS-B1 a consistent WAL backup restores original hashes, approvals, financial history, run records and signing identity', async () => {
    const { d, execution, runId } = await fixture();
    const sourceRecord = `${d.database}.${runId}.json`;
    const sourceKey = join(dirname(d.database), 'outbox.key');
    // Keep a live connection and disable autocheckpoint: committed WAL-only data must survive.
    const wal = new DatabaseSync(d.database);
    wal.exec('PRAGMA wal_autocheckpoint=0');
    const read = new DatabaseSync(d.database, { readOnly: true });
    read.exec('BEGIN');
    read.prepare('SELECT count(*) FROM channel_snapshots').get();
    try {
      // Fixture-only insertion is a literal SPEC snapshot; no operator SQL procedure is proposed.
      wal.prepare(`INSERT INTO channel_snapshots (channel_id, observed_at, block_height, local_msat, remote_msat,
        spendable_msat, receivable_msat, pending_out_msat, pending_in_msat, pending_htlc_count, confidence, provenance_json)
        SELECT id, 1793000000000, 812, 1880000000, 120000000, 1820000000, 100000000, 0, 0, 0,
        'NODE_REPORTED', '{"operational_fixture":"committed-wal"}' FROM channels LIMIT 1`).run();
      expect(lstatSync(`${d.database}-wal`).size).toBeGreaterThan(0);
      const expected = book(d.database), keyHash = fingerprint(sourceKey), runHash = fingerprint(sourceRecord);
      const out = await backup(d, 'consistent-backup');
      const destination = restoredConfig(d, 'restore-consistent');
      result(await runPrivateStateCopy({ operation: 'restore', bundle: out, config: destination.config,
        sourcePath: join(out, 'outbox.key'), path: join(destination.state, 'outbox.key') }), 0);
      expect(book(destination.database)).toEqual(expected);
      expect(fingerprint(join(dirname(destination.database), 'outbox.key'))).toBe(keyHash);
      expect(fingerprint(`${destination.database}.${runId}.json`)).toBe(runHash);
      expect(rows(destination.database, 'SELECT status FROM executions WHERE id = ?', execution ?? '')).toEqual([{ status: 'UNKNOWN' }]);
      expect(rows(destination.database, 'SELECT state, consumed_msat FROM budget_reservations')).toEqual([{ state: 'HELD', consumed_msat: null }]);
      expect(rows(destination.database, `SELECT count(*) AS n FROM channel_snapshots WHERE provenance_json = '{"operational_fixture":"committed-wal"}'`)).toEqual([{ n: 1 }]);
      const sourceAlerts = inventory(join(d.dir, 'alerts')).map(path => [basename(path), fingerprint(path)]).sort();
      expect(sourceAlerts.length).toBeGreaterThan(0);
      const restoredAlerts = inventory(destination.alertDir).map(path => [basename(path), fingerprint(path)]).sort();
      expect(restoredAlerts).toEqual(sourceAlerts);
      expect(methodsOf(d.cln.fake).filter(method => method === 'sendpay')).toHaveLength(1);
    } finally { read.exec('ROLLBACK'); read.close(); wal.close(); }
  }, 120_000);

  it('CP-044/OPS-B2 restore verifies every payload and refuses an occupied destination without partial financial state', async () => {
    const { d } = await fixture(false);
    const out = await backup(d, 'tamper-backup');
    const keyHash = fingerprint(join(dirname(d.database), 'outbox.key'));
    const keyCopy = inventory(out).find(file => fingerprint(file) === keyHash);
    if (keyCopy === undefined) throw new Error('backup did not retain its signing key');
    const originalIdentity = lstatSync(keyCopy, { bigint: true });
    const destination = restoredConfig(d, 'restore-tamper');
    // The actual product backup remains immutable SECRET_OUTPUT. Build a distinct
    // corrupt INPUT, declaring each exact path before the trusted fixture copy.
    const originalKey = readFileSync(keyCopy), changed = Buffer.from(randomBytes(16).toString('hex'), 'utf8');
    // Printable corruption cannot collapse distinct invalid bytes to the same
    // lossy UTF-8 text; resolve even a coincidental exact printable match.
    if (changed.toString('utf8') === originalKey.toString('utf8')) changed[0] = changed[0] === 0x30 ? 0x31 : 0x30;
    expect(changed.length).toBe(originalKey.length);
    expect(changed.equals(originalKey)).toBe(false);
    expect(changed.toString('utf8') === originalKey.toString('utf8')).toBe(false);
    const sentinelName = `ops-tampered-outbox-${hash(changed)}.bin`;
    publishSentinel(testRoot('FLUXWARDEN_SENTINEL_DIR'), sentinelName, changed);
    const corruptInput = join(d.dir, 'corrupt-input-backup'); privateDir(corruptInput);
    const copies = inventory(out).map(source => ({ source, path: join(corruptInput, relative(out, source)) }));
    declareFixturePaths(copies.map(copy => copy.path));
    for (const copy of copies) {
      mkdirSync(dirname(copy.path), { recursive: true, mode: 0o700 });
      copyDemoFixture(copy.source === keyCopy ? join(testRoot('FLUXWARDEN_SENTINEL_DIR'), sentinelName) : copy.source, copy.path);
    }
    const tampered = await runCli(['--json', 'state', 'restore', '--from', corruptInput, '--config', destination.config]);
    expect([2, 5, 8]).toContain(tampered.status);
    expect(existsSync(destination.database)).toBe(false);
    expect(existsSync(join(destination.state, 'outbox.key'))).toBe(false);
    privateDir(destination.state);
    const retained = join(destination.state, 'operator-owned.txt'); writeFileSync(retained, 'preserve this destination\n');
    const occupied = await runCli(['--json', 'state', 'restore', '--from', out, '--config', destination.config]);
    expect([2, 5]).toContain(occupied.status);
    expect(readFileSync(retained, 'utf8')).toBe('preserve this destination\n');
    expect(existsSync(destination.database)).toBe(false);
    expect(fingerprint(keyCopy)).toBe(keyHash);
    const afterIdentity = lstatSync(keyCopy, { bigint: true });
    expect([afterIdentity.dev, afterIdentity.ino, afterIdentity.mtimeNs, afterIdentity.ctimeNs])
      .toEqual([originalIdentity.dev, originalIdentity.ino, originalIdentity.mtimeNs, originalIdentity.ctimeNs]);
  }, 120_000);

  it('CP-044/OPS-B3 restored authority remains blocked across processes and failed reconciliation; the original hash resolves with one send', async () => {
    const { d, proposal, execution } = await fixture();
    const out = await backup(d, 'authority-backup'), destination = restoredConfig(d, 'restore-authority');
    result(await runPrivateStateCopy({ operation: 'restore', bundle: out, config: destination.config,
      sourcePath: join(out, 'outbox.key'), path: join(destination.state, 'outbox.key') }), 0);
    const before = methodsOf(d.cln.fake).filter(method => MUTATING.includes(method)).length;
    for (let restart = 0; restart < 2; restart += 1) {
      result(await runCli(['--json', 'liquidity', 'approve', proposal, '--key', d.key.keyFile, '--config', destination.config]), 5);
      result(await runCli(['--json', 'actions', 'execute', proposal, '--require-regtest', '--config', destination.config]), 5);
    }
    const failed = await runCli(['--json', 'reconcile', '--config', destination.config]);
    expect([4, 7]).toContain(failed.status);
    result(await runCli(['--json', 'liquidity', 'approve', proposal, '--key', d.key.keyFile, '--config', destination.config]), 5);
    expect(rows(destination.database, 'SELECT status FROM executions WHERE id = ?', execution ?? '')).toEqual([{ status: 'UNKNOWN' }]);
    expect(rows(destination.database, 'SELECT state FROM budget_reservations')).toEqual([{ state: 'HELD' }]);
    expect(methodsOf(d.cln.fake).filter(method => MUTATING.includes(method))).toHaveLength(before);
    d.cln.state.unreachable = false;
    result(await runCli(['--json', 'reconcile', '--config', destination.config]), 0);
    expect(rows(destination.database, 'SELECT status, actual_fee_msat FROM executions WHERE id = ?', execution ?? ''))
      .toEqual([{ status: 'VERIFIED_SUCCESS', actual_fee_msat: 202101 }]);
    expect(rows(destination.database, 'SELECT event_type FROM ledger_journals WHERE execution_id = ? ORDER BY event_type', execution ?? ''))
      .toEqual([{ event_type: 'REBALANCE_SENT' }, { event_type: 'REBALANCE_SETTLED' }]);
    // An approval now reaches ordinary admission and can succeed; each invocation is a fresh process.
    result(await runCli(['--json', 'liquidity', 'approve', proposal, '--key', d.key.keyFile, '--config', destination.config]), 0);
    expect(methodsOf(d.cln.fake).filter(method => method === 'sendpay')).toHaveLength(1);
    const verified = await runCli(['--json', 'ledger', 'verify', '--config', destination.config]); result(verified, 0);
  }, 120_000);

  it('CP-044/OPS-Q1 quarantine recovery rejects replacement identity and preserves original uncertain attempts and fences', async () => {
    const { d } = await fixture();
    d.cln.state.unreachable = false;
    const before = rows(d.database, 'SELECT e.id, e.payment_hash, e.fence_epoch, e.status, r.state FROM executions e JOIN budget_reservations r ON r.execution_id=e.id');
    d.cln.state.id = `02${'d7'.repeat(32)}`;
    result(await d.run(['--json', 'nodes', 'inspect', 'cln-m']), 5);
    const pinned = rows(d.database, 'SELECT id, expected_pubkey, implementation FROM nodes');
    result(await d.run(['--json', 'nodes', 'recover', 'cln-m']), 5);
    expect(rows(d.database, 'SELECT id, expected_pubkey, implementation FROM nodes')).toEqual(pinned);
    expect(rows(d.database, 'SELECT state FROM nodes')).toEqual([{ state: 'QUARANTINED' }]);
    expect(rows(d.database, 'SELECT e.id, e.payment_hash, e.fence_epoch, e.status, r.state FROM executions e JOIN budget_reservations r ON r.execution_id=e.id')).toEqual(before);
    // A config-only replacement cannot invent the original execution's provenance.
    d.rewrite({ node: { name: 'cln-m', url: d.cln.url, runeFile: d.cln.runeFile, expectedPubkey: d.cln.state.id } });
    result(await d.run(['--json', 'nodes', 'recover', 'cln-m']), 5);
    expect(rows(d.database, 'SELECT id, expected_pubkey, implementation FROM nodes')).toEqual(pinned);
    expect(rows(d.database, 'SELECT e.id, e.payment_hash, e.fence_epoch, e.status, r.state FROM executions e JOIN budget_reservations r ON r.execution_id=e.id')).toEqual(before);
    expect(methodsOf(d.cln.fake).filter(method => method === 'sendpay')).toHaveLength(1);
  }, 120_000);

  it('CP-044/OPS-B4 a selected-node reconciliation cannot clear the restored all-node authority barrier', async () => {
    const { d, proposal } = await fixture(false);
    const bravo = await startRebalanceCln(d.dir, servers, { id: `02${'d7'.repeat(32)}` });
    registerMoneySafetyCredentials([bravo.runeFile]);
    const nodes = [nodeEntry(d), { name: 'bravo', implementation: 'cln' as const, url: bravo.url, tlsCert: certificatePath('node'),
      credential: bravo.runeFile, expectedPubkey: bravo.state.id }];
    const originalAlertDirectory = readFileSync(d.config, 'utf8').split(/\r?\n/).find(line => line.startsWith('alert_dir:'));
    if (originalAlertDirectory === undefined) throw new Error('operational fixture has no configured alert directory');
    const sourceConfig = writeConfig(d.dir, { database: d.database, policy: d.policy, nodes });
    // Adding a node must retain the source archive selected by the demo fixture.
    writeFileSync(sourceConfig, `${readFileSync(sourceConfig, 'utf8')}${originalAlertDirectory}\n`);
    result(await runCli(['--json', 'nodes', 'inspect', 'bravo', '--config', sourceConfig]), 0);
    const out = await backup(d, 'all-nodes-backup');
    const destination = restoredConfig(d, 'restore-all-nodes', nodes);
    result(await runPrivateStateCopy({ operation: 'restore', bundle: out, config: destination.config,
      sourcePath: join(out, 'outbox.key'), path: join(destination.state, 'outbox.key') }), 0);
    result(await runCli(['--json', 'reconcile', '--node', 'cln-m', '--config', destination.config]), 0);
    result(await runCli(['--json', 'liquidity', 'approve', proposal, '--key', d.key.keyFile, '--config', destination.config]), 5);
    bravo.state.unreachable = true;
    const incomplete = await runCli(['--json', 'reconcile', '--config', destination.config]);
    expect([4, 7]).toContain(incomplete.status);
    result(await runCli(['--json', 'liquidity', 'approve', proposal, '--key', d.key.keyFile, '--config', destination.config]), 5);
    bravo.state.unreachable = false;
    result(await runCli(['--json', 'reconcile', '--config', destination.config]), 0);
    result(await runCli(['--json', 'liquidity', 'approve', proposal, '--key', d.key.keyFile, '--config', destination.config]), 0);
    expect(methodsOf(d.cln.fake).filter(method => MUTATING.includes(method))).toEqual([]);
    expect(methodsOf(bravo.fake).filter(method => MUTATING.includes(method))).toEqual([]);
  }, 120_000);

  it('CP-044/OPS-B5 backup refuses a lost signing key, existing bundle and linked destination without changing originals', async () => {
    const { d } = await fixture(false);
    await backup(d, 'valid-before-negative-controls');
    // A lost-key control has its own source; the successful backup's retained
    // original must keep its physical lifetime unchanged through closing checks.
    const { d: missingKeyDemo } = await fixture(false);
    const key = join(dirname(missingKeyDemo.database), 'outbox.key'), movedKey = join(dirname(missingKeyDemo.database), 'held-outbox.key');
    declareFixturePaths([movedKey]);
    renameSync(key, movedKey);
    try {
      const missing = await missingKeyDemo.run(['--json', 'state', 'backup', '--out', join(missingKeyDemo.dir, 'missing-key-backup')]);
      expect([2, 5, 8]).toContain(missing.status);
      expect(existsSync(key)).toBe(false);
    } finally { renameSync(movedKey, key); }
    const existing = join(d.dir, 'existing-bundle'); privateDir(existing);
    const original = join(existing, 'preserve.txt'); writeFileSync(original, 'owned-original\n');
    const occupied = await d.run(['--json', 'state', 'backup', '--out', existing]);
    expect([2, 5]).toContain(occupied.status);
    expect(readFileSync(original, 'utf8')).toBe('owned-original\n');
    const linked = join(d.dir, 'linked-bundle');
    symlinkSync(existing, linked, process.platform === 'win32' ? 'junction' : 'dir');
    const created = lstatSync(linked), target = readlinkSync(linked), originalHash = fingerprint(original);
    const provenance: Record<string, unknown> = { case: 'CP-044/OPS-B5', fixture: 'linked-bundle',
      target: 'existing-bundle', createdLink: created.isSymbolicLink(), originalSha256: originalHash };
    try {
      const refused = await d.run(['--json', 'state', 'backup', '--out', linked]);
      provenance['refusalExit'] = refused.status;
      provenance['targetEntriesAfterCommand'] = readdirSync(existing);
      provenance['targetSha256AfterCommand'] = fingerprint(original);
      expect([2, 5]).toContain(refused.status);
      expect(readdirSync(existing)).toEqual(['preserve.txt']);
      expect(fingerprint(original)).toBe(originalHash);
      provenance['assertionsPassed'] = true;
    } finally {
      try {
        // Unlink only this fixture's original directory entry; never recurse into its target.
        const retained = lstatSync(linked);
        if (retained.isSymbolicLink() && retained.dev === created.dev && retained.ino === created.ino && readlinkSync(linked) === target) {
          unlinkSync(linked);
        } else provenance['cleanupRefusedIdentityChange'] = true;
      } finally {
        provenance['linkAbsentAfterCleanup'] = lstatSync(linked, { throwIfNoEntry: false }) === undefined;
        provenance['targetEntriesAfterCleanup'] = readdirSync(existing);
        provenance['targetSha256AfterCleanup'] = fingerprint(original);
        writeFileSync(join(d.dir, 'ops-b5-link-control.json'), `${JSON.stringify(provenance, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
      }
    }
    expect(lstatSync(linked, { throwIfNoEntry: false })).toBeUndefined();
    expect(readdirSync(existing)).toEqual(['preserve.txt']);
    expect(fingerprint(original)).toBe(originalHash);
  }, 120_000);

  it('CP-044/OPS-Q2 corrected original connection recovers quarantine using the retained hash, with monotonic fencing and no resend', async () => {
    const { d, execution } = await fixture();
    d.cln.state.unreachable = false;
    d.cln.state.id = `02${'d7'.repeat(32)}`;
    result(await d.run(['--json', 'nodes', 'inspect', 'cln-m']), 5);
    const before = rows(d.database, 'SELECT id, payment_hash, fence_epoch FROM executions')[0];
    d.cln.state.id = SELF;
    result(await d.run(['--json', 'nodes', 'inspect', 'cln-m']), 0);
    expect(rows(d.database, 'SELECT state FROM nodes')).toEqual([{ state: 'QUARANTINED' }]);
    result(await d.run(['--json', 'nodes', 'recover', 'cln-m']), 0);
    const after = rows(d.database, 'SELECT id, payment_hash, fence_epoch FROM executions')[0];
    expect(after?.['id']).toBe(before?.['id']);
    expect(after?.['payment_hash']).toBe(before?.['payment_hash']);
    expect(Number(after?.['fence_epoch'])).toBeGreaterThanOrEqual(Number(before?.['fence_epoch']));
    expect(rows(d.database, 'SELECT expected_pubkey, implementation, state FROM nodes'))
      .toEqual([{ expected_pubkey: SELF, implementation: 'cln', state: 'ONLINE' }]);
    expect(rows(d.database, 'SELECT status, actual_fee_msat FROM executions WHERE id = ?', execution ?? ''))
      .toEqual([{ status: 'VERIFIED_SUCCESS', actual_fee_msat: 202101 }]);
    expect(rows(d.database, 'SELECT state, consumed_msat FROM budget_reservations'))
      .toEqual([{ state: 'CONSUMED', consumed_msat: 202101 }]);
    expect(methodsOf(d.cln.fake).filter(method => method === 'sendpay')).toHaveLength(1);
    result(await d.run(['--json', 'ledger', 'verify']), 0);
  }, 120_000);
});
