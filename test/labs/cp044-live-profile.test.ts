// These injected artifact controls prove producer custody/refusal only. They are
// never accepted as a live run, native observation or completed validation plan.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { assertChaosPlan, assertCurrentBinding, assertPlannerCapture, capturePlanner, classifyFirstHop, frozenChaosPolicy, independentPolicyHash, measureValidation, readCurrentBinding, readRetainedDemoRuntime, retainDemoHandoff, setRunner, type Native } from '../../labs/scenarios/live-profile.mjs';
import { scratch } from '../helpers/cp016-cli.js';

const sourceCommit = 'a'.repeat(40);
function fixture() {
  const root = scratch('live-profile-controls'), ownerPath = join(root, 'owner.json');
  const owner = { id: 'control', project: 'fluxwarden-lab-control', runtimeRoot: join(root, 'runtime'), tmpRoot: join(root, 'tmp'), evidenceRoot: join(root, 'evidence'), sentinelRoot: join(root, 'sentinels'), ports: { lndRest: 31001, clnRest: 31002, toxiproxy: 31003 } };
  for (const dir of [owner.runtimeRoot, owner.tmpRoot, owner.evidenceRoot, owner.sentinelRoot]) mkdirSync(dir);
  const nodes = Object.fromEntries(['lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m'].map((name, index) => [name, { network: 'regtest', pubkey: `02${String(index + 1).repeat(64)}`, version: name.startsWith('lnd') ? '0.21.4-beta' : 'v26.06.9' }]));
  const manifest = { ownerId: owner.id, project: owner.project, ports: owner.ports, nodes };
  writeFileSync(ownerPath, JSON.stringify(owner)); writeFileSync(join(owner.runtimeRoot, 'lab.json'), JSON.stringify(manifest));
  return { root, ownerPath, owner, manifest };
}

it('CP-044/LP-B startup-bound captures reject prior manifest and changed artifact bytes', () => {
  const f = fixture(), binding = readCurrentBinding(f.ownerPath, sourceCommit);
  expect(() => { assertCurrentBinding(binding, f.ownerPath, sourceCommit); }).not.toThrow();
  writeFileSync(join(f.owner.runtimeRoot, 'lab.json'), JSON.stringify({ ...f.manifest, freshStartup: 'second' }));
  expect(() => { assertCurrentBinding(binding, f.ownerPath, sourceCommit); }).toThrow(/stale/);
  expect(() => { assertCurrentBinding(binding, f.ownerPath, 'b'.repeat(40)); }).toThrow(/stale/);
});

it('CP-044/LP-B measured boundary admits conservative gaps and retains unsafe declarations as REFERENCE_CONFLICT', () => {
  const f = fixture();
  let nativeAccepted = 990005n, pinnedCliShape = true;
  const native: Native = (service, args) => {
    let answer: unknown;
    if (service === 'bitcoind') answer = 150;
    else if (args[0] === 'getinfo') answer = service === 'lnd-r' ? { block_height: 150, identity_pubkey: f.manifest.nodes['lnd-r']?.pubkey } : { blockheight: 150, id: f.manifest.nodes['cln-m']?.pubkey };
    else if (args[0] === 'listchannels') answer = { channels: [{ chan_id: pinnedCliShape ? 'a'.repeat(64) : '123', ...(pinnedCliShape ? { scid: '123' } : {}), remote_pubkey: f.manifest.nodes['cln-m']?.pubkey, local_balance: '1000', local_constraints: { chan_reserve_sat: '10' }, initiator: false, pending_htlcs: [] }] };
    else if (args[0] === 'listpeerchannels') answer = { channels: [{ short_channel_id: '1x2x3', spendable_msat: 1000, receivable_msat: 2000, htlcs: [] }] };
    else {
      const envelope = JSON.parse(args[args.indexOf('--routes') + 1] ?? '{}') as { route: { hops: { mpp_record: unknown }[]; total_amt_msat: string } };
      expect(envelope.route.hops[0]?.mpp_record).toBeDefined();
      const accepted = BigInt(envelope.route.total_amt_msat) <= nativeAccepted;
      answer = { status: 'FAILED', failure: { failure_source_index: accepted ? 1 : 0, code: accepted ? 'INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS' : 'TEMPORARY_CHANNEL_FAILURE' } };
    }
    return { exitCode: 0, stdout: JSON.stringify(answer), stderr: '' };
  };
  const observed = capturePlanner({ ownerPath: f.ownerPath, sourceCommit, native });
  expect(JSON.parse(readFileSync(join(observed.captureDir, 'lnd-r/spendable-probe.json'), 'utf8')) as unknown).toEqual([{ chan_id: '123', accepted_msat: '990005', refused_msat: '990006' }]);
  expect(observed.referenceConflicts).toEqual([]);
  const receipt = JSON.parse(readFileSync(observed.receiptPath, 'utf8')) as { observations: unknown[] };
  expect(receipt.observations).toContainEqual({ chan_id: '123', amount_msat: '990000', status: 'FAILED', failure: { code: 'INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS', failure_source_index: 1 }, outcome: 'accepted' });
  expect(receipt.observations).toContainEqual({ chan_id: '123', amount_msat: '990001', status: 'FAILED', failure: { code: 'INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS', failure_source_index: 1 }, outcome: 'accepted' });
  expect(() => assertPlannerCapture(observed.captureDir, f.ownerPath, sourceCommit)).not.toThrow();
  writeFileSync(join(observed.captureDir, 'lnd-r/listchannels.json'), '{}');
  expect(() => assertPlannerCapture(observed.captureDir, f.ownerPath, sourceCommit)).toThrow(/hash mismatch/);
  // Keep the original decimal-only fixture as a separate legacy control.
  pinnedCliShape = false;
  const legacy = capturePlanner({ ownerPath: f.ownerPath, sourceCommit, native });
  expect(JSON.parse(readFileSync(join(legacy.captureDir, 'lnd-r/spendable-probe.json'), 'utf8')) as unknown).toEqual([{ chan_id: '123', accepted_msat: '990005', refused_msat: '990006' }]);
  nativeAccepted = 989999n;
  expect(() => capturePlanner({ ownerPath: f.ownerPath, sourceCommit, native })).toThrow(/REFERENCE_CONFLICT.*declared conservative spendable refused/);
});

it('CP-044/LP-B only pinned remote unknown-hash or local first-hop refusals classify a native boundary', () => {
  expect(classifyFirstHop({ status: 'FAILED', failure: { failure_source_index: 1, code: 'INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS' } })).toBe('accepted');
  expect(classifyFirstHop({ status: 'FAILED', failure: { failure_source_index: 0, code: 'TEMPORARY_CHANNEL_FAILURE' } })).toBe('refused');
  for (const attempt of [{ status: 'SUCCEEDED' }, { status: 'FAILED', failure: { failure_source_index: 1, code: 'TEMPORARY_NODE_FAILURE' } }, { status: 'FAILED', failure: { failure_source_index: 2, code: 'INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS' } }]) expect(() => classifyFirstHop(attempt)).toThrow(/probe|outcome/);
});

it('CP-044/LP-B retained original runtime survives ordinary cleanup and rejects altered bytes or owner facts', () => {
  const f = fixture(), bundle = join(f.owner.evidenceRoot, 'bundle'); mkdirSync(bundle);
  const files = ['actualT05Path', 'nativeHistoryPath', 'verificationPath'] as const;
  const inputs = Object.fromEntries(files.map(name => { const file = join(f.owner.evidenceRoot, `${name}.json`); writeFileSync(file, '{}'); return [name, file]; })) as Record<typeof files[number], string>;
  const original = readFileSync(join(f.owner.runtimeRoot, 'lab.json'));
  const retained = retainDemoHandoff({ ownerPath: f.ownerPath, sourceCommit, bundle, ...inputs });
  expect(readFileSync(retained.runtimeManifest.file)).toEqual(original);
  const handoff = JSON.parse(readFileSync(retained.handoffPath, 'utf8')) as Record<string, unknown>;
  rmSync(join(f.owner.runtimeRoot, 'lab.json'));
  expect(readRetainedDemoRuntime(handoff).runtime['project']).toBe(f.owner.project);
  writeFileSync(retained.runtimeManifest.file, `${original.toString('utf8')} `);
  expect(() => readRetainedDemoRuntime(handoff)).toThrow(/hash mismatch/);
  writeFileSync(retained.runtimeManifest.file, original);
  writeFileSync(f.ownerPath, JSON.stringify({ ...f.owner, project: 'fluxwarden-lab-other' }));
  expect(() => readRetainedDemoRuntime(handoff)).toThrow(/owner binding mismatch/);
});

it('CP-044/LP-B independent current-channel policy hash retains every frozen monetary and routing cap', () => {
  const f = fixture(), targets = { 'cln-m': { '150x1x0': { min_inbound_msat: '105000000' }, '150x2x0': { min_inbound_msat: '0' } } };
  const policy = frozenChaosPolicy(targets);
  // SPEC 7.1 plus walkthrough.json's explicit cooldown before any planning.
  expect(policy).toMatchObject({ fees: { max_fee_msat: '300000', max_fee_ppm: 2500, exempt_fee_msat: '5000' }, routing: { max_cltv_delta: 144 }, amounts: { min_channel_reserve_msat: '50000000', max_principal_msat: '100000000', min_principal_msat: '10000000' }, budget: { msat: '2000000', period: 86400 }, cooldown_after_failure: 3600, cooldown_after_success: 1, max_in_flight: 1, max_snapshot_age: 60, proposal_ttl: 900, approval_max_ttl: 900, targets });
  expect(independentPolicyHash({ z: 1, a: { b: '2', a: 3 } })).toBe(createHash('sha256').update('{"a":{"a":3,"b":"2"},"z":1}').digest('hex'));
  expect(independentPolicyHash(policy)).not.toBe(independentPolicyHash(frozenChaosPolicy({ 'cln-m': { '151x1x0': { min_inbound_msat: '105000000' } } })));
  for (const [section, field, value] of [['fees', 'max_fee_msat', '300001'], ['amounts', 'max_principal_msat', '100000001'], ['budget', 'msat', '2000001'], ['routing', 'max_cltv_delta', 145]] as const) {
    const changed = { ...policy, [section]: { ...(policy[section] as Record<string, unknown>), [field]: value } };
    expect(() => { assertChaosPlan({ binding: readCurrentBinding(f.ownerPath, sourceCommit), owner: f.ownerPath, policyDocument: changed }); }).toThrow(/frozen chaos safety cap/);
  }
});

it('CP-044/LP-B failed real subprocess retains failure cleanup and leak observations without publishing an R6 plan', async () => {
  const f = fixture(), calls: string[][] = [];
  setRunner((file, args, options) => { calls.push(args); return spawnSync(file, args, options); });
  const invalidSource = join(f.root, 'invalid-build.js'); writeFileSync(invalidSource, 'const = ;');
  const command = [process.execPath, '--version'];
  const input = { sourceRoot: f.root, sourceSha256: 'a'.repeat(64), invocation: 'failed-subprocess-control', evidenceRoot: f.owner.evidenceRoot, selection: [{ file: 'selected.test.ts', fullName: 'CP-010/R1 selected control' }], collectedAt: Date.now(), commands: { build: [process.execPath, '--check', invalidSource], setup: command, run: [{ argv: command, report: 'never-created.json' }], teardown: command, leak: command } };
  await expect(measureValidation(input)).rejects.toThrow(/original measured subprocess failed/);
  expect(calls.map(args => args[0])).toEqual(['--check', '--version', '--version']);
  expect(existsSync(join(f.owner.evidenceRoot, 'validation-plan.json'))).toBe(false);
  const observed = JSON.parse(readFileSync(join(f.owner.evidenceRoot, 'observations.json'), 'utf8')) as { commands: { phase: string; exitCode: number }[] };
  expect(observed.commands.map(value => value.phase)).toEqual(['build', 'teardown', 'leak']);
  expect(observed.commands[0]?.exitCode).not.toBe(0);
  await expect(measureValidation({ ...input, selection: [{ file: 'selected.test.ts', fullName: 'CP-006/R6 still running' }] })).rejects.toThrow(/excluding R6/);
  expect(calls).toHaveLength(3);
});
