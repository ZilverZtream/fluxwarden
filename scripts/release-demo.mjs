// Execute the public walkthrough against a fresh explicitly owned regtest lab.
// Key generation uses the existing prospective output authorization and CLI.
import fs from 'node:fs';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { prepareOwnedLive, startOwnedLive, stopOwnedLive } from './release-live.mjs';
import { authorizeSecretOutput } from './ci-secret-output.mjs';
import { findLeaks } from './leak-check.mjs';
import { retainDemoHandoff } from '../labs/scenarios/live-profile.mjs';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const check = value => { if (!value) throw new Error('release demo: observed proof unavailable'); };
function command(executable, args, timeout = 180_000) {
  const result = spawnSync(executable, args, { env: process.env, cwd: process.cwd(), windowsHide: true, timeout, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  check(!result.error && result.signal === null && result.status === 0); return result.stdout;
}
const yaml = (value, depth = 0) => Object.entries(value).map(([key, child]) => `${' '.repeat(depth)}${JSON.stringify(key)}:${child && typeof child === 'object' && !Array.isArray(child) ? '\n' + yaml(child, depth + 2) : ' ' + JSON.stringify(child) + '\n'}`).join('');
export async function produceDemo(ctx) {
  const previousEnvironment = { ...process.env };
  const prepared = await prepareOwnedLive(process.env.FLUXWARDEN_CI_TMP_PARENT ?? process.env.TEMP, ctx.sourceCommit); Object.assign(process.env, prepared.environment);
  const plan = JSON.parse(fs.readFileSync(prepared.path, 'utf8')), owner = plan.owner;
  let started = false;
  try {
    await startOwnedLive(); started = true;
    const manifest = JSON.parse(fs.readFileSync(join(owner.runtimeRoot, 'lab.json'), 'utf8'));
    const key = join(plan.directory, 'operator.key'), bin = resolve('dist/cli/bin.js');
    const keyArgs = [bin, '--json', 'keys', 'generate', '--out', key];
    await authorizeSecretOutput({ path: key, command: process.execPath, args: keyArgs });
    const publicKey = JSON.parse(command(process.execPath, keyArgs)).result;
    check(publicKey && typeof publicKey.public_key === 'string' && /^[a-f0-9]{32}$/.test(publicKey.key_id));
    const policyPath = join(plan.directory, 'policy.yaml'), config = join(plan.directory, 'config.yaml'), database = join(plan.directory, 'state', 'fluxwarden.db');
    const native = args => JSON.parse(command('docker', ['exec', `${owner.project}-cln-m-1`, 'lightning-cli', '--network=regtest', '-k', ...args], 30_000));
    const channels = native(['listpeerchannels']).channels; check(Array.isArray(channels) && channels.length === 2);
    const policy = { version: 3, network: 'regtest', fees: { max_fee_msat: '300000', max_fee_ppm: 2500, exempt_fee_msat: '0' }, routing: { max_cltv_delta: 144 },
      amounts: { min_channel_reserve_msat: '10000000', max_principal_msat: '100000000', min_principal_msat: '1000000' }, budget: { msat: '1000000', period: '1h' },
      cooldown_after_failure: '1h', cooldown_after_success: '1s', max_in_flight: 1, max_snapshot_age: '30s', proposal_ttl: '5m', approval_max_ttl: '5m',
      demand: { mode: 'targets', horizon: '1h', burst_factor: '1.4', ewma: { bucket_seconds: 60, alpha: '0.25', min_samples: 5 } },
      targets: { 'cln-m': Object.fromEntries(channels.map(channel => [channel.short_channel_id, { min_inbound_msat: '0' }])) } };
    fs.writeFileSync(policyPath, yaml(policy), { mode: 0o600, flag: 'wx' });
    fs.writeFileSync(config, `database: ${JSON.stringify(database)}\npolicy: ${JSON.stringify(policyPath)}\ncollect_interval: 15s\nattempt_deadline: 120s\nescalate_after: 1h\ndelta_tolerance_msat: "0"\napproval_keys:\n  - key_id: ${publicKey.key_id}\n    public_key: ${JSON.stringify(publicKey.public_key)}\nnodes:\n  - name: cln-m\n    implementation: cln\n    url: https://localhost:${owner.ports.clnRest}\n    tls_cert_path: ${JSON.stringify(manifest.nodes['cln-m'].certificate.path)}\n    rune_path: ${JSON.stringify(manifest.credentials['cln-m'].execute.path)}\n    expected_pubkey: ${JSON.stringify(manifest.nodes['cln-m'].pubkey)}\n    expected_network: regtest\n`, { mode: 0o600, flag: 'wx' });
    process.env.FLUXWARDEN_DEMO_POLICY = policyPath;
    const doctor = JSON.parse(command(process.execPath, [bin, 'doctor', '--config', config, '--json'])); check(doctor.ok === true);
    const bundle = join(plan.directory, 'bundle');
    // Each public phase retains its original 180-second bound. The walkthrough
    // itself owns six independent phase timers; no widened phase cap is passed.
    const child = spawnSync(process.execPath, ['scripts/reproduce-demo.mjs', '--config', config, '--key', key, '--out', bundle], { env: process.env, windowsHide: true, stdio: 'inherit' });
    check(!child.error && child.signal === null && child.status === 0);
    const ledger = JSON.parse(command(process.execPath, [bin, 'ledger', 'verify', '--config', config, '--json'])); check(ledger.ok === true);
    const checksums = fs.readFileSync(join(bundle, 'checksums.sha256'), 'utf8').trim().split('\n'); check(checksums.length === 8);
    for (const line of checksums) { const match = /^([a-f0-9]{64}) {2}([a-z][a-z.-]+)$/.exec(line); check(match && hash(fs.readFileSync(join(bundle, match[2]))) === match[1]); }
    const observations = fs.readdirSync(owner.evidenceRoot).filter(name => /^demo-T-05-[a-f0-9]{64}\.json$/.test(name)); check(observations.length === 1);
    const actualT05Path = join(owner.evidenceRoot, observations[0]);
    const actual = JSON.parse(fs.readFileSync(actualT05Path, 'utf8'));
    check(actual.caseId === 'T-05' && actual.exit === 7 && actual.status === 'UNKNOWN' && actual.sendCount === 1 && /^[a-f0-9]{64}$/.test(actual.paymentHash));
    const db = new DatabaseSync(database, { readOnly: true });
    let executions;
    try {
      executions = db.prepare('SELECT id, status, payment_hash FROM executions WHERE payment_hash = ?').all(actual.paymentHash);
      check(executions.length === 1 && executions[0].status === 'VERIFIED_SUCCESS');
      const transitions = db.prepare('SELECT from_status, to_status FROM execution_events WHERE execution_id = ?').all(executions[0].id);
      check(transitions.some(row => row.to_status === 'UNKNOWN') && transitions.some(row => row.from_status === 'UNKNOWN' && row.to_status === 'VERIFIED_SUCCESS'));
    } finally { db.close(); }
    const payments = native(['listsendpays', `payment_hash=${actual.paymentHash}`]).payments;
    check(Array.isArray(payments) && payments.length === 1 && payments[0].status === 'complete');
    const resources = [];
    for (const service of ['bitcoind', 'lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m', 'toxiproxy']) {
      const ids = command('docker', ['ps', '-q', '--filter', `label=com.docker.compose.project=${owner.project}`, '--filter', `label=com.docker.compose.service=${service}`]).trim().split(/\s+/).filter(Boolean);
      check(ids.length === 1);
      const inspected = JSON.parse(command('docker', ['inspect', ids[0]])); check(inspected.length === 1);
      const observed = inspected[0], labels = observed.Config.Labels;
      const pin = manifest.images[service.split('-')[0]].reference;
      check(labels['com.docker.compose.project'] === owner.project && labels['com.docker.compose.service'] === service && observed.Config.Image === pin && observed.State.Running === true);
      resources.push({ service, project: labels['com.docker.compose.project'], image: observed.Config.Image });
    }
    const records = [];
    for (const node of ['lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m']) {
      const args = node.startsWith('lnd-') ? ['lncli', '--network=regtest', 'listpayments', '--max_payments', '1000'] : ['lightning-cli', '--network=regtest', '-k', 'listsendpays'];
      const history = JSON.parse(command('docker', ['exec', `${owner.project}-${node}-1`, ...args])).payments;
      check(Array.isArray(history));
      records.push({ node, payments: history.map(payment => {
        const paymentHash = payment.payment_hash, preimage = payment.payment_preimage;
        check(typeof paymentHash === 'string' && /^[a-f0-9]{64}$/.test(paymentHash));
        return { paymentHash, status: payment.status, preimageMatchesHash: typeof preimage === 'string' && hash(Buffer.from(preimage, /^[a-f0-9]{64}$/i.test(preimage) ? 'hex' : 'base64')) === paymentHash };
      }) });
    }
    const matching = records.find(record => record.node === 'cln-m').payments.filter(payment => payment.paymentHash === actual.paymentHash);
    check(matching.length === 1 && matching[0].status === 'complete' && matching[0].preimageMatchesHash === true);
    const nativeHistoryPath = join(owner.evidenceRoot, 'demo-native-history.json'), verificationPath = join(owner.evidenceRoot, 'demo-verification.json');
    fs.writeFileSync(nativeHistoryPath, JSON.stringify({ project: owner.project, resources, records }) + '\n', { mode: 0o600, flag: 'wx' });
    fs.writeFileSync(verificationPath, JSON.stringify({ executions: executions.map(execution => ({ id: execution.id, hash: execution.payment_hash, status: execution.status,
      nativeRecords: records.find(record => record.node === 'cln-m').payments.filter(payment => payment.paymentHash === execution.payment_hash).length })) }) + '\n', { mode: 0o600, flag: 'wx' });
    const retained = retainDemoHandoff({ ownerPath: plan.ownerPath, sourceCommit: ctx.sourceCommit, bundle, actualT05Path, nativeHistoryPath, verificationPath });
    const bound = { sourceCommit: ctx.sourceCommit, compiledCommit: ctx.compiledCommit, tarballSha256: ctx.tarballSha256 };
    const scenario = Buffer.from(JSON.stringify({ ...bound, scenario: 'T-05', paymentHashFingerprint: hash(Buffer.from(actual.paymentHash)), sendCount: payments.length, observedStatus: actual.status, recoveredStatus: 'VERIFIED_SUCCESS' }));
    fs.writeFileSync(join(ctx.output, 'scenario.json'), scenario, { mode: 0o600, flag: 'wx' });
    check(findLeaks({ root: process.cwd(), sentinels: resolve('test/sentinels.json'), sentinelDir: owner.sentinelRoot,
      testTmp: process.env.FLUXWARDEN_TEST_TMP, evidenceDir: owner.evidenceRoot, paths: [bundle, owner.evidenceRoot, ctx.output] }) === null);
    process.env.FLUXWARDEN_DEMO_HANDOFF = retained.handoffPath;
    process.env.FLUXWARDEN_DEMO_BUNDLE = bundle;
    return { scenarioRecord: { path: 'release/demo/scenario.json', sha256: hash(scenario) }, sameHashRecovery: true, sendCount: 1, ledgerVerified: true, checksumsVerified: true, completeLeakScan: true };
  } finally {
    try { if (started) await stopOwnedLive(); }
    finally {
      // The retained handoff is the sole lifecycle result inherited by CP043.
      const handoff = process.env.FLUXWARDEN_DEMO_HANDOFF, bundle = process.env.FLUXWARDEN_DEMO_BUNDLE;
      for (const key of Object.keys(process.env)) if (!(key in previousEnvironment)) Reflect.deleteProperty(process.env, key);
      Object.assign(process.env, previousEnvironment);
      if (handoff) process.env.FLUXWARDEN_DEMO_HANDOFF = handoff;
      if (bundle) process.env.FLUXWARDEN_DEMO_BUNDLE = bundle;
    }
  }
}
