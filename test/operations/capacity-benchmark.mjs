/**
 * Bounded synthetic regtest capacity observations, not a production capacity promise.
 * Build first. Example: node test/operations/capacity-benchmark.mjs --profile smoke
 * Requires an existing private FLUXWARDEN_TEST_TMP and FLUXWARDEN_EVIDENCE_DIR.
 * Each phase runs in a separate process with its own CPU/peak-RSS observation.
 * No node is contacted, no payment is sent, no financial history is deleted.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, lstatSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';
import { assertPrivateDirectory, createPrivateDirectory } from '../../scripts/private-scratch.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const here = fileURLToPath(import.meta.url);
const profiles = Object.freeze({
  smoke: { nodes: 2, channelsPerNode: 8, snapshotRounds: 4, proposals: 24, executions: 12, runRecords: 4, alerts: 4, ewmaBuckets: 48, ewmaPasses: 2 },
  representative: { nodes: 4, channelsPerNode: 64, snapshotRounds: 720, proposals: 1200, executions: 600, runRecords: 32, alerts: 32, ewmaBuckets: 8760, ewmaPasses: 10 },
});
const hash = value => createHash('sha256').update(value).digest('hex');
const id = (prefix, n) => `${prefix}${String(n).padStart(25, '0')}`;
const yaml = path => path.replace(/\\/g, '/');
const load = relative => import(pathToFileURL(join(root, 'dist', relative)).href);
const plain = value => JSON.stringify(value, (_key, item) => typeof item === 'bigint' ? item.toString() : item);

function files(directory) {
  return readdirSync(directory).flatMap(name => {
    const path = join(directory, name), info = lstatSync(path);
    assert(!info.isSymbolicLink(), 'benchmark state must not contain links');
    return info.isDirectory() ? files(path) : [{ path, bytes: info.size, sha256: hash(readFileSync(path)) }];
  });
}

function counts(database) {
  const db = new DatabaseSync(database, { readOnly: true });
  try {
    return Object.fromEntries(['nodes', 'channels', 'channel_snapshots', 'liquidity_proposals', 'approvals', 'executions',
      'execution_events', 'budget_reservations', 'ledger_journals', 'ledger_lines'].map(table =>
      [table, Number(db.prepare(`SELECT count(*) AS n FROM ${table}`).get().n)]));
  } finally { db.close(); }
}

async function seed(context) {
  const { openDatabase } = await load('persistence/index.js');
  const { createAlertWriter } = await load('daemon/alerts.js');
  const { writeRunRecord } = await load('output/run-record.js');
  const { publishSentinel } = await import('../helpers/capacity-sentinels.mjs');
  const p = context.profile, db = openDatabase(context.database, { readOnly: false });
  const channels = [], now = db.now();
  try {
    for (let n = 0; n < p.nodes; n++) {
      const nodeId = id('N', n), name = `owned-${String(n)}`;
      db.nodes.insert({ id: nodeId, name, implementation: n % 2 === 0 ? 'lnd' : 'cln', expectedNetwork: 'regtest',
        expectedPubkey: `02${hash(name)}` });
      for (let c = 0; c < p.channelsPerNode; c++) {
        channels.push({ nodeId, channelKey: `${String(1000 + n)}x${String(c + 1)}x0`, scid: `${String(1000 + n)}x${String(c + 1)}x0`,
          peerPubkey: `03${hash(`${name}-${String(c)}`)}`, fundingOutpoint: `${hash(`${name}-${String(c)}-funding`)}:0`,
          state: 'ACTIVE', nodeState: 'active', opener: 'local', capacityMsat: 2_000_000_000n,
          localBalanceMsat: 1_000_000_000n, remoteBalanceMsat: 1_000_000_000n, spendableMsat: 950_000_000n, receivableMsat: 950_000_000n,
          confidence: n % 2 === 0 ? 'DERIVED_ESTIMATE' : 'NODE_REPORTED', caveat: null,
          localReserveMsat: 10_000_000n, remoteReserveMsat: 10_000_000n, pendingOutMsat: 0n, pendingInMsat: 0n, pendingHtlcCount: 0,
          localMaxPendingAmtMsat: null, remoteMaxPendingAmtMsat: null, observedAt: now, blockHeight: 812,
          provenance: { fixture: 'bounded-owned-regtest-capacity' } });
      }
    }
    for (let round = 0; round < p.snapshotRounds; round++) db.snapshots.storeAll(channels);
    for (let n = 0; n < p.proposals; n++) {
      const node = n % p.nodes, offset = node * p.channelsPerNode, pair = 2 * (Math.floor(n / p.nodes) % (p.channelsPerNode / 2));
      const proposalId = id('P', n), approvalId = id('A', n);
      db.proposals.insert({ id: proposalId, nodeId: id('N', node), policy: { sha256: hash('capacity-policy'), canonicalJson: '{"fees":{"exempt_fee_msat":"5000"}}' },
        actionType: 'CIRCULAR_REBALANCE', sourceChannelKey: channels[offset + pair].channelKey, targetChannelKey: channels[offset + pair + 1].channelKey,
        principalMsat: 10_000_000n, maxFeeMsat: 300_000n, maxFeePpm: 2500n, maxCltvDelta: 144, routeJson: null,
        demandSource: 'EWMA', digest: hash(proposalId), reasonJson: '{"fixture":"bounded-owned-regtest-capacity"}', createdAt: now, expiresAt: now + 86_400_000 });
      if (n >= p.executions) continue;
      db.commandData.approvals.insert({ id: approvalId, proposal_id: proposalId, key_id: 'capacity-fixture-public-key', nonce: hash(approvalId),
        expires_at: now + 86_400_000, signature: 'synthetic-fixture-never-executed', max_fee_msat: 300_000n, max_cltv_delta: 144, created_at: now });
      const claim = db.executions.claim(scope => scope.insertClaimed({ proposalId, approvalId, workerId: 'owned-capacity-fixture', leaseMs: 60_000, reservedMsat: 300_000n }));
      let epoch = db.executions.transition(claim.executionId, claim.fenceEpoch, 'CLAIMED', 'PREFLIGHT', { leaseMs: 60_000 });
      epoch = db.executions.transition(claim.executionId, epoch, 'PREFLIGHT', 'PREFLIGHT', { leaseMs: 60_000,
        paymentHash: hash(`owned-capacity-hash-${String(n)}`), plannedFeeMsat: 1000n });
      const submitted = db.executions.submit(claim.executionId, epoch, p.executions + 1, 60_000);
      epoch = db.executions.transition(claim.executionId, submitted.fenceEpoch, 'SUBMITTING', 'IN_FLIGHT', { leaseMs: 60_000 });
      db.executions.transition(claim.executionId, epoch, 'IN_FLIGHT', 'VERIFIED_SUCCESS', { actualFeeMsat: 1000n,
        settledChannelKey: channels[offset + pair + 1].channelKey, deltaStatus: 'MATCH' });
    }
    const key = randomBytes(32), keyPath = join(context.state, 'outbox.key');
    appendFileSync(join(process.env.FLUXWARDEN_TEST_TMP, 'declared-out.txt'), `${keyPath}\n`);
    writeFileSync(keyPath, key, { flag: 'wx', mode: 0o600 });
    await publishSentinel(context, key);
    const writer = createAlertWriter({ dir: context.alertDir, key, monotonic: { now: () => performance.now() }, clock: { now: () => now },
      maxPerWindow: p.alerts + 1, windowMs: 60_000, secrets: [] });
    for (let n = 0; n < p.alerts; n++) assert.equal(writer.raise({ kind: 'stuck-in-flight', subject: `owned-${String(n)}`, state: 'synthetic-observation' }), 'written');
    for (let n = 0; n < p.runRecords; n++) writeRunRecord(context.database, {
      manifest: { runId: `run_${id('R', n)}`, command: 'reconcile', fluxwardenVersion: 'synthetic-capacity-fixture', gitCommit: context.sourceCommit,
        imageDigests: {}, nodes: [], seeds: [0], policySha256: hash('capacity-policy'), approvalKeyIds: [], chaosScenarioIds: [],
        unavailableEvidence: { native: 'Synthetic capacity measurement; no native-node evidence.' } },
      topologyBefore: channels, topologyAfter: channels, proposals: [], executionTrace: [],
      ledgerAudit: { fixture: 'financial book retained in database' }, reconciliation: { differences: [] }, chaosResults: [] });
  } finally { db.close(); }
  const actual = counts(context.database);
  assert.equal(actual.nodes, p.nodes); assert.equal(actual.channels, p.nodes * p.channelsPerNode);
  assert.equal(actual.channel_snapshots, p.nodes * p.channelsPerNode * p.snapshotRounds);
  assert.equal(actual.liquidity_proposals, p.proposals); assert.equal(actual.executions, p.executions);
  assert.equal(actual.approvals, p.executions); assert.equal(actual.budget_reservations, p.executions);
  assert.equal(actual.ledger_journals, p.nodes * p.channelsPerNode + p.executions * 2);
  // Independent SPEC §9.3 arithmetic: 1,000 msat fee per success, two balanced postings.
  const raw = new DatabaseSync(context.database, { readOnly: true });
  try {
    assert.equal(raw.prepare('SELECT sum(debit_msat-credit_msat) AS net FROM ledger_lines').get().net, 0);
    assert.equal(raw.prepare("SELECT balance_decimal AS n FROM account_balances WHERE account_code='expense:routing_fees'").get().n,
      String(p.executions * 1000));
  } finally { raw.close(); }
  return { counts: actual };
}

async function demand(context) {
  const { diagnose } = await load('planner/diagnose.js');
  const { openDatabase } = await load('persistence/index.js');
  const db = openDatabase(context.database, { readOnly: true }), now = 1_793_001_600_000, width = 3_600_000;
  try {
    let evaluated = 0;
    for (let pass = 0; pass < context.profile.ewmaPasses; pass++) {
      for (const node of db.nodes.list()) {
        const channels = db.commandData.snapshots(node.id).map(channel => ({ ...channel, observedAt: now }));
        const receipts = channels.flatMap(channel => Array.from({ length: context.profile.ewmaBuckets }, (_, n) => ({ channelKey: channel.channelKey,
          settledAt: now - (context.profile.ewmaBuckets - n) * width, amountMsat: 3_600_000n })));
        const diagnosed = diagnose({ nodeName: node.name, channels, clock: { now: () => now }, horizonMs: null,
          incomingHistory: { receipts, complete: true }, policy: {
            fees: { max_fee_msat: 300_000n, max_fee_ppm: 2500n, exempt_fee_msat: 5000n }, routing: { max_cltv_delta: 144 },
            amounts: { min_channel_reserve_msat: 50_000_000n, max_principal_msat: 100_000_000n, min_principal_msat: 10_000_000n },
            budget: { msat: 2_000_000n, period: 86_400_000 }, cooldown_after_failure: 3_600_000, cooldown_after_success: 1_800_000,
            max_in_flight: 1, max_snapshot_age: 60_000, proposal_ttl: 900_000, exclude_channels: [], targets: {},
            demand: { mode: 'ewma', horizon: 21_600_000, burst_factor: '1.4', ewma: { bucket_seconds: 3600, alpha: '0.35', min_samples: 12 } } } });
        assert.equal(diagnosed.status, 'OK'); assert.equal(diagnosed.demandSource, 'EWMA');
        // Normalized weights sum to 1: constant 3,600,000 × 6 × 1.4 = 30,240,000 msat.
        for (const row of diagnosed.channels) assert.equal(row.inboundTargetMsat, 30_240_000n);
        evaluated += channels.length;
      }
    }
    return { channelsEvaluated: evaluated, receiptRowsPerPass: context.profile.nodes * context.profile.channelsPerNode * context.profile.ewmaBuckets,
      expectedRequiredInboundMsat: '30240000' };
  } finally { db.close(); }
}

if (process.argv[2] === '--phase') {
  const phase = process.argv[3], context = JSON.parse(readFileSync(process.argv[4], 'utf8')), metrics = process.argv[5];
  const started = performance.now();
  process.on('exit', code => writeFileSync(metrics, plain({ phase, exitCode: code, wallMs: performance.now() - started,
    cpuMicroseconds: process.cpuUsage(), resourceUsage: process.resourceUsage(), memoryBytes: process.memoryUsage() }), { flag: 'wx', mode: 0o600 }));
  if (phase === 'seed') writeFileSync(context.seedResult, plain(await seed(context)), { flag: 'wx', mode: 0o600 });
  else if (phase === 'ewma') writeFileSync(context.demandResult, plain(await demand(context)), { flag: 'wx', mode: 0o600 });
  else {
    process.argv = [process.execPath, join(root, 'dist/cli/bin.js'), '--json', ...(phase === 'verify' ? ['ledger', 'verify'] :
      ['evidence', 'export', '--run-id', `run_${id('R', 0)}`, '--out', context.exportDir]), '--config', context.config];
    await import(pathToFileURL(join(root, 'dist/cli/bin.js')).href);
  }
} else {
  assert(process.argv.length <= 4 && (process.argv[2] === undefined || process.argv[2] === '--profile'), 'usage: --profile smoke|representative');
  const name = process.argv[3] ?? 'smoke', profile = profiles[name]; assert(profile, 'unknown bounded profile');
  for (const variable of ['FLUXWARDEN_TEST_TMP', 'FLUXWARDEN_EVIDENCE_DIR', 'FLUXWARDEN_SENTINEL_DIR']) {
    assert(process.env[variable], `missing ${variable}`); await assertPrivateDirectory(process.env[variable]);
  }
  const state = await createPrivateDirectory(process.env.FLUXWARDEN_TEST_TMP, 'capacity-state-');
  const evidence = await createPrivateDirectory(process.env.FLUXWARDEN_EVIDENCE_DIR, 'capacity-observation-');
  const alertDir = await createPrivateDirectory(state, 'alerts-');
  const source = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8', windowsHide: true });
  assert.equal(source.status, 0);
  const build = JSON.parse(readFileSync(join(root, 'dist/evidence/build-info.json'), 'utf8'));
  assert.equal(build.gitCommit, source.stdout.trim(), 'build this exact source before measuring');
  const driverSha256 = hash(readFileSync(here));
  const compiledTreeSha256 = hash(plain(files(join(root, 'dist')).map(file => ({ path: file.path.slice(join(root, 'dist').length + 1), sha256: file.sha256 })).sort((a, b) => a.path.localeCompare(b.path))));
  const context = { profile, state, evidence, sourceCommit: source.stdout.trim(), database: join(state, 'fluxwarden.db'), alertDir,
    config: join(state, 'fluxwarden.yaml'), exportDir: join(state, 'export'), seedResult: join(evidence, 'seed.json'), demandResult: join(evidence, 'demand.json') };
  writeFileSync(context.config, `database: "${yaml(context.database)}"\nalert_dir: "${yaml(alertDir)}"\nnodes:\n  - name: owned-0\n    implementation: lnd\n    url: "https://127.0.0.1:1"\n    tls_cert_path: absent-test-certificate\n    macaroon_path: absent-test-credential\n    expected_pubkey: "02${hash('owned-0')}"\n    expected_network: regtest\n`, { flag: 'wx', mode: 0o600 });
  const contextPath = join(evidence, 'context.json'); writeFileSync(contextPath, plain(context), { flag: 'wx', mode: 0o600 });
  const observations = [];
  const phaseTimeoutMs = name === 'representative' ? 600_000 : 120_000;
  for (const phase of ['seed', 'verify', 'ewma', 'export']) {
    const metrics = join(evidence, `${phase}-metrics.json`);
    const phaseStarted = performance.now();
    const child = spawnSync(process.execPath, [here, '--phase', phase, contextPath, metrics], { cwd: root, env: process.env, encoding: 'utf8',
      windowsHide: true, shell: false, timeout: phaseTimeoutMs, maxBuffer: 2 * 1024 * 1024 });
    writeFileSync(join(evidence, `${phase}-stdout.log`), child.stdout ?? '', { flag: 'wx', mode: 0o600 });
    writeFileSync(join(evidence, `${phase}-stderr.log`), child.stderr ?? '', { flag: 'wx', mode: 0o600 });
    writeFileSync(join(evidence, `${phase}-outcome.json`), plain({ phase, status: child.status, signal: child.signal,
      errorCode: child.error?.code ?? null, parentObservedWallMs: performance.now() - phaseStarted, timeoutMs: phaseTimeoutMs }), { flag: 'wx', mode: 0o600 });
    assert.equal(child.status, 0, `${phase} failed; see private phase evidence`);
    observations.push(JSON.parse(readFileSync(metrics, 'utf8')));
  }
  const initial = JSON.parse(readFileSync(context.seedResult, 'utf8')).counts, final = counts(context.database);
  assert.deepEqual(final, initial, 'read/diagnosis/export phases must not prune financial history');
  const inventory = files(state), report = { schema: 'fluxwarden-capacity-observation-v1', scope: 'Synthetic regtest state; no native node or payment throughput claim.',
    profile: name, workload: profile, sourceCommit: context.sourceCommit, nodeVersion: process.versions.node, platform: process.platform,
    cpuModel: (await import('node:os')).cpus()[0]?.model, driverSha256, compiledTreeSha256, counts: final, observations,
    retained: { files: inventory.length, totalBytes: inventory.reduce((sum, file) => sum + file.bytes, 0),
      databaseBytes: lstatSync(context.database).size, runRecordBytes: inventory.filter(file => /\.run_[^.]+\.json$/.test(file.path)).reduce((sum, file) => sum + file.bytes, 0) },
    inventory: inventory.map(file => ({ ...file, path: file.path.slice(state.length + 1) })),
    retention: 'Keep the complete immutable financial book, approvals, intents, hashes, events and run evidence. This benchmark deletes nothing and establishes no pruning policy.',
    phaseTimeoutMs, limits: 'Profile counts and explicit per-phase watchdogs bound this experiment. Watchdogs are harness limits, not supported capacity/SLO thresholds. Peak RSS is per-process maxRSS in KiB.' };
  const reportPath = join(evidence, 'capacity.json'); writeFileSync(reportPath, plain(report), { flag: 'wx', mode: 0o600 });
  process.stdout.write(`${plain({ report: reportPath, profile: name, counts: final, observations, retained: report.retained })}\n`);
}
