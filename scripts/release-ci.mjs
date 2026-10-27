// Source-bound producers and authenticated aggregate. GitHub's artifact digest
// authenticates transport; each retained receipt binds actual bytes and job ID.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compiledSource, officialGitHub, repository, tarballMembers, zipMembers, verifyPublisherEnvironment } from './release-gate.mjs';
import { deriveInventory, nodes, platformJobs, reportedCaseName, requiredLiveRows } from './release-inventory.mjs';
import { findLeaks } from './leak-check.mjs';
import { observationPath, rejectIncomplete, validateObservations } from './release-observations.mjs';
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const check = value => { if (!value) throw new Error('release evidence: prerequisite unavailable'); };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const read = path => JSON.parse(fs.readFileSync(path, 'utf8'));
const put = (path, value) => fs.writeFileSync(path, JSON.stringify(value) + '\n', { mode: 0o600, flag: 'wx' });
const ref = (path, bytes) => ({ path, sha256: hash(bytes) });
const artifactName = key => 'fluxwarden-' + key.replaceAll('/', '-');
function sourceMatchesRunHead(head, source) {
  if (head === source) return true;
  // PR CI validates GitHub's merge result. The official run may name its head
  // parent; read that immutable commit header without changing checkout semantics.
  // Publication still requires exact run.head_sha === source in release-gate.
  if (process.env.GITHUB_EVENT_NAME !== 'pull_request' || !/^[a-f0-9]{40}$/.test(source) || !/^[a-f0-9]{40}$/.test(head)) return false;
  const object = spawnSync('git', ['cat-file', '-p', source], { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 15_000, maxBuffer: 1024 * 1024 });
  return !object.error && object.status === 0 && object.stdout.split('\n\n', 1)[0].split('\n').includes(`parent ${head}`);
}
function run(command, args) {
  if (command === 'node') command = process.execPath;
  if (command === 'npm') { args = [join(dirname(process.execPath), process.platform === 'win32' ? 'node_modules/npm/bin/npm-cli.js' : '../lib/node_modules/npm/bin/npm-cli.js'), ...args]; command = process.execPath; }
  const result = spawnSync(command, args, { cwd: root, env: process.env, stdio: 'inherit', windowsHide: true, timeout: 180_000 });
  check(!result.error && result.signal === null && result.status === 0);
}
function context() {
  const sourceCommit = process.env.GITHUB_SHA, tarballPath = process.env.FLUXWARDEN_FINAL_TARBALL, output = process.env.FLUXWARDEN_RELEASE_OUTPUT;
  check(/^[a-f0-9]{40}$/.test(sourceCommit) && tarballPath && output);
  const bytes = fs.readFileSync(tarballPath); check(compiledSource(bytes) === sourceCommit);
  if (process.env.FLUXWARDEN_EXPECTED_TARBALL_SHA256) check(hash(bytes) === process.env.FLUXWARDEN_EXPECTED_TARBALL_SHA256);
  const compiled = read(join(root, 'dist/evidence/build-info.json')).gitCommit; check(compiled === sourceCommit);
  return { sourceCommit, compiledCommit: compiled, tarballSha256: hash(bytes), tarballPath, output, tarball: { sha256: hash(bytes), bytes: bytes.length } };
}
function binding(ctx) { return { sourceCommit: ctx.sourceCommit, compiledCommit: ctx.compiledCommit, tarballSha256: ctx.tarballSha256 }; }
function reportCases(report) {
  check(report.success === true && report.numFailedTests === 0 && report.numPendingTests === 0 && report.numTodoTests === 0 && Array.isArray(report.testResults) && report.testResults.length > 0);
  const cases = [];
  for (const file of report.testResults) {
    check(Array.isArray(file.assertionResults) && file.assertionResults.length > 0);
    const name = file.name.replaceAll('\\', '/'), at = name.lastIndexOf('/test/'), normalized = name.startsWith('test/') ? name : name.slice(at + 1);
    check(normalized.startsWith('test/') && !normalized.split('/').includes('..'));
    for (const assertion of file.assertionResults) { check(assertion.status === 'passed'); cases.push(JSON.stringify([normalized, reportedCaseName(assertion)])); }
  }
  check(cases.length > 0 && report.numTotalTests === cases.length && report.numPassedTests === cases.length && new Set(cases).size === cases.length);
  return cases;
}
const successful = job => job.status === 'completed' && job.conclusion === 'success' && Array.isArray(job.steps) && job.steps.length > 0 && job.steps.every(step => step.status === 'completed' && step.conclusion === 'success');
async function officialJob(github, key, completed = false) {
  const jobs = await github.listJobs(Number(process.env.GITHUB_RUN_ID), Number(process.env.GITHUB_RUN_ATTEMPT));
  const matches = jobs.filter(job => job.name === key);
  check(matches.length === 1 && sourceMatchesRunHead(matches[0].head_sha, process.env.GITHUB_SHA) && matches[0].run_id === Number(process.env.GITHUB_RUN_ID) && (!completed || successful(matches[0])));
  return matches[0];
}
export async function authenticatedMembers(github, artifact, sourceCommit, runId) {
  const metadata = await github.getArtifact(artifact.id), bytes = await github.downloadArtifact(artifact.id);
  check(metadata.id === artifact.id && metadata.name === artifact.name && metadata.expired === false && metadata.workflow_run.id === runId && sourceMatchesRunHead(metadata.workflow_run.head_sha, sourceCommit) &&
    metadata.size_in_bytes === bytes.length && metadata.digest === `sha256:${hash(bytes)}`);
  return zipMembers(bytes);
}
async function namedArtifact(github, artifacts, name, sourceCommit, runId) {
  const matches = artifacts.filter(artifact => artifact.name === name && artifact.expired === false);
  check(matches.length === 1); return authenticatedMembers(github, matches[0], sourceCommit, runId);
}
export async function authenticateTargetInventories({ github, sourceCommit, runId, runAttempt, tarballSha256 }) {
  const [artifacts, jobs] = await Promise.all([github.listArtifacts(runId), github.listJobs(runId, runAttempt)]), casesByTarget = {};
  for (const os of ['ubuntu-latest', 'windows-latest']) for (const node of nodes) {
    const key = `inventory/${os}/${node}`, matches = jobs.filter(job => job.name === key);
    check(matches.length === 1 && Number.isSafeInteger(matches[0].id) && matches[0].id > 0 && matches[0].run_id === runId && matches[0].head_sha === sourceCommit && successful(matches[0]));
    const files = await namedArtifact(github, artifacts, artifactName(key), sourceCommit, runId);
    check(files.size === 1 && files.has('inventory.json'));
    const inventory = JSON.parse(files.get('inventory.json').toString('utf8'));
    check(inventory.schemaVersion === 1 && inventory.sourceCommit === sourceCommit && inventory.compiledCommit === sourceCommit && inventory.tarballSha256 === tarballSha256 && inventory.key === `${os}/${node}` && inventory.jobId === matches[0].id &&
      inventory.os === os && inventory.node === node && inventory.platform === (os === 'windows-latest' ? 'win32' : 'linux') &&
      (node.endsWith('.x') ? new RegExp(`^v${node.split('.')[0]}\\.`).test(inventory.runtime) : inventory.runtime === `v${node}`));
    for (const suite of ['product', 'harness']) {
      check(Array.isArray(inventory.cases?.[suite]) && inventory.cases[suite].length > 0);
      const ids = inventory.cases[suite].map(row => JSON.stringify([row.file, row.name])); check(new Set(ids).size === ids.length);
    }
    casesByTarget[`${os}/${node}`] = inventory.cases;
  }
  return casesByTarget;
}
function compareCompiled(ctx) {
  const members = tarballMembers(fs.readFileSync(ctx.tarballPath));
  for (const [name, bytes] of members) if (name.startsWith('package/dist/')) check(bytes.equals(fs.readFileSync(join(root, name.slice('package/'.length)))));
}
function scan(paths) {
  check(findLeaks({ root, sentinels: join(root, 'test/sentinels.json'), sentinelDir: process.env.FLUXWARDEN_SENTINEL_DIR,
    testTmp: process.env.FLUXWARDEN_TEST_TMP, evidenceDir: process.env.FLUXWARDEN_EVIDENCE_DIR, paths }) === null);
}
async function fetchCandidate(github) {
  const source = process.env.GITHUB_SHA, runId = Number(process.env.GITHUB_RUN_ID), artifacts = await github.listArtifacts(runId);
  const files = await namedArtifact(github, artifacts, 'fluxwarden-final-package', source, runId);
  const expected = `fluxwarden-${read(join(root, 'package.json')).version}.tgz`;
  check(files.size === 1 && files.has(expected) && compiledSource(files.get(expected)) === source);
  const destination = process.env.FLUXWARDEN_FINAL_TARBALL;
  if (fs.existsSync(destination)) {
    const info = fs.lstatSync(destination); check(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && fs.readFileSync(destination).equals(files.get(expected)));
  } else fs.writeFileSync(destination, files.get(expected), { mode: 0o600, flag: 'wx' });
}
async function collectInventory(github, os, node) {
  const ctx = context(); check(nodes.includes(node) && ['ubuntu-latest', 'windows-latest'].includes(os));
  const inventory = await deriveInventory(ctx.sourceCommit, ['product', 'harness']);
  const key = `inventory/${os}/${node}`, job = await officialJob(github, key);
  put(join(ctx.output, 'inventory.json'), { schemaVersion: 1, ...binding(ctx), key: `${os}/${node}`, jobId: job.id, os, node, platform: process.platform, runtime: process.version, cases: inventory.cases });
}
export async function sealReport(github, key) {
  const ctx = context(), suite = key.startsWith('live/') ? key.split('/')[1] : key.includes('/harness-') ? 'harness' : 'product';
  const reportPath = join(process.env.FLUXWARDEN_EVIDENCE_DIR, `vitest-${suite}.json`);
  const stat = fs.lstatSync(reportPath); check(stat.isFile() && !stat.isSymbolicLink() && stat.size > 0 && stat.size <= 64 * 1024 * 1024);
  const bytes = fs.readFileSync(reportPath), original = JSON.parse(bytes.toString('utf8'));
  const captured = read(join(process.env.FLUXWARDEN_CI_CAPTURE_DIR, 'receipt.json'));
  let passed = captured.result?.exitCode === 0;
  try { reportCases(original); } catch { passed = false; }
  if (suite === 'chaos' && passed) {
    // Explicit incompleteness already refuses authorization. Check it before
    // expensive re-verification, without writing any output or crediting PASS.
    const plan = read(process.env.FLUXWARDEN_LAB_PLAN), owner = plan.ownerPath ? read(plan.ownerPath) : plan.owner;
    for (const name of fs.readdirSync(owner.evidenceRoot)) if (name.endsWith('.json')) {
      check(observationPath(name));
      const path = join(owner.evidenceRoot, name), info = fs.lstatSync(path);
      if (resolve(path) === resolve(reportPath)) { rejectIncomplete(original); continue; }
      check(info.isFile() && !info.isSymbolicLink() && info.size > 0 && info.size <= 8 * 1024 * 1024);
      rejectIncomplete(read(path));
    }
  }
  run('node', ['scripts/ci-capture.mjs', 'verify', '--root', root, '--capture-dir', process.env.FLUXWARDEN_CI_CAPTURE_DIR]);
  if (passed) { run('node', ['scripts/no-pending.mjs', reportPath]); compareCompiled(ctx); }
  const job = await officialJob(github, key), report = ref('report.json', bytes);
  fs.writeFileSync(join(ctx.output, report.path), bytes, { mode: 0o600, flag: 'wx' });
  const receipt = { ...binding(ctx), jobId: job.id, complete: captured.result.complete, exitCode: passed ? 0 : captured.result.exitCode || 1, reportSha256: report.sha256 };
  put(join(ctx.output, 'receipt.json'), receipt);
  const capture = fs.readFileSync(join(process.env.FLUXWARDEN_CI_CAPTURE_DIR, 'receipt.json'));
  fs.writeFileSync(join(ctx.output, 'capture.json'), capture, { mode: 0o600, flag: 'wx' });
  put(join(ctx.output, 'row.json'), { key, jobId: job.id, report, receipt: ref('receipt.json', fs.readFileSync(join(ctx.output, 'receipt.json'))) });
  if (key.startsWith('live/')) {
    const plan = read(process.env.FLUXWARDEN_LAB_PLAN); check(plan.sourceCommit === ctx.sourceCommit && plan.exclusive === true && plan.network === 'regtest');
    const owner = plan.ownerPath ? read(plan.ownerPath) : plan.owner, ownerId = owner.id ?? plan.ownerId;
    check(typeof ownerId === 'string' && ownerId.length > 0 && plan.ownerId === ownerId && plan.owner.evidenceRoot === owner.evidenceRoot &&
      (!plan.ownerPath || owner.id === plan.owner.id));
    put(join(ctx.output, 'owner-plan.json'), { schemaVersion: 1, sourceCommit: ctx.sourceCommit, exclusive: true, network: 'regtest', ownerId });
    if (suite === 'chaos' && passed) {
      for (const id of requiredLiveRows) {
        const assertions = original.testResults.filter(file => file.name.endsWith('.live.test.ts')).flatMap(file => file.assertionResults
          .filter(assertion => assertion.fullName.includes(id)).map(assertion => ({ file: file.name, name: assertion.fullName, status: assertion.status })));
        check(assertions.length > 0 && assertions.every(assertion => assertion.status === 'passed'));
        const prefix = id.toLowerCase().replace('-', '') + '-';
        const matches = fs.readdirSync(owner.evidenceRoot).filter(name => name.startsWith(prefix) && name.endsWith('.json'));
        check(matches.length > 0);
        const rawMembers = new Map();
        const observations = matches.map(name => {
          check(observationPath(name));
          const path = join(owner.evidenceRoot, name), info = fs.lstatSync(path);
          check(info.isFile() && !info.isSymbolicLink() && info.size > 0 && info.size <= 8 * 1024 * 1024);
          const bytes = fs.readFileSync(path); rawMembers.set(name, bytes);
          fs.writeFileSync(join(ctx.output, name), bytes, { mode: 0o600, flag: 'wx' });
          return ref(name, bytes);
        });
        const summary = { ...binding(ctx), row: id, complete: true, assertions, observations };
        validateObservations(id, summary, reference => JSON.parse(rawMembers.get(reference.path).toString('utf8')), { ...binding(ctx), ownerId });
        put(join(ctx.output, `${id}.json`), summary);
      }
    }
  }
  scan([ctx.output]);
}
async function producer(github, kind) {
  const ctx = context(), key = `release/${kind}`, job = await officialJob(github, key);
  compareCompiled(ctx);
  let evidence;
  if (kind === 'installed-smoke') {
    run('node', ['scripts/release-smoke.mjs', ctx.tarballPath]); evidence = { complete: true, exitCode: 0 };
  } else if (kind === 'publisher') {
    await verifyPublisherEnvironment(github);
    check(process.env.NPM_TRUST_READ_TOKEN);
    // Read-only official registry API; no token exchange, publish or tag mutation.
    // https://api-docs.npmjs.com/ GET /-/package/{package}/trust
    const response = await fetch('https://registry.npmjs.org/-/package/fluxwarden/trust', { headers: { Authorization: `Bearer ${process.env.NPM_TRUST_READ_TOKEN}` }, redirect: 'error', signal: AbortSignal.timeout(30_000) });
    check(response.ok); const configurations = await response.json();
    const matches = Array.isArray(configurations) ? configurations.filter(value => value.type === 'github' && value.claims?.repository === repository && value.claims?.workflow_ref?.file === 'release.yml' && value.claims?.environment === 'npm-release' && value.permissions?.includes('createPackage')) : [];
    check(matches.length === 1);
    evidence = { environment: 'npm-release', repository, workflow: 'release.yml', package: 'fluxwarden', oidc: true, trustedPublisherVerified: true, configurationSha256: hash(Buffer.from(JSON.stringify(matches[0]))) };
  } else if (kind === 'demo') {
    // The demo producer creates its inputs from the fresh owned manifest and
    // verifies its actual same-hash recovery and bundle. Missing inputs refuse.
    const { produceDemo } = await import('./release-demo.mjs'); evidence = await produceDemo(ctx);
  } else if (kind === 'leak-scan') {
    const artifacts = await github.listArtifacts(Number(process.env.GITHUB_RUN_ID));
    const names = [...platformJobs().map(row => artifactName(row.key)), 'fluxwarden-live-lab', 'fluxwarden-live-chaos', 'fluxwarden-release-demo', 'fluxwarden-release-installed-smoke'];
    const directory = join(ctx.output, 'scan'); fs.mkdirSync(directory, { mode: 0o700 });
    for (const name of names) {
      const files = await namedArtifact(github, artifacts, name, ctx.sourceCommit, Number(process.env.GITHUB_RUN_ID));
      const rowDirectory = join(directory, name); fs.mkdirSync(rowDirectory, { mode: 0o700 });
      for (const [name, bytes] of files) { check(!name.includes('/')); fs.writeFileSync(join(rowDirectory, name), bytes, { mode: 0o600, flag: 'wx' }); }
      if (files.has('capture.json')) { const capture = JSON.parse(files.get('capture.json').toString('utf8')); check(capture.result?.complete === true && capture.result?.exitCode === 0 && capture.result?.policySatisfied === true); }
    }
    scan([directory, ctx.tarballPath]);
    evidence = { complete: true, exitCode: 0, scannedArtifacts: names };
    // The producer output contains evidence only, not a second unbound copy of inputs.
    fs.rmSync(directory, { recursive: true });
  } else throw new Error('release evidence: unsupported producer');
  put(join(ctx.output, 'evidence.json'), { ...binding(ctx), ...evidence });
  put(join(ctx.output, 'row.json'), { key, jobId: job.id, evidence: ref('evidence.json', fs.readFileSync(join(ctx.output, 'evidence.json'))) });
  scan([ctx.output]);
}
export async function aggregateEvidence(github) {
  const ctx = context(), runId = Number(process.env.GITHUB_RUN_ID), runAttempt = Number(process.env.GITHUB_RUN_ATTEMPT);
  const [artifacts, jobs] = await Promise.all([github.listArtifacts(runId), github.listJobs(runId, runAttempt)]);
  const casesByTarget = await authenticateTargetInventories({ github, sourceCommit: ctx.sourceCommit, runId, runAttempt, tarballSha256: ctx.tarballSha256 });
  const liveInventory = await deriveInventory(ctx.sourceCommit, ['lab', 'chaos']), unions = new Map();
  const exact = (actual, expected) => {
    const ids = expected.map(row => JSON.stringify([row.file, row.name]));
    check(ids.length > 0 && actual.length === ids.length && new Set(actual).size === actual.length && ids.every(id => actual.includes(id)));
  };
  const bundle = { schemaVersion: 1, sourceCommit: ctx.sourceCommit, compiledCommit: ctx.compiledCommit, tarball: ctx.tarball, platform: [], live: { rows: [] } };
  const directory = join(ctx.output, 'aggregate'); fs.mkdirSync(directory, { mode: 0o700 });
  const retain = (path, bytes) => { const dest = join(directory, path); fs.mkdirSync(dirname(dest), { recursive: true, mode: 0o700 }); fs.writeFileSync(dest, bytes, { mode: 0o600, flag: 'wx' }); return ref(path, bytes); };
  async function row(key) {
    const matches = jobs.filter(job => job.name === key); check(matches.length === 1 && matches[0].head_sha === ctx.sourceCommit && matches[0].run_id === runId && successful(matches[0]));
    const files = await namedArtifact(github, artifacts, artifactName(key), ctx.sourceCommit, runId), row = JSON.parse(files.get('row.json')?.toString('utf8'));
    check(row.key === key && row.jobId === matches[0].id);
    for (const field of ['report', 'receipt', 'evidence']) if (row[field]) {
      const bytes = files.get(row[field].path); check(bytes && hash(bytes) === row[field].sha256);
      if (field === 'report') reportCases(JSON.parse(bytes.toString('utf8')));
      row[field] = retain(`${key}/${row[field].path}`, bytes);
    }
    if (files.has('receipt.json')) {
      const receipt = JSON.parse(files.get('receipt.json').toString('utf8'));
      check(receipt.sourceCommit === ctx.sourceCommit && receipt.compiledCommit === ctx.compiledCommit && receipt.tarballSha256 === ctx.tarballSha256 &&
        receipt.jobId === row.jobId && receipt.complete === true && receipt.exitCode === 0 && receipt.reportSha256 === row.report.sha256);
    }
    if (files.has('evidence.json')) {
      const evidence = JSON.parse(files.get('evidence.json').toString('utf8'));
      check(evidence.sourceCommit === ctx.sourceCommit && evidence.compiledCommit === ctx.compiledCommit && evidence.tarballSha256 === ctx.tarballSha256);
      if (key === 'release/demo') check(evidence.sameHashRecovery === true && evidence.sendCount === 1 && evidence.ledgerVerified === true && evidence.checksumsVerified === true && evidence.completeLeakScan === true);
      else if (key === 'release/publisher') check(evidence.environment === 'npm-release' && evidence.repository === repository && evidence.workflow === 'release.yml' && evidence.package === 'fluxwarden' && evidence.oidc === true && evidence.trustedPublisherVerified === true);
      else check(evidence.complete === true && evidence.exitCode === 0);
    }
    return { row, files };
  }
  for (const required of platformJobs()) {
    const actual = await row(required.key); bundle.platform.push({ ...required, ...actual.row });
    const group = `${required.os}/${required.node}/${required.suite}`;
    unions.set(group, [...unions.get(group) ?? [], ...reportCases(JSON.parse(actual.files.get('report.json').toString('utf8')))]);
  }
  for (const [group, actual] of unions) { const [os, node, suite] = group.split('/'); exact(actual, casesByTarget[`${os}/${node}`][suite]); }
  for (const suite of ['lab', 'chaos']) {
    const actual = await row(`live/${suite}`); bundle.live[suite] = actual.row;
    exact(reportCases(JSON.parse(actual.files.get('report.json').toString('utf8'))), liveInventory.cases[suite]);
    if (suite === 'lab') {
      const owner = JSON.parse(actual.files.get('owner-plan.json').toString('utf8'));
      check(owner.sourceCommit === ctx.sourceCommit && owner.exclusive === true && owner.network === 'regtest' && typeof owner.ownerId === 'string' && owner.ownerId.length > 0);
      bundle.live.lab.ownerPlan = retain('live/lab/owner-plan.json', actual.files.get('owner-plan.json'));
    } else {
      const owner = JSON.parse(actual.files.get('owner-plan.json').toString('utf8'));
      check(owner.sourceCommit === ctx.sourceCommit && owner.exclusive === true && owner.network === 'regtest' && typeof owner.ownerId === 'string' && owner.ownerId.length > 0);
      bundle.live.ownerPlan = retain('live/owner-plan.json', actual.files.get('owner-plan.json'));
      const retained = new Set(['row.json', 'report.json', 'receipt.json', 'capture.json', 'owner-plan.json', ...requiredLiveRows.map(id => `${id}.json`)]);
      for (const id of requiredLiveRows) {
        const observed = JSON.parse(actual.files.get(`${id}.json`).toString('utf8'));
        check(observed.sourceCommit === ctx.sourceCommit && observed.compiledCommit === ctx.compiledCommit && observed.tarballSha256 === ctx.tarballSha256 && observed.row === id && observed.complete === true);
        const references = validateObservations(id, observed, reference => {
          const bytes = actual.files.get(reference.path); check(bytes && hash(bytes) === reference.sha256);
          return JSON.parse(bytes.toString('utf8'));
        }, { ...binding(ctx), ownerId: owner.ownerId });
        observed.observations = references.map(reference => {
          check(!retained.has(reference.path)); retained.add(reference.path);
          return retain(`live/observations/${reference.path}`, actual.files.get(reference.path));
        });
        bundle.live.rows.push({ id, status: 'PASS', evidence: retain(`live/${id}.json`, Buffer.from(JSON.stringify(observed) + '\n')) });
      }
      check([...actual.files.keys()].every(path => retained.has(path)));
    }
  }
  for (const [kind, field] of [['demo', 'demo'], ['leak-scan', 'leakScan'], ['installed-smoke', 'installedSmoke'], ['publisher', 'publisher']]) {
    const actual = await row(`release/${kind}`); bundle[field] = actual.row;
    if (kind === 'demo') {
      const bytes = actual.files.get('scenario.json'); check(bytes);
      const evidence = JSON.parse(actual.files.get('evidence.json').toString('utf8'));
      check(evidence.scenarioRecord?.path === 'release/demo/scenario.json' && evidence.scenarioRecord.sha256 === hash(bytes)); retain(evidence.scenarioRecord.path, bytes);
    }
  }
  put(join(directory, 'release-evidence.json'), bundle); scan([directory]);
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [operation, ...args] = process.argv.slice(2);
    if (operation === 'package' && args.length === 0) {
      run('npm', ['pack', '--pack-destination', process.env.FLUXWARDEN_RELEASE_OUTPUT]); const ctx = context(); run('node', ['scripts/release-smoke.mjs', process.env.FLUXWARDEN_FINAL_TARBALL]);
      check(process.env.GITHUB_OUTPUT); fs.appendFileSync(process.env.GITHUB_OUTPUT, `sha256=${ctx.tarballSha256}\n`);
    } else {
      const github = officialGitHub(process.env.GITHUB_TOKEN);
      if (operation === 'fetch' && args.length === 0) await fetchCandidate(github);
      else if (operation === 'inventory' && args.length === 4 && args[0] === '--os' && args[2] === '--node') await collectInventory(github, args[1], args[3]);
      else if (operation === 'seal' && args.length === 2 && args[0] === '--key') await sealReport(github, args[1]);
      else if (operation === 'producer' && args.length === 2 && args[0] === '--kind') await producer(github, args[1]);
      else if (operation === 'aggregate' && args.length === 0) await aggregateEvidence(github);
      else throw new Error('release evidence: unsupported operation');
    }
  } catch { process.stderr.write('release evidence: authenticated prerequisite unavailable or validation failed\n'); process.exitCode = 1; }
}
