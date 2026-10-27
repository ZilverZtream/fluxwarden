// Provision declarations exclusively for this invocation, using the ordinary lab
// lifecycle and its allocation fencing (labs/docker/owner.mjs). No retained
// observation or PASS result is synthesized by this preparation tool.
import { createHash, randomUUID, randomInt } from 'node:crypto';
import { readFile, writeFile, appendFile, copyFile, lstat } from 'node:fs/promises';
import { execFile, spawnSync } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPrivateDirectory, assertPrivateDirectories } from './private-scratch.mjs';
import { preparePinnedCredentialSources } from './live-credential-sources.mjs';
import { capturePlanner, prepareChaos, measureValidation, setRunner } from '../labs/scenarios/live-profile.mjs';
setRunner(spawnSync);
const execute = promisify(execFile);
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const put = (path, data) => writeFile(path, JSON.stringify(data, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
const read = async path => JSON.parse(await readFile(path, 'utf8'));
const services = ['bitcoind', 'lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m', 'toxiproxy'];
const lightning = services.filter(service => /^(lnd|cln)-/.test(service));
// Read only the trusted repository/full-commit pairs in the independent contract.
// Git never runs upstream hooks or programs, and prompts and lazy fetch are off.
async function pinnedCheckouts(staticRoot) {
  if (process.env.FLUXWARDEN_LAB_SOURCE_CHECKOUTS) {
    if (!isAbsolute(process.env.FLUXWARDEN_LAB_SOURCE_CHECKOUTS)) throw new Error('required-live preparation: absolute source checkout input required');
    return read(process.env.FLUXWARDEN_LAB_SOURCE_CHECKOUTS);
  }
  const contract = await read(join(root, 'labs/fixtures/credential-reference-contract.json')), checkouts = {};
  for (const [name, pin] of Object.entries(contract.repositories)) {
    const directory = await createPrivateDirectory(staticRoot, `${name}-upstream-`);
    for (const args of [['init', '--bare', directory], ['-C', directory, 'remote', 'add', 'origin', pin.url],
      ['-C', directory, 'fetch', '--depth=1', '--no-tags', 'origin', pin.commit],
      ...(pin.revision === pin.commit || /^[a-f0-9]+$/.test(pin.revision) ? [] : [['-C', directory, 'update-ref', `refs/tags/${pin.revision}`, pin.commit]])]) {
      await execute('git', ['-c', 'core.hooksPath=', ...args], { cwd: root, windowsHide: true, timeout: 180_000,
        env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_NO_LAZY_FETCH: '1', GIT_CONFIG_NOSYSTEM: '1',
          GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null' } });
    }
    checkouts[name] = directory;
  }
  return checkouts;
}
async function currentSource() {
  return (await execute('git', ['rev-parse', 'HEAD'], { cwd: root, windowsHide: true, timeout: 15_000 })).stdout.trim();
}
async function publishEnvironment(env) {
  if (!process.env.GITHUB_ENV) throw new Error('required-live preparation: workflow environment required');
  for (const value of Object.values(env)) if (typeof value !== 'string' || /[\r\n\0]/.test(value)) throw new Error('required-live preparation: invalid environment');
  await appendFile(process.env.GITHUB_ENV, Object.entries(env).map(([key, value]) => `${key}=${value}\n`).join(''));
}

export async function prepareOwnedLive(parent, sourceCommit) {
  if (!isAbsolute(parent) || !/^[a-f0-9]{40}$/.test(sourceCommit)) throw new Error('required-live preparation: absolute private parent and source required');
  const directory = await createPrivateDirectory(parent, 'release-live-');
  const id = randomUUID(), ownerId = `ci-${id}`, base = randomInt(20000, 60000);
  const owners = [];
  for (let index = 0; index < 3; index++) {
    const ownerRoot = await createPrivateDirectory(directory, `owner-${index}-`), paths = {};
    for (const [key, prefix] of [['runtimeRoot', 'runtime-'], ['tmpRoot', 'tmp-'], ['sentinelRoot', 'sentinels-'], ['evidenceRoot', 'evidence-']]) paths[key] = await createPrivateDirectory(ownerRoot, prefix);
    const owner = { version: 1, id: `${ownerId}-${index}`, project: `fluxwarden-lab-${id}-${index}`, ...paths,
      ports: { lndRest: base + index * 3, clnRest: base + index * 3 + 1, toxiproxy: base + index * 3 + 2 },
      resources: { cpus: 2, memoryBytes: 2147483648, pids: 512 },
      credentialPolicy: { maxPrincipalMsat: '100000000', callsPerMinute: '600',
        lndRootKeyIds: { 'lnd-p': { read: '1001', execute: '1002' }, 'lnd-r': { read: '2001', execute: '2002' } } } };
    const declaration = join(ownerRoot, 'owner.json'); await put(declaration, owner); owners.push({ declaration, owner });
  }
  await assertPrivateDirectories(owners.flatMap(({ owner }) => ['runtimeRoot', 'tmpRoot', 'sentinelRoot', 'evidenceRoot'].map(key => owner[key])));
  const staticRoot = await createPrivateDirectory(directory, 'static-');
  const sources = await preparePinnedCredentialSources({ directory: join(staticRoot, 'sources'), checkouts: await pinnedCheckouts(staticRoot) });
  const compose = await readFile(join(root, 'labs/docker/docker-compose.yml'), 'utf8');
  const imagePins = Object.fromEntries(services.map(service => {
    const section = compose.split(`  ${service}:`)[1]?.split(/\r?\n {2}\S/)[0];
    const image = section?.match(/image:\s*([^\s]+)/)?.[1];
    if (!image || !/@sha256:[a-f0-9]{64}$/.test(image)) throw new Error('required-live preparation: pinned compose image required');
    return [service, image];
  }));
  const credentialPlan = join(staticRoot, 'credential-plan.json');
  await put(credentialPlan, { version: 2, authorized: true, disposable: true, network: 'regtest', staticRoot,
    sourceManifest: sources.sourceManifest, bindingSourceManifest: sources.bindingSourceManifest,
    budget: { cpus: 8, memoryBytes: 8589934592, pids: 2048, workers: 2 },
    owners: owners.slice(1).map(({ declaration }) => ({ declaration, imagePins,
      endpointRefs: Object.fromEntries(lightning.map(node => [node, { node, transport: 'owned-node-https', certificate: { node }, roles: ['read', 'execute'] }])),
      changePassword: { kind: 'fresh-denial-control' } })) });
  const path = join(directory, 'live-plan.json');
  await put(path, { ...owners[0].owner, schemaVersion: 1, sourceCommit, exclusive: true, network: 'regtest', authorized: true, disposable: true,
    ownerId: owners[0].owner.id, directory, staticRoot, owner: owners[0].owner, ownerPath: owners[0].declaration, cohortOwners: owners.slice(1).map(row => row.declaration) });
  // Concrete two-owner lifecycle inputs. The independent suite observes outcomes.
  const scenarios = [
    { outcome: 'child-failure', trigger: { kind: 'owned-child-exit', service: 'lnd-p' } },
    { outcome: 'INVALID', trigger: { kind: 'invalid-network', service: 'lnd-p', network: 'mainnet' } },
    { outcome: 'timeout', trigger: { kind: 'deadline', service: 'lnd-p' } },
    { outcome: 'exception', trigger: { kind: 'transport-exception', service: 'lnd-p' } },
    { outcome: 'SIGINT', trigger: { kind: 'SIGINT' } }, { outcome: 'SIGTERM', trigger: { kind: 'SIGTERM' } },
  ];
  const resourcePlan = join(directory, 'lifecycle-plan.json');
  await put(resourcePlan, { version: 2, authorized: true, disposable: true, network: 'regtest', owners: owners.slice(1).map(({ declaration }) => ({ declaration, scenarios })) });
  return { path, environment: { FLUXWARDEN_REQUIRE_LIVE: '1', FLUXWARDEN_LAB_PLAN: path, FLUXWARDEN_LAB_OWNER: owners[0].declaration,
    FLUXWARDEN_LAB_RESOURCE_PLAN: resourcePlan, FLUXWARDEN_LAB_CREDENTIAL_PLAN: credentialPlan, FLUXWARDEN_REFERENCE_ROOT: sources.referenceRoot } };
}

async function selectedPlan() {
  const path = process.env.FLUXWARDEN_LAB_PLAN;
  if (!path || !isAbsolute(path)) throw new Error('required-live operation: explicit owner plan required');
  const info = await lstat(path), plan = await read(path);
  if (!info.isFile() || info.isSymbolicLink() || plan.schemaVersion !== 1 || plan.sourceCommit !== await currentSource() ||
    plan.network !== 'regtest' || plan.exclusive !== true || plan.authorized !== true || plan.disposable !== true ||
    !isAbsolute(plan.directory) || resolve(path) !== join(plan.directory, 'live-plan.json')) throw new Error('required-live operation: source-bound owned plan required');
  const owner = await read(plan.ownerPath);
  if (owner.id !== plan.ownerId) throw new Error('required-live operation: owner identity mismatch');
  await assertPrivateDirectories(['runtimeRoot', 'tmpRoot', 'sentinelRoot', 'evidenceRoot'].map(key => owner[key]));
  return { plan, owner };
}

export async function startOwnedLive(publishToWorkflow = false, profile = '') {
  const { plan, owner } = await selectedPlan();
  const { createLab } = await import('../labs/docker/lab.mjs');
  const controller = new AbortController(), interrupt = () => controller.abort();
  process.on('SIGINT', interrupt); process.on('SIGTERM', interrupt);
  const lab = createLab({ owner, signal: controller.signal });
  let acquired = false;
  try {
    const manifest = await lab.up(); acquired = true;
    const composeFile = join(owner.runtimeRoot, 'release-compose.yml');
    await copyFile(join(root, 'labs/docker/docker-compose.yml'), composeFile);
    const invocation = randomUUID();
    const oraclePath = join(plan.directory, `oracle-owner-${invocation}.json`);
    await put(oraclePath, { authorized: true, disposable: true, network: 'regtest', project: owner.project, composeFile,
      imagePins: Object.fromEntries(services.map(service => [service, manifest.images[service.split('-')[0]].reference])),
      pubkeys: Object.fromEntries(lightning.map(node => [node, manifest.nodes[node].pubkey])) });
    const node = (name, port, credentialKey) => ({ service: name, host: '127.0.0.1', port,
      tlsCert: manifest.nodes[name].certificate.path, [credentialKey]: manifest.credentials[name].execute.path, pubkey: manifest.nodes[name].pubkey });
    const adapterPath = join(plan.directory, `adapter-plan-${invocation}.json`);
    await put(adapterPath, { version: 1, disposable: true, network: 'regtest', project: owner.project, composeFile,
      lnd: node('lnd-r', owner.ports.lndRest, 'macaroon'), cln: node('cln-m', owner.ports.clnRest, 'rune'), wrongCert: manifest.nodes['lnd-p'].certificate.path });
    const faultPath = join(plan.directory, `toxiproxy-owners-${invocation}.json`);
    await put(faultPath, { authorized: true, disposable: true, network: 'regtest', owners: [{ project: owner.project,
      ports: owner.ports, resources: owner.resources, allowToxiproxyRestart: true, credentials: {
        tlsCertificate: manifest.nodes['lnd-r'].certificate.path, macaroon: manifest.credentials['lnd-r'].execute.path,
        clnCertificate: manifest.nodes['cln-m'].certificate.path, rune: manifest.credentials['cln-m'].execute.path } }] });
    const environment = { FLUXWARDEN_LAB_ORACLE_OWNER: oraclePath, FLUXWARDEN_LAB_ADAPTER_PLAN: adapterPath, FLUXWARDEN_TOXIPROXY_OWNERS: faultPath };
    if (profile === 'planner') {
      const capture = capturePlanner({ ownerPath: plan.ownerPath, sourceCommit: plan.sourceCommit });
      environment.FLUXWARDEN_LAB_CAPTURE_DIR = capture.captureDir;
    } else if (profile === 'chaos') {
      const chaos = await prepareChaos({ ownerPath: plan.ownerPath, sourceRoot: root, sourceCommit: plan.sourceCommit });
      environment.FLUXWARDEN_CHAOS_REFERENCE_PLAN = chaos.planPath;
    } else if (profile !== '') throw new Error('required-live startup: unknown profile');
    Object.assign(process.env, environment);
    if (publishToWorkflow) await publishEnvironment(environment);
    await put(join(plan.directory, 'started.json'), { ownerId: owner.id, project: owner.project, sourceCommit: plan.sourceCommit });
    await put(join(plan.directory, 'startup-environment.json'), environment);
  } catch {
    if (acquired) await lab.down();
    throw new Error('required-live startup: failed');
  } finally { process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', interrupt); }
}

export async function stopOwnedLive() {
  const { plan, owner } = await selectedPlan();
  let started;
  try { started = await read(join(plan.directory, 'started.json')); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  if (started.ownerId !== owner.id || started.project !== owner.project || started.sourceCommit !== plan.sourceCommit) throw new Error('required-live cleanup: ownership receipt required');
  const { createLab } = await import('../labs/docker/lab.mjs');
  await createLab({ owner }).down();
  await put(join(plan.directory, `cleaned-${randomUUID()}.json`), { ownerId: owner.id, project: owner.project, sourceCommit: plan.sourceCommit });
  await (await import('node:fs/promises')).unlink(join(plan.directory, 'started.json'));
  await (await import('node:fs/promises')).unlink(join(plan.directory, 'startup-environment.json'));
  for (const key of ['FLUXWARDEN_LAB_ORACLE_OWNER', 'FLUXWARDEN_LAB_ADAPTER_PLAN', 'FLUXWARDEN_TOXIPROXY_OWNERS',
    'FLUXWARDEN_LAB_CAPTURE_DIR', 'FLUXWARDEN_CHAOS_REFERENCE_PLAN']) Reflect.deleteProperty(process.env, key);
}

export async function startFaultPeer() {
  const { plan } = await selectedPlan(), owner = await read(plan.cohortOwners[0]);
  const { createLab } = await import('../labs/docker/lab.mjs');
  const lab = createLab({ owner }), manifest = await lab.up();
  try {
    const faultPath = process.env.FLUXWARDEN_TOXIPROXY_OWNERS, faults = await read(faultPath);
    faults.owners.push({ project: owner.project, ports: owner.ports, resources: owner.resources, allowToxiproxyRestart: true, credentials: {
      tlsCertificate: manifest.nodes['lnd-r'].certificate.path, macaroon: manifest.credentials['lnd-r'].execute.path,
      clnCertificate: manifest.nodes['cln-m'].certificate.path, rune: manifest.credentials['cln-m'].execute.path } });
    const path = join(plan.directory, `two-owner-faults-${randomUUID()}.json`); await put(path, faults);
    process.env.FLUXWARDEN_TOXIPROXY_OWNERS = path;
    return () => lab.down();
  } catch { await lab.down(); throw new Error('required-live fault peer: failed'); }
}

export async function prepareLiveValidation(publishToWorkflow = false) {
  const { plan } = await selectedPlan();
  const evidenceRoot = await createPrivateDirectory(plan.directory, 'validation-');
  const selectedPath = join(evidenceRoot, 'collected.json');
  const env = { ...process.env, FLUXWARDEN_LIVE_EXTERNAL_OWNER: '1' };
  delete env.FLUXWARDEN_REQUIRE_LIVE;
  await execute(process.execPath, ['scripts/ci-test-driver.mjs', 'list', '--config', 'vitest.lab.config.ts',
    'test/lab/facts/cp010-smoke.live.test.ts', '--staticParse=false', `--json=${selectedPath}`],
  { cwd: root, env, windowsHide: true, timeout: 180_000, maxBuffer: 16 * 1024 * 1024 });
  const selection = (await read(selectedPath)).map(row => ({ file: row.file, fullName: row.name }));
  if (!selection.length || selection.some(row => !row.file.replaceAll('\\', '/').endsWith('/test/lab/facts/cp010-smoke.live.test.ts'))) throw new Error('required-live validation: independent smoke selection required');
  const collectedAt = Date.now();
  const source = await execute('git', ['ls-tree', '-r', '-z', plan.sourceCommit], { cwd: root, windowsHide: true, timeout: 15_000, maxBuffer: 16 * 1024 * 1024 });
  const sourceSha256 = createHash('sha256').update(source.stdout).digest('hex');
  const host = operation => [process.execPath, 'scripts/release-live.mjs', operation];
  const measured = await measureValidation({ sourceRoot: root, sourceSha256, invocation: randomUUID(), evidenceRoot, selection, collectedAt,
    env: { ...process.env, FLUXWARDEN_LIVE_EXTERNAL_OWNER: '1' }, commands: {
      build: host('validation-build'), setup: host('up'),
      run: [{ argv: [...host('validation-run'), join(evidenceRoot, 'smoke.json')], report: 'smoke.json' }], teardown: host('down'),
      leak: [process.execPath, 'scripts/leak-check.mjs', '--sentinels', 'test/sentinels.json', '--sentinel-dir', process.env.FLUXWARDEN_SENTINEL_DIR,
        evidenceRoot, process.env.FLUXWARDEN_EVIDENCE_DIR, plan.owner.evidenceRoot] } });
  const environment = { FLUXWARDEN_LAB_VALIDATION_PLAN: measured.planPath };
  Object.assign(process.env, environment);
  if (publishToWorkflow) await publishEnvironment(environment);
  return measured;
}

export async function prepareOwnedDemo() {
  const { plan } = await selectedPlan();
  await stopOwnedLive();
  const compiled = await read(join(root, 'dist/evidence/build-info.json'));
  if (compiled.gitCommit !== plan.sourceCommit || !isAbsolute(process.env.FLUXWARDEN_FINAL_TARBALL ?? '')) throw new Error('required-live demo: exact build and package required');
  const output = await createPrivateDirectory(plan.directory, 'demo-output-');
  const { produceDemo } = await import('./release-demo.mjs');
  await produceDemo({ sourceCommit: plan.sourceCommit, compiledCommit: compiled.gitCommit,
    tarballSha256: createHash('sha256').update(await readFile(process.env.FLUXWARDEN_FINAL_TARBALL)).digest('hex'), output });
}

function checkedCommand(args) {
  const result = spawnSync(process.execPath, args, { cwd: root, env: process.env, encoding: 'utf8', windowsHide: true,
    shell: false, timeout: 180_000, maxBuffer: 16 * 1024 * 1024 });
  if (result.error || result.signal !== null || result.status !== 0) throw new Error('required-live validation: actual phase failed');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args[0] === 'validation-run' && args.length === 2 && isAbsolute(args[1])) {
      const { plan } = await selectedPlan();
      Object.assign(process.env, await read(join(plan.directory, 'startup-environment.json')));
      checkedCommand(['scripts/ci-test-driver.mjs', 'run', '--config', 'vitest.lab.config.ts', 'test/lab/facts/cp010-smoke.live.test.ts', '--reporter=json', '--outputFile.json', args[1]]);
    } else if (args.length !== 1) throw new Error('required-live operation: one operation required');
    else if (args[0] === 'prepare') {
      const result = await prepareOwnedLive(process.env.FLUXWARDEN_CI_TMP_PARENT, await currentSource());
      if (process.env.GITHUB_ENV) await publishEnvironment(result.environment);
      else process.stdout.write(JSON.stringify(result.environment) + '\n');
    } else if (args[0] === 'up') await startOwnedLive(Boolean(process.env.GITHUB_ENV));
    else if (args[0] === 'down') await stopOwnedLive();
    else if (args[0] === 'measure') {
      const result = await prepareLiveValidation(Boolean(process.env.GITHUB_ENV));
      if (!process.env.GITHUB_ENV) process.stdout.write(JSON.stringify({ FLUXWARDEN_LAB_VALIDATION_PLAN: result.planPath }) + '\n');
    }
    else if (args[0] === 'validation-build') {
      checkedCommand(['node_modules/typescript/bin/tsc', '-p', 'tsconfig.json']);
      checkedCommand(['scripts/build-info.mjs']);
    }
    else throw new Error('required-live operation: unsupported operation');
  } catch { process.stderr.write('required-live preparation or lifecycle failed\n'); process.exitCode = 1; }
}
