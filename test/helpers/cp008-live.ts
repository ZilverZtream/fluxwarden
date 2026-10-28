import { spawn, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto';
import { appendFileSync, closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { request } from 'node:https';
import { setTimeout as delay } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect } from 'vitest';
import { asRecord, readJson, repoRoot } from './cli.js';
import { productInventory } from './leak-scan.js';
import { declareFixturePaths } from './capture-fixture.js';
import type { BindingProducer, BindingRequest, BoundOwner, Endpoint } from '../../labs/scenarios/credentials/producer-contract.d.mts';
import { afterBothFreshStarts, verifyFreshBinding } from './cp008-fresh-binding.js';
import { verifySourceManifest } from './cp008-source-contract.js';
import { allServices, docker, dockerText, identity, oracle, rows, LabInvalidError, type OracleOwner } from './cp006-oracle.js';
import type { Owner } from './cp006-lab.js';
import { nodes, readMethods, executeMethods, forbiddenCln, type Node, type Role, type Policy, type Params } from './cp008-credentials.js';

export const titles = [
  'CP-008/R1 both LND nodes distinguish read and execute authority with valid route and administrative controls',
  'CP-008/R2 all CLN nodes prove actual method authorization and separately authenticated checkrune controls',
  'CP-008/R3 stored role authority has independently revocable roots exact restrictions and owner-only fingerprints',
  'CP-008/RA15 actual pinned sendpay bounds and missing amount controls agree with OR and AND restrictions',
  'CP-008/R4 minimal LND credentials prove invoice permission mapping and URI scoping on pinned nodes',
  'CP-008/Rowner two ordinary owners have measured allocations workers complete inventory and real cleanup',
  'CP-008/Rleak fresh complete retained artifacts reject every planted encoding and missing sentinel registration',
] as const;

export interface LiveOwner {
  declaration: string;
  owner: Owner & { credentialPolicy: Policy };
  oracle: OracleOwner;
  endpointRefs: BindingRequest['endpointRefs'];
  changePassword: BindingRequest['changePassword'];
  endpoints?: Record<Node, Endpoint>;
  // Named request parameters, never expected responses. Password bytes remain file-only.
  changePasswordFile?: string;
}
export interface Plan {
  version: 2;
  staticRoot: string;
  sourceManifest: string;
  bindingSourceManifest: string;
  owners: LiveOwner[];
  budget: { cpus: number; memoryBytes: number; pids: number; workers: number };
}
interface PrivateIO {
  assertPrivateDirectory(path: string): Promise<void>;
  createPrivateDirectory(parent: string, prefix: string): Promise<string>;
}
interface Response { status: number; body: Record<string, unknown> }
const roles: Role[] = ['read', 'execute'];
const maxDuration = 180_000;
const validatePlan = new Ajv2020.default({ strict: true }).compile(readJson('labs/fixtures/credential-plan.schema.json') as object);
function string(value: unknown): string { if (typeof value !== 'string' || !value) throw new LabInvalidError('explicit nonempty declaration value required'); return value; }
function absolute(value: unknown): string { const path = string(value); if (!isAbsolute(path)) throw new LabInvalidError('absolute declaration path required'); return resolve(path); }
function json(path: string): Record<string, unknown> { try { return asRecord(JSON.parse(readFileSync(path, 'utf8')) as unknown, 'declaration'); } catch { throw new LabInvalidError('declaration is absent unreadable or malformed'); } }
function within(root: string, path: string): boolean { const part = relative(resolve(root), resolve(path)); return part !== '' && !part.startsWith('..') && !isAbsolute(part); }
function positive(value: unknown, upper: number): number { if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0 || value > upper) throw new LabInvalidError('explicit bounded allocation required'); return value; }
function decimal(value: unknown, upper?: bigint): string { const text = string(value); if (!/^[1-9][0-9]*$/.test(text) || (upper !== undefined && BigInt(text) > upper)) throw new LabInvalidError('canonical positive decimal policy required'); return text; }
function bytes32(value: unknown): Buffer {
  const text = string(value), bytes = Buffer.from(text, /^[a-f0-9]{64}$/i.test(text) ? 'hex' : 'base64');
  if (bytes.length !== 32) throw new LabInvalidError('observed node bytes field must contain exactly 32 bytes');
  return bytes;
}
function checkedFile(path: string): Buffer {
  // Independent native descriptor checks, not a producer permission boolean.
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink() || before.uid !== process.getuid?.() || (before.mode & 0o777) !== 0o600 || before.size === 0 || before.size > 65536) throw new LabInvalidError('owned file must be a nonempty owner-only regular file within 64 KiB');
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const after = fstatSync(descriptor);
    if (after.ino !== before.ino || after.dev !== before.dev || after.uid !== before.uid || after.mode !== before.mode) throw new LabInvalidError('owned file changed during checked read');
    return readFileSync(descriptor);
  } finally { closeSync(descriptor); }
}
export function credentialPlan(input = process.env['FLUXWARDEN_LAB_CREDENTIAL_PLAN']): Plan {
  if (!input || !isAbsolute(input)) throw new LabInvalidError('absolute explicit owned-regtest credential plan required before Docker');
  const plan = json(input);
  if (!validatePlan(plan)) throw new LabInvalidError('version2 fresh-reference disposable regtest credential plan required');
  const staticRoot = absolute(plan['staticRoot']);
  const budget = asRecord(plan['budget'], 'aggregate allocation');
  const selected = rows(plan['owners'], 'two explicit owners');
  if (selected.length !== 2) throw new LabInvalidError('exactly two explicit owners required');
  const owners = selected.map((raw): LiveOwner => {
    const declaration = absolute(raw['declaration']), owner = json(declaration);
    if (owner['version'] !== 1 || !/^[a-z0-9-]+$/.test(string(owner['id'])) || !/^fluxwarden-lab-[a-z0-9-]+$/.test(string(owner['project']))) throw new LabInvalidError('ordinary version 1 isolated owner required');
    for (const key of ['runtimeRoot', 'tmpRoot', 'sentinelRoot', 'evidenceRoot']) absolute(owner[key]);
    const ports = asRecord(owner['ports'], 'ordinary owner ports'), resource = asRecord(owner['resources'], 'ordinary owner allocation');
    for (const key of ['lndRest', 'clnRest', 'toxiproxy']) { const value = positive(ports[key], 65535); if (!Number.isInteger(value) || value < 1024) throw new LabInvalidError('explicit unprivileged port required'); }
    positive(resource['cpus'], 4); positive(resource['memoryBytes'], 4294967296); positive(resource['pids'], 1024);
    const policy = asRecord(owner['credentialPolicy'], 'explicit ordinary credential policy');
    decimal(policy['maxPrincipalMsat'], 9223372036854775807n); decimal(policy['callsPerMinute']);
    const ids = asRecord(policy['lndRootKeyIds'], 'per-node root ids');
    for (const node of ['lnd-p', 'lnd-r']) {
      const pair = asRecord(ids[node], 'independent role roots');
      for (const role of roles) decimal(pair[role], 18446744073709551615n);
      if (pair['read'] === pair['execute']) throw new LabInvalidError('independently revocable role roots required');
    }
    const pins = asRecord(raw['imagePins'], 'independently supplied image pins');
    for (const service of allServices) if (!/^\S+@sha256:[a-f0-9]{64}$/.test(string(pins[service]))) throw new LabInvalidError('all pinned image digests required');
    const endpointRefs = asRecord(raw['endpointRefs'], 'declared late-bound HTTPS references');
    for (const node of nodes) {
      const ref = asRecord(endpointRefs[node], 'node reference');
      if (ref['node'] !== node || asRecord(ref['certificate'], 'certificate reference')['node'] !== node) throw new LabInvalidError('node and certificate references must match their declared owner node');
    }
    return { declaration, owner: owner as unknown as LiveOwner['owner'], endpointRefs: endpointRefs as unknown as BindingRequest['endpointRefs'],
      changePassword: { kind: 'fresh-denial-control' }, oracle: { project: string(owner['project']),
        composeFile: join(absolute(owner['runtimeRoot']), 'compose-owner.json'), imagePins: pins as Record<string, string>, pubkeys: {} } };
  });
  const roots = owners.flatMap(({ owner }) => [owner.runtimeRoot, owner.tmpRoot, owner.sentinelRoot, owner.evidenceRoot].map(path => process.platform === 'win32' ? resolve(path).toLowerCase() : resolve(path)));
  if (new Set(owners.map(({ owner }) => owner.project)).size !== 2 || new Set(owners.map(({ owner }) => owner.id)).size !== 2 || new Set(owners.flatMap(({ owner }) => Object.values(owner.ports))).size !== 6) throw new LabInvalidError('owner identities projects and ports must be disjoint');
  for (const [index, root] of roots.entries()) for (const other of roots.slice(index + 1)) if (root === other || within(root, other) || within(other, root)) throw new LabInvalidError('owner roots must be disjoint and unnested');
  for (const root of roots) if (relative(root, staticRoot) === '' || within(root, staticRoot) || within(staticRoot, root)) throw new LabInvalidError('immutable source and policy root must survive all owned runtime cleanup');
  const sourceManifest = absolute(plan['sourceManifest']), bindingSourceManifest = absolute(plan['bindingSourceManifest']);
  if (![sourceManifest, bindingSourceManifest].every(path => within(staticRoot, path))) throw new LabInvalidError('source manifests require the immutable static root');
  for (const item of owners) for (const root of owners.flatMap(value => [value.owner.runtimeRoot, value.owner.tmpRoot])) {
    if (item.declaration === root || within(root, item.declaration) || resolve(input) === root || within(root, resolve(input))) throw new LabInvalidError('plan and owner declarations must survive ordinary cleanup');
  }
  const allocation = { cpus: positive(budget['cpus'], 8), memoryBytes: positive(budget['memoryBytes'], 8589934592), pids: positive(budget['pids'], 2048), workers: positive(budget['workers'], 2) };
  if (allocation.workers !== 2) throw new LabInvalidError('two actual owner workers required within declared budget');
  for (const key of ['cpus', 'memoryBytes', 'pids'] as const) if (owners.reduce((sum, value) => sum + value.owner.resources[key], 0) > allocation[key]) throw new LabInvalidError('aggregate declared owners exceed budget');
  return { version: 2, staticRoot, sourceManifest, bindingSourceManifest, owners, budget: allocation };
}
export function rolePath(item: LiveOwner, node: Node, role: Role): string { return join(item.owner.runtimeRoot, 'credentials', node, `${role}.${node.startsWith('lnd-') ? 'macaroon' : 'rune'}`); }
export function fingerprint(bytes: Uint8Array): string { return `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`; }
/** Docker RepoDigests uses repository@digest even when Config.Image retained
 * repository:tag@digest. A registry port belongs to the repository, not a tag.
 */
export function hasPinnedRepoDigest(observed: unknown, requested: string): boolean {
  const match = /^([^@\s]+)@(sha256:[a-f0-9]{64})$/.exec(requested);
  if (!match?.[1] || !match[2]) return false;
  const tagged = match[1], colon = tagged.lastIndexOf(':'), slash = tagged.lastIndexOf('/');
  if (colon > slash && colon === tagged.length - 1) return false;
  const repository = colon > slash ? tagged.slice(0, colon) : tagged;
  return repository !== '' && Array.isArray(observed) && observed.includes(`${repository}@${match[2]}`);
}
function containerIds(project: string): string[] { return dockerText(['ps', '-aq', '--filter', `label=com.docker.compose.project=${project}`]).split(/\s+/).filter(Boolean); }
function inventory(project: string): { containers: string[]; volumes: string[]; networks: string[] } {
  return { containers: containerIds(project), volumes: dockerText(['volume', 'ls', '-q', '--filter', `label=com.docker.compose.project=${project}`]).split(/\s+/).filter(Boolean), networks: dockerText(['network', 'ls', '-q', '--filter', `label=com.docker.compose.project=${project}`]).split(/\s+/).filter(Boolean) };
}
function unrelated(projects: string[]): string[] {
  return ['ps', 'volume', 'network'].flatMap(kind => dockerText(kind === 'ps' ? ['ps', '-a', '--no-trunc', '--format', '{{.ID}} {{.State}} {{.Labels}}'] : [kind, 'ls', '--format', '{{.Name}} {{.Labels}}']).split('\n').filter(line => line && !projects.some(project => line.includes(`com.docker.compose.project=${project}`)))).sort();
}
/** CP008 Rleak requires fresh independent format sentinels (needsLab:false).
 * These genuine private keys are SOURCE-only controls, never node or approval
 * authority, and are created directly in the already validated owned pool. */
export async function prepareCp008LeakSources(sentinelRoot: string, permissions: Pick<PrivateIO, 'assertPrivateDirectory'>): Promise<string[]> {
  await permissions.assertPrivateDirectory(sentinelRoot);
  const global = absolute(process.env['FLUXWARDEN_SENTINEL_DIR']);
  await permissions.assertPrivateDirectory(global);
  if (!within(global, sentinelRoot)) throw new LabInvalidError('owned format sources require the actual global source namespace before creation');
  const tls = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
  const approval = generateKeyPairSync('ed25519').privateKey;
  const paths = ([['tls-key', tls], ['approval-key', approval]] as const).map(([kind, key]) => {
    const path = join(sentinelRoot, `${kind}-${randomUUID()}.pem`);
    writeFileSync(path, key.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600, flag: 'wx' });
    return path;
  });
  const { protectCreated } = await import(pathToFileURL(join(repoRoot, 'labs/docker/owner.mjs')).href) as {
    protectCreated: (paths: readonly string[], options: { privateDirectories: readonly string[] }) => Promise<void>;
  };
  await protectCreated(paths, { privateDirectories: [sentinelRoot] });
  return paths;
}
export class Cohort {
  readonly cancellation = new AbortController();
  readonly runId = randomUUID();
  readonly completed: string[] = [];
  readonly phases: Record<string, number> = {};
  readonly bootstrap = new Map<string, string>();
  readonly bootstrapIds = new Map<string, { item: LiveOwner; node: Node; id: string }>();
  readonly allocations: { cpus: number; memoryBytes: number; pids: number }[] = [];
  readonly workers = new Set<number>();
  peakWorkers = 0;
  readonly processExits: { operation: string; pid: number; exit: number | null }[] = [];
  readonly lastUse = new Map<string, number>();
  plan!: Plan;
  privateIO!: PrivateIO;
  before: string[] = [];
  started: LiveOwner[] = [];
  begin = performance.now();
  async initialize(): Promise<void> {
    // Plan refusal is deliberately first, including on Windows and with no Docker installed.
    this.plan = credentialPlan();
    if (process.platform === 'win32') throw new LabInvalidError('native owner-file and ordinary all-node HTTPS live proof requires the declared POSIX lab host');
    this.privateIO = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as PrivateIO;
    checkedFile(absolute(process.env['FLUXWARDEN_LAB_CREDENTIAL_PLAN']));
    await this.privateIO.assertPrivateDirectory(this.plan.staticRoot);
    verifySourceManifest(this.plan.sourceManifest, 'credential-primary-v1', this.plan.staticRoot);
    verifySourceManifest(this.plan.bindingSourceManifest, 'credential-wire-v1', this.plan.staticRoot);
    for (const item of this.plan.owners) {
      checkedFile(item.declaration);
      if (!within(item.owner.runtimeRoot, item.oracle.composeFile)) throw new LabInvalidError('explicit compose file must be under the owned runtime root');
      for (const root of [item.owner.runtimeRoot, item.owner.tmpRoot, item.owner.sentinelRoot, item.owner.evidenceRoot]) await this.privateIO.assertPrivateDirectory(root);
      await prepareCp008LeakSources(item.owner.sentinelRoot, this.privateIO);
      this.retain(item, 'inventory', { runId: this.runId, file: 'test/lab/cp008-credentials.live.test.ts', titles, sourceManifestHash: createHash('sha256').update(readFileSync(this.plan.sourceManifest)).digest('hex'), bindingSourceManifestHash: createHash('sha256').update(readFileSync(this.plan.bindingSourceManifest)).digest('hex'), planHash: createHash('sha256').update(readFileSync(absolute(process.env['FLUXWARDEN_LAB_CREDENTIAL_PLAN']))).digest('hex') });
    }
    this.before = unrelated(this.plan.owners.map(item => item.owner.project));
    for (const item of this.plan.owners) if (Object.values(inventory(item.owner.project)).some(values => values.length)) throw new LabInvalidError('fresh explicit owners already have resources');
    const binder = await import(pathToFileURL(join(repoRoot, 'scripts/live-credential-binding.mjs')).href) as BindingProducer;
    const setup = performance.now();
    // Simultaneous ordinary CLI processes; no verifier/proof hooks or injected transports.
    await afterBothFreshStarts(this.plan.owners.map(async item => { this.started.push(item); return this.command(item, 'up'); }), async () => {
      for (const item of this.plan.owners) {
        const receipt = await binder.bindFreshCredentialOwner({ declaration: item.declaration, imagePins: item.oracle.imagePins,
          endpointRefs: item.endpointRefs, changePassword: item.changePassword, signal: this.cancellation.signal });
        await this.acceptFreshBinding(item, receipt);
      }
    });
    this.phases['setup'] = performance.now() - setup;
    for (const item of this.plan.owners) {
      this.observe(item);
      try {
        const response = await fetch(`http://127.0.0.1:${String(item.owner.ports.toxiproxy)}/proxies`, { signal: AbortSignal.timeout(3000) });
        if (!response.ok) throw new Error();
        const proxies = asRecord(await response.json() as unknown, 'observed owned proxies');
        if (Object.keys(proxies).length !== 2 || Object.values(proxies).some(value => { const proxy = asRecord(value, 'actual proxy'); return proxy['enabled'] !== true || !Array.isArray(proxy['toxics']) || proxy['toxics'].length !== 0; })) throw new Error();
      } catch { throw new LabInvalidError('owned Toxiproxy is unavailable disabled or dirty before permission controls'); }
      for (const node of nodes) for (const role of roles) await this.register(item, rolePath(item, node, role), node.startsWith('lnd-') ? 'macaroon' : 'rune');
    }
  }
  async acceptFreshBinding(item: LiveOwner, receipt: BoundOwner): Promise<void> {
    const declaration = checkedFile(item.declaration), manifestBytes = checkedFile(join(item.owner.runtimeRoot, 'lab.json'));
    const observed = rows(docker(['inspect', ...containerIds(item.owner.project)]), 'independent fresh binding observations');
    verifyFreshBinding({ declaration: item.declaration, imagePins: item.oracle.imagePins, endpointRefs: item.endpointRefs,
      changePassword: item.changePassword }, item.owner, receipt, declaration, manifestBytes, observed);
    const manifest = asRecord(JSON.parse(manifestBytes.toString('utf8')) as unknown, 'fresh current manifest');
    for (const node of nodes) {
      const endpoint = receipt.endpoints[node], entry = asRecord(asRecord(manifest['nodes'], 'nodes')[node], 'node');
      item.oracle.pubkeys[node] = string(entry['pubkey']);
      const cert = asRecord(entry['certificate'], 'current certificate'), bytes = await this.bytes(endpoint.certificate);
      if (createHash('sha256').update(bytes).digest('hex') !== cert['sha256']) throw new LabInvalidError('current pinned certificate bytes mismatch');
      for (const role of roles) {
        const record = receipt.credentials[node][role], roleBytes = await this.bytes(record.path);
        if (record.path !== rolePath(item, node, role) || fingerprint(roleBytes) !== record.fingerprint) throw new LabInvalidError('current canonical role bytes or fingerprint mismatch');
      }
    }
    const requestBytes = await this.bytes(receipt.changePasswordFile);
    const params = asRecord(JSON.parse(requestBytes.toString('utf8')) as unknown, 'fresh disposable denial request');
    if (Object.keys(params).sort().join(',') !== 'current_password,new_password') throw new LabInvalidError('fresh denial request fields mismatch');
    const current = bytes32(params['current_password']), next = bytes32(params['new_password']);
    if (current.equals(next) || params['current_password'] !== current.toString('base64') || params['new_password'] !== next.toString('base64')) throw new LabInvalidError('distinct fresh canonical base64 denial controls required');
    // Register actual source bytes, without echoing a password request or its fields.
    for (const bytes of [current, next]) writeFileSync(join(item.owner.sentinelRoot, `password-control-${randomUUID()}.bin`), bytes, { mode: 0o600, flag: 'wx' });
    await this.register(item, receipt.changePasswordFile, 'password-request');
    item.endpoints = receipt.endpoints; item.changePasswordFile = receipt.changePasswordFile;
    this.retain(item, 'fresh-binding', receipt);
  }
  retain(item: LiveOwner, name: string, value: unknown): void { writeFileSync(join(item.owner.evidenceRoot, `cp008-${this.runId}-${name}.json`), JSON.stringify(value), { mode: 0o600, flag: 'w' }); }
  async command(item: LiveOwner, operation: 'up' | 'down'): Promise<number | null> {
    return await new Promise((done, reject) => {
      const child = spawn(process.execPath, [join(repoRoot, 'labs/docker/lab.mjs'), operation, '--owner', item.declaration], { cwd: repoRoot, shell: false, windowsHide: true, env: { ...process.env, VITEST_MAX_WORKERS: '99', VITEST_MAX_THREADS: '99' }, stdio: ['ignore', 'pipe', 'pipe'] });
      const pid = child.pid ?? 0; this.workers.add(pid);
      const observedWorkers = [...this.workers].filter(worker => { try { process.kill(worker, 0); return true; } catch { return false; } });
      this.peakWorkers = Math.max(this.peakWorkers, observedWorkers.length);
      this.retain(item, `${operation}-workers`, { pid, workers: [...this.workers], running: [...this.workers].map(worker => { try { process.kill(worker, 0); return true; } catch { return false; } }) });
      const chunks: Buffer[] = []; let size = 0, invalid = false;
      const capture = (bytes: Buffer) => { size += bytes.length; if (size > 65536) { invalid = true; child.kill('SIGKILL'); } else chunks.push(bytes); };
      child.stdout.on('data', capture); child.stderr.on('data', capture);
      const timer = setTimeout(() => { invalid = true; child.kill('SIGKILL'); }, maxDuration);
      child.once('error', () => { clearTimeout(timer); this.workers.delete(pid); reject(new LabInvalidError('ordinary CLI transport failed')); });
      child.once('close', exit => {
        clearTimeout(timer); this.workers.delete(pid); this.processExits.push({ operation, pid, exit });
        // Original output is retained for the independent leak scan, never attached to assertions.
        writeFileSync(join(item.owner.evidenceRoot, `cp008-${this.runId}-${operation}-original-output.txt`), Buffer.concat(chunks), { mode: 0o600 });
        this.retain(item, `${operation}-exit`, { pid, exit, invalid });
        if (invalid) reject(new LabInvalidError('ordinary CLI bounded capture or watchdog exhausted')); else done(exit);
      });
    });
  }
  observe(item: LiveOwner): void {
    const ids = containerIds(item.owner.project); expect(ids.length === 7, 'seven actual owned services').toBe(true);
    const observed = rows(docker(['inspect', ...ids]), 'actual owned allocations');
    const total = { cpus: 0, memoryBytes: 0, pids: 0 }; const published: number[] = [];
    const observations: unknown[] = [];
    for (const container of observed) {
      const config = asRecord(container['Config'], 'actual config'), labels = asRecord(config['Labels'], 'actual labels');
      const service = string(labels['com.docker.compose.service']); expect(labels['com.docker.compose.project']).toBe(item.owner.project);
      expect(config['Image']).toBe(item.oracle.imagePins[service]); expect(asRecord(container['State'], 'actual state')['Running']).toBe(true);
      const image = rows(docker(['image', 'inspect', string(container['Image'])]), 'actual image')[0];
      expect(hasPinnedRepoDigest(image?.['RepoDigests'], item.oracle.imagePins[service] ?? ''), 'actual repository digest').toBe(true);
      const limits = asRecord(container['HostConfig'], 'actual limits');
      total.cpus += positive(limits['NanoCpus'], 4e9) / 1e9; total.memoryBytes += positive(limits['Memory'], 4294967296); total.pids += positive(limits['PidsLimit'], 1024);
      const settings = asRecord(container['NetworkSettings'], 'actual network settings');
      const bindings = Object.values(asRecord(settings['Ports'], 'actual publications')).flatMap(value => value === null ? [] : rows(value, 'actual loopback bindings'));
      for (const binding of bindings) { expect(binding['HostIp']).toBe('127.0.0.1'); published.push(Number(binding['HostPort'])); }
      if (nodes.includes(service as Node)) {
        if (!item.endpoints) throw new LabInvalidError('fresh binding required before node observation');
        const node = service as Node, endpoint = item.endpoints[node];
        const networks = Object.values(asRecord(settings['Networks'], 'actual owned networks')).map(network => asRecord(network, 'owned network'));
        const direct = networks.some(network => network['IPAddress'] === endpoint.hostname) && endpoint.port === (node.startsWith('lnd-') ? 8080 : 3010);
        const loopback = endpoint.hostname === '127.0.0.1' && bindings.some(binding => Number(binding['HostPort']) === endpoint.port);
        if (!direct && !loopback) throw new LabInvalidError('endpoint is not an observed owned node HTTPS address');
        const info = oracle(item.oracle, node, 'getinfo');
        if (info[node.startsWith('lnd-') ? 'identity_pubkey' : 'id'] !== item.oracle.pubkeys[node]) throw new LabInvalidError('fresh native node differs from current manifest identity');
        item.oracle.pubkeys[node] = string(info[node.startsWith('lnd-') ? 'identity_pubkey' : 'id']); identity(item.oracle, node);
        this.retain(item, `identity-${node}`, { node, publicKey: item.oracle.pubkeys[node], version: info['version'], network: node.startsWith('lnd-') ? rows(info['chains'], 'observed identity chains')[0]?.['network'] : info['network'] });
        const channels = rows(oracle(item.oracle, node, node.startsWith('lnd-') ? 'listchannels' : 'listpeerchannels')['channels'], 'fresh channel state');
        const expectedCount: Record<Node, number> = { 'lnd-p': 1, 'lnd-r': 3, 'cln-p': 1, 'cln-r': 3, 'cln-m': 2 };
        if (channels.length !== expectedCount[node] || channels.some(channel => node.startsWith('lnd-') ? channel['active'] !== true : channel['state'] !== 'CHANNELD_NORMAL' || channel['peer_connected'] !== true)) throw new LabInvalidError('owned topology is dirty or not in the required active channel state');
        if (channels.some(channel => node.startsWith('lnd-') ? Array.isArray(channel['pending_htlcs']) && channel['pending_htlcs'].length > 0 : Array.isArray(channel['htlcs']) && channel['htlcs'].length > 0)) throw new LabInvalidError('owner has pending HTLCs before controls');
      }
      observations.push({ service, image: config['Image'], limits, bindings });
    }
    expect(published.sort((a, b) => a - b)).toEqual(Object.values(item.owner.ports).sort((a, b) => a - b));
    for (const key of ['cpus', 'memoryBytes', 'pids'] as const) expect(total[key]).toBeLessThanOrEqual(item.owner.resources[key]);
    this.allocations.push(total); this.retain(item, 'allocations', { observations, total, pubkeys: item.oracle.pubkeys });
    // SPEC 11.3: active events cannot replace both signed graph policies.
    for (const node of ['lnd-p', 'lnd-r'] as const) {
      const graph = rows(oracle(item.oracle, node, 'describegraph')['edges'], 'actual readiness graph');
      if (graph.length !== 5 || graph.some(edge => ['node1_policy', 'node2_policy'].some(key => { const policy = edge[key]; return typeof policy !== 'object' || policy === null || asRecord(policy, 'policy')['disabled'] !== false; }))) throw new LabInvalidError('owned graph lacks both signed usable policies for all five edges');
    }
    const chain = this.cli(item, 'bitcoind', 'getblockchaininfo'); if (chain['chain'] !== 'regtest') throw new LabInvalidError('owned chain is not regtest');
  }
  cliText(item: LiveOwner, node: string, method: string, params: string[] = []): string {
    const binary = node === 'bitcoind' ? ['bitcoin-cli', '-regtest'] : node.startsWith('lnd-') ? ['lncli', '--network=regtest'] : ['lightning-cli', '--network=regtest', '-k'];
    const result = spawnSync('docker', ['compose', '--project-name', item.owner.project, '-f', item.oracle.composeFile, 'exec', '-T', node, ...binary, method, ...params], { cwd: repoRoot, shell: false, windowsHide: true, encoding: 'utf8', maxBuffer: 65536, timeout: 30000 });
    this.retain(item, `cli-${randomUUID()}`, { node, method, exitCode: result.status, signal: result.signal, transportCompleted: result.error === undefined });
    // Raw command errors/bodies may contain secrets and must never become test errors.
    if (result.error || result.status !== 0) throw new LabInvalidError('independent owned node command failed');
    return result.stdout;
  }
  cli(item: LiveOwner, node: string, method: string, params: string[] = []): Record<string, unknown> {
    try { return asRecord(JSON.parse(this.cliText(item, node, method, params)) as unknown, 'node JSON'); } catch { throw new LabInvalidError('independent node command returned malformed JSON or failed'); }
  }
  async bytes(path: string): Promise<Buffer> {
    await this.privateIO.assertPrivateDirectory(resolve(path, '..'));
    return checkedFile(path);
  }
  async register(item: LiveOwner, path: string, kind: string): Promise<void> {
    const bytes = await this.bytes(path), destination = join(item.owner.sentinelRoot, `${kind}-${randomUUID()}.bin`);
    writeFileSync(destination, bytes, { mode: 0o600, flag: 'wx' });
    appendFileSync(join(item.owner.tmpRoot, 'declared-out.txt'), `${path}\n`);
  }
  registerPreimage(item: LiveOwner, value: unknown, encoding: 'hex' | 'base64'): void {
    if (typeof value !== 'string' || !value) return;
    const bytes = Buffer.from(value, encoding);
    if (bytes.length !== 32) throw new LabInvalidError('node preimage was not a 32-byte value');
    writeFileSync(join(item.owner.sentinelRoot, `preimage-${randomUUID()}.bin`), bytes, { mode: 0o600, flag: 'wx' });
  }
  async bootstrapPath(item: LiveOwner, node: Node): Promise<string> {
    const key = `${item.owner.project}/${node}`, old = this.bootstrap.get(key); if (old) return old;
    // Primary createrune request: restrictions only in argv, never secret rune bytes.
    const result = this.cli(item, node, 'createrune', ['restrictions=[["method=checkrune","method=sendpay"]]']);
    const path = join(item.owner.tmpRoot, `cp008-bootstrap-${node}-${this.runId}.rune`);
    writeFileSync(path, string(result['rune']), { mode: 0o600, flag: 'wx' });
    this.bootstrap.set(key, path); this.bootstrapIds.set(key, { item, node, id: string(result['unique_id']) }); await this.register(item, path, 'rune'); return path;
  }
  async http(item: LiveOwner, node: Node, path: string, method: string, params: Params, credential: string): Promise<Response> {
    if (!item.endpoints) throw new LabInvalidError('fresh binding required before any HTTPS use');
    const endpoint = item.endpoints[node], ca = await this.bytes(endpoint.certificate), bytes = await this.bytes(credential);
    const body = method === 'GET' ? undefined : JSON.stringify(params);
    return await new Promise((done, reject) => {
      const call = request({ hostname: endpoint.hostname, servername: endpoint.servername, port: endpoint.port, path, method, ca, rejectUnauthorized: true, signal: this.cancellation.signal,
        headers: { 'content-type': 'application/json', ...(node.startsWith('lnd-') ? { 'Grpc-Metadata-macaroon': bytes.toString('hex') } : { rune: bytes.toString('utf8') }) } }, response => {
        const chunks: Buffer[] = []; let length = 0;
        response.on('data', (chunk: Buffer) => { length += chunk.length; if (length > 65536) call.destroy(); else chunks.push(chunk); });
        response.once('error', () => { reject(new LabInvalidError('owned HTTPS response transport failed')); });
        response.once('end', () => { try { if (length > 65536) throw new Error(); done({ status: response.statusCode ?? 0, body: asRecord(JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown, 'response') }); } catch { reject(new LabInvalidError('owned HTTPS response malformed or oversized')); } });
      });
      const timer = setTimeout(() => { call.destroy(); reject(new LabInvalidError('owned HTTPS transport deadline')); }, 10000);
      call.once('error', () => { reject(new LabInvalidError('owned HTTPS or pinned TLS transport failed')); }); call.once('close', () => { clearTimeout(timer); }); call.end(body);
    });
  }
  async ready(item: LiveOwner, node: Node, role: Role): Promise<void> {
    if (node.startsWith('lnd-')) return;
    // showrunes observes last_used; checkrune and clnrest both consume this same-ID budget.
    const candidate = await this.bytes(rolePath(item, node, role));
    const actual = rows(this.cli(item, node, 'showrunes')['runes'], 'observed runes').find(rune => rune['rune'] === candidate.toString('utf8'));
    if (!actual) throw new LabInvalidError('stored candidate absent from actual node rune inventory');
    const key = `${item.owner.project}/${node}/${role}`, last = Math.max(typeof actual['last_used'] === 'number' ? actual['last_used'] * 1000 : 0, this.lastUse.get(key) ?? 0);
    const interval = (60000n + BigInt(item.owner.credentialPolicy.callsPerMinute) - 1n) / BigInt(item.owner.credentialPolicy.callsPerMinute);
    const remaining = last + Number(interval) + 10 - Date.now();
    if (remaining > 0) await delay(Math.min(remaining, 60010), undefined, { signal: this.cancellation.signal });
  }
  async cln(item: LiveOwner, node: Node, role: Role, method: string, params: Params, allowed: boolean, check = false): Promise<Record<string, unknown>> {
    await this.ready(item, node, role);
    const credential = check ? await this.bootstrapPath(item, node) : rolePath(item, node, role);
    const input = check ? { rune: (await this.bytes(rolePath(item, node, role))).toString('utf8'), method, params } : params;
    const result = await this.http(item, node, `/v1/${check ? 'checkrune' : method}`, 'POST', input, credential);
    const key = `${item.owner.project}/${node}/${role}`;
    const success = result.status === 200 && result.body['error'] === undefined && (check ? result.body['valid'] === true : result.body['code'] === undefined);
    const error = asRecord(result.body['error'] ?? result.body, 'CLN error classification');
    const message = typeof error['message'] === 'string' ? error['message'] : '';
    // 1502 also covers rate, so classify the reason before permitting a denial PASS.
    const denial = error['code'] === 1502 && !/rate|per |time|blacklist|expired/i.test(message) && /method|amount_msat/i.test(message);
    this.retain(item, `probe-${randomUUID()}`, { node, role, method, check, status: result.status, classification: success ? 'allowed' : denial ? 'permission-denied' : 'invalid', source: 'cln-checkrune.json/errors' });
    expect(allowed ? success : denial, `${node}/${role}/${method} actual ${check ? 'checkrune' : 'clnrest'} authorization classification`).toBe(true);
    if (success) this.lastUse.set(key, Date.now());
    if (success) this.registerPreimage(item, result.body['payment_preimage'], 'hex');
    return result.body;
  }
  async lnd(item: LiveOwner, node: Node, role: Role, path: string, method: string, params: Params, allowed: boolean, credential = rolePath(item, node, role)): Promise<Record<string, unknown>> {
    const result = await this.http(item, node, path, method, params, credential);
    const success = result.status === 200 && result.body['code'] === undefined && result.body['error'] === undefined;
    const denied = result.body['code'] === 7 && (result.status === 403 || result.status === 401);
    this.retain(item, `probe-${randomUUID()}`, { node, role, path: path.split('?')[0], status: result.status, classification: success ? 'allowed' : denied ? 'permission-denied' : 'invalid' });
    expect(allowed ? success : denied, `${node}/${role} actual LND authorization classification`).toBe(true); return result.body;
  }
  async close(): Promise<void> {
    const start = performance.now();
    this.cancellation.abort();
    const revokeFailures: Error[] = [];
    for (const { item, node, id } of this.bootstrapIds.values()) {
      try { this.cli(item, node, 'blacklistrune', [`start=${id}`]); }
      catch { revokeFailures.push(new LabInvalidError('provisional bootstrap revocation failed')); }
    }
    this.bootstrapIds.clear();
    for (const path of this.bootstrap.values()) rmSync(path, { force: true }); this.bootstrap.clear();
    const outcomes = await Promise.allSettled(this.started.map(async item => {
      expect(await this.command(item, 'down'), 'ordinary owned teardown exit').toBe(0);
      expect(inventory(item.owner.project)).toEqual({ containers: [], volumes: [], networks: [] });
      for (const node of nodes) for (const role of roles) expect(existsSync(rolePath(item, node, role)), 'role outputs destroyed after owner down').toBe(false);
    }));
    this.phases['teardown'] = performance.now() - start; this.started = [];
    expect(unrelated(this.plan.owners.map(item => item.owner.project))).toEqual(this.before);
    for (const result of outcomes) if (result.status === 'rejected') throw result.reason instanceof Error ? result.reason : new LabInvalidError('owned teardown failed');
    if (revokeFailures[0]) throw revokeFailures[0];
  }
}

// Sources: exact SECURITY 3.2 arrays and pinned CLN request schemas. Self payment
// is explicitly supported by cln-sendpay.json; no invented route is involved.
export function invoice(cohort: Cohort, item: LiveOwner, node: Node, amount: string): Params {
  const result = cohort.cli(item, node, 'invoice', [`amount_msat=${amount}`, `label=cp008-${randomUUID()}`, 'description=disposable permission control']);
  return { route: [], payment_hash: string(result['payment_hash']), payment_secret: string(result['payment_secret']), amount_msat: amount };
}
export async function lndRoute(cohort: Cohort, item: LiveOwner, node: Node): Promise<Params> {
  const receiver: Node = node === 'lnd-p' ? 'lnd-r' : 'lnd-p';
  const created = cohort.cli(item, receiver, 'addinvoice', ['--amt=1']);
  const hash = bytes32(created['r_hash']).toString('base64');
  const decoded = cohort.cli(item, node, 'decodepayreq', [string(created['payment_request'])]);
  // QueryRoutesRequest.final_cltv_delta explicitly requires padding above the
  // invoice minimum. Three blocks are this disposable control's own padding.
  const delta = (BigInt(string(decoded['cltv_expiry'])) + 3n).toString();
  const queried = await cohort.lnd(item, node, 'execute', `/v1/graph/routes/${string(item.oracle.pubkeys[receiver])}/1?final_cltv_delta=${delta}`, 'GET', {}, true);
  const route = rows(queried['routes'], 'fresh actual LND route')[0]; if (!route) throw new LabInvalidError('ordinary owned topology yielded no valid route');
  const hops = rows(route['hops'], 'actual route hops');
  const final = hops.at(-1); if (!final) throw new LabInvalidError('ordinary owned route is empty');
  final['mpp_record'] = { payment_addr: bytes32(decoded['payment_addr']).toString('base64'), total_amt_msat: '1000' };
  route['hops'] = hops;
  return { payment_hash: hash, route };
}

export async function proveR1(cohort: Cohort): Promise<void> {
  for (const item of cohort.plan.owners) for (const node of ['lnd-p', 'lnd-r'] as const) {
    for (const role of roles) await cohort.lnd(item, node, role, '/v1/channels', 'GET', {}, true);
    const route = await lndRoute(cohort, item, node);
    await cohort.lnd(item, node, 'read', '/v2/router/route/send', 'POST', route, false);
    const result = await cohort.lnd(item, node, 'execute', '/v2/router/route/send', 'POST', route, true);
    expect(result['status'], 'valid route must result in actual payment success').toBe('SUCCEEDED');
    for (const role of roles) {
      await cohort.lnd(item, node, role, '/v1/stop', 'POST', {}, false);
      await cohort.lnd(item, node, role, '/v1/changepassword', 'POST', json(string(item.changePasswordFile)), false);
      await cohort.lnd(item, node, role, '/v1/channels', 'GET', {}, true);
    }
  }
}

export async function proveR2(cohort: Cohort): Promise<void> {
  const outcomes = await Promise.allSettled(cohort.plan.owners.map(async item => { for (const node of ['cln-p', 'cln-r', 'cln-m'] as const) {
    const params = invoice(cohort, item, node, '1');
    const absentInvoice = cohort.cli(item, node, 'invoice', ['amount_msat=1', `label=cp008-denied-${randomUUID()}`, 'description=disposable denied payment control']);
    const withdraw = cohort.cli(item, node, 'newaddr');
    const deniedParams: Record<string, Params> = { pay: { bolt11: absentInvoice['bolt11'] }, xpay: { invstring: absentInvoice['bolt11'] }, withdraw: { destination: withdraw['bech32'], satoshi: '1' } };
    for (const role of roles) {
      for (const method of readMethods.map(value => value.slice(7))) {
        let input: Params = {};
        // cln-getroutes.json request.required and description automatic layers.
        if (method === 'getroutes') input = { source: item.oracle.pubkeys[node], destination: item.oracle.pubkeys[node === 'cln-p' ? 'cln-r' : 'cln-p'], amount_msat: '1', layers: ['auto.localchans', 'auto.sourcefree'], maxfee_msat: item.owner.credentialPolicy.maxPrincipalMsat, final_cltv: 18 };
        if (method === 'waitsendpay') { await cohort.cln(item, node, 'execute', 'sendpay', params, true); input = { payment_hash: params['payment_hash'], timeout: 1 }; }
        await cohort.cln(item, node, role, method, input, true, true);
        await cohort.cln(item, node, role, method, input, true);
      }
      await cohort.cln(item, node, role, 'sendpay', params, role === 'execute', true);
      await cohort.cln(item, node, role, 'sendpay', params, role === 'execute');
      for (const method of forbiddenCln) {
        await cohort.cln(item, node, role, 'getinfo', {}, true);
        const input = deniedParams[method] ?? {};
        await cohort.cln(item, node, role, method, input, false, true);
        await cohort.cln(item, node, role, method, input, false);
      }
    }
    const label = `cp008-role-${randomUUID()}`, create = { amount_msat: '1', label, description: 'disposable role mutation' };
    for (const method of ['invoice', 'delinvoice']) {
      const input = method === 'invoice' ? create : { label, status: 'unpaid' };
      await cohort.cln(item, node, 'read', method, input, false, true);
      await cohort.cln(item, node, 'read', method, input, false);
      await cohort.cln(item, node, 'execute', method, input, true, true);
      await cohort.cln(item, node, 'execute', method, input, true);
    }
  } }));
  for (const outcome of outcomes) if (outcome.status === 'rejected') throw outcome.reason instanceof Error ? outcome.reason : new LabInvalidError('owned CLN controls rejected');
}

export async function proveRA15(cohort: Cohort): Promise<void> {
  for (const item of cohort.plan.owners) for (const node of ['cln-p', 'cln-r', 'cln-m'] as const) {
    const max = BigInt(item.owner.credentialPolicy.maxPrincipalMsat);
    if (max < 2n) throw new LabInvalidError('this live fixture needs a principal allowing a positive below-maximum payment');
    await cohort.cln(item, node, 'execute', 'getinfo', {}, true, true); await cohort.cln(item, node, 'execute', 'getinfo', {}, true);
    for (const value of [max > 1n ? max - 1n : 1n, max]) {
      const params = invoice(cohort, item, node, value.toString());
      await cohort.cln(item, node, 'execute', 'sendpay', params, true, true); await cohort.cln(item, node, 'execute', 'sendpay', params, true);
    }
    const above = invoice(cohort, item, node, (max + 1n).toString());
    await cohort.cln(item, node, 'execute', 'sendpay', above, false, true); await cohort.cln(item, node, 'execute', 'sendpay', above, false);
    // Missing amount must be independently valid: obtain a real route to another
    // node and omit optional amount_msat; empty self-route requires that parameter.
    const receiver: Node = node === 'cln-p' ? 'cln-r' : node === 'cln-r' ? 'cln-m' : 'cln-r';
    const payment = invoice(cohort, item, receiver, '1');
    const routes = cohort.cli(item, node, 'getroutes', [`source=${string(item.oracle.pubkeys[node])}`, `destination=${string(item.oracle.pubkeys[receiver])}`, 'amount_msat=1', 'layers=["auto.localchans","auto.sourcefree"]', `maxfee_msat=${item.owner.credentialPolicy.maxPrincipalMsat}`, 'final_cltv=18', 'maxparts=1']);
    const route = rows(routes['routes'], 'actual disposable getroutes paths')[0]; if (!route) throw new LabInvalidError('no actual disposable CLN route for missing-amount control');
    const missing: Params = { ...payment, route: route['path'] }; delete missing['amount_msat'];
    // Source-supported named body, independently valid ordinary actual sendpay.
    // A separately owned provisional bootstrap carries no role acceptance proof.
    const control = await cohort.http(item, node, '/v1/sendpay', 'POST', missing, await cohort.bootstrapPath(item, node));
    expect(control.status === 200 && ['pending', 'complete'].includes(string(control.body['status'])), 'actual missing-amount request is independently valid').toBe(true);
    cohort.cli(item, node, 'waitsendpay', [`payment_hash=${string(missing['payment_hash'])}`, 'timeout=10']);
    await cohort.cln(item, node, 'execute', 'sendpay', missing, false, true); await cohort.cln(item, node, 'execute', 'sendpay', missing, false);
    for (const method of ['pay', 'xpay', 'stop', 'createrune']) await cohort.cln(item, node, 'execute', method, {}, false, true);
    cohort.retain(item, `RA15-${node}`, { node, bound: (max + 1n).toString(), belowAndAt: true, overAndMissingDenied: true, classificationsObserved: true });
  }
}

export async function proveR3(cohort: Cohort): Promise<void> {
  for (const item of cohort.plan.owners) {
    const manifest = json(join(item.owner.runtimeRoot, 'lab.json'));
    const credentials = asRecord(manifest['credentials'], 'canonical role manifest'); expect(Object.keys(credentials).sort()).toEqual([...nodes].sort());
    expect(readdirSync(join(item.owner.runtimeRoot, 'credentials')).sort(), 'only the five accepted role directories').toEqual([...nodes].sort());
    for (const node of nodes) {
      expect(readdirSync(join(item.owner.runtimeRoot, 'credentials', node)).sort(), 'only canonical accepted role outputs').toEqual(roles.map(role => `${role}.${node.startsWith('lnd-') ? 'macaroon' : 'rune'}`).sort());
      const pair = asRecord(credentials[node], 'manifest node'); expect(Object.keys(pair).sort()).toEqual(['execute', 'read']);
      for (const role of roles) {
        const path = rolePath(item, node, role), bytes = await cohort.bytes(path), record = asRecord(pair[role], 'manifest role');
        expect(Object.keys(record).sort()).toEqual(['fingerprint', 'path']); expect(record['path']).toBe(path); expect(record['fingerprint']).toBe(fingerprint(bytes));
        await cohort.privateIO.assertPrivateDirectory(join(item.owner.runtimeRoot, 'credentials', node)); await cohort.register(item, path, node.startsWith('lnd-') ? 'macaroon' : 'rune');
        if (!node.startsWith('lnd-')) {
          const found = rows(cohort.cli(item, node, 'showrunes')['runes'], 'actual runes').find(rune => rune['rune'] === bytes.toString('utf8'));
          if (!found) throw new LabInvalidError('candidate rune absent from actual inventory');
          const restrictions = rows(found['restrictions'], 'actual restrictions').map(restriction => rows(restriction['alternatives'], 'actual alternatives').map(value => `${string(value['fieldname'])}${string(value['condition'])}${string(value['value'])}`));
          expect(restrictions).toEqual(role === 'read' ? [readMethods, [`rate=${item.owner.credentialPolicy.callsPerMinute}`]] : [executeMethods, ['method/sendpay', `pnameamount_msat<${(BigInt(item.owner.credentialPolicy.maxPrincipalMsat) + 1n).toString()}`], [`rate=${item.owner.credentialPolicy.callsPerMinute}`]]);
          await cohort.cln(item, node, role, 'createrune', {}, false);
        }
      }
      if (node.startsWith('lnd-')) {
        // Revoke only read's configured root; execute must remain independently usable.
        const lndNode = node as 'lnd-p' | 'lnd-r';
        const ids = cohort.cli(item, node, 'listmacaroonids')['root_key_ids'];
        expect(Array.isArray(ids) && roles.every(role => ids.includes(item.owner.credentialPolicy.lndRootKeyIds[lndNode][role])), 'both independently configured actual roots exist').toBe(true);
        for (const role of roles) await cohort.lnd(item, node, role, '/v1/channels', 'GET', {}, true);
        const result = cohort.cli(item, node, 'deletemacaroonid', [item.owner.credentialPolicy.lndRootKeyIds[lndNode].read]); expect(result['deleted']).toBe(true);
        const rejected = await cohort.http(item, node, '/v1/channels', 'GET', {}, rolePath(item, node, 'read'));
        expect(rejected.status >= 400 && rejected.status < 500, 'actual revoked read root rejected').toBe(true);
        await cohort.lnd(item, node, 'execute', '/v1/channels', 'GET', {}, true);
        expect(cohort.cli(item, node, 'deletemacaroonid', [item.owner.credentialPolicy.lndRootKeyIds[lndNode].execute])['deleted']).toBe(true);
        const executeRevoked = await cohort.http(item, node, '/v1/channels', 'GET', {}, rolePath(item, node, 'execute'));
        expect(executeRevoked.status >= 400 && executeRevoked.status < 500, 'independently revoked execute root rejected').toBe(true);
      } else {
        const permissive = rows(cohort.cli(item, node, 'showrunes')['runes'], 'actual stored runes').filter(rune => rows(rune['restrictions'], 'restrictions').length === 0 && rune['blacklisted'] !== true);
        expect(permissive.length, 'no unrestricted experimental rune remains usable').toBe(0);
      }
    }
  }
}

export async function proveR4(cohort: Cohort): Promise<void> {
  for (const item of cohort.plan.owners) for (const node of ['lnd-p', 'lnd-r'] as const) {
    const permissions = asRecord(cohort.cli(item, node, 'listpermissions')['method_permissions'], 'actual permission map');
    expect(asRecord(permissions['/lnrpc.Lightning/LookupInvoice'], 'v1 permission')['permissions']).toEqual([{ entity: 'invoices', action: 'read' }]);
    expect(asRecord(permissions['/invoicesrpc.Invoices/LookupInvoiceV2'], 'v2 permission')['permissions']).toEqual([{ entity: 'invoices', action: 'write' }]);
    const created = cohort.cli(item, node, 'addinvoice', ['--amt=1']), hashBytes = bytes32(created['r_hash']), hash = hashBytes.toString('hex');
    const observedInvoice = await cohort.lnd(item, node, 'read', `/v1/invoice/${hash}`, 'GET', {}, true);
    cohort.registerPreimage(item, observedInvoice['r_preimage'], 'base64');
    // invoices.yaml LookupInvoiceV2 GET; invoices.proto LookupInvoiceMsg bytes;
    // protobuf JSON bytes use base64, then query encoding preserves '+'/'/'/'='.
    const lookup = `/v2/invoices/lookup?payment_hash=${encodeURIComponent(hashBytes.toString('base64'))}`;
    await cohort.lnd(item, node, 'read', lookup, 'GET', {}, false);
    await cohort.lnd(item, node, 'execute', lookup, 'GET', {}, true);
    for (const permission of ['invoices:read', 'invoices:write']) {
      const encoded = cohort.cliText(item, node, 'bakemacaroon', [permission]).trim();
      if (!/^(?:[a-f0-9]{2})+$/.test(encoded)) throw new LabInvalidError('minimal macaroon baking returned invalid serialized bytes');
      const minimal = join(item.owner.tmpRoot, `cp008-minimal-${node}-${permission.replace(':', '-')}-${cohort.runId}.macaroon`);
      writeFileSync(minimal, Buffer.from(encoded, 'hex'), { mode: 0o600, flag: 'wx' });
      try {
        await cohort.register(item, minimal, 'macaroon');
        if (permission === 'invoices:read') await cohort.lnd(item, node, 'read', `/v1/invoice/${hash}`, 'GET', {}, true, minimal);
        await cohort.lnd(item, node, 'read', lookup, 'GET', {}, permission === 'invoices:write', minimal);
      } finally { rmSync(minimal, { force: true }); }
    }
    // Pinned cmd_macaroon.go documents URI bake arguments. This experimental
    // credential is separately owned and always removed, never role metadata.
    const baked = cohort.cliText(item, node, 'bakemacaroon', ['uri:/lnrpc.Lightning/GetInfo']).trim();
    if (!/^(?:[a-f0-9]{2})+$/.test(baked)) throw new LabInvalidError('pinned bakemacaroon did not return serialized hex');
    const path = join(item.owner.tmpRoot, `cp008-uri-${node}-${cohort.runId}.macaroon`);
    writeFileSync(path, Buffer.from(baked, 'hex'), { mode: 0o600, flag: 'wx' });
    try { await cohort.register(item, path, 'macaroon'); await cohort.lnd(item, node, 'read', '/v1/getinfo', 'GET', {}, true, path); await cohort.lnd(item, node, 'read', '/v1/channels', 'GET', {}, false, path); }
    finally { rmSync(path, { force: true }); }
  }
}

export async function proveRowner(cohort: Cohort): Promise<void> {
  expect(cohort.peakWorkers, 'two actually observed simultaneous CLI workers').toBe(2);
  for (const key of ['cpus', 'memoryBytes', 'pids'] as const) expect(cohort.allocations.reduce((sum, value) => sum + value[key], 0)).toBeLessThanOrEqual(cohort.plan.budget[key]);
  expect(cohort.processExits.filter(value => value.operation === 'up').map(value => value.exit)).toEqual([0, 0]);
  expect(new Set(cohort.processExits.filter(value => value.operation === 'up').map(value => value.pid)).size).toBe(2);
  await cohort.close();
  expect(cohort.processExits.filter(value => value.operation === 'down').map(value => value.exit)).toEqual([0, 0]);
  for (const item of cohort.plan.owners) cohort.retain(item, 'owner-observations', { runId: cohort.runId, allocations: cohort.allocations, exits: cohort.processExits, phases: cohort.phases, unrelatedUnchanged: true });
}

interface Scanner { findLeaks(options: { root: string; sentinels: string; sentinelDir: string; testTmp: string; evidenceDir: string; paths: string[] }): { path: string; encoding: string } | null }
interface LeakFixture {
  privateIO: PrivateIO;
  plan: { owners: { owner: Pick<Owner, 'runtimeRoot' | 'tmpRoot' | 'sentinelRoot' | 'evidenceRoot'> }[] };
}
export async function proveCp008ArtifactLeaks(cohort: LeakFixture): Promise<void> {
  const scanner = await import(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href) as Scanner;
  const { paths: artifacts, excluded } = productInventory(); expect(artifacts.length).toBeGreaterThan(0);
  const staticSources = excluded.map(path => ({ path, bytes: readFileSync(path), info: lstatSync(path, { bigint: true }) }));
  for (const source of staticSources) if (!source.info.isFile() || source.info.isSymbolicLink()) throw new LabInvalidError('original registered static source required');
  const global = absolute(process.env['FLUXWARDEN_SENTINEL_DIR']);
  await cohort.privateIO.assertPrivateDirectory(global);
  for (const item of cohort.plan.owners) if (!within(global, item.owner.sentinelRoot)) throw new LabInvalidError('owned original sources must belong to the complete global source population');
  for (const item of cohort.plan.owners) {
    const { tmpRoot, sentinelRoot, evidenceRoot } = item.owner;
    const samples = readdirSync(sentinelRoot, { withFileTypes: true }).filter(entry => entry.isFile() && readFileSync(join(sentinelRoot, entry.name)).length > 0);
    for (const kind of ['preimage', 'macaroon', 'rune', 'tls-key', 'approval-key']) expect(samples.some(entry => entry.name.includes(kind)), 'independent required nonempty sentinel kind').toBe(true);
    const options = { root: repoRoot, sentinels: join(repoRoot, 'test/sentinels.json'), sentinelDir: global, testTmp: tmpRoot, evidenceDir: evidenceRoot, paths: [...artifacts, ...cohort.plan.owners.flatMap(value => [value.owner.runtimeRoot, value.owner.tmpRoot, value.owner.evidenceRoot])] };
    expect(scanner.findLeaks(options) === null, 'fresh original complete artifact scan').toBe(true);
    const control = await cohort.privateIO.createPrivateDirectory(tmpRoot, 'cp008-leak-'), planted = join(control, 'unexpected-recording.bin'), empty = await cohort.privateIO.createPrivateDirectory(control, 'empty-');
    declareFixturePaths([planted]);
    writeFileSync(join(control, 'sentinels.json'), '[]', { mode: 0o600 });
    try {
      for (const sample of samples) {
        const bytes = readFileSync(join(sentinelRoot, sample.name)), b64 = bytes.toString('base64'), url = bytes.toString('base64url');
        for (const encoded of [bytes.toString('utf8'), bytes.toString('latin1'), bytes.toString('hex'), bytes.toString('hex').toUpperCase(), b64, b64.replace(/=+$/, ''), url + '='.repeat((4 - url.length % 4) % 4), url]) {
          writeFileSync(planted, encoded, { mode: 0o600 }); expect(scanner.findLeaks({ ...options, paths: [planted] }) !== null, 'planted required encoding is detected').toBe(true);
        }
      }
      for (const absent of [empty, join(control, 'absent')]) expect(() => scanner.findLeaks({ ...options, sentinelDir: absent, sentinels: join(control, 'sentinels.json'), paths: [planted] })).toThrow();
    } finally { rmSync(planted, { force: true }); }
  }
  for (const source of staticSources) {
    const now = lstatSync(source.path, { bigint: true });
    expect(now.dev === source.info.dev && now.ino === source.info.ino && readFileSync(source.path).equals(source.bytes), 'original static source remains unchanged').toBe(true);
  }
}
export async function proveRleak(cohort: Cohort): Promise<void> {
  const start = performance.now();
  await proveCp008ArtifactLeaks(cohort);
  cohort.phases['leak'] = performance.now() - start;
  cohort.phases['total'] = performance.now() - cohort.begin;
  const inventory = [...cohort.completed, titles[6]];
  expect(inventory.length).toBe(7); expect(new Set(inventory).size).toBe(7); expect([...inventory].sort()).toEqual([...titles].sort());
  for (const item of cohort.plan.owners) cohort.retain(item, 'complete-inventory', { runId: cohort.runId, file: 'test/lab/cp008-credentials.live.test.ts', selected: titles, executed: inventory, phases: cohort.phases, longestShardMs: cohort.phases['total'], criticalPathMs: cohort.phases['total'], exits: cohort.processExits });
}
