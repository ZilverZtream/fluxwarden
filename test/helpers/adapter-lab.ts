// Live comparison of the node adapters with the nodes' own command-line clients on the owned
// regtest lab. The plan names the compose project, the REST endpoints, the pinned certificates
// and the credential files by absolute path; credential bytes never enter the plan.
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, lstatSync, realpathSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect } from 'vitest';
import { asRecord, repoRoot } from './cli.js';
import { assertCurrentBinding, readCurrentBinding } from '../../labs/scenarios/live-profile.mjs';

export interface LabNode { service: string; host: string; port: number; tlsCert: string; credential: string; pubkey: string }
export interface AdapterLabPlan { project: string; composeFile: string; lnd: LabNode; cln: LabNode; wrongCert: string }

function text(value: unknown, what: string): string {
  if (typeof value !== 'string' || value === '') throw new Error(`adapter lab plan: ${what} is required`);
  return value;
}

function absolute(value: unknown, what: string): string {
  const path = text(value, what);
  if (!isAbsolute(path)) throw new Error(`adapter lab plan: ${what} must be an absolute path`);
  return path;
}

function node(value: unknown, credentialKey: 'macaroon' | 'rune', what: string): LabNode {
  const raw = asRecord(value, what);
  const port = raw['port'];
  if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`adapter lab plan: ${what}.port is invalid`);
  const pubkey = text(raw['pubkey'], `${what}.pubkey`);
  if (!/^(?:02|03)[0-9a-f]{64}$/.test(pubkey)) throw new Error(`adapter lab plan: ${what}.pubkey is invalid`);
  return {
    service: text(raw['service'], `${what}.service`), host: text(raw['host'], `${what}.host`), port,
    tlsCert: absolute(raw['tlsCert'], `${what}.tlsCert`), credential: absolute(raw[credentialKey], `${what}.${credentialKey}`), pubkey,
  };
}

/** Reads FLUXWARDEN_LAB_ADAPTER_PLAN before any Docker call; the plan must declare a disposable regtest lab. */
export function adapterLabPlan(input = process.env['FLUXWARDEN_LAB_ADAPTER_PLAN']): AdapterLabPlan {
  if (input === undefined || !isAbsolute(input)) throw new Error('an absolute FLUXWARDEN_LAB_ADAPTER_PLAN is required before Docker');
  return parseAdapterLabPlan(asRecord(JSON.parse(readFileSync(input, 'utf8')) as unknown, 'adapter lab plan'));
}
function parseAdapterLabPlan(plan: Record<string, unknown>): AdapterLabPlan {
  if (plan['version'] !== 1 || plan['network'] !== 'regtest' || plan['disposable'] !== true) throw new Error('adapter lab plan must be version 1, regtest and disposable');
  const project = text(plan['project'], 'project');
  if (!/^fluxwarden-lab-[a-z0-9-]+$/.test(project)) throw new Error('adapter lab plan: project must be an owned lab project');
  return {
    project, composeFile: absolute(plan['composeFile'], 'composeFile'),
    lnd: node(plan['lnd'], 'macaroon', 'lnd'), cln: node(plan['cln'], 'rune', 'cln'), wrongCert: absolute(plan['wrongCert'], 'wrongCert'),
  };
}

function exec(plan: AdapterLabPlan, service: string, args: readonly string[]): unknown {
  const result = spawnSync('docker', ['compose', '--project-name', plan.project, '-f', plan.composeFile, 'exec', '-T', service, ...args],
    { shell: false, windowsHide: true, encoding: 'utf8', timeout: 60_000, maxBuffer: 64 * 1024 * 1024 });
  if (result.error !== undefined || result.status !== 0) throw new Error(`lab command on ${service} did not complete`);
  return JSON.parse(result.stdout) as unknown;
}

/** lncli prints protojson with proto names, every field, and bytes as hex (lnrpc/rpc_utils.go ProtoJSONMarshalOpts, UseHexForBytes). */
export function lncli(plan: AdapterLabPlan, args: readonly string[]): Record<string, unknown> {
  return asRecord(exec(plan, plan.lnd.service, ['lncli', '--network=regtest', ...args]), 'lncli answer');
}

export function lightningCli(plan: AdapterLabPlan, args: readonly string[]): Record<string, unknown> {
  return asRecord(exec(plan, plan.cln.service, ['lightning-cli', '--network=regtest', ...args]), 'lightning-cli answer');
}

export function rows(value: unknown, what: string): Record<string, unknown>[] {
  if (!Array.isArray(value)) throw new Error(`${what} must be a list`);
  return value.map(item => asRecord(item, what));
}

/** lncli replaceAndAppendScid/appendChanID: scid is decimal; chan_id is 32 bytes.
 * Legacy decimal-only output remains valid when scid is absent. */
export function lncliShortChannelId(channel: Record<string, unknown>): string {
  const value = String(channel['scid'] ?? channel['chan_id']);
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) throw new Error('LabInvalidError: decimal short channel id required');
  return value;
}
/** A JSON integer or decimal string as bigint; CLN "<n>msat" strings too. */
export function big(value: unknown): bigint {
  if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value);
  if (typeof value === 'string' && /^(?:0|[1-9][0-9]*)(?:msat)?$/.test(value)) return BigInt(value.replace(/msat$/, ''));
  if (value === undefined || value === null) return 0n;
  throw new Error('not an integer');
}


interface SourceObject { file: string; bytes: Buffer; sha256: string; dev: bigint; ino: bigint }
const sourceHash = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');
const pathIdentity = (path: string): string => process.platform === 'win32' ? resolve(path).toLowerCase() : resolve(path);
function sourceObject(path: string, limit = 16 * 1024 * 1024): SourceObject {
  try {
    if (!isAbsolute(path)) throw new Error();
    const file = resolve(path), info = lstatSync(file, { bigint: true });
    if (!info.isFile() || info.isSymbolicLink() || info.size > BigInt(limit) || pathIdentity(realpathSync(file)) !== pathIdentity(file)) throw new Error();
    const bytes = readFileSync(file);
    if (BigInt(bytes.length) !== info.size) throw new Error();
    return { file, bytes, sha256: sourceHash(bytes), dev: info.dev, ino: info.ino };
  } catch { throw new Error('LabInvalidError: original ordinary source input unavailable'); }
}
function unchangedSource(source: SourceObject): void {
  const current = sourceObject(source.file);
  if (current.dev !== source.dev || current.ino !== source.ino || current.sha256 !== source.sha256) throw new Error('LabInvalidError: original source input changed during scan');
}
/** The actual adapters send complete raw LND bytes or the complete trimmed CLN token. */
function canonicalCredential(kind: 'lnd' | 'cln', bytes: Buffer): Buffer | null {
  if (bytes.length === 0 || bytes.length > 65536) return null;
  if (kind === 'lnd') return bytes;
  const token = bytes.toString('utf8').trim();
  return /^[\x21-\x7e]+$/.test(token) ? Buffer.from(token, 'utf8') : null;
}
function bindActiveAdapter(kind: 'lnd' | 'cln', active: LabNode, ownerRuntime: string, manifest: Record<string, unknown>, registrations: SourceObject[]): SourceObject[] {
  const service = kind === 'lnd' ? 'lnd-r' : 'cln-m', ports = asRecord(manifest['ports'], 'current ports');
  const host = kind === 'lnd' ? '127.0.0.1' : 'localhost';
  if (active.service !== service || active.host !== host || active.port !== ports[kind === 'lnd' ? 'lndRest' : 'clnRest']) throw new Error('LabInvalidError: active adapter endpoint or service differs from current manifest');
  const currentNode = asRecord(asRecord(manifest['nodes'], 'current nodes')[service], 'active current node');
  if (currentNode['kind'] !== kind || currentNode['pubkey'] !== active.pubkey) throw new Error('LabInvalidError: active adapter identity differs from current manifest');
  const certificate = asRecord(currentNode['certificate'], 'current certificate'), expectedCertificate = absolute(certificate['path'], 'current certificate path');
  if (pathIdentity(active.tlsCert) !== pathIdentity(expectedCertificate)) throw new Error('LabInvalidError: active TLS path differs from current manifest');
  const credentials = asRecord(asRecord(manifest['credentials'], 'current credentials')[service], 'current role credentials');
  const roles = ['read', 'execute'].filter(role => credentials[role] !== undefined).map(role => asRecord(credentials[role], 'current role'));
  const matching = roles.filter(role => pathIdentity(absolute(role['path'], 'current credential path')) === pathIdentity(active.credential));
  if (matching.length !== 1) throw new Error('LabInvalidError: active credential path differs from current manifest');
  const expectedFingerprint = matching[0]?.['fingerprint'];
  if (typeof expectedFingerprint !== 'string' || !/^fp:[0-9a-f]{16}$/.test(expectedFingerprint)) throw new Error('LabInvalidError: current credential fingerprint required');
  for (const path of [expectedCertificate, active.credential]) {
    const within = relative(ownerRuntime, resolve(path));
    if (!within || within === '..' || within.startsWith(`..${sep}`) || isAbsolute(within)) throw new Error('LabInvalidError: active input lies outside the current owner runtime');
  }
  const tls = sourceObject(expectedCertificate, 65536), credential = sourceObject(active.credential, 65536);
  if (tls.bytes.length === 0 || tls.sha256 !== certificate['sha256']) throw new Error('LabInvalidError: active TLS bytes differ from current manifest');
  const canonical = canonicalCredential(kind, credential.bytes);
  // Recognition of a registered substring is never proof of whole-value coverage.
  // Authority comes only from the registrations frozen before this credential read.
  // Source authority is the original bytes recognized by the unchanged engine;
  // reader normalization must never manufacture a new registered source alias.
  const covered = canonical !== null && registrations.some(source => source.bytes.equals(canonical)
    && `fp:${source.sha256.slice(0, 16)}` === expectedFingerprint);
  if (!covered) throw new Error('LabInvalidError: complete active credential lacks original registered authority');
  return [tls, credential];
}

/** The same sentinel scan as the other lab checks: product files, scratch and retained output. */
export async function expectNoSentinelLeak(): Promise<void> {
  const sentinelDir = process.env['FLUXWARDEN_SENTINEL_DIR'];
  const testTmp = process.env['FLUXWARDEN_TEST_TMP'];
  const evidenceDir = process.env['FLUXWARDEN_EVIDENCE_DIR'];
  if (!sentinelDir || !testTmp || !evidenceDir) throw new Error('isolated sentinel temporary and retained output roots are required');
  const ownerPath = absolute(process.env['FLUXWARDEN_LAB_OWNER'], 'current owner');
  const identity = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: repoRoot, windowsHide: true, encoding: 'utf8', timeout: 15000 });
  expect(identity.status, 'current source identity').toBe(0);
  const sourceCommit = identity.stdout.trim(), binding = readCurrentBinding(ownerPath, sourceCommit);
  const ownerBytes = readFileSync(ownerPath);
  if (createHash('sha256').update(ownerBytes).digest('hex') !== binding.ownerSha256) throw new Error('LabInvalidError: current source owner changed');
  const owner = asRecord(JSON.parse(ownerBytes.toString('utf8')) as unknown, 'current source owner');
  const ownedSources = absolute(owner['sentinelRoot'], 'owner sentinel root');
  const planInput = sourceObject(absolute(process.env['FLUXWARDEN_LAB_ADAPTER_PLAN'], 'active adapter plan'));
  const plan = parseAdapterLabPlan(asRecord(JSON.parse(planInput.bytes.toString('utf8')) as unknown, 'active adapter plan'));
  const manifestBytes = readFileSync(join(absolute(owner['runtimeRoot'], 'owner runtime root'), 'lab.json'));
  if (createHash('sha256').update(manifestBytes).digest('hex') !== binding.manifestSha256) throw new Error('LabInvalidError: current source manifest changed');
  const manifest = asRecord(JSON.parse(manifestBytes.toString('utf8')) as unknown, 'current manifest');
  const nodes = asRecord(manifest['nodes'], 'current nodes');
  if (plan.project !== binding.project || plan.lnd.pubkey !== asRecord(nodes[plan.lnd.service], 'current LND')['pubkey'] || plan.cln.pubkey !== asRecord(nodes[plan.cln.service], 'current CLN')['pubkey']) throw new Error('LabInvalidError: sentinel owner does not bind the current adapter plan');
  const registrations = readdirSync(ownedSources, { withFileTypes: true }).filter(entry => entry.isFile()).map(entry => sourceObject(join(ownedSources, entry.name)));
  expect(registrations.filter(source => source.bytes.length > 0).length, 'independent registered owned-lab sentinels').toBeGreaterThanOrEqual(5);
  const activeInputs = [planInput, ...bindActiveAdapter('lnd', plan.lnd, absolute(owner['runtimeRoot'], 'owner runtime root'), manifest, registrations),
    ...bindActiveAdapter('cln', plan.cln, absolute(owner['runtimeRoot'], 'owner runtime root'), manifest, registrations)];
  interface Scanner { findLeaks(options: { root: string; sentinelDir: string; sentinels: string; testTmp: string; evidenceDir: string; paths: string[] }): { path: string; encoding: string } | null }
  const scanner = await import(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href) as Scanner;
  const inventory = spawnSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], { cwd: repoRoot, shell: false, windowsHide: true, encoding: 'utf8', timeout: 15000 });
  expect(inventory.status, 'product file inventory').toBe(0);
  const registryPath = 'test/sentinels.json', registry = readFileSync(join(repoRoot, registryPath));
  const registered: unknown = JSON.parse(registry.toString('utf8'));
  if (!Array.isArray(registered) || registered.length === 0 || registered.some(path => typeof path !== 'string' || path === '')) throw new Error('official static source registration required');
  const sourcePaths = registered as string[];
  // Only these original tracked SOURCE objects are INPUT. The registry itself,
  // other files in the directory, and every copy at another path remain EGRESS.
  const authority = spawnSync('git', ['ls-tree', '-r', '-z', 'HEAD', '--', registryPath, ...sourcePaths], { cwd: repoRoot, windowsHide: true, encoding: 'utf8', timeout: 15000 });
  expect(authority.status, 'original tracked source authority').toBe(0);
  const entries = new Map(authority.stdout.split('\0').filter(Boolean).map(entry => {
    const match = /^(100644|100755) blob ([0-9a-f]{40})\t(.+)$/.exec(entry);
    if (!match) throw new Error('registered sources require original regular-file authority');
    return [match[3] ?? '', match[2] ?? ''];
  }));
  const hash = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');
  const original = [registryPath, ...sourcePaths].map(path => {
    const file = resolve(repoRoot, path), within = relative(repoRoot, file), info = lstatSync(file, { bigint: true });
    if (isAbsolute(within) || within === '..' || within.startsWith(`..${sep}`) || !info.isFile() || info.isSymbolicLink() || resolve(realpathSync(file)) !== file) throw new Error('registered source must be its original physical file');
    const payload = path === registryPath ? registry : readFileSync(file);
    const object = spawnSync('git', ['hash-object', `--path=${path}`, '--stdin'], { cwd: repoRoot, input: payload, windowsHide: true, encoding: 'utf8', timeout: 15000 });
    if (object.status !== 0 || object.stdout.trim() !== entries.get(path)) throw new Error('registered source differs from original tracked authority');
    return { file, dev: info.dev, ino: info.ino, sha256: hash(payload) };
  });
  const inputs = new Set(original.filter(item => item.file !== resolve(repoRoot, registryPath)).map(item => item.file));
  const paths = inventory.stdout.split('\0').filter(Boolean).map(path => resolve(repoRoot, path)).filter(path => !inputs.has(path));
  expect(paths.length, 'every other product file is scanned').toBeGreaterThan(0);
  // Keep every original sink and declaration context. Scan the full official
  // static pool with both runtime channels, without copying or relabelling any
  // native credential to satisfy coverage. An isolated global registry may be empty.
  let hit: { path: string; encoding: string } | null = null;
  for (const sourceDir of new Set([sentinelDir, ownedSources])) {
    const found = scanner.findLeaks({ root: repoRoot, sentinelDir: sourceDir, sentinels: join(repoRoot, registryPath), testTmp, evidenceDir, paths: [...paths, testTmp, evidenceDir] });
    if (found !== null) hit = found;
  }
  assertCurrentBinding(binding, ownerPath, sourceCommit);
  const currentRegistrations = readdirSync(ownedSources, { withFileTypes: true }).filter(entry => entry.isFile()).map(entry => resolve(ownedSources, entry.name)).sort();
  if (JSON.stringify(currentRegistrations) !== JSON.stringify(registrations.map(source => source.file).sort())) throw new Error('LabInvalidError: original registrations changed during scan');
  for (const input of [...registrations, ...activeInputs]) unchangedSource(input);
  for (const source of original) {
    const info = lstatSync(source.file, { bigint: true });
    if (!info.isFile() || info.isSymbolicLink() || info.dev !== source.dev || info.ino !== source.ino || hash(readFileSync(source.file)) !== source.sha256) throw new Error('original registered source changed during full scan');
  }
  expect(hit).toBeNull();
}
