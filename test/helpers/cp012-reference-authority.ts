import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { assertCurrentBinding, readCurrentBinding } from '../../labs/scenarios/live-profile.mjs';
import { adapterLabPlan, lightningCli, type AdapterLabPlan } from './adapter-lab.js';
import { asRecord, repoRoot } from './cli.js';
/** CP012 lab-only observation authority. This record is metadata EGRESS;
 * its credential is never a normal READ/EXECUTE role or application input.
 * The producer writes this exact record at owner.evidenceRoot/
 * cp012-reference-authority.json and the raw rune (without a newline) at
 * owner.runtimeRoot/reference/cln-m-cp012-read.rune. Both original owner and
 * global sentinel populations must contain the full raw token before use.
 */
export const CP012_REFERENCE_METHODS = [
  'getinfo', 'listpeerchannels', 'listsendpays', 'listpays', 'listinvoices',
  'bkpr-listaccountevents', 'askrene-listlayers',
] as const;

export interface Cp012ReferenceAuthority {
  version: 1;
  purpose: 'cp012-reference-read-only';
  /** Exact independent readCurrentBinding(ownerPath, sourceCommit) result. */
  binding: {
    version: 1; sourceCommit: string; ownerPath: string; ownerSha256: string;
    ownerId: string; project: string; manifestSha256: string;
  };
  endpoint: {
    service: 'cln-m'; host: string; port: number; pubkey: string;
    tlsCert: string; tlsSha256: string;
  };
  credential: { path: string; sha256: string; fingerprint: string; uniqueId: string };
  methods: typeof CP012_REFERENCE_METHODS;
  ratePerMinute: string;
}
interface OriginalFile {
  path: string; bytes: Buffer; sha256: string; dev: bigint; ino: bigint;
  size: bigint; mtimeNs: bigint; ctimeNs: bigint; mode: bigint; uid: bigint; nlink: bigint;
}
export interface Cp012ReferenceContext {
  ownerPath: string;
  sourceCommit: string;
  sentinelDir: string;
  recordPath: string;
  adapterPlanPath: string;
  /** Independent CLI observation; synthetic observations are unit proof only. */
  observeRunes: () => unknown;
}
export interface Cp012ReferenceLease {
  credentialPath: string;
  normalCredentials: readonly string[];
  ratePerMinute: string;
  assertCurrent(): void;
}
function invalid(): never { throw new Error('LabInvalidError: CP012 reference authority does not match its original owned scope'); }
const digest = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');
const object = (value: unknown): Record<string, unknown> => asRecord(value, 'CP012 reference authority');
function keys(value: Record<string, unknown>, expected: string[]): void {
  if (!isDeepStrictEqual(Object.keys(value).sort(), expected.sort())) invalid();
}
function path(value: unknown): string {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value || realpathSync(value) !== value) invalid();
  return value;
}
function directory(value: unknown): string {
  const result = path(value), info = lstatSync(result);
  if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0) invalid();
  return result;
}
function original(value: unknown, privateFile = false, limit = 16 * 1024 * 1024): OriginalFile {
  const target = path(value), before = lstatSync(target, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.uid !== BigInt(process.getuid?.() ?? -1)
    || before.size <= 0n || before.size > BigInt(limit) || (privateFile && (before.mode & 0o777n) !== 0o600n)) invalid();
  const fd = openSync(target, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const bytes = readFileSync(fd), after = fstatSync(fd, { bigint: true });
    for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs', 'mode', 'uid', 'nlink'] as const) if (before[field] !== after[field]) invalid();
    return { path: target, bytes, sha256: digest(bytes), dev: after.dev, ino: after.ino,
      size: after.size, mtimeNs: after.mtimeNs, ctimeNs: after.ctimeNs, mode: after.mode, uid: after.uid, nlink: after.nlink };
  } finally { closeSync(fd); }
}
function population(root: string): OriginalFile[] {
  const result: OriginalFile[] = [];
  for (const entry of readdirSync(directory(root), { withFileTypes: true })) {
    const child = join(root, entry.name);
    if (entry.isDirectory()) result.push(...population(child));
    else if (entry.isFile()) result.push(original(child));
    else invalid();
  }
  return result.sort((a, b) => a.path.localeCompare(b.path));
}
function inside(root: string, target: string): void {
  const part = relative(root, target);
  if (!part || part === '..' || part.startsWith(`..${sep}`) || isAbsolute(part)) invalid();
}
function unchanged(file: OriginalFile): void {
  const next = original(file.path);
  for (const field of ['sha256', 'dev', 'ino', 'size', 'mtimeNs', 'ctimeNs', 'mode', 'uid', 'nlink'] as const) if (file[field] !== next[field]) invalid();
}
function decode(file: OriginalFile): Record<string, unknown> {
  return object(JSON.parse(file.bytes.toString('utf8')) as unknown);
}
function registered(files: OriginalFile[], bytes: Buffer): boolean {
  return files.some(file => file.bytes.equals(bytes));
}
export function assertCp012ReferenceScope(observed: unknown, token: string, record: Cp012ReferenceAuthority): void {
  const projection = object(observed);
  keys(projection, ['runes']);
  const runes = projection['runes'];
  if (!Array.isArray(runes)) invalid();
  // v26.06.9 ccan/rune/coding.c:32-byte auth prefix, then the encoded
  // restriction string; rune.c puts the numeric unique-ID restriction first.
  // Scope is checked from original token bytes, never from claimed metadata.
  const id = record.credential.uniqueId;
  if (!/^(?:0|[1-9][0-9]*)$/.test(id) || BigInt(id) > 9223372036854775807n || !/^[A-Za-z0-9_-]+={0,2}$/.test(token)) invalid();
  const decoded = Buffer.from(token, 'base64url');
  const expected = `=${id}&${CP012_REFERENCE_METHODS.map(method => `method=${method}`).join('|')}&rate=${record.ratePerMinute}`;
  if (decoded.toString('base64url') !== token.replace(/=+$/, '') || !decoded.subarray(32).equals(Buffer.from(expected))) invalid();
  const metadata = runes.map(object);
  if (metadata.some(row => Object.keys(row).some(key => !['unique_id', 'restrictions', 'blacklisted', 'our_rune', 'stored'].includes(key)))) invalid();
  if (metadata.some(row => typeof row['unique_id'] !== 'string' || !Array.isArray(row['restrictions'])
    || ['blacklisted', 'our_rune', 'stored'].some(flag => row[flag] !== undefined && typeof row[flag] !== 'boolean'))) invalid();
  const matching = metadata.filter(row => row['unique_id'] === id);
  const native = matching[0];
  if (matching.length !== 1 || !native || native['unique_id'] !== record.credential.uniqueId
    || native['blacklisted'] === true || native['our_rune'] === false || native['stored'] === false) invalid();
  const restrictions = native['restrictions'];
  if (!Array.isArray(restrictions)) invalid();
  const actual = restrictions.map(item => {
    const restriction = object(item);
    keys(restriction, ['alternatives']);
    const alternatives = restriction['alternatives'];
    if (!Array.isArray(alternatives)) invalid();
    return alternatives.map(value => {
      const row = object(value);
      keys(row, ['fieldname', 'condition', 'value']);
      if (['fieldname', 'condition', 'value'].some(field => typeof row[field] !== 'string')) invalid();
      return `${String(row['fieldname'])}${String(row['condition'])}${String(row['value'])}`;
    });
  });
  if (!isDeepStrictEqual(actual, [CP012_REFERENCE_METHODS.map(method => `method=${method}`), [`rate=${record.ratePerMinute}`]])) invalid();
}

/** Only an authenticated owner's declared SOURCE directory may nest inside the
 * actual global SOURCE pool. Every operational namespace stays disjoint. */
export function assertCp012SourceNamespaces(runtime: string, temporary: string, ownerSource: string, evidence: string, globalSource: string): void {
  const namespaces = [runtime, temporary, ownerSource, evidence, globalSource];
  const nested = relative(globalSource, ownerSource);
  const ownedWithinGlobal = nested !== '' && nested !== '..' && !nested.startsWith(`..${sep}`) && !isAbsolute(nested);
  for (const [index, a] of namespaces.entries()) for (const b of namespaces.slice(index + 1)) {
    if (ownedWithinGlobal && ((a === ownerSource && b === globalSource) || (b === ownerSource && a === globalSource))) continue;
    for (const [parent, child] of [[a, b], [b, a]]) {
      const part = relative(parent, child);
      if (part === '' || (part !== '..' && !part.startsWith(`..${sep}`) && !isAbsolute(part))) invalid();
    }
  }
}
/** Admit original files and the independently observed node restriction scope
 * before returning a credential path. No record field grants authority itself. */
export function admitCp012Reference(plan: AdapterLabPlan, context: Cp012ReferenceContext): Cp012ReferenceLease {
  if (process.platform === 'win32') invalid();
  const binding = readCurrentBinding(context.ownerPath, context.sourceCommit);
  const adapterInput = original(context.adapterPlanPath, true, 65536);
  if (!isDeepStrictEqual(adapterLabPlan(context.adapterPlanPath), plan)) invalid();
  const ownerFile = original(context.ownerPath, true), owner = decode(ownerFile);
  const runtime = directory(owner['runtimeRoot']), evidence = directory(owner['evidenceRoot']);
  const manifestFile = original(join(runtime, 'lab.json')), manifest = decode(manifestFile);
  if (context.recordPath !== join(evidence, 'cp012-reference-authority.json')) invalid();
  const recordFile = original(context.recordPath, true, 65536), raw = decode(recordFile);
  keys(raw, ['version', 'purpose', 'binding', 'endpoint', 'credential', 'methods', 'ratePerMinute']);
  if (raw['version'] !== 1 || raw['purpose'] !== 'cp012-reference-read-only' || !isDeepStrictEqual(raw['binding'], binding)
    || !isDeepStrictEqual(raw['methods'], [...CP012_REFERENCE_METHODS])) invalid();
  const policy = object(owner['credentialPolicy']), rate = policy['callsPerMinute'];
  if (typeof rate !== 'string' || !/^[1-9][0-9]*$/.test(rate) || raw['ratePerMinute'] !== rate) invalid();
  const endpoint = object(raw['endpoint']);
  keys(endpoint, ['service', 'host', 'port', 'pubkey', 'tlsCert', 'tlsSha256']);
  const node = object(object(manifest['nodes'])['cln-m']), certificate = object(node['certificate']);
  if (plan.project !== binding.project || plan.cln.service !== 'cln-m' || plan.cln.host !== 'localhost'
    || plan.cln.port !== object(manifest['ports'])['clnRest'] || node['kind'] !== 'cln' || node['pubkey'] !== plan.cln.pubkey
    || !isDeepStrictEqual(endpoint, { service: plan.cln.service, host: plan.cln.host, port: plan.cln.port,
      pubkey: plan.cln.pubkey, tlsCert: plan.cln.tlsCert, tlsSha256: certificate['sha256'] })) invalid();
  if (plan.cln.tlsCert !== certificate['path']) invalid();
  const ca = original(plan.cln.tlsCert, false, 65536);
  inside(runtime, ca.path);
  if (ca.sha256 !== certificate['sha256']) invalid();
  // Freeze both complete original populations before reading an active token.
  const ownerRoot = directory(owner['sentinelRoot']), globalRoot = directory(context.sentinelDir);
  const namespaces = [runtime, directory(owner['tmpRoot']), ownerRoot, evidence, globalRoot];
  assertCp012SourceNamespaces(runtime, namespaces[1] ?? invalid(), ownerRoot, evidence, globalRoot);
  const roots = namespaces.map(path => ({ path, info: lstatSync(path, { bigint: true }) }));
  const ownerSources = population(ownerRoot), globalSources = population(globalRoot);
  const credential = object(raw['credential']);
  keys(credential, ['path', 'sha256', 'fingerprint', 'uniqueId']);
  if (credential['path'] !== join(runtime, 'reference', 'cln-m-cp012-read.rune') || typeof credential['uniqueId'] !== 'string' || credential['uniqueId'] === '') invalid();
  const active = original(credential['path'], true, 65536), token = active.bytes.toString('utf8');
  if (!/^[\x21-\x7e]+$/.test(token) || !active.bytes.equals(Buffer.from(token)) || credential['sha256'] !== active.sha256
    || credential['fingerprint'] !== `fp:${active.sha256.slice(0, 16)}` || !registered(ownerSources, active.bytes)
    || !registered(globalSources, active.bytes)) invalid();
  const roleRecords = object(object(manifest['credentials'])['cln-m']);
  keys(roleRecords, ['read', 'execute']);
  const normal = ['read', 'execute'].map(role => {
    const entry = object(roleRecords[role]), file = original(entry['path'], true, 65536);
    inside(runtime, file.path);
    const canonical = Buffer.from(file.bytes.toString('utf8').trim());
    if (file.path === active.path || canonical.equals(active.bytes) || entry['fingerprint'] !== `fp:${digest(canonical).slice(0, 16)}`
      || !registered(ownerSources, canonical)) invalid();
    return file;
  });
  if (!normal.some(file => file.path === plan.cln.credential)) invalid();
  assertCp012ReferenceScope(context.observeRunes(), token, raw as unknown as Cp012ReferenceAuthority);
  const files = [ownerFile, manifestFile, adapterInput, recordFile, ca, active, ...normal, ...ownerSources, ...globalSources];
  const assertCurrent = () => {
    assertCurrentBinding(binding, context.ownerPath, context.sourceCommit);
    for (const [root, frozen] of [[ownerRoot, ownerSources], [globalRoot, globalSources]] as const) {
      if (!isDeepStrictEqual(population(root).map(file => file.path), frozen.map(file => file.path))) invalid();
    }
    for (const root of roots) {
      const now = lstatSync(directory(root.path), { bigint: true });
      for (const field of ['dev', 'ino', 'mode', 'uid'] as const) if (now[field] !== root.info[field]) invalid();
    }
    for (const file of files) unchanged(file);
  };
  assertCurrent();
  return { credentialPath: active.path, normalCredentials: normal.map(file => file.path), ratePerMinute: rate, assertCurrent };
}

/** Native daemon-side projection keeps every raw rune outside CLI stdout.
 * Pinned v26.06.9 cli/lightning-cli.c644-646,717-718; doc/lightning-cli.1.md71-73.
 */
export const CP012_SCOPE_FILTER = JSON.stringify({ runes: [{ unique_id: true,
  restrictions: [{ alternatives: [{ fieldname: true, condition: true, value: true }] }],
  blacklisted: true, our_rune: true, stored: true }] });

export function cp012Reference(plan = adapterLabPlan()): Cp012ReferenceLease {
  const identity = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: repoRoot, encoding: 'utf8', windowsHide: true, timeout: 15000 });
  if (identity.status !== 0) invalid();
  const ownerPath = process.env['FLUXWARDEN_LAB_OWNER'], sentinelDir = process.env['FLUXWARDEN_SENTINEL_DIR'], recordPath = process.env['FLUXWARDEN_LAB_CP012_REFERENCE'];
  const adapterPlanPath = process.env['FLUXWARDEN_LAB_ADAPTER_PLAN'];
  if (!ownerPath || !sentinelDir || !recordPath || !adapterPlanPath) invalid();
  return admitCp012Reference(plan, { ownerPath, sentinelDir, recordPath, adapterPlanPath, sourceCommit: identity.stdout.trim(),
    observeRunes: () => lightningCli(plan, [`--filter=${CP012_SCOPE_FILTER}`, 'showrunes']) });
}