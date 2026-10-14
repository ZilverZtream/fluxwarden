import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { appendFileSync, existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect } from 'vitest';
import { asRecord, repoRoot } from './cli.js';
import type { Owner } from './cp006-lab.js';

export const nodes = ['lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m'] as const;
export type Node = typeof nodes[number];
export type Role = 'read' | 'execute';
export type Params = Record<string, unknown>;
export interface Policy {
  maxPrincipalMsat: string;
  callsPerMinute: string;
  lndRootKeyIds: Record<'lnd-p' | 'lnd-r', Record<Role, string>>;
}
export interface Request {
  node: Node;
  credentialPath: string;
  transport: 'lnd-rest' | 'clnrest';
  operation: string;
  params: Params;
  signal?: AbortSignal;
}
export interface ProcessOptions {
  cwd: string;
  env: NodeJS.ProcessEnv;
  timeoutMs: number;
  signal?: AbortSignal;
  stdin?: Uint8Array | string;
}
export interface BakerOptions {
  owner: Owner;
  policy: Policy;
  authorizationFixtures: Record<Node, Record<string, Params>>;
  ports: {
    runProcess(argv: readonly string[], options: ProcessOptions): Promise<{ exitCode: number; stdout: string; stderr: string }>;
    permissions: {
      ensureDirectory(path: string): Promise<void>;
      writeExclusive(path: string, bytes: Uint8Array): Promise<void>;
      readChecked(path: string): Promise<Uint8Array>;
      remove(path: string): Promise<void>;
    };
    permissionRequest(request: Request): Promise<{ statusCode: number; body: unknown }>;
  };
  signal?: AbortSignal;
}
export interface Credential { path: string; fingerprint: string }
export interface BakeResult { credentials: Record<Node, Record<Role, Credential>> }
interface Baker { bakeLabCredentials(options: BakerOptions): Promise<BakeResult> }
interface Scratch { createPrivateDirectory(parent: string, prefix: string): Promise<string> }
interface Material { bytes: Buffer; node: Node; role: Role | 'bootstrap'; permissions: string[]; restrictions: string[][] }
interface Command { argv: string[]; options: ProcessOptions }
export interface Faults {
  process?: 'exit' | 'malformed' | 'oversize' | 'throw';
  permissions?: 'broad-directory' | 'broad-file' | 'symlink' | 'foreign-owner' | 'readback';
  response?: 'allow-denied' | 'deny-allowed' | 'malformed' | 'transport' | 'rate';
  abortAfterWrite?: AbortController;
}

// Public interface load only. Absence is a legitimate fail-first outcome, not a fixture failure.
export async function loadBaker(): Promise<Baker> {
  const target = join(repoRoot, 'labs/docker/credentials.mjs');
  if (!existsSync(target)) throw new Error('CP-008 normal credential baking is not implemented');
  return await import(pathToFileURL(target).href) as Baker;
}

export const readMethods = [
  'method=getinfo', 'method=listpeerchannels', 'method=listchannels', 'method=listinvoices', 'method=listhtlcs',
  'method=getroutes', 'method=askrene-listlayers', 'method=waitsendpay', 'method=listsendpays', 'method=bkpr-listaccountevents',
];
export const executeMethods = [
  'method=getinfo', 'method=listpeerchannels', 'method=listchannels', 'method=invoice', 'method=listinvoices', 'method=listhtlcs',
  'method=delinvoice', 'method=getroutes', 'method^askrene-', 'method=sendpay', 'method=waitsendpay',
  'method=listsendpays', 'method=bkpr-listaccountevents',
];
export const forbiddenCln = ['pay', 'xpay', 'withdraw', 'stop', 'createrune', 'invokerune', 'listconfigs', 'blacklistrune'];
const roles: Role[] = ['read', 'execute'];

function fingerprint(bytes: Uint8Array): string {
  return `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
}
function credentialPath(owner: Owner, node: Node, role: Role): string {
  return join(owner.runtimeRoot, 'credentials', node, `${role}.${node.startsWith('lnd-') ? 'macaroon' : 'rune'}`);
}
function flag(argv: readonly string[], name: string): string {
  const direct = argv.find(value => value.startsWith(`${name}=`));
  if (direct) return direct.slice(name.length + 1);
  const offset = argv.indexOf(name);
  return offset < 0 ? '' : argv[offset + 1] ?? '';
}
function named(argv: readonly string[], name: string): unknown {
  const token = argv.find(value => value.startsWith(`${name}=`));
  if (!token) return undefined;
  return JSON.parse(token.slice(name.length + 1)) as unknown;
}
function arrays(value: unknown): string[][] {
  if (!Array.isArray(value) || !value.every(row => Array.isArray(row) && row.every(item => typeof item === 'string'))) {
    throw new Error('synthetic process received malformed rune restrictions');
  }
  return value;
}
function included(root: string, path: string): boolean {
  const inside = relative(resolve(root), resolve(path));
  return inside !== '' && !inside.startsWith('..') && !isAbsolute(inside);
}
function encodings(bytes: Buffer): string[] {
  const b64 = bytes.toString('base64'), url = bytes.toString('base64url');
  return [bytes.toString('utf8'), bytes.toString('latin1'), bytes.toString('hex'), bytes.toString('hex').toUpperCase(),
    b64, b64.replace(/=+$/, ''), url, url + '='.repeat((4 - url.length % 4) % 4)];
}

/** Independently scripted normal boundaries. These answers model source semantics, not live authority.
 * CLN v26.06.9 createrune.json request/response/restriction_format and checkrune.json response/errors;
 * LND v0.21.4-beta cmd_macaroon.go 205-251 (normal stdout is serialized hex).
 * Fault responses are deliberately hostile inputs, never claims about pinned node availability.
 */
export async function rig(faults: Faults = {}, reuseOwner?: Owner) {
  const tmp = process.env['FLUXWARDEN_TEST_TMP'], sentinel = process.env['FLUXWARDEN_SENTINEL_DIR'];
  if (!tmp || !sentinel) throw new Error('explicit private test temporary and independent sentinel roots are required');
  const declarationPath = join(tmp, 'declared-out.txt');
  const scratch = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as Scratch;
  const root = reuseOwner ? '' : await scratch.createPrivateDirectory(tmp, 'c8-');
  const roots: string[] = [];
  if (!reuseOwner) for (const prefix of ['runtime-', 'tmp-', 'sentinels-', 'evidence-']) roots.push(await scratch.createPrivateDirectory(root, prefix));
  const selected: Owner = reuseOwner ? structuredClone(reuseOwner) : {
    version: 1, id: root.split(/[\\/]/).at(-1) ?? 'cp008', project: `fluxwarden-lab-${root.split(/[\\/]/).at(-1)?.toLowerCase() ?? 'cp008'}`,
    runtimeRoot: roots[0] ?? '', tmpRoot: roots[1] ?? '', sentinelRoot: roots[2] ?? '', evidenceRoot: roots[3] ?? '',
    ports: { lndRest: 28100, clnRest: 28101, toxiproxy: 28102 }, resources: { cpus: 1, memoryBytes: 1073741824, pids: 128 },
  };
  const registration = reuseOwner ? `${selected.id}-${randomUUID()}` : selected.id;
  const policy: Policy = {
    maxPrincipalMsat: '1000', callsPerMinute: '1000000',
    lndRootKeyIds: { 'lnd-p': { read: '11', execute: '12' }, 'lnd-r': { read: '21', execute: '22' } },
  };
  const preimage = randomBytes(32), hash = createHash('sha256').update(preimage).digest('hex'), secret = randomBytes(32), altered = randomBytes(48);
  const pubkey = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
  for (const [kind, bytes] of [['preimage', preimage], ['payment-secret', secret], ['altered-readback', altered]] as const) {
    writeFileSync(join(sentinel, `${registration}-${kind}.bin`), bytes, { flag: 'wx', mode: 0o600 });
  }
  // Params use the pinned schema spelling; synthetic routes are never live valid-request proof.
  const authorizationFixtures = Object.fromEntries(nodes.map(node => [node, node.startsWith('lnd-') ? {
    ListChannels: {}, SendToRouteV2: {
      payment_hash: Buffer.from(hash, 'hex').toString('base64'),
      route: { total_time_lock: 144, total_fees_msat: '0', total_amt_msat: '1000', hops: [{ pub_key: pubkey, chan_id: '1',
        amt_to_forward_msat: '1000', fee_msat: '0', expiry: 144, mpp_record: { payment_addr: secret.toString('base64'), total_amt_msat: '1000' } }] },
    }, ChangePassword: { current_password: 'disposable-current', new_password: 'disposable-new' }, StopDaemon: {},
    LookupInvoice: { r_hash: Buffer.from(hash, 'hex').toString('base64') }, LookupInvoiceV2: { payment_hash: Buffer.from(hash, 'hex').toString('base64') },
  } : {
    getinfo: {}, listpeerchannels: {}, listchannels: {}, listinvoices: {},
    // D75 authorizes this one bounded native read on newly generated roles.
    // CLN v26.06.9 listhtlcs.json request index/start/limit and response htlcs.
    listhtlcs: { index: 'created', start: 0, limit: 500 },
    getroutes: { source: pubkey, destination: pubkey, amount_msat: '1000msat', layers: [] },
    'askrene-listlayers': {}, waitsendpay: { payment_hash: hash, timeout: 1 }, listsendpays: {}, 'bkpr-listaccountevents': {},
    invoice: { amount_msat: '1000msat', label: `cp008-${selected.id}`, description: 'disposable authorization control' },
    delinvoice: { label: `cp008-${selected.id}`, status: 'unpaid' },
    sendpay: { route: [{ id: pubkey, channel: '1x1x1', amount_msat: '1000msat', delay: 144 }], payment_hash: hash, amount_msat: '1000msat', payment_secret: secret.toString('hex') },
    pay: { bolt11: 'synthetic-schema-control' }, xpay: { invstring: 'synthetic-schema-control' }, withdraw: { destination: 'synthetic-schema-control', satoshi: '1' },
    stop: {}, createrune: { restrictions: [] }, invokerune: { restrictions: [] }, listconfigs: {}, blacklistrune: { start: 0, end: 0 },
  }])) as unknown as Record<Node, Record<string, Params>>;
  const commands: Command[] = [], requests: Request[] = [], materials: Material[] = [];
  const files = new Map<string, Buffer>(), checked = new Set<string>(), removed: string[] = [], directories: string[] = [];
  let rejectedPermission = false;
  function materialFor(request: Request): Material {
    const bytes = files.get(request.credentialPath);
    const material = materials.find(row => row.node === request.node && bytes?.equals(row.bytes));
    if (!material) throw new Error('permission control did not use its own provisional stored credential');
    return material;
  }
  function authorized(material: Material, operation: string, params: Params): boolean {
    if (material.role === 'bootstrap') return true;
    if (material.node.startsWith('lnd-')) {
      const permission = operation === 'ListChannels' ? 'offchain:read' : operation === 'SendToRouteV2' ? 'offchain:write' :
        operation === 'LookupInvoice' ? 'invoices:read' : operation === 'LookupInvoiceV2' ? 'invoices:write' :
          operation === 'StopDaemon' ? 'info:write' : undefined;
      return permission !== undefined && material.permissions.includes(permission);
    }
    // createrune.json: OR within an array, AND across arrays; / is inequality, missing pname fails.
    return material.restrictions.every(alternatives => alternatives.some(term => {
      if (term.startsWith('method=')) return operation === term.slice(7);
      if (term.startsWith('method^')) return operation.startsWith(term.slice(7));
      if (term.startsWith('method/')) return operation !== term.slice(7);
      if (term.startsWith('rate=')) return true; // Real shared-ID usage/rate readiness must be proven live.
      if (term.startsWith('pnameamount_msat<')) {
        const amount = params['amount_msat'];
        if (typeof amount !== 'string' && typeof amount !== 'number') return false;
        const decimal = String(amount).replace(/msat$/, '');
        return /^[0-9]+$/.test(decimal) && BigInt(decimal) < BigInt(term.slice(17));
      }
      return false;
    }));
  }
  const options: BakerOptions = { owner: selected, policy, authorizationFixtures, ports: {
    runProcess: (argv, commandOptions) => {
      commands.push({ argv: [...argv], options: commandOptions });
      const node = nodes.find(name => argv.includes(name));
      if (!node) return Promise.reject(new Error('synthetic process requires explicit disposable node'));
      if (faults.process === 'exit') return Promise.resolve({ exitCode: 17, stdout: '', stderr: preimage.toString('hex') });
      if (faults.process === 'throw') return Promise.reject(new Error(secret.toString('base64')));
      if (faults.process === 'malformed') return Promise.resolve({ exitCode: 0, stdout: '{broken', stderr: '' });
      if (faults.process === 'oversize') return Promise.resolve({ exitCode: 0, stdout: preimage.toString('hex') + '00'.repeat(65537 - preimage.length), stderr: '' });
      if (argv.includes('bakemacaroon')) {
        const rootKey = flag(argv, '--root_key_id');
        const role = rootKey === policy.lndRootKeyIds[node as 'lnd-p' | 'lnd-r'].read ? 'read' : 'execute';
        const bytes = randomBytes(48), permissions = argv.filter(arg => /^[a-z]+:(?:read|write)$/.test(arg)).sort();
        materials.push({ bytes, node, role, permissions, restrictions: [] });
        writeFileSync(join(sentinel, `${registration}-${node}-${String(materials.length)}.bin`), bytes, { flag: 'wx', mode: 0o600 });
        return Promise.resolve({ exitCode: 0, stdout: `${bytes.toString('hex')}\n`, stderr: '' });
      }
      if (argv.includes('createrune')) {
        const input = named(argv, 'restrictions');
        const restrictions = input === undefined ? [] : arrays(input);
        const role = restrictions.length === 0 ? 'bootstrap' : restrictions.flat().includes('method=sendpay') ? 'execute' : 'read';
        const bytes = Buffer.from(randomBytes(31).toString('base64'), 'utf8'); // Deliberately retains trailing ==.
        materials.push({ bytes, node, role, permissions: [], restrictions });
        writeFileSync(join(sentinel, `${registration}-${node}-${String(materials.length)}.bin`), bytes, { flag: 'wx', mode: 0o600 });
        return Promise.resolve({ exitCode: 0, stdout: JSON.stringify({ rune: bytes.toString('utf8'), unique_id: String(materials.length) }), stderr: '' });
      }
      return Promise.reject(new Error('unsupported synthetic command; no unverified utility or credential CLI syntax'));
    },
    permissions: {
      ensureDirectory: path => {
        directories.push(path);
        if (faults.permissions === 'broad-directory') { rejectedPermission = true; return Promise.reject(new Error('unsafe owner directory')); }
        if (![tmp, selected.runtimeRoot, selected.sentinelRoot, sentinel].some(parent => included(parent, path))) return Promise.reject(new Error('directory escaped disposable owner'));
        return Promise.resolve();
      },
      writeExclusive: (path, bytes) => {
        if (![selected.runtimeRoot, selected.sentinelRoot, sentinel].some(parent => included(parent, path)) || path.split(/[\\/]/).includes('..')) return Promise.reject(new Error('credential path escaped disposable owner'));
        if (files.has(path)) return Promise.reject(new Error('exclusive credential collision'));
        if (bytes.length === 0 || bytes.length > 65536) return Promise.reject(new Error('credential size outside 1..64KiB'));
        files.set(path, Buffer.from(bytes));
        appendFileSync(declarationPath, `${path}\n`);
        faults.abortAfterWrite?.abort();
        return Promise.resolve();
      },
      readChecked: path => {
        checked.add(path);
        if (faults.permissions && faults.permissions !== 'broad-directory' && faults.permissions !== 'readback') { rejectedPermission = true; return Promise.reject(new Error('descriptor ownership or access check failed')); }
        const value = files.get(path);
        if (!value) return Promise.reject(new Error('missing provisional credential'));
        return Promise.resolve(faults.permissions === 'readback' ? Buffer.from(altered) : Buffer.from(value));
      },
      remove: path => { removed.push(path); files.delete(path); return Promise.resolve(); },
    },
    permissionRequest: request => {
      requests.push(request);
      if (faults.response === 'transport') return Promise.reject(new Error(preimage.toString('base64')));
      if (faults.response === 'malformed') return Promise.resolve({ statusCode: 200, body: { error: { code: 1502, message: secret.toString('hex') } } });
      if (faults.response === 'rate') return Promise.resolve({ statusCode: 403, body: { code: 1502, message: 'rate limit exceeded' } });
      const material = materialFor(request);
      let allow: boolean;
      if (request.operation === 'checkrune') {
        const value = request.params['rune'], method = request.params['method'];
        const candidate = materials.find(row => row.node === request.node && row.bytes.toString('utf8') === value);
        if (!candidate || typeof method !== 'string') return Promise.reject(new Error('checkrune requires normal candidate body and named method'));
        allow = authorized(candidate, method, asRecord(request.params['params'], 'checkrune named parameters'));
      } else allow = authorized(material, request.operation, request.params);
      if (faults.response === 'allow-denied' && !allow) allow = true;
      if (faults.response === 'deny-allowed' && allow) allow = false;
      if (!allow) return Promise.resolve({ statusCode: 403, body: { code: request.node.startsWith('lnd-') ? 7 : 1502, message: 'permission denied' } });
      const body = request.operation === 'checkrune' ? { valid: true } : request.operation === 'ListChannels' ? { channels: [] } :
        request.operation === 'listhtlcs' ? { htlcs: [] } :
        request.operation === 'LookupInvoice' || request.operation === 'LookupInvoiceV2' ? { r_preimage: preimage.toString('base64'), settled: false } : {};
      return Promise.resolve({ statusCode: 200, body });
    },
  } };
  function lndBakes() {
    return commands.filter(call => call.argv.includes('bakemacaroon')).map(call => ({
      node: nodes.find(node => call.argv.includes(node)), root: flag(call.argv, '--root_key_id'),
      permissions: call.argv.filter(arg => /^[a-z]+:(?:read|write)$/.test(arg)).sort(),
    })).sort((a, b) => `${a.node ?? ''}-${a.root}`.localeCompare(`${b.node ?? ''}-${b.root}`));
  }
  function runeBakes() { return materials.filter(row => row.role !== 'bootstrap' && row.node.startsWith('cln-')); }
  function assertPrivateBoundary() {
    for (const command of commands) {
      expect(command.argv[0]).toBe('docker');
      expect(command.argv).toContain(selected.project);
      expect(command.argv).toContain('-T');
      if (command.argv.includes('lightning-cli')) expect(command.argv).toContain('-k');
      const text = JSON.stringify({ argv: command.argv, env: command.options.env });
      expect(materials.every(row => encodings(row.bytes).every(value => !text.includes(value))) &&
        [preimage, secret].every(bytes => encodings(bytes).every(value => !text.includes(value))), 'no credentials or payment secrets in argv/environment').toBe(true);
    }
    expect(commands.length, 'baking actually invokes normal processes').toBeGreaterThanOrEqual(10);
  }
  function assertAccepted(result: BakeResult) {
    expect(Object.keys(result)).toEqual(['credentials']);
    expect(Object.keys(result.credentials).sort()).toEqual([...nodes].sort());
    for (const node of nodes) {
      expect(Object.keys(result.credentials[node]).sort()).toEqual(['execute', 'read']);
      for (const role of roles) {
        const record = result.credentials[node][role], target = credentialPath(selected, node, role), bytes = files.get(target);
        expect(Object.keys(record).sort()).toEqual(['fingerprint', 'path']);
        expect(record.path).toBe(target);
        expect(bytes !== undefined && bytes.length > 0 && bytes.length <= 65536, 'nonempty bounded provisional file exists').toBe(true);
        expect(record.fingerprint === fingerprint(bytes ?? Buffer.alloc(0)), 'stored bytes determine canonical fingerprint').toBe(true);
        expect(checked.has(target), 'acceptance requires checked descriptor readback').toBe(true);
        expect(materials.some(row => row.node === node && row.role === role && row.bytes.equals(bytes ?? Buffer.alloc(0))), 'exact role bytes including padding survive').toBe(true);
        expect(requests.some(request => request.node === node && request.credentialPath === target), 'every role receives normal permission controls').toBe(true);
      }
    }
    expect(materials.filter(row => row.role === 'bootstrap').every(row => ![...files.values()].some(bytes => bytes.equals(row.bytes))), 'no unrestricted bootstrap survives acceptance').toBe(true);
    const serialized = JSON.stringify(result);
    expect(materials.every(row => encodings(row.bytes).every(value => !serialized.includes(value))) &&
      [preimage, secret].every(bytes => encodings(bytes).every(value => !serialized.includes(value))), 'retained metadata excludes secret encodings').toBe(true);
    assertPrivateBoundary();
  }
  function assertClean(error: unknown) {
    expect(error instanceof Error, 'failed baking rejects').toBe(true);
    const text = error instanceof Error ? `${error.message}\n${error.stack ?? ''}` : '';
    expect(materials.every(row => encodings(row.bytes).every(value => !text.includes(value))) &&
      [preimage, secret, altered].every(bytes => encodings(bytes).every(value => !text.includes(value))), 'failure diagnostics redact every secret encoding').toBe(true);
    expect([...files.keys()].filter(path => included(selected.runtimeRoot, path)), 'all provisional owner output removed').toEqual([]);
  }
  function assertUntouched() {
    if ([commands, requests, materials, removed, directories].some(rows => rows.length !== 0) || files.size !== 0 || checked.size !== 0 || rejectedPermission) {
      throw new Error('refused policy produced a process request credential or permission side effect');
    }
    const ownerRoots = [selected.runtimeRoot, selected.tmpRoot, selected.sentinelRoot, selected.evidenceRoot];
    if (ownerRoots.some(path => readdirSync(path).length !== 0)) throw new Error('refusal owner fixture contains undeclared artifacts');
    const declared = readFileSync(declarationPath, 'utf8').split(/\r?\n/).filter(Boolean);
    if (declared.some(path => ownerRoots.some(parent => included(parent, path)))) throw new Error('refused policy declared an owner output');
  }
  return { options, selected, commands, requests, materials, files, checked, removed, directories, preimage,
    lndBakes, runeBakes, assertAccepted, assertPrivateBoundary, assertClean, assertUntouched, rejectedPermission: () => rejectedPermission };
}

/** Refusal cases share immutable secure roots; every mutable boundary state and policy is fresh.
 * Prior side effects abort reuse rather than being cleared, so contamination cannot hide a defect. */
export async function refusalFixtures() {
  const baseline = await rig();
  const owner = structuredClone(baseline.selected);
  const paths = nodes.flatMap(node => roles.map(role => credentialPath(owner, node, role)));
  if (new Set(paths).size !== 10) throw new Error('refusal owner has duplicate role paths');
  baseline.assertUntouched();
  let current = baseline, first = true;
  return async () => {
    current.assertUntouched();
    if (first) first = false;
    else current = await rig({}, owner);
    current.assertUntouched();
    return current;
  };
}

export async function rejection(action: () => Promise<unknown>): Promise<unknown> {
  try { await action(); } catch (error) { return error; }
  throw new Error('baker accepted a forbidden outcome');
}
