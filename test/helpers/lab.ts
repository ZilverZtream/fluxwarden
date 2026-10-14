// Live regtest oracles for the lab facts suite. Node commands run inside the
// owner's containers with `docker exec` (no shell, never through a proxy); REST
// calls go through the owner's Toxiproxy ports with a certificate copied out of
// the container and pinned as the only CA.
//
// The lab is selected only by an explicit declaration: FLUXWARDEN_LAB_OWNER is the
// absolute path of the owner JSON given to `lab.mjs up --owner`. Its runtime root
// holds lab.json (ports, pubkeys, credential paths and fingerprints).
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { request, type RequestOptions } from 'node:https';
import { isAbsolute, join } from 'node:path';
import { LabInvalidError } from './chaos.js';

export { LabInvalidError };

export const lightningNodes = ['lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m'] as const;
export type Node = typeof lightningNodes[number];
export type Service = Node | 'bitcoind';
export type Role = 'read' | 'execute';

export interface CommandResult { exitCode: number | null; stdout: string; stderr: string }
export type Runner = (service: Service, argv: readonly string[]) => CommandResult;
export type Outcome =
  | { kind: 'accepted'; value: unknown }
  | { kind: 'rejected'; code: string | number; message: string }
  | { kind: 'error'; detail: string };

export interface LabDeclaration {
  project: string;
  ports?: { lndRest: number; clnRest: number; toxiproxy: number };
  runtimeRoot?: string;
  sentinelRoot?: string;
}

const lnd = (service: Service): boolean => service.startsWith('lnd-');
const cln = (service: Service): boolean => service.startsWith('cln-');

export function record(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new LabInvalidError(`${what} is not an observed object`);
  return value as Record<string, unknown>;
}
export function list(value: unknown, what: string): Record<string, unknown>[] {
  if (!Array.isArray(value)) throw new LabInvalidError(`${what} is not an observed list`);
  return value.map(item => record(item, what));
}
export function text(value: unknown, what: string): string {
  if (typeof value !== 'string') throw new LabInvalidError(`${what} is not observed text`);
  return value;
}

/** Oracle argv per container. CLN calls always use named parameters (-k). */
export function cliArgv(service: Service, args: readonly string[]): string[] {
  if (service === 'bitcoind') return ['bitcoin-cli', '-regtest', ...args];
  return lnd(service) ? ['lncli', '--network=regtest', ...args] : ['lightning-cli', '--network=regtest', '-k', ...args];
}

// lightning-cli prints JSON-RPC notifications (askrene progress) as '# ' lines before the reply.
function parse(stdout: string): unknown {
  const trimmed = stdout.split('\n').filter(line => !line.startsWith('# ')).join('\n').trim();
  try { return JSON.parse(trimmed) as unknown; } catch { return undefined; }
}

/**
 * Maps one finished oracle command to accepted / rejected / error.
 * - lncli (lnd cmd/lncli/main.go `fatal`): success exits 0 with JSON; a node answer
 *   exits 1 with `[lncli] rpc error: code = <Code> desc = <text>` on stderr. Any other
 *   failure (local usage, connection, docker) is an error, not a node refusal.
 * - lightning-cli (doc/lightning-cli.1.md EXIT STATUS): 0 success; 1 lightningd returned
 *   an error reply, printed as JSON `{code, message}`; 2 could not talk to lightningd;
 *   3 usage error.
 * - bitcoin-cli (src/bitcoin-cli.cpp): an RPC error prints `error code: <n>` and exits
 *   with |n|.
 * Docker's own failures (125, 126, 127, no exit status) are errors.
 */
export function classify(service: Service, result: CommandResult): Outcome {
  const { exitCode, stdout, stderr } = result;
  if (exitCode === null || exitCode >= 125) return { kind: 'error', detail: `container command did not run (exit ${String(exitCode)})` };
  if (exitCode === 0) {
    const value = parse(stdout);
    if (value !== undefined) return { kind: 'accepted', value };
    if (service === 'bitcoind' && stdout.trim() !== '') return { kind: 'accepted', value: stdout.trim() };
    return { kind: 'error', detail: 'successful exit without a JSON answer' };
  }
  if (lnd(service)) {
    const match = exitCode === 1 ? /^\[lncli\] rpc error: code = (\w+) desc = (.*)$/m.exec(stderr) : null;
    // grpc-go raises Unavailable and DeadlineExceeded in the client when lnd did not answer.
    if (!match || match[1] === 'Unavailable' || match[1] === 'DeadlineExceeded') return { kind: 'error', detail: 'lncli failed without a node answer' };
    return { kind: 'rejected', code: match[1] ?? '', message: match[2] ?? '' };
  }
  if (cln(service)) {
    const answer = exitCode === 1 ? parse(stdout) : undefined;
    if (typeof answer === 'object' && answer !== null && !Array.isArray(answer)) {
      const { code, message } = answer as Record<string, unknown>;
      if (Number.isInteger(code) && typeof message === 'string') return { kind: 'rejected', code: code as number, message };
    }
    return { kind: 'error', detail: 'lightning-cli failed without a lightningd error reply' };
  }
  const match = /^error code: (-?\d+)$/m.exec(stderr);
  if (match && Math.abs(Number(match[1])) === exitCode) {
    const message = /^error message:\n([\s\S]*)$/m.exec(stderr)?.[1]?.trim() ?? '';
    return { kind: 'rejected', code: Number(match[1]), message };
  }
  return { kind: 'error', detail: 'bitcoin-cli failed without an RPC error' };
}

const containers = new Map<string, string>();
function container(project: string, service: Service): string {
  const key = `${project}/${service}`;
  const known = containers.get(key);
  if (known) return known;
  const found = spawnSync('docker', ['ps', '-q', '--filter', `label=com.docker.compose.project=${project}`, '--filter', `label=com.docker.compose.service=${service}`],
    { shell: false, windowsHide: true, encoding: 'utf8', timeout: 30_000 });
  const ids = found.status === 0 ? found.stdout.split(/\s+/).filter(Boolean) : [];
  if (ids.length !== 1 || !ids[0]) throw new LabInvalidError(`exactly one running ${service} container of the declared project is required`);
  containers.set(key, ids[0]);
  return ids[0];
}

export function dockerRunner(project: string): Runner {
  return (service, argv) => {
    const result = spawnSync('docker', ['exec', container(project, service), ...argv], { shell: false, windowsHide: true, encoding: 'utf8', timeout: 60_000, maxBuffer: 16 * 1024 * 1024 });
    return { exitCode: result.error ? null : result.status, stdout: result.stdout, stderr: result.stderr };
  };
}

/** Starts an oracle command that blocks (a payment to a held invoice) and resolves when it ends. */
export function background(project: string, service: Service, args: readonly string[]): Promise<CommandResult> {
  return new Promise(resolve => {
    const child = spawn('docker', ['exec', container(project, service), ...cliArgv(service, args)], { shell: false, windowsHide: true });
    let stdout = '', stderr = '';
    child.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString('utf8'); });
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8'); });
    child.on('error', () => { resolve({ exitCode: null, stdout, stderr }); });
    child.on('close', code => { resolve({ exitCode: code, stdout, stderr }); });
  });
}

/** The explicit owner declaration and its lab.json; nothing is discovered or adopted. */
export function declaredLab(): LabDeclaration & { manifest: Record<string, unknown> } {
  const file = process.env['FLUXWARDEN_LAB_OWNER'];
  if (!file || !isAbsolute(file) || !existsSync(file)) throw new LabInvalidError('FLUXWARDEN_LAB_OWNER must name the absolute owner declaration of a running lab');
  const owner = record(JSON.parse(readFileSync(file, 'utf8')) as unknown, 'owner declaration');
  const project = text(owner['project'], 'owner project'), runtimeRoot = text(owner['runtimeRoot'], 'owner runtime root');
  if (!/^fluxwarden-lab-[a-z0-9-]+$/.test(project)) throw new LabInvalidError('an isolated fluxwarden-lab project is required');
  const ports = record(owner['ports'], 'owner ports');
  const manifestPath = join(runtimeRoot, 'lab.json');
  if (!existsSync(manifestPath)) throw new LabInvalidError('the declared owner has no lab.json; the lab is not up');
  const manifest = record(JSON.parse(readFileSync(manifestPath, 'utf8')) as unknown, 'lab.json');
  if (manifest['project'] !== project) throw new LabInvalidError('lab.json belongs to another project');
  return {
    project, runtimeRoot, sentinelRoot: text(owner['sentinelRoot'], 'owner sentinel root'), manifest,
    ports: { lndRest: Number(ports['lndRest']), clnRest: Number(ports['clnRest']), toxiproxy: Number(ports['toxiproxy']) },
  };
}

export interface Lab {
  readonly declaration: LabDeclaration & { manifest?: Record<string, unknown> };
  readonly pubkeys: Record<Node, string>;
  run(service: Service, args: readonly string[]): Outcome;
  ok(service: Service, args: readonly string[]): Record<string, unknown>;
  value(service: Service, args: readonly string[]): unknown;
  height(): number;
}

const secrets = new Set<string>();
/** A fresh 32-byte preimage, registered as a sentinel and redacted from transcripts. */
export function newPreimage(): { preimage: string; hash: string } {
  const bytes = randomBytes(32);
  const directory = process.env['FLUXWARDEN_SENTINEL_DIR'];
  if (directory) writeFileSync(join(directory, `lab-preimage-${bytes.subarray(0, 4).toString('hex')}.bin`), bytes, { mode: 0o600 });
  secrets.add(bytes.toString('hex'));
  return { preimage: bytes.toString('hex'), hash: createHash('sha256').update(bytes).digest('hex') };
}
function transcript(service: Service, args: readonly string[], outcome: Outcome): void {
  const directory = process.env['FLUXWARDEN_EVIDENCE_DIR'];
  if (!directory) return;
  let line = JSON.stringify({ service, args, outcome: outcome.kind, code: outcome.kind === 'rejected' ? outcome.code : undefined });
  for (const secret of secrets) line = line.split(secret).join('[redacted]');
  appendFileSync(join(directory, 'lab-facts-transcript.jsonl'), `${line}\n`, { mode: 0o600 });
}

/**
 * Opens the declared lab. Before any fact body runs, every node must report regtest and
 * the pinned version (SPEC 11.1: LND 0.21.4-beta, CLN v26.06.9, Bitcoin Core 31.1) using
 * read-only identity calls only; anything else is LabInvalidError.
 */
export function openLab(options: { run?: Runner; declaration?: LabDeclaration & { manifest?: Record<string, unknown> } } = {}): Lab {
  const declaration = options.declaration ?? declaredLab();
  const run = options.run ?? dockerRunner(declaration.project);
  const call = (service: Service, args: readonly string[]): Outcome => {
    const outcome = classify(service, run(service, cliArgv(service, args)));
    transcript(service, args, outcome);
    return outcome;
  };
  const accepted = (service: Service, args: readonly string[]): unknown => {
    const outcome = call(service, args);
    if (outcome.kind !== 'accepted') throw new LabInvalidError(`${service} ${args[0] ?? ''} was not accepted: ${outcome.kind === 'rejected' ? `${String(outcome.code)} ${outcome.message}` : outcome.detail}`);
    return outcome.value;
  };
  const chain = record(accepted('bitcoind', ['getblockchaininfo']), 'bitcoind chain');
  if (chain['chain'] !== 'regtest') throw new LabInvalidError('bitcoind is not on regtest');
  const bitcoin = record(accepted('bitcoind', ['getnetworkinfo']), 'bitcoind identity');
  if (bitcoin['subversion'] !== '/Satoshi:31.1.0/') throw new LabInvalidError('bitcoind is not the pinned 31.1');
  const pubkeys = {} as Record<Node, string>;
  for (const node of lightningNodes) {
    const info = record(accepted(node, ['getinfo']), `${node} identity`);
    const network = lnd(node) ? list(info['chains'], `${node} chains`)[0]?.['network'] : info['network'];
    const version = text(info['version'], `${node} version`);
    if (network !== 'regtest') throw new LabInvalidError(`${node} is not on regtest`);
    if (lnd(node) ? !/^0\.21\.4-beta(?: |$)/.test(version) : version !== 'v26.06.9') throw new LabInvalidError(`${node} is not the pinned version`);
    const key = text(lnd(node) ? info['identity_pubkey'] : info['id'], `${node} pubkey`);
    if (!/^0[23][0-9a-f]{64}$/.test(key)) throw new LabInvalidError(`${node} pubkey is malformed`);
    pubkeys[node] = key;
  }
  return {
    declaration, pubkeys, run: call, value: accepted,
    ok: (service, args) => record(accepted(service, args), `${service} ${args[0] ?? ''}`),
    height: () => Number(record(accepted('bitcoind', ['getblockchaininfo']), 'bitcoind chain')['blocks']),
  };
}

let shared: Lab | undefined;
/** One guarded lab per test file. */
export function lab(): Lab { return shared ??= openLab(); }

// ---- REST through the owner's proxies -------------------------------------------------

export interface RestAnswer { status: number; text: string; body: unknown }
const pemCache = new Map<string, Buffer>();
/** Certificates copied out of the container: LND tls.cert, and the clnrest CA (A4). */
export function copiedCertificate(l: Lab, node: 'lnd-p' | 'lnd-r' | 'cln-m'): Buffer {
  const key = `${l.declaration.project}/${node}`;
  const cached = pemCache.get(key);
  if (cached) return cached;
  const nodes = l.declaration.manifest?.['nodes'];
  if (nodes && typeof nodes === 'object' && !Array.isArray(nodes)) {
    const identity = record(record(nodes, 'node identities')[node], 'node identity');
    const file = text(record(identity['certificate'], 'node certificate')['path'], 'node certificate path');
    const certificate = readFileSync(file);
    pemCache.set(key, certificate);
    return certificate;
  }
  const path = node.startsWith('lnd-') ? '/root/.lnd/tls.cert' : '/root/.lightning/regtest/ca.pem';
  const result = spawnSync('docker', ['exec', container(l.declaration.project, node), 'cat', path], { shell: false, windowsHide: true, timeout: 30_000 });
  if (result.status !== 0 || !result.stdout.toString('utf8').includes('BEGIN CERTIFICATE')) throw new LabInvalidError(`${node} certificate ${path} could not be copied`);
  pemCache.set(key, result.stdout);
  return result.stdout;
}
function credential(l: Lab, node: Node, role: Role): Buffer {
  const credentials = record(l.declaration.manifest?.['credentials'], 'lab.json credentials');
  const entry = record(record(credentials[node], `${node} credentials`)[role], `${node} ${role} credential`);
  return readFileSync(text(entry['path'], 'credential path'));
}
function ports(l: Lab): { lndRest: number; clnRest: number; toxiproxy: number } {
  const value = l.declaration.ports;
  if (!value) throw new LabInvalidError('declared owner ports are required for REST');
  return value;
}

export async function toxiproxy(l: Lab, method: 'GET' | 'POST', path: string, body?: unknown): Promise<unknown> {
  const response = await fetch(`http://127.0.0.1:${String(ports(l).toxiproxy)}${path}`, { method, ...(body === undefined ? {} : { body: JSON.stringify(body), headers: { 'content-type': 'application/json' } }) });
  if (!response.ok) throw new LabInvalidError(`toxiproxy ${method} ${path} answered ${String(response.status)}`);
  return await response.json() as unknown;
}
/** Both managed proxies must be enabled, clean and aimed at their own node (ARCHITECTURE 10.2). */
export async function cleanProxies(l: Lab): Promise<void> {
  const state = record(await toxiproxy(l, 'GET', '/proxies'), 'proxy state');
  for (const [name, upstream] of [['lnd-r-rest', 'lnd-r:8080'], ['cln-m-rest', 'cln-m:3010']] as const) {
    const proxy = record(state[name], name);
    if (proxy['enabled'] !== true || list(proxy['toxics'], 'toxics').length !== 0 || proxy['upstream'] !== upstream) throw new LabInvalidError(`${name} is not an enabled clean proxy to ${upstream}`);
  }
}

function https(options: RequestOptions, body: string | undefined, timeoutMs: number, onChunk?: (chunk: string) => boolean): Promise<RestAnswer> {
  return new Promise((resolve, reject) => {
    let raw = '', status = 0, settled = false;
    const finish = (): void => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      let parsed: unknown; try { parsed = JSON.parse(raw) as unknown; } catch { parsed = undefined; }
      resolve({ status, text: raw, body: parsed });
      outgoing.destroy();
    };
    const timer = setTimeout(() => { if (onChunk) finish(); else { settled = true; outgoing.destroy(); reject(new Error('REST call timed out')); } }, timeoutMs);
    const outgoing = request({ ...options, agent: false }, response => {
      status = response.statusCode ?? 0;
      response.on('data', (chunk: Buffer) => { raw += chunk.toString('utf8'); if (onChunk?.(raw)) finish(); });
      response.on('end', finish);
      response.on('error', () => { finish(); });
    });
    outgoing.on('error', error => { if (!settled) { settled = true; clearTimeout(timer); reject(error); } });
    outgoing.end(body);
  });
}

/** LND REST through lnd-r-rest with the copied tls.cert (IP SAN 127.0.0.1, --tlsextraip). */
export async function lndRest(l: Lab, method: 'GET' | 'POST', path: string, body?: unknown, role: Role = 'execute'): Promise<RestAnswer> {
  return await https({ host: '127.0.0.1', port: ports(l).lndRest, method, path, ca: copiedCertificate(l, 'lnd-r'), rejectUnauthorized: true,
    headers: { 'Grpc-Metadata-macaroon': credential(l, 'lnd-r', role).toString('hex'), ...(body === undefined ? {} : { 'content-type': 'application/json' }) } },
  body === undefined ? undefined : JSON.stringify(body), 30_000);
}

/** Secret-bearing requests use pinned HTTPS; LND-P shares the owner proxy temporarily. */
async function lndInvoiceRequest(l: Lab, node: 'lnd-p' | 'lnd-r', path: string, body: unknown): Promise<RestAnswer> {
  if (node === 'lnd-r') return await lndRest(l, 'POST', path, body);
  const state = record(await toxiproxy(l, 'GET', '/proxies/lnd-r-rest'), 'LND proxy');
  const upstream = text(state['upstream'], 'LND proxy upstream'), enabled = state['enabled'];
  if (typeof enabled !== 'boolean') throw new LabInvalidError('LND proxy enabled state is required');
  const setProxy = async (upstream: string, enabled: boolean): Promise<void> => {
    const changed = record(await toxiproxy(l, 'POST', '/proxies/lnd-r-rest', { upstream, enabled }), 'LND proxy target');
    if (changed['upstream'] !== upstream || changed['enabled'] !== enabled) throw new LabInvalidError('LND proxy did not retain its requested state');
  };
  try {
    await setProxy('lnd-p:8080', true);
    return await https({ host: '127.0.0.1', port: ports(l).lndRest, servername: node, method: 'POST', path, ca: copiedCertificate(l, node), rejectUnauthorized: true,
      headers: { 'Grpc-Metadata-macaroon': credential(l, node, 'execute').toString('hex'), 'content-type': 'application/json' } }, JSON.stringify(body), 30_000);
  } finally {
    await setProxy(upstream, enabled);
  }
}

/** lnrpc/lightning.yaml AddInvoice: base64 bytes on REST, hex bytes for CLI oracles. */
export async function lndInvoice(l: Lab, node: 'lnd-p' | 'lnd-r', amountMsat: bigint, preimage: string): Promise<Record<string, unknown>> {
  const answer = await lndInvoiceRequest(l, node, '/v1/invoices', { value_msat: amountMsat.toString(), r_preimage: Buffer.from(preimage, 'hex').toString('base64') });
  if (answer.status !== 200) throw new LabInvalidError('LND invoice creation was not accepted');
  const invoice = record(answer.body, 'LND invoice');
  for (const name of ['r_hash', 'payment_addr']) invoice[name] = Buffer.from(text(invoice[name], name), 'base64').toString('hex');
  return invoice;
}

/** invoicesrpc/invoices.yaml SettleInvoice: POST body carries base64 bytes. */
export async function settleInvoice(l: Lab, node: 'lnd-p', preimage: string): Promise<void> {
  const answer = await lndInvoiceRequest(l, node, '/v2/invoices/settle', { preimage: Buffer.from(preimage, 'hex').toString('base64') });
  if (answer.status !== 200) throw new LabInvalidError('LND invoice settlement was not accepted');
}

/** CLN doc/schemas/invoice.json: preimage is a hex string in the HTTPS body. */
export async function clnInvoice(l: Lab, amountMsat: bigint, label: string, description: string, preimage: string): Promise<Record<string, unknown>> {
  if (amountMsat > BigInt(Number.MAX_SAFE_INTEGER)) throw new LabInvalidError('invoice amount exceeds the exact JSON integer range');
  const answer = await clnRest(l, 'invoice', { amount_msat: Number(amountMsat), label, description, preimage });
  if (answer.status !== 201) throw new LabInvalidError('CLN invoice creation was not accepted');
  return record(answer.body, 'CLN invoice');
}

/** NDJSON stream lines (grpc-gateway ForwardResponseStream, L22) until `until` holds or the deadline. */
export async function lndStream(l: Lab, path: string, until: (lines: unknown[]) => boolean, timeoutMs = 30_000): Promise<{ status: number; lines: unknown[] }> {
  const lines = (raw: string): unknown[] => raw.split('\n').filter(line => line.trim() !== '').flatMap(line => { try { return [JSON.parse(line) as unknown]; } catch { return []; } });
  const answer = await https({ host: '127.0.0.1', port: ports(l).lndRest, method: 'GET', path, ca: copiedCertificate(l, 'lnd-r'), rejectUnauthorized: true,
    headers: { 'Grpc-Metadata-macaroon': credential(l, 'lnd-r', 'read').toString('hex') } }, undefined, timeoutMs, raw => until(lines(raw)));
  return { status: answer.status, lines: lines(answer.text) };
}

/** clnrest `POST /v1/<method>` through cln-m-rest, pinning the copied CA; the server certificate names `cln` and `localhost`. */
export async function clnRest(l: Lab, method: string, params: Record<string, unknown>, role: Role = 'execute', ca: Buffer = copiedCertificate(l, 'cln-m'), servername = 'localhost'): Promise<RestAnswer> {
  // A rune `rate=` refusal (1502 "too soon") says nothing about the method; it is retried within a deadline.
  for (let attempt = 0; ; attempt += 1) {
    const answer = await clnOnce(l, method, params, role, ca, servername);
    const body = answer.body as { code?: unknown; message?: unknown } | undefined;
    if (!(answer.status === 401 && body?.code === 1502 && body.message === 'Not permitted: too soon') || attempt >= 20) return answer;
    await new Promise(resolve => { setTimeout(resolve, 200); });
  }
}
async function clnOnce(l: Lab, method: string, params: Record<string, unknown>, role: Role, ca: Buffer, servername: string): Promise<RestAnswer> {
  return await https({ host: '127.0.0.1', port: ports(l).clnRest, servername, method: 'POST', path: `/v1/${method}`, ca, rejectUnauthorized: true,
    headers: { rune: credential(l, 'cln-m', role).toString('utf8'), 'content-type': 'application/json' } }, JSON.stringify(params), 30_000);
}

// ---- Lab scenario helpers ---------------------------------------------------------------

/** Polls an observed condition with a deadline; there are no condition-free sleeps. */
export async function until<T>(observe: () => T | undefined, what: string, timeoutMs = 60_000): Promise<T> {
  const end = performance.now() + timeoutMs;
  for (;;) {
    const value = observe();
    if (value !== undefined) return value;
    if (performance.now() > end) throw new Error(`${what} was not observed within ${String(timeoutMs)} ms`);
    await new Promise(resolve => { setTimeout(resolve, 250); });
  }
}

/** LND's `local_balance` etc. of one channel, read with lncli (sat strings). */
export function lndChannel(l: Lab, node: 'lnd-p' | 'lnd-r', peer: Node): Record<string, unknown> {
  const channels = list(l.ok(node, ['listchannels'])['channels'], `${node} channels`).filter(channel => channel['remote_pubkey'] === l.pubkeys[peer]);
  if (channels.length !== 1 || !channels[0]) throw new LabInvalidError(`${node} has no single channel with ${peer}`);
  return channels[0];
}
/** Decimal short channel id as lncli `scid` (the REST `chan_id`, L29). */
export function lndScid(l: Lab, node: 'lnd-p' | 'lnd-r', peer: Node): string { return text(lndChannel(l, node, peer)['scid'], 'scid'); }
export function blockScid(decimal: string): string {
  const value = BigInt(decimal);
  return `${String(value >> 40n)}x${String((value >> 16n) & 0xffffffn)}x${String(value & 0xffffn)}`;
}
/** BOLT 7 channel direction: 0 when the source has the lexicographically smaller node id. */
export function direction(from: string, to: string): 0 | 1 { return from < to ? 0 : 1; }

/** A hold invoice on an LND node (invoicesrpc AddHoldInvoice); settle or cancel it explicitly. */
export function holdInvoice(l: Lab, node: 'lnd-p', amountSat: number): { hash: string; preimage: string; bolt11: string; paymentAddr: string } {
  const { preimage, hash } = newPreimage();
  const answer = l.ok(node, ['addholdinvoice', hash, '--amt', String(amountSat)]);
  return { hash, preimage, bolt11: text(answer['payment_request'], 'hold invoice'), paymentAddr: text(answer['payment_addr'], 'hold payment addr') };
}
export async function invoiceState(l: Lab, node: 'lnd-p' | 'lnd-r', hash: string, state: 'ACCEPTED' | 'SETTLED' | 'CANCELED'): Promise<Record<string, unknown>> {
  return await until(() => { const invoice = l.ok(node, ['lookupinvoice', hash]); return invoice['state'] === state ? invoice : undefined; }, `${node} invoice ${state}`);
}

/** Single-hop route for lncli sendtoroute (bytes in hex, lncli UseHexForBytes); `payment_addr` is required since 0.21 (L8). */
export function oneHopRoute(chanId: string, pubkey: string, amountMsat: bigint, expiry: number): string {
  return JSON.stringify({ route: { total_time_lock: expiry, total_amt_msat: amountMsat.toString(), hops: [{
    chan_id: chanId, expiry, amt_to_forward_msat: amountMsat.toString(), pub_key: pubkey, tlv_payload: true,
    mpp_record: { payment_addr: randomBytes(32).toString('hex'), total_amt_msat: amountMsat.toString() } }] } });
}
