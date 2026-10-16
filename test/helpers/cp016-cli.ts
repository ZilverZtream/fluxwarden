// Helpers for the read-only commands and the collector: a configuration writer, a child-process
// runner with environment and Node-flag control and in-child signal delivery, fake-node setups and
// database readers. Product code is reached only through the built binary and dist modules.
import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { pathToFileURL } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { binPath, childEnv, readJson, repoRoot } from './cli.js';
import { secretForms } from './output.js';
import { certificatePath, type FakeServer, type Identity } from '../fakes/https.js';
import { startFakeLnd, type FakeLnd, type LndRoute } from '../fakes/lnd/fake-lnd.js';
import { startFakeCln, type ClnHandler, type FakeCln } from '../fakes/cln/fake-cln.js';
import { getInfo } from '../fakes/lnd/responses.js';
import { getinfo } from '../fakes/cln/responses.js';

/** Forward slashes: a Windows path then needs no escaping inside a double-quoted YAML scalar. */
export const yamlPath = (path: string): string => path.replace(/\\/g, '/');

export function scratch(prefix: string): string {
  return mkdtempSync(join(process.env['FLUXWARDEN_TEST_TMP'] ?? tmpdir(), `fw-${prefix}-`));
}

/** The repository's disposable sentinel credentials (test/sentinels.json), read by path. */
export const SENTINEL_MACAROON = join(repoRoot, 'test', 'sentinels', 'macaroon.bin');
export const SENTINEL_RUNE = join(repoRoot, 'test', 'sentinels', 'rune.txt');
export const sentinelMacaroonHex = (): string => readFileSync(SENTINEL_MACAROON).toString('hex');
export const sentinelRune = (): string => readFileSync(SENTINEL_RUNE, 'utf8').trim();

/** Every encoding of `bytes` that `text` contains (empty when nothing leaked). */
export function leakedForms(text: string, bytes: Buffer): string[] {
  return secretForms(bytes).filter(([, form]) => form.length >= 16 && text.includes(form)).map(([name]) => name);
}

export interface NodeEntry {
  readonly name: string;
  readonly implementation: 'lnd' | 'cln';
  readonly url: string;
  readonly tlsCert: string;
  /** macaroon file (lnd) or rune file (cln) */
  readonly credential: string;
  readonly expectedPubkey: string;
}

export interface ConfigInput {
  readonly database: string;
  readonly policy?: string;
  readonly collectInterval?: string;
  readonly nodes: readonly NodeEntry[];
}

/** Writes fluxwarden.yaml in the SPEC.md §10.1 YAML subset; credential keys as SECURITY.md §3.3 names them. */
export function writeConfig(dir: string, input: ConfigInput): string {
  const lines = [`database: "${yamlPath(input.database)}"`];
  if (input.policy !== undefined) lines.push(`policy: "${yamlPath(input.policy)}"`);
  if (input.collectInterval !== undefined) lines.push(`collect_interval: ${input.collectInterval}`);
  lines.push('nodes:');
  for (const node of input.nodes) {
    lines.push(
      `  - name: ${node.name}`,
      `    implementation: ${node.implementation}`,
      `    url: "${node.url}"`,
      `    tls_cert_path: "${yamlPath(node.tlsCert)}"`,
      `    ${node.implementation === 'lnd' ? 'macaroon_path' : 'rune_path'}: "${yamlPath(node.credential)}"`,
      `    expected_pubkey: "${node.expectedPubkey}"`,
      '    expected_network: regtest',
    );
  }
  const file = join(dir, 'fluxwarden.yaml');
  writeFileSync(file, `${lines.join('\n')}\n`, 'utf8');
  return file;
}

/** The SPEC.md §7.1 example policy with the given operator targets (node → channel key → targets). */
export function writePolicy(dir: string, targets: Record<string, Record<string, { minInbound?: string; minOutbound?: string }>>): string {
  const lines = [
    'version: 3', 'network: regtest', 'fees:', '  max_fee_msat: "300000"', '  max_fee_ppm: 2500', '  exempt_fee_msat: "5000"',
    'routing:', '  max_cltv_delta: 144', 'amounts:', '  min_channel_reserve_msat: "50000000"', '  max_principal_msat: "100000000"',
    '  min_principal_msat: "10000000"', 'budget:', '  msat: "2000000"', '  period: 24h', 'cooldown_after_failure: 1h',
    'cooldown_after_success: 30m', 'max_in_flight: 1', 'max_snapshot_age: 60s', 'proposal_ttl: 15m', 'approval_max_ttl: 15m',
    'demand:', '  mode: targets', '  horizon: 6h', '  burst_factor: "1.4"', '  ewma:', '    bucket_seconds: 3600', '    alpha: "0.35"',
    '    min_samples: 12', 'targets:',
  ];
  for (const [node, channels] of Object.entries(targets)) {
    lines.push(`  ${node}:`);
    for (const [key, target] of Object.entries(channels)) {
      lines.push(`    "${key}":`);
      if (target.minInbound !== undefined) lines.push(`      min_inbound_msat: "${target.minInbound}"`);
      if (target.minOutbound !== undefined) lines.push(`      min_outbound_msat: "${target.minOutbound}"`);
    }
  }
  const file = join(dir, 'policy.yaml');
  writeFileSync(file, `${lines.join('\n')}\n`, 'utf8');
  return file;
}

/** Creates and migrates the database through the persistence module, as a first run would. */
export async function createDatabase(path: string): Promise<void> {
  const module = await import(pathToFileURL(join(repoRoot, 'dist/persistence/index.js')).href) as {
    openDatabase: (path: string, options: { readOnly: boolean }) => { close(): void };
  };
  module.openDatabase(path, { readOnly: false }).close();
}

/** Snapshot rows stored for the node named `name`. */
export function snapshotCount(database: string, name: string): number {
  const db = new DatabaseSync(database, { readOnly: true });
  try {
    const row = db.prepare(`SELECT count(*) AS n FROM channel_snapshots s JOIN channels c ON c.id = s.channel_id
      JOIN nodes n ON n.id = c.node_id WHERE n.name = ?`).get(name);
    return Number(row?.['n'] ?? -1);
  } finally {
    db.close();
  }
}

export function nodeState(database: string, name: string): string | null {
  const db = new DatabaseSync(database, { readOnly: true });
  try {
    const row = db.prepare('SELECT state FROM nodes WHERE name = ?').get(name);
    return typeof row?.['state'] === 'string' ? row['state'] : null;
  } finally {
    db.close();
  }
}

// ---------------------------------------------------------------------------------------------
// Child process

export interface Run {
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  /** Date.now() when the process exited. */
  exitedAt: number;
}

export interface SpawnOptions {
  /** Existing protected working directory prepared by the scenario fixture. */
  cwd?: string;
  /** Environment overrides; undefined removes a variable. Applied after FLUXWARDEN_* and NODE_* are cleared. */
  env?: Record<string, string | undefined>;
  /** Node options placed before the binary (process.execArgv of the child). */
  nodeArgs?: readonly string[];
  /** Deliver signals inside the child (Windows has no catchable signal from outside). */
  signals?: boolean;
  timeoutMs?: number;
}

export interface Spawned {
  readonly child: ChildProcess;
  readonly done: Promise<Run>;
  /** Linux: a real signal. Windows: the same event raised inside the child over its IPC channel. */
  signal: (name: 'SIGINT' | 'SIGTERM') => void;
}

/** Signals raised inside the child from IPC messages; the channel is unref'd so it never keeps the child alive. */
const SIGNAL_PRELOAD = [
  "process.on('message', (m) => { if (m === 'SIGINT' || m === 'SIGTERM') process.emit(m, m); });",
  'process.channel?.unref();',
  '',
].join('\n');

export function cliEnv(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  const kept = Object.entries(childEnv()).filter(([key]) =>
    !/^(FLUXWARDEN_|NODE_OPTIONS$|NODE_DEBUG$)/i.test(key) || key.toUpperCase() === 'FLUXWARDEN_TEST_TMP');
  const merged = new Map<string, string | undefined>(kept);
  for (const [key, value] of Object.entries(overrides)) merged.set(key, value);
  return Object.fromEntries([...merged].filter((entry): entry is [string, string] => entry[1] !== undefined));
}

export function spawnCli(args: readonly string[], options: SpawnOptions = {}): Spawned {
  const nodeArgs = [...(options.nodeArgs ?? [])];
  const viaIpc = options.signals === true && process.platform === 'win32';
  if (viaIpc) {
    const file = join(scratch('preload'), 'signals.mjs');
    writeFileSync(file, SIGNAL_PRELOAD, 'utf8');
    nodeArgs.unshift('--import', pathToFileURL(file).href);
  }
  const child = spawn(process.execPath, [...nodeArgs, binPath(), ...args], {
    cwd: options.cwd ?? scratch('cwd'),
    env: cliEnv(options.env),
    stdio: viaIpc ? ['ignore', 'pipe', 'pipe', 'ipc'] : ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  const done = new Promise<Run>((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (chunk: Buffer) => { stdout += chunk.toString('utf8'); });
    child.stderr?.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8'); });
    const limit = options.timeoutMs ?? 20000;
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`fluxwarden ${args.slice(0, 2).join(' ')} did not exit within ${String(limit)} ms`));
    }, limit);
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', (status, signal) => { clearTimeout(timer); resolve({ status, signal, stdout, stderr, exitedAt: Date.now() }); });
  });
  const signal = (name: 'SIGINT' | 'SIGTERM'): void => {
    if (viaIpc) child.send(name);
    else child.kill(name);
  };
  return { child, done, signal };
}

export function runCli(args: readonly string[], options: SpawnOptions = {}): Promise<Run> {
  return spawnCli(args, options).done;
}

/** Parses stdout as exactly one JSON document followed by one newline. */
export function jsonDocument(run: Run): Record<string, unknown> {
  if (!run.stdout.endsWith('\n') || run.stdout.slice(0, -1).includes('\n')) throw new Error(`stdout is not one JSON document: ${JSON.stringify(run.stdout.slice(0, 400))}`);
  const value: unknown = JSON.parse(run.stdout);
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('stdout document is not an object');
  return value as Record<string, unknown>;
}

const ajv = new Ajv2020.default({ strict: true, allErrors: true });
const validators = new Map<string, ReturnType<typeof ajv.compile>>();

/** Validates a --json document against schemas/output/<name>.schema.json; returns the error list. */
export function schemaErrors(name: 'doctor' | 'nodes-list' | 'nodes-inspect' | 'channels', doc: unknown): string[] {
  let validate = validators.get(name);
  if (validate === undefined) {
    validate = ajv.compile(readJson(`schemas/output/${name}.schema.json`) as object);
    validators.set(name, validate);
  }
  return validate(doc) ? [] : (validate.errors ?? []).map(error => `${error.instancePath} ${error.message ?? ''}`);
}

// ---------------------------------------------------------------------------------------------
// Fake nodes

/** GetMissionControlConfigResponse, lnrpc/routerrpc/router.proto#L535-L540 at v0.21.4-beta. */
export const MISSION_CONTROL = { config: { half_life_seconds: '3600', hop_probability: 0.6, weight: 0.5, maximum_payment_results: 1000, minimum_failure_relax_interval: '60', model: 'APRIORI', apriori: null, bimodal: null } };

/** PendingChannelsResponse with nothing pending, lightning.proto#L2728-L2969. */
export const NO_PENDING = { total_limbo_balance: '0', pending_open_channels: [], pending_closing_channels: [], pending_force_closing_channels: [], waiting_close_channels: [] };

export interface LndSetup {
  info?: Record<string, unknown>;
  channels?: readonly Record<string, unknown>[];
  routes?: Partial<Record<string, LndRoute>>;
  identity?: Identity;
  /** The macaroon the fake accepts, as hex (default: a fresh random one, written to `macaroon`). */
  macaroonHex?: string;
}

export interface LndNode { fake: FakeLnd; macaroon: string; macaroonHex: string; url: string }

/** A fake LND that answers GetInfo, the router probe, ListChannels and PendingChannels. */
export async function lndNode(dir: string, open: FakeServer[], setup: LndSetup = {}): Promise<LndNode> {
  const bytes = Buffer.concat([Buffer.from('0201', 'hex'), randomBytes(58)]);
  const macaroon = join(dir, `${randomBytes(4).toString('hex')}.macaroon`);
  writeFileSync(macaroon, bytes);
  const macaroonHex = setup.macaroonHex ?? bytes.toString('hex');
  const fake = await startFakeLnd({
    macaroonHex,
    ...(setup.identity === undefined ? {} : { identity: setup.identity }),
    routes: {
      'GET /v1/getinfo': (ctx, f) => { f.answer(ctx, 'getinfo', setup.info ?? getInfo()); },
      'GET /v2/router/mccfg': (ctx, f) => { f.answer(ctx, 'router-mccfg', MISSION_CONTROL); },
      'GET /v1/channels': (ctx, f) => { f.answer(ctx, 'listchannels', { channels: setup.channels ?? [] }); },
      'GET /v1/channels/pending': (ctx, f) => { f.answer(ctx, 'pendingchannels', NO_PENDING); },
      'GET /v1/payments': (ctx, f) => { f.answer(ctx, 'listpayments', { payments: [], first_index_offset: '0', last_index_offset: '0', total_num_payments: '0' }); },
      ...setup.routes,
    },
  });
  open.push(fake);
  return { fake, macaroon, macaroonHex, url: `https://${fake.host}:${String(fake.port)}` };
}

export interface ClnSetup {
  info?: Record<string, unknown>;
  channels?: readonly Record<string, unknown>[];
  methods?: Partial<Record<string, ClnHandler>>;
  identity?: Identity;
  rune?: string;
}

export interface ClnNode { fake: FakeCln; runeFile: string; rune: string; url: string }

/** A fake CLN (clnrest) that answers getinfo, askrene-listlayers, listpeerchannels and the payment lists. */
export async function clnNode(dir: string, open: FakeServer[], setup: ClnSetup = {}): Promise<ClnNode> {
  const fresh = randomBytes(48).toString('base64url');
  const runeFile = join(dir, `${randomBytes(4).toString('hex')}.rune`);
  writeFileSync(runeFile, `${fresh}\n`);
  const fake = await startFakeCln({
    rune: setup.rune ?? fresh,
    ...(setup.identity === undefined ? {} : { identity: setup.identity }),
    methods: {
      getinfo: (ctx, f) => { f.result(ctx, 'getinfo', setup.info ?? getinfo()); },
      'askrene-listlayers': (ctx, f) => { f.result(ctx, 'askrene-listlayers', { layers: [] }); },
      listpeerchannels: (ctx, f) => { f.result(ctx, 'listpeerchannels', { channels: setup.channels ?? [] }); },
      listsendpays: (ctx, f) => { f.result(ctx, 'listsendpays', { payments: [] }); },
      listpays: (ctx, f) => { f.result(ctx, 'listpays', { pays: [] }); },
      ...setup.methods,
    },
  });
  open.push(fake);
  return { fake, runeFile, rune: setup.rune ?? fresh, url: `https://${fake.host}:${String(fake.port)}` };
}

export const nodeCert = (): string => certificatePath('node');
