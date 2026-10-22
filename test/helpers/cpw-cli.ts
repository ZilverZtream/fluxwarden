// Helpers for the money-path commands through the built CLI: configuration and policy writers with approval keys,
// operator keys from `keys generate`, the CLN-M demo setup on the stateful fake, --json schema validation for
// every command and database readers. Product code is reached only through the binary.
import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { constants, copyFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import Ajv2020 from 'ajv/dist/2020.js';
import { binPath, readJson } from './cli.js';
import { declareFixturePaths } from './capture-fixture.js';
import { createDatabase, jsonDocument, runCli, scratch, yamlPath, type Run, type SpawnOptions } from './cp016-cli.js';
import { makeOwnerOnlyDir } from './cp015-persistence.js';
import { certificatePath, type FakeServer, type TlsMaterial } from '../fakes/https.js';
import { S, SELF, startRebalanceCln, T, type RebalanceCln, type RebalanceState } from '../fakes/cln/rebalance-node.js';

export { jsonDocument, runCli, scratch, type Run };

export const SUCCESS = 0;
export const POLICY_VIOLATION = 1;
export const INVALID_INPUT = 2;
export const SAFETY_REFUSAL = 5;
export const OUTCOME_UNKNOWN = 7;
export const INVARIANT_BREACH = 8;
export const RECONCILIATION_ALERT = 9;

export type Doc = Record<string, unknown>;
export const rec = (value: unknown): Doc => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error(`not an object: ${JSON.stringify(value)}`);
  return value as Doc;
};
export const list = (value: unknown): unknown[] => {
  if (!Array.isArray(value)) throw new Error(`not an array: ${JSON.stringify(value)}`);
  return value;
};

// ---------------------------------------------------------------------------------------------
// --json documents

export type SchemaName =
  | 'liquidity-diagnose' | 'liquidity-plan' | 'liquidity-explain' | 'liquidity-approve' | 'actions-execute' | 'actions-status'
  | 'ledger-verify' | 'reconcile' | 'evidence-export';

const ajv = new Ajv2020.default({ strict: true, allErrors: true });
const validators = new Map<string, ReturnType<typeof ajv.compile>>();

/** Validates a --json document against schemas/output/<name>.json; returns the error list. */
export function schemaErrors(name: SchemaName, doc: unknown): string[] {
  let validate = validators.get(name);
  if (validate === undefined) {
    validate = ajv.compile(readJson(`schemas/output/${name}.json`) as object);
    validators.set(name, validate);
  }
  return validate(doc) ? [] : (validate.errors ?? []).map(error => `${error.instancePath} ${error.message ?? ''}`);
}

/** The one stdout document of a --json run, validated against its schema; throws with the error list otherwise. */
export function documentOf(run: Run, name: SchemaName): Doc {
  const doc = jsonDocument(run);
  const errors = schemaErrors(name, doc);
  if (errors.length > 0) throw new Error(`${name} document does not match its schema: ${errors.join('; ')}\n${run.stdout.slice(0, 800)}`);
  return doc;
}

export const resultOf = (doc: Doc): Doc => rec(doc['result']);
export const errorOf = (doc: Doc): Doc => rec(doc['error']);

// ---------------------------------------------------------------------------------------------
// Configuration and policy

export interface ApprovalKeyEntry { readonly keyId: string; readonly publicKey: string }

export interface FullConfig {
  readonly database: string;
  readonly policy: string;
  readonly node: { readonly name: string; readonly url: string; readonly runeFile: string; readonly expectedPubkey: string; readonly tlsCert?: string };
  readonly approvalKeys: readonly ApprovalKeyEntry[];
  readonly collectInterval?: string;
  readonly attemptDeadline?: string;
  readonly alertDir?: string;
}

/** fluxwarden.yaml in the SPEC §10.1 subset: one CLN node, approval_keys as `keys generate` prints them. */
export function writeFullConfig(dir: string, input: FullConfig, file = 'fluxwarden.yaml'): string {
  const lines = [`database: "${yamlPath(input.database)}"`, `policy: "${yamlPath(input.policy)}"`];
  if (input.collectInterval !== undefined) lines.push(`collect_interval: ${input.collectInterval}`);
  if (input.attemptDeadline !== undefined) lines.push(`attempt_deadline: ${input.attemptDeadline}`);
  if (input.alertDir !== undefined) lines.push(`alert_dir: "${yamlPath(input.alertDir)}"`);
  lines.push(
    'nodes:',
    `  - name: ${input.node.name}`,
    '    implementation: cln',
    `    url: "${input.node.url}"`,
    `    tls_cert_path: "${yamlPath(input.node.tlsCert ?? certificatePath('node'))}"`,
    `    rune_path: "${yamlPath(input.node.runeFile)}"`,
    `    expected_pubkey: "${input.node.expectedPubkey}"`,
    '    expected_network: regtest',
  );
  if (input.approvalKeys.length > 0) {
    lines.push('approval_keys:');
    for (const key of input.approvalKeys) lines.push(`  - key_id: "${key.keyId}"`, `    public_key: "${key.publicKey}"`);
  }
  const path = join(dir, file);
  writeFileSync(path, `${lines.join('\n')}\n`, 'utf8');
  return path;
}

export interface PolicyOptions {
  readonly network?: string;
  readonly maxSnapshotAge?: string;
  readonly proposalTtl?: string;
  readonly approvalMaxTtl?: string;
  /** Node name -> channel key -> min_inbound_msat. Default: the CLN-M targets below. */
  readonly targets?: Record<string, Record<string, string>>;
}

/**
 * The SPEC §7.1 example policy. Default targets for cln-m: S needs 400,000,000 msat inbound (it has 100,000,000:
 * deficit 300,000,000), T needs 50,000,000 (it has 2,000,000,000: 1,950,000,000 to spare).
 */
export const DEMO_TARGETS = { 'cln-m': { [S]: '400000000', [T]: '50000000' } };

export function writeDemoPolicy(dir: string, options: PolicyOptions = {}, file = 'policy.yaml'): string {
  const lines = [
    'version: 3', `network: ${options.network ?? 'regtest'}`, 'fees:', '  max_fee_msat: "300000"', '  max_fee_ppm: 2500', '  exempt_fee_msat: "5000"',
    'routing:', '  max_cltv_delta: 144', 'amounts:', '  min_channel_reserve_msat: "50000000"', '  max_principal_msat: "100000000"',
    '  min_principal_msat: "10000000"', 'budget:', '  msat: "2000000"', '  period: 24h', 'cooldown_after_failure: 1h',
    'cooldown_after_success: 30m', 'max_in_flight: 1', `max_snapshot_age: ${options.maxSnapshotAge ?? '60s'}`,
    `proposal_ttl: ${options.proposalTtl ?? '15m'}`, `approval_max_ttl: ${options.approvalMaxTtl ?? '15m'}`,
    'demand:', '  mode: targets', '  horizon: 6h', '  burst_factor: "1.4"', '  ewma:', '    bucket_seconds: 3600', '    alpha: "0.35"',
    '    min_samples: 12', 'targets:',
  ];
  for (const [node, channels] of Object.entries(options.targets ?? DEMO_TARGETS)) {
    lines.push(`  ${node}:`);
    for (const [key, inbound] of Object.entries(channels)) lines.push(`    "${key}":`, `      min_inbound_msat: "${inbound}"`);
  }
  const path = join(dir, file);
  writeFileSync(path, `${lines.join('\n')}\n`, 'utf8');
  return path;
}

// ---------------------------------------------------------------------------------------------
// Operator keys

export interface OperatorKey { readonly keyFile: string; readonly keyId: string; readonly publicKey: string }

/** A key pair from `fluxwarden keys generate --out <file> --json` (SPEC §10.3 command 13). */
export async function generateKey(dir: string, name = 'operator.key'): Promise<OperatorKey> {
  const keyDir = join(dir, 'keys');
  if (!existsSync(keyDir)) mkdirSync(keyDir);
  const keyFile = join(keyDir, name);
  if (process.env['FLUXWARDEN_CI_CAPTURE']) {
    const { authorizeSecretOutput } = await import(new URL('../../scripts/ci-secret-output.mjs', import.meta.url).href) as {
      authorizeSecretOutput: (intent: { path: string; command: string; args: readonly string[] }) => Promise<void>;
    };
    await authorizeSecretOutput({ path: keyFile, command: process.execPath,
      args: [binPath(), '--json', 'keys', 'generate', '--out', keyFile] });
  }
  const run = await runCli(['--json', 'keys', 'generate', '--out', keyFile]);
  if (run.status !== 0) throw new Error(`keys generate failed (${String(run.status)}): ${run.stdout}${run.stderr}`);
  const result = rec(jsonDocument(run)['result']);
  return { keyFile, keyId: String(result['key_id']), publicKey: String(result['public_key']) };
}

// ---------------------------------------------------------------------------------------------
// The CLN-M demo

export interface Demo {
  readonly dir: string;
  readonly cln: RebalanceCln;
  readonly database: string;
  readonly policy: string;
  readonly key: OperatorKey;
  readonly config: string;
  /** Rewrites the configuration (same path) with changes. */
  rewrite(changes: Partial<FullConfig>): string;
  run(args: readonly string[], options?: SpawnOptions): Promise<Run>;
}

export interface DemoOptions extends PolicyOptions {
  readonly tls?: TlsMaterial;
  readonly fake?: Partial<Pick<RebalanceState, 'network' | 'id' | 'sendpay' | 'bkprFeeMsat'>>;
  readonly withKey?: boolean;
  readonly collectInterval?: string;
  readonly fixtures?: DemoFixtures;
}

/** Closed, empty database and CLI-generated key material; only copies are given to individual cases. */
export interface DemoFixtures { readonly database: string; readonly key: OperatorKey }

/** One public-API seed per test file; no proposal, approval, execution or node state is shared. */
export async function prepareDemoFixtures(): Promise<DemoFixtures> {
  const dir = scratch('cpw-fixtures');
  const database = join(dir, 'state', 'empty.db');
  await createDatabase(database);
  const key = await generateKey(dir);
  return Object.freeze({ database, key: Object.freeze(key) });
}

function copyDemoFixture(source: string, destination: string): void {
  copyFileSync(source, destination, constants.COPYFILE_EXCL);
  if (process.platform !== 'win32') return;
  // The parent already grants only the owner access. Keep that entry explicitly and protect the copy's DACL.
  const run = spawnSync(join(process.env['SystemRoot'] ?? 'C:/Windows', 'System32', 'icacls.exe'),
    [destination, '/inheritance:d'], { encoding: 'utf8', windowsHide: true, shell: false });
  if (run.error !== undefined) throw run.error;
  if (run.status !== 0) throw new Error(`protecting demo fixture failed: ${run.stderr}`);
}

export async function demo(open: FakeServer[], options: DemoOptions = {}): Promise<Demo> {
  const dir = scratch('cpw');
  if (options.fixtures !== undefined) makeOwnerOnlyDir(dir);
  const cln = await startRebalanceCln(dir, open, { ...options.fake, ...(options.tls === undefined ? {} : { tls: options.tls }) });
  const database = join(dir, 'state', 'fluxwarden.db');
  if (options.fixtures === undefined) await createDatabase(database);
  else {
    mkdirSync(join(dir, 'state'), { mode: 0o700 });
    makeOwnerOnlyDir(join(dir, 'state'));
    copyDemoFixture(options.fixtures.database, database);
  }
  const policy = writeDemoPolicy(dir, options);
  // Without a key (withKey false) the configuration has no approval_keys and `key` names a file that does not exist.
  let key: OperatorKey;
  if (options.withKey === false) key = { keyFile: join(dir, 'keys', 'absent.key'), keyId: '', publicKey: '' };
  else if (options.fixtures === undefined) key = await generateKey(dir);
  else {
    mkdirSync(join(dir, 'keys'), { mode: 0o700 });
    const keyFile = join(dir, 'keys', 'operator.key');
    declareFixturePaths([keyFile]);
    copyDemoFixture(options.fixtures.key.keyFile, keyFile);
    key = { ...options.fixtures.key, keyFile };
  }
  const base: FullConfig = {
    database, policy, node: { name: 'cln-m', url: cln.url, runeFile: cln.runeFile, expectedPubkey: SELF,
      ...(options.tls === undefined ? {} : { tlsCert: options.tls.certPath }) },
    approvalKeys: options.withKey === false ? [] : [key], alertDir: join(dir, 'alerts'),
    ...(options.collectInterval === undefined ? {} : { collectInterval: options.collectInterval }),
  };
  mkdirSync(join(dir, 'alerts'), { mode: 0o700 });
  let current = base;
  const config = writeFullConfig(dir, base);
  return {
    dir, cln, database, policy, key, config,
    rewrite: changes => { current = { ...current, ...changes }; return writeFullConfig(dir, current); },
    run: (args, runOptions) => runCli([...args, '--config', config], runOptions),
  };
}

/** `liquidity plan --refresh --json` on the demo; returns the proposal document's result. */
export async function plan(d: Demo): Promise<Doc> {
  const run = await d.run(['--json', 'liquidity', 'plan', '--refresh']);
  if (run.status !== SUCCESS) throw new Error(`liquidity plan exited ${String(run.status)}: ${run.stdout}${run.stderr}`);
  return resultOf(documentOf(run, 'liquidity-plan'));
}

/** `liquidity approve <id> --key <file> --max-fee-msat 300000 --max-cltv-delta 144 --json` (SPEC §14.1). */
export async function approve(d: Demo, proposalId: string, key: OperatorKey = d.key): Promise<Doc> {
  const run = await d.run(['--json', 'liquidity', 'approve', proposalId, '--key', key.keyFile, '--max-fee-msat', '300000', '--max-cltv-delta', '144']);
  if (run.status !== SUCCESS) throw new Error(`liquidity approve exited ${String(run.status)}: ${run.stdout}${run.stderr}`);
  return resultOf(documentOf(run, 'liquidity-approve'));
}

// ---------------------------------------------------------------------------------------------
// Database readers (SPEC §6.2 names)

export function rows(database: string, sql: string, ...params: (string | number)[]): Record<string, unknown>[] {
  const db = new DatabaseSync(database, { readOnly: true });
  try {
    return db.prepare(sql).all(...params);
  } finally {
    db.close();
  }
}

export function count(database: string, table: string): number {
  return Number(rows(database, `SELECT count(*) AS n FROM ${table}`)[0]?.['n'] ?? -1);
}

/** Runs statements on the database file as someone with write access to it would (the tamper cases). */
export function tamper(database: string, ...statements: string[]): void {
  const db = new DatabaseSync(database);
  try {
    for (const statement of statements) db.exec(statement);
  } finally {
    db.close();
  }
}

/** The stored proposal id behind `prop_<ULID>`. */
export const storedId = (proposalId: string): string => proposalId.replace(/^prop_/, '');

// ---------------------------------------------------------------------------------------------
// Approval message (SECURITY.md §4.1), built independently of the product.

const u64 = (value: bigint): Buffer => { const b = Buffer.alloc(8); b.writeBigUInt64BE(value); return b; };
const u32 = (value: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32BE(value); return b; };

/** Bytes of a stored hex or base64 field of the given length; null when it is neither. */
export function bytesOf(text: string, length: number): Buffer | null {
  if (new RegExp(`^[0-9a-f]{${String(length * 2)}}$`).test(text)) return Buffer.from(text, 'hex');
  const decoded = Buffer.from(text, 'base64');
  return decoded.length === length && decoded.toString('base64') === text ? decoded : null;
}

export function approvalMessage(fields: { digest: string; policySha256: string; maxFeeMsat: bigint; maxCltvDelta: number; expiresAt: bigint; nonce: Buffer; keyId: string }): Buffer {
  return Buffer.concat([
    Buffer.from('FluxWarden-approval-v1', 'utf8'), Buffer.from([0]),
    Buffer.from(fields.digest, 'hex'), Buffer.from(fields.policySha256, 'hex'),
    u64(fields.maxFeeMsat), u32(fields.maxCltvDelta), u64(fields.expiresAt), fields.nonce, Buffer.from(fields.keyId, 'hex'),
  ]);
}

/** Ed25519 verification against the raw 32-byte public key `keys generate` printed (base64). */
export function verifiesWith(publicKeyBase64: string, message: Buffer, signature: Buffer): boolean {
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(publicKeyBase64, 'base64').toString('base64url') }, format: 'jwk' });
  return verifySignature(null, message, key, signature);
}

export const sha256Hex = (bytes: Buffer | string): string => createHash('sha256').update(bytes).digest('hex');

/** Waits until `check` holds, polling every 100 ms, or throws after `ms`. */
export async function until(check: () => boolean, ms: number, what: string): Promise<void> {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise(resolve => setTimeout(resolve, 100));
  }
}

export const pause = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms));
