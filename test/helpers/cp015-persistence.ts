// Shared loaders and fixtures for the persistence tests. Product code is reached through its public module only.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { pathToFileURL } from 'node:url';
import { repoRoot } from './cli.js';
import { assertStrictWindowsOwnerOnly, readWindowsSecurity } from './windows-security.js';

export type PersistenceCode = 'SCHEMA_TOO_NEW' | 'SCHEMA_OUTDATED' | 'NOT_FOUND' | 'UNSAFE_PATH' | 'BUSY' | 'OUT_OF_RANGE' | 'READ_ONLY';

export interface SnapshotInput {
  readonly nodeId: string; readonly channelKey: string; readonly scid: string | null; readonly peerPubkey: string;
  readonly fundingOutpoint: string; readonly state: 'ACTIVE' | 'INACTIVE' | 'PENDING' | 'CLOSING' | 'UNKNOWN'; readonly nodeState: string;
  readonly opener: 'local' | 'remote'; readonly capacityMsat: bigint; readonly localBalanceMsat: bigint; readonly remoteBalanceMsat: bigint;
  readonly spendableMsat: bigint; readonly receivableMsat: bigint; readonly confidence: 'NODE_REPORTED' | 'DERIVED_ESTIMATE';
  readonly caveat: string | null; readonly localReserveMsat: bigint; readonly remoteReserveMsat: bigint;
  readonly pendingOutMsat: bigint; readonly pendingInMsat: bigint; readonly pendingHtlcCount: number;
  readonly localMaxPendingAmtMsat: bigint | null; readonly remoteMaxPendingAmtMsat: bigint | null;
  readonly observedAt: number; readonly blockHeight: number; readonly provenance: Readonly<Record<string, string>>;
}

export interface SnapshotRow {
  readonly channelId: string; readonly observedAt: number; readonly blockHeight: number;
  readonly localMsat: bigint; readonly remoteMsat: bigint; readonly spendableMsat: bigint; readonly receivableMsat: bigint;
  readonly pendingOutMsat: bigint; readonly pendingInMsat: bigint; readonly pendingHtlcCount: number;
  readonly confidence: 'NODE_REPORTED' | 'DERIVED_ESTIMATE'; readonly provenance: Readonly<Record<string, string>>;
}

export interface Database {
  close(): void;
  pragmas(): { journalMode: string; synchronous: number };
  nodes: { insert(node: { id: string; name: string; implementation: 'lnd' | 'cln'; expectedNetwork: 'regtest'; expectedPubkey: string }): void };
  channels: { upsert(channel: SnapshotInput): string };
  snapshots: {
    record(channelId: string, channel: SnapshotInput): void;
    latest(channelId: string): SnapshotRow | null;
    ageMs(channelId: string): number | null;
  };
}

export interface Persistence {
  openDatabase(path: string, options: { readOnly: boolean; busyTimeoutMs?: number }): Database;
  PersistenceError: new (...args: never[]) => Error & { code: PersistenceCode };
}

export async function loadPersistence(): Promise<Persistence> {
  return await import(pathToFileURL(join(repoRoot, 'src/persistence/index.ts')).href) as Persistence;
}

export function scratch(prefix: string): string {
  return mkdtempSync(join(process.env['FLUXWARDEN_TEST_TMP'] ?? tmpdir(), `fw-cp015-${prefix}-`));
}

export function fileHash(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

export function raw(path: string): DatabaseSync {
  return new DatabaseSync(path, { readBigInts: true });
}

export function count(path: string, table: string): bigint {
  const db = raw(path);
  try {
    const row = db.prepare(`SELECT count(*) AS n FROM ${table}`).get() as { n: bigint };
    return row.n;
  } finally { db.close(); }
}

export function codeOf(run: () => unknown): string | undefined {
  try { run(); } catch (error) {
    const code = (error as { code?: unknown }).code;
    return typeof code === 'string' ? code : `not-coded:${error instanceof Error ? error.name : String(error)}`;
  }
  return undefined;
}

export const NODE_ID = '01JZ8Q5W3K6Y2N4R7T9V1X3Z5B';
export const PUBKEY = `03${'cd'.repeat(32)}`;

export function channel(over: Partial<SnapshotInput> = {}): SnapshotInput {
  return {
    nodeId: NODE_ID, channelKey: '123145302376448', scid: '112x1x0', peerPubkey: `02${'ab'.repeat(32)}`,
    fundingOutpoint: `${'c3'.repeat(32)}:0`, state: 'ACTIVE', nodeState: 'active', opener: 'local',
    capacityMsat: 1_000_000_000n, localBalanceMsat: 600_000_000n, remoteBalanceMsat: 396_530_000n,
    spendableMsat: 582_858_000n, receivableMsat: 386_530_000n, confidence: 'DERIVED_ESTIMATE', caveat: null,
    localReserveMsat: 10_000_000n, remoteReserveMsat: 10_000_000n, pendingOutMsat: 50_000_000n, pendingInMsat: 20_000_000n,
    pendingHtlcCount: 2, localMaxPendingAmtMsat: 18_446_744_073_709_551_615n, remoteMaxPendingAmtMsat: 990_000_000n,
    observedAt: 1_000, blockHeight: 1_234,
    provenance: { local_balance: '600000', 'local_constraints.max_pending_amt_msat': '18446744073709551615' },
    ...over,
  };
}

/** A fresh database with one node and one channel; returns the channel row id. */
export function seeded(p: Persistence, path: string): string {
  const db = p.openDatabase(path, { readOnly: false });
  try {
    db.nodes.insert({ id: NODE_ID, name: 'lnd-r', implementation: 'lnd', expectedNetwork: 'regtest', expectedPubkey: PUBKEY });
    return db.channels.upsert(channel());
  } finally { db.close(); }
}

export const sideFiles = (path: string): string[] => [path, `${path}-wal`, `${path}-shm`].filter(existsSync);

function windowsTool(tool: readonly string[], args: readonly string[]): string {
  const run = spawnSync(join(process.env['SystemRoot'] ?? 'C:/Windows', 'System32', ...tool), args, { encoding: 'utf8', windowsHide: true, shell: false });
  if (run.status !== 0) throw new Error(`${tool.join('/')} failed: ${run.stderr}`);
  return run.stdout.trim();
}

/**
 * Owner-only as SECURITY.md §5 states it. POSIX: no group or other permission bits (directory 0700, files 0600).
 * Windows: read from the effective security descriptor (SDDL): owned by the current user, every allow entry names
 * only the current user SID; for the state directory and the database file the DACL is also protected and no entry
 * is inherited. SQLite creates -wal and -shm itself, so those may inherit, but only owner-only entries.
 */
export function expectOwnerOnly(path: string, kind: 'directory' | 'file' | 'side'): void {
  if (process.platform !== 'win32') {
    if (statSync(path).mode & 0o077) throw new Error(`${path} grants group or other access: ${(statSync(path).mode & 0o777).toString(8)}`);
    return;
  }
  const security = readWindowsSecurity(path);
  const { userSid: user, sddl } = security;
  if (kind !== 'side') assertStrictWindowsOwnerOnly(security, kind);
  const dacl = /D:([A-Z]*)((?:\([^)]*\))*)/.exec(sddl);
  if (!dacl) throw new Error(`no DACL in ${sddl}`);
  const aces = [...(dacl[2] ?? '').matchAll(/\(([^;]*);([^;]*);([^;]*);[^;]*;[^;]*;([^)]*)\)/g)];
  const allows = aces.filter(ace => ace[1] === 'A');
  const problems: string[] = [];
  if (security.ownerSid !== user) problems.push('owner is not the current user');
  if (kind !== 'side' && !(dacl[1] ?? '').includes('P')) problems.push('DACL is not protected from inheritance');
  if (allows.length === 0) problems.push('no allow entry');
  if (allows.length !== aces.length) problems.push('entry is not an ordinary allow ACE');
  if (kind === 'file' && allows.length !== 1) problems.push(`expected exactly one allow entry, found ${String(allows.length)}`);
  for (const ace of allows) {
    if (kind !== 'side' && (ace[2] ?? '').includes('ID')) problems.push(`inherited entry ${ace[0]}`);
    if (ace[4] !== user) problems.push(`entry for another principal ${ace[0]}`);
  }
  if (problems.length > 0) throw new Error(`${path} is not owner-only (${problems.join('; ')}): ${sddl}`);
}

/** Names in a directory, sorted, for "created nothing" checks. */
export function listing(dir: string): string[] {
  return readdirSync(dir).sort();
}

/**
 * Grants another principal access: on Windows an allow entry for Everyone (S-1-1-0), inheritable on a directory;
 * on POSIX group access (file 0640, directory 0770).
 */
export function grantOthers(path: string, kind: 'directory' | 'file', sid = 'S-1-1-0'): void {
  if (process.platform !== 'win32') {
    chmodSync(path, kind === 'directory' ? 0o770 : 0o640);
    return;
  }
  windowsTool(['icacls.exe'], [path, '/grant', kind === 'directory' ? `*${sid}:(OI)(CI)(R)` : `*${sid}:(R)`]);
}

/** Grants foreign users mutation authority over a test-created directory and its children. */
export function grantDirectoryMutation(path: string): void {
  if (process.platform !== 'win32') {
    chmodSync(path, 0o770);
    return;
  }
  windowsTool(['icacls.exe'], [path, '/grant', '*S-1-1-0:(OI)(CI)(M)']);
}

/** Makes a test-created directory owner-only: POSIX 0700; Windows a protected DACL with one inheritable entry for the current user. */
export function makeOwnerOnlyDir(path: string): void {
  if (process.platform !== 'win32') {
    chmodSync(path, 0o700);
    return;
  }
  const user = /"([^"]*)"$/.exec(windowsTool(['whoami.exe'], ['/user', '/fo', 'csv', '/nh']))?.[1];
  if (user === undefined) throw new Error('current user SID not found');
  windowsTool(['icacls.exe'], [path, '/inheritance:r', '/grant:r', `*${user}:(OI)(CI)F`]);
}

/** The effective access description of a path: the SDDL on Windows, mode and owner on POSIX. */
export function descriptor(path: string): string {
  if (process.platform !== 'win32') {
    const stat = statSync(path);
    return `${(stat.mode & 0o7777).toString(8)}:${String(stat.uid)}:${String(stat.gid)}`;
  }
  return windowsTool(['WindowsPowerShell', 'v1.0', 'powershell.exe'], ['-NoProfile', '-NonInteractive', '-Command', '& { (Get-Acl -LiteralPath $args[0]).Sddl }', path]);
}
