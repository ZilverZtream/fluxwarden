/*
Interface: src/persistence/index.ts (the only module that imports node:sqlite).

  export type PersistenceCode = 'SCHEMA_TOO_NEW' | 'SCHEMA_OUTDATED' | 'NOT_FOUND' | 'UNSAFE_PATH' | 'BUSY' | 'OUT_OF_RANGE' | 'READ_ONLY';
  export class PersistenceError extends Error { readonly code: PersistenceCode }
  export function openDatabase(path: string, options: { readOnly: boolean; busyTimeoutMs?: number }): Database;

  interface Database {
    close(): void;
    pragmas(): { journalMode: string; synchronous: number };   // read from the live connection (PRAGMA journal_mode / synchronous)
    nodes: { insert(node: { id; name; implementation: 'lnd' | 'cln'; expectedNetwork: 'regtest'; expectedPubkey }): void };
    channels: { upsert(channel: NormalizedChannel): string };   // returns channels.id; the row is found by (nodeId, channelKey),
                                                                // else by (nodeId, fundingOutpoint) when that is non-empty, and
                                                                // then updated (key, scid, state, capacity) in place
    snapshots: {
      record(channelId: string, channel: NormalizedChannel): void; // observed_at = database clock, block_height = channel.blockHeight
      latest(channelId: string): SnapshotRow | null;               // the most recently recorded snapshot
      ageMs(channelId: string): number | null;                     // db_now − newest observed_at, computed in SQL;
                                                                   // Number.POSITIVE_INFINITY when observed_at > db_now
    };
  }
  interface SnapshotRow { channelId; observedAt: number; blockHeight: number; localMsat: bigint; remoteMsat: bigint;
    spendableMsat: bigint; receivableMsat: bigint; pendingOutMsat: bigint; pendingInMsat: bigint; pendingHtlcCount: number;
    confidence; provenance: Record<string, string> }

Rules under test (SPEC §4.3 and §6, ARCHITECTURE §7, SECURITY §5):
  - Read-write open creates the state directory (0700) and database (0600), sets WAL and synchronous=FULL, and runs
    forward-only migrations; the schema version is PRAGMA user_version. A newer version than the code is refused.
    On Windows "owner-only" is the effective DACL: protected, owned by and granting only the current user, nothing
    inherited (SQLite's own -wal/-shm may inherit, but only from such a directory); the database file carries exactly
    one such entry of its own. An existing state directory is checked, never rewritten: its DACL or mode and its other
    files stay exactly as they were, and one that grants anyone else access is refused (UNSAFE_PATH), as is an
    existing database, -wal or -shm that does.
    Ancestors granting foreign mutation authority are refused before database or staging creation, without changing
    their permissions. Read-only ancestor access is permitted on Windows; POSIX sticky ancestors protect owned children.
  - Read-only open never creates (not even -wal or -shm), never migrates and never writes; an older schema is refused
    with SCHEMA_OUTDATED. A refused open leaves no file behind.
  - msat columns are signed 64-bit INTEGER read as bigint; a value outside 0 … 2^63 − 1 is refused with OUT_OF_RANGE
    before any SQL runs.
  - Timestamps are unix milliseconds from the database clock (SPEC §6.2). channel_snapshots carries observed_at and
    block_height (an integer in 0 … 2^32 − 1, else OUT_OF_RANGE) and is append-only: UPDATE, DELETE and every
    REPLACE / UPSERT path abort on any connection, as they do for approvals, ledger_journals and ledger_lines.
  - Symbolic links and junctions at the database path or its parents are refused with UNSAFE_PATH (a root-owned
    link above the state directory is tolerated on POSIX only), as is a database file with more than one hard link.
  - A write that fails inside its transaction is rolled back; the connection stays usable.
  - A read-only handle never returns data older than the last commit: it reads the new state or fails with BUSY.
  - One channel keeps one row for its whole life: pending (keyed by outpoint, or per peer while uncommitted), open
    (alias or real scid), closing; a later uncommitted open with the same peer is a new row.
*/
import { chmodSync, existsSync, linkSync, lstatSync, mkdirSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { unlinkFixture } from '../helpers/fixture-links.js';
import { repoRoot } from '../helpers/cli.js';
import {
  channel, codeOf, count, descriptor, expectOwnerOnly, fileHash, grantDirectoryMutation, grantOthers, listing, loadPersistence, makeOwnerOnlyDir, NODE_ID, PUBKEY, raw,
  scratch, seeded, sideFiles, type SnapshotInput,
} from '../helpers/cp015-persistence.js';

// SPEC §6.2 schema v1.
const SPEC_TABLES = [
  'nodes', 'channels', 'channel_snapshots', 'policy_versions', 'liquidity_proposals', 'approvals', 'executions',
  'execution_events', 'budget_reservations', 'ledger_journals', 'ledger_lines', 'account_balances',
];
const posix = process.platform !== 'win32';

function userVersion(path: string): number {
  const db = raw(path);
  try { return Number((db.prepare('PRAGMA user_version').get() as { user_version: bigint }).user_version); } finally { db.close(); }
}
function setUserVersion(path: string, version: number): void {
  const db = raw(path);
  try { db.exec(`PRAGMA user_version = ${String(version)}`); } finally { db.close(); }
}

afterEach(() => { vi.useRealTimers(); });

describe('creation and migrations', () => {
  it('CP-015/B1 a fresh database is created owner-only with WAL, synchronous=FULL and the v1 tables', async () => {
    const p = await loadPersistence();
    const dir = join(scratch('fresh'), 'state');
    const path = join(dir, 'fluxwarden.db');
    const db = p.openDatabase(path, { readOnly: false });
    try {
      expect(db.pragmas()).toEqual({ journalMode: 'wal', synchronous: 2 }); // FULL = 2 (sqlite.org/pragma.html#pragma_synchronous)
      db.nodes.insert({ id: NODE_ID, name: 'lnd-r', implementation: 'lnd', expectedNetwork: 'regtest', expectedPubkey: PUBKEY });
      // SECURITY §5: state directory 0700 and database 0600 on POSIX; on Windows a protected DACL granting only the
      // current user, read from the effective security descriptor.
      expectOwnerOnly(dir, 'directory');
      expectOwnerOnly(path, 'file');
      for (const side of sideFiles(path).filter(file => file !== path)) expectOwnerOnly(side, 'side');
      const check = raw(path);
      try {
        expect((check.prepare('PRAGMA journal_mode').get() as { journal_mode: string }).journal_mode).toBe('wal');
        const tables = (check.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as { name: string }[]).map(row => row.name);
        for (const table of SPEC_TABLES) expect(tables, table).toContain(table);
      } finally { check.close(); }
    } finally { db.close(); }
    expect(userVersion(path)).toBeGreaterThan(0);
    expect(count(path, 'nodes')).toBe(1n);
  });

  it('CP-015/B1 synchronous=FULL is set explicitly, not left to the SQLite build default', () => {
    // SQLITE_DEFAULT_WAL_SYNCHRONOUS can make a build default to NORMAL in WAL mode (sqlite.org/compile.html), so a
    // connection that happens to report FULL proves nothing about another engine floor; the setting must be in the code.
    const sources = readdirSync(join(repoRoot, 'src', 'persistence'), { recursive: true, encoding: 'utf8' })
      .filter(name => name.endsWith('.ts'))
      .map(name => readFileSync(join(repoRoot, 'src', 'persistence', name), 'utf8'));
    expect(sources.length).toBeGreaterThan(0);
    expect(sources.some(text => /PRAGMA\s+synchronous\s*=\s*(?:FULL|2)\b/i.test(text))).toBe(true);
  });

  it('CP-015/B1 a database whose schema version is newer than the code is refused untouched, in both modes', async () => {
    const p = await loadPersistence();
    const path = join(scratch('newer'), 'fluxwarden.db');
    seeded(p, path);
    const current = userVersion(path);
    setUserVersion(path, current + 1);
    const before = fileHash(path);
    expect(codeOf(() => { p.openDatabase(path, { readOnly: false }).close(); })).toBe('SCHEMA_TOO_NEW');
    expect(codeOf(() => { p.openDatabase(path, { readOnly: true }).close(); })).toBe('SCHEMA_TOO_NEW');
    expect(fileHash(path)).toBe(before);
    expect(userVersion(path)).toBe(current + 1);
  });

  it('CP-015/B1 an existing empty database at version 0 is migrated forward to the current version', async () => {
    const p = await loadPersistence();
    const reference = join(scratch('reference'), 'fluxwarden.db');
    p.openDatabase(reference, { readOnly: false }).close();
    const target = userVersion(reference);
    const path = join(scratch('older'), 'fluxwarden.db');
    const empty = raw(path);
    empty.exec('PRAGMA user_version = 0');
    empty.close();
    if (posix) chmodSync(path, 0o600);
    p.openDatabase(path, { readOnly: false }).close();
    expect(userVersion(path)).toBe(target);
    for (const table of SPEC_TABLES) expect(count(path, table), table).toBe(0n);
  });
});

describe('read-only opening', () => {
  it('CP-015/B2 read-only open of a missing database creates neither the file nor its directory', async () => {
    const p = await loadPersistence();
    const dir = join(scratch('missing'), 'state');
    const path = join(dir, 'fluxwarden.db');
    expect(codeOf(() => { p.openDatabase(path, { readOnly: true }).close(); })).toBe('NOT_FOUND');
    expect(existsSync(path)).toBe(false);
    expect(existsSync(dir)).toBe(false);
  });

  it('CP-015/B2 read-only open never migrates an older schema', async () => {
    const p = await loadPersistence();
    const path = join(scratch('ro-old'), 'fluxwarden.db');
    seeded(p, path);
    const older = userVersion(path) - 1;
    setUserVersion(path, older);
    const before = fileHash(path);
    expect(codeOf(() => { p.openDatabase(path, { readOnly: true }).close(); })).toBe('SCHEMA_OUTDATED');
    expect(userVersion(path)).toBe(older);
    expect(fileHash(path)).toBe(before);
  });

  it('CP-015/B2 read-only open reads snapshots and refuses every write without changing the file', async () => {
    const p = await loadPersistence();
    const path = join(scratch('ro-read'), 'fluxwarden.db');
    const channelId = seeded(p, path);
    const writer = p.openDatabase(path, { readOnly: false });
    writer.snapshots.record(channelId, channel());
    writer.close();
    const before = fileHash(path);
    const reader = p.openDatabase(path, { readOnly: true });
    try {
      expect(reader.snapshots.latest(channelId)?.spendableMsat).toBe(582_858_000n);
      expect(codeOf(() => { reader.snapshots.record(channelId, channel()); })).toBe('READ_ONLY');
      expect(codeOf(() => { reader.nodes.insert({ id: '01JZ8Q5W3K6Y2N4R7T9V1X3Z5C', name: 'cln-m', implementation: 'cln', expectedNetwork: 'regtest', expectedPubkey: `02${'ef'.repeat(32)}` }); })).toBe('READ_ONLY');
    } finally { reader.close(); }
    expect(fileHash(path)).toBe(before);
    expect(count(path, 'channel_snapshots')).toBe(1n);
    expect(count(path, 'nodes')).toBe(1n);
  });
});

describe('money columns', () => {
  it('CP-015/B3 every msat column in every table is declared INTEGER (signed 64-bit)', async () => {
    const p = await loadPersistence();
    const path = join(scratch('types'), 'fluxwarden.db');
    p.openDatabase(path, { readOnly: false }).close();
    const db = raw(path);
    try {
      const tables = (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all() as { name: string }[]).map(r => r.name);
      const msat: string[] = [];
      for (const table of tables) {
        for (const column of db.prepare(`PRAGMA table_info(${table})`).all() as { name: string; type: string }[]) {
          if (!column.name.endsWith('_msat')) continue;
          msat.push(`${table}.${column.name}`);
          expect(column.type.toUpperCase(), `${table}.${column.name}`).toBe('INTEGER');
        }
      }
      // SPEC §6.2 has msat columns in channels, channel_snapshots, liquidity_proposals, approvals, executions,
      // budget_reservations and ledger_lines.
      for (const expected of ['channels.capacity_msat', 'channel_snapshots.spendable_msat', 'channel_snapshots.receivable_msat',
        'channel_snapshots.pending_out_msat', 'channel_snapshots.pending_in_msat']) expect(msat).toContain(expected);
      expect(msat.length).toBeGreaterThanOrEqual(12);
    } finally { db.close(); }
  });

  it('CP-015/B3 2^63 − 1 msat and a uint64 provenance value round-trip exactly', async () => {
    const p = await loadPersistence();
    const path = join(scratch('max'), 'fluxwarden.db');
    const channelId = seeded(p, path);
    const db = p.openDatabase(path, { readOnly: false });
    try {
      db.snapshots.record(channelId, channel({ localBalanceMsat: 9_223_372_036_854_775_807n, spendableMsat: 9_223_372_036_854_775_807n }));
      const row = db.snapshots.latest(channelId);
      expect(row?.localMsat).toBe(9_223_372_036_854_775_807n);
      expect(row?.spendableMsat).toBe(9_223_372_036_854_775_807n);
      expect(row?.receivableMsat).toBe(386_530_000n);
      expect(row?.pendingOutMsat).toBe(50_000_000n);
      expect(row?.pendingInMsat).toBe(20_000_000n);
      expect(row?.pendingHtlcCount).toBe(2);
      expect(row?.confidence).toBe('DERIVED_ESTIMATE');
      expect(row?.provenance['local_constraints.max_pending_amt_msat']).toBe('18446744073709551615');
    } finally { db.close(); }
    const check = raw(path);
    try {
      const stored = check.prepare('SELECT spendable_msat AS s, typeof(spendable_msat) AS t FROM channel_snapshots').get() as { s: bigint; t: string };
      expect(stored).toEqual({ s: 9_223_372_036_854_775_807n, t: 'integer' });
    } finally { check.close(); }
  });

  it('CP-015/B3 an msat value of 2^63 is refused before SQL and nothing is written', async () => {
    const p = await loadPersistence();
    const path = join(scratch('over'), 'fluxwarden.db');
    const channelId = seeded(p, path);
    const db = p.openDatabase(path, { readOnly: false });
    try {
      expect(codeOf(() => { db.snapshots.record(channelId, channel({ spendableMsat: 9_223_372_036_854_775_808n })); })).toBe('OUT_OF_RANGE');
      expect(codeOf(() => { db.snapshots.record(channelId, channel({ pendingInMsat: 2n ** 64n - 1n })); })).toBe('OUT_OF_RANGE');
      expect(codeOf(() => db.channels.upsert(channel({ channelKey: '999', capacityMsat: 9_223_372_036_854_775_808n })))).toBe('OUT_OF_RANGE');
      expect(codeOf(() => { db.snapshots.record(channelId, channel({ receivableMsat: -1n })); })).toBe('OUT_OF_RANGE');
    } finally { db.close(); }
    expect(count(path, 'channel_snapshots')).toBe(0n);
    expect(count(path, 'channels')).toBe(1n);
  });
});

describe('snapshots', () => {
  it('CP-015/B5 a snapshot stores observed_at from the database clock and the block height it was taken at', async () => {
    const p = await loadPersistence();
    const path = join(scratch('snap'), 'fluxwarden.db');
    const channelId = seeded(p, path);
    const db = p.openDatabase(path, { readOnly: false });
    try {
      const before = Date.now();
      db.snapshots.record(channelId, channel({ observedAt: 1_000, blockHeight: 1_234 }));
      db.snapshots.record(channelId, channel({ observedAt: 1_000, blockHeight: 1_240, spendableMsat: 1n }));
      const after = Date.now();
      const row = db.snapshots.latest(channelId);
      expect(row?.blockHeight).toBe(1_240);
      expect(row?.spendableMsat).toBe(1n);
      expect(row?.channelId).toBe(channelId);
      // the caller's observedAt (1,000 ms after the epoch) is not the stored time; the database clock is
      expect(row?.observedAt).toBeGreaterThanOrEqual(before - 5);
      expect(row?.observedAt).toBeLessThanOrEqual(after + 5);
      expect(db.snapshots.latest('01JZ8Q5W3K6Y2N4R7T9V1X3Z5D')).toBeNull();
    } finally { db.close(); }
    const check = raw(path);
    try {
      const columns = check.prepare('PRAGMA table_info(channel_snapshots)').all() as { name: string; type: string; notnull: bigint }[];
      for (const name of ['observed_at', 'block_height']) {
        const column = columns.find(c => c.name === name);
        expect(column?.type.toUpperCase(), name).toBe('INTEGER');
        expect(column?.notnull, name).toBe(1n);
      }
      const heights = (check.prepare('SELECT block_height AS h FROM channel_snapshots ORDER BY id').all() as { h: bigint }[]).map(r => r.h);
      expect(heights).toEqual([1_234n, 1_240n]);
    } finally { check.close(); }
  });

  it('CP-015/B5 snapshot age is measured with the database clock, not the process clock', async () => {
    const p = await loadPersistence();
    const path = join(scratch('age'), 'fluxwarden.db');
    const channelId = seeded(p, path);
    const writer = p.openDatabase(path, { readOnly: false });
    expect(writer.snapshots.ageMs(channelId)).toBeNull();
    writer.snapshots.record(channelId, channel());
    writer.close();
    // Age the stored snapshot by 90 s. The append-only triggers are dropped on this scratch copy only.
    const edit = raw(path);
    for (const row of edit.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'channel_snapshots'").all() as { name: string }[]) {
      edit.exec(`DROP TRIGGER "${row.name}"`);
    }
    edit.exec('UPDATE channel_snapshots SET observed_at = observed_at - 90000');
    edit.close();
    // A process clock 14 years ahead must not change the answer: SQLite reads the host clock itself.
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2040-01-01T00:00:00Z'));
    const reader = p.openDatabase(path, { readOnly: true });
    try {
      const age = reader.snapshots.ageMs(channelId);
      expect(age).toBeGreaterThanOrEqual(90_000);
      expect(age).toBeLessThan(100_000);
    } finally { reader.close(); }
  });

  it('CP-015/B5 snapshots are append-only: UPDATE and DELETE abort', async () => {
    const p = await loadPersistence();
    const path = join(scratch('append'), 'fluxwarden.db');
    const channelId = seeded(p, path);
    const db = p.openDatabase(path, { readOnly: false });
    db.snapshots.record(channelId, channel());
    db.close();
    const edit = raw(path);
    try {
      expect(() => { edit.exec('UPDATE channel_snapshots SET spendable_msat = 0'); }).toThrow();
      expect(() => { edit.exec('DELETE FROM channel_snapshots'); }).toThrow();
      const row = edit.prepare('SELECT spendable_msat AS s FROM channel_snapshots').get() as { s: bigint };
      expect(row.s).toBe(582_858_000n);
    } finally { edit.close(); }
  });
});

describe('hostile paths', () => {
  it('CP-015/B7 a symbolic link at the database path is refused and its target is untouched', async () => {
    const p = await loadPersistence();
    const target = join(scratch('target'), 'real.db');
    seeded(p, target);
    const before = fileHash(target);
    const link = join(scratch('link'), 'fluxwarden.db');
    symlinkSync(target, link, 'file');
    try {
      expect(codeOf(() => { p.openDatabase(link, { readOnly: false }).close(); })).toBe('UNSAFE_PATH');
      expect(codeOf(() => { p.openDatabase(link, { readOnly: true }).close(); })).toBe('UNSAFE_PATH');
      expect(fileHash(target)).toBe(before);
      expect(existsSync(`${target}-wal`)).toBe(false);
    } finally { unlinkFixture(link); }
  });

  it('CP-015/B7 a symbolic link or junction among the parent directories is refused', async () => {
    const p = await loadPersistence();
    const realDir = join(scratch('realdir'), 'state');
    mkdirSync(realDir);
    const linkedDir = join(scratch('linkdir'), 'state');
    symlinkSync(realDir, linkedDir, posix ? 'dir' : 'junction');
    try {
      expect(codeOf(() => { p.openDatabase(join(linkedDir, 'fluxwarden.db'), { readOnly: false }).close(); })).toBe('UNSAFE_PATH');
      expect(existsSync(join(realDir, 'fluxwarden.db'))).toBe(false);
    } finally { unlinkFixture(linkedDir); }
  });

  it('CP-015/B7 a dangling symbolic link is refused and nothing is created at its target', async () => {
    const p = await loadPersistence();
    const dir = scratch('dangling');
    const target = join(dir, 'elsewhere.db');
    const link = join(dir, 'fluxwarden.db');
    symlinkSync(target, link, 'file');
    try {
      expect(codeOf(() => { p.openDatabase(link, { readOnly: false }).close(); })).toBe('UNSAFE_PATH');
      expect(existsSync(target)).toBe(false);
    } finally { unlinkFixture(link); }
  });
});

describe('read-only side files', () => {
  it('CP-015/B2 read-only open creates no -wal or -shm file, during the session or after it', async () => {
    const p = await loadPersistence();
    const dir = scratch('ro-side');
    const path = join(dir, 'fluxwarden.db');
    const channelId = seeded(p, path);
    const writer = p.openDatabase(path, { readOnly: false });
    writer.snapshots.record(channelId, channel());
    writer.close();
    const before = listing(dir);
    const reader = p.openDatabase(path, { readOnly: true });
    try {
      expect(reader.snapshots.latest(channelId)?.spendableMsat).toBe(582_858_000n);
      expect(reader.snapshots.ageMs(channelId)).not.toBeNull();
      expect(listing(dir)).toEqual(before);
    } finally { reader.close(); }
    expect(listing(dir)).toEqual(before);
  });

  it('CP-015/B1 a refused open of a newer schema leaves no side files behind', async () => {
    const p = await loadPersistence();
    const dir = scratch('newer-side');
    const path = join(dir, 'fluxwarden.db');
    seeded(p, path);
    setUserVersion(path, userVersion(path) + 1);
    const before = listing(dir);
    expect(codeOf(() => { p.openDatabase(path, { readOnly: true }).close(); })).toBe('SCHEMA_TOO_NEW');
    expect(listing(dir)).toEqual(before);
    expect(codeOf(() => { p.openDatabase(path, { readOnly: false }).close(); })).toBe('SCHEMA_TOO_NEW');
    expect(listing(dir)).toEqual(before);
  });
});

describe('append-only tables under conflict resolution', () => {
  // sqlite.org/lang_conflict.html: REPLACE deletes the conflicting row without firing DELETE triggers unless
  // recursive_triggers is on, which is a per-connection setting. The guard must hold for any connection to the file.
  function attempts(table: string, columns: string[], key: string, change: Record<string, string>): string[] {
    const select = columns.map(c => change[c] ?? c).join(', ');
    const list = columns.join(', ');
    const set = Object.keys(change).filter(c => c !== key).map(c => `${c} = excluded.${c}`).join(', ');
    return [
      `INSERT OR REPLACE INTO ${table} (${list}) SELECT ${select} FROM ${table}`,
      `REPLACE INTO ${table} (${list}) SELECT ${select} FROM ${table}`,
      `INSERT INTO ${table} (${list}) SELECT ${select} FROM ${table} WHERE true ON CONFLICT DO UPDATE SET ${set || `${key} = excluded.${key}`}`,
    ];
  }
  function expectRefused(path: string, table: string, statements: string[], snapshot: () => unknown): void {
    const db = new DatabaseSync(path, { readBigInts: true, enableForeignKeyConstraints: false });
    try {
      const before = snapshot();
      for (const statement of statements) {
        expect(() => { db.exec(statement); }, statement).toThrow();
        expect(snapshot(), `${table} after ${statement}`).toEqual(before);
      }
    } finally { db.close(); }
  }

  it('CP-015/B5 INSERT OR REPLACE, REPLACE INTO and UPSERT cannot rewrite a snapshot', async () => {
    const p = await loadPersistence();
    const path = join(scratch('replace-snap'), 'fluxwarden.db');
    const channelId = seeded(p, path);
    const db = p.openDatabase(path, { readOnly: false });
    db.snapshots.record(channelId, channel());
    db.close();
    const look = raw(path);
    const columns = (look.prepare('PRAGMA table_info(channel_snapshots)').all() as { name: string }[]).map(c => c.name);
    look.close();
    const rows = (): unknown => {
      const r = raw(path);
      try { return r.prepare('SELECT * FROM channel_snapshots ORDER BY id').all(); } finally { r.close(); }
    };
    expectRefused(path, 'channel_snapshots', attempts('channel_snapshots', columns, 'id', { spendable_msat: '0' }), rows);
    expect(count(path, 'channel_snapshots')).toBe(1n);
  });

  it('CP-015/B5 REPLACE cannot rewrite approvals or ledger rows through their unique keys', async () => {
    const p = await loadPersistence();
    const path = join(scratch('replace-ledger'), 'fluxwarden.db');
    p.openDatabase(path, { readOnly: false }).close();
    // Columns of SPEC §6.2; foreign keys are off on this connection so single rows can be placed.
    const seed = new DatabaseSync(path, { enableForeignKeyConstraints: false });
    seed.exec(`INSERT INTO ledger_journals (id, execution_id, event_type, reference, occurred_at)
      VALUES ('01JZ8Q5W3K6Y2N4R7T9V1X3Z61', NULL, 'OPENING', 'opening-1', 1000)`);
    seed.exec(`INSERT INTO ledger_lines (journal_id, sequence_no, account_code, debit_msat, credit_msat)
      VALUES ('01JZ8Q5W3K6Y2N4R7T9V1X3Z61', 1, 'asset:channel', 5000, 0)`);
    seed.exec(`INSERT INTO approvals (id, proposal_id, key_id, nonce, expires_at, signature, max_fee_msat, max_cltv_delta, created_at)
      VALUES ('01JZ8Q5W3K6Y2N4R7T9V1X3Z62', '01JZ8Q5W3K6Y2N4R7T9V1X3Z63', 'k1', 'nonce-1', 2000, 'c2ln', 1000, 144, 1000)`);
    seed.close();
    const rows = (table: string) => (): unknown => {
      const r = raw(path);
      try { return r.prepare(`SELECT * FROM ${table}`).all(); } finally { r.close(); }
    };
    // same (event_type, reference) under a new id: REPLACE would delete the original journal
    expectRefused(path, 'ledger_journals', attempts('ledger_journals', ['id', 'execution_id', 'event_type', 'reference', 'occurred_at'], 'id',
      { id: "'01JZ8Q5W3K6Y2N4R7T9V1X3Z64'", occurred_at: '9999' }), rows('ledger_journals'));
    // same primary key (journal_id, sequence_no) with another amount
    expectRefused(path, 'ledger_lines', attempts('ledger_lines', ['journal_id', 'sequence_no', 'account_code', 'debit_msat', 'credit_msat'], 'journal_id',
      { debit_msat: '1' }), rows('ledger_lines'));
    // same single-use nonce under a new id
    expectRefused(path, 'approvals', attempts('approvals', ['id', 'proposal_id', 'key_id', 'nonce', 'expires_at', 'signature', 'max_fee_msat', 'max_cltv_delta', 'created_at'], 'id',
      { id: "'01JZ8Q5W3K6Y2N4R7T9V1X3Z65'", max_fee_msat: '999999' }), rows('approvals'));
  });
});

describe('hostile paths, continued', () => {
  it('CP-015/B7 a junction or symbolic link higher up the path is refused (unless it is owned by root on POSIX)', async () => {
    const p = await loadPersistence();
    const realRoot = scratch('anc-real');
    mkdirSync(join(realRoot, 'state'));
    const link = join(scratch('anc-link'), 'mid');
    symlinkSync(realRoot, link, posix ? 'dir' : 'junction');
    try {
      // Windows reports uid 0 for every file, so the POSIX root exemption must not apply there.
      const exempt = posix && lstatSync(link).uid === 0;
      const code = codeOf(() => { p.openDatabase(join(link, 'state', 'fluxwarden.db'), { readOnly: false }).close(); });
      expect(code).toBe(exempt ? undefined : 'UNSAFE_PATH');
      expect(existsSync(join(realRoot, 'state', 'fluxwarden.db'))).toBe(exempt);
    } finally { unlinkFixture(link); }
  });

  it('CP-015/B7 a database file with a second hard link is refused in both modes', async () => {
    const p = await loadPersistence();
    const path = join(scratch('hard'), 'fluxwarden.db');
    seeded(p, path);
    const alias = join(scratch('hard-alias'), 'copy.db');
    linkSync(path, alias);
    const before = fileHash(path);
    expect(codeOf(() => { p.openDatabase(path, { readOnly: false }).close(); })).toBe('UNSAFE_PATH');
    expect(codeOf(() => { p.openDatabase(path, { readOnly: true }).close(); })).toBe('UNSAFE_PATH');
    expect(codeOf(() => { p.openDatabase(alias, { readOnly: false }).close(); })).toBe('UNSAFE_PATH');
    expect(fileHash(path)).toBe(before);
  });
});

describe('snapshot age and validation', () => {
  function shiftObservedAt(path: string, sql: string): void {
    const edit = raw(path);
    try {
      for (const row of edit.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'channel_snapshots'").all() as { name: string }[]) {
        edit.exec(`DROP TRIGGER "${row.name}"`);
      }
      edit.exec(sql);
    } finally { edit.close(); }
  }

  it('CP-015/B5 the age is that of the newest snapshot, not the oldest', async () => {
    const p = await loadPersistence();
    const path = join(scratch('age-newest'), 'fluxwarden.db');
    const channelId = seeded(p, path);
    const db = p.openDatabase(path, { readOnly: false });
    db.snapshots.record(channelId, channel({ blockHeight: 1_234 }));
    db.close();
    shiftObservedAt(path, 'UPDATE channel_snapshots SET observed_at = observed_at - 90000');
    const again = p.openDatabase(path, { readOnly: false });
    try {
      again.snapshots.record(channelId, channel({ blockHeight: 1_235 }));
      const age = again.snapshots.ageMs(channelId);
      expect(age).toBeGreaterThanOrEqual(0);
      expect(age).toBeLessThan(5_000);
    } finally { again.close(); }
  });

  it('CP-015/B5 a snapshot stamped ahead of the database clock (clock stepped back) reads as infinitely old', async () => {
    const p = await loadPersistence();
    const path = join(scratch('age-future'), 'fluxwarden.db');
    const channelId = seeded(p, path);
    const db = p.openDatabase(path, { readOnly: false });
    db.snapshots.record(channelId, channel());
    db.close();
    shiftObservedAt(path, 'UPDATE channel_snapshots SET observed_at = observed_at + 3600000');
    const reader = p.openDatabase(path, { readOnly: true });
    try {
      // INV-06: a negative age would pass every "age ≤ max" check; it must fail all of them instead.
      expect(reader.snapshots.ageMs(channelId)).toBe(Number.POSITIVE_INFINITY);
    } finally { reader.close(); }
  });

  it('CP-015/B3 a block height that is negative, fractional or beyond 2^53 is refused before SQL', async () => {
    const p = await loadPersistence();
    const path = join(scratch('height'), 'fluxwarden.db');
    const channelId = seeded(p, path);
    const db = p.openDatabase(path, { readOnly: false });
    try {
      for (const blockHeight of [-1, 1.5, 2 ** 53, Number.NaN]) {
        expect(codeOf(() => { db.snapshots.record(channelId, channel({ blockHeight })); }), String(blockHeight)).toBe('OUT_OF_RANGE');
      }
    } finally { db.close(); }
    expect(count(path, 'channel_snapshots')).toBe(0n);
  });
});

describe('channel rows', () => {
  const OTHER_NODE = '01JZ8Q5W3K6Y2N4R7T9V1X3Z5C';

  function channelRows(path: string): { id: string; node_id: string; channel_key: string; scid: string | null; lifecycle_state: string; capacity_msat: bigint }[] {
    const r = raw(path);
    try {
      return r.prepare('SELECT id, node_id, channel_key, scid, lifecycle_state, capacity_msat FROM channels ORDER BY node_id, channel_key').all() as never;
    } finally { r.close(); }
  }

  it('CP-015/B5 a failed write is rolled back and the next write succeeds', async () => {
    const p = await loadPersistence();
    const path = join(scratch('rollback'), 'fluxwarden.db');
    seeded(p, path);
    const db = p.openDatabase(path, { readOnly: false });
    try {
      // unknown node: the foreign key fails inside the write transaction
      expect(() => db.channels.upsert(channel({ nodeId: '01JZ8Q5W3K6Y2N4R7T9V1X3Z5Z', channelKey: '777', fundingOutpoint: `${'b7'.repeat(32)}:0` }))).toThrow();
      const id = db.channels.upsert(channel({ channelKey: '888', fundingOutpoint: `${'b8'.repeat(32)}:0` }));
      expect(id.length).toBeGreaterThan(0);
      db.snapshots.record(id, channel());
    } finally { db.close(); }
    expect(count(path, 'channels')).toBe(2n);
    expect(count(path, 'channel_snapshots')).toBe(1n);
  });

  it('CP-015/B5 upsert updates the existing row: state, capacity and scid follow the latest observation', async () => {
    const p = await loadPersistence();
    const path = join(scratch('upsert'), 'fluxwarden.db');
    const first = seeded(p, path);
    const db = p.openDatabase(path, { readOnly: false });
    try {
      const second = db.channels.upsert(channel({ state: 'INACTIVE', nodeState: 'inactive', capacityMsat: 2_000_000_000n }));
      expect(second).toBe(first);
    } finally { db.close(); }
    const rows = channelRows(path);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.lifecycle_state).toBe('INACTIVE');
    expect(rows[0]?.capacity_msat).toBe(2_000_000_000n);
  });

  it('CP-015/B5 the same channel key on two managed nodes is two rows', async () => {
    const p = await loadPersistence();
    const path = join(scratch('two-nodes'), 'fluxwarden.db');
    const first = seeded(p, path);
    const db = p.openDatabase(path, { readOnly: false });
    try {
      db.nodes.insert({ id: OTHER_NODE, name: 'cln-m', implementation: 'cln', expectedNetwork: 'regtest', expectedPubkey: `02${'ef'.repeat(32)}` });
      const second = db.channels.upsert(channel({ nodeId: OTHER_NODE, state: 'INACTIVE' }));
      expect(second).not.toBe(first);
    } finally { db.close(); }
    const rows = channelRows(path);
    expect(rows.map(r => [r.node_id, r.lifecycle_state])).toEqual([[NODE_ID, 'ACTIVE'], [OTHER_NODE, 'INACTIVE']]);
  });

  it('CP-015/B5 a channel keeps one row from pending to open: same node and funding outpoint, new key', async () => {
    const p = await loadPersistence();
    const path = join(scratch('lifecycle'), 'fluxwarden.db');
    seeded(p, path);
    const outpoint = `${'aa'.repeat(32)}:1`;
    const db = p.openDatabase(path, { readOnly: false });
    let pendingId: string;
    try {
      // LND: PendingChannels keys by channel_point, ListChannels by chan_id
      pendingId = db.channels.upsert(channel({ channelKey: outpoint, scid: null, fundingOutpoint: outpoint, state: 'PENDING', nodeState: 'pending_open' }));
      const openId = db.channels.upsert(channel({ channelKey: '123145302441984', scid: '112x2x0', fundingOutpoint: outpoint }));
      expect(openId).toBe(pendingId);
    } finally { db.close(); }
    const rows = channelRows(path).filter(r => r.id === pendingId);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.channel_key).toBe('123145302441984');
    expect(rows[0]?.scid).toBe('112x2x0');
    expect(rows[0]?.lifecycle_state).toBe('ACTIVE');
    // the seeded channel (another outpoint) plus this one
    expect(count(path, 'channels')).toBe(2n);
  });
});

describe('owner-only checks on existing files', () => {
  // SECURITY §5: owner and mode (POSIX) or owner and DACL (Windows) are verified for an existing state directory and
  // database on every open, read-only included; anything another principal may access is refused before use.
  it('CP-015/B1 an existing database another principal can read is refused in both modes and left unchanged', async () => {
    const p = await loadPersistence();
    const path = join(scratch('loose-file'), 'state', 'fluxwarden.db');
    seeded(p, path);
    grantOthers(path, 'file');
    const before = fileHash(path);
    expect(codeOf(() => { p.openDatabase(path, { readOnly: false }).close(); })).toBe('UNSAFE_PATH');
    expect(codeOf(() => { p.openDatabase(path, { readOnly: true }).close(); })).toBe('UNSAFE_PATH');
    expect(fileHash(path)).toBe(before);
  });

  it('CP-015/B1 an existing state directory another principal can access is refused in both modes', async () => {
    const p = await loadPersistence();
    const dir = join(scratch('loose-dir'), 'state');
    const path = join(dir, 'fluxwarden.db');
    seeded(p, path);
    grantOthers(dir, 'directory');
    expect(codeOf(() => { p.openDatabase(path, { readOnly: false }).close(); })).toBe('UNSAFE_PATH');
    expect(codeOf(() => { p.openDatabase(path, { readOnly: true }).close(); })).toBe('UNSAFE_PATH');
  });

  it('CP-015/B1 a database planted before the first run, with inherited or group access, is refused rather than adopted', async () => {
    const p = await loadPersistence();
    const dir = join(scratch('planted'), 'state');
    mkdirSync(dir);
    grantOthers(dir, 'directory');
    const path = join(dir, 'fluxwarden.db');
    const plant = raw(path);
    plant.exec('CREATE TABLE planted (x INTEGER)');
    plant.close();
    grantOthers(path, 'file');
    const before = fileHash(path);
    expect(codeOf(() => { p.openDatabase(path, { readOnly: false }).close(); })).toBe('UNSAFE_PATH');
    expect(fileHash(path)).toBe(before);
    expect(userVersion(path)).toBe(0);
  });

  it('CP-015/B1 database creation beneath foreign-mutable ancestry is refused without creating files or changing parent permissions', async () => {
    const p = await loadPersistence();
    const parent = scratch('open-parent');
    makeOwnerOnlyDir(parent);
    grantDirectoryMutation(parent);
    const before = descriptor(parent);
    const dir = join(parent, 'state');
    const path = join(dir, 'fluxwarden.db');
    expect.soft(codeOf(() => { p.openDatabase(path, { readOnly: false }).close(); })).toBe('UNSAFE_PATH');
    expect.soft(existsSync(dir)).toBe(false);
    expect.soft(sideFiles(path)).toEqual([]);
    expect.soft(listing(parent)).toEqual([]);
    expect.soft(descriptor(parent)).toBe(before);
  });

  it('CP-015/B1 a new database beneath a safe owned parent is owner-only without changing parent permissions', async () => {
    const p = await loadPersistence();
    const parent = scratch('safe-parent');
    makeOwnerOnlyDir(parent);
    const before = descriptor(parent);
    const dir = join(parent, 'state');
    const path = join(dir, 'fluxwarden.db');
    const db = p.openDatabase(path, { readOnly: false });
    try {
      expectOwnerOnly(dir, 'directory');
      expectOwnerOnly(path, 'file');
      for (const side of sideFiles(path).filter(file => file !== path)) expectOwnerOnly(side, 'side');
    } finally { db.close(); }
    expect(descriptor(parent)).toBe(before);
    expect(listing(parent)).toEqual(['state']);
  });

  if (!posix) it('CP-015/B1 a Windows ancestor granting others read-only access permits owner-only database creation', async () => {
    const p = await loadPersistence();
    const parent = scratch('readable-parent');
    makeOwnerOnlyDir(parent);
    grantOthers(parent, 'directory');
    const before = descriptor(parent);
    const dir = join(parent, 'state');
    const path = join(dir, 'fluxwarden.db');
    const db = p.openDatabase(path, { readOnly: false });
    try {
      expectOwnerOnly(dir, 'directory');
      expectOwnerOnly(path, 'file');
    } finally { db.close(); }
    expect(descriptor(parent)).toBe(before);
    expect(listing(parent)).toEqual(['state']);
  });

  if (posix) it('CP-015/B1 a POSIX sticky ancestor permits a new database inside an existing current-user-owned state directory', async () => {
    const p = await loadPersistence();
    const parent = scratch('sticky-parent');
    chmodSync(parent, 0o1777);
    const dir = join(parent, 'state');
    mkdirSync(dir, { mode: 0o700 });
    const before = descriptor(parent);
    const path = join(dir, 'fluxwarden.db');
    const db = p.openDatabase(path, { readOnly: false });
    try {
      expectOwnerOnly(dir, 'directory');
      expectOwnerOnly(path, 'file');
    } finally { db.close(); }
    expect(descriptor(parent)).toBe(before);
    expect(listing(parent)).toEqual(['state']);
  });

  if (posix) it.each([0o770, 0o777])('CP-015/B1 POSIX non-sticky ancestor mode %i is refused without creating files or changing permissions', async mode => {
    const p = await loadPersistence();
    const parent = scratch('mutable-parent');
    chmodSync(parent, mode);
    const before = descriptor(parent);
    const dir = join(parent, 'state');
    const path = join(dir, 'fluxwarden.db');
    expect.soft(codeOf(() => { p.openDatabase(path, { readOnly: false }).close(); })).toBe('UNSAFE_PATH');
    expect.soft(existsSync(dir)).toBe(false);
    expect.soft(sideFiles(path)).toEqual([]);
    expect.soft(listing(parent)).toEqual([]);
    expect.soft(descriptor(parent)).toBe(before);
  });
});

describe('journal mode switch', () => {
  it('CP-015/B1 a database that cannot be switched to WAL is refused as BUSY, never used in rollback-journal mode', async () => {
    const p = await loadPersistence();
    const path = join(scratch('no-wal'), 'fluxwarden.db');
    seeded(p, path);
    // Put the current-version database back into rollback-journal mode and hold a read transaction on it: SQLite
    // cannot change the journal mode while another connection holds a lock (sqlite.org/pragma.html#pragma_journal_mode).
    const holder = raw(path);
    try {
      expect((holder.prepare('PRAGMA journal_mode = DELETE').get() as { journal_mode: string }).journal_mode).toBe('delete');
      holder.exec('BEGIN');
      holder.prepare('SELECT count(*) FROM nodes').get();
      const started = performance.now();
      expect(codeOf(() => { p.openDatabase(path, { readOnly: false, busyTimeoutMs: 300 }).close(); })).toBe('BUSY');
      expect(performance.now() - started).toBeGreaterThanOrEqual(250);
      holder.exec('COMMIT');
    } finally { holder.close(); }
    const db = p.openDatabase(path, { readOnly: false });
    try { expect(db.pragmas().journalMode).toBe('wal'); } finally { db.close(); }
  });
});

describe('channel rows across closing', () => {
  it('CP-015/B5 an open channel that starts closing keeps its single row and takes the CLOSING state', async () => {
    const p = await loadPersistence();
    const path = join(scratch('closing'), 'fluxwarden.db');
    const openId = seeded(p, path); // ListChannels: key chan_id 123145302376448, outpoint c3…:0, ACTIVE
    const db = p.openDatabase(path, { readOnly: false });
    try {
      // PendingChannels waiting_close and pending_force_closing entries carry only channel_point (no chan_id)
      const outpoint = `${'c3'.repeat(32)}:0`;
      const closingId = db.channels.upsert(channel({ channelKey: outpoint, scid: null, fundingOutpoint: outpoint, state: 'CLOSING', nodeState: 'waiting_close' }));
      expect(closingId).toBe(openId);
      expect(db.channels.upsert(channel({ channelKey: outpoint, scid: null, fundingOutpoint: outpoint, state: 'CLOSING', nodeState: 'pending_force_closing' }))).toBe(openId);
    } finally { db.close(); }
    const r = raw(path);
    try {
      const rows = r.prepare('SELECT id, lifecycle_state FROM channels').all() as { id: string; lifecycle_state: string }[];
      expect(rows).toEqual([{ id: openId, lifecycle_state: 'CLOSING' }]);
    } finally { r.close(); }
  });
});

describe('pre-existing directories are never rewritten', () => {
  // SECURITY §5 asks for a state directory FluxWarden creates to be owner-only and for the database file to be
  // owner-only; a directory that already exists is checked, never rewritten (on Windows a DACL change propagates to
  // everything below it). Every directory here is a scratch directory created by the test.
  it('CP-015/B1 creating a database in an existing owner-only directory leaves its DACL or mode and its other files unchanged', async () => {
    const p = await loadPersistence();
    const dir = scratch('existing-dir');
    makeOwnerOnlyDir(dir);
    const sibling = join(dir, 'notes.txt');
    writeFileSync(sibling, 'operator notes');
    const nested = join(dir, 'sub');
    mkdirSync(nested);
    const before = [descriptor(dir), descriptor(sibling), descriptor(nested)];
    const path = join(dir, 'fluxwarden.db');
    const db = p.openDatabase(path, { readOnly: false });
    try {
      // the file is owner-only by its own protected DACL with a single entry, not by inheritance from the directory
      expectOwnerOnly(path, 'file');
    } finally { db.close(); }
    expect([descriptor(dir), descriptor(sibling), descriptor(nested)]).toEqual(before);
  });

  it('CP-015/B1 an existing directory that grants others access is refused and left exactly as it was', async () => {
    const p = await loadPersistence();
    const dir = scratch('existing-loose');
    makeOwnerOnlyDir(dir);
    grantOthers(dir, 'directory');
    const sibling = join(dir, 'notes.txt');
    writeFileSync(sibling, 'operator notes');
    const before = [descriptor(dir), descriptor(sibling)];
    const path = join(dir, 'fluxwarden.db');
    expect(codeOf(() => { p.openDatabase(path, { readOnly: false }).close(); })).toBe('UNSAFE_PATH');
    expect(existsSync(path)).toBe(false);
    expect([descriptor(dir), descriptor(sibling)]).toEqual(before);
  });

  it('CP-015/B1 an existing database readable by a principal other than Everyone is refused too', async () => {
    const p = await loadPersistence();
    const path = join(scratch('users-read'), 'state', 'fluxwarden.db');
    seeded(p, path);
    grantOthers(path, 'file', 'S-1-5-32-545'); // BUILTIN\Users on Windows; group read on POSIX
    expect(codeOf(() => { p.openDatabase(path, { readOnly: false }).close(); })).toBe('UNSAFE_PATH');
    expect(codeOf(() => { p.openDatabase(path, { readOnly: true }).close(); })).toBe('UNSAFE_PATH');
  });
});

describe('one channel row for the whole lifecycle', () => {
  function rows(path: string): { id: string; channel_key: string; scid: string | null; lifecycle_state: string }[] {
    const r = raw(path);
    try { return r.prepare('SELECT id, channel_key, scid, lifecycle_state FROM channels ORDER BY id').all() as never; } finally { r.close(); }
  }

  it('CP-015/B5 an LND zero-conf channel keeps one row from pending through alias and real scid to closing', async () => {
    const p = await loadPersistence();
    const path = join(scratch('lnd-life'), 'fluxwarden.db');
    p.openDatabase(path, { readOnly: false }).close();
    const outpoint = `${'ab'.repeat(32)}:0`;
    const alias = '17592186044416000001';
    const db = p.openDatabase(path, { readOnly: false });
    const ids: string[] = [];
    try {
      db.nodes.insert({ id: NODE_ID, name: 'lnd-r', implementation: 'lnd', expectedNetwork: 'regtest', expectedPubkey: PUBKEY });
      const step = (over: Partial<SnapshotInput>): void => { ids.push(db.channels.upsert(channel({ fundingOutpoint: outpoint, ...over }))); };
      step({ channelKey: outpoint, scid: null, state: 'PENDING', nodeState: 'pending_open' });   // PendingChannels
      step({ channelKey: alias, scid: null, state: 'ACTIVE', nodeState: 'active' });             // ListChannels, zero-conf alias
      step({ channelKey: alias, scid: '112x1x0', state: 'ACTIVE', nodeState: 'active' });        // confirmed real scid
      step({ channelKey: alias, scid: '112x1x0', state: 'INACTIVE', nodeState: 'inactive' });
      step({ channelKey: outpoint, scid: null, state: 'CLOSING', nodeState: 'waiting_close' });  // PendingChannels again
      step({ channelKey: outpoint, scid: null, state: 'CLOSING', nodeState: 'pending_force_closing' });
    } finally { db.close(); }
    expect(new Set(ids).size).toBe(1);
    const all = rows(path);
    expect(all).toHaveLength(1);
    expect(all[0]?.lifecycle_state).toBe('CLOSING');
  });

  it('CP-015/B5 a CLN channel keeps one row from uncommitted to closing, and a later open with the same peer is a new row', async () => {
    const p = await loadPersistence();
    const path = join(scratch('cln-life'), 'fluxwarden.db');
    p.openDatabase(path, { readOnly: false }).close();
    const peer = `02${'ab'.repeat(32)}`;
    const outpoint = `${'cd'.repeat(32)}:1`;
    const db = p.openDatabase(path, { readOnly: false });
    const ids: string[] = [];
    let later: string;
    try {
      db.nodes.insert({ id: NODE_ID, name: 'cln-m', implementation: 'cln', expectedNetwork: 'regtest', expectedPubkey: PUBKEY });
      const step = (over: Partial<SnapshotInput>): void => { ids.push(db.channels.upsert(channel({ peerPubkey: peer, ...over }))); };
      // uncommitted (no channel_id, no funding fields: the normalizer keys it per peer), then committed, locked in, closing
      step({ channelKey: `uncommitted:${peer}`, scid: null, fundingOutpoint: '', state: 'PENDING', nodeState: 'OPENINGD' });
      step({ channelKey: 'e1'.repeat(32), scid: null, fundingOutpoint: outpoint, state: 'PENDING', nodeState: 'CHANNELD_AWAITING_LOCKIN' });
      step({ channelKey: '109x1x1', scid: '109x1x1', fundingOutpoint: outpoint, state: 'ACTIVE', nodeState: 'CHANNELD_NORMAL' });
      step({ channelKey: '109x1x1', scid: '109x1x1', fundingOutpoint: outpoint, state: 'CLOSING', nodeState: 'ONCHAIN' });
      later = db.channels.upsert(channel({ peerPubkey: peer, channelKey: `uncommitted:${peer}`, scid: null, fundingOutpoint: '', state: 'PENDING', nodeState: 'OPENINGD' }));
    } finally { db.close(); }
    expect(new Set(ids).size).toBe(1);
    expect(later).not.toBe(ids[0]);
    const all = rows(path);
    expect(all).toHaveLength(2);
    expect(all.find(r => r.id === ids[0])?.lifecycle_state).toBe('CLOSING');
  });

  it('CP-015/B5 uncommitted channels with two different peers are two rows', async () => {
    const p = await loadPersistence();
    const path = join(scratch('two-uncommitted'), 'fluxwarden.db');
    seeded(p, path);
    const db = p.openDatabase(path, { readOnly: false });
    try {
      const a = `02${'a1'.repeat(32)}`;
      const b = `02${'b1'.repeat(32)}`;
      const first = db.channels.upsert(channel({ peerPubkey: a, channelKey: `uncommitted:${a}`, scid: null, fundingOutpoint: '', state: 'PENDING' }));
      const second = db.channels.upsert(channel({ peerPubkey: b, channelKey: `uncommitted:${b}`, scid: null, fundingOutpoint: '', state: 'PENDING' }));
      expect(second).not.toBe(first);
    } finally { db.close(); }
    expect(count(path, 'channels')).toBe(3n);
  });
});

describe('snapshot freshness and height bounds at the edge', () => {
  it('CP-015/B5 a snapshot even under a second ahead of the database clock reads as infinitely old', async () => {
    const p = await loadPersistence();
    const path = join(scratch('age-edge'), 'fluxwarden.db');
    const channelId = seeded(p, path);
    const db = p.openDatabase(path, { readOnly: false });
    try {
      db.snapshots.record(channelId, channel());
      const edit = raw(path);
      try {
        for (const row of edit.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'channel_snapshots'").all() as { name: string }[]) {
          edit.exec(`DROP TRIGGER "${row.name}"`);
        }
        // 800 ms ahead of the database clock at this moment; ageMs runs a few ms later
        edit.exec("UPDATE channel_snapshots SET observed_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000) AS INTEGER) + 800");
      } finally { edit.close(); }
      expect(db.snapshots.ageMs(channelId)).toBe(Number.POSITIVE_INFINITY);
    } finally { db.close(); }
  });

  it('CP-015/B3 the block height is a uint32: 2^32 − 1 is stored, 2^32 is refused', async () => {
    const p = await loadPersistence();
    const path = join(scratch('height-edge'), 'fluxwarden.db');
    const channelId = seeded(p, path);
    const db = p.openDatabase(path, { readOnly: false });
    try {
      db.snapshots.record(channelId, channel({ blockHeight: 4_294_967_295 }));
      expect(db.snapshots.latest(channelId)?.blockHeight).toBe(4_294_967_295);
      expect(codeOf(() => { db.snapshots.record(channelId, channel({ blockHeight: 4_294_967_296 })); })).toBe('OUT_OF_RANGE');
    } finally { db.close(); }
    expect(count(path, 'channel_snapshots')).toBe(1n);
  });
});

describe('read-only handles never serve stale data', () => {
  it('CP-015/B2 after a writer commits and closes, a read-only handle returns the new snapshot or BUSY, never the old one', async () => {
    const p = await loadPersistence();
    const path = join(scratch('ro-fresh'), 'fluxwarden.db');
    const channelId = seeded(p, path);
    const first = p.openDatabase(path, { readOnly: false });
    first.snapshots.record(channelId, channel({ blockHeight: 1_234 }));
    first.close();
    const reader = p.openDatabase(path, { readOnly: true });
    try {
      expect(reader.snapshots.latest(channelId)?.blockHeight).toBe(1_234);
      // The second snapshot fits in the same page: after the checkpoint the file keeps its size, only its content and
      // modification time change.
      const writer = p.openDatabase(path, { readOnly: false });
      writer.snapshots.record(channelId, channel({ blockHeight: 1_240 }));
      writer.close();
      let seen: number | undefined;
      const code = codeOf(() => { seen = reader.snapshots.latest(channelId)?.blockHeight; });
      if (code === undefined) expect(seen).toBe(1_240);
      else expect(code).toBe('BUSY');
    } finally { reader.close(); }
    const again = p.openDatabase(path, { readOnly: true });
    try { expect(again.snapshots.latest(channelId)?.blockHeight).toBe(1_240); } finally { again.close(); }
  });

  it('CP-015/B1 a newer-schema database in rollback-journal mode is refused before any write, journal mode included', async () => {
    const p = await loadPersistence();
    const path = join(scratch('newer-delete'), 'fluxwarden.db');
    seeded(p, path);
    const edit = raw(path);
    try {
      const version = Number((edit.prepare('PRAGMA user_version').get() as { user_version: bigint }).user_version);
      edit.exec(`PRAGMA user_version = ${String(version + 1)}`);
      edit.prepare('PRAGMA journal_mode = DELETE').get();
    } finally { edit.close(); }
    const header = (): number[] => [...readFileSync(path).subarray(18, 20)];
    expect(header()).toEqual([1, 1]); // file format write/read version 1: rollback journal (sqlite.org/fileformat.html)
    const before = fileHash(path);
    expect(codeOf(() => { p.openDatabase(path, { readOnly: false }).close(); })).toBe('SCHEMA_TOO_NEW');
    expect(header()).toEqual([1, 1]);
    expect(fileHash(path)).toBe(before);
  });
});
