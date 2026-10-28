import { createHash } from 'node:crypto';
import { closeSync, existsSync, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import type { DatabaseSync, SQLOutputValue } from 'node:sqlite';
import { pathToFileURL } from 'node:url';
import { dirname } from 'node:path';
import { writeOwnerOnlyFile } from '../output/private-file.js';
import type { ExecutionRecord, LedgerBook, StoredJournal, Transaction } from '../core/ledger.js';
import type { ChannelState, Confidence, NormalizedChannel } from '../core/normalize.js';
import { lastTerminal, type TerminalTimes } from './budget.js';
import { PersistenceError, translateSqliteError } from './errors.js';
import { ledgerTransaction, readBalances, readBook, readExecutions, readJournals } from './ledger.js';
import { executionsRepository, type ExecutionsRepository } from './executions.js';
import { proposalRepository, type ProposalRepository } from './proposals.js';
import { commandData, type CommandData } from './command-data.js';
import { routingLayersRepository, type RoutingLayersRepository } from './routing-layers.js';
import { postAccountTransfer, postOpening } from '../ledger/post.js';
import { channelLocalAccount } from '../ledger/accounts.js';
import { checkPrivateDirectory, checkReadablePath, prepareWritablePath, secureSideFiles } from './paths.js';
import { MIGRATIONS, SCHEMA_VERSION } from './schema.js';
import { assertNodeIdentity } from './node-identity.js';
import { assertRecoveryResolved } from './recovery-state.js';
import { assertStateAdmitted, completeRestore, installRestoreBarrier } from './restore-barrier.js';
import { bigintColumn, checkedCount, checkedMsat, DB_NOW, dbNow, immediate, newUlid, numberColumn, textColumn } from './sql.js';

export interface OpenOptions {
  readonly readOnly: boolean;
  /** How long a write waits for a lock held by another connection before it fails with BUSY. */
  readonly busyTimeoutMs?: number;
  /** A read-write open that refuses to create a missing database (NOT_FOUND). */
  readonly mustExist?: boolean;
}

export interface NodeRecord {
  readonly id: string;
  readonly name: string;
  readonly implementation: 'lnd' | 'cln';
  readonly expectedNetwork: 'regtest';
  readonly expectedPubkey: string;
}

export type NodeState = 'ONLINE' | 'OFFLINE' | 'QUARANTINED';

/** A `nodes` row as stored. */
export interface StoredNode {
  readonly id: string;
  readonly name: string;
  readonly implementation: 'lnd' | 'cln';
  readonly expectedNetwork: 'regtest';
  readonly expectedPubkey: string;
  readonly state: NodeState;
  readonly observedVersion: string | null;
  readonly capabilities: readonly string[] | null;
  /** Unix milliseconds from the database clock. */
  readonly lastProbedAt: number | null;
}

/** The outcome of a handshake for the node configured under `name` (SPEC.md §5.2 H3, H8). */
export interface ProbeRecord {
  readonly name: string;
  readonly implementation: 'lnd' | 'cln';
  readonly expectedPubkey: string;
  readonly state: 'ONLINE' | 'QUARANTINED';
  readonly observedVersion: string | null;
  readonly capabilities: readonly string[];
}

/**
 * The row id and whether the row stays QUARANTINED (a quarantine is lifted only by an explicit operator step,
 * never by a later handshake), or the name of another node whose row already holds this expected identity.
 */
export type ProbeRecordResult = { readonly id: string; readonly quarantined: boolean } | { readonly heldBy: string };

export interface SnapshotRow {
  readonly channelId: string;
  /** Unix milliseconds from the database clock. */
  readonly observedAt: number;
  readonly blockHeight: number;
  readonly localMsat: bigint;
  readonly remoteMsat: bigint;
  readonly spendableMsat: bigint;
  readonly receivableMsat: bigint;
  readonly pendingOutMsat: bigint;
  readonly pendingInMsat: bigint;
  readonly pendingHtlcCount: number;
  readonly confidence: Confidence;
  readonly provenance: Readonly<Record<string, string>>;
}

export interface Database {
  backupTo(path: string): Promise<void>;
  integrityCheck(): void;
  readonly state: { assertAdmitted(): void; installRestoreBarrier(): void; completeRestore(nodeIds: readonly string[]): void };
  readonly commandData: CommandData;
  readonly routingLayers: RoutingLayersRepository;
  close(): void;
  /** The journal mode and synchronous level of the live connection. */
  pragmas(): { journalMode: string; synchronous: number };
  readonly nodes: {
    fenceEpoch(nodeId: string): bigint;
    recover(nodeId: string, fenceEpoch: bigint): void;
    /** Refuses a legacy node whose original binding cannot be established from durable provenance. */
    assertIdentity(nodeId: string): void;
    insert(node: NodeRecord): void;
    /** Every stored node, by name. */
    list(): StoredNode[];
    /** Records probe metadata without rebinding an existing identity; last_probed_at is the database clock. */
    recordProbe(record: ProbeRecord): ProbeRecordResult;
    /** Marks the named node OFFLINE when it is ONLINE; a quarantined node or a node without a row is left alone. */
    markOffline(name: string): void;
  };
  readonly channels: {
    /** Inserts or updates the channel row keyed by (nodeId, channelKey) and returns its id. */
    upsert(channel: NormalizedChannel): string;
  };
  readonly snapshots: {
    /** Appends a snapshot; observed_at is the database clock, block_height the channel's observation height. */
    record(channelId: string, channel: NormalizedChannel): void;
    /** Upserts every channel and appends one snapshot each, in one transaction; returns the channel ids in order. */
    storeAll(channels: readonly NormalizedChannel[]): string[];
    /** The most recently recorded snapshot of the channel. */
    latest(channelId: string): SnapshotRow | null;
    /** Milliseconds between the database clock and the newest snapshot's observed_at; Infinity when negative. */
    ageMs(channelId: string): number | null;
  };
  /**
   * Runs `work` inside BEGIN IMMEDIATE and commits; a throw rolls everything back and is rethrown. The handle
   * is the write port of this transaction only and refuses every write once it has ended.
   */
  transaction<T>(work: (tx: Transaction) => T): T;
  readonly ledger: {
    /** Every journal with its lines in sequence order. */
    journals(): StoredJournal[];
    /** The stored net-debit balance of every account; null where the stored text is not a canonical decimal. */
    balances(): ReadonlyMap<string, bigint | null>;
    /** Every execution row with the principal of its proposal. */
    executions(): ExecutionRecord[];
    /** Journals, balances and execution records read from one consistent snapshot of the database. */
    book(): LedgerBook;
  };
  readonly executions: ExecutionsRepository;
  readonly budget: {
    /** The latest VERIFIED_FAILURE of the pair and the latest VERIFIED_SUCCESS touching S or T, in database time. */
    lastTerminal(sourceChannelId: string, targetChannelId: string): TerminalTimes;
  };
  /** The database clock in unix milliseconds. */
  now(): number;
  readonly proposals: ProposalRepository;
}

const DEFAULT_BUSY_TIMEOUT_MS = 5_000;
/** Block heights are uint32 in both node APIs. */
const MAX_BLOCK_HEIGHT = 0xFFFFFFFF;

function readProvenance(text: string): Record<string, string> {
  const parsed: unknown = JSON.parse(text);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('provenance_json is not an object');
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(parsed)) {
    if (typeof value === 'string') result[key] = value;
  }
  return result;
}

function schemaVersion(db: DatabaseSync): number {
  // MySQL: n/a, the version is kept in a one-row schema_version table
  const row = db.prepare('PRAGMA user_version').get();
  return row === undefined ? 0 : numberColumn(row, 'user_version');
}

function refuseNewer(version: number): void {
  if (version > SCHEMA_VERSION) {
    throw new PersistenceError('SCHEMA_TOO_NEW', `the database schema is version ${String(version)}; this release reads up to version ${String(SCHEMA_VERSION)}`);
  }
}

/** Runs `work` inside a deferred read transaction, so every statement in it reads the same snapshot. */
function snapshot<T>(db: DatabaseSync, work: () => T): T {
  const inTransaction = (): boolean => db.isTransaction;
  if (inTransaction()) return work();
  try {
    // MySQL: START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY
    db.exec('BEGIN');
  } catch (error) {
    throw translateSqliteError(error);
  }
  try {
    return work();
  } finally {
    // MySQL: same
    if (inTransaction()) db.exec('COMMIT');
  }
}

function migrate(db: DatabaseSync): void {
  immediate(db, () => {
    const from = schemaVersion(db);
    refuseNewer(from);
    for (let version = from; version < SCHEMA_VERSION; version += 1) {
      for (const statement of MIGRATIONS[version] ?? []) db.exec(statement);
    }
    // MySQL: n/a, UPDATE schema_version SET version = ? in the same transaction
    db.exec(`PRAGMA user_version = ${String(SCHEMA_VERSION)}`);
  });
}

/** Blocks the thread for `ms` milliseconds without spinning. */
function pause(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Switches the database to WAL. Changing the journal mode needs an exclusive lock that SQLite does not wait for
 * through the busy handler, so a switch that meets another process's lock is retried until the busy timeout.
 */
function switchToWal(db: DatabaseSync, timeout: number): void {
  const deadline = performance.now() + timeout;
  for (;;) {
    let mode: string | undefined;
    try {
      // MySQL: n/a, InnoDB always writes through its redo log
      const row = db.prepare('PRAGMA journal_mode = WAL').get();
      mode = row === undefined ? undefined : textColumn(row, 'journal_mode').toLowerCase();
    } catch (error) {
      const translated = translateSqliteError(error);
      if (!(translated instanceof PersistenceError)) throw translated;
    }
    if (mode === 'wal') return;
    if (performance.now() >= deadline) throw new PersistenceError('BUSY', 'the database could not be switched to WAL mode');
    pause(10);
  }
}

function configure(db: DatabaseSync, readOnly: boolean, timeout: number): void {
  if (!readOnly) switchToWal(db, timeout);
  // Set explicitly: a build default (SQLITE_DEFAULT_WAL_SYNCHRONOUS) may otherwise be NORMAL in WAL mode.
  // MySQL: n/a, innodb_flush_log_at_trx_commit = 1 and sync_binlog = 1 on the server
  db.exec('PRAGMA synchronous = FULL');
  // A REPLACE that deletes a conflicting row then fires the append-only DELETE triggers (sqlite.org/lang_conflict.html).
  // MySQL: n/a, REPLACE is never used and BEFORE DELETE triggers fire for every delete
  db.exec('PRAGMA recursive_triggers = ON');
}

/** A read-only connection and a check that the database file did not change under it. */
interface Reader {
  readonly db: DatabaseSync;
  readonly unchanged: () => void;
}

/**
 * Opens a read-only connection that creates no file. A database without a -wal file was closed cleanly, so its
 * main file holds every committed transaction and is read as immutable: SQLite then opens no -wal or -shm.
 * Only a checkpoint can change the main file, so each read is followed by a check of its metadata and content;
 * a change means a writer ran meanwhile and the read fails as BUSY. With a -wal file present the
 * ordinary read-only connection requires an existing -shm file: otherwise SQLite could create it while reading
 * the schema. Side-file presence is checked before opening, within the already validated trusted ancestry.
 */
function openReader(absolute: string, timeout: number): Reader {
  // Load SQLite only for a database open: Node 22 emits its experimental warning on loading,
  // and importing the CLI for help, version or an early refusal needs no database.
  const { DatabaseSync } = process.getBuiltinModule('node:sqlite');
  const wal = `${absolute}-wal`;
  const options = { readOnly: true, readBigInts: true, timeout, enableForeignKeyConstraints: true };
  try {
    if (existsSync(wal)) {
      if (!existsSync(`${absolute}-shm`)) {
        throw new PersistenceError('UNSAFE_PATH', 'the database WAL has no shared-memory file; a read-only open could create it');
      }
      return { db: new DatabaseSync(absolute, options), unchanged: () => undefined };
    }
    const fingerprint = (): string => {
      const fd = openSync(absolute, 'r');
      try {
        const stat = fstatSync(fd, { bigint: true });
        const identity = () => {
          const held = fstatSync(fd, { bigint: true }), named = lstatSync(absolute, { bigint: true });
          if (!held.isFile() || held.nlink !== 1n || !named.isFile() || named.isSymbolicLink()
            || named.dev !== held.dev || named.ino !== held.ino || held.dev !== stat.dev || held.ino !== stat.ino
            || held.size !== stat.size || held.mtimeNs !== stat.mtimeNs || held.ctimeNs !== stat.ctimeNs) {
            throw new PersistenceError('BUSY', 'the database changed while it was read; retry');
          }
        };
        identity();
        // Node.js/node doc/api/fs.md readSync: fixed-size reads keep memory bounded.
        // Same-size checkpoints can share a filesystem timestamp; immutable SQLite
        // readers need content identity too before returning their cached snapshot.
        const chunk = Buffer.allocUnsafe(65_536);
        const content = (): string => {
          const digest = createHash('sha256');
          let position = 0n;
          while (position < stat.size) {
            const remaining = stat.size - position;
            const length = Number(remaining > BigInt(chunk.length) ? BigInt(chunk.length) : remaining);
            const count = readSync(fd, chunk, 0, length, position);
            if (count === 0) throw new PersistenceError('BUSY', 'the database changed while it was read; retry');
            digest.update(chunk.subarray(0, count));
            position += BigInt(count);
          }
          identity();
          return digest.digest('hex');
        };
        const digest = content();
        // A concurrent rewrite must not establish the initial cached identity
        // from a single partial view, even when filesystem timestamps coincide.
        if (content() !== digest) {
          throw new PersistenceError('BUSY', 'the database changed while it was read; retry');
        }
        return `${stat.size.toString()}:${stat.mtimeNs.toString()}:${String(existsSync(wal))}:${digest}`;
      } finally { closeSync(fd); }
    };
    const before = fingerprint();
    const url = pathToFileURL(absolute);
    url.searchParams.set('mode', 'ro');
    url.searchParams.set('immutable', '1');
    const db = new DatabaseSync(url, options);
    return {
      db,
      unchanged: () => {
        if (fingerprint() !== before) throw new PersistenceError('BUSY', 'the database changed while it was read; retry');
      },
    };
  } catch (error) {
    throw translateSqliteError(error);
  }
}

function readerVersion(reader: Reader): number {
  const version = schemaVersion(reader.db);
  reader.unchanged();
  return version;
}

/**
 * Opens the FluxWarden database. A read-write open creates the state directory (0700) and database (0600) if
 * needed, switches to WAL with synchronous=FULL and applies pending migrations. A read-only open creates
 * nothing, never migrates and refuses every write. A schema newer than this release is refused in both modes
 * before any read-write connection exists, an older one in read-only mode.
 */
export function openDatabase(path: string, options: OpenOptions): Database {
  const timeout = options.busyTimeoutMs ?? DEFAULT_BUSY_TIMEOUT_MS;
  if (options.readOnly) {
    const reader = openReader(checkReadablePath(path), timeout);
    try {
      const version = readerVersion(reader);
      refuseNewer(version);
      if (version < SCHEMA_VERSION) {
        throw new PersistenceError('SCHEMA_OUTDATED', `the database schema is version ${String(version)}; run a read-write command to migrate it to version ${String(SCHEMA_VERSION)}`);
      }
      configure(reader.db, true, timeout);
    } catch (error) {
      reader.db.close();
      throw translateSqliteError(error);
    }
    return repositories(reader.db, true, () => {
      checkReadablePath(path);
      reader.unchanged();
    });
  }

  const absolute = options.mustExist === true ? checkReadablePath(path) : prepareWritablePath(path);
  const peek = openReader(absolute, timeout);
  try {
    refuseNewer(readerVersion(peek));
  } catch (error) {
    // A file that another process is creating or migrating is checked again on the read-write connection below.
    const translated = translateSqliteError(error);
    if (!(translated instanceof PersistenceError && translated.code === 'BUSY')) throw translated;
  } finally {
    peek.db.close();
  }
  let db: DatabaseSync;
  try {
    const { DatabaseSync } = process.getBuiltinModule('node:sqlite');
    db = new DatabaseSync(absolute, { readOnly: false, readBigInts: true, timeout, enableForeignKeyConstraints: true });
  } catch (error) {
    throw translateSqliteError(error);
  }
  try {
    configure(db, false, timeout);
    const version = schemaVersion(db);
    refuseNewer(version);
    if (version < SCHEMA_VERSION) migrate(db);
    secureSideFiles(absolute);
  } catch (error) {
    db.close();
    throw translateSqliteError(error);
  }
  return repositories(db, false, () => undefined);
}

function optionalText(row: Record<string, SQLOutputValue>, key: string): string | null {
  return row[key] === null ? null : textColumn(row, key);
}

function readCapabilities(text: string | null): string[] | null {
  if (text === null) return null;
  const parsed: unknown = JSON.parse(text);
  if (!Array.isArray(parsed) || !parsed.every((item): item is string => typeof item === 'string')) throw new Error('capabilities_json is not a list of names');
  return [...parsed].sort();
}

function nodeState(value: string): NodeState {
  if (value === 'ONLINE' || value === 'OFFLINE' || value === 'QUARANTINED') return value;
  throw new Error('nodes.state is not a known state');
}

function implementationOf(value: string): 'lnd' | 'cln' {
  if (value === 'lnd' || value === 'cln') return value;
  throw new Error('nodes.implementation is not a known implementation');
}

/** Inserts or updates the channel row keyed by (nodeId, channelKey) inside the caller's transaction. */
function upsertChannelRow(db: DatabaseSync, channel: NormalizedChannel): string {
  const capacity = checkedMsat(channel.capacityMsat, 'capacityMsat');
  const state: ChannelState = channel.state;
  // The same channel keeps one row while its key changes over its life on the same node: by key first;
  // else by funding outpoint when either side is in a pending listing (LND keys pending_open, waiting_close
  // and pending_force_closing channels by outpoint, open ones by chan_id; CLN moves from channel_id to
  // short_channel_id). A shared peer alone cannot prove that a committed channel owns an uncommitted row.
  const transitional = channel.state === 'PENDING' || channel.state === 'CLOSING';
  // MySQL: same with FOR UPDATE appended, which locks the row or the gap inside the transaction
  const existing = db.prepare(`SELECT id, channel_key FROM channels WHERE node_id = ? AND (channel_key = ?
      OR (funding_outpoint = ? AND funding_outpoint <> '' AND (lifecycle_state = 'PENDING' OR ? = 1)))
    ORDER BY CASE WHEN channel_key = ? THEN 0 ELSE 1 END LIMIT 1`)
    .get(channel.nodeId, channel.channelKey, channel.fundingOutpoint, transitional ? 1 : 0, channel.channelKey);
  if (existing !== undefined) {
    const id = textColumn(existing, 'id');
    // MySQL: same, with NOW(6) for the clock
    db.prepare(`UPDATE channels SET opening_channel_key = coalesce(opening_channel_key, channel_key), channel_key = ?, scid = ?, peer_pubkey = ?, funding_outpoint = ?, capacity_msat = ?, lifecycle_state = ?,
      updated_at = ${DB_NOW} WHERE id = ? AND node_id = ?`)
      .run(channel.channelKey, channel.scid, channel.peerPubkey, channel.fundingOutpoint, capacity, state, id, channel.nodeId);
    const previousKey = textColumn(existing, 'channel_key');
    if (previousKey !== channel.channelKey) {
      // MySQL: same SELECT inside the channel update transaction.
      const node = db.prepare('SELECT name FROM nodes WHERE id = ?').get(channel.nodeId);
      if (node === undefined) throw new Error('a channel has no node');
      let active = true;
      const tx = ledgerTransaction(db, newUlid, () => active);
      try {
        const from = channelLocalAccount(textColumn(node, 'name'), previousKey);
        postAccountTransfer(tx, { from, to: channelLocalAccount(textColumn(node, 'name'), channel.channelKey), amount: tx.balance(from),
          reference: `channel:${id}:${newUlid()}`, executionId: null, occurredAt: dbNow(db) });
      } finally { active = false; }
    }
    return id;
  }
  const singlePendingKey = `uncommitted:${channel.peerPubkey}`;
  const dualPendingKey = `uncommitted-dual:${channel.peerPubkey}`;
  if (channel.channelKey !== singlePendingKey && channel.channelKey !== dualPendingKey) {
    // MySQL: same with FOR UPDATE; the surrounding snapshot transaction rolls back all earlier rows too.
    const pending = db.prepare(`SELECT id FROM channels WHERE node_id = ? AND lifecycle_state = 'PENDING'
      AND funding_outpoint = '' AND channel_key IN (?, ?) LIMIT 1`).get(channel.nodeId, singlePendingKey, dualPendingKey);
    if (pending !== undefined) throw new PersistenceError('AMBIGUOUS_CHANNEL_IDENTITY', 'a committed channel has no proven link to the pending channel identity');
  }
  const id = newUlid();
  // MySQL: same, with NOW(6) for the clock
  db.prepare(`INSERT INTO channels (id, node_id, channel_key, opening_channel_key, scid, peer_pubkey, funding_outpoint, capacity_msat, lifecycle_state, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ${DB_NOW})`)
    .run(id, channel.nodeId, channel.channelKey, channel.channelKey, channel.scid, channel.peerPubkey, channel.fundingOutpoint, capacity, state);
  return id;
}

/** The validated values of a snapshot row after its channel id, before any statement runs. */
function snapshotValues(channel: NormalizedChannel): (bigint | number | string)[] {
  const amounts = [
    checkedMsat(channel.localBalanceMsat, 'localBalanceMsat'),
    checkedMsat(channel.remoteBalanceMsat, 'remoteBalanceMsat'),
    checkedMsat(channel.spendableMsat, 'spendableMsat'),
    checkedMsat(channel.receivableMsat, 'receivableMsat'),
    checkedMsat(channel.pendingOutMsat, 'pendingOutMsat'),
    checkedMsat(channel.pendingInMsat, 'pendingInMsat'),
  ];
  const height = checkedCount(channel.blockHeight, 'blockHeight');
  if (height > MAX_BLOCK_HEIGHT) throw new PersistenceError('OUT_OF_RANGE', 'blockHeight is above 2^32 - 1');
  const htlcCount = checkedCount(channel.pendingHtlcCount, 'pendingHtlcCount');
  return [height, ...amounts, htlcCount, channel.confidence, JSON.stringify(channel.provenance)];
}

// MySQL: same, with NOW(6) for the clock
const INSERT_SNAPSHOT = `INSERT INTO channel_snapshots (channel_id, observed_at, block_height, local_msat, remote_msat, spendable_msat,
    receivable_msat, pending_out_msat, pending_in_msat, pending_htlc_count, confidence, provenance_json)
  VALUES (?, ${DB_NOW}, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

function repositories(db: DatabaseSync, readOnly: boolean, unchanged: () => void): Database {
  const writable = (what: string): void => {
    if (readOnly) throw new PersistenceError('READ_ONLY', `${what} needs a read-write database`);
  };
  const run = <T>(work: () => T): T => {
    try {
      const result = work();
      unchanged();
      return result;
    } catch (error) {
      throw translateSqliteError(error);
    }
  };

  return {
    integrityCheck() {
      run(() => {
        // MySQL: CHECK TABLE and referential checks, run before adopting a restored book.
        const rows = db.prepare('PRAGMA integrity_check').all();
        if (rows.length !== 1 || rows[0]?.['integrity_check'] !== 'ok' || db.prepare('PRAGMA foreign_key_check').all().length !== 0) {
          throw new Error('state: SQLite integrity validation failed');
        }
      });
    },
    async backupTo(path) {
      unchanged();
      checkPrivateDirectory(dirname(path));
      if (writeOwnerOnlyFile(path, new Uint8Array()) !== 'written') throw new PersistenceError('UNSAFE_PATH', 'backup: destination is occupied or unsafe');
      await process.getBuiltinModule('node:sqlite').backup(db, path);
      unchanged();
    },
    state: {
      assertAdmitted: () => { run(() => { assertStateAdmitted(db); }); },
      installRestoreBarrier: () => { writable('state.restore'); installRestoreBarrier(db); },
      completeRestore: nodeIds => { writable('state.completeRestore'); completeRestore(db, nodeIds); },
    },
    commandData: commandData(db, writable, run),
    routingLayers: routingLayersRepository(db, writable, run),
    close: () => { if (db.isOpen) db.close(); },

    now: () => run(() => dbNow(db)),

    executions: executionsRepository(db, writable, run),

    budget: {
      lastTerminal: (sourceChannelId, targetChannelId) => run(() => lastTerminal(db, sourceChannelId, targetChannelId)),
    },

    proposals: proposalRepository(db, { writable, run, immediate: work => immediate(db, work) }),

    pragmas: () => run(() => {
      // MySQL: n/a
      const journal = db.prepare('PRAGMA journal_mode').get();
      // MySQL: n/a
      const synchronous = db.prepare('PRAGMA synchronous').get();
      if (journal === undefined || synchronous === undefined) throw new Error('pragma returned no row');
      return { journalMode: textColumn(journal, 'journal_mode').toLowerCase(), synchronous: numberColumn(synchronous, 'synchronous') };
    }),

    nodes: {
      fenceEpoch: nodeId => run(() => {
        // MySQL: same.
        const row = db.prepare('SELECT fence_epoch FROM nodes WHERE id = ?').get(nodeId);
        if (row === undefined) throw new PersistenceError('NOT_FOUND', 'identity: no stored node');
        return bigintColumn(row, 'fence_epoch');
      }),
      recover(nodeId, fenceEpoch) {
        writable('nodes.recover');
        immediate(db, () => {
          assertNodeIdentity(db, nodeId);
          assertRecoveryResolved(db, nodeId);
          // MySQL: same; only the exact fresh probe can authorize lifting quarantine.
          const result = db.prepare(`UPDATE nodes SET state = 'ONLINE', fence_epoch = fence_epoch + 1
            WHERE id = ? AND fence_epoch = ? AND state IN ('ONLINE','QUARANTINED')`).run(nodeId, fenceEpoch);
          if (Number(result.changes) === 0) throw new PersistenceError('NODE_IDENTITY_CHANGED', 'identity: the node changed during recovery');
        });
      },
      assertIdentity: nodeId => { run(() => { assertNodeIdentity(db, nodeId); }); },
      insert(node: NodeRecord): void {
        writable('nodes.insert');
        run(() => {
          // MySQL: same
          db.prepare(`INSERT INTO nodes (id, name, implementation, expected_network, expected_pubkey, state)
            VALUES (?, ?, ?, ?, ?, 'OFFLINE')`).run(node.id, node.name, node.implementation, node.expectedNetwork, node.expectedPubkey);
        });
      },

      list(): StoredNode[] {
        return run(() => {
          // MySQL: same
          const rows = db.prepare(`SELECT id, name, implementation, expected_network, expected_pubkey, state, observed_version,
              capabilities_json, last_probed_at FROM nodes ORDER BY name`).all();
          return rows.map(row => ({
            id: textColumn(row, 'id'),
            name: textColumn(row, 'name'),
            implementation: implementationOf(textColumn(row, 'implementation')),
            expectedNetwork: 'regtest' as const,
            expectedPubkey: textColumn(row, 'expected_pubkey'),
            state: nodeState(textColumn(row, 'state')),
            observedVersion: optionalText(row, 'observed_version'),
            capabilities: readCapabilities(optionalText(row, 'capabilities_json')),
            lastProbedAt: row['last_probed_at'] === null ? null : numberColumn(row, 'last_probed_at'),
          }));
        });
      },

      recordProbe(record: ProbeRecord): ProbeRecordResult {
        writable('nodes.recordProbe');
        const capabilities = JSON.stringify([...record.capabilities].sort());
        return immediate(db, () => {
          // MySQL: same
          const holder = db.prepare(`SELECT name FROM nodes WHERE expected_network = 'regtest' AND expected_pubkey = ? AND name <> ?`)
            .get(record.expectedPubkey, record.name);
          if (holder !== undefined) return { heldBy: textColumn(holder, 'name') };
          // MySQL: same
          const existing = db.prepare('SELECT id, state, implementation, expected_pubkey FROM nodes WHERE name = ?').get(record.name);
          if (existing !== undefined) {
            assertNodeIdentity(db, textColumn(existing, 'id'));
            // The node row owns channel and execution history. Rebinding it would let a replacement
            // resolve the original node's hashes, including UNKNOWN payments and terminal history.
            if (textColumn(existing, 'implementation') !== record.implementation
              || textColumn(existing, 'expected_pubkey') !== record.expectedPubkey) {
              throw new PersistenceError('NODE_IDENTITY_CHANGED', 'identity: the configured node differs from its stored identity; preserve the original database and restore its verified connection');
            }
            const id = textColumn(existing, 'id');
            const quarantined = textColumn(existing, 'state') === 'QUARANTINED' || record.state === 'QUARANTINED';
            // MySQL: same, with NOW(6) for the clock
            db.prepare(`UPDATE nodes SET observed_version = ?, capabilities_json = ?, state = ?, fence_epoch = fence_epoch + 1,
                last_probed_at = ${DB_NOW} WHERE id = ?`)
              .run(record.observedVersion, capabilities, quarantined ? 'QUARANTINED' : record.state, id);
            return { id, quarantined };
          }
          const id = newUlid();
          // MySQL: same, with NOW(6) for the clock
          db.prepare(`INSERT INTO nodes (id, name, implementation, expected_network, expected_pubkey, observed_version, capabilities_json,
              state, last_probed_at) VALUES (?, ?, ?, 'regtest', ?, ?, ?, ?, ${DB_NOW})`)
            .run(id, record.name, record.implementation, record.expectedPubkey, record.observedVersion, capabilities, record.state);
          return { id, quarantined: record.state === 'QUARANTINED' };
        });
      },

      markOffline(name: string): void {
        writable('nodes.markOffline');
        run(() => {
          // MySQL: same
          db.prepare(`UPDATE nodes SET state = 'OFFLINE', fence_epoch = fence_epoch + 1 WHERE name = ? AND state = 'ONLINE'`).run(name);
        });
      },
    },

    channels: {
      upsert(channel: NormalizedChannel): string {
        writable('channels.upsert');
        checkedMsat(channel.capacityMsat, 'capacityMsat');
        return immediate(db, () => upsertChannelRow(db, channel));
      },
    },

    snapshots: {
      record(channelId: string, channel: NormalizedChannel): void {
        writable('snapshots.record');
        const values = snapshotValues(channel);
        run(() => {
          db.prepare(INSERT_SNAPSHOT).run(channelId, ...values);
        });
      },

      storeAll(channels: readonly NormalizedChannel[]): string[] {
        writable('snapshots.storeAll');
        const rows = channels.map(channel => {
          checkedMsat(channel.capacityMsat, 'capacityMsat');
          return { channel, values: snapshotValues(channel) };
        });
        return immediate(db, () => {
          const insert = db.prepare(INSERT_SNAPSHOT);
          return rows.map(({ channel, values }) => {
            const id = upsertChannelRow(db, channel);
            insert.run(id, ...values);
            let active = true;
            const tx = ledgerTransaction(db, newUlid, () => active);
            try {
              // MySQL: same
              const node = db.prepare('SELECT name FROM nodes WHERE id = ?').get(channel.nodeId);
              if (node === undefined) throw new Error('a snapshot has no node');
              postOpening(tx, { node: textColumn(node, 'name'), channel: channel.channelKey, channelId: id });
            } finally { active = false; }
            return id;
          });
        });
      },

      latest(channelId: string): SnapshotRow | null {
        return run(() => {
          // MySQL: same
          const row = db.prepare(`SELECT channel_id, observed_at, block_height, local_msat, remote_msat, spendable_msat, receivable_msat,
              pending_out_msat, pending_in_msat, pending_htlc_count, confidence, provenance_json
            FROM channel_snapshots WHERE channel_id = ? ORDER BY id DESC LIMIT 1`).get(channelId);
          if (row === undefined) return null;
          const confidence = textColumn(row, 'confidence');
          if (confidence !== 'NODE_REPORTED' && confidence !== 'DERIVED_ESTIMATE') throw new Error('confidence is not a known tag');
          return {
            channelId: textColumn(row, 'channel_id'),
            observedAt: numberColumn(row, 'observed_at'),
            blockHeight: numberColumn(row, 'block_height'),
            localMsat: bigintColumn(row, 'local_msat'),
            remoteMsat: bigintColumn(row, 'remote_msat'),
            spendableMsat: bigintColumn(row, 'spendable_msat'),
            receivableMsat: bigintColumn(row, 'receivable_msat'),
            pendingOutMsat: bigintColumn(row, 'pending_out_msat'),
            pendingInMsat: bigintColumn(row, 'pending_in_msat'),
            pendingHtlcCount: numberColumn(row, 'pending_htlc_count'),
            confidence,
            provenance: readProvenance(textColumn(row, 'provenance_json')),
          };
        });
      },

      ageMs(channelId: string): number | null {
        return run(() => {
          // MySQL: TIMESTAMPDIFF(MICROSECOND, observed_at, NOW(6)) DIV 1000 in place of the subtraction
          const row = db.prepare(`SELECT ${DB_NOW} - observed_at AS age_ms FROM channel_snapshots
            WHERE channel_id = ? ORDER BY observed_at DESC, id DESC LIMIT 1`).get(channelId);
          if (row === undefined) return null;
          const age = numberColumn(row, 'age_ms');
          // A snapshot stamped after the database clock (the host clock stepped back) has no trustworthy age;
          // it reads as too old for any freshness bound.
          return age < 0 ? Number.POSITIVE_INFINITY : age;
        });
      },
    },

    transaction<T>(work: (tx: Transaction) => T): T {
      writable('transaction');
      let open = true;
      const tx = ledgerTransaction(db, newUlid, () => open);
      try {
        return immediate(db, () => work(tx));
      } finally {
        open = false;
      }
    },

    ledger: {
      journals: () => run(() => readJournals(db)),
      balances: () => run(() => readBalances(db)),
      executions: () => run(() => readExecutions(db)),
      book: () => run(() => snapshot(db, () => readBook(db))),
    },
  };
}
