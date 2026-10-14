// Loaders and fixtures for the ledger tests. Product code is reached through its public modules only. The raw
// connection seeds the execution rows journals refer to (their writer belongs to the executor) and simulates
// someone who writes to the database file directly.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { pathToFileURL } from 'node:url';
import { repoRoot } from './cli.js';
import { channel, NODE_ID, PUBKEY, type SnapshotInput, type SnapshotRow } from './cp015-persistence.js';
import { cloneEmptyDatabaseFixture } from './cp028-executor.js';

export type EventType = 'OPENING' | 'REBALANCE_SENT' | 'REBALANCE_SETTLED' | 'REBALANCE_REVERSED' | 'RECON_DIFFERENCE';
export type LedgerCode = 'UNBALANCED' | 'UNKNOWN_ACCOUNT' | 'OUT_OF_RANGE' | 'MALFORMED' | 'NOT_IN_TRANSACTION' | 'CONFLICT';
export type ExecStatus = 'CLAIMED' | 'PREFLIGHT' | 'SUBMITTING' | 'IN_FLIGHT' | 'VERIFIED_SUCCESS' | 'VERIFIED_FAILURE' | 'UNKNOWN' | 'CANCELLED';

export interface JournalLine { readonly account: string; readonly debitMsat: bigint; readonly creditMsat: bigint }
export interface Journal {
  readonly eventType: string; readonly reference: string; readonly executionId: string | null;
  readonly occurredAt: number; readonly lines: readonly JournalLine[];
}
export interface StoredLine extends JournalLine { readonly sequenceNo: number }
export interface StoredJournal {
  readonly id: string; readonly executionId: string | null; readonly eventType: string; readonly reference: string;
  readonly occurredAt: number; readonly lines: readonly StoredLine[];
}
export interface ExecutionRecord {
  readonly id: string; readonly status: ExecStatus;
  readonly principalMsat: bigint | null; readonly routeFeeMsat: bigint | null; readonly actualFeeMsat: bigint | null;
}
export interface Rebalance {
  readonly executionId: string; readonly node: string; readonly sourceChannel: string;
  readonly principalMsat: bigint; readonly routeFeeMsat: bigint;
}
export type ExecutionOutcome =
  | { readonly status: Exclude<ExecStatus, 'VERIFIED_SUCCESS'> }
  | { readonly status: 'VERIFIED_SUCCESS'; readonly settledChannel: string; readonly actualFeeMsat: bigint };

/** Opaque transaction handle; only the ledger functions use it. */
export type Tx = { readonly __tx?: never };

export interface LedgerDatabase {
  close(): void;
  nodes: { insert(node: { id: string; name: string; implementation: 'lnd' | 'cln'; expectedNetwork: 'regtest'; expectedPubkey: string }): void };
  channels: { upsert(channel: SnapshotInput): string };
  snapshots: { record(channelId: string, channel: SnapshotInput): void; latest(channelId: string): SnapshotRow | null };
  transaction<T>(work: (tx: Tx) => T): T;
  ledger: {
    journals(): StoredJournal[];
    balances(): ReadonlyMap<string, bigint | null>;
    executions(): ExecutionRecord[];
  };
}

export type Step3Reason = 'UNKNOWN_EXECUTION' | 'MISSING_JOURNAL' | 'UNEXPECTED_JOURNAL' | 'AMOUNT_MISMATCH';
export type VerifyFailure =
  | { readonly step: 'journal-balanced'; readonly journalId: string; readonly eventType: string; readonly reference: string }
  | { readonly step: 'stored-balance'; readonly account: string; readonly stored: bigint | null; readonly recomputed: bigint }
  | { readonly step: 'execution-records'; readonly executionId: string; readonly reason: Step3Reason };
export interface VerifyReport { readonly ok: boolean; readonly failures: readonly VerifyFailure[] }
export interface LedgerBook {
  readonly journals: readonly StoredJournal[];
  readonly balances: ReadonlyMap<string, bigint | null>;
  readonly executions: readonly ExecutionRecord[];
}

export interface LedgerModules {
  openDatabase(path: string, options: { readOnly: boolean }): LedgerDatabase;
  CLEARING_INFLIGHT: string; EQUITY_OPENING_BALANCE: string; EXPENSE_ROUTING_FEES: string; RECON_DIFFERENCE: string;
  channelLocalAccount(node: string, channel: string): string;
  isKnownAccount(code: string): boolean;
  openingJournal(input: { node: string; channel: string; localMsat: bigint; occurredAt: number }): Journal | null;
  sentJournal(rebalance: Rebalance, occurredAt: number): Journal;
  settledJournal(rebalance: Rebalance, settle: { settledChannel: string; actualFeeMsat: bigint }, occurredAt: number): Journal;
  reversedJournal(rebalance: Rebalance, occurredAt: number): Journal;
  post(tx: Tx, journal: Journal): { posted: boolean; journalId: string };
  postOpening(tx: Tx, input: { node: string; channel: string; channelId: string }): { posted: boolean; openingMsat: bigint };
  postTransition(tx: Tx, rebalance: Rebalance, to: ExecutionOutcome, occurredAt: number): { posted: EventType[] };
  LedgerError: new (...args: never[]) => Error & { code: LedgerCode };
  verifyLedger(book: LedgerBook): VerifyReport;
  runLedgerVerify(db: LedgerDatabase): { exitCode: 0 | 8; report: VerifyReport };
}

async function load(relative: string): Promise<Record<string, unknown>> {
  return await import(pathToFileURL(join(repoRoot, relative)).href) as Record<string, unknown>;
}

export async function loadLedger(): Promise<LedgerModules> {
  const modules = await Promise.all([
    'src/persistence/index.ts', 'src/ledger/accounts.ts', 'src/ledger/postings.ts', 'src/ledger/post.ts',
    'src/ledger/verify.ts', 'src/commands/ledger.ts',
  ].map(load));
  return Object.assign({}, ...modules) as LedgerModules;
}

export function scratchDb(prefix: string): string {
  return join(mkdtempSync(join(process.env['FLUXWARDEN_TEST_TMP'] ?? tmpdir(), `fw-cp037-${prefix}-`)), 'fluxwarden.db');
}

export function raw(path: string, foreignKeys = true): DatabaseSync {
  return new DatabaseSync(path, { readBigInts: true, enableForeignKeyConstraints: foreignKeys });
}

/** Error code of a thrown error, or undefined when nothing was thrown. */
export function codeOf(run: () => unknown): string | undefined {
  try { run(); } catch (error) {
    const code = (error as { code?: unknown }).code;
    return typeof code === 'string' ? code : `not-coded:${error instanceof Error ? error.message : String(error)}`;
  }
  return undefined;
}

/** The LedgerError code of a refusal; any other error is reported by name so the assertion shows it. */
export function ledgerCodeOf(m: LedgerModules, run: () => unknown): string | undefined {
  try { run(); } catch (error) {
    if (error instanceof m.LedgerError) return error.code;
    return `not-ledger:${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}`;
  }
  return undefined;
}

export const NODE_NAME = 'cln-m';

export interface ExecSeed {
  readonly id: string; readonly status?: ExecStatus;
  readonly principalMsat?: bigint; readonly routeFeeMsat?: bigint; readonly actualFeeMsat?: bigint | null;
}

/**
 * Opens a fresh database with one node and the execution rows journals refer to (SPEC §6.2: ledger_journals.execution_id
 * references executions). Principal lives on the proposal (`principal_msat`), the dispatched route fee on the execution
 * (`planned_fee_msat`), the node-reported fee in `actual_fee_msat`. Defaults: the SPEC §4.4 worked example, CLAIMED.
 */
export function seededLedger(m: LedgerModules, path: string, executions: readonly (string | ExecSeed)[], emptyDatabase?: string): LedgerDatabase {
  if (emptyDatabase !== undefined) cloneEmptyDatabaseFixture(emptyDatabase, path);
  const db = m.openDatabase(path, { readOnly: false });
  db.nodes.insert({ id: NODE_ID, name: NODE_NAME, implementation: 'cln', expectedNetwork: 'regtest', expectedPubkey: PUBKEY });
  if (executions.length > 0) {
    const r = raw(path);
    try {
      r.prepare(`INSERT INTO policy_versions (id, version_no, policy_sha256, policy_canonical_json, author, created_at)
        VALUES ('POL00000000000000000000001', 1, ?, '{}', 'test', 1)`).run('ab'.repeat(32));
      executions.forEach((entry, i) => {
        const e: ExecSeed = typeof entry === 'string' ? { id: entry } : entry;
        const n = String(i).padStart(4, '0');
        r.prepare(`INSERT INTO liquidity_proposals (id, policy_version_id, node_id, action_type, principal_msat, demand_source,
            proposal_digest, reason_json, expires_at, created_at)
          VALUES (?, 'POL00000000000000000000001', ?, 'CIRCULAR_REBALANCE', ?, 'TARGETS', ?, '{}', 1, 1)`)
          .run(`PRO${n}`, NODE_ID, e.principalMsat ?? 100_000_000n, `digest-${n}`);
        r.prepare(`INSERT INTO approvals (id, proposal_id, key_id, nonce, expires_at, signature, max_fee_msat, max_cltv_delta, created_at)
          VALUES (?, ?, 'key', ?, 1, 'sig', 300000, 144, 1)`).run(`APP${n}`, `PRO${n}`, `nonce-${n}`);
        r.prepare(`INSERT INTO executions (id, proposal_id, approval_id, status, planned_fee_msat, actual_fee_msat, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, 1, 1)`)
          .run(e.id, `PRO${n}`, `APP${n}`, e.status ?? 'CLAIMED', e.routeFeeMsat ?? 202_101n, e.actualFeeMsat ?? null);
      });
    } finally { r.close(); }
  }
  return db;
}

/** Moves an execution row the way the executor's fenced writes will. */
export function setExecution(path: string, id: string, status: ExecStatus, actualFeeMsat: bigint | null = null): void {
  const r = raw(path);
  try {
    r.prepare('UPDATE executions SET status = ?, actual_fee_msat = ? WHERE id = ?').run(status, actualFeeMsat, id);
  } finally { r.close(); }
}

/**
 * Writes a journal straight into the file, bypassing post(), and moves account_balances to match, so only the
 * verification step under test can notice it.
 */
export function rawJournal(path: string, id: string, journal: Journal, foreignKeys = true): void {
  const r = raw(path, foreignKeys);
  try {
    r.exec('BEGIN');
    r.prepare('INSERT INTO ledger_journals (id, execution_id, event_type, reference, occurred_at) VALUES (?, ?, ?, ?, ?)')
      .run(id, journal.executionId, journal.eventType, journal.reference, journal.occurredAt);
    journal.lines.forEach((l, i) => {
      r.prepare('INSERT INTO ledger_lines (journal_id, sequence_no, account_code, debit_msat, credit_msat) VALUES (?, ?, ?, ?, ?)')
        .run(id, i + 1, l.account, l.debitMsat, l.creditMsat);
      const row = r.prepare('SELECT balance_decimal AS b FROM account_balances WHERE account_code = ?').get(l.account) as { b: string } | undefined;
      const next = (row === undefined ? 0n : BigInt(row.b)) + l.debitMsat - l.creditMsat;
      r.prepare(`INSERT INTO account_balances (account_code, balance_decimal) VALUES (?, ?)
        ON CONFLICT (account_code) DO UPDATE SET balance_decimal = excluded.balance_decimal`).run(l.account, next.toString());
    });
    r.exec('COMMIT');
  } finally { r.close(); }
}

export function balanceOf(db: LedgerDatabase, account: string): bigint | null {
  const value = db.ledger.balances().get(account);
  return value === undefined ? 0n : value;
}

export { channel };
