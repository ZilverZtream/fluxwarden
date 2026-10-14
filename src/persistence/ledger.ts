import type { DatabaseSync, SQLOutputValue } from 'node:sqlite';
import type { ExecutionRecord, FirstSnapshot, JournalRecord, LedgerBook, StoredJournal, StoredLine, Transaction } from '../core/ledger.js';

/** A canonical signed decimal as account_balances stores it; it may exceed int64. */
const CANONICAL_DECIMAL = /^(?:0|-?[1-9][0-9]*)$/;

type Row = Record<string, SQLOutputValue>;

function text(row: Row, key: string): string {
  const value = row[key];
  if (typeof value !== 'string') throw new Error(`column ${key} is not text`);
  return value;
}

function optionalText(row: Row, key: string): string | null {
  return row[key] === null ? null : text(row, key);
}

function integer(row: Row, key: string): bigint {
  const value = row[key];
  if (typeof value !== 'bigint') throw new Error(`column ${key} is not an integer`);
  return value;
}

function optionalInteger(row: Row, key: string): bigint | null {
  return row[key] === null ? null : integer(row, key);
}

function safeInteger(row: Row, key: string): number {
  const value = integer(row, key);
  if (value > BigInt(Number.MAX_SAFE_INTEGER) || value < BigInt(Number.MIN_SAFE_INTEGER)) throw new Error(`column ${key} is out of range`);
  return Number(value);
}

/** A stored balance as bigint, or null when its text is not a canonical decimal. */
function readDecimal(value: string): bigint | null {
  return CANONICAL_DECIMAL.test(value) ? BigInt(value) : null;
}

export function parseBalance(value: string): bigint {
  const parsed = readDecimal(value);
  if (parsed === null) throw new Error(`balance ${JSON.stringify(value)} is not a canonical decimal`);
  return parsed;
}

function toLine(row: Row): StoredLine {
  return {
    sequenceNo: safeInteger(row, 'sequence_no'), account: text(row, 'account_code'),
    debitMsat: integer(row, 'debit_msat'), creditMsat: integer(row, 'credit_msat'),
  };
}

function toJournal(row: Row, lines: readonly StoredLine[]): StoredJournal {
  return {
    id: text(row, 'id'), executionId: optionalText(row, 'execution_id'), eventType: text(row, 'event_type'),
    reference: text(row, 'reference'), occurredAt: safeInteger(row, 'occurred_at'), lines,
  };
}

function findJournal(db: DatabaseSync, eventType: string, reference: string): StoredJournal | null {
  // MySQL: same
  const row = db.prepare(`SELECT id, execution_id, event_type, reference, occurred_at FROM ledger_journals
    WHERE event_type = ? AND reference = ?`).get(eventType, reference);
  if (row === undefined) return null;
  // MySQL: same
  const lines = db.prepare(`SELECT sequence_no, account_code, debit_msat, credit_msat FROM ledger_lines
    WHERE journal_id = ? ORDER BY sequence_no`).all(text(row, 'id'));
  return toJournal(row, lines.map(toLine));
}

/**
 * The ledger write port of one open BEGIN IMMEDIATE transaction. `isOpen` reports whether that transaction
 * is still running; every call is refused once it has ended.
 */
export function ledgerTransaction(db: DatabaseSync, newId: () => string, isOpen: () => boolean): Transaction {
  const open = (what: string): void => {
    if (!isOpen() || !db.isTransaction) throw new Error(`${what} needs the transaction that issued it, which has ended`);
  };
  return {
    get active(): boolean {
      return isOpen() && db.isTransaction;
    },

    appendJournal(journal: JournalRecord): { inserted: boolean; journalId: string } {
      open('appendJournal');
      const id = newId();
      // MySQL: INSERT ... ON DUPLICATE KEY UPDATE id = id, which reports 0 affected rows for an existing (event_type, reference)
      const inserted = db.prepare(`INSERT INTO ledger_journals (id, execution_id, event_type, reference, occurred_at)
        VALUES (?, ?, ?, ?, ?) ON CONFLICT (event_type, reference) DO NOTHING`)
        .run(id, journal.executionId, journal.eventType, journal.reference, journal.occurredAt);
      if (Number(inserted.changes) !== 1) {
        const existing = findJournal(db, journal.eventType, journal.reference);
        if (existing === null) throw new Error('a journal insert changed nothing and no journal holds its key');
        return { inserted: false, journalId: existing.id };
      }
      // MySQL: same
      const line = db.prepare('INSERT INTO ledger_lines (journal_id, sequence_no, account_code, debit_msat, credit_msat) VALUES (?, ?, ?, ?, ?)');
      journal.lines.forEach((item, index) => line.run(id, index + 1, item.account, item.debitMsat, item.creditMsat));
      return { inserted: true, journalId: id };
    },

    findJournal(eventType: string, reference: string): StoredJournal | null {
      open('findJournal');
      return findJournal(db, eventType, reference);
    },

    firstSnapshot(channelId: string): FirstSnapshot | null {
      open('firstSnapshot');
      // MySQL: same
      const row = db.prepare(`SELECT n.name, c.channel_key, c.opening_channel_key, s.local_msat, s.observed_at FROM channel_snapshots s
          JOIN channels c ON c.id = s.channel_id JOIN nodes n ON n.id = c.node_id
        WHERE s.channel_id = ? ORDER BY s.id LIMIT 1`).get(channelId);
      return row === undefined ? null : {
        nodeName: text(row, 'name'), channelKey: text(row, 'channel_key'), openingChannelKey: optionalText(row, 'opening_channel_key') ?? text(row, 'channel_key'),
        localMsat: integer(row, 'local_msat'), observedAt: safeInteger(row, 'observed_at'),
      };
    },

    balance(account: string): bigint {
      open('balance');
      // MySQL: same, balance_decimal read as a string
      const row = db.prepare('SELECT balance_decimal FROM account_balances WHERE account_code = ?').get(account);
      return row === undefined ? 0n : parseBalance(text(row, 'balance_decimal'));
    },

    setBalance(account: string, balance: bigint): void {
      open('setBalance');
      // MySQL: INSERT ... ON DUPLICATE KEY UPDATE balance_decimal = VALUES(balance_decimal)
      db.prepare(`INSERT INTO account_balances (account_code, balance_decimal) VALUES (?, ?)
        ON CONFLICT (account_code) DO UPDATE SET balance_decimal = excluded.balance_decimal`).run(account, balance.toString());
    },
  };
}

/** Every journal with its lines in sequence order, journals in the order they occurred, and the ids of lines without a journal. */
function journalsAndOrphans(db: DatabaseSync): { journals: StoredJournal[]; orphanJournalIds: string[] } {
  // MySQL: same
  const lines = db.prepare(`SELECT journal_id, sequence_no, account_code, debit_msat, credit_msat FROM ledger_lines
    ORDER BY journal_id, sequence_no`).all();
  const byJournal = new Map<string, StoredLine[]>();
  for (const row of lines) {
    const journalId = text(row, 'journal_id');
    const list = byJournal.get(journalId) ?? [];
    list.push(toLine(row));
    byJournal.set(journalId, list);
  }
  // MySQL: same
  const rows = db.prepare('SELECT id, execution_id, event_type, reference, occurred_at FROM ledger_journals ORDER BY occurred_at, id').all();
  const journals = rows.map(row => toJournal(row, byJournal.get(text(row, 'id')) ?? []));
  const known = new Set(journals.map(journal => journal.id));
  return { journals, orphanJournalIds: [...byJournal.keys()].filter(id => !known.has(id)).sort() };
}

export function readJournals(db: DatabaseSync): StoredJournal[] {
  return journalsAndOrphans(db).journals;
}

/** Every stored account balance; null where the stored text is not a canonical decimal. */
export function readBalances(db: DatabaseSync): Map<string, bigint | null> {
  // MySQL: same, balance_decimal read as a string
  const rows = db.prepare('SELECT account_code, balance_decimal FROM account_balances ORDER BY account_code').all();
  return new Map(rows.map(row => [text(row, 'account_code'), readDecimal(text(row, 'balance_decimal'))]));
}

/** Every execution row with the principal of its proposal. */
export function readExecutions(db: DatabaseSync): ExecutionRecord[] {
  // MySQL: same
  const rows = db.prepare(`SELECT e.id, e.status, e.planned_fee_msat, e.actual_fee_msat, p.principal_msat
    FROM executions e LEFT JOIN liquidity_proposals p ON p.id = e.proposal_id ORDER BY e.id`).all();
  return rows.map(row => ({
    id: text(row, 'id'), status: text(row, 'status'), principalMsat: optionalInteger(row, 'principal_msat'),
    routeFeeMsat: optionalInteger(row, 'planned_fee_msat'), actualFeeMsat: optionalInteger(row, 'actual_fee_msat'),
  }));
}

/** Everything ledger verification reads. Call it inside one read transaction so the parts agree. */
export function readBook(db: DatabaseSync): LedgerBook {
  const { journals, orphanJournalIds } = journalsAndOrphans(db);
  return { journals, balances: readBalances(db), orphanJournalIds, executions: readExecutions(db) };
}
