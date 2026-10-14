import { randomBytes } from 'node:crypto';
import type { DatabaseSync, SQLOutputValue } from 'node:sqlite';
import { PersistenceError, translateSqliteError } from './errors.js';

export const MAX_INT64 = 2n ** 63n - 1n;

/**
 * The database clock in unix milliseconds. One host clock read inside SQL, so a process with a wrong clock
 * cannot move stored times. MySQL: NOW(6).
 */
export const DB_NOW = "CAST(ROUND((julianday('now') - 2440587.5) * 86400000) AS INTEGER)";

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** A ULID: 48-bit millisecond time and 80 random bits in Crockford base32. */
export function newUlid(): string {
  let time = BigInt(Date.now());
  let text = '';
  for (let i = 0; i < 10; i += 1) {
    text = (CROCKFORD[Number(time & 31n)] ?? '0') + text;
    time >>= 5n;
  }
  let random = BigInt(`0x${randomBytes(10).toString('hex')}`);
  let tail = '';
  for (let i = 0; i < 16; i += 1) {
    tail = (CROCKFORD[Number(random & 31n)] ?? '0') + tail;
    random >>= 5n;
  }
  return text + tail;
}

export function checkedMsat(value: unknown, what: string): bigint {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_INT64) {
    throw new PersistenceError('OUT_OF_RANGE', `${what} is outside 0 to 2^63 - 1 msat`);
  }
  return value;
}

export function checkedCount(value: unknown, what: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new PersistenceError('OUT_OF_RANGE', `${what} is not a non-negative integer`);
  }
  return value;
}

export function bigintColumn(row: Record<string, SQLOutputValue>, key: string): bigint {
  const value = row[key];
  if (typeof value !== 'bigint') throw new Error(`column ${key} is not an integer`);
  return value;
}

export function numberColumn(row: Record<string, SQLOutputValue>, key: string): number {
  const value = bigintColumn(row, key);
  if (value > BigInt(Number.MAX_SAFE_INTEGER) || value < BigInt(Number.MIN_SAFE_INTEGER)) throw new Error(`column ${key} is out of range`);
  return Number(value);
}

export function textColumn(row: Record<string, SQLOutputValue>, key: string): string {
  const value = row[key];
  if (typeof value !== 'string') throw new Error(`column ${key} is not text`);
  return value;
}

/** Runs `work` inside BEGIN IMMEDIATE, the single serialisation point for multi-statement writes. */
export function immediate<T>(db: DatabaseSync, work: () => T): T {
  try {
    // MySQL: START TRANSACTION, then SELECT ... FOR UPDATE on the rows the work changes
    db.exec('BEGIN IMMEDIATE');
  } catch (error) {
    throw translateSqliteError(error);
  }
  try {
    const result = work();
    // MySQL: same
    db.exec('COMMIT');
    return result;
  } catch (error) {
    rollback(db);
    throw translateSqliteError(error);
  }
}

/** Ends a failed transaction; SQLite may already have rolled it back itself. */
function rollback(db: DatabaseSync): void {
  if (!db.isTransaction) return;
  try {
    // MySQL: same
    db.exec('ROLLBACK');
  } catch {
    // The original error is the one reported.
  }
}

/** The database clock read once, in unix milliseconds. */
export function dbNow(db: DatabaseSync): number {
  // MySQL: SELECT CAST(UNIX_TIMESTAMP(NOW(6)) * 1000 AS SIGNED) AS now_ms
  const row = db.prepare(`SELECT ${DB_NOW} AS now_ms`).get();
  if (row === undefined) throw new Error('the database clock returned no row');
  return numberColumn(row, 'now_ms');
}
