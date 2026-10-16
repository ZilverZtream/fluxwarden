export type PersistenceCode =
  | 'SCHEMA_TOO_NEW' | 'SCHEMA_OUTDATED' | 'NOT_FOUND' | 'UNSAFE_PATH' | 'BUSY' | 'OUT_OF_RANGE' | 'READ_ONLY' | 'LEASE_LOST' | 'INVALID_TRANSITION'
  | 'AMBIGUOUS_CHANNEL_IDENTITY';

export class PersistenceError extends Error {
  readonly code: PersistenceCode;

  constructor(code: PersistenceCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'PersistenceError';
    this.code = code;
  }
}

/** SQLite primary result codes for a lock held by another connection (sqlite.org/rescode.html). */
const SQLITE_BUSY = 5;
const SQLITE_LOCKED = 6;

/** Reports a lock that outlasted the busy timeout as BUSY; any other error is passed through unchanged. */
export function translateSqliteError(error: unknown): unknown {
  if (error instanceof PersistenceError || !(error instanceof Error)) return error;
  const errcode = (error as { errcode?: unknown }).errcode;
  if (typeof errcode === 'number' && ((errcode & 0xFF) === SQLITE_BUSY || (errcode & 0xFF) === SQLITE_LOCKED)) {
    return new PersistenceError('BUSY', 'the database is locked by another process and the busy timeout expired', { cause: error });
  }
  return error;
}
