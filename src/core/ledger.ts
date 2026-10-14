/** One journal line: exactly one side is non-zero. */
export interface LedgerLine {
  readonly account: string;
  readonly debitMsat: bigint;
  readonly creditMsat: bigint;
}

/** A journal as it is written: unique on (eventType, reference). */
export interface JournalRecord {
  readonly eventType: string;
  readonly reference: string;
  readonly executionId: string | null;
  /** Unix milliseconds. */
  readonly occurredAt: number;
  readonly lines: readonly LedgerLine[];
}

export interface StoredLine extends LedgerLine {
  readonly sequenceNo: number;
}

export interface StoredJournal {
  readonly id: string;
  readonly executionId: string | null;
  readonly eventType: string;
  readonly reference: string;
  readonly occurredAt: number;
  readonly lines: readonly StoredLine[];
}

/**
 * The write port of one open database transaction. Every method refuses once that transaction has
 * committed or rolled back; `active` tells the caller beforehand.
 */
export interface Transaction {
  readonly active: boolean;
  /**
   * Appends the journal and its lines with sequence numbers 1..n in the given order. When
   * (eventType, reference) is already present nothing is written and the existing journal's id is returned.
   */
  appendJournal(journal: JournalRecord): { readonly inserted: boolean; readonly journalId: string };
  /** The stored journal with this (eventType, reference) and its lines, or null. */
  findJournal(eventType: string, reference: string): StoredJournal | null;
  /** The first snapshot recorded for the channel, with the node name and channel key it belongs to, or null. */
  firstSnapshot(channelId: string): FirstSnapshot | null;
  /** The stored net-debit balance of the account, 0 when it has none. */
  balance(account: string): bigint;
  /** Replaces the stored net-debit balance of the account. */
  setBalance(account: string, balance: bigint): void;
}

export interface FirstSnapshot {
  readonly nodeName: string;
  readonly channelKey: string;
  readonly openingChannelKey?: string;
  readonly localMsat: bigint;
  /** Unix milliseconds. */
  readonly observedAt: number;
}

/** What ledger verification compares the book against: one execution row and the amounts it records. */
export interface ExecutionRecord {
  readonly id: string;
  readonly status: string;
  readonly principalMsat: bigint | null;
  /** The fee of the dispatched route (executions.planned_fee_msat). */
  readonly routeFeeMsat: bigint | null;
  /** The node-reported fee. */
  readonly actualFeeMsat: bigint | null;
}

/** Everything ledger verification reads, from one consistent snapshot of the database. */
export interface LedgerBook {
  readonly journals: readonly StoredJournal[];
  /** Stored balances; null where the stored text is not a canonical decimal. */
  readonly balances: ReadonlyMap<string, bigint | null>;
  /** Journal ids that lines refer to but no journal row holds. */
  readonly orphanJournalIds: readonly string[];
  readonly executions: readonly ExecutionRecord[];
}
