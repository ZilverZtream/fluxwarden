// Adapted from ZilverZtream/macwarden examples/payment-lab/src/ledger/verify.ts (25bbfa4).
import type { ExecutionRecord, StoredJournal } from '../core/ledger.js';
import { MAX_INT64 } from '../core/money.js';
import { CLEARING_INFLIGHT, CLEARING_UNASSIGNED, EXPENSE_ROUTING_FEES, isKnownAccount, RECON_DIFFERENCE } from './accounts.js';
import { amountOn, channelDebits, ruleViolation } from './rules.js';

/** How the book disagrees with the execution records (step 3). */
export type RecordReason =
  | 'UNKNOWN_EXECUTION'      // a journal names an execution that has no record
  | 'MISSING_JOURNAL'        // a journal the execution's status requires is absent
  | 'UNEXPECTED_JOURNAL'     // a journal the execution's status excludes
  | 'AMOUNT_MISMATCH';       // a journal amount differs from the recorded principal or fees

/** A finding of ledger verification; any finding is an invariant breach. */
export type VerifyFailure =
  | { readonly step: 'journal-balanced'; readonly journalId: string; readonly eventType: string; readonly reference: string }
  | { readonly step: 'orphan-lines'; readonly journalId: string }
  | { readonly step: 'stored-balance'; readonly account: string; readonly stored: bigint | null; readonly recomputed: bigint }
  | { readonly step: 'execution-records'; readonly executionId: string; readonly reason: RecordReason };

export interface VerifyReport {
  readonly ok: boolean;
  readonly failures: VerifyFailure[];
}

export interface VerifyInput {
  readonly journals: readonly StoredJournal[];
  /** Stored balances; null where the stored text is unreadable. */
  readonly balances: ReadonlyMap<string, bigint | null>;
  readonly executions: readonly ExecutionRecord[];
  /** Journal ids that lines refer to but no journal row holds. */
  readonly orphanJournalIds?: readonly string[];
}

function wellFormed(journal: StoredJournal): boolean {
  let debits = 0n;
  let credits = 0n;
  for (const [index, line] of journal.lines.entries()) {
    if (line.sequenceNo !== index + 1 || !isKnownAccount(line.account)) return false;
    if ((line.debitMsat === 0n) === (line.creditMsat === 0n)) return false;
    const amount = line.debitMsat !== 0n ? line.debitMsat : line.creditMsat;
    if (amount < 1n || amount > MAX_INT64) return false;
    if (line.debitMsat !== 0n) debits += amount;
    else credits += amount;
  }
  return debits === credits && ruleViolation(journal) === null;
}

const REBALANCE_EVENTS = ['REBALANCE_SENT', 'REBALANCE_SETTLED', 'REBALANCE_REVERSED'] as const;
type RebalanceEvent = (typeof REBALANCE_EVENTS)[number];

/** The rebalance journals an execution status requires, given those posted; any other one is unexpected (SPEC §8.2, §9.5). */
function required(status: string, posted: ReadonlySet<RebalanceEvent>): readonly RebalanceEvent[] {
  switch (status) {
    case 'IN_FLIGHT': return ['REBALANCE_SENT'];
    case 'UNKNOWN': return posted.has('REBALANCE_SENT') ? ['REBALANCE_SENT'] : [];
    case 'VERIFIED_SUCCESS': return ['REBALANCE_SENT', 'REBALANCE_SETTLED'];
    case 'VERIFIED_FAILURE': return posted.has('REBALANCE_SENT') || posted.has('REBALANCE_REVERSED') ? ['REBALANCE_SENT', 'REBALANCE_REVERSED'] : [];
    default: return [];
  }
}

/** Whether the journals' amounts disagree with the record; figures the record lacks are not compared. */
function amountsDiffer(record: ExecutionRecord, events: ReadonlyMap<RebalanceEvent, StoredJournal>, journals: readonly StoredJournal[]): boolean {
  const { principalMsat: principal, routeFeeMsat: routeFee, actualFeeMsat: actualFee } = record;
  const settled = events.get('REBALANCE_SETTLED');
  if (principal !== null && routeFee !== null) {
    for (const journal of events.values()) {
      if (amountOn(journal.lines, CLEARING_INFLIGHT) !== principal + routeFee) return true;
    }
  }
  if (settled !== undefined) {
    if (principal !== null && channelDebits(settled.lines) + amountOn(settled.lines, CLEARING_UNASSIGNED) !== principal) return true;
    const corrections = journals.filter(j => j.eventType === 'RECON_DIFFERENCE' && j.executionId === record.id && j.reference === `fee-reported:${record.id}`);
    let feeCorrection = 0n;
    for (const correction of corrections) {
      const expense = correction.lines.find(line => line.account === EXPENSE_ROUTING_FEES);
      const suspense = correction.lines.find(line => line.account === RECON_DIFFERENCE);
      if (correction.lines.length !== 2 || expense === undefined || suspense === undefined || expense.debitMsat <= 0n ||
          expense.creditMsat !== 0n || suspense.debitMsat !== 0n || suspense.creditMsat !== expense.debitMsat) return true;
      feeCorrection += expense.debitMsat;
    }
    const expensed = amountOn(settled.lines, EXPENSE_ROUTING_FEES) + feeCorrection;
    if (actualFee === null ? record.status === 'VERIFIED_SUCCESS' && expensed !== 0n : expensed !== actualFee) return true;
  }
  return false;
}

/** Step 3: the rebalance journals agree with the execution records; at most one finding per execution and reason. */
function checkRecords(journals: readonly StoredJournal[], executions: readonly ExecutionRecord[]): VerifyFailure[] {
  const seen = new Set<string>();
  const failures: VerifyFailure[] = [];
  const finding = (executionId: string, reason: RecordReason): void => {
    const key = `${reason} ${executionId}`;
    if (seen.has(key)) return;
    seen.add(key);
    failures.push({ step: 'execution-records', executionId, reason });
  };
  const records = new Map(executions.map(record => [record.id, record]));
  const byExecution = new Map<string, Map<RebalanceEvent, StoredJournal>>();
  for (const journal of journals) {
    const event = REBALANCE_EVENTS.find(name => name === journal.eventType);
    const executionId = journal.executionId ?? (event === undefined ? null : journal.reference);
    if (executionId === null) continue;
    if (!records.has(executionId)) {
      finding(executionId, 'UNKNOWN_EXECUTION');
      continue;
    }
    if (event === undefined) continue;
    const events = byExecution.get(executionId) ?? new Map<RebalanceEvent, StoredJournal>();
    events.set(event, journal);
    byExecution.set(executionId, events);
  }
  for (const record of executions) {
    const events = byExecution.get(record.id) ?? new Map<RebalanceEvent, StoredJournal>();
    const posted = new Set(events.keys());
    const needed = required(record.status, posted);
    for (const event of REBALANCE_EVENTS) {
      if (posted.has(event) && !needed.includes(event)) finding(record.id, 'UNEXPECTED_JOURNAL');
      if (!posted.has(event) && needed.includes(event)) finding(record.id, 'MISSING_JOURNAL');
    }
    if (amountsDiffer(record, events, journals)) finding(record.id, 'AMOUNT_MISMATCH');
  }
  return failures;
}

/**
 * Step 1: every journal is well formed (a known event type and non-empty reference, sequence numbers 1..n, known
 * accounts, one side per line in 1 … 2^63 − 1, the lines its posting rule prescribes) and balanced in bigint;
 * lines without a journal are named. Step 2: every stored balance is readable and equals the net debit
 * recomputed from all lines; an account without a stored row has a stored balance of 0. Step 3: the rebalance
 * journals match the execution records, journal by journal and amount by amount.
 */
export function verifyLedger(book: VerifyInput): VerifyReport {
  const failures: VerifyFailure[] = [];
  const recomputed = new Map<string, bigint>();
  for (const journal of book.journals) {
    if (!wellFormed(journal)) {
      failures.push({ step: 'journal-balanced', journalId: journal.id, eventType: journal.eventType, reference: journal.reference });
    }
    for (const line of journal.lines) recomputed.set(line.account, (recomputed.get(line.account) ?? 0n) + line.debitMsat - line.creditMsat);
  }
  for (const journalId of book.orphanJournalIds ?? []) failures.push({ step: 'orphan-lines', journalId });
  const accounts = [...new Set([...recomputed.keys(), ...book.balances.keys()])].sort();
  for (const account of accounts) {
    const stored = book.balances.has(account) ? book.balances.get(account) ?? null : 0n;
    const expected = recomputed.get(account) ?? 0n;
    if (stored !== expected) failures.push({ step: 'stored-balance', account, stored, recomputed: expected });
  }
  failures.push(...checkRecords(book.journals, book.executions));
  return { ok: failures.length === 0, failures };
}
