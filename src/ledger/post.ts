// Adapted from ZilverZtream/macwarden examples/payment-lab/src/ledger/journal.ts (25bbfa4).
import type { StoredJournal, Transaction } from '../core/ledger.js';
import { MAX_INT64 } from '../core/money.js';
import { isKnownAccount, RECON_DIFFERENCE } from './accounts.js';
import { journalsForTransition, openingJournal, type EventType, type ExecutionOutcome, type Journal, type Rebalance } from './postings.js';
import { isEventType, ruleViolation } from './rules.js';

export type LedgerCode = 'UNBALANCED' | 'UNKNOWN_ACCOUNT' | 'OUT_OF_RANGE' | 'MALFORMED' | 'NOT_IN_TRANSACTION' | 'CONFLICT';

export class LedgerError extends Error {
  readonly code: LedgerCode;

  constructor(code: LedgerCode, message: string) {
    super(message);
    this.name = 'LedgerError';
    this.code = code;
  }
}

export interface PostResult {
  readonly posted: boolean;
  readonly journalId: string;
}

/** The net-debit change of every account the journal touches, or a LedgerError for a journal that may not be posted. */
function validate(journal: Journal): Map<string, bigint> {
  const what = `${journal.eventType} ${journal.reference}`;
  if (!isEventType(journal.eventType)) throw new LedgerError('MALFORMED', `${what}: unknown event type`);
  if (typeof journal.reference !== 'string' || journal.reference.length === 0) throw new LedgerError('MALFORMED', `${what}: a journal needs a reference`);
  if (journal.executionId !== null && (typeof journal.executionId !== 'string' || journal.executionId.length === 0)) {
    throw new LedgerError('MALFORMED', `${what}: the execution id is not a string`);
  }
  if (!Number.isSafeInteger(journal.occurredAt) || journal.occurredAt < 0) throw new LedgerError('MALFORMED', `${what}: occurredAt is not a unix millisecond time`);
  if (journal.lines.length === 0) throw new LedgerError('MALFORMED', `${what}: a journal needs lines`);
  let debits = 0n;
  let credits = 0n;
  let debitLines = 0;
  let creditLines = 0;
  const deltas = new Map<string, bigint>();
  for (const line of journal.lines) {
    if (!isKnownAccount(line.account)) throw new LedgerError('UNKNOWN_ACCOUNT', `${what}: account ${JSON.stringify(line.account)} is not in the chart of accounts`);
    if (typeof line.debitMsat !== 'bigint' || typeof line.creditMsat !== 'bigint') throw new LedgerError('MALFORMED', `${what}: amounts are bigint msat`);
    if (line.debitMsat !== 0n && line.creditMsat !== 0n) throw new LedgerError('MALFORMED', `${what}: a line is a debit or a credit, not both`);
    const amount = line.debitMsat !== 0n ? line.debitMsat : line.creditMsat;
    if (amount < 1n || amount > MAX_INT64) throw new LedgerError('OUT_OF_RANGE', `${what}: amount ${amount.toString()} msat is outside 1 to 2^63 - 1`);
    if (line.debitMsat !== 0n) {
      debits += amount;
      debitLines += 1;
    } else {
      credits += amount;
      creditLines += 1;
    }
    deltas.set(line.account, (deltas.get(line.account) ?? 0n) + line.debitMsat - line.creditMsat);
  }
  if (debitLines === 0 || creditLines === 0) throw new LedgerError('MALFORMED', `${what}: a journal needs a debit and a credit line`);
  if (debits !== credits) throw new LedgerError('UNBALANCED', `${what}: debits ${debits.toString()} msat differ from credits ${credits.toString()} msat`);
  const violation = ruleViolation(journal);
  if (violation !== null) throw new LedgerError('MALFORMED', `${what}: ${violation}`);
  return deltas;
}

/** Whether a stored journal records the same event as the offered one: same execution and the same lines in the same order. */
function sameContent(stored: StoredJournal, journal: Journal): boolean {
  return stored.executionId === journal.executionId && stored.lines.length === journal.lines.length &&
    stored.lines.every((line, index) => {
      const offered = journal.lines[index];
      return offered !== undefined && line.account === offered.account && line.debitMsat === offered.debitMsat && line.creditMsat === offered.creditMsat;
    });
}

function requireOpen(tx: Transaction): void {
  if (!tx.active) throw new LedgerError('NOT_IN_TRANSACTION', 'a journal is posted only inside the transaction of the state change it records');
}

/** Refuses a settlement or reversal that the execution's other journals exclude: each needs the send, and they exclude each other. */
function checkSequence(tx: Transaction, journal: Journal): void {
  const other = journal.eventType === 'REBALANCE_SETTLED' ? 'REBALANCE_REVERSED' : journal.eventType === 'REBALANCE_REVERSED' ? 'REBALANCE_SETTLED' : null;
  if (other === null) return;
  const what = `${journal.eventType} ${journal.reference}`;
  if (tx.findJournal('REBALANCE_SENT', journal.reference) === null) throw new LedgerError('CONFLICT', `${what}: the execution has no send journal`);
  if (tx.findJournal(other, journal.reference) !== null) throw new LedgerError('CONFLICT', `${what}: the execution already has ${other}`);
}

/**
 * Posts one balanced journal and moves the stored balances, inside the caller's transaction, so the journal
 * commits or rolls back with the state change it records. A refused journal throws before anything is written,
 * and the caller's transaction rolls back. Posting the same event again changes nothing and returns the existing
 * journal's id with `posted: false`; a different journal under the same (eventType, reference) is a CONFLICT.
 */
export function post(tx: Transaction, journal: Journal): PostResult {
  requireOpen(tx);
  const deltas = validate(journal);
  const existing = tx.findJournal(journal.eventType, journal.reference);
  if (existing !== null) {
    if (!sameContent(existing, journal)) {
      throw new LedgerError('CONFLICT', `${journal.eventType} ${journal.reference}: a different journal is already posted under this reference`);
    }
    return { posted: false, journalId: existing.id };
  }
  checkSequence(tx, journal);
  const { inserted, journalId } = tx.appendJournal(journal);
  if (!inserted) return { posted: false, journalId };
  for (const [account, delta] of deltas) tx.setBalance(account, tx.balance(account) + delta);
  return { posted: true, journalId };
}

/**
 * Posts the opening of a channel as its first recorded snapshot decides it, whatever later snapshots show:
 * Dr channel / Cr equity for that snapshot's local balance. A first balance of 0 posts nothing, then or later,
 * because a zero amount is not a line. Repeated calls replay the same journal.
 */
export function postOpening(tx: Transaction, input: { readonly node: string; readonly channel: string; readonly channelId: string }): { posted: boolean; openingMsat: bigint } {
  requireOpen(tx);
  const first = tx.firstSnapshot(input.channelId);
  if (first === null) throw new LedgerError('MALFORMED', `channel ${input.channelId} has no snapshot to open from`);
  if (first.nodeName !== input.node || first.channelKey !== input.channel) {
    throw new LedgerError('MALFORMED', `channel ${input.channelId} is ${first.nodeName}/${first.channelKey}, not ${input.node}/${input.channel}`);
  }
  const journal = openingJournal({ node: input.node, channel: first.openingChannelKey ?? input.channel, localMsat: first.localMsat, occurredAt: first.observedAt });
  if (journal === null) return { posted: false, openingMsat: 0n };
  return { posted: post(tx, journal).posted, openingMsat: first.localMsat };
}

/** Transfers an existing asset balance without changing the historical opening or introducing equity. */
export function postAccountTransfer(tx: Transaction, input: { from: string; to: string; amount: bigint; reference: string; executionId: string | null; occurredAt: number }): void {
  if (input.amount === 0n) return;
  const amount = input.amount < 0n ? -input.amount : input.amount;
  const from = input.amount < 0n ? input.to : input.from;
  const to = input.amount < 0n ? input.from : input.to;
  const line = (account: string, debitMsat: bigint, creditMsat: bigint) => ({ account, debitMsat, creditMsat });
  post(tx, { eventType: 'RECON_DIFFERENCE', reference: `${input.reference}:release`, executionId: input.executionId, occurredAt: input.occurredAt,
    lines: [line(RECON_DIFFERENCE, amount, 0n), line(from, 0n, amount)] });
  post(tx, { eventType: 'RECON_DIFFERENCE', reference: `${input.reference}:assign`, executionId: input.executionId, occurredAt: input.occurredAt,
    lines: [line(to, amount, 0n), line(RECON_DIFFERENCE, 0n, amount)] });
}

/**
 * Posts the journals of an execution's transition to `to` inside the transition's transaction and lists the
 * event types newly written. Whether the send journal is already posted is read from the ledger in the same
 * transaction, never taken from the caller.
 */
export function postTransition(tx: Transaction, rebalance: Rebalance, to: ExecutionOutcome, occurredAt: number): { posted: EventType[] } {
  requireOpen(tx);
  const sentPosted = tx.findJournal('REBALANCE_SENT', rebalance.executionId) !== null;
  const posted: EventType[] = [];
  for (const journal of journalsForTransition(rebalance, to, sentPosted, occurredAt)) {
    if (post(tx, journal).posted) posted.push(journal.eventType);
  }
  return { posted };
}
