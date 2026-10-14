// Adapted from ZilverZtream/macwarden examples/payment-lab/src/ledger/postings.ts (25bbfa4).
import { CLEARING_INFLIGHT, CLEARING_UNASSIGNED, channelLocalAccount, EQUITY_OPENING_BALANCE, EXPENSE_ROUTING_FEES, RECON_DIFFERENCE } from './accounts.js';

/**
 * The posting rules: one builder per event, each returning a balanced journal. The caller posts them
 * inside the transaction of the state change they record. Lines with a zero amount are left out.
 */

export const EVENT_TYPES = ['OPENING', 'REBALANCE_SENT', 'REBALANCE_SETTLED', 'REBALANCE_REVERSED', 'RECON_DIFFERENCE'] as const;
export type EventType = (typeof EVENT_TYPES)[number];

export interface JournalLine {
  readonly account: string;
  readonly debitMsat: bigint;
  readonly creditMsat: bigint;
}

export interface Journal {
  readonly eventType: EventType;
  /** The idempotency key within the event type. */
  readonly reference: string;
  readonly executionId: string | null;
  /** Unix milliseconds. */
  readonly occurredAt: number;
  readonly lines: readonly JournalLine[];
}

/** One circular rebalance of principal P out of source channel S, with the route fee known before dispatch. */
export interface Rebalance {
  readonly executionId: string;
  readonly node: string;
  readonly sourceChannel: string;
  readonly principalMsat: bigint;
  readonly routeFeeMsat: bigint;
}

/** The execution status a transition reaches; a success carries the channel that settled and the fee the node reported. */
export type ExecutionOutcome =
  | { readonly status: 'CLAIMED' | 'PREFLIGHT' | 'SUBMITTING' | 'IN_FLIGHT' | 'UNKNOWN' | 'CANCELLED' | 'VERIFIED_FAILURE' }
  | { readonly status: 'VERIFIED_SUCCESS'; readonly settledChannel: string | null; readonly actualFeeMsat: bigint | null };

const debit = (account: string, msat: bigint): JournalLine => ({ account, debitMsat: msat, creditMsat: 0n });
const credit = (account: string, msat: bigint): JournalLine => ({ account, debitMsat: 0n, creditMsat: msat });
const nonZero = (lines: readonly JournalLine[]): JournalLine[] => lines.filter(line => line.debitMsat !== 0n || line.creditMsat !== 0n);

/** At the first snapshot of a channel: Dr its local balance account / Cr equity. Null for an empty local balance. */
export function openingJournal(input: { readonly node: string; readonly channel: string; readonly localMsat: bigint; readonly occurredAt: number }): Journal | null {
  if (input.localMsat === 0n) return null;
  const account = channelLocalAccount(input.node, input.channel);
  return {
    eventType: 'OPENING', reference: account, executionId: null, occurredAt: input.occurredAt,
    lines: [debit(account, input.localMsat), credit(EQUITY_OPENING_BALANCE, input.localMsat)],
  };
}

/** At IN_FLIGHT: principal and route fee leave the source channel for clearing. */
export function sentJournal(rebalance: Rebalance, occurredAt: number): Journal {
  const total = rebalance.principalMsat + rebalance.routeFeeMsat;
  return {
    eventType: 'REBALANCE_SENT', reference: rebalance.executionId, executionId: rebalance.executionId, occurredAt,
    lines: nonZero([debit(CLEARING_INFLIGHT, total), credit(channelLocalAccount(rebalance.node, rebalance.sourceChannel), total)]),
  };
}

/**
 * At VERIFIED_SUCCESS: the principal arrives in the channel that settled, the node-reported fee is expensed,
 * and clearing gives up what the send put there. A reported fee that differs from the route fee leaves the
 * difference in recon:difference.
 */
export function settledJournal(rebalance: Rebalance, settle: { readonly settledChannel: string | null; readonly actualFeeMsat: bigint | null }, occurredAt: number): Journal {
  const total = rebalance.principalMsat + rebalance.routeFeeMsat;
  const fee = settle.actualFeeMsat ?? 0n;
  const difference = rebalance.routeFeeMsat - fee;
  return {
    eventType: 'REBALANCE_SETTLED', reference: rebalance.executionId, executionId: rebalance.executionId, occurredAt,
    lines: nonZero([
      debit(settle.settledChannel === null ? CLEARING_UNASSIGNED : channelLocalAccount(rebalance.node, settle.settledChannel), rebalance.principalMsat),
      debit(EXPENSE_ROUTING_FEES, fee),
      credit(CLEARING_INFLIGHT, total),
      difference >= 0n ? debit(RECON_DIFFERENCE, difference) : credit(RECON_DIFFERENCE, -difference),
    ]),
  };
}

/** At VERIFIED_FAILURE after a send journal: everything the send moved returns to the source channel. */
export function reversedJournal(rebalance: Rebalance, occurredAt: number): Journal {
  const total = rebalance.principalMsat + rebalance.routeFeeMsat;
  return {
    eventType: 'REBALANCE_REVERSED', reference: rebalance.executionId, executionId: rebalance.executionId, occurredAt,
    lines: nonZero([debit(channelLocalAccount(rebalance.node, rebalance.sourceChannel), total), credit(CLEARING_INFLIGHT, total)]),
  };
}

/**
 * The journals a transition to `to` posts, given whether the send journal is already posted. Nothing is
 * posted while the outcome is pending or unknown; a success whose send journal is missing (a crash between
 * SUBMITTING and IN_FLIGHT) posts the send first, and a failure reverses only a posted send.
 */
export function journalsForTransition(rebalance: Rebalance, to: ExecutionOutcome, sentPosted: boolean, occurredAt: number): Journal[] {
  switch (to.status) {
    case 'IN_FLIGHT':
      return sentPosted ? [] : [sentJournal(rebalance, occurredAt)];
    case 'VERIFIED_SUCCESS': {
      const settled = settledJournal(rebalance, to, occurredAt);
      return sentPosted ? [settled] : [sentJournal(rebalance, occurredAt), settled];
    }
    case 'VERIFIED_FAILURE':
      return sentPosted ? [reversedJournal(rebalance, occurredAt)] : [];
    case 'CLAIMED':
    case 'PREFLIGHT':
    case 'SUBMITTING':
    case 'UNKNOWN':
    case 'CANCELLED':
      return [];
  }
}
