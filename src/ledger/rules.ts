import { CLEARING_INFLIGHT, CLEARING_UNASSIGNED, EQUITY_OPENING_BALANCE, EXPENSE_ROUTING_FEES, isKnownAccount, RECON_DIFFERENCE } from './accounts.js';
import { EVENT_TYPES, type EventType } from './postings.js';

interface Line {
  readonly account: string;
  readonly debitMsat: bigint;
  readonly creditMsat: bigint;
}

interface Shape {
  readonly eventType: string;
  readonly reference: string;
  readonly executionId: string | null;
  readonly lines: readonly Line[];
}

const EVENTS: ReadonlySet<string> = new Set(EVENT_TYPES);

export function isEventType(value: string): value is EventType {
  return EVENTS.has(value);
}

const isChannelLocal = (account: string): boolean => account.startsWith('channel:') && isKnownAccount(account);
const isDebit = (line: Line): boolean => line.debitMsat > 0n && line.creditMsat === 0n;
const isCredit = (line: Line): boolean => line.creditMsat > 0n && line.debitMsat === 0n;

/** A line kind of a posting rule: which account it posts to and on which side. */
interface Kind {
  readonly matches: (line: Line) => boolean;
  readonly min: number;
  readonly max: number;
}

const kind = (account: (code: string) => boolean, side: ((line: Line) => boolean) | null, min: number, max: number): Kind =>
  ({ matches: line => account(line.account) && (side === null || side(line)), min, max });
const is = (code: string) => (account: string): boolean => account === code;

/** Whether every line matches exactly one kind and each kind occurs between its bounds; line order is free. */
function fits(lines: readonly Line[], kinds: readonly Kind[]): boolean {
  const counts = kinds.map(() => 0);
  for (const line of lines) {
    const index = kinds.findIndex(item => item.matches(line));
    if (index < 0) return false;
    counts[index] = (counts[index] ?? 0) + 1;
  }
  return kinds.every((item, index) => (counts[index] ?? 0) >= item.min && (counts[index] ?? 0) <= item.max);
}

/** Why the journal does not have the lines its posting rule prescribes, or null when it does. */
export function ruleViolation(journal: Shape): string | null {
  const { eventType, reference, executionId, lines } = journal;
  if (!isEventType(eventType)) return 'the event type has no posting rule';
  if (reference.length === 0) return 'the reference is empty';
  switch (eventType) {
    case 'OPENING': {
      if (executionId !== null) return 'an opening belongs to no execution';
      const channel = lines.find(line => isChannelLocal(line.account));
      return channel?.account === reference && fits(lines, [kind(is(reference), isDebit, 1, 1), kind(is(EQUITY_OPENING_BALANCE), isCredit, 1, 1)])
        ? null : 'an opening debits its channel account, the reference, and credits equity';
    }
    case 'REBALANCE_SENT':
      if (executionId !== reference) return 'a rebalance journal is referenced by its execution';
      return fits(lines, [kind(is(CLEARING_INFLIGHT), isDebit, 1, 1), kind(isChannelLocal, isCredit, 1, 1)])
        ? null : 'a send debits clearing and credits the source channel';
    case 'REBALANCE_SETTLED':
      if (executionId !== reference) return 'a rebalance journal is referenced by its execution';
      return fits(lines, [
        kind(account => isChannelLocal(account) || account === CLEARING_UNASSIGNED, isDebit, 1, 1), kind(is(EXPENSE_ROUTING_FEES), isDebit, 0, 1),
        kind(is(CLEARING_INFLIGHT), isCredit, 1, 1), kind(is(RECON_DIFFERENCE), null, 0, 1),
      ]) ? null : 'a settlement debits the settled channel and the fee, credits clearing, and puts any fee difference in recon:difference';
    case 'REBALANCE_REVERSED':
      if (executionId !== reference) return 'a rebalance journal is referenced by its execution';
      return fits(lines, [kind(isChannelLocal, isDebit, 1, 1), kind(is(CLEARING_INFLIGHT), isCredit, 1, 1)])
        ? null : 'a reversal debits the source channel and credits clearing';
    case 'RECON_DIFFERENCE':
      return lines.some(line => line.account === RECON_DIFFERENCE) ? null : 'a reconciliation difference posts to recon:difference';
  }
}

/** The total of the lines on `account`, either side. */
export function amountOn(lines: readonly Line[], account: string): bigint {
  return lines.filter(line => line.account === account).reduce((sum, line) => sum + line.debitMsat + line.creditMsat, 0n);
}

/** The total debited to channel local accounts. */
export function channelDebits(lines: readonly Line[]): bigint {
  return lines.filter(line => isChannelLocal(line.account)).reduce((sum, line) => sum + line.debitMsat, 0n);
}
