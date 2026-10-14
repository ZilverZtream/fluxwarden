// Adapted from ZilverZtream/macwarden examples/payment-lab/src/ledger/accounts.ts (25bbfa4).
/**
 * The chart of accounts. Balances are net debit (debits minus credits), whatever the account type.
 *
 * | Account                     | Type     | Meaning                                                              |
 * | --------------------------- | -------- | -------------------------------------------------------------------- |
 * | channel:<node>:<chan>:local | asset    | our local balance in the channel                                     |
 * | clearing:inflight           | asset    | value that left a source channel and has not settled or returned     |
 * | onchain:<node>:wallet       | asset    | the node's on-chain wallet                                           |
 * | equity:opening_balance      | equity   | counterpart of the opening balances                                  |
 * | expense:routing_fees        | expense  | fees paid to forwarding nodes for rebalances                         |
 * | recon:difference            | suspense | differences between the ledger and the node, flagged on every report |
 *
 * The remote balance of a channel is the peer's asset and has no account; inbound capacity is a metric.
 */

export const CLEARING_INFLIGHT = 'clearing:inflight';
export const CLEARING_UNASSIGNED = 'clearing:unassigned';
export const EQUITY_OPENING_BALANCE = 'equity:opening_balance';
export const EXPENSE_ROUTING_FEES = 'expense:routing_fees';
export const RECON_DIFFERENCE = 'recon:difference';

const FIXED: ReadonlySet<string> = new Set([CLEARING_INFLIGHT, CLEARING_UNASSIGNED, EQUITY_OPENING_BALANCE, EXPENSE_ROUTING_FEES, RECON_DIFFERENCE]);

/** A node or channel segment of an account code: printable ASCII without ':' or spaces. */
const SEGMENT = /^[\x21-\x39\x3B-\x7E]+$/;

/** The local balance account of one channel. */
export function channelLocalAccount(node: string, channel: string): string {
  return `channel:${encodeURIComponent(node)}:${encodeURIComponent(channel)}:local`;
}

/** Whether `code` is in the chart: a fixed account, or a channel or wallet account with well-formed segments. */
export function isKnownAccount(code: string): boolean {
  if (FIXED.has(code)) return true;
  const parts = code.split(':');
  if (parts.length === 4) {
    const [kind, node = '', channel = '', side] = parts;
    return kind === 'channel' && side === 'local' && SEGMENT.test(node) && SEGMENT.test(channel);
  }
  if (parts.length === 3) {
    const [kind, node = '', wallet] = parts;
    return kind === 'onchain' && wallet === 'wallet' && SEGMENT.test(node);
  }
  return false;
}
