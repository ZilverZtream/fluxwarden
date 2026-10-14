// D76, SPEC §9.2/§9.5: observing a previously unreported actual fee debits
// routing expense and credits recon:difference. A balanced journal with those
// directions reversed cannot prove the observed expense, even if amounts match.
import { expect, it } from 'vitest';
import { loadLedger, type JournalLine, type StoredJournal } from '../helpers/cp037-ledger.js';

const executionId = 'EXE01K00000000000000000001';
const principal = 100_000_000n;
const fee = 150_000n;
const line = (account: string, debitMsat: bigint, creditMsat: bigint): JournalLine => ({ account, debitMsat, creditMsat });

function journal(id: string, eventType: string, reference: string, lines: readonly JournalLine[]): StoredJournal {
  return { id, eventType, reference, executionId, occurredAt: 1_000,
    lines: lines.map((entry, index) => ({ ...entry, sequenceNo: index + 1 })) };
}

function book(reversed: boolean) {
  const journals = [
    journal('sent', 'REBALANCE_SENT', executionId, [line('clearing:inflight', principal + fee, 0n), line('channel:lnd-r:123145302376448:local', 0n, principal + fee)]),
    // Original settlement preserves fee uncertainty instead of fabricating an expense.
    journal('settled', 'REBALANCE_SETTLED', executionId, [line('channel:lnd-r:246290604752896:local', principal, 0n),
      line('recon:difference', fee, 0n), line('clearing:inflight', 0n, principal + fee)]),
    journal('fee', 'RECON_DIFFERENCE', `fee-reported:${executionId}`, reversed
      ? [line('recon:difference', fee, 0n), line('expense:routing_fees', 0n, fee)]
      : [line('expense:routing_fees', fee, 0n), line('recon:difference', 0n, fee)]),
  ];
  const balances = new Map<string, bigint>();
  for (const entry of journals) for (const amount of entry.lines) balances.set(amount.account,
    (balances.get(amount.account) ?? 0n) + amount.debitMsat - amount.creditMsat);
  return { journals, balances, executions: [{ id: executionId, status: 'VERIFIED_SUCCESS' as const,
    principalMsat: principal, routeFeeMsat: fee, actualFeeMsat: fee }] };
}

it('CP-037/B5 a balanced reversed fee-report correction fails verification while the exact debit-expense reference passes', async () => {
  const m = await loadLedger();
  expect(m.verifyLedger(book(false))).toEqual({ ok: true, failures: [] });
  const reversed = m.verifyLedger(book(true));
  expect(reversed.ok).toBe(false);
  expect(reversed.failures).toContainEqual({ step: 'execution-records', executionId, reason: 'AMOUNT_MISMATCH' });
});

it('CP-037/B5 a terminal success with an unreported actual fee cannot validate a positive routing expense', async () => {
  // D76's terminal unreported-fee rule must remain strict when the legacy
  // UNKNOWN status-only fixture keeps its distinct null-field semantics.
  const m = await loadLedger();
  const reportedBook = book(false);
  const unreported = m.verifyLedger({ ...reportedBook,
    executions: reportedBook.executions.map(execution => ({ ...execution, actualFeeMsat: null })) });
  expect(unreported.ok).toBe(false);
  expect(unreported.failures).toContainEqual({ step: 'execution-records', executionId, reason: 'AMOUNT_MISMATCH' });
});
