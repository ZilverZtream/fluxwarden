// Interface: runReconcile's existing accounting source port and task-owned ledger database.
import { expect, it } from 'vitest';
import { fakeClnAccounting, preimagePair, type ClnAccountingApi } from '../fakes/accounting.js';
import { loadSource } from '../helpers/adapter-interfaces.js';
import { loadLedger, scratchDb, seededLedger, type LedgerDatabase } from '../helpers/cp037-ledger.js';

interface AccountingCommand {
  readonly runReconcile: (input: { db: LedgerDatabase; window: { sinceMs: number; untilMs: number };
    executions: { id: string; node: string; paymentHash: string; status: 'VERIFIED_SUCCESS' }[];
    sources: { node: string; implementation: 'cln'; api: ClnAccountingApi }[]; clock: { now(): number };
  }) => Promise<{ exitCode: number; report: { postedJournalIds: string[]; accounting: {
    differences: unknown[]; comparisons: { ledgerFeeMsat: bigint; nodeFeeMsat: bigint | null }[];
  } | null } }>;
}

it('CP-038/B3 REG-REC004 repeated agreeing observations compare the corrected current expense without a persistent stale difference', async () => {
  const m = await loadLedger();
  const executionId = 'EXE01K00000000000000000001';
  const principal = 100_000_000n;
  const originalFee = 150_000n;
  const actualFee = 200_000n;
  const sinceMs = 1_760_000_000_000;
  const db = seededLedger(m, scratchDb('corrected-comparison'), [{ id: executionId, status: 'VERIFIED_SUCCESS', routeFeeMsat: originalFee, actualFeeMsat: originalFee }]);
  try {
    const rebalance = { executionId, node: 'cln-m', sourceChannel: '812x1x0', principalMsat: principal, routeFeeMsat: originalFee };
    db.transaction(tx => {
      m.post(tx, m.sentJournal(rebalance, sinceMs + 1_000));
      m.post(tx, m.settledJournal(rebalance, { settledChannel: '812x2x0', actualFeeMsat: originalFee }, sinceMs + 2_000));
    });
    const cln = await fakeClnAccounting([{ seed: executionId, partid: 0, status: 'complete', amountMsat: principal, amountSentMsat: principal + actualFee, createdAt: sinceMs / 1000 + 1 }],
      [{ seed: executionId, partId: 0, feesMsat: actualFee, debitMsat: principal, creditMsat: 0n, timestamp: sinceMs / 1000 + 2, account: '78'.repeat(32) }]);
    const { runReconcile } = await loadSource<AccountingCommand>('commands/reconcile.ts');
    const run = () => runReconcile({ db, window: { sinceMs, untilMs: sinceMs + 86_400_000 },
      executions: [{ id: executionId, node: 'cln-m', paymentHash: preimagePair(executionId).hash, status: 'VERIFIED_SUCCESS' }],
      sources: [{ node: 'cln-m', implementation: 'cln', api: cln.api }], clock: { now: () => sinceMs + 5_000 } });
    const first = await run();
    expect(first.report.postedJournalIds).toHaveLength(1);
    expect(db.ledger.balances().get('expense:routing_fees')).toBe(actualFee);
    const journals = db.ledger.journals();
    for (let i = 0; i < 2; i++) {
      const repeated = await run();
      expect(repeated.exitCode).toBe(0);
      expect(repeated.report.accounting?.differences).toEqual([]);
      expect(repeated.report.accounting?.comparisons).toEqual([
        expect.objectContaining({ ledgerFeeMsat: actualFee, nodeFeeMsat: actualFee }),
        expect.objectContaining({ ledgerFeeMsat: actualFee, nodeFeeMsat: actualFee }),
      ]);
      expect(repeated.report.postedJournalIds).toEqual([]);
      expect(db.ledger.journals()).toEqual(journals);
    }
  } finally { db.close(); }
});
