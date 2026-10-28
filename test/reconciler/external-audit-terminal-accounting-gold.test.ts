// SPEC 8.4 / INV-04/08: confirmed failed payer + deleted receiver invoice
// is closed failure. SPEC 9.4: stable observations have bounded, balanced,
// idempotent financial effects even when two CLN sources disagree.
import { expect, it } from 'vitest';
import { fakeClnAccounting, preimagePair, type ClnAccountingApi } from '../fakes/accounting.js';
import { failed } from '../fakes/execution-node.js';
import { loadSource } from '../helpers/adapter-interfaces.js';
import { force } from '../helpers/cp028-executor.js';
import { prepare } from '../helpers/cp030-dispatch.js';
import { loadReconciler, reservationState, rowOf, type PaymentObservation } from '../helpers/cp030-execution.js';
import { loadLedger, scratchDb, seededLedger, type LedgerDatabase } from '../helpers/cp037-ledger.js';

for (const evidence of ['confirmed-failed', 'in-flight', 'ambiguous'] as const) {
  it(`CP-032/REG-REC002 deleted receiver invoice with ${evidence} payer evidence`, async () => {
    const payer: PaymentObservation = evidence === 'confirmed-failed' ? failed('SENDPAY_FAILED') : evidence === 'in-flight'
      ? { kind: 'IN_FLIGHT' } : { kind: 'AMBIGUOUS', cause: 'ordinary observation unavailable' };
    const r = await prepare(`external-deleted-invoice-${evidence}`, {
      node: { implementation: 'cln' },
      script: () => ({
        send: context => { context.onDispatched?.(); return Promise.resolve({ kind: 'AMBIGUOUS', cause: 'ordinary lost acknowledgement' }); },
        observe: () => Promise.resolve(payer), invoiceState: () => Promise.resolve('NOT_FOUND'), cancel: () => Promise.resolve('NOT_FOUND'),
      }),
    });
    expect((await r.run()).exit).toBe(7);
    const { reconcile } = await loadReconciler();
    const db = r.p.openDatabase(r.path, { readOnly: false });
    try {
      const pass = async () => {
        force(r.path, r.executionId, { leaseAgoMs: 1_000 });
        return await reconcile({ db, adapters: new Map([[r.base.nodeId, r.node]]), workerId: 'reconciler', leaseMs: 60_000,
          notFoundWindowMs: 120_000, escalateAfterMs: 3_600_000, confirmIntervalMs: 1, alert: () => undefined }, { startup: false });
      };
      await pass(); // First CLN FAILED observation cannot establish terminality.
      expect(rowOf(r.path, r.executionId).status).toBe('UNKNOWN');
      expect(reservationState(r.path, r.executionId).state).toBe('HELD');
      await pass(); // Fenced SQLite work has advanced its real clock beyond 1 ms.
      if (evidence === 'confirmed-failed') {
        expect(rowOf(r.path, r.executionId).status).toBe('VERIFIED_FAILURE');
        expect(reservationState(r.path, r.executionId).state).toBe('RELEASED');
        const m = await loadLedger();
        const book = m.openDatabase(r.path, { readOnly: true });
        try {
          const before = book.ledger.journals().filter(j => j.executionId === r.executionId);
          expect(before.filter(j => j.eventType === 'REBALANCE_SENT')).toHaveLength(1);
          expect(before.filter(j => j.eventType === 'REBALANCE_REVERSED')).toHaveLength(1);
          await pass();
          expect(book.ledger.journals().filter(j => j.executionId === r.executionId)).toEqual(before);
          expect(m.runLedgerVerify(book).exitCode).toBe(0);
        } finally { book.close(); }
      } else {
        expect(rowOf(r.path, r.executionId).status).toBe('UNKNOWN');
        expect(reservationState(r.path, r.executionId).state).toBe('HELD');
      }
      expect(r.node.count('sendOnRoute')).toBe(1);
      expect(r.node.count('createInvoice')).toBe(1);
    } finally { db.close(); }
  });
}

interface AccountingCommand {
  runReconcile: (input: {
    db: LedgerDatabase; window: { sinceMs: number; untilMs: number };
    executions: { id: string; node: string; paymentHash: string; status: 'VERIFIED_SUCCESS' }[];
    sources: { node: string; implementation: 'cln'; api: ClnAccountingApi }[]; clock: { now(): number };
  }) => Promise<{ exitCode: number; report: { postedJournalIds: string[]; accounting: { differences: unknown[] } | null } }>;
}

for (const evidence of ['agreeing', 'contradictory'] as const) {
  it(`CP-038/REG-REC003 repeated stable ${evidence} CLN fees do not create recurring economic corrections`, async () => {
    const m = await loadLedger();
    const executionId = 'EXE01K00000000000000000001';
    const principal = 100_000_000n;
    const originalFee = 150_000n;
    const sendPayFee = 200_000n;
    const bookkeeperFee = evidence === 'agreeing' ? sendPayFee : 250_000n;
    const sinceMs = 1_760_000_000_000;
    const db = seededLedger(m, scratchDb(`external-cln-fees-${evidence}`),
      [{ id: executionId, status: 'VERIFIED_SUCCESS', routeFeeMsat: originalFee, actualFeeMsat: originalFee }]);
    try {
      const rebalance = { executionId, node: 'cln-m', sourceChannel: '812x1x0', principalMsat: principal, routeFeeMsat: originalFee };
      db.transaction(tx => {
        m.post(tx, m.sentJournal(rebalance, sinceMs + 1_000));
        m.post(tx, m.settledJournal(rebalance, { settledChannel: '812x2x0', actualFeeMsat: originalFee }, sinceMs + 2_000));
      });
      const cln = await fakeClnAccounting([
        { seed: executionId, partid: 0, status: 'complete', amountMsat: principal, amountSentMsat: principal + sendPayFee, createdAt: sinceMs / 1000 + 1 },
      ], [
        { seed: executionId, partId: 0, feesMsat: bookkeeperFee, debitMsat: principal, creditMsat: 0n, timestamp: sinceMs / 1000 + 2, account: '78'.repeat(32) },
      ]);
      const { runReconcile } = await loadSource<AccountingCommand>('commands/reconcile.ts');
      const run = () => runReconcile({ db, window: { sinceMs, untilMs: sinceMs + 86_400_000 },
        executions: [{ id: executionId, node: 'cln-m', paymentHash: preimagePair(executionId).hash, status: 'VERIFIED_SUCCESS' }],
        sources: [{ node: 'cln-m', implementation: 'cln', api: cln.api }], clock: { now: () => sinceMs + 5_000 } });
      const first = await run();
      if (evidence === 'agreeing') expect(first.report.postedJournalIds).toHaveLength(1);
      const afterFirst = db.ledger.journals();
      for (let pass = 0; pass < 3; pass++) {
        const repeated = await run();
        expect(repeated.report.postedJournalIds).toEqual([]);
        expect(db.ledger.journals()).toEqual(afterFirst);
        if (evidence === 'contradictory') {
          expect(repeated.exitCode).toBe(9);
          expect(repeated.report.accounting?.differences.length).toBeGreaterThan(0);
        }
      }
      expect(m.runLedgerVerify(db).exitCode).toBe(0);
    } finally { db.close(); }
  });
}
