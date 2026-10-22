// INV-08/09: a proven paid principal with unknown incoming channel is an explicit unassigned
// settlement asset. SPEC §8.2/§9.2/§9.5 still require one balanced SETTLED
// journal and exact actual fee. No missing-journal waiver or target guess.
import { expect, it } from 'vitest';
import { succeeded } from '../fakes/execution-node.js';
import { prepare, ROUTE_FEE, S_BEFORE, T_BEFORE, balances } from '../helpers/cp030-dispatch.js';
import { PRINCIPAL } from '../helpers/cp028-executor.js';
import { loadLedger } from '../helpers/cp037-ledger.js';
import { loadReconciler, rowOf } from '../helpers/cp030-execution.js';

it('CP-037/B2 a proven paid unknown incoming principal has a complete balanced terminal journal and a verifiable book without fabricated channel credit', async () => {
  const r = await prepare('external-unassigned-settlement', {
    script: ({ base }) => ({ settledChannelKey: null,
      after: () => balances(base, S_BEFORE - PRINCIPAL - ROUTE_FEE, T_BEFORE) }),
  });
  const outcome = await r.run();
  expect(rowOf(r.path, r.executionId).status).toBe('VERIFIED_SUCCESS');
  expect(outcome.exit).toBe(9);
  const m = await loadLedger();
  const db = m.openDatabase(r.path, { readOnly: true });
  try {
    const settled = db.ledger.journals().filter(j => j.executionId === r.executionId && j.eventType === 'REBALANCE_SETTLED');
    expect(settled).toHaveLength(1);
    expect(settled[0]?.lines.map(line => [line.account, line.debitMsat, line.creditMsat])).toEqual([
      ['clearing:unassigned', 100_000_000n, 0n],
      ['expense:routing_fees', 150_000n, 0n],
      ['clearing:inflight', 0n, 100_150_000n],
    ]);
    expect(db.ledger.balances().get('clearing:unassigned')).toBe(100_000_000n);
    expect(db.ledger.balances().get('clearing:inflight') ?? 0n).toBe(0n);
    expect(settled[0]?.lines.some(line => line.account.startsWith('channel:'))).toBe(false);
    expect(m.runLedgerVerify(db)).toEqual({ exitCode: 0, report: { ok: true, failures: [] } });
  } finally { db.close(); }

  // Terminal success with pending attribution is recovered through the
  // existing public reconciler using read-only observations, never a new send.
  const originalSettled = (() => {
    const book = m.openDatabase(r.path, { readOnly: true });
    try { return book.ledger.journals().filter(j => j.eventType === 'REBALANCE_SETTLED'); }
    finally { book.close(); }
  })();
  const oldSendCount = r.node.count('sendOnRoute');
  const oldInvoiceCount = r.node.count('createInvoice');
  const oldCancelCount = r.node.count('cancelUnpaidInvoice');
  r.node.script.observe = () => Promise.resolve(succeeded(ROUTE_FEE, 1, true, r.base.targetKey));
  r.node.script.after = () => balances(r.base, S_BEFORE - PRINCIPAL - ROUTE_FEE, T_BEFORE + PRINCIPAL);
  const { reconcile } = await loadReconciler();
  const state = r.p.openDatabase(r.path, { readOnly: false });
  try {
    const recover = () => reconcile({ db: state, adapters: new Map([[r.base.nodeId, r.node]]), workerId: 'attribution-recovery',
      leaseMs: 60_000, notFoundWindowMs: 120_000, escalateAfterMs: 3_600_000,
      confirmIntervalMs: 60_000, deltaToleranceMsat: 1_000n, alert: () => undefined }, { startup: false });
    await recover();
    const book = m.openDatabase(r.path, { readOnly: true });
    let recovered;
    try {
      recovered = book.ledger.journals();
      expect(recovered.filter(j => j.eventType === 'REBALANCE_SETTLED')).toEqual(originalSettled);
      expect(book.ledger.balances().get('clearing:unassigned') ?? 0n).toBe(0n);
      expect(book.ledger.balances().get(`channel:lnd-r:${r.base.targetKey}:local`)).toBe(100_000_000n);
      expect(book.ledger.balances().get('expense:routing_fees')).toBe(150_000n);
      expect(m.runLedgerVerify(book).exitCode).toBe(0);
    } finally { book.close(); }
    await recover();
    const replay = m.openDatabase(r.path, { readOnly: true });
    try { expect(replay.ledger.journals()).toEqual(recovered); }
    finally { replay.close(); }
    expect(rowOf(r.path, r.executionId).status).toBe('VERIFIED_SUCCESS');
    expect(r.node.count('sendOnRoute')).toBe(oldSendCount);
    expect(r.node.count('createInvoice')).toBe(oldInvoiceCount);
    expect(r.node.count('cancelUnpaidInvoice')).toBe(oldCancelCount);
  } finally { state.close(); }
}, 60_000);
