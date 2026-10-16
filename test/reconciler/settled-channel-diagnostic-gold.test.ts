// SPEC 8.4 / 8.7 / 9.2 and SECURITY INV-07/08: a paid observation
// retains its actual channel and balanced journal. Missing baseline evidence
// must remain explicitly pending and produce a reconciliation diagnostic.
import { expect, it } from 'vitest';
import { ScriptedExecutionNode, succeeded } from '../fakes/execution-node.js';
import { fakeChannel } from '../fakes/preflight-node.js';
import { force, IN_PEER, PRINCIPAL } from '../helpers/cp028-executor.js';
import { balances, prepare, ROUTE_FEE, S_BEFORE, T_BEFORE } from '../helpers/cp030-dispatch.js';
import { loadReconciler, reservationState, rowOf, type Alert } from '../helpers/cp030-execution.js';
import { loadLedger } from '../helpers/cp037-ledger.js';

for (const receiver of ['planned-with-baseline', 'actual-without-baseline'] as const) {
  it(`CP-032/REG-SRC005 a reconciled paid ${receiver} receiver retains truthful delta diagnostics`, async () => {
    const r = await prepare(`settled-diagnostic-${receiver}`, { script: () => ({ send: context => {
      context.onDispatched?.();
      return Promise.resolve({ kind: 'AMBIGUOUS', cause: 'ordinary lost payment acknowledgement' });
    } }) });
    expect((await r.run()).exit).toBe(7);
    expect(rowOf(r.path, r.executionId).status).toBe('UNKNOWN');
    force(r.path, r.executionId, { leaseAgoMs: 1_000 });
    const incoming = receiver === 'planned-with-baseline' ? r.base.targetKey : '369435907129344';
    const current = () => [
      ...balances(r.base, S_BEFORE - PRINCIPAL - ROUTE_FEE, T_BEFORE + PRINCIPAL),
      ...(receiver === 'actual-without-baseline' ? [fakeChannel(incoming, IN_PEER, { localBalanceMsat: 400_000_000n })] : []),
    ];
    const node = new ScriptedExecutionNode({ observe: () => Promise.resolve(succeeded(ROUTE_FEE, 1, true, incoming)),
      before: current, after: current, invoiceState: () => Promise.resolve('SETTLED') });
    const alerts: Alert[] = [];
    const db = r.p.openDatabase(r.path, { readOnly: false });
    const { reconcile } = await loadReconciler();
    try {
      const report = await reconcile({ db, adapters: new Map([[r.base.nodeId, node]]), workerId: 'reconciler', leaseMs: 60_000,
        notFoundWindowMs: 120_000, escalateAfterMs: 3_600_000, confirmIntervalMs: 60_000, deltaToleranceMsat: 1_000n,
        alert: alert => { alerts.push(alert); } }, { startup: false });
      expect(rowOf(r.path, r.executionId)).toMatchObject({ status: 'VERIFIED_SUCCESS', actual_fee_msat: 150_000n,
        delta_status: receiver === 'planned-with-baseline' ? 'MATCH' : 'PENDING' });
      expect(reservationState(r.path, r.executionId)).toEqual({ state: 'CONSUMED', consumed: 150_000n });
      const m = await loadLedger();
      const book = m.openDatabase(r.path, { readOnly: true });
      try {
        const settled = book.ledger.journals().filter(j => j.executionId === r.executionId && j.eventType === 'REBALANCE_SETTLED');
        expect(settled).toHaveLength(1);
        expect(settled[0]?.lines.map(line => [line.account, line.debitMsat, line.creditMsat])).toEqual([
          [`channel:lnd-r:${incoming}:local`, 100_000_000n, 0n],
          ['expense:routing_fees', 150_000n, 0n],
          ['clearing:inflight', 0n, 100_150_000n],
        ]);
        expect(m.runLedgerVerify(book).exitCode).toBe(0);
      } finally { book.close(); }
      expect(node.fundMovingCalls()).toEqual([]);
      expect(r.node.count('sendOnRoute')).toBe(1);
      if (receiver === 'actual-without-baseline') {
        expect(report.exit).toBe(9);
        expect(alerts.map(alert => alert.code)).toContain('DELTA_UNVERIFIED');
      } else {
        expect(report.exit).toBe(0);
        expect(alerts).toEqual([]);
      }
    } finally { db.close(); }
  });
}
