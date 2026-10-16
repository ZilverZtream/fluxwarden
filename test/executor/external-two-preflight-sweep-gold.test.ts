// SPEC §6.5 / §10.4 DM4; ARCHITECTURE §8.2; SECURITY INV-13:
// the ordinary adapter-free lease sweep precedes admitted invoice recovery.
import { expect, it } from 'vitest';
import { ScriptedExecutionNode, succeeded } from '../fakes/execution-node.js';
import { circularRoute } from '../fakes/preflight-node.js';
import { loadPersistence, scratchDb, seedBase, ulid, type ExecDatabase } from '../helpers/cp028-executor.js';
import { ROUTE_FEE } from '../helpers/cp030-dispatch.js';
import { exec, labelOf, loadReconciler, reservationState, rowOf, seedExecution, type ExecutionAdapter } from '../helpers/cp030-execution.js';
import { loadSrc } from '../helpers/load-src.js';

interface RecoveryModule {
  readonly recoverPreflight: (deps: { db: ExecDatabase; workerId: string; leaseMs: number;
    adapter?: Pick<ExecutionAdapter, 'invoiceState' | 'cancelUnpaidInvoice'>;
    adapters?: ReadonlyMap<string, Pick<ExecutionAdapter, 'invoiceState' | 'cancelUnpaidInvoice'>>;
  }) => Promise<{ cancelled: readonly string[] }>;
}

for (const state of ['OPEN', 'SETTLED'] as const) {
  it(`CP-029/REG-EXEC014 adapter-free sweep then admitted ${state} invoice recovery`, async () => {
    const p = await loadPersistence();
    const { recoverPreflight } = await loadSrc<RecoveryModule>('executor/preflight.ts');
    const { reconcile } = await loadReconciler();
    const path = scratchDb(`external-two-sweep-${state}`), base = seedBase(p, path);
    const route = circularRoute(base.sourceKey, base.targetKey, ROUTE_FEE, 80);
    const hash = 'b7'.repeat(32);
    const seeded = seedExecution(base, { status: 'PREFLIGHT', paymentHash: hash, leaseInMs: -1_000,
      route, plannedFeeMsat: ROUTE_FEE, proposalOptions: { approvalTtlMs: -1_000, proposalTtlMs: -1_000 } });
    const live = seedExecution(base, { status: 'PREFLIGHT', paymentHash: 'b8'.repeat(32), leaseInMs: 60_000,
      proposalOptions: { approvalTtlMs: -1_000, proposalTtlMs: -1_000 } });
    const unexpired = seedExecution(base, { status: 'PREFLIGHT', paymentHash: 'b9'.repeat(32), leaseInMs: -1_000 });
    const otherNode = ulid();
    exec(path, "INSERT INTO nodes(id,name,implementation,expected_network,expected_pubkey,state) VALUES (?,'other-node','lnd','regtest',?,'ONLINE')", otherNode, `03${'ea'.repeat(32)}`);
    const unrelated = seedExecution(base, { status: 'PREFLIGHT', paymentHash: 'ba'.repeat(32), leaseInMs: -1_000,
      proposalOptions: { approvalTtlMs: -1_000, proposalTtlMs: -1_000 } });
    exec(path, 'UPDATE liquidity_proposals SET node_id = ? WHERE id = ?', otherNode, unrelated.approval.proposalId);
    const controls = [live, unexpired, unrelated].map(x => ({ id: x.executionId, row: rowOf(path, x.executionId), reservation: reservationState(path, x.executionId) }));
    // Existing scripted port cites LND InvoiceRegistry / CLN delinvoice paid-state refusal.
    const node = new ScriptedExecutionNode({ invoiceState: () => Promise.resolve(state),
      cancel: () => Promise.resolve(state === 'OPEN' ? 'CANCELED' : 'ALREADY_PAID'),
      observe: () => Promise.resolve(succeeded(ROUTE_FEE, 1, true, base.targetKey)) });
    const db = p.openDatabase(path, { readOnly: false });
    try {
      await recoverPreflight({ db, workerId: 'ordinary-sweeper', leaseMs: 60_000 });
      expect.soft(rowOf(path, seeded.executionId).status, 'without admitted node evidence the invoice-bearing intent remains recoverable').toBe('PREFLIGHT');
      expect.soft(reservationState(path, seeded.executionId)).toEqual({ state: 'HELD', consumed: null });
      const recovered = await recoverPreflight({ db, adapters: new Map([[base.nodeId, node]]), workerId: 'admitted-recovery', leaseMs: 60_000 });
      if (state === 'OPEN') {
        expect.soft(recovered.cancelled).toEqual([seeded.executionId]);
        expect.soft(rowOf(path, seeded.executionId)).toMatchObject({ status: 'CANCELLED', payment_hash: hash });
        expect.soft(node.named('cancelUnpaidInvoice').map(call => call.args)).toEqual([[hash, labelOf(seeded.executionId)]]);
        expect.soft(reservationState(path, seeded.executionId)).toEqual({ state: 'RELEASED', consumed: null });
      } else {
        await reconcile({ db, adapters: new Map([[base.nodeId, node]]), workerId: 'admitted-recovery', leaseMs: 60_000,
          notFoundWindowMs: 120_000, escalateAfterMs: 3_600_000, confirmIntervalMs: 60_000, alert: () => undefined }, { startup: true });
        expect.soft(rowOf(path, seeded.executionId)).toMatchObject({ status: 'VERIFIED_SUCCESS', payment_hash: hash, actual_fee_msat: ROUTE_FEE });
        expect.soft(reservationState(path, seeded.executionId)).toEqual({ state: 'CONSUMED', consumed: ROUTE_FEE });
      }
      expect.soft(node.count('invoiceState')).toBeGreaterThanOrEqual(1);
      expect.soft(node.count('createInvoice')).toBe(0);
      expect.soft(node.count('sendOnRoute')).toBe(0);
      for (const control of controls) {
        // Unknown-node sweep bookkeeping may fence the unrelated row; no
        // admitted node call or financial transition is authorised for it.
        if (control.id === unrelated.executionId) expect.soft(rowOf(path, control.id)).toMatchObject({
          status: control.row.status, payment_hash: control.row.payment_hash, actual_fee_msat: control.row.actual_fee_msat,
        });
        else expect.soft(rowOf(path, control.id)).toEqual(control.row);
        expect.soft(reservationState(path, control.id)).toEqual(control.reservation);
      }
      expect.soft(node.calls.filter(call => call.args[0] !== hash && call.name !== 'listChannels')).toEqual([]);
    } finally { db.close(); }
  });
}
