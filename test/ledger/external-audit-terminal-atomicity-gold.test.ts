// SECURITY INV-08, SPEC 9.2 / 9.5: truthful terminal state and its balanced
// required journals are atomic; missing metadata cannot silently omit money.
import { expect, it } from 'vitest';
import { eventsOf, execById, loadPersistence, scratchDb, seedBase } from '../helpers/cp028-executor.js';
import { circularRoute } from '../fakes/preflight-node.js';
import { reservationState, seedExecution, sha256 } from '../helpers/cp030-execution.js';
import { loadLedger } from '../helpers/cp037-ledger.js';

for (const metadata of ['complete', 'no-planned-fee', 'no-route-or-fee'] as const) {
  it(`CP-037/REG-PERS006 terminal success posts required journals or rolls back with ${metadata} metadata`, async () => {
    const p = await loadPersistence();
    const path = scratchDb(`external-atomic-${metadata}`);
    const base = seedBase(p, path);
    const route = circularRoute(base.sourceKey, base.targetKey, 150_000n, 80);
    const { executionId } = seedExecution(base, { status: 'IN_FLIGHT', paymentHash: sha256(new Uint8Array(32)),
      submittedAgoMs: 1_000, route: metadata === 'no-route-or-fee' ? null : route,
      plannedFeeMsat: metadata === 'complete' ? 150_000n : null });
    const before = execById(path, executionId);
    const events = eventsOf(path, executionId);
    const db = p.openDatabase(path, { readOnly: false });
    let rejected = false;
    try {
      try {
        db.executions.transition(executionId, 3n, 'IN_FLIGHT', 'VERIFIED_SUCCESS', {
          actualFeeMsat: 150_000n, settledChannelKey: base.targetKey,
        });
      } catch { rejected = true; }
      if (metadata === 'complete') expect(rejected).toBe(false);
      const m = await loadLedger();
      const book = m.openDatabase(path, { readOnly: true });
      try {
        const journals = book.ledger.journals().filter(j => j.executionId === executionId);
        if (rejected) {
          expect(execById(path, executionId)).toEqual(before);
          expect(eventsOf(path, executionId)).toEqual(events);
          expect(reservationState(path, executionId)).toEqual({ state: 'HELD', consumed: null });
          expect(journals).toEqual([]);
        } else {
          expect(execById(path, executionId)).toMatchObject({ status: 'VERIFIED_SUCCESS', actual_fee_msat: 150_000n });
          expect(journals.filter(j => j.eventType === 'REBALANCE_SENT')).toHaveLength(1);
          expect(journals.filter(j => j.eventType === 'REBALANCE_SETTLED')).toHaveLength(1);
          expect(reservationState(path, executionId)).toEqual({ state: 'CONSUMED', consumed: 150_000n });
          expect(m.runLedgerVerify(book).exitCode).toBe(0);
          for (const journal of journals) expect(journal.lines.reduce((sum, line) => sum + line.debitMsat - line.creditMsat, 0n)).toBe(0n);
        }
      } finally { book.close(); }
    } finally { db.close(); }
  });
}
