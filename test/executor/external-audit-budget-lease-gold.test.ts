// SECURITY 4.3 / SPEC 7.2: actual fees belong to their settlement window;
// unresolved reservations count regardless of age. INV-13/18: elapsed
// database-clock preparation authority cannot renew itself across an await.
import { expect, it } from 'vitest';
import { PAYMENT_SECRET, succeeded } from '../fakes/execution-node.js';
import { FakePreflightNode } from '../fakes/preflight-node.js';
import {
  APPROVAL_KEYS, APPROVED_MAX_FEE, claimed, codeOf, dbNow, eventsOf, execById, execByProposal, force,
  loadClaim, loadPersistence, loadPreflight, policyFor, reservationsOf, scratchDb, seedBase, seedProposal, seedReservation,
} from '../helpers/cp028-executor.js';
import { balances, prepare, ROUTE_FEE, S_BEFORE, T_BEFORE } from '../helpers/cp030-dispatch.js';
import { reservationState, rowOf, sha256 } from '../helpers/cp030-execution.js';

const DAY = 86_400_000;

for (const scenario of ['settled-now', 'still-held', 'settled-long-ago'] as const) {
  it(`CP-035/REG-PERS005 rolling budget distinguishes ${scenario} after a two-day-old claim`, async () => {
    const p = await loadPersistence();
    const { claimExecution } = await loadClaim();
    const path = scratchDb(`external-budget-${scenario}`);
    const base = seedBase(p, path);
    const old = seedReservation(base, scenario === 'settled-long-ago' ? 'CONSUMED' : 'HELD', 150_000n, 2 * DAY);
    const db = p.openDatabase(path, { readOnly: false });
    try {
      if (scenario === 'settled-now') {
        // Ordinary terminal write supplies today's actual fee, although the
        // execution and its reservation were created two rolling periods ago.
        force(path, old, { status: 'IN_FLIGHT' });
        db.executions.transition(old, execById(path, old).fence_epoch, 'IN_FLIGHT', 'VERIFIED_SUCCESS', { actualFeeMsat: 150_000n });
        expect(reservationsOf(path, old)).toMatchObject([{ state: 'CONSUMED', consumed_msat: 150_000n }]);
      }
      const result = claimExecution(db, {
        approval: seedProposal(base), policy: policyFor(base, { budget: { msat: 300_000n, periodMs: DAY }, maxInFlight: 100 }),
        approvalKeyIds: APPROVAL_KEYS, workerId: 'new-worker', leaseMs: 60_000,
      });
      if (scenario === 'settled-long-ago') {
        const admitted = claimed(result);
        expect(reservationsOf(path, admitted.executionId)).toMatchObject([{ state: 'HELD', reserved_msat: APPROVED_MAX_FEE }]);
      } else {
        expect(result).toMatchObject({ ok: false, exit: 5, step: 'BUDGET_EXHAUSTED' });
        if (result.executionId === null) throw new Error('budget refusal must record the refused execution');
        expect(execById(path, result.executionId).status).toBe('CANCELLED');
        expect(reservationsOf(path, result.executionId).filter(r => r.state === 'HELD')).toEqual([]);
      }
    } finally { db.close(); }
  });
}

it('CP-028/REG-EXEC008 an expired preparation lease cannot renew itself with an unchanged fence', async () => {
  const r = await prepare('external-expired-renew');
  force(r.path, r.executionId, { leaseAgoMs: 1_000 });
  const before = execById(r.path, r.executionId);
  const events = eventsOf(r.path, r.executionId);
  const db = r.p.openDatabase(r.path, { readOnly: false });
  try {
    expect(codeOf(() => db.executions.renewLease(r.executionId, before.fence_epoch, 60_000))).toBe('LEASE_LOST');
    expect(execById(r.path, r.executionId)).toEqual(before);
    expect(eventsOf(r.path, r.executionId)).toEqual(events);
    expect(reservationState(r.path, r.executionId)).toEqual({ state: 'HELD', consumed: null });
    expect(r.node.names()).toEqual([]);
  } finally { db.close(); }
});

it('CP-029/REG-EXEC008 preflight cannot revive its expired lease after the ordinary route query awaits', async () => {
  const p = await loadPersistence();
  const { prepareExecution } = await loadPreflight();
  const path = scratchDb('external-preflight-expired-query');
  const base = seedBase(p, path);
  const approval = seedProposal(base);
  const claimId = () => {
    const row = execByProposal(path, approval.proposalId);
    if (row === undefined) throw new Error('preflight must claim before querying a route');
    return row.id;
  };
  let expiry = 0n;
  const node = new FakePreflightNode(base.sourceKey, base.targetKey, { during: { findCircularRoute: () => {
    // Public record query used by the ordinary test helpers; no epoch change
    // and no competing worker: expiration itself must end this authority.
    const executionId = claimId();
    force(path, executionId, { leaseAgoMs: 1_000 });
    expiry = execById(path, executionId).lease_expires_at ?? 0n;
  } } });
  const db = p.openDatabase(path, { readOnly: false });
  try {
    const result = await prepareExecution({ db, adapter: node, workerId: 'worker-a', leaseMs: 60_000 },
      { approval, policy: policyFor(base), approvalKeyIds: APPROVAL_KEYS });
    expect(result).toMatchObject({ kind: 'REFUSED', exit: 5, step: 'lease-lost' });
    expect(execById(path, claimId()).lease_expires_at).toBe(expiry);
    expect(node.mutatingCalls()).toEqual([]);
  } finally { db.close(); }
});

for (const boundary of ['baseline-read', 'invoice-creation'] as const) {
  it(`CP-030/REG-EXEC009 lease expiry during ordinary ${boundary} stops further invoice/send work`, async () => {
    const r = await prepare(`external-lease-${boundary}`, {
      script: ({ base, path, executionId }) => ({
        ...(boundary === 'baseline-read' ? { before: () => {
          force(path, executionId, { leaseAgoMs: 1_000 });
          return balances(base, S_BEFORE, T_BEFORE);
        } } : { invoice: (_amount: bigint, preimage: Uint8Array) => {
          force(path, executionId, { leaseAgoMs: 1_000 });
          return Promise.resolve({ paymentHash: sha256(preimage), paymentSecret: PAYMENT_SECRET, finalCltvDelta: 18 });
        } }),
      }),
    });
    const outcome = await r.run();
    expect(r.node.count('sendOnRoute')).toBe(0);
    expect(r.node.count('createInvoice')).toBe(boundary === 'baseline-read' ? 0 : 1);
    expect(outcome).toMatchObject({ exit: 5, step: 'lease-lost' });
    expect(Number(execById(r.path, r.executionId).lease_expires_at)).toBeLessThan(dbNow(r.path));
  });
}

it('CP-030/REG-EXEC009 a live preparation lease still creates one invoice and dispatches one payment', async () => {
  const r = await prepare('external-lease-valid-control');
  expect(await r.run()).toMatchObject({ exit: 0, step: null });
  expect(r.node.count('createInvoice')).toBe(1);
  expect(r.node.count('sendOnRoute')).toBe(1);
  expect(rowOf(r.path, r.executionId).status).toBe('VERIFIED_SUCCESS');
});

it('CP-030/REG-EXEC009 late confirmed paid evidence still consumes the actual fee after the send lease elapsed', async () => {
  const r = await prepare('external-lease-late-paid-control', {
    script: ({ base, path, executionId }) => ({ send: context => {
      context.onDispatched?.();
      force(path, executionId, { leaseAgoMs: 1_000 });
      return Promise.resolve(succeeded(ROUTE_FEE, 1, true, base.targetKey));
    } }),
  });
  expect(await r.run()).toMatchObject({ exit: 0, step: null });
  expect(rowOf(r.path, r.executionId)).toMatchObject({ status: 'VERIFIED_SUCCESS', actual_fee_msat: 150_000n });
  expect(reservationState(r.path, r.executionId)).toEqual({ state: 'CONSUMED', consumed: 150_000n });
  expect(r.node.count('sendOnRoute')).toBe(1);
  expect(r.node.count('createInvoice')).toBe(1);
  expect(r.node.count('cancelUnpaidInvoice')).toBe(0);
});
