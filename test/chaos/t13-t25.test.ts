// Interface: existing route, executor, ledger and reconciler public ports in test/helpers/.
// SPEC §11.6 T-13..T-25 and SECURITY INV-03..08,10,13..17. Wire anomalies also run in matrix-wire.test.ts.
import { expect, it } from 'vitest';
import { failed, succeeded } from '../fakes/execution-node.js';
import { circularRoute } from '../fakes/preflight-node.js';
import { APPROVAL_KEYS, loadClaim, loadPersistence, policyFor, scratchDb, seedBase, seedProposal } from '../helpers/cp028-executor.js';
import { prepare, settled } from '../helpers/cp030-dispatch.js';
import { reservationState, rowOf, seedExecution } from '../helpers/cp030-execution.js';
import { cancelled, journalTypes, preflight, reconciliation, routeWorld } from '../helpers/chaos-matrix.js';
import { loadLedger } from '../helpers/cp037-ledger.js';

it('CP-034/B1 T-13 a FAILED record with a pending HTLC stays unresolved then settles without reversal', async () => {
  // seedBase's independently declared receiving fixture channel, not inferred
  // from a production route. The final ordinary receipt includes its identity.
  const w = await reconciliation('t13', [failed('FAILURE_REASON_TIMEOUT', 1), succeeded(150_000n, 1, true, '246290604752896')]);
  expect((await w.run()).exit).toBe(7); expect(w.reservation().state).toBe('HELD');
  expect(journalTypes(w.path, w.executionId)).not.toContain('REBALANCE_REVERSED');
  expect((await w.run()).exit).toBe(0); expect(w.row().status).toBe('VERIFIED_SUCCESS');
  expect(journalTypes(w.path, w.executionId)).toEqual(['REBALANCE_SENT', 'REBALANCE_SETTLED']);
  expect(w.node.fundMovingCalls()).toEqual([]);
});

it('CP-034/B1 T-14 already-paid without preimage stays UNKNOWN until evidence for the same hash appears', async () => {
  const w = await reconciliation('t14', [{ kind: 'AMBIGUOUS', cause: 'already paid without a preimage' }, succeeded(150_000n, 1, true, '246290604752896')]);
  expect((await w.run()).exit).toBe(7); expect(w.row().status).toBe('UNKNOWN'); expect(w.row().payment_hash).toBe(w.hash);
  expect((await w.run()).exit).toBe(0); expect(w.row().status).toBe('VERIFIED_SUCCESS'); expect(w.row().payment_hash).toBe(w.hash);
  expect(w.node.named('observePayment').map(c => c.args[0])).toEqual([w.hash, w.hash]);
  expect(w.node.fundMovingCalls()).toEqual([]);
});

it('CP-034/B1 T-15 two workers racing the same hash cause one send and no second invoice', async () => {
  const r = await prepare('t15');
  const outcomes = await Promise.all([r.run(), r.run()]);
  expect(outcomes.filter(o => o.exit === 0)).toHaveLength(1);
  expect(outcomes.filter(o => o.exit === 5 && o.step === 'lease-lost')).toHaveLength(1);
  expect(r.node.count('createInvoice')).toBe(1); expect(r.node.count('sendOnRoute')).toBe(1);
  expect(rowOf(r.path, r.executionId).status).toBe('VERIFIED_SUCCESS');
  expect(journalTypes(r.path, r.executionId)).toEqual(['REBALANCE_SENT', 'REBALANCE_SETTLED']);
});

it('CP-034/B1 T-15 the stored payment hash is globally unique across intents', async () => {
  const p = await loadPersistence(), path = scratchDb('t15-unique'), b = seedBase(p, path), hash = '71'.repeat(32);
  seedExecution(b, { status: 'UNKNOWN', paymentHash: hash, route: circularRoute(b.sourceKey, b.targetKey, 150_000n, 80) });
  expect(() => seedExecution(b, { status: 'UNKNOWN', paymentHash: hash, route: circularRoute(b.sourceKey, b.targetKey, 150_000n, 80) })).toThrow(/UNIQUE constraint failed: executions.payment_hash/);
});

it('CP-034/B1 T-16 startup resolves terminal evidence from the list while stuck rows alert on every pass', async () => {
  const terminal = await reconciliation('t16-done', [succeeded(150_000n)], { status: 'IN_FLIGHT' });
  await terminal.run(true); expect(terminal.row().status).toBe('VERIFIED_SUCCESS');
  expect(terminal.node.named('observePayment').map(c => c.args)).toEqual([[terminal.hash, 'sweep']]);
  expect(terminal.node.fundMovingCalls()).toEqual([]);
  const stuck = await reconciliation('t16-stuck', [{ kind: 'IN_FLIGHT' }], { status: 'IN_FLIGHT', ageMs: 3_700_000 });
  for (let pass = 0; pass < 2; pass += 1) {
    expect((await stuck.run(true)).exit).toBe(7); expect(stuck.reservation().state).toBe('HELD');
    expect(stuck.alerts.filter(a => a.kind === 'stuck-in-flight')).toHaveLength(pass + 1);
  }
  expect(stuck.node.fundMovingCalls()).toEqual([]); expect(stuck.row().payment_hash).toBe(stuck.hash);
});

it('CP-034/B1 T-17 a repeated channel is refused before payment', async () => {
  const w = routeWorld(); const mid = w.route.hops[1]; if (!mid) throw new Error('missing middle hop'); mid.scid = w.constraints.sourceScid;
  expect(await w.validate()).toEqual({ ok: false, code: 'REPEATED_CHANNEL', check: 'V2' });
});

it('CP-034/B1 T-17 the same first and last peer is refused', async () => {
  const w = routeWorld(); w.constraints.inPeer = w.constraints.outPeer;
  const target = w.channels[1]; if (!target) throw new Error('missing target'); target.peerPubkey = w.constraints.outPeer;
  const mid = w.route.hops[1]; if (!mid) throw new Error('missing middle hop'); mid.nodeIdOut = w.constraints.outPeer;
  expect(await w.validate()).toEqual({ ok: false, code: 'SAME_PEER', check: 'V7' });
});

for (const [channel, value, code, check] of [[1, 99_999_999n, 'LAST_HOP_RECEIVABLE', 'V9'], [0, 100_202_100n, 'FIRST_HOP_SPENDABLE', 'V8']] as const) {
  it(`CP-034/B1 T-18 ${code} uses observed available balance rather than graph capacity`, async () => {
    const w = routeWorld(), c = w.channels[channel]; if (!c) throw new Error('missing channel');
    if (channel === 1) c.receivableMsat = value; else c.spendableMsat = value;
    expect(await w.validate()).toEqual({ ok: false, code, check });
  });
}

it('CP-034/B1 T-19 fee includes both base fees and rounds 2021.01 ppm up to 2022', async () => {
  const w = routeWorld(); expect(await w.validate()).toMatchObject({ ok: true, feeMsat: 202_101n, feePpm: 2022n });
  w.constraints.maxFeeMsat = 202_100n;
  expect(await w.validate()).toEqual({ ok: false, code: 'FEE_CEILING_EXCEEDED', check: 'V3' });
});

it('CP-034/B1 T-19 actual fee mismatch posts the actual expense and difference while alerting', async () => {
  const r = await prepare('t19-fee', { script: ({ base }) => ({ send: c => { c.onDispatched?.(); return Promise.resolve(succeeded(180_000n)); }, after: settled(base, 180_000n) }) });
  expect(await r.run()).toEqual({ executionId: r.executionId, exit: 9, step: 'FEE_MISMATCH' });
  expect(r.alerts).toContainEqual({ kind: 'fee-mismatch', executionId: r.executionId, code: 'FEE_MISMATCH' });
  const m = await loadLedger(), db = m.openDatabase(r.path, { readOnly: true });
  try {
    expect(rowOf(r.path, r.executionId).actual_fee_msat).toBe(180_000n);
    const lines = db.ledger.journals().filter(j => j.executionId === r.executionId).flatMap(j => j.lines);
    expect(lines.filter(l => l.account === m.EXPENSE_ROUTING_FEES).reduce((n, l) => n + l.debitMsat - l.creditMsat, 0n)).toBe(180_000n);
    // Extra expense is debited; the reconciliation difference is credited by the same 30,000 msat.
    expect(lines.filter(l => l.account === m.RECON_DIFFERENCE).reduce((n, l) => n + l.debitMsat - l.creditMsat, 0n)).toBe(-30_000n);
  } finally { db.close(); }
});

it('CP-034/B1 T-20 LND padding is included at the three-block boundary', async () => {
  const w = routeWorld(); w.constraints.maxCltvDelta = 134;
  expect(await w.validate()).toEqual({ ok: false, code: 'CLTV_DELTA_UNSAFE', check: 'V5' });
  w.constraints.maxCltvDelta = 135;
  expect(await w.validate()).toMatchObject({ ok: true, cltvDelta: 132, padding: 3 });
});

it('CP-034/B1 T-20 final CLTV cannot exceed the cap even on a direct-peer candidate', async () => {
  const w = routeWorld(); w.constraints.maxCltvDelta = 17;
  expect(await w.validate()).toEqual({ ok: false, code: 'CLTV_DELTA_UNSAFE', check: 'V5' });
});

it('CP-034/B1 T-21 two settled HTLCs alert exit8 and still book the actual movement', async () => {
  const r = await prepare('t21', { script: () => ({ send: c => { c.onDispatched?.(); return Promise.resolve(succeeded(150_000n, 2)); } }) });
  expect(await r.run()).toEqual({ executionId: r.executionId, exit: 8, step: 'SINGLE_PATH_UNAVAILABLE' });
  expect(r.alerts).toContainEqual({ kind: 'INVARIANT_BREACH', executionId: r.executionId, code: 'SINGLE_PATH_UNAVAILABLE' });
  expect(rowOf(r.path, r.executionId).status).toBe('VERIFIED_SUCCESS');
  expect(reservationState(r.path, r.executionId)).toEqual({ state: 'CONSUMED', consumed: 150_000n });
  expect(journalTypes(r.path, r.executionId)).toEqual(['REBALANCE_SENT', 'REBALANCE_SETTLED']);
});

for (const version of ['0.20.1-beta', 'v26.04', 'vendor-custom']) {
  it(`CP-034/B1 T-23 missing required capability for ${version} refuses without approximation`, async () => {
    cancelled(await preflight('t23', () => ({ version, capabilities: new Set(['CHANNEL_READ', 'PAYMENT_READ']) })), 'CAPABILITY_UNSUPPORTED', 3);
  });
}

for (const [name, observation, state, exit] of [['success', succeeded(150_000n, 1, true, '246290604752896'), 'CONSUMED', 0], ['refusal', failed('LOCAL_HTLC_LIMIT'), 'RELEASED', 5], ['pending-fee', { kind: 'IN_FLIGHT' } as const, 'HELD', 7]] as const) {
  it(`CP-034/B1 T-24 ${name} closes or holds the reservation without posting a pending fee`, async () => {
    const r = await prepare(`t24-${name}`, { script: () => ({ send: c => { c.onDispatched?.(); return Promise.resolve(observation); } }) });
    expect((await r.run()).exit).toBe(exit); expect(reservationState(r.path, r.executionId).state).toBe(state);
    if (exit === 7) { expect(rowOf(r.path, r.executionId).actual_fee_msat).toBeNull(); expect(journalTypes(r.path, r.executionId)).toEqual(['REBALANCE_SENT']); }
    expect(r.node.count('sendOnRoute')).toBe(1);
  });
}

it('CP-034/B1 T-24 interrupt before dispatch releases the reservation without any node call', async () => {
  const signal = new AbortController(); signal.abort(); const r = await prepare('t24-interrupt', { signal: signal.signal });
  expect((await r.run()).exit).toBe(6); expect(reservationState(r.path, r.executionId).state).toBe('RELEASED'); expect(r.node.calls).toEqual([]);
});

it('CP-034/B1 T-25 unsynced chain cancels before invoice or send', async () => {
  cancelled(await preflight('t25', () => ({ synced: false })), 'chain-sync');
});

it('CP-034/B1 T-25 a local failure is recorded with cooldown and cannot immediately dispatch again', async () => {
  const r = await prepare('t25-local', { script: () => ({ send: c => { c.onDispatched?.(); return Promise.resolve({ kind: 'FAILED', reason: 'LOCAL_HTLC_LIMIT', local: true, htlcsInFlight: 0 }); } }) });
  expect((await r.run()).exit).toBe(5); expect(rowOf(r.path, r.executionId).error_code).toBe('LOCAL_HTLC_LIMIT');
  const { claimExecution } = await loadClaim(), approval = seedProposal(r.base), policy = policyFor(r.base), db = r.p.openDatabase(r.path, { readOnly: false });
  try { expect(claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'second', leaseMs: 60_000 })).toMatchObject({ ok: false, exit: 5, step: 'COOLDOWN_ACTIVE' }); }
  finally { db.close(); }
  expect(r.node.count('sendOnRoute')).toBe(1);
});
