/*
Interface: test/helpers/cp028-executor.ts (claimExecution budget and cooldown admission, Database.executions.transition
reservation side effects, Database.executions.submit). Race workers load dist/executor/claim.js and dist/persistence/index.js.

Rules under test: SPEC §6.6 (worst-case reservation at claim, release, consumption), §7.2 (budget per rolling period,
cooldown_after_failure, cooldown_after_success), §10.3 AE4; SECURITY §4.3 (held reservations of every unresolved
execution count, cooldowns measured from the terminal state's database time), INV-03, INV-13; SPEC §7.1/§7.2 failure
cooldown per channel pair, success cooldown per channel;
SPEC §7.1/§7.2 max_in_flight (executions in SUBMITTING, IN_FLIGHT or UNKNOWN per node) checked again at claim with the
refusal BUDGET_EXHAUSTED (§7.4), and enforced atomically by the PREFLIGHT -> SUBMITTING write.
*/
import { afterEach, expect, it, vi } from 'vitest';
import {
  APPROVAL_KEYS, APPROVED_MAX_FEE, claimed, dbNow, execById, execByProposal, force, loadClaim, loadPersistence, policyFor, raceClaims, reservationsOf,
  preflightWithHash, raceSubmits, scalar, scratchDb, seedBase, seedChannel, seedExecution, seedOtherNode, seedProposal, seedReservation,
  seedTerminal, type ExecutionPolicy,
  type ExecutionStatus,
} from '../helpers/cp028-executor.js';

const LEASE = 60_000;
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

async function setup(prefix: string, budgetMsat: bigint, over: Partial<ExecutionPolicy> = {}) {
  const p = await loadPersistence();
  const { claimExecution } = await loadClaim();
  const path = scratchDb(prefix);
  const base = seedBase(p, path);
  const db = p.openDatabase(path, { readOnly: false });
  const policy = policyFor(base, { budget: { msat: budgetMsat, periodMs: DAY }, ...over });
  const claim = (workerId = 'worker-a', approval = seedProposal(base)) => claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId, leaseMs: LEASE });
  const held = (): bigint => scalar(path, "SELECT coalesce(sum(reserved_msat), 0) AS v FROM budget_reservations WHERE state = 'HELD'");
  return { path, base, db, policy, claim, held, claimExecution };
}

afterEach(() => { vi.useRealTimers(); });

function expectBudgetRefusal(path: string, outcome: ReturnType<Awaited<ReturnType<typeof setup>>['claim']>, step = 'BUDGET_EXHAUSTED'): void {
  expect(outcome.ok).toBe(false);
  if (outcome.ok) return;
  expect({ exit: outcome.exit, step: outcome.step }).toEqual({ exit: 5, step });
  if (outcome.executionId === null) throw new Error('SPEC §6.6: the refused execution is recorded CANCELLED');
  const row = execById(path, outcome.executionId);
  expect(row.status).toBe('CANCELLED');
  expect(row.error_code).toBe(step);
  expect(reservationsOf(path, outcome.executionId).filter(r => r.state !== 'RELEASED')).toEqual([]);
}

it('CP-035/B1 the claim reserves the approved max fee (not the proposal cap) as HELD with a database-clock period start', async () => {
  const { path, claim, db } = await setup('reserve', 2_000_000n);
  try {
    const before = dbNow(path);
    const { executionId } = claimed(claim());
    const after = dbNow(path);
    const [reservation, ...rest] = reservationsOf(path, executionId);
    expect(rest).toEqual([]);
    expect(reservation).toMatchObject({ state: 'HELD', reserved_msat: APPROVED_MAX_FEE, consumed_msat: null });
    expect(Number(reservation?.period_start)).toBeGreaterThanOrEqual(before);
    expect(Number(reservation?.period_start)).toBeLessThanOrEqual(after);
  } finally { db.close(); }
});

it('CP-035/B1 two in-flight attempts cannot both fit a budget of 1.5 x the max fee: the second is BUDGET_EXHAUSTED', async () => {
  const { path, claim, held, db } = await setup('exhaust', (APPROVED_MAX_FEE * 3n) / 2n, { maxInFlight: 100 });
  try {
    const first = claimed(claim());
    force(path, first.executionId, { status: 'IN_FLIGHT' });
    expectBudgetRefusal(path, claim('worker-b'));
    expect(held()).toBe(APPROVED_MAX_FEE);
  } finally { db.close(); }
});

it('CP-035/B1 reservations may reach the budget exactly but not exceed it', async () => {
  const { path, claim, held, db } = await setup('exact', APPROVED_MAX_FEE * 2n);
  try {
    claimed(claim());
    claimed(claim('worker-b'));
    expect(held()).toBe(APPROVED_MAX_FEE * 2n);
    expectBudgetRefusal(path, claim('worker-c'));
    expect(held()).toBe(APPROVED_MAX_FEE * 2n);
  } finally { db.close(); }
});

it('CP-035/B1 two worker processes racing for ten proposals under a budget for five admit exactly five', async () => {
  const p = await loadPersistence();
  const path = scratchDb('budget-race');
  const base = seedBase(p, path);
  const policy = policyFor(base, { budget: { msat: 500_000n, periodMs: DAY } });
  const inputs = Array.from({ length: 10 }, () => ({ approval: seedProposal(base, { approvedMaxFeeMsat: 100_000n }), policy }));
  const results = await raceClaims(path, [
    { workerId: 'worker-a', inputs },
    { workerId: 'worker-b', inputs: [...inputs].reverse() },
  ]);
  const admitted = results.flatMap(r => r.outcomes).filter(o => o.ok);
  expect(admitted).toHaveLength(5);
  expect(scalar(path, "SELECT coalesce(sum(reserved_msat), 0) AS v FROM budget_reservations WHERE state = 'HELD'")).toBe(500_000n);
  expect(scalar(path, "SELECT count(*) AS v FROM executions WHERE status = 'CLAIMED'")).toBe(5n);
  expect(scalar(path, "SELECT count(*) AS v FROM executions WHERE status = 'CANCELLED' AND error_code = 'BUDGET_EXHAUSTED'")).toBe(5n);
  const refusals = results.flatMap(r => r.outcomes).flatMap(o => o.ok ? [] : [o.step]);
  expect(new Set(refusals)).toEqual(new Set(['BUDGET_EXHAUSTED', 'claimed-elsewhere']));
}, 90_000);

it('CP-035/B2 VERIFIED_FAILURE and CANCELLED release the reservation, which frees the budget', async () => {
  const { path, db, claim, held } = await setup('release', APPROVED_MAX_FEE, { cooldownAfterFailureMs: 0 });
  try {
    const failed = claimed(claim());
    force(path, failed.executionId, { status: 'IN_FLIGHT' });
    db.executions.transition(failed.executionId, failed.fenceEpoch, 'IN_FLIGHT', 'VERIFIED_FAILURE');
    expect(reservationsOf(path, failed.executionId).map(r => ({ state: r.state, consumed: r.consumed_msat }))).toEqual([{ state: 'RELEASED', consumed: null }]);
    expect(held()).toBe(0n);

    const cancelled = claimed(claim('worker-b'));
    const epoch = db.executions.transition(cancelled.executionId, cancelled.fenceEpoch, 'CLAIMED', 'PREFLIGHT');
    db.executions.transition(cancelled.executionId, epoch, 'PREFLIGHT', 'CANCELLED', { errorCode: 'STALE_SNAPSHOT' });
    expect(reservationsOf(path, cancelled.executionId).map(r => r.state)).toEqual(['RELEASED']);
    expect(held()).toBe(0n);
    claimed(claim('worker-c'));
  } finally { db.close(); }
});

it('CP-035/B2 success consumes the actual fee, and the budget then counts the actual fee rather than the reservation', async () => {
  const { path, base, db, claimExecution } = await setup('consume', 0n);
  try {
    const policy = (msat: bigint) => policyFor(base, { budget: { msat, periodMs: DAY }, cooldownAfterSuccessMs: 0 });
    const first = claimed(claimExecution(db, { approval: seedProposal(base), policy: policy(APPROVED_MAX_FEE), approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-a', leaseMs: LEASE }));
    force(path, first.executionId, { status: 'IN_FLIGHT' });
    expect(db.executions.transition(first.executionId, first.fenceEpoch, 'IN_FLIGHT', 'VERIFIED_SUCCESS', { actualFeeMsat: 123_456n })).toBe(first.fenceEpoch + 1n);
    expect(reservationsOf(path, first.executionId).map(r => ({ state: r.state, consumed: r.consumed_msat }))).toEqual([{ state: 'CONSUMED', consumed: 123_456n }]);
    expect(execById(path, first.executionId).actual_fee_msat).toBe(123_456n);

    expectBudgetRefusal(path, claimExecution(db, { approval: seedProposal(base), policy: policy(123_456n + APPROVED_MAX_FEE - 1n), approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-b', leaseMs: LEASE }));
    claimed(claimExecution(db, { approval: seedProposal(base), policy: policy(123_456n + APPROVED_MAX_FEE), approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-c', leaseMs: LEASE }));
  } finally { db.close(); }
});

it('CP-035/B2 an actual fee above the reservation is consumed in full and never refused after the fact', async () => {
  const { path, db, claim } = await setup('overrun', 2_000_000n);
  try {
    const x = claimed(claim());
    force(path, x.executionId, { status: 'IN_FLIGHT' });
    db.executions.transition(x.executionId, x.fenceEpoch, 'IN_FLIGHT', 'VERIFIED_SUCCESS', { actualFeeMsat: 250_000n });
    expect(execById(path, x.executionId).status).toBe('VERIFIED_SUCCESS');
    expect(reservationsOf(path, x.executionId).map(r => ({ state: r.state, consumed: r.consumed_msat }))).toEqual([{ state: 'CONSUMED', consumed: 250_000n }]);
  } finally { db.close(); }
});

it('CP-035/B2 an execution that becomes UNKNOWN keeps its reservation HELD', async () => {
  const { path, db, claim, held } = await setup('unknown', 2_000_000n);
  try {
    const x = claimed(claim());
    force(path, x.executionId, { status: 'IN_FLIGHT' });
    db.executions.transition(x.executionId, x.fenceEpoch, 'IN_FLIGHT', 'UNKNOWN');
    expect(reservationsOf(path, x.executionId).map(r => r.state)).toEqual(['HELD']);
    expect(held()).toBe(APPROVED_MAX_FEE);
  } finally { db.close(); }
});

const cooldownCases = [
  { status: 'VERIFIED_FAILURE', agoMs: 59 * 60_000, refused: true },
  { status: 'VERIFIED_FAILURE', agoMs: 61 * 60_000, refused: false },
  { status: 'VERIFIED_SUCCESS', agoMs: 29 * 60_000, refused: true },
  { status: 'VERIFIED_SUCCESS', agoMs: 31 * 60_000, refused: false },
  { status: 'CANCELLED', agoMs: 60_000, refused: false },
] as const;

for (const c of cooldownCases) {
  it(`CP-035/B3 a ${c.status} on the same channel pair ${String(c.agoMs / 60_000)} min ago ${c.refused ? 'refuses the claim with COOLDOWN_ACTIVE' : 'does not block the claim'} (failure 1h, success 30m)`, async () => {
    const { path, base, db, claim } = await setup(`cool-${c.status}-${String(c.agoMs)}`, 2_000_000n);
    try {
      seedTerminal(base, { status: c.status, agoMs: c.agoMs });
      const outcome = claim();
      if (c.refused) expectBudgetRefusal(path, outcome, 'COOLDOWN_ACTIVE');
      else claimed(outcome);
    } finally { db.close(); }
  });
}

it('CP-035/B3 a failure on an unrelated channel pair starts no cooldown for this pair', async () => {
  const { base, db, claim } = await setup('cool-other', 2_000_000n);
  try {
    // A VERIFIED_FAILURE one minute ago on two other channels of the node.
    seedReservation(base, 'RELEASED', 0n, 60_000);
    claimed(claim());
  } finally { db.close(); }
});

it('CP-035/B3 a failure written through the fenced transition starts the cooldown for the next proposal on the pair at once', async () => {
  const { path, db, claim } = await setup('cool-live', 2_000_000n);
  try {
    const x = claimed(claim());
    force(path, x.executionId, { status: 'IN_FLIGHT' });
    db.executions.transition(x.executionId, x.fenceEpoch, 'IN_FLIGHT', 'VERIFIED_FAILURE');
    expectBudgetRefusal(path, claim('worker-b'), 'COOLDOWN_ACTIVE');
  } finally { db.close(); }
});

for (const terminal of ['VERIFIED_SUCCESS', 'CANCELLED'] as const) {
  it(`CP-035/B4 a second execute of the same proposal is refused (exit 5 claimed-elsewhere) after the first ended ${terminal}, with no new reservation`, async () => {
    // SPEC §10.3 AE4 fixes exit 5, step claimed-elsewhere, for an already claimed proposal.
    const { path, base, db, claimExecution, policy } = await setup(`again-${terminal}`, 2_000_000n);
    try {
      const approval = seedProposal(base);
      const x = claimed(claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-a', leaseMs: LEASE }));
      if (terminal === 'VERIFIED_SUCCESS') {
        force(path, x.executionId, { status: 'IN_FLIGHT' });
        db.executions.transition(x.executionId, x.fenceEpoch, 'IN_FLIGHT', 'VERIFIED_SUCCESS', { actualFeeMsat: 1_000n });
      } else {
        db.executions.transition(x.executionId, x.fenceEpoch, 'CLAIMED', 'CANCELLED', { errorCode: 'STALE_SNAPSHOT' });
      }
      const row = execById(path, x.executionId);
      const reservations = reservationsOf(path, x.executionId);
      expect(claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-b', leaseMs: LEASE }))
        .toEqual({ ok: false, exit: 5, step: 'claimed-elsewhere', executionId: x.executionId });
      expect(execById(path, x.executionId)).toEqual(row);
      expect(reservationsOf(path, x.executionId)).toEqual(reservations);
      expect(scalar(path, 'SELECT count(*) AS v FROM budget_reservations')).toBe(1n);
      expect(execByProposal(path, approval.proposalId)?.id).toBe(x.executionId);
    } finally { db.close(); }
  });
}

const windowCases = [
  { name: 'a CONSUMED fee 23 h old counts', state: 'CONSUMED', agoMs: 23 * HOUR, refused: true },
  { name: 'a CONSUMED fee 25 h old is outside the 24 h period', state: 'CONSUMED', agoMs: 25 * HOUR, refused: false },
  { name: 'a HELD reservation 49 h old still counts', state: 'HELD', agoMs: 49 * HOUR, refused: true },
  { name: 'a RELEASED reservation 1 h old does not count', state: 'RELEASED', agoMs: HOUR, refused: false },
] as const;

for (const c of windowCases) {
  it(`CP-035/B5 budget window: ${c.name}`, async () => {
    // Budget 300,000; existing 150,000; new 200,000: 350,000 when the existing amount counts.
    const { path, base, db, claim } = await setup(`window-${c.state}-${String(c.agoMs)}`, 300_000n, { maxInFlight: 100 });
    try {
      seedReservation(base, c.state, 150_000n, c.agoMs);
      const outcome = claim();
      if (c.refused) expectBudgetRefusal(path, outcome);
      else claimed(outcome);
    } finally { db.close(); }
  });
}

it('CP-035/B5 the budget window is measured on the database clock; stepping the worker clock two days either way changes nothing', async () => {
  const realNow = Date.now();
  vi.useFakeTimers({ toFake: ['Date'] });

  vi.setSystemTime(realNow + 2 * DAY);
  const fast = await setup('window-fast', 300_000n);
  try {
    seedReservation(fast.base, 'CONSUMED', 150_000n, HOUR);
    expectBudgetRefusal(fast.path, fast.claim());
  } finally { fast.db.close(); }

  vi.setSystemTime(realNow - 2 * DAY);
  const slow = await setup('window-slow', 300_000n);
  try {
    seedReservation(slow.base, 'CONSUMED', 150_000n, 25 * HOUR);
    const before = dbNow(slow.path);
    const { executionId } = claimed(slow.claim());
    const periodStart = Number(reservationsOf(slow.path, executionId)[0]?.period_start);
    expect(periodStart).toBeGreaterThanOrEqual(before);
    expect(periodStart).toBeLessThanOrEqual(dbNow(slow.path));
  } finally { slow.db.close(); }
});

for (const status of ['SUBMITTING', 'IN_FLIGHT', 'UNKNOWN'] as const) {
  it(`CP-035/B1 with max_in_flight 1, an execution of the same node in ${status} refuses a new claim with BUDGET_EXHAUSTED and a CANCELLED row`, async () => {
    // Ample budget: only the in-flight limit can refuse.
    const { path, base, db, claim } = await setup(`inflight-${status}`, 100_000_000n, { maxInFlight: 1 });
    try {
      seedExecution(base, status);
      expectBudgetRefusal(path, claim());
    } finally { db.close(); }
  });
}

it('CP-035/B1 in-flight executions of another node do not count toward the max_in_flight of this node', async () => {
  const { base, db, claim } = await setup('inflight-other-node', 100_000_000n, { maxInFlight: 1 });
  try {
    const other = seedOtherNode(base);
    for (const status of ['SUBMITTING', 'IN_FLIGHT', 'UNKNOWN'] as const) seedExecution(other, status);
    claimed(claim());
  } finally { db.close(); }
});

it('CP-035/B1 CLAIMED, PREFLIGHT and terminal executions of the same node are not in flight', async () => {
  const { base, db, claim } = await setup('inflight-not', 100_000_000n, { maxInFlight: 1, cooldownAfterFailureMs: 0, cooldownAfterSuccessMs: 0 });
  try {
    const statuses: ExecutionStatus[] = ['CLAIMED', 'PREFLIGHT', 'VERIFIED_SUCCESS', 'VERIFIED_FAILURE', 'CANCELLED'];
    for (const status of statuses) seedExecution(base, status);
    claimed(claim());
  } finally { db.close(); }
});

it('CP-035/B1 max_in_flight is a count: with a limit of 2, one UNKNOWN execution admits the claim and two refuse it', async () => {
  const { path, base, db, claim } = await setup('inflight-two', 100_000_000n, { maxInFlight: 2 });
  try {
    seedExecution(base, 'UNKNOWN');
    claimed(claim());
    seedExecution(base, 'IN_FLIGHT');
    expectBudgetRefusal(path, claim('worker-b'));
  } finally { db.close(); }
});

it('CP-035/B1 two worker processes that both see zero executions in flight are both admitted: a CLAIMED row is not in flight', async () => {
  // SPEC §7.1 counts SUBMITTING, IN_FLIGHT and UNKNOWN only, so concurrent claims under max_in_flight 1 both hold their
  // reservation; nothing has been sent by either.
  const p = await loadPersistence();
  const path = scratchDb('inflight-race');
  const base = seedBase(p, path);
  const policy = policyFor(base, { maxInFlight: 1, budget: { msat: 100_000_000n, periodMs: DAY } });
  const a = { approval: seedProposal(base), policy };
  const b = { approval: seedProposal(base), policy };
  const results = await raceClaims(path, [{ workerId: 'worker-a', inputs: [a] }, { workerId: 'worker-b', inputs: [b] }]);
  expect(results.flatMap(r => r.outcomes).map(o => o.ok)).toEqual([true, true]);
  expect(scalar(path, "SELECT count(*) AS v FROM executions WHERE status = 'CLAIMED'")).toBe(2n);
  expect(scalar(path, "SELECT count(*) AS v FROM budget_reservations WHERE state = 'HELD'")).toBe(2n);
}, 90_000);

// SPEC §7.1 "cooldown_after_success: 30m # per channel", §7.2 "no new proposal touching a channel": a success on S -> T
// blocks every proposal that uses S or T as its source or target. (Per channel also covers SECURITY §4.3's pair.)
const touching = [
  { name: 'S -> U (same source)', pair: (s: string, _t: string, u: string) => [s, u] },
  { name: 'U -> T (same target)', pair: (_s: string, t: string, u: string) => [u, t] },
  { name: 'U -> S (source used as target)', pair: (s: string, _t: string, u: string) => [u, s] },
  { name: 'T -> U (target used as source)', pair: (_s: string, t: string, u: string) => [t, u] },
] as const;

for (const c of touching) {
  it(`CP-035/B3 a VERIFIED_SUCCESS on S -> T 10 min ago refuses a claim on ${c.name} with COOLDOWN_ACTIVE`, async () => {
    const { path, base, db, claim } = await setup(`cool-touch-${c.name.slice(0, 6).replace(/\W/g, '')}`, 2_000_000n);
    try {
      seedTerminal(base, { status: 'VERIFIED_SUCCESS', agoMs: 600_000 });
      const [sourceChannelId, targetChannelId] = c.pair(base.sourceChannelId, base.targetChannelId, seedChannel(base));
      if (sourceChannelId === undefined || targetChannelId === undefined) throw new Error('pair');
      expectBudgetRefusal(path, claim('worker-a', seedProposal(base, { sourceChannelId, targetChannelId })), 'COOLDOWN_ACTIVE');
    } finally { db.close(); }
  });
}

it('CP-035/B3 the per-channel success cooldown ends after cooldown_after_success (31 min ago on S -> T admits S -> U)', async () => {
  const { base, db, claim } = await setup('cool-touch-expired', 2_000_000n);
  try {
    seedTerminal(base, { status: 'VERIFIED_SUCCESS', agoMs: 31 * 60_000 });
    claimed(claim('worker-a', seedProposal(base, { sourceChannelId: base.sourceChannelId, targetChannelId: seedChannel(base) })));
  } finally { db.close(); }
});

it('CP-035/B3 the failure cooldown stays per pair: a VERIFIED_FAILURE on S -> T 10 min ago does not block S -> U', async () => {
  const { base, db, claim } = await setup('cool-fail-pair', 2_000_000n);
  try {
    seedTerminal(base, { status: 'VERIFIED_FAILURE', agoMs: 600_000 });
    claimed(claim('worker-a', seedProposal(base, { sourceChannelId: base.sourceChannelId, targetChannelId: seedChannel(base) })));
  } finally { db.close(); }
});

for (const status of ['VERIFIED_FAILURE', 'VERIFIED_SUCCESS'] as const) {
  it(`CP-035/B3 a ${status} whose terminal time lies after the database clock keeps the cooldown active`, async () => {
    // A database clock stepped back makes now - terminal time negative: that is less than the cooldown, not expired.
    const { path, base, db, claim } = await setup(`cool-future-${status}`, 2_000_000n);
    try {
      seedTerminal(base, { status, agoMs: -600_000 });
      expectBudgetRefusal(path, claim(), 'COOLDOWN_ACTIVE');
    } finally { db.close(); }
  });
}

it('CP-035/B1 submit admits at max_in_flight - 1 other unresolved executions and cancels at max_in_flight with BUDGET_EXHAUSTED, releasing the reservation', async () => {
  const { path, base, db, policy } = await setup('submit-limit', 100_000_000n, { maxInFlight: 2 });
  try {
    const claimModule = await loadClaim();
    seedExecution(base, 'UNKNOWN');
    const first = preflightWithHash(db, claimModule, base, policy);
    const second = preflightWithHash(db, claimModule, base, policy, 'worker-b');
    // One other unresolved execution (UNKNOWN) with a limit of 2: admitted.
    expect(db.executions.submit(first.executionId, first.fenceEpoch, 2, LEASE)).toEqual({ status: 'SUBMITTING', fenceEpoch: first.fenceEpoch + 1n });
    // Now two others (UNKNOWN, SUBMITTING): refused by the same fenced write.
    expect(db.executions.submit(second.executionId, second.fenceEpoch, 2, LEASE)).toEqual({ status: 'CANCELLED', fenceEpoch: second.fenceEpoch + 1n });
    const row = execById(path, second.executionId);
    expect(row.status).toBe('CANCELLED');
    expect(row.error_code).toBe('BUDGET_EXHAUSTED');
    expect(row.fence_epoch).toBe(second.fenceEpoch + 1n);
    expect(reservationsOf(path, second.executionId).map(r => r.state)).toEqual(['RELEASED']);
    expect(scalar(path, 'SELECT count(*) AS v FROM executions WHERE id = ? AND submitted_at IS NOT NULL', second.executionId)).toBe(0n);
  } finally { db.close(); }
});

it('CP-035/B1 submit counts only other unresolved executions of the same node', async () => {
  const { base, db, policy } = await setup('submit-scope', 100_000_000n, { maxInFlight: 1 });
  try {
    const other = seedOtherNode(base);
    for (const status of ['SUBMITTING', 'IN_FLIGHT', 'UNKNOWN'] as const) seedExecution(other, status);
    for (const status of ['CLAIMED', 'PREFLIGHT', 'VERIFIED_SUCCESS', 'VERIFIED_FAILURE', 'CANCELLED'] as const) seedExecution(base, status);
    const x = preflightWithHash(db, await loadClaim(), base, { ...policy, cooldownAfterFailureMs: 0, cooldownAfterSuccessMs: 0 });
    expect(db.executions.submit(x.executionId, x.fenceEpoch, 1, LEASE).status).toBe('SUBMITTING');
  } finally { db.close(); }
});

it('CP-035/B1 two processes submitting admitted claims of one node at once: only max_in_flight (1) reaches SUBMITTING, per node', async () => {
  const p = await loadPersistence();
  const claimModule = await loadClaim();
  const path = scratchDb('submit-race');
  const first = seedBase(p, path);
  const db = p.openDatabase(path, { readOnly: false });
  const left: { executionId: string; fenceEpoch: bigint }[] = [];
  const right: { executionId: string; fenceEpoch: bigint }[] = [];
  const nodes: string[][] = [];
  try {
    for (let i = 0; i < 8; i += 1) {
      const base = i === 0 ? first : seedOtherNode(first);
      const policy = policyFor(base, { maxInFlight: 1, budget: { msat: 100_000_000n, periodMs: DAY } });
      const a = preflightWithHash(db, claimModule, base, policy, 'worker-a');
      const b = preflightWithHash(db, claimModule, base, policy, 'worker-b');
      left.push(a);
      right.push(b);
      nodes.push([a.executionId, b.executionId]);
    }
  } finally { db.close(); }
  const [fromLeft, fromRight] = await raceSubmits(path, 1, [left, right]);
  for (let i = 0; i < 8; i += 1) {
    expect([fromLeft?.[i], fromRight?.[i]].sort(), `node ${String(i)}`).toEqual(['CANCELLED', 'SUBMITTING']);
    const statuses = (nodes[i] ?? []).map(id => execById(path, id).status).sort();
    expect(statuses, `node ${String(i)}`).toEqual(['CANCELLED', 'SUBMITTING']);
  }
  expect(scalar(path, "SELECT count(*) AS v FROM executions WHERE status = 'SUBMITTING'")).toBe(8n);
}, 90_000);

for (const c of [
  { status: 'VERIFIED_FAILURE', agoMs: 61 * 60_000 },
  { status: 'VERIFIED_SUCCESS', agoMs: 31 * 60_000 },
] as const) {
  it(`CP-035/B3 the cooldown runs from the terminal event: a ${c.status} reached ${String(c.agoMs / 60_000)} min ago and written again 1 min ago no longer blocks`, async () => {
    // SECURITY §4.3: measured from the terminal state's database time; a later write to the row (updated_at) does not restart it.
    const { base, db, claim } = await setup(`cool-anchor-${c.status}`, 2_000_000n);
    try {
      seedTerminal(base, { status: c.status, agoMs: c.agoMs, touchedAgoMs: 60_000 });
      claimed(claim());
    } finally { db.close(); }
  });
}
