/*
Interface: src/planner/plan.ts (pure; imports only src/core and src/planner; time from the injected clock).
Candidate generation only: route discovery and validation come later and consume these candidates.

  import type { Clock, Diagnosis, PlanningPolicy } from './diagnose.js';

  export type RefusalCode =                       // SPEC §7.5
    | 'NO_FEASIBLE_ROUTE' | 'FEE_CEILING_EXCEEDED' | 'PPM_CEILING_EXCEEDED' | 'CLTV_DELTA_UNSAFE' | 'RESERVE_FLOOR'
    | 'BUDGET_EXHAUSTED' | 'COOLDOWN_ACTIVE' | 'STALE_SNAPSHOT' | 'INSUFFICIENT_HISTORY' | 'CAPABILITY_UNSUPPORTED'
    | 'SINGLE_PATH_UNAVAILABLE' | 'REPEATED_CHANNEL' | 'SAME_PEER' | 'FIRST_HOP_SPENDABLE' | 'LAST_HOP_RECEIVABLE';
  export interface CooldownEvent {                // a terminal execution
    readonly outcome: 'VERIFIED_SUCCESS' | 'VERIFIED_FAILURE';
    readonly sourceChannel: string;
    readonly targetChannel: string;
    readonly at: number;                          // unix ms of the terminal transition
  }
  export interface BudgetReservation {            // a budget_reservations row (SPEC §6.2, §6.6)
    readonly state: 'HELD' | 'CONSUMED' | 'RELEASED';
    readonly reservedMsat: bigint;                // the approved max fee (worst case)
    readonly consumedMsat: bigint | null;         // the actual fee once CONSUMED
    readonly at: number;                          // unix ms the reservation was made
  }
  export interface PlanInput {
    readonly diagnosis: Extract<Diagnosis, { status: 'OK' }>;
    readonly policy: PlanningPolicy;
    readonly cooldowns: readonly CooldownEvent[];
    readonly reservations: readonly BudgetReservation[];
    readonly inFlight: number;                    // this node's executions in SUBMITTING, IN_FLIGHT or UNKNOWN
    readonly clock: Clock;
  }
  export interface Candidate { readonly sourceChannel: string; readonly targetChannel: string; readonly principalMsat: bigint }
  export type PairCode = RefusalCode | 'BALANCED_OR_INSUFFICIENT_SURPLUS';
  export interface PairRefusal {
    readonly sourceChannel: string; readonly targetChannel: string; readonly code: PairCode;
    readonly remainingMs: number | null;          // COOLDOWN_ACTIVE only: the longest remaining cooldown; else null
  }
  export interface PlanResult {
    readonly action: 'CANDIDATES' | 'NO_ACTION';
    readonly reason: 'BALANCED_OR_INSUFFICIENT_SURPLUS' | null;   // set only when Starved or Donors is empty
    readonly candidates: readonly Candidate[];     // ranked
    readonly refusals: readonly PairRefusal[];     // sorted by source key, then target key
  }
  export function plan(input: PlanInput): PlanResult;

  Rules (SPEC §7.4, §6.6, §7.2; INV-14):
  - Sources are diagnosis.starved (inbound deficit), targets are diagnosis.donors (inbound surplus), SPEC §4.1,
    minus policy.exclude_channels (excluded channels are skipped, not refused: SPEC §7.4 "neither excluded").
    Either empty → { action: 'NO_ACTION', reason: 'BALANCED_OR_INSUFFICIENT_SURPLUS', candidates: [], refusals: [] }.
  - Every (S, T) in starved × donors gets exactly one outcome: a candidate or one refusal. Checks in order:
    0. Channel state: S or T not ACTIVE (INACTIVE, PENDING, CLOSING, UNKNOWN) → NO_FEASIBLE_ROUTE (no route can use it).
    1. Cooldown: a VERIFIED_FAILURE with the same (source, target) is active until at + cooldown_after_failure;
       a VERIFIED_SUCCESS whose source or target is S or T is active until at + cooldown_after_success.
       Active while now < end; remainingMs = end − now (the largest over active cooldowns) → COOLDOWN_ACTIVE.
       A cooldown whose `at` lies after now (clock stepped back, even beyond the whole cooldown length) is active.
    2. Budget: committed = Σ reservedMsat of HELD + Σ consumedMsat of CONSUMED with at > now − budget.period
       (RELEASED counts nothing; a HELD reservation counts whatever its age; a CONSUMED one without consumedMsat
       counts its reservedMsat). committed + fees.max_fee_msat > budget.msat → BUDGET_EXHAUSTED.
       inFlight ≥ policy.max_in_flight → BUDGET_EXHAUSTED as well (SPEC §7.4: budget and max_in_flight are checked at
       plan time with refusal BUDGET_EXHAUSTED).
    3. Principal = min(inboundDeficit(S), inboundSurplus(T),
                       spendable(S) − fees.max_fee_msat − amounts.min_channel_reserve_msat,
                       amounts.max_principal_msat), in bigint.
       Principal < min_principal_msat → refused with the code of the binding term, checked in this order:
       reserve term → RESERVE_FLOOR; donor surplus → LAST_HOP_RECEIVABLE; otherwise (the source's own deficit or
       max_principal_msat) → BALANCED_OR_INSUFFICIENT_SURPLUS, the SPEC §7.4 wording for nothing worth moving,
       because neither §7.5 code describes it and LAST_HOP_RECEIVABLE would blame a donor that can receive P.
  - Ranking: principal descending, then source key ascending, then target key ascending (route fees do not exist yet).
  - At least one candidate → action 'CANDIDATES', reason null; none → action 'NO_ACTION', reason null, refusals listed.
*/
import { describe, expect, it } from 'vitest';
import {
  HOUR, MINUTE, NODE, NOW, canonical, channel, diagnoseModule, fixedClock, ok, planModule, policy,
  type BudgetReservation, type CooldownEvent, type NormalizedChannel, type OkDiagnosis, type PlanInput, type PlanningPolicy, type PlanResult,
} from '../helpers/cp020-planner.js';

type Targets = Readonly<Record<string, { readonly min_inbound_msat?: bigint }>>;

/** A diagnosis and the policy it was made under; the plan runs under the same policy. */
interface Planned { readonly diagnosis: OkDiagnosis; readonly policy: PlanningPolicy }

async function diagnosed(channels: readonly NormalizedChannel[], targets: Targets, pol: PlanningPolicy = policy({ [NODE]: targets })): Promise<Planned> {
  const { diagnose } = await diagnoseModule();
  return { diagnosis: ok(diagnose({ nodeName: NODE, channels, policy: pol, horizonMs: null, clock: fixedClock() })), policy: pol };
}

async function runPlan(planned: Planned, extra: Partial<Omit<PlanInput, 'diagnosis' | 'policy'>> = {}): Promise<PlanResult> {
  const { plan } = await planModule();
  return plan({ diagnosis: planned.diagnosis, policy: planned.policy, cooldowns: [], reservations: [], inFlight: 0, clock: fixedClock(), ...extra });
}

const S = '110x1x0';
const T1 = '120x1x0';
const T2 = '130x1x0';

/** One starved source and one donor. Policy (SPEC §7.1): max_fee 300,000, reserve floor 50,000,000, principal 10,000,000..100,000,000. */
async function onePair(source: { spendable: bigint; receivable: bigint; target: bigint; capacity?: bigint }, donor: { receivable: bigint; target?: bigint }): Promise<PlanResult> {
  const targets: Record<string, { min_inbound_msat: bigint }> = { [S]: { min_inbound_msat: source.target } };
  if (donor.target !== undefined) targets[T1] = { min_inbound_msat: donor.target };
  const diagnosis = await diagnosed([
    channel(S, { capacity: source.capacity ?? source.spendable + source.receivable, spendable: source.spendable, receivable: source.receivable }),
    channel(T1, { capacity: donor.receivable + 70_000_000n, spendable: 70_000_000n, receivable: donor.receivable }),
  ], targets);
  return await runPlan(diagnosis);
}

const candidates = (pairs: [string, string, bigint][]): PlanResult => ({
  action: 'CANDIDATES', reason: null, refusals: [],
  candidates: pairs.map(([sourceChannel, targetChannel, principalMsat]) => ({ sourceChannel, targetChannel, principalMsat })),
});

describe('principal bounds', () => {
  const cases: { title: string; source: Parameters<typeof onePair>[0]; donor: Parameters<typeof onePair>[1]; principal: bigint }[] = [
    // deficit 100,000,000 − 60,000,000 = 40,000,000; surplus 330,000,000; reserve term 500,000,000 − 300,000 − 50,000,000 = 449,700,000.
    { title: 'the deficit binds', source: { spendable: 500_000_000n, receivable: 60_000_000n, target: 100_000_000n }, donor: { receivable: 330_000_000n }, principal: 40_000_000n },
    // deficit 150,000,000 − 30,000,000 = 120,000,000; surplus 75,000,000 − 50,000,000 = 25,000,000.
    { title: 'the donor surplus binds', source: { spendable: 500_000_000n, receivable: 30_000_000n, target: 150_000_000n }, donor: { receivable: 75_000_000n, target: 50_000_000n }, principal: 25_000_000n },
    // deficit 120,000,000; surplus 330,000,000; reserve term 449,700,000; max_principal 100,000,000.
    { title: 'max_principal_msat binds', source: { spendable: 500_000_000n, receivable: 30_000_000n, target: 150_000_000n }, donor: { receivable: 330_000_000n }, principal: 100_000_000n },
    // deficit 100,000,001 − 0 is one msat over max_principal → 100,000,000.
    { title: 'a deficit of max_principal + 1 msat is capped at max_principal', source: { spendable: 500_000_000n, receivable: 0n, target: 100_000_001n }, donor: { receivable: 330_000_000n }, principal: 100_000_000n },
    // deficit 99,999,999 − 0 is one msat under max_principal → 99,999,999.
    { title: 'a deficit of max_principal − 1 msat is kept', source: { spendable: 500_000_000n, receivable: 0n, target: 99_999_999n }, donor: { receivable: 330_000_000n }, principal: 99_999_999n },
    // reserve term 120,300,000 − 300,000 − 50,000,000 = 70,000,000 < deficit 120,000,000 and surplus 330,000,000.
    { title: 'the reserve floor binds', source: { spendable: 120_300_000n, receivable: 30_000_000n, target: 150_000_000n }, donor: { receivable: 330_000_000n }, principal: 70_000_000n },
    // Target 250,000,000 above capacity 100,000,000: deficit 250,000,000, reserve term 95,000,000 − 300,000 − 50,000,000 = 44,700,000.
    { title: 'a target above capacity is bounded by the source reserve term', source: { capacity: 100_000_000n, spendable: 95_000_000n, receivable: 0n, target: 250_000_000n }, donor: { receivable: 330_000_000n }, principal: 44_700_000n },
  ];
  for (const c of cases) {
    it(`CP-021/B1 principal = min(deficit, surplus, spendable − max fee − reserve, max principal): ${c.title}`, async () => {
      expect(await onePair(c.source, c.donor)).toEqual(candidates([[S, T1, c.principal]]));
    });
  }
});

describe('reserve floor (INV-14)', () => {
  it('CP-021/B2 a source that would end one msat below min_channel_reserve_msat is refused with RESERVE_FLOOR', async () => {
    // Reserve term 60,299,999 − 300,000 − 50,000,000 = 9,999,999 < min_principal 10,000,000; deficit 120,000,000, surplus 330,000,000.
    expect(await onePair({ spendable: 60_299_999n, receivable: 30_000_000n, target: 150_000_000n }, { receivable: 330_000_000n })).toEqual({
      action: 'NO_ACTION', reason: null, candidates: [],
      refusals: [{ sourceChannel: S, targetChannel: T1, code: 'RESERVE_FLOOR', remainingMs: null }],
    });
  });

  it('CP-021/B2 a source left exactly at the floor after the worst-case fee is accepted', async () => {
    // Reserve term 60,300,000 − 300,000 − 50,000,000 = 10,000,000 = min_principal; afterwards
    // 60,300,000 − 10,000,000 − 300,000 = 50,000,000, exactly the floor.
    expect(await onePair({ spendable: 60_300_000n, receivable: 30_000_000n, target: 150_000_000n }, { receivable: 330_000_000n }))
      .toEqual(candidates([[S, T1, 10_000_000n]]));
  });

  it('CP-021/B2 a zero-capacity starved channel is refused with RESERVE_FLOOR, never a negative principal', async () => {
    // Reserve term 0 − 300,000 − 50,000,000 = −50,300,000.
    expect(await onePair({ capacity: 0n, spendable: 0n, receivable: 0n, target: 20_000_000n }, { receivable: 330_000_000n })).toEqual({
      action: 'NO_ACTION', reason: null, candidates: [],
      refusals: [{ sourceChannel: S, targetChannel: T1, code: 'RESERVE_FLOOR', remainingMs: null }],
    });
  });

  it('CP-021/B2 the floor is the policy value, not a constant', async () => {
    // min_channel_reserve_msat 20,000,000: reserve term 60,299,999 − 300,000 − 20,000,000 = 39,999,999.
    const targets = { [S]: { min_inbound_msat: 150_000_000n } };
    const pol = policy({ [NODE]: targets }, { amounts: { min_channel_reserve_msat: 20_000_000n, max_principal_msat: 100_000_000n, min_principal_msat: 10_000_000n } });
    const diagnosis = await diagnosed([
      channel(S, { capacity: 90_299_999n, spendable: 60_299_999n, receivable: 30_000_000n }),
      channel(T1, { capacity: 400_000_000n, spendable: 70_000_000n, receivable: 330_000_000n }),
    ], targets, pol);
    expect(await runPlan(diagnosis)).toEqual(candidates([[S, T1, 39_999_999n]]));
  });
});

/** S starved (deficit 120,000,000, spendable 500,000,000); donors T1 (surplus 330,000,000) and T2 (surplus 200,000,000). Both pairs size to 100,000,000. */
async function twoDonors(): Promise<Planned> {
  return await diagnosed([
    channel(T2, { capacity: 260_000_000n, spendable: 60_000_000n, receivable: 200_000_000n }),
    channel(S, { capacity: 530_000_000n, spendable: 500_000_000n, receivable: 30_000_000n }),
    channel(T1, { capacity: 400_000_000n, spendable: 70_000_000n, receivable: 330_000_000n }),
  ], { [S]: { min_inbound_msat: 150_000_000n } });
}

const failure = (source: string, target: string, at: number): CooldownEvent => ({ outcome: 'VERIFIED_FAILURE', sourceChannel: source, targetChannel: target, at });
const success = (source: string, target: string, at: number): CooldownEvent => ({ outcome: 'VERIFIED_SUCCESS', sourceChannel: source, targetChannel: target, at });
const cooling = (source: string, target: string, remainingMs: number) => ({ sourceChannel: source, targetChannel: target, code: 'COOLDOWN_ACTIVE' as const, remainingMs });

describe('cooldowns', () => {
  it('CP-021/B3 a failure cooldown refuses its pair with the remaining time and leaves other pairs alone', async () => {
    // cooldown_after_failure 1 h: (NOW − 1,000,000) + 3,600,000 − NOW = 2,600,000 ms remaining.
    expect(await runPlan(await twoDonors(), { cooldowns: [failure(S, T1, NOW - 1_000_000)] })).toEqual({
      action: 'CANDIDATES', reason: null,
      candidates: [{ sourceChannel: S, targetChannel: T2, principalMsat: 100_000_000n }],
      refusals: [cooling(S, T1, 2_600_000)],
    });
  });

  it('CP-021/B3 a failure cooldown is active 1 ms before its end and over at its end', async () => {
    const before = await runPlan(await twoDonors(), { cooldowns: [failure(S, T1, NOW - HOUR + 1)] });
    expect(before.refusals).toEqual([cooling(S, T1, 1)]);
    const at = await runPlan(await twoDonors(), { cooldowns: [failure(S, T1, NOW - HOUR)] });
    // Both pairs tie at 100,000,000; the tie is broken by target key 120x1x0 < 130x1x0.
    expect(at).toEqual(candidates([[S, T1, 100_000_000n], [S, T2, 100_000_000n]]));
  });

  it('CP-021/B3 a success cooldown covers every pair touching either channel of that execution', async () => {
    // Success S → 999x9x9 at NOW − 600,000; cooldown_after_success 30 min: 1,800,000 − 600,000 = 1,200,000 ms for both pairs with source S.
    expect(await runPlan(await twoDonors(), { cooldowns: [success(S, '999x9x9', NOW - 10 * MINUTE)] })).toEqual({
      action: 'NO_ACTION', reason: null, candidates: [],
      refusals: [cooling(S, T1, 1_200_000), cooling(S, T2, 1_200_000)],
    });
    // Success 140x1x0 → T2 at NOW − 1,799,999: 1 ms remains on (S, T2); at NOW − 1,800,000 it is over.
    const edge = await runPlan(await twoDonors(), { cooldowns: [success('140x1x0', T2, NOW - 30 * MINUTE + 1)] });
    expect(edge).toEqual({ action: 'CANDIDATES', reason: null, candidates: [{ sourceChannel: S, targetChannel: T1, principalMsat: 100_000_000n }], refusals: [cooling(S, T2, 1)] });
    const over = await runPlan(await twoDonors(), { cooldowns: [success('140x1x0', T2, NOW - 30 * MINUTE)] });
    expect(over.refusals).toEqual([]);
  });

  it('CP-021/B3 overlapping cooldowns report the longest remaining time', async () => {
    // Failure (S, T1) at NOW − 3,000,000 → 600,000 ms; success touching T1 at NOW − 100,000 → 1,800,000 − 100,000 = 1,700,000 ms.
    const result = await runPlan(await twoDonors(), { cooldowns: [success('140x1x0', T1, NOW - 100_000), failure(S, T1, NOW - 3_000_000)] });
    expect(result.refusals).toEqual([cooling(S, T1, 1_700_000)]);
  });

  it('CP-021/B3 a clock stepped back behind a cooldown start keeps the cooldown active', async () => {
    const result = await runPlan(await twoDonors(), { cooldowns: [failure(S, T1, NOW + 5_000)] });
    expect(result.refusals.map(r => [r.sourceChannel, r.targetChannel, r.code])).toEqual([[S, T1, 'COOLDOWN_ACTIVE']]);
    expect(result.candidates).toEqual([{ sourceChannel: S, targetChannel: T2, principalMsat: 100_000_000n }]);
  });
});

const reservation = (state: BudgetReservation['state'], reservedMsat: bigint, consumedMsat: bigint | null, at: number): BudgetReservation => ({ state, reservedMsat, consumedMsat, at });

/**
 * Committed in the 24 h period: CONSUMED 250,000 (actual fee, not the 300,000 reserved) + HELD 300,000 (worst case)
 * + CONSUMED 1,000,000 (an overrun counts in full) + HELD 150,000 = 1,700,000. RELEASED 300,000 and the CONSUMED
 * 900,000 from 25 h ago count nothing.
 */
const RESERVATIONS: BudgetReservation[] = [
  reservation('CONSUMED', 300_000n, 250_000n, NOW - HOUR),
  reservation('HELD', 300_000n, null, NOW - 10 * MINUTE),
  reservation('RELEASED', 300_000n, null, NOW - 2 * HOUR),
  reservation('CONSUMED', 300_000n, 900_000n, NOW - 25 * HOUR),
  reservation('CONSUMED', 300_000n, 1_000_000n, NOW - 2 * HOUR),
];

describe('worst-case budget', () => {
  it('CP-021/B4 committed + max_fee_msat exactly equal to budget.msat is allowed', async () => {
    // 1,700,000 + 300,000 = 2,000,000 = budget.msat.
    const result = await runPlan(await twoDonors(), { reservations: [...RESERVATIONS, reservation('HELD', 150_000n, null, NOW - MINUTE)] });
    expect(result).toEqual(candidates([[S, T1, 100_000_000n], [S, T2, 100_000_000n]]));
  });

  it('CP-021/B4 one msat over budget refuses every pair with BUDGET_EXHAUSTED', async () => {
    // 1,550,000 + 150,001 + 300,000 = 2,000,001 > 2,000,000.
    const result = await runPlan(await twoDonors(), { reservations: [...RESERVATIONS, reservation('HELD', 150_001n, null, NOW - MINUTE)] });
    expect(result).toEqual({
      action: 'NO_ACTION', reason: null, candidates: [],
      refusals: [
        { sourceChannel: S, targetChannel: T1, code: 'BUDGET_EXHAUSTED', remainingMs: null },
        { sourceChannel: S, targetChannel: T2, code: 'BUDGET_EXHAUSTED', remainingMs: null },
      ],
    });
  });

  it('CP-021/B4 two planners: the second sees the first one\'s in-flight worst-case reservation', async () => {
    const shared = [reservation('CONSUMED', 300_000n, 1_500_000n, NOW - 3 * HOUR)];
    // Both read 1,500,000 + 300,000 = 1,800,000 ≤ 2,000,000; plans are proposals, the claim decides (SPEC §6.6).
    const a = await runPlan(await twoDonors(), { reservations: shared });
    const b = await runPlan(await twoDonors(), { reservations: shared });
    expect(a.candidates.length).toBe(2);
    expect(canonical(b)).toBe(canonical(a));
    // A's attempt is in flight and holds its 300,000 max fee: 1,500,000 + 300,000 + 300,000 = 2,100,000 > 2,000,000.
    const afterClaim = await runPlan(await twoDonors(), { reservations: [...shared, reservation('HELD', 300_000n, null, NOW)] });
    expect(afterClaim.candidates).toEqual([]);
    expect(afterClaim.refusals.map(r => r.code)).toEqual(['BUDGET_EXHAUSTED', 'BUDGET_EXHAUSTED']);
  });
});

const S1 = '201x1x0';
const S2 = '202x1x0';
const S3 = '203x1x0';
const TA = '300x1x0';
const TB = '301x1x0';
const TC = '302x1x0';

/**
 * S1 deficit 60,000,000 − 10,000,000 = 50,000,000; S2 deficit 30,000,000 − 0 = 30,000,000; both spendable 800,000,000
 * (reserve term 749,700,000). Surpluses: TA 20,000,000 (no target); TB 400,000,000 − 380,000,000 = 20,000,000;
 * TC 500,000,000 (no target).
 */
function rankingChannels(): NormalizedChannel[] {
  return [
    channel(TC, { capacity: 600_000_000n, spendable: 100_000_000n, receivable: 500_000_000n }),
    channel(S2, { capacity: 800_000_000n, spendable: 800_000_000n, receivable: 0n }),
    channel(TA, { capacity: 30_000_000n, spendable: 10_000_000n, receivable: 20_000_000n }),
    channel(S1, { capacity: 810_000_000n, spendable: 800_000_000n, receivable: 10_000_000n }),
    channel(TB, { capacity: 450_000_000n, spendable: 50_000_000n, receivable: 400_000_000n }),
  ];
}
const RANKING_TARGETS: Targets = { [S1]: { min_inbound_msat: 60_000_000n }, [S2]: { min_inbound_msat: 30_000_000n }, [TB]: { min_inbound_msat: 380_000_000n } };

describe('ranking', () => {
  it('CP-021/B5 candidates rank by principal, then source key, then target key', async () => {
    const result = await runPlan(await diagnosed(rankingChannels(), RANKING_TARGETS));
    expect(result).toEqual(candidates([
      [S1, TC, 50_000_000n], // min(50,000,000, 500,000,000, 749,700,000, 100,000,000)
      [S2, TC, 30_000_000n], // min(30,000,000, 500,000,000, ...)
      [S1, TA, 20_000_000n], // ties at 20,000,000 (donor surplus): S1 before S2, TA before TB
      [S1, TB, 20_000_000n],
      [S2, TA, 20_000_000n],
      [S2, TB, 20_000_000n],
    ]));
  });

  it('CP-021/B5 the same inputs in any order give byte-identical plans', async () => {
    const cooldowns = [failure(S1, TA, NOW - 10 * MINUTE), success('999x9x9', TB, NOW - 20 * HOUR)];
    const first = canonical(await runPlan(await diagnosed(rankingChannels(), RANKING_TARGETS), { cooldowns, reservations: RESERVATIONS }));
    expect(canonical(await runPlan(await diagnosed(rankingChannels(), RANKING_TARGETS), { cooldowns, reservations: RESERVATIONS }))).toBe(first);
    const shuffled = await runPlan(await diagnosed([...rankingChannels()].reverse(), RANKING_TARGETS), { cooldowns: [...cooldowns].reverse(), reservations: [...RESERVATIONS].reverse() });
    expect(canonical(shuffled)).toBe(first);
    // The plan does not lean on the order of the diagnosis lists either.
    const planned = await diagnosed(rankingChannels(), RANKING_TARGETS);
    const reordered = { ...planned, diagnosis: { ...planned.diagnosis, channels: [...planned.diagnosis.channels].reverse(), starved: [...planned.diagnosis.starved].reverse(), donors: [...planned.diagnosis.donors].reverse() } };
    expect(canonical(await runPlan(reordered, { cooldowns, reservations: RESERVATIONS }))).toBe(first);
  });
});

describe('refusal reasons', () => {
  it('CP-021/B6 every pair of starved × donors ends as exactly one candidate or one refusal with a reason', async () => {
    // S1 deficit 50,000,000 (spendable 800,000,000); S2 deficit 30,000,000 with spendable 60,000,000 → reserve term
    // 60,000,000 − 300,000 − 50,000,000 = 9,700,000 < 10,000,000; S3 deficit 50,000,000 − 49,999,999 = 1 < min_principal.
    // Donors TB (surplus 20,000,000) and TC (surplus 500,000,000). Failure (S1, TB) at NOW − 1,000,000 → 2,600,000 ms.
    const diagnosis = await diagnosed([
      channel(S3, { capacity: 849_999_999n, spendable: 800_000_000n, receivable: 49_999_999n }),
      channel(TC, { capacity: 600_000_000n, spendable: 100_000_000n, receivable: 500_000_000n }),
      channel(S2, { capacity: 60_000_000n, spendable: 60_000_000n, receivable: 0n }),
      channel(TB, { capacity: 450_000_000n, spendable: 50_000_000n, receivable: 400_000_000n }),
      channel(S1, { capacity: 810_000_000n, spendable: 800_000_000n, receivable: 10_000_000n }),
    ], { [S1]: { min_inbound_msat: 60_000_000n }, [S2]: { min_inbound_msat: 30_000_000n }, [S3]: { min_inbound_msat: 50_000_000n }, [TB]: { min_inbound_msat: 380_000_000n } });
    const result = await runPlan(diagnosis, { cooldowns: [failure(S1, TB, NOW - 1_000_000)] });

    expect(result.action).toBe('CANDIDATES');
    expect(result.candidates).toEqual([{ sourceChannel: S1, targetChannel: TC, principalMsat: 50_000_000n }]);
    expect(result.refusals.map(r => [r.sourceChannel, r.targetChannel])).toEqual([[S1, TB], [S2, TB], [S2, TC], [S3, TB], [S3, TC]]);
    expect(result.refusals.slice(0, 3)).toEqual([
      cooling(S1, TB, 2_600_000),
      { sourceChannel: S2, targetChannel: TB, code: 'RESERVE_FLOOR', remainingMs: null },
      { sourceChannel: S2, targetChannel: TC, code: 'RESERVE_FLOOR', remainingMs: null },
    ]);
    // S3: min(1, 20,000,000 | 500,000,000, 749,700,000, 100,000,000) = 1, bound by its own deficit, not by the donor.
    expect(result.refusals.slice(3)).toEqual([
      { sourceChannel: S3, targetChannel: TB, code: 'BALANCED_OR_INSUFFICIENT_SURPLUS', remainingMs: null },
      { sourceChannel: S3, targetChannel: TC, code: 'BALANCED_OR_INSUFFICIENT_SURPLUS', remainingMs: null },
    ]);
    const outcomes = [...result.candidates, ...result.refusals].map(o => `${o.sourceChannel}>${o.targetChannel}`).sort();
    expect(outcomes).toEqual([S1, S2, S3].flatMap(s => [TB, TC].map(t => `${s}>${t}`)).sort());
  });
});

describe('nothing to do', () => {
  it('CP-021/B7 no starved channel gives NO_ACTION with BALANCED_OR_INSUFFICIENT_SURPLUS and no pairs', async () => {
    // T1 exactly at target (150,000,000 − 150,000,000 = 0); T2 surplus 200,000,000; nobody starved.
    const diagnosis = await diagnosed([
      channel(T1, { capacity: 400_000_000n, spendable: 250_000_000n, receivable: 150_000_000n }),
      channel(T2, { capacity: 260_000_000n, spendable: 60_000_000n, receivable: 200_000_000n }),
    ], { [T1]: { min_inbound_msat: 150_000_000n } });
    // Exhausted budget and cooldowns do not turn an empty set into refusals.
    const result = await runPlan(diagnosis, { reservations: [reservation('HELD', 2_000_000n, null, NOW)], cooldowns: [failure(T1, T2, NOW)] });
    expect(result).toEqual({ action: 'NO_ACTION', reason: 'BALANCED_OR_INSUFFICIENT_SURPLUS', candidates: [], refusals: [] });
  });

  it('CP-021/B7 no donor gives NO_ACTION with BALANCED_OR_INSUFFICIENT_SURPLUS', async () => {
    // S deficit 120,000,000; T1 exactly at its target 50,000,000 → surplus 0, so Donors is empty.
    const diagnosis = await diagnosed([
      channel(S, { capacity: 530_000_000n, spendable: 500_000_000n, receivable: 30_000_000n }),
      channel(T1, { capacity: 120_000_000n, spendable: 70_000_000n, receivable: 50_000_000n }),
    ], { [S]: { min_inbound_msat: 150_000_000n }, [T1]: { min_inbound_msat: 50_000_000n } });
    expect(await runPlan(diagnosis)).toEqual({ action: 'NO_ACTION', reason: 'BALANCED_OR_INSUFFICIENT_SURPLUS', candidates: [], refusals: [] });
  });
});

describe('in-flight limit', () => {
  it('CP-021/B4 max_in_flight reached refuses every pair with BUDGET_EXHAUSTED although the fee budget has room', async () => {
    // No reservations: 0 + 300,000 ≤ 2,000,000. max_in_flight 1 (SPEC §7.1): 0 in flight plans, 1 in flight refuses.
    expect(await runPlan(await twoDonors(), { inFlight: 0 })).toEqual(candidates([[S, T1, 100_000_000n], [S, T2, 100_000_000n]]));
    expect(await runPlan(await twoDonors(), { inFlight: 1 })).toEqual({
      action: 'NO_ACTION', reason: null, candidates: [],
      refusals: [
        { sourceChannel: S, targetChannel: T1, code: 'BUDGET_EXHAUSTED', remainingMs: null },
        { sourceChannel: S, targetChannel: T2, code: 'BUDGET_EXHAUSTED', remainingMs: null },
      ],
    });
  });

  it('CP-021/B4 the limit is the policy max_in_flight: 2 allows one in flight and refuses at two', async () => {
    const planned = await twoDonors();
    const two = { ...planned, policy: { ...planned.policy, max_in_flight: 2 } };
    expect((await runPlan(two, { inFlight: 1 })).candidates.length).toBe(2);
    const full = await runPlan(two, { inFlight: 2 });
    expect(full.candidates).toEqual([]);
    expect(full.refusals.map(r => r.code)).toEqual(['BUDGET_EXHAUSTED', 'BUDGET_EXHAUSTED']);
  });
});

describe('budget window edges', () => {
  // Each case puts committed at 1,700,001 or 0: 1,700,001 + 300,000 = 2,000,001 > 2,000,000 refuses; 0 + 300,000 plans.
  const refusedBoth: PlanResult = {
    action: 'NO_ACTION', reason: null, candidates: [],
    refusals: [
      { sourceChannel: S, targetChannel: T1, code: 'BUDGET_EXHAUSTED', remainingMs: null },
      { sourceChannel: S, targetChannel: T2, code: 'BUDGET_EXHAUSTED', remainingMs: null },
    ],
  };

  it('CP-021/B4 a fee consumed exactly one period ago is outside the window; 1 ms later it is inside', async () => {
    // The window is at > now − period: NOW − 24 h is out, NOW − 24 h + 1 ms is in.
    expect(await runPlan(await twoDonors(), { reservations: [reservation('CONSUMED', 300_000n, 1_700_001n, NOW - 24 * HOUR)] }))
      .toEqual(candidates([[S, T1, 100_000_000n], [S, T2, 100_000_000n]]));
    expect(await runPlan(await twoDonors(), { reservations: [reservation('CONSUMED', 300_000n, 1_700_001n, NOW - 24 * HOUR + 1)] })).toEqual(refusedBoth);
  });

  it('CP-021/B4 a HELD reservation older than the period still counts at its worst case', async () => {
    // An attempt still unresolved after 30 h may yet be charged (SPEC §6.6: while UNKNOWN it stays HELD).
    expect(await runPlan(await twoDonors(), { reservations: [reservation('HELD', 1_700_001n, null, NOW - 30 * HOUR)] })).toEqual(refusedBoth);
  });

  it('CP-021/B4 a CONSUMED reservation without an actual fee counts its reserved worst case', async () => {
    expect(await runPlan(await twoDonors(), { reservations: [reservation('CONSUMED', 1_700_001n, null, NOW - HOUR)] })).toEqual(refusedBoth);
  });
});

describe('cooldown clock steps', () => {
  it('CP-021/B3 a clock stepped back further than the whole cooldown keeps the cooldown active', async () => {
    // Failure recorded at NOW + 2 h with a 1 h cooldown; success touching T2 at NOW + 2 h with a 30 min cooldown.
    const result = await runPlan(await twoDonors(), { cooldowns: [failure(S, T1, NOW + 2 * HOUR), success('140x1x0', T2, NOW + 2 * HOUR)] });
    expect(result.candidates).toEqual([]);
    expect(result.refusals.map(r => [r.sourceChannel, r.targetChannel, r.code])).toEqual([[S, T1, 'COOLDOWN_ACTIVE'], [S, T2, 'COOLDOWN_ACTIVE']]);
  });
});

describe('excluded and unusable channels', () => {
  it('CP-021/B6 an excluded donor is never a target and is skipped without a refusal', async () => {
    const planned = await twoDonors();
    const result = await runPlan({ ...planned, policy: { ...planned.policy, exclude_channels: [T1] } });
    expect(result).toEqual(candidates([[S, T2, 100_000_000n]]));
  });

  it('CP-021/B7 an excluded source leaves no starved channel: NO_ACTION with BALANCED_OR_INSUFFICIENT_SURPLUS', async () => {
    const planned = await twoDonors();
    expect(await runPlan({ ...planned, policy: { ...planned.policy, exclude_channels: [S] } }))
      .toEqual({ action: 'NO_ACTION', reason: 'BALANCED_OR_INSUFFICIENT_SURPLUS', candidates: [], refusals: [] });
  });

  it('CP-021/B6 channels that are not ACTIVE are never source or target; each such pair is refused with NO_FEASIBLE_ROUTE', async () => {
    const S2 = '115x1x0';
    const T3 = '140x1x0';
    // S deficit 150,000,000 − 30,000,000 = 120,000,000 (ACTIVE); S2 deficit 30,000,000 − 0 = 30,000,000 (PENDING);
    // donors T1 330,000,000 (CLOSING), T2 200,000,000 (INACTIVE), T3 250,000,000 (ACTIVE).
    const planned = await diagnosed([
      channel(T3, { capacity: 300_000_000n, spendable: 50_000_000n, receivable: 250_000_000n }),
      channel(S2, { capacity: 100_000_000n, spendable: 100_000_000n, receivable: 0n, state: 'PENDING' }),
      channel(T1, { capacity: 400_000_000n, spendable: 70_000_000n, receivable: 330_000_000n, state: 'CLOSING' }),
      channel(S, { capacity: 530_000_000n, spendable: 500_000_000n, receivable: 30_000_000n }),
      channel(T2, { capacity: 260_000_000n, spendable: 60_000_000n, receivable: 200_000_000n, state: 'INACTIVE' }),
    ], { [S]: { min_inbound_msat: 150_000_000n }, [S2]: { min_inbound_msat: 30_000_000n } });
    expect(planned.diagnosis.channels.map(c => [c.channelKey, c.state])).toEqual([[S, 'ACTIVE'], [S2, 'PENDING'], [T1, 'CLOSING'], [T2, 'INACTIVE'], [T3, 'ACTIVE']]);
    const unusable = (source: string, target: string) => ({ sourceChannel: source, targetChannel: target, code: 'NO_FEASIBLE_ROUTE' as const, remainingMs: null });
    expect(await runPlan(planned)).toEqual({
      action: 'CANDIDATES', reason: null,
      // (S, T3) = min(120,000,000, 250,000,000, 500,000,000 − 300,000 − 50,000,000 = 449,700,000, 100,000,000).
      candidates: [{ sourceChannel: S, targetChannel: T3, principalMsat: 100_000_000n }],
      refusals: [unusable(S, T1), unusable(S, T2), unusable(S2, T1), unusable(S2, T2), unusable(S2, T3)],
    });
  });
});

describe('refusal codes name the binding channel', () => {
  it('CP-021/B6 a source deficit below min_principal is refused as BALANCED_OR_INSUFFICIENT_SURPLUS, not blamed on the donor', async () => {
    // deficit 5 − 0 = 5 msat; surplus 330,000,000; reserve term 449,700,000 → principal 5 < 10,000,000, bound by the deficit.
    expect(await onePair({ spendable: 500_000_000n, receivable: 0n, target: 5n }, { receivable: 330_000_000n })).toEqual({
      action: 'NO_ACTION', reason: null, candidates: [],
      refusals: [{ sourceChannel: S, targetChannel: T1, code: 'BALANCED_OR_INSUFFICIENT_SURPLUS', remainingMs: null }],
    });
  });

  it('CP-021/B6 a donor surplus below min_principal is refused as LAST_HOP_RECEIVABLE', async () => {
    // deficit 120,000,000; surplus 55,000,000 − 50,000,000 = 5,000,000 < 10,000,000, bound by the donor.
    expect(await onePair({ spendable: 500_000_000n, receivable: 30_000_000n, target: 150_000_000n }, { receivable: 55_000_000n, target: 50_000_000n })).toEqual({
      action: 'NO_ACTION', reason: null, candidates: [],
      refusals: [{ sourceChannel: S, targetChannel: T1, code: 'LAST_HOP_RECEIVABLE', remainingMs: null }],
    });
  });
});

describe('ties between binding terms', () => {
  it('CP-021/B6 a source deficit equal to the donor surplus, both below min_principal, is LAST_HOP_RECEIVABLE (donor checked before the deficit)', async () => {
    // deficit 5,000,000 − 0 = 5,000,000; surplus 55,000,000 − 50,000,000 = 5,000,000; reserve term 449,700,000.
    expect(await onePair({ spendable: 500_000_000n, receivable: 0n, target: 5_000_000n }, { receivable: 55_000_000n, target: 50_000_000n })).toEqual({
      action: 'NO_ACTION', reason: null, candidates: [],
      refusals: [{ sourceChannel: S, targetChannel: T1, code: 'LAST_HOP_RECEIVABLE', remainingMs: null }],
    });
  });

  it('CP-021/B6 a reserve term equal to the donor surplus, both below min_principal, is RESERVE_FLOOR (reserve checked first)', async () => {
    // reserve term 55,300,000 − 300,000 − 50,000,000 = 5,000,000; surplus 5,000,000; deficit 150,000,000 − 30,000,000 = 120,000,000.
    expect(await onePair({ spendable: 55_300_000n, receivable: 30_000_000n, target: 150_000_000n }, { receivable: 55_000_000n, target: 50_000_000n })).toEqual({
      action: 'NO_ACTION', reason: null, candidates: [],
      refusals: [{ sourceChannel: S, targetChannel: T1, code: 'RESERVE_FLOOR', remainingMs: null }],
    });
  });
});
