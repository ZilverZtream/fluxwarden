/*
Interface (src/core/route.ts, pure; amounts are Msat bigints, the types below with Msat for bigint):
  export type Implementation = 'lnd' | 'cln';
  export interface HopPolicy {            // the forwarding policy of this hop's channel, as set by the node that sends on it
    readonly baseFeeMsat: Msat; readonly feePpm: bigint; readonly cltvExpiryDelta: number;
    readonly minHtlcMsat: Msat; readonly maxHtlcMsat: Msat | null;
  }
  export interface RouteHop {             // hop-end semantics (as CLN sendpay): the HTLC on channel `scid`
    readonly scid: string;                // that reaches `nodeIdOut` carries `amountOutMsat` and expires at
    readonly nodeIdOut: string;           // absolute height `cltvOut`; `policy` is null for the first hop
    readonly amountOutMsat: Msat;         // (our own channel, no fee)
    readonly cltvOut: number;
    readonly policy: HopPolicy | null;
  }
  export interface CandidateRoute {
    readonly hops: readonly RouteHop[]; readonly parts: number;
    readonly totalAmountMsat: Msat; readonly totalFeeMsat: Msat;   // as the node reported; must equal hops[0] amount and F
    readonly totalTimeLock: number; readonly builtAtHeight: number;   // totalTimeLock must equal hops[0].cltvOut
  }
  export type ValidatedRoute = CandidateRoute & { readonly __brand: 'validated-route' };
  export interface RouteConstraints {
    readonly selfPubkey: string; readonly implementation: Implementation;
    readonly sourceScid: string; readonly targetScid: string; readonly outPeer: string; readonly inPeer: string;
    readonly principalMsat: Msat; readonly maxFeeMsat: Msat;      // approved caps, never above the policy's
    readonly maxCltvDelta: number; readonly finalCltvDelta: number; readonly blockHeight: number;
  }
  export type RouteChannel = Pick<NormalizedChannel, 'channelKey' | 'scid' | 'peerPubkey' | 'state' | 'spendableMsat' | 'receivableMsat'>;
  export interface EffectivePolicy {
    readonly maxFeeMsat: Msat; readonly maxFeePpm: bigint; readonly exemptFeeMsat: Msat;
    readonly maxCltvDelta: number; readonly minChannelReserveMsat: Msat;
  }
  export type RefusalCode = 'NO_FEASIBLE_ROUTE' | 'REPEATED_CHANNEL' | 'FEE_CEILING_EXCEEDED' | 'PPM_CEILING_EXCEEDED'
    | 'CLTV_DELTA_UNSAFE' | 'SINGLE_PATH_UNAVAILABLE' | 'SAME_PEER' | 'FIRST_HOP_SPENDABLE' | 'RESERVE_FLOOR' | 'LAST_HOP_RECEIVABLE';
  export type RouteVerdict =
    | { ok: true; route: ValidatedRoute; feeMsat: Msat; feePpm: bigint; cltvDelta: number; padding: 1 | 3 }
    | { ok: false; code: RefusalCode; check: 'V1' | 'V2' | ... | 'V12' };
  export function validateRoute(route: CandidateRoute, c: RouteConstraints,
    channels: readonly RouteChannel[], policy: EffectivePolicy): RouteVerdict;
  Checks V1..V12 of SPEC §5.5 run in order and the first failure is returned (SPEC §7.4). The fee
  F = hops[0].amountOutMsat − P and Δ = hops[0].cltvOut − blockHeight are recomputed from the hops;
  feePpm = ceil(F × 10^6 / P); padding is 3 for LND and 1 for CLN (SPEC §4.5; Decision D52: lightningd sends each HTLC at height + 1 + cltv_out); the fee and CLTV caps
  applied are the lower of the approved caps (constraints) and the policy's.
  Also refused: our snapshot's peer of S / T differing from outPeer / inPeer (V1), S or T missing
  from the snapshot or not ACTIVE (V12), fewer than two hops or a zero principal (V1), a final hop
  expiring before blockHeight + finalCltvDelta (V5), any hop expiry that is not a safe integer, a
  negative hop base fee or rate, and reported totals that contradict the hops (FC-032).
*/
import { describe, expect, it } from 'vitest';
import { loadSrc } from '../helpers/load-src.js';

interface HopPolicy { baseFeeMsat: bigint; feePpm: bigint; cltvExpiryDelta: number; minHtlcMsat: bigint; maxHtlcMsat: bigint | null }
interface RouteHop { scid: string; nodeIdOut: string; amountOutMsat: bigint; cltvOut: number; policy: HopPolicy | null }
interface CandidateRoute { hops: RouteHop[]; parts: number; totalAmountMsat: bigint; totalFeeMsat: bigint; totalTimeLock: number; builtAtHeight: number }
interface RouteConstraints {
  selfPubkey: string; implementation: 'lnd' | 'cln'; sourceScid: string; targetScid: string; outPeer: string; inPeer: string;
  principalMsat: bigint; maxFeeMsat: bigint; maxCltvDelta: number; finalCltvDelta: number; blockHeight: number;
}
interface RouteChannel { channelKey: string; scid: string | null; peerPubkey: string; state: 'ACTIVE' | 'INACTIVE' | 'PENDING' | 'CLOSING' | 'UNKNOWN'; spendableMsat: bigint; receivableMsat: bigint }
interface EffectivePolicy { maxFeeMsat: bigint; maxFeePpm: bigint; exemptFeeMsat: bigint; maxCltvDelta: number; minChannelReserveMsat: bigint }
type RouteVerdict =
  | { ok: true; route: CandidateRoute; feeMsat: bigint; feePpm: bigint; cltvDelta: number; padding: number }
  | { ok: false; code: string; check: string };
interface RouteModule { validateRoute: (route: CandidateRoute, c: RouteConstraints, channels: readonly RouteChannel[], policy: EffectivePolicy) => RouteVerdict }

const route = (): Promise<RouteModule> => loadSrc<RouteModule>('core/route.ts');

const node = (byte: string): string => `02${byte.repeat(32)}`;
const SELF = node('11');
const A = node('aa');
const B = node('bb');
const C = node('cc');
const D = node('dd');
const S = '101x1x0';
const T = '103x1x0';
const X = '102x1x0';
const Y = '104x1x0';
const HEIGHT = 800;
const FINAL = 18;
const P = 100_000_000n;
const PLENTY = 10n ** 15n;

function hopPolicy(base: bigint, ppm: bigint, cltvExpiryDelta = 40, limits: Partial<Pick<HopPolicy, 'minHtlcMsat' | 'maxHtlcMsat'>> = {}): HopPolicy {
  return { baseFeeMsat: base, feePpm: ppm, cltvExpiryDelta, minHtlcMsat: limits.minHtlcMsat ?? 1n, maxHtlcMsat: limits.maxHtlcMsat ?? null };
}

interface Leg { scid: string; to: string; policy: HopPolicy | null }

/**
 * Builds hop amounts and expiries backwards from the destination as SPEC §4.4 describes:
 * each forwarder charges base + floor(amount out × ppm / 10^6) of the next hop's channel policy.
 */
function assemble(legs: readonly Leg[], deliver: bigint, finalDelta = FINAL, height = HEIGHT): CandidateRoute {
  const amounts: bigint[] = new Array<bigint>(legs.length).fill(0n);
  const expiries: number[] = new Array<number>(legs.length).fill(0);
  amounts[legs.length - 1] = deliver;
  expiries[legs.length - 1] = height + finalDelta;
  for (let i = legs.length - 1; i >= 1; i -= 1) {
    const policy = legs[i]?.policy;
    if (!policy) throw new Error('forwarded hop without a policy');
    const out = amounts[i] ?? 0n;
    amounts[i - 1] = out + policy.baseFeeMsat + (out * policy.feePpm) / 1_000_000n;
    expiries[i - 1] = (expiries[i] ?? 0) + policy.cltvExpiryDelta;
  }
  const hops = legs.map((leg, i) => ({ scid: leg.scid, nodeIdOut: leg.to, amountOutMsat: amounts[i] ?? 0n, cltvOut: expiries[i] ?? 0, policy: leg.policy }));
  return withTotals(hops, deliver, height);
}

function withTotals(hops: RouteHop[], deliver: bigint, height = HEIGHT): CandidateRoute {
  const first = hops[0];
  if (!first) throw new Error('empty route');
  return { hops, parts: 1, totalAmountMsat: first.amountOutMsat, totalFeeMsat: first.amountOutMsat - deliver, totalTimeLock: first.cltvOut, builtAtHeight: height };
}

/** us -S-> A -X-> C -T-> us, with the fee F charged by A on X and nothing by C on T. */
function threeHop(fee: bigint, principal = P, xDelta = 40, tDelta = 40): CandidateRoute {
  return assemble([
    { scid: S, to: A, policy: null },
    { scid: X, to: C, policy: hopPolicy(fee, 0n, xDelta) },
    { scid: T, to: SELF, policy: hopPolicy(0n, 0n, tDelta) },
  ], principal);
}

// SPEC §4.4 worked example: 100,000,000 msat out over channel 2, forwarded by LND-R over channel 3
// and by CLN-R over channel 5, both at base 1,000 msat and 1,000 ppm.
const WORKED: CandidateRoute = {
  hops: [
    { scid: S, nodeIdOut: A, amountOutMsat: 100_202_101n, cltvOut: HEIGHT + FINAL + 40 + 40, policy: null },
    { scid: X, nodeIdOut: C, amountOutMsat: 100_101_000n, cltvOut: HEIGHT + FINAL + 40, policy: hopPolicy(1000n, 1000n) },
    { scid: T, nodeIdOut: SELF, amountOutMsat: 100_000_000n, cltvOut: HEIGHT + FINAL, policy: hopPolicy(1000n, 1000n) },
  ],
  parts: 1, totalAmountMsat: 100_202_101n, totalFeeMsat: 202_101n, totalTimeLock: HEIGHT + FINAL + 80, builtAtHeight: HEIGHT,
};

function constraints(over: Partial<RouteConstraints> = {}): RouteConstraints {
  return {
    selfPubkey: SELF, implementation: 'cln', sourceScid: S, targetScid: T, outPeer: A, inPeer: C,
    principalMsat: P, maxFeeMsat: 300_000n, maxCltvDelta: 144, finalCltvDelta: FINAL, blockHeight: HEIGHT, ...over,
  };
}

function channels(over: { spendable?: bigint; receivable?: bigint; sourcePeer?: string; targetPeer?: string; sourceState?: RouteChannel['state'] } = {}): RouteChannel[] {
  return [
    { channelKey: S, scid: S, peerPubkey: over.sourcePeer ?? A, state: over.sourceState ?? 'ACTIVE', spendableMsat: over.spendable ?? PLENTY, receivableMsat: PLENTY },
    { channelKey: T, scid: T, peerPubkey: over.targetPeer ?? C, state: 'ACTIVE', spendableMsat: PLENTY, receivableMsat: over.receivable ?? PLENTY },
  ];
}

function policy(over: Partial<EffectivePolicy> = {}): EffectivePolicy {
  return { maxFeeMsat: 300_000n, maxFeePpm: 1_000_000n, exemptFeeMsat: 0n, maxCltvDelta: 144, minChannelReserveMsat: 0n, ...over };
}

function refused(verdict: RouteVerdict): { code: string; check: string } {
  if (verdict.ok) throw new Error('expected a refusal, the route was accepted');
  return { code: verdict.code, check: verdict.check };
}

function accepted(verdict: RouteVerdict): { feeMsat: bigint; feePpm: bigint; cltvDelta: number; padding: number; route: CandidateRoute } {
  if (!verdict.ok) throw new Error(`expected acceptance, refused with ${verdict.code} at ${verdict.check}`);
  return verdict;
}

describe('fee caps (V3, V4)', () => {
  it('CP-022/B1 the absolute fee cap accepts F = max_fee_msat and refuses one msat more', async () => {
    const { validateRoute } = await route();
    const p = policy({ maxFeeMsat: 300_000n });
    const atCap = accepted(validateRoute(threeHop(300_000n), constraints(), channels(), p));
    expect(atCap.feeMsat).toBe(300_000n);
    expect(atCap.feePpm).toBe(3000n);
    expect(refused(validateRoute(threeHop(300_001n), constraints(), channels(), p))).toStrictEqual({ code: 'FEE_CEILING_EXCEEDED', check: 'V3' });
  });

  it('CP-022/B1 the ppm cap rounds up: 250,000 msat on 10^8 is 2,500 ppm, 250,001 msat is 2,501', async () => {
    const { validateRoute } = await route();
    const p = policy({ maxFeeMsat: 10_000_000n, maxFeePpm: 2500n });
    const c = constraints({ maxFeeMsat: 10_000_000n });
    expect(accepted(validateRoute(threeHop(250_000n), c, channels(), p)).feePpm).toBe(2500n);
    // floor(2,500.01) = 2,500 would pass; the specified ceil gives 2,501.
    expect(refused(validateRoute(threeHop(250_001n), c, channels(), p))).toStrictEqual({ code: 'PPM_CEILING_EXCEEDED', check: 'V4' });
  });

  it('CP-022/B1 fees at or below exempt_fee_msat skip the ppm cap, one msat more does not', async () => {
    const { validateRoute } = await route();
    const p = policy({ maxFeeMsat: 300_000n, maxFeePpm: 2500n, exemptFeeMsat: 5000n });
    const c = constraints({ principalMsat: 1_000_000n });
    const exempt = accepted(validateRoute(threeHop(5000n, 1_000_000n), c, channels(), p));
    expect(exempt.feePpm).toBe(5000n);
    expect(refused(validateRoute(threeHop(5001n, 1_000_000n), c, channels(), p))).toStrictEqual({ code: 'PPM_CEILING_EXCEEDED', check: 'V4' });
  });

  it('CP-022/B1 the exemption never relaxes the absolute cap', async () => {
    const { validateRoute } = await route();
    const p = policy({ maxFeeMsat: 4000n, exemptFeeMsat: 5000n });
    const c = constraints({ maxFeeMsat: 4000n });
    accepted(validateRoute(threeHop(4000n), c, channels(), p));
    expect(refused(validateRoute(threeHop(4001n), c, channels(), p))).toStrictEqual({ code: 'FEE_CEILING_EXCEEDED', check: 'V3' });
  });

  it('CP-022/B1 the worked example costs 202,101 msat at 2,022 ppm and fails a 2,021 ppm cap', async () => {
    const { validateRoute } = await route();
    const ok = accepted(validateRoute(WORKED, constraints(), channels(), policy({ maxFeePpm: 2022n })));
    expect(ok).toMatchObject({ feeMsat: 202_101n, feePpm: 2022n, cltvDelta: FINAL + 80, padding: 1 });
    expect(ok.route).toStrictEqual(WORKED);
    expect(refused(validateRoute(WORKED, constraints(), channels(), policy({ maxFeePpm: 2021n })))).toStrictEqual({ code: 'PPM_CEILING_EXCEEDED', check: 'V4' });
  });

  it('CP-022/B1 a tighter approved fee cap is enforced below the policy cap', async () => {
    const { validateRoute } = await route();
    const c = constraints({ maxFeeMsat: 200_000n });
    accepted(validateRoute(threeHop(200_000n), c, channels(), policy()));
    expect(refused(validateRoute(threeHop(200_001n), c, channels(), policy()))).toStrictEqual({ code: 'FEE_CEILING_EXCEEDED', check: 'V3' });
  });

  it('CP-022/B1 the fee is recomputed from the hops, not taken from the reported totals', async () => {
    const { validateRoute } = await route();
    const real = threeHop(300_001n);
    const understated = { ...real, totalFeeMsat: 300_000n, totalAmountMsat: P + 300_000n };
    expect(refused(validateRoute(understated, constraints(), channels(), policy()))).toStrictEqual({ code: 'FEE_CEILING_EXCEEDED', check: 'V3' });
  });
});

describe('timelock (V5)', () => {
  /** Δ = final 18 + T's delta 40 + X's delta. */
  const withDelta = (delta: number): CandidateRoute => threeHop(1000n, P, delta - FINAL - 40, 40);

  it('CP-022/B2 a CLN route (padding 1) passes at Δ = max_cltv_delta − 1 and fails at Δ = max_cltv_delta', async () => {
    // Decision D52: lightningd v26.06.9 sends each HTLC at network height + 1 + cltv_out (lightningd/pay.c L786-L790),
    // so Δ 143 occupies 144 blocks above the current height and Δ 144 would occupy 145.
    const { validateRoute } = await route();
    expect(accepted(validateRoute(withDelta(143), constraints(), channels(), policy()))).toMatchObject({ cltvDelta: 143, padding: 1 });
    expect(refused(validateRoute(withDelta(144), constraints(), channels(), policy()))).toStrictEqual({ code: 'CLTV_DELTA_UNSAFE', check: 'V5' });
  });

  it('CP-022/B2 an LND route adds the block padding of 3: Δ 141 passes a 144 cap, Δ 142 fails', async () => {
    const { validateRoute } = await route();
    const c = constraints({ implementation: 'lnd' });
    expect(accepted(validateRoute(withDelta(141), c, channels(), policy()))).toMatchObject({ cltvDelta: 141, padding: 3 });
    expect(refused(validateRoute(withDelta(142), c, channels(), policy()))).toStrictEqual({ code: 'CLTV_DELTA_UNSAFE', check: 'V5' });
  });

  it('CP-022/B2 the policy cap and a tighter approved cap both bound Δ', async () => {
    const { validateRoute } = await route();
    // CLN routes carry padding 1 (Decision D52): Δ 99 fits a cap of 100, Δ 100 does not.
    accepted(validateRoute(withDelta(99), constraints({ maxCltvDelta: 100 }), channels(), policy()));
    accepted(validateRoute(withDelta(99), constraints({ maxCltvDelta: 144 }), channels(), policy({ maxCltvDelta: 100 })));
    expect(refused(validateRoute(withDelta(100), constraints({ maxCltvDelta: 100 }), channels(), policy()))).toStrictEqual({ code: 'CLTV_DELTA_UNSAFE', check: 'V5' });
    expect(refused(validateRoute(withDelta(100), constraints({ maxCltvDelta: 144 }), channels(), policy({ maxCltvDelta: 100 })))).toStrictEqual({ code: 'CLTV_DELTA_UNSAFE', check: 'V5' });
  });

  it('CP-022/B2 Δ is measured from the first hop expiry, not the reported total timelock', async () => {
    const { validateRoute } = await route();
    const real = withDelta(145);
    const understated = { ...real, totalTimeLock: HEIGHT + 100 };
    expect(refused(validateRoute(understated, constraints(), channels(), policy()))).toStrictEqual({ code: 'CLTV_DELTA_UNSAFE', check: 'V5' });
  });

  it('CP-022/B2 a hop whose expiry exceeds the previous hop expiry is refused', async () => {
    const { validateRoute } = await route();
    const base = threeHop(1000n);
    const [first, second, third] = base.hops;
    if (!first || !second || !third) throw new Error('fixture');
    const rising = withTotals([{ ...first, cltvOut: HEIGHT + 30 }, { ...second, cltvOut: HEIGHT + 40 }, third], P);
    expect(refused(validateRoute(rising, constraints(), channels(), policy()))).toStrictEqual({ code: 'CLTV_DELTA_UNSAFE', check: 'V5' });
  });
});

describe('route shape', () => {
  it('CP-022/B3 more than one part is SINGLE_PATH_UNAVAILABLE', async () => {
    const { validateRoute } = await route();
    accepted(validateRoute(threeHop(1000n), constraints(), channels(), policy()));
    for (const parts of [2, 0]) {
      expect(refused(validateRoute({ ...threeHop(1000n), parts }, constraints(), channels(), policy()))).toStrictEqual({ code: 'SINGLE_PATH_UNAVAILABLE', check: 'V6' });
    }
  });

  it('CP-022/B4 a channel used twice, in the same or the opposite direction, is REPEATED_CHANNEL', async () => {
    const { validateRoute } = await route();
    const same = assemble([
      { scid: S, to: A, policy: null }, { scid: X, to: B, policy: hopPolicy(1000n, 10n, 20) },
      { scid: Y, to: D, policy: hopPolicy(1000n, 10n, 20) }, { scid: X, to: C, policy: hopPolicy(1000n, 10n, 20) },
      { scid: T, to: SELF, policy: hopPolicy(1000n, 10n, 20) },
    ], P);
    const backAndForth = assemble([
      { scid: S, to: A, policy: null }, { scid: X, to: B, policy: hopPolicy(1000n, 10n, 20) },
      { scid: X, to: A, policy: hopPolicy(1000n, 10n, 20) }, { scid: Y, to: C, policy: hopPolicy(1000n, 10n, 20) },
      { scid: T, to: SELF, policy: hopPolicy(1000n, 10n, 20) },
    ], P);
    for (const candidate of [same, backAndForth]) {
      expect(refused(validateRoute(candidate, constraints(), channels(), policy()))).toStrictEqual({ code: 'REPEATED_CHANNEL', check: 'V2' });
    }
  });

  it('CP-022/B4 a route through our own node uses the reverse edges and is REPEATED_CHANNEL', async () => {
    const { validateRoute } = await route();
    // us -S-> A -X-> us -Y-> C -T-> us: X is out_peer -> us and Y is us -> in_peer (SPEC §5.5 V11).
    const viaSelf = assemble([
      { scid: S, to: A, policy: null }, { scid: X, to: SELF, policy: hopPolicy(1000n, 10n) },
      { scid: Y, to: C, policy: hopPolicy(0n, 0n) }, { scid: T, to: SELF, policy: hopPolicy(1000n, 10n) },
    ], P);
    expect(refused(validateRoute(viaSelf, constraints(), channels(), policy()))).toStrictEqual({ code: 'REPEATED_CHANNEL', check: 'V11' });
  });

  it('CP-022/B5 the same peer at both ends is SAME_PEER', async () => {
    const { validateRoute } = await route();
    const loop = assemble([
      { scid: S, to: A, policy: null }, { scid: X, to: B, policy: hopPolicy(1000n, 10n) },
      { scid: Y, to: A, policy: hopPolicy(1000n, 10n) }, { scid: T, to: SELF, policy: hopPolicy(1000n, 10n) },
    ], P);
    expect(refused(validateRoute(loop, constraints({ inPeer: A }), channels({ targetPeer: A }), policy()))).toStrictEqual({ code: 'SAME_PEER', check: 'V7' });
  });
});

describe('own channel liquidity (V8, V9)', () => {
  it('CP-022/B6 first-hop spendable must cover principal plus fee: P + F passes, one msat less fails', async () => {
    const { validateRoute } = await route();
    accepted(validateRoute(WORKED, constraints(), channels({ spendable: 100_202_101n }), policy()));
    // 100,202,100 still covers the principal alone; counting the first-hop fees refuses it (cln#7563).
    expect(refused(validateRoute(WORKED, constraints(), channels({ spendable: 100_202_100n }), policy()))).toStrictEqual({ code: 'FIRST_HOP_SPENDABLE', check: 'V8' });
  });

  it('CP-022/B6 the source keeps min_channel_reserve_msat after P + F or the route is RESERVE_FLOOR', async () => {
    const { validateRoute } = await route();
    const p = policy({ minChannelReserveMsat: 50_000_000n });
    accepted(validateRoute(WORKED, constraints(), channels({ spendable: 150_202_101n }), p));
    expect(refused(validateRoute(WORKED, constraints(), channels({ spendable: 150_202_100n }), p))).toStrictEqual({ code: 'RESERVE_FLOOR', check: 'V8' });
  });

  it('CP-022/B7 last-hop receivable must cover the principal: P passes, P - 1 fails', async () => {
    const { validateRoute } = await route();
    accepted(validateRoute(WORKED, constraints(), channels({ receivable: 100_000_000n }), policy()));
    expect(refused(validateRoute(WORKED, constraints(), channels({ receivable: 99_999_999n }), policy()))).toStrictEqual({ code: 'LAST_HOP_RECEIVABLE', check: 'V9' });
  });
});

describe('hop amounts and endpoints (V1, V10, V12)', () => {
  function edit(index: number, change: Partial<RouteHop>): CandidateRoute {
    const hops = WORKED.hops.map((hop, i) => (i === index ? { ...hop, ...change } : hop));
    return withTotals(hops, P);
  }

  it('CP-022/B8 a forwarder taking one msat more or less than its policy fee is NO_FEASIBLE_ROUTE', async () => {
    const { validateRoute } = await route();
    for (const candidate of [edit(0, { amountOutMsat: 100_202_102n }), edit(0, { amountOutMsat: 100_202_100n }), edit(1, { amountOutMsat: 100_100_999n })]) {
      expect(refused(validateRoute(candidate, constraints(), channels(), policy()))).toStrictEqual({ code: 'NO_FEASIBLE_ROUTE', check: 'V10' });
    }
  });

  it('CP-022/B8 a final hop that does not deliver exactly the principal is NO_FEASIBLE_ROUTE', async () => {
    const { validateRoute } = await route();
    const overpaying = assemble([
      { scid: S, to: A, policy: null }, { scid: X, to: C, policy: hopPolicy(1000n, 1000n) }, { scid: T, to: SELF, policy: hopPolicy(1000n, 1000n) },
    ], P + 1n);
    expect(refused(validateRoute(overpaying, constraints(), channels(), policy()))).toStrictEqual({ code: 'NO_FEASIBLE_ROUTE', check: 'V10' });
  });

  it('CP-022/B8 an amount outside a hop htlc_minimum or htlc_maximum is NO_FEASIBLE_ROUTE', async () => {
    const { validateRoute } = await route();
    const build = (x: HopPolicy, t: HopPolicy): CandidateRoute => assemble([{ scid: S, to: A, policy: null }, { scid: X, to: C, policy: x }, { scid: T, to: SELF, policy: t }], P);
    accepted(validateRoute(build(hopPolicy(1000n, 1000n, 40, { minHtlcMsat: 100_101_000n }), hopPolicy(1000n, 1000n, 40, { maxHtlcMsat: P })), constraints(), channels(), policy()));
    expect(refused(validateRoute(build(hopPolicy(1000n, 1000n), hopPolicy(1000n, 1000n, 40, { maxHtlcMsat: P - 1n })), constraints(), channels(), policy()))).toStrictEqual({ code: 'NO_FEASIBLE_ROUTE', check: 'V10' });
    expect(refused(validateRoute(build(hopPolicy(1000n, 1000n, 40, { minHtlcMsat: 100_101_001n }), hopPolicy(1000n, 1000n)), constraints(), channels(), policy()))).toStrictEqual({ code: 'NO_FEASIBLE_ROUTE', check: 'V10' });
  });

  it('CP-022/B8 a route that does not leave over S and return to us over T is NO_FEASIBLE_ROUTE', async () => {
    const { validateRoute } = await route();
    expect(refused(validateRoute(WORKED, constraints({ sourceScid: '999x9x9' }), channels(), policy()))).toStrictEqual({ code: 'NO_FEASIBLE_ROUTE', check: 'V1' });
    expect(refused(validateRoute(WORKED, constraints({ targetScid: '999x9x9' }), channels(), policy()))).toStrictEqual({ code: 'NO_FEASIBLE_ROUTE', check: 'V1' });
    expect(refused(validateRoute(edit(2, { nodeIdOut: D }), constraints(), channels(), policy()))).toStrictEqual({ code: 'NO_FEASIBLE_ROUTE', check: 'V1' });
  });

  it('CP-022/B8 a route over a channel that is no longer open is NO_FEASIBLE_ROUTE', async () => {
    const { validateRoute } = await route();
    expect(refused(validateRoute(WORKED, constraints(), channels({ sourceState: 'CLOSING' }), policy()))).toStrictEqual({ code: 'NO_FEASIBLE_ROUTE', check: 'V12' });
  });
});

/** mulberry32: a small seeded generator, so every run draws the same cases. */
function generator(seed: number): { int(lo: number, hi: number): number } {
  let state = seed >>> 0;
  const next = (): number => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return { int: (lo, hi) => lo + Math.floor(next() * (hi - lo + 1)) };
}

const MID_NODES = [node('21'), node('22'), node('23'), node('24'), node('25')];

function randomLegs(rand: ReturnType<typeof generator>, middle: number, sameDelta: boolean): Leg[] {
  const delta = rand.int(6, 60);
  const legs: Leg[] = [{ scid: S, to: A, policy: null }];
  for (let i = 0; i < middle; i += 1) {
    const to = i === middle - 1 ? C : MID_NODES[i] ?? B;
    legs.push({ scid: `${String(200 + i)}x1x0`, to, policy: hopPolicy(BigInt(rand.int(0, 5000)), BigInt(rand.int(0, 5000)), sameDelta ? delta : rand.int(6, 60)) });
  }
  legs.push({ scid: T, to: SELF, policy: hopPolicy(BigInt(rand.int(0, 5000)), BigInt(rand.int(0, 5000)), sameDelta ? delta : rand.int(6, 60)) });
  return legs;
}

const nonNegative = (value: bigint): bigint => (value < 0n ? 0n : value);

describe('endpoints, liquidity snapshot and reported totals', () => {
  function withHop(index: number, change: Partial<RouteHop>): CandidateRoute {
    return withTotals(WORKED.hops.map((hop, i) => (i === index ? { ...hop, ...change } : hop)), P);
  }

  it('CP-022/B8 our snapshot must show S to the out-peer and T to the in-peer (V1)', async () => {
    const { validateRoute } = await route();
    expect(refused(validateRoute(WORKED, constraints(), channels({ sourcePeer: B }), policy()))).toStrictEqual({ code: 'NO_FEASIBLE_ROUTE', check: 'V1' });
    expect(refused(validateRoute(WORKED, constraints(), channels({ targetPeer: D }), policy()))).toStrictEqual({ code: 'NO_FEASIBLE_ROUTE', check: 'V1' });
  });

  it('CP-022/B8 a target channel that is not open in the newest snapshot is refused (V12)', async () => {
    const { validateRoute } = await route();
    for (const state of ['CLOSING', 'PENDING', 'UNKNOWN'] as const) {
      const listed = channels().map(channel => (channel.scid === T ? { ...channel, state } : channel));
      expect(refused(validateRoute(WORKED, constraints(), listed, policy())), state).toStrictEqual({ code: 'NO_FEASIBLE_ROUTE', check: 'V12' });
    }
  });

  it('CP-022/B8 a source or target channel missing from our snapshot is NO_FEASIBLE_ROUTE', async () => {
    const { validateRoute } = await route();
    for (const missing of [S, T]) {
      const verdict = validateRoute(WORKED, constraints(), channels().filter(channel => channel.scid !== missing), policy());
      expect(refused(verdict).code, missing).toBe('NO_FEASIBLE_ROUTE');
    }
  });

  it('CP-022/B8 an empty route, a one-hop route and a zero principal are refused without throwing', async () => {
    const { validateRoute } = await route();
    expect(refused(validateRoute({ ...WORKED, hops: [] }, constraints(), channels(), policy())).code).toBe('NO_FEASIBLE_ROUTE');
    const oneHop = withTotals([{ scid: S, nodeIdOut: SELF, amountOutMsat: P, cltvOut: HEIGHT + FINAL, policy: null }], P);
    expect(refused(validateRoute(oneHop, constraints({ targetScid: S }), channels(), policy())).code).toBe('NO_FEASIBLE_ROUTE');
    const zero = threeHop(0n, 0n);
    expect(refused(validateRoute(zero, constraints({ principalMsat: 0n }), channels(), policy())).code).toBe('NO_FEASIBLE_ROUTE');
  });

  it('CP-022/B2 a final hop expiring one block short of height + final CLTV delta is refused', async () => {
    const { validateRoute } = await route();
    // The invoice's final delta is part of Δ (SPEC §4.5); 18 blocks are required, 17 are offered.
    const short = assemble([
      { scid: S, to: A, policy: null }, { scid: X, to: C, policy: hopPolicy(1000n, 1000n) }, { scid: T, to: SELF, policy: hopPolicy(1000n, 1000n) },
    ], P, FINAL - 1);
    expect(refused(validateRoute(short, constraints(), channels(), policy()))).toStrictEqual({ code: 'CLTV_DELTA_UNSAFE', check: 'V5' });
  });

  it('CP-022/B2 a non-integer or missing expiry on any later hop is refused', async () => {
    const { validateRoute } = await route();
    for (const cltvOut of [Number.NaN, HEIGHT + FINAL + 0.5, Number.POSITIVE_INFINITY]) {
      expect(validateRoute(withHop(1, { cltvOut }), constraints(), channels(), policy()).ok, String(cltvOut)).toBe(false);
      expect(validateRoute(withHop(2, { cltvOut }), constraints(), channels(), policy()).ok, String(cltvOut)).toBe(false);
    }
  });

  it('CP-022/B2 a block height or final CLTV delta that is not a safe integer is refused', async () => {
    const { validateRoute } = await route();
    for (const blockHeight of [Number.NaN, HEIGHT + 0.5, undefined as unknown as number]) {
      expect(refused(validateRoute(WORKED, constraints({ blockHeight }), channels(), policy())), `height ${String(blockHeight)}`).toStrictEqual({ code: 'CLTV_DELTA_UNSAFE', check: 'V5' });
    }
    for (const finalCltvDelta of [Number.NaN, FINAL + 0.5, undefined as unknown as number]) {
      expect(refused(validateRoute(WORKED, constraints({ finalCltvDelta }), channels(), policy())), `final ${String(finalCltvDelta)}`).toStrictEqual({ code: 'CLTV_DELTA_UNSAFE', check: 'V5' });
    }
  });

  it('CP-022/B2 a CLTV cap that is missing or not a number fails closed', async () => {
    const { validateRoute } = await route();
    for (const cap of [Number.NaN, undefined as unknown as number, 144.5]) {
      expect(refused(validateRoute(WORKED, constraints({ maxCltvDelta: cap }), channels(), policy())), `approved ${String(cap)}`).toStrictEqual({ code: 'CLTV_DELTA_UNSAFE', check: 'V5' });
      expect(refused(validateRoute(WORKED, constraints(), channels(), policy({ maxCltvDelta: cap }))), `policy ${String(cap)}`).toStrictEqual({ code: 'CLTV_DELTA_UNSAFE', check: 'V5' });
    }
  });

  it('CP-022/B2 a negative final CLTV delta cannot admit a final hop expiring below the current height', async () => {
    const { validateRoute } = await route();
    const belowHeight = assemble([
      { scid: S, to: A, policy: null }, { scid: X, to: C, policy: hopPolicy(1000n, 1000n) }, { scid: T, to: SELF, policy: hopPolicy(1000n, 1000n) },
    ], P, -5);
    expect(refused(validateRoute(belowHeight, constraints({ finalCltvDelta: -5 }), channels(), policy())).code).toBe('CLTV_DELTA_UNSAFE');
  });

  // A missing or non-bigint amount or cap must refuse at its check, never pass a comparison.
  it('CP-022/B8 a principal that is not a bigint is NO_FEASIBLE_ROUTE, not an exception', async () => {
    const { validateRoute } = await route();
    expect(refused(validateRoute(WORKED, constraints({ principalMsat: 100_000_000 as unknown as bigint }), channels(), policy()))).toStrictEqual({ code: 'NO_FEASIBLE_ROUTE', check: 'V1' });
  });

  it.each([
    ['the policy fee cap', {}, { maxFeeMsat: undefined as unknown as bigint }],
    ['the approved fee cap', { maxFeeMsat: undefined as unknown as bigint }, {}],
  ] as const)('CP-022/B1 a missing %s refuses at V3', async (_name, c, p) => {
    const { validateRoute } = await route();
    expect(refused(validateRoute(WORKED, constraints(c), channels(), policy(p)))).toStrictEqual({ code: 'FEE_CEILING_EXCEEDED', check: 'V3' });
  });

  it.each([
    ['exempt_fee_msat', { exemptFeeMsat: undefined as unknown as bigint }],
    ['max_fee_ppm', { maxFeePpm: undefined as unknown as bigint }],
  ] as const)('CP-022/B1 a missing %s refuses at V4', async (_name, p) => {
    const { validateRoute } = await route();
    expect(refused(validateRoute(WORKED, constraints(), channels(), policy(p)))).toStrictEqual({ code: 'PPM_CEILING_EXCEEDED', check: 'V4' });
  });

  it('CP-022/B6 a missing reserve floor or spendable figure refuses at V8', async () => {
    const { validateRoute } = await route();
    expect(refused(validateRoute(WORKED, constraints(), channels(), policy({ minChannelReserveMsat: undefined as unknown as bigint })))).toStrictEqual({ code: 'FIRST_HOP_SPENDABLE', check: 'V8' });
    const listed = channels().map(channel => (channel.scid === S ? { ...channel, spendableMsat: undefined as unknown as bigint } : channel));
    expect(refused(validateRoute(WORKED, constraints(), listed, policy()))).toStrictEqual({ code: 'FIRST_HOP_SPENDABLE', check: 'V8' });
  });

  it('CP-022/B7 a missing receivable figure refuses at V9', async () => {
    const { validateRoute } = await route();
    const listed = channels().map(channel => (channel.scid === T ? { ...channel, receivableMsat: undefined as unknown as bigint } : channel));
    expect(refused(validateRoute(WORKED, constraints(), listed, policy()))).toStrictEqual({ code: 'LAST_HOP_RECEIVABLE', check: 'V9' });
  });

  it('CP-022/B8 a hop policy with a negative base fee or rate is refused', async () => {
    const { validateRoute } = await route();
    const build = (x: HopPolicy): CandidateRoute => assemble([{ scid: S, to: A, policy: null }, { scid: X, to: C, policy: x }, { scid: T, to: SELF, policy: hopPolicy(1000n, 1000n) }], P);
    expect(validateRoute(build(hopPolicy(-1n, 1000n)), constraints(), channels(), policy()).ok).toBe(false);
    expect(validateRoute(build(hopPolicy(1000n, -1n)), constraints(), channels(), policy()).ok).toBe(false);
  });

  // FC-032: the first HTLC is sent with the reported total timelock and amount, so totals that
  // contradict the hops cannot be validated.
  it('CP-022/B8 reported totals that contradict the hops are refused', async () => {
    const { validateRoute } = await route();
    expect(refused(validateRoute({ ...WORKED, totalTimeLock: HEIGHT + 1098 }, constraints(), channels(), policy())).code).toBe('CLTV_DELTA_UNSAFE');
    expect(validateRoute({ ...WORKED, totalTimeLock: WORKED.totalTimeLock - 1 }, constraints(), channels(), policy()).ok).toBe(false);
    expect(validateRoute({ ...WORKED, totalAmountMsat: 2n * P }, constraints(), channels(), policy()).ok).toBe(false);
    expect(validateRoute({ ...WORKED, totalFeeMsat: 202_100n }, constraints(), channels(), policy()).ok).toBe(false);
  });
});

describe('properties', () => {
  it('CP-022/B9 random routes pass exactly when every bound holds, else fail with the first broken check', async () => {
    const { validateRoute } = await route();
    const rand = generator(0x5eed);
    const seen = new Set<string>();
    for (let round = 0; round < 400; round += 1) {
      const implementation = rand.int(0, 1) === 0 ? 'lnd' : 'cln';
      const principal = BigInt(rand.int(1_000_000, 1_000_000_000));
      const finalDelta = rand.int(9, 40);
      const candidate = assemble(randomLegs(rand, rand.int(1, 5), false), principal, finalDelta);
      const first = candidate.hops[0];
      if (!first) throw new Error('fixture');
      // Expected values by SPEC §4.4/§4.5 arithmetic, independent of the code under test.
      const fee = first.amountOutMsat - principal;
      const ppm = (fee * 1_000_000n + principal - 1n) / principal;
      const delta = first.cltvOut - HEIGHT;
      const padding = implementation === 'lnd' ? 3 : 1;
      // Two rounds in three break at most one bound, by exactly one unit, and meet the others exactly
      // or with a little room; the third round draws every margin at random, so several bounds break at once.
      const broken = round % 3 === 2 ? -1 : rand.int(0, 6);
      const margin = (bound: number): number => (broken === -1 ? rand.int(-2, 2) : broken === bound ? -1 : rand.int(0, 2));
      const exempt = rand.int(0, 1) === 0;
      const p: EffectivePolicy = {
        maxFeeMsat: nonNegative(fee + BigInt(margin(0))),
        maxFeePpm: nonNegative(ppm + BigInt(margin(1))),
        exemptFeeMsat: exempt ? nonNegative(fee + BigInt(margin(1))) : 0n,
        maxCltvDelta: delta + padding + margin(2),
        minChannelReserveMsat: BigInt(rand.int(0, 1000)),
      };
      const firstHopMargin = BigInt(margin(3));
      const spendable = firstHopMargin < 0n
        ? principal + fee + firstHopMargin
        : nonNegative(principal + fee + p.minChannelReserveMsat + BigInt(margin(4)));
      const receivable = nonNegative(principal + BigInt(margin(5)));
      let expected: string | null = null;
      if (fee > p.maxFeeMsat) expected = 'FEE_CEILING_EXCEEDED';
      else if (fee > p.exemptFeeMsat && ppm > p.maxFeePpm) expected = 'PPM_CEILING_EXCEEDED';
      else if (delta + padding > p.maxCltvDelta) expected = 'CLTV_DELTA_UNSAFE';
      else if (spendable < principal + fee) expected = 'FIRST_HOP_SPENDABLE';
      else if (spendable - (principal + fee) < p.minChannelReserveMsat) expected = 'RESERVE_FLOOR';
      else if (receivable < principal) expected = 'LAST_HOP_RECEIVABLE';
      const c = constraints({ implementation, principalMsat: principal, maxFeeMsat: p.maxFeeMsat, maxCltvDelta: p.maxCltvDelta, finalCltvDelta: finalDelta });
      const verdict = validateRoute(candidate, c, channels({ spendable, receivable }), p);
      const label = `round ${String(round)}`;
      if (expected === null) {
        expect(verdict, label).toMatchObject({ ok: true, feeMsat: fee, feePpm: ppm, cltvDelta: delta, padding });
      } else {
        expect(verdict, label).toMatchObject({ ok: false, code: expected });
      }
      seen.add(expected ?? 'OK');
    }
    expect([...seen].sort()).toStrictEqual(['CLTV_DELTA_UNSAFE', 'FEE_CEILING_EXCEEDED', 'FIRST_HOP_SPENDABLE', 'LAST_HOP_RECEIVABLE', 'OK', 'PPM_CEILING_EXCEEDED', 'RESERVE_FLOOR']);
  });

  it('CP-022/B9 changing any single hop amount of a valid route never passes', async () => {
    const { validateRoute } = await route();
    const rand = generator(0xa11ce);
    const generous = policy({ maxFeeMsat: PLENTY, maxFeePpm: 1_000_000n, maxCltvDelta: 2016 });
    const c = constraints({ maxFeeMsat: PLENTY, maxCltvDelta: 2016 });
    for (let round = 0; round < 200; round += 1) {
      const candidate = assemble(randomLegs(rand, rand.int(1, 5), false), P);
      accepted(validateRoute(candidate, c, channels(), generous));
      const index = rand.int(0, candidate.hops.length - 1);
      const change = BigInt(rand.int(1, 1000)) * (rand.int(0, 1) === 0 ? 1n : -1n);
      const hops = candidate.hops.map((hop, i) => (i === index ? { ...hop, amountOutMsat: hop.amountOutMsat + change } : hop));
      expect(validateRoute(withTotals(hops, P), c, channels(), generous).ok, `round ${String(round)} hop ${String(index)}`).toBe(false);
    }
  });

  it('CP-022/B9 reordering middle hops keeps a route valid only when the amounts are recomputed', async () => {
    const { validateRoute } = await route();
    const rand = generator(0xc0ffee);
    const generous = policy({ maxFeeMsat: PLENTY, maxFeePpm: 1_000_000n, maxCltvDelta: 2016 });
    const c = constraints({ maxFeeMsat: PLENTY, maxCltvDelta: 2016 });
    let staleRefused = 0;
    for (let round = 0; round < 100; round += 1) {
      const legs = randomLegs(rand, rand.int(3, 5), true);
      const original = assemble(legs, P);
      accepted(validateRoute(original, c, channels(), generous));
      // Rotate the middle legs except the last one, which must still arrive at the in-peer.
      const movable = legs.slice(1, legs.length - 2);
      const rotated = [legs[0], ...movable.slice(1), movable[0], ...legs.slice(legs.length - 2)].filter((leg): leg is Leg => leg !== undefined);
      const stale = withTotals(original.hops.map((hop, i) => {
        const leg = rotated[i];
        return leg ? { ...hop, scid: leg.scid, nodeIdOut: leg.to, policy: leg.policy } : hop;
      }), P);
      const recomputed = assemble(rotated, P);
      const sameAmounts = recomputed.hops.every((hop, i) => hop.amountOutMsat === original.hops[i]?.amountOutMsat);
      expect(validateRoute(stale, c, channels(), generous).ok, `round ${String(round)} stale`).toBe(sameAmounts);
      if (!sameAmounts) staleRefused += 1;
      accepted(validateRoute(recomputed, c, channels(), generous));
    }
    expect(staleRefused).toBeGreaterThan(90);
  });
});
