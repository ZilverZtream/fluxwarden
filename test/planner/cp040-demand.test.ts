/*
Interface: src/planner/demand.ts (pure; no I/O, no clock of its own: `now` is passed in).

  export interface Rational { readonly numerator: bigint; readonly denominator: bigint }   // denominator > 0, not
                                                                                           // necessarily reduced
  export interface DemandParams {
    readonly bucketSeconds: number;   // policy demand.ewma.bucket_seconds, integer ≥ 1
    readonly alpha: string;           // policy demand.ewma.alpha, decimal string parsed as an exact rational, 0 < α ≤ 1
    readonly minSamples: number;      // policy demand.ewma.min_samples, integer ≥ 1
    readonly horizonSeconds: number;  // policy demand.horizon, integer ≥ 1
    readonly burstFactor: string;     // policy demand.burst_factor, decimal string parsed as an exact rational
  }
  export interface VolumeBucket {
    readonly start: number;           // unix ms; the bucket covers [start, start + bucketSeconds × 1000)
    readonly volumeMsat: bigint;      // settled incoming volume in the bucket (0 when observed and empty)
  }
  export type DemandResult =
    | { readonly source: 'EWMA'; readonly samples: number; readonly estimate: Rational; readonly requiredInboundMsat: bigint }
    | { readonly source: 'TARGETS'; readonly reason: 'INSUFFICIENT_HISTORY'; readonly samples: number;
        readonly requiredInboundMsat: bigint };
  export function ewmaWeights(alpha: string, n: number): readonly Rational[];
      // normalised weights w_k = α(1−α)^k / (1 − (1−α)^(N+1)) for k = 0..N (k = 0 the newest bucket)
  export function estimateDemand(input: {
    readonly buckets: readonly VolumeBucket[];   // observed buckets, oldest first
    readonly now: number;                        // unix ms
    readonly targetMsat: bigint;                 // targets.<node>.<channel>.min_inbound_msat
    readonly params: DemandParams;
  }): DemandResult;
  Invalid parameters (alpha outside (0, 1], bucketSeconds, minSamples or horizonSeconds < 1) and a negative bucket
  volume throw RangeError.

Rules (SPEC §7.1 "Decimal factors are strings and parsed as exact rationals"; §7.3):
  D_in = α · Σ_{k=0..N} (1−α)^k · V_in(t−k) / (1 − (1−α)^(N+1)), N + 1 = number of buckets, exact rational (`estimate`).
  Required inbound = D_in · (horizon / bucket_seconds) · burst_factor, exact, then rounded UP to whole msat: SPEC gives no
  rounding direction, and rounding up never understates the inbound requirement (the direction SPEC §4.4 uses for caps).
  Window: only the newest W = max(min_samples, ceil(horizon / bucket_seconds)) entries of `buckets` are read; older
  entries are ignored, so the cost is bounded by policy values and not by the length of the stored history (SECURITY
  threat model: input sizes are bounded). SPEC §7.3 sums k = 0..N without fixing N; W covers the planning horizon and
  never fewer buckets than min_samples requires. `samples` is the number of entries read (≤ W).
  History is usable only when the window has at least min_samples buckets and no observation gap: consecutive starts
  (in the given order, so a duplicate or out-of-order entry is a gap) differ by
  exactly bucketSeconds × 1000 and the newest bucket is the last complete one (start + B ≤ now < start + 2B). Otherwise
  source TARGETS, reason INSUFFICIENT_HISTORY, requiredInboundMsat = targetMsat. SPEC's TARGETS/EWMA names are used
  (they are the stored `demand_source` values), not "operator-target"/"ewma".
*/
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';

interface Rational { readonly numerator: bigint; readonly denominator: bigint }
interface DemandParams { bucketSeconds: number; alpha: string; minSamples: number; horizonSeconds: number; burstFactor: string }
interface VolumeBucket { start: number; volumeMsat: bigint }
type DemandResult =
  | { source: 'EWMA'; samples: number; estimate: Rational; requiredInboundMsat: bigint }
  | { source: 'TARGETS'; reason: 'INSUFFICIENT_HISTORY'; samples: number; requiredInboundMsat: bigint };
interface Demand {
  ewmaWeights(alpha: string, n: number): readonly Rational[];
  estimateDemand(input: { buckets: readonly VolumeBucket[]; now: number; targetMsat: bigint; params: DemandParams }): DemandResult;
}

async function loadDemand(): Promise<Demand> {
  return await import(pathToFileURL(join(repoRoot, 'src/planner/demand.ts')).href) as Demand;
}

const HOUR = 3600;
const HORIZON = 6 * HOUR;                 // policy example `horizon: 6h`
const TARGET = 150_000_000n;              // policy example cln-m channel-2 min_inbound_msat
const POLICY: DemandParams = { bucketSeconds: HOUR, alpha: '0.35', minSamples: 12, horizonSeconds: HORIZON, burstFactor: '1.4' };
const NOW = 1_760_000_400_000 + 1_000;    // 1 s into a bucket boundary that is a multiple of 3,600,000 ms

/** Contiguous complete buckets ending with the last complete one before `now` (oldest first). */
function history(volumes: readonly bigint[], bucketSeconds: number, now = NOW): VolumeBucket[] {
  const width = bucketSeconds * 1000;
  const newest = Math.floor(now / width) * width - width;
  return volumes.map((volumeMsat, i) => ({ start: newest - (volumes.length - 1 - i) * width, volumeMsat }));
}

const same = (r: Rational, numerator: bigint, denominator: bigint): boolean => r.numerator * denominator === numerator * r.denominator;

function ewma(result: DemandResult): Extract<DemandResult, { source: 'EWMA' }> {
  if (result.source !== 'EWMA') throw new Error(`expected EWMA, got ${result.source}`);
  return result;
}

/**
 * Plain-arithmetic reference, independent of any recursive EWMA form. With α = a/d (lowest terms) the weights multiply
 * out to integers: D = Σ_k a·(d−a)^k·d^(N−k)·V_k / (d^(N+1) − (d−a)^(N+1)). Required = ceil(D · H · bn / (B · bd)).
 */
function reference(a: bigint, d: bigint, volumes: readonly bigint[], h: bigint, b: bigint, bn: bigint, bd: bigint): bigint {
  const n = volumes.length - 1;
  let num = 0n;
  for (let k = 0; k <= n; k += 1) num += a * (d - a) ** BigInt(k) * d ** BigInt(n - k) * (volumes[n - k] ?? 0n);
  const den = d ** BigInt(n + 1) - (d - a) ** BigInt(n + 1);
  const top = num * h * bn;
  const bottom = den * b * bd;
  return (top + bottom - 1n) / bottom;
}

describe('normalised weights', () => {
  it('CP-040/B1 the weights sum to exactly 1 for N = 0, 3, 10 and 100', async () => {
    const d = await loadDemand();
    for (const n of [0, 3, 10, 100]) {
      const weights = d.ewmaWeights('0.35', n);
      expect(weights).toHaveLength(n + 1);
      let num = 0n;
      let den = 1n;
      for (const w of weights) { num = num * w.denominator + w.numerator * den; den *= w.denominator; }
      expect(num, `N = ${String(n)}`).toBe(den);
    }
    // N = 0: α / (1 − (1 − α)) = 1, where the unnormalised weight would be 0.35 (SPEC §7.3).
    const [only] = d.ewmaWeights('0.35', 0);
    expect(only !== undefined && same(only, 1n, 1n)).toBe(true);
    // N = 3, α = 7/20, 1 − α = 13/20: 1 − (13/20)^4 = 1 − 28561/160000 = 131439/160000.
    // w_0 = (7/20)·160000/131439 = 56000/131439; w_1 = w_0·13/20 = 36400/131439; w_2 = 23660/131439; w_3 = 15379/131439.
    const w3 = d.ewmaWeights('0.35', 3);
    const expected = [56_000n, 36_400n, 23_660n, 15_379n];
    expected.forEach((num, k) => { const w = w3[k]; expect(w !== undefined && same(w, num, 131_439n), `w_${String(k)}`).toBe(true); });
    // α = 1: (1 − α)^0 = 1 for the newest bucket, 0 for every older one.
    const ones = d.ewmaWeights('1', 3);
    expect(ones.map(w => (w.numerator === 0n ? 0 : same(w, 1n, 1n) ? 1 : -1))).toEqual([1, 0, 0, 0]);
  });

  it('CP-040/B1 alpha outside (0, 1] and non-positive bucket, sample or horizon parameters are refused', async () => {
    const d = await loadDemand();
    expect(() => d.ewmaWeights('0', 3)).toThrow(RangeError);
    expect(() => d.ewmaWeights('1.01', 3)).toThrow(RangeError);
    const buckets = history(Array.from({ length: 12 }, () => 1_000n), HOUR);
    for (const bad of [{ alpha: '0' }, { alpha: '1.5' }, { bucketSeconds: 0 }, { minSamples: 0 }, { horizonSeconds: 0 }]) {
      expect(() => d.estimateDemand({ buckets, now: NOW, targetMsat: TARGET, params: { ...POLICY, ...bad } }), JSON.stringify(bad)).toThrow(RangeError);
    }
  });
});

describe('units', () => {
  it('CP-040/B2 the requirement scales by horizon / bucket, so a constant rate gives the same msat for any bucket width', async () => {
    const d = await loadDemand();
    // A steady 1,000 msat/s fills each bucket with 1,000 × B msat. Normalised weights sum to 1, so D_in = 1,000 × B exactly,
    // and Required = 1,000 × B × (21,600 / B) × 7/5 = 30,240,000 msat whatever B is. B = 7 s does not divide the horizon:
    // 7,000 × 21,600/7 × 1.4 = 30,240,000, whereas floor(21,600 / 7) = 3,085 buckets would give 30,233,000.
    for (const bucketSeconds of [1, 7, 10, HOUR]) {
      const volume = 1_000n * BigInt(bucketSeconds);
      const result = ewma(d.estimateDemand({
        buckets: history(Array.from({ length: 12 }, () => volume), bucketSeconds), now: NOW, targetMsat: TARGET,
        params: { ...POLICY, bucketSeconds },
      }));
      expect(same(result.estimate, volume, 1n), `B = ${String(bucketSeconds)}`).toBe(true);
      expect(result.requiredInboundMsat, `B = ${String(bucketSeconds)}`).toBe(30_240_000n);
    }
  });
});

describe('source selection', () => {
  const volumes = (n: number): bigint[] => Array.from({ length: n }, (_, i) => 1_000_000n * BigInt(i + 1));

  it('CP-040/B3 below min_samples the operator target is used with source TARGETS; at min_samples EWMA', async () => {
    const d = await loadDemand();
    const short = d.estimateDemand({ buckets: history(volumes(11), HOUR), now: NOW, targetMsat: TARGET, params: POLICY });
    expect(short).toEqual({ source: 'TARGETS', reason: 'INSUFFICIENT_HISTORY', samples: 11, requiredInboundMsat: TARGET });
    const empty = d.estimateDemand({ buckets: [], now: NOW, targetMsat: TARGET, params: POLICY });
    expect(empty).toEqual({ source: 'TARGETS', reason: 'INSUFFICIENT_HISTORY', samples: 0, requiredInboundMsat: TARGET });
    const enough = ewma(d.estimateDemand({ buckets: history(volumes(12), HOUR), now: NOW, targetMsat: TARGET, params: POLICY }));
    expect(enough.samples).toBe(12);
    expect(enough.requiredInboundMsat).toBe(reference(7n, 20n, volumes(12), 21_600n, 3_600n, 7n, 5n));
    expect(enough.requiredInboundMsat).not.toBe(TARGET);
  });

  it('CP-040/B3 an observation gap or a stale newest bucket falls back to the target', async () => {
    const d = await loadDemand();
    const full = history(volumes(14), HOUR);
    const gap = [...full.slice(0, 6), ...full.slice(7)];          // 13 buckets, one hour missing; the newest 12 span it
    expect(d.estimateDemand({ buckets: gap, now: NOW, targetMsat: TARGET, params: POLICY }))
      .toEqual({ source: 'TARGETS', reason: 'INSUFFICIENT_HISTORY', samples: 12, requiredInboundMsat: TARGET });
    const stale = full.slice(0, 13);                               // newest complete bucket missing
    expect(d.estimateDemand({ buckets: stale, now: NOW, targetMsat: TARGET, params: POLICY }))
      .toEqual({ source: 'TARGETS', reason: 'INSUFFICIENT_HISTORY', samples: 12, requiredInboundMsat: TARGET });
    // Exactly at the end of the bucket after the newest one, the newest is no longer the last complete bucket.
    const newest = full[13];
    if (newest === undefined) throw new Error('fixture');
    expect(d.estimateDemand({ buckets: full, now: newest.start + 2 * HOUR * 1000, targetMsat: TARGET, params: POLICY }).source).toBe('TARGETS');
    expect(d.estimateDemand({ buckets: full, now: newest.start + 2 * HOUR * 1000 - 1, targetMsat: TARGET, params: POLICY }).source).toBe('EWMA');
  });
});

describe('input bounds', () => {
  it('CP-040/B3 a duplicate or out-of-order bucket is an observation gap and falls back to the target', async () => {
    const d = await loadDemand();
    const full = history(Array.from({ length: 12 }, (_, i) => 1_000_000n * BigInt(i + 1)), HOUR);
    const at = (i: number): VolumeBucket => { const b = full[i]; if (b === undefined) throw new Error('fixture'); return b; };
    // 13 entries, the bucket at index 5 delivered twice; the newest 12 still contain both copies.
    const duplicate = [...full.slice(0, 6), at(5), ...full.slice(6)];
    expect(d.estimateDemand({ buckets: duplicate, now: NOW, targetMsat: TARGET, params: POLICY }))
      .toEqual({ source: 'TARGETS', reason: 'INSUFFICIENT_HISTORY', samples: 12, requiredInboundMsat: TARGET });
    const swapped = [...full.slice(0, 4), at(5), at(4), ...full.slice(6)];
    expect(d.estimateDemand({ buckets: swapped, now: NOW, targetMsat: TARGET, params: POLICY }))
      .toEqual({ source: 'TARGETS', reason: 'INSUFFICIENT_HISTORY', samples: 12, requiredInboundMsat: TARGET });
  });

  it('CP-040/B3 a negative bucket volume is refused', async () => {
    const d = await loadDemand();
    const buckets = history([...Array.from({ length: 11 }, () => 1_000n), -1n], HOUR);
    expect(() => d.estimateDemand({ buckets, now: NOW, targetMsat: TARGET, params: POLICY })).toThrow(RangeError);
  });

  it('CP-040/B4 only the newest max(min_samples, horizon / bucket) buckets are read', async () => {
    const d = await loadDemand();
    // W = max(12, 21,600 / 3,600 = 6) = 12: a 13th, older bucket of 10^15 msat must not move the estimate.
    const recent = Array.from({ length: 12 }, (_, i) => 1_000_000n * BigInt(i + 1));
    const result = ewma(d.estimateDemand({ buckets: history([10n ** 15n, ...recent], HOUR), now: NOW, targetMsat: TARGET, params: POLICY }));
    expect(result.samples).toBe(12);
    expect(result.requiredInboundMsat).toBe(reference(7n, 20n, recent, 21_600n, 3_600n, 7n, 5n));
    // Lab bucket 10 s: W = max(12, 2,160) = 2,160. Of 20,000 stored buckets the newest 2,160 hold a steady 10,000 msat,
    // so D_in = 10,000 exactly and Required = 10,000 × 2,160 × 1.4 = 30,240,000; the older 10^12 msat buckets are ignored.
    const volumes = Array.from({ length: 20_000 }, (_, i) => (i < 20_000 - 2_160 ? 10n ** 12n : 10_000n));
    const lab = ewma(d.estimateDemand({ buckets: history(volumes, 10), now: NOW, targetMsat: TARGET, params: { ...POLICY, bucketSeconds: 10 } }));
    expect(lab.samples).toBe(2_160);
    expect(same(lab.estimate, 10_000n, 1n)).toBe(true);
    expect(lab.requiredInboundMsat).toBe(30_240_000n);
  });
});

describe('numeric table', () => {
  it('CP-040/B4 a hand-derived N = 3 case: exact estimate and the requirement rounded up', async () => {
    const d = await loadDemand();
    // Oldest first: V(t−3) = 4,000,000, V(t−2) = 0, V(t−1) = 2,000,000, V(t) = 1,000,000; α = 0.35, min_samples 4.
    // D = (56000·1,000,000 + 36400·2,000,000 + 23660·0 + 15379·4,000,000) / 131439 = 190,316,000,000 / 131,439 ≈ 1,447,941.6.
    // Required = D · 21,600/3,600 · 7/5 = 7,993,272,000,000 / 657,195 = 12,162,709.698… → 12,162,710 msat (rounded up).
    const result = ewma(d.estimateDemand({
      buckets: history([4_000_000n, 0n, 2_000_000n, 1_000_000n], HOUR), now: NOW, targetMsat: TARGET, params: { ...POLICY, minSamples: 4 },
    }));
    expect(same(result.estimate, 190_316_000_000n, 131_439n)).toBe(true);
    expect(result.requiredInboundMsat).toBe(12_162_710n);
  });

  it('CP-040/B4 pinned table against the plain-arithmetic reference', async () => {
    const d = await loadDemand();
    const big = Array.from({ length: 12 }, (_, i) => 1_000_000_000_000n + BigInt(i) * 123_456_789_012n);
    const rows: { name: string; params: DemandParams; volumes: bigint[]; ref: bigint; pinned: bigint }[] = [
      {
        name: 'policy example, 12 hourly buckets', params: POLICY,
        volumes: [5_000_000n, 0n, 12_000_000n, 7_500_000n, 3_000_000n, 3_000_000n, 0n, 9_100_000n, 1_000_000n, 2_500_000n, 4_000_000n, 6_000_000n],
        ref: 0n, pinned: 36_841_620n,
      },
      {
        // α = 1: only the newest bucket counts. 4,000,001 × 6 × 1.4 = 33,600,008.4 → 33,600,009.
        name: 'alpha 1', params: { ...POLICY, alpha: '1' },
        volumes: [...Array.from({ length: 11 }, () => 9_999_999n), 4_000_001n], ref: 0n, pinned: 33_600_009n,
      },
      {
        // α = 1/2, oldest first 1, 2, 3: D = ½(3 + ½·2 + ¼·1) / (1 − ⅛) = 2.125 / 0.875 = 17/7;
        // horizon/bucket = 21,600/10 = 2,160, burst 1: 17·2,160/7 = 5,245.71… → 5,246.
        name: 'lab bucket 10 s', params: { bucketSeconds: 10, alpha: '0.5', minSamples: 3, horizonSeconds: HORIZON, burstFactor: '1' },
        volumes: [1n, 2n, 3n], ref: 0n, pinned: 5_246n,
      },
      {
        // bucket 1 s multiplies by 21,600; the product passes 2^53, where float arithmetic answers …456.
        name: 'bucket 1 s, amounts past 2^53', params: { ...POLICY, bucketSeconds: 1 },
        volumes: big, ref: 0n, pinned: 64_629_613_555_746_458n,
      },
    ];
    const ratio = (text: string): [bigint, bigint] => {
      const [whole = '0', frac = ''] = text.split('.');
      return [BigInt(whole + frac), 10n ** BigInt(frac.length)];
    };
    for (const row of rows) {
      const [an, ad] = ratio(row.params.alpha);
      const [bn, bd] = ratio(row.params.burstFactor);
      // The reference needs α in lowest terms only for readability; the formula holds for any a/d.
      row.ref = reference(an, ad, row.volumes, BigInt(row.params.horizonSeconds), BigInt(row.params.bucketSeconds), bn, bd);
      expect(row.ref, `${row.name} reference`).toBe(row.pinned);
      const result = ewma(d.estimateDemand({
        buckets: history(row.volumes, row.params.bucketSeconds), now: NOW, targetMsat: TARGET, params: row.params,
      }));
      expect(result.samples, row.name).toBe(row.volumes.length);
      expect(result.requiredInboundMsat, row.name).toBe(row.pinned);
    }
  });
});
