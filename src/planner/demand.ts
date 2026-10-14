/**
 * Demand estimation: a truncated EWMA of settled incoming volume per bucket, normalised so its weights sum
 * to 1, and the operator target as fallback. Every figure is an exact rational over bigint; the requirement
 * is rounded up to whole msat, so rounding never understates the inbound needed.
 *
 *   D_in     = α · Σ_{k=0..N} (1−α)^k · V(t−k) / (1 − (1−α)^(N+1))     (k = 0 the newest bucket)
 *   Required = ceil(D_in · (horizon / bucket_seconds) · burst_factor)
 */

/** denominator > 0; not necessarily reduced. */
export interface Rational {
  readonly numerator: bigint;
  readonly denominator: bigint;
}

export interface DemandParams {
  readonly bucketSeconds: number;
  /** Decimal string, 0 < α ≤ 1. */
  readonly alpha: string;
  readonly minSamples: number;
  readonly horizonSeconds: number;
  /** Decimal string, ≥ 0. */
  readonly burstFactor: string;
}

export interface VolumeBucket {
  /** Unix ms; the bucket covers [start, start + bucketSeconds × 1000). */
  readonly start: number;
  /** Settled incoming volume in the bucket; 0 when observed and empty. */
  readonly volumeMsat: bigint;
}

export type DemandResult =
  | { readonly source: 'EWMA'; readonly samples: number; readonly estimate: Rational; readonly requiredInboundMsat: bigint }
  | { readonly source: 'TARGETS'; readonly reason: 'INSUFFICIENT_HISTORY'; readonly samples: number; readonly requiredInboundMsat: bigint };

const DECIMAL = /^(0|[1-9][0-9]*)(?:\.([0-9]+))?$/;

function gcd(a: bigint, b: bigint): bigint {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y !== 0n) [x, y] = [y, x % y];
  return x;
}

function reduced(numerator: bigint, denominator: bigint): Rational {
  const divisor = gcd(numerator, denominator);
  return divisor <= 1n ? { numerator, denominator } : { numerator: numerator / divisor, denominator: denominator / divisor };
}

/** A decimal string as an exact rational in lowest terms. */
function parseDecimal(text: string, what: string): Rational {
  const match = DECIMAL.exec(text);
  if (match === null) throw new RangeError(`${what} must be a decimal string such as "0.35"`);
  const fraction = match[2] ?? '';
  return reduced(BigInt((match[1] ?? '') + fraction), 10n ** BigInt(fraction.length));
}

function parseAlpha(alpha: string): Rational {
  const value = parseDecimal(alpha, 'alpha');
  if (value.numerator <= 0n || value.numerator > value.denominator) throw new RangeError('alpha must be greater than 0 and at most 1');
  return value;
}

function positiveInteger(value: number, what: string): bigint {
  if (!Number.isSafeInteger(value) || value < 1) throw new RangeError(`${what} must be an integer of at least 1`);
  return BigInt(value);
}

function bucketCount(n: number): number {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError('N must be a non-negative integer');
  return n + 1;
}

/**
 * The normalised weights w_k = α(1−α)^k / (1 − (1−α)^(N+1)) for k = 0..N. With α = a/d the common factor
 * d^(N+1) cancels: w_k = a·(d−a)^k·d^(N−k) / (d^(N+1) − (d−a)^(N+1)).
 */
export function ewmaWeights(alpha: string, n: number): readonly Rational[] {
  const { numerator: a, denominator: d } = parseAlpha(alpha);
  const count = bucketCount(n);
  const q = d - a;
  const denominator = d ** BigInt(count) - q ** BigInt(count);
  const weights: Rational[] = [];
  for (let k = 0; k < count; k += 1) weights.push(reduced(a * q ** BigInt(k) * d ** BigInt(count - 1 - k), denominator));
  return weights;
}

/** Whether the buckets are strictly ascending without gaps or duplicates and end with the last complete bucket before `now`. */
function contiguous(buckets: readonly VolumeBucket[], width: number, now: number): boolean {
  for (let i = 1; i < buckets.length; i += 1) {
    const previous = buckets[i - 1];
    const current = buckets[i];
    if (previous === undefined || current === undefined || current.start - previous.start !== width) return false;
  }
  const newest = buckets[buckets.length - 1];
  return newest !== undefined && newest.start + width <= now && now < newest.start + 2 * width;
}

/**
 * The required inbound of one channel, read from the newest max(min_samples, ceil(horizon / bucket_seconds))
 * buckets only, so the cost is bounded by policy values rather than the stored history. EWMA when they
 * number at least min_samples, run oldest first without a gap, duplicate or reordering, and end with the last
 * complete bucket; otherwise the operator target with source TARGETS and reason INSUFFICIENT_HISTORY.
 */
export function estimateDemand(input: {
  readonly buckets: readonly VolumeBucket[];
  readonly now: number;
  readonly targetMsat: bigint;
  readonly params: DemandParams;
}): DemandResult {
  const { now, params } = input;
  const { numerator: a, denominator: d } = parseAlpha(params.alpha);
  const bucketSeconds = positiveInteger(params.bucketSeconds, 'bucketSeconds');
  const minSamples = Number(positiveInteger(params.minSamples, 'minSamples'));
  const horizon = positiveInteger(params.horizonSeconds, 'horizonSeconds');
  const burst = parseDecimal(params.burstFactor, 'burstFactor');
  if (!Number.isSafeInteger(now)) throw new RangeError('now must be unix milliseconds');
  for (const bucket of input.buckets) {
    if (!Number.isSafeInteger(bucket.start)) throw new RangeError('a bucket start must be unix milliseconds');
    if (typeof bucket.volumeMsat !== 'bigint' || bucket.volumeMsat < 0n) throw new RangeError('a bucket volume must be a non-negative bigint');
  }
  const perHorizon = (horizon + bucketSeconds - 1n) / bucketSeconds;
  const windowSize = Math.max(minSamples, Number(perHorizon));
  const buckets = input.buckets.slice(-windowSize);
  const samples = buckets.length;
  const width = params.bucketSeconds * 1000;
  if (samples < minSamples || !Number.isSafeInteger(width) || !contiguous(buckets, width, now)) {
    return { source: 'TARGETS', reason: 'INSUFFICIENT_HISTORY', samples, requiredInboundMsat: input.targetMsat };
  }

  // Oldest first, bucket j has k = N − j and weight a·q^(N−j)·d^j over d^(N+1) − q^(N+1).
  const q = d - a;
  let numerator = 0n;
  let dPower = 1n;
  let qPower = 1n;
  for (let j = 0; j < samples; j += 1) {
    numerator = numerator * q + a * dPower * (buckets[j]?.volumeMsat ?? 0n);
    dPower *= d;
    qPower *= q;
  }
  const estimate = reduced(numerator, dPower - qPower);

  const top = estimate.numerator * horizon * burst.numerator;
  const bottom = estimate.denominator * bucketSeconds * burst.denominator;
  const requiredInboundMsat = (top + bottom - 1n) / bottom;
  return { source: 'EWMA', samples, estimate, requiredInboundMsat };
}
