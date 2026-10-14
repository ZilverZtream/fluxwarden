// Adapted from ZilverZtream/macwarden examples/payment-lab/src/util/money.ts (25bbfa4).
/** Amounts are carried as millisatoshi bigints end to end: LND's REST API sends uint64 values as strings. */

export type Msat = bigint & { readonly __msat: unique symbol };

export const MSAT_PER_SAT = 1000n;

export function satToMsat(sat: bigint): bigint {
  return sat * MSAT_PER_SAT;
}

/** `25000000n` → `25,000 sat`; `1121n` → `1.121 sat`. */
export function formatMsat(msat: bigint): string {
  const negative = msat < 0n;
  const absolute = negative ? -msat : msat;
  const sat = absolute / MSAT_PER_SAT;
  const rest = absolute % MSAT_PER_SAT;
  const whole = sat.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const fraction = rest === 0n ? '' : `.${rest.toString().padStart(3, '0').replace(/0+$/, '')}`;
  return `${negative ? '-' : ''}${whole}${fraction} sat`;
}

/** The largest value SQLite stores in an INTEGER column (a signed 64-bit integer): 2^63 - 1. */
export const MAX_INT64 = 2n ** 63n - 1n;

/** Canonical non-negative millisatoshis, bounded to the signed storage range. */
export function parseMsat(text: string): Msat {
  return parseAmount(text, 'money parse') as Msat;
}

/** JSON and wire amounts are decimal strings, separate from display formatting. */
export function msatToString(value: Msat): string {
  return value.toString();
}

function checkedMsat(value: bigint, stage: string): Msat {
  if (value < 0n || value > MAX_INT64) throw new Error(`${stage}: amount out of range`);
  return value as Msat;
}

/** Forwarding fees include the base fee and floor the proportional part. */
export function hopFee(amount: Msat, base: Msat, ppm: bigint): Msat {
  checkedMsat(amount, 'hop fee');
  checkedMsat(base, 'hop fee');
  if (ppm < 0n) throw new Error('hop fee: negative rate');
  return checkedMsat(base + amount * ppm / 1_000_000n, 'hop fee');
}

/** Round up for cap checks so a fractional ppm never understates the fee. */
export function routePpm(fee: Msat, principal: Msat): bigint {
  checkedMsat(fee, 'route ppm');
  checkedMsat(principal, 'route ppm');
  if (principal === 0n) throw new Error('route ppm: zero principal');
  return (fee * 1_000_000n + principal - 1n) / principal;
}

/** Parses a non-negative integer given on the command line, at most MAX_INT64 (anything larger can not be stored). */
export function parseAmount(text: string, what: string): bigint {
  if (!/^(0|[1-9][0-9]{0,18})$/.test(text) || text.endsWith('\n')) throw new Error(`${what} must be a non-negative integer`);
  const value = BigInt(text);
  if (value > MAX_INT64) throw new Error(`${what} must be at most ${MAX_INT64.toString()}`);
  return value;
}

/** `value` limited to the signed 64-bit range, for a figure that is stored but may exceed it (a sum of stored amounts). */
export function saturateInt64(value: bigint): bigint {
  if (value > MAX_INT64) return MAX_INT64;
  if (value < -MAX_INT64 - 1n) return -MAX_INT64 - 1n;
  return value;
}
