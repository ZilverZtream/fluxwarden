import { expect, it } from 'vitest';
import { loadCore, type Money } from '../helpers/cp004-reference.js';

// Exact monetary literals and formulas follow the public money representation and fee specification.
it('CP-004/B1 canonical amounts retain every bit through parsing and bigint arithmetic', async () => {
  const money = await loadCore<Money>('money');
  for (const text of ['0', '1', '9007199254740992', '9223372036854775807']) {
    const amount = money.parseMsat(text);
    expect(amount).toBe(BigInt(text));
    expect(typeof amount).toBe('bigint');
    expect(money.msatToString(amount)).toBe(text);
    expect(money.parseMsat(money.msatToString(amount))).toBe(amount);
    expect(amount + 1n - 1n).toBe(BigInt(text));
  }
  expect(money.parseMsat('9007199254740992') + money.parseMsat('1')).toBe(9007199254740993n);
  for (const text of ['9223372036854775808', '-1', '-0', '1.5', '1e3', '0x10', '+1', '01', '', ' 1', '1 ', '1\n', '1msat']) {
    expect(() => money.parseMsat(text), 'invalid canonical amount').toThrow();
  }
});

it('CP-004/B2 forwarding fees include base fees and floor while route fee rates round up exactly', async () => {
  const money = await loadCore<Money>('money');
  const hops = [
    ['100000000', '1000', 1000n, '101000'], ['100101000', '1000', 1000n, '101101'],
    ['999', '0', 1000n, '0'], ['1000', '0', 1000n, '1'], ['1', '7', 0n, '7'],
    ['9007199254740993', '1000', 999999n, '9007190247542738'],
    ['9223372036854775807', '0', 1000000n, '9223372036854775807'],
  ] as const;
  for (const [amount, base, ppm, expected] of hops) {
    const result = money.hopFee(money.parseMsat(amount), money.parseMsat(base), ppm);
    expect(result).toBe(BigInt(expected));
    expect(result).toBe(BigInt(base) + BigInt(amount) * ppm / 1000000n);
  }
  const routes = [
    ['202101', '100000000', 2022n], ['1', '1000000', 1n], ['1', '1000001', 1n],
    ['0', '1', 0n], ['1', '1', 1000000n], ['9007199254740993', '9223372036854775807', 977n],
  ] as const;
  for (const [fee, principal, expected] of routes) {
    const result = money.routePpm(money.parseMsat(fee), money.parseMsat(principal));
    expect(result).toBe(expected);
    expect(result).toBe((BigInt(fee) * 1000000n + BigInt(principal) - 1n) / BigInt(principal));
  }
  expect(() => money.routePpm(money.parseMsat('1'), money.parseMsat('0'))).toThrow();
});

it('CP-004/B8 JSON amounts are canonical decimal strings with no loss above the number range', async () => {
  const money = await loadCore<Money>('money');
  for (const text of ['0', '1', '9007199254740993', '9223372036854775807']) {
    const encoded = money.msatToString(money.parseMsat(text));
    expect(encoded).toMatch(/^-?(0|[1-9][0-9]*)$/);
    expect(JSON.stringify({ amount_msat: encoded })).toBe(`{"amount_msat":"${text}"}`);
  }
});

it('CP-004/B9 extracted money display conversion and saturation preserve the reference results', async () => {
  const money = await loadCore<Money>('money');
  expect(money.satToMsat(9007199254740993n)).toBe(9007199254740993000n);
  for (const [input, expected] of [[25000000n, '25,000 sat'], [1121n, '1.121 sat'], [1010n, '1.01 sat'], [-1n, '-0.001 sat'], [0n, '0 sat']] as const) {
    expect(money.formatMsat(input)).toBe(expected);
  }
  expect(money.parseAmount('9223372036854775807', 'amount')).toBe(9223372036854775807n);
  expect(() => money.parseAmount('9223372036854775808', 'amount')).toThrow();
  expect(money.saturateInt64(9223372036854775808n)).toBe(9223372036854775807n);
  expect(money.saturateInt64(-9223372036854775809n)).toBe(-9223372036854775808n);
  expect(money.saturateInt64(-1n)).toBe(-1n);
});

it('CP-004/B2 a negative proportional fee rate is refused even when the fee would stay non-negative', async () => {
  const money = await loadCore<Money>('money');
  // Channel fee rates are unsigned (LND fee_rate_milli_msat, CLN fee_proportional_millionths).
  // base 1000 + 1000000 * -1 / 1000000 = 999 would otherwise look like a valid fee.
  expect(() => money.hopFee(money.parseMsat('1000000'), money.parseMsat('1000'), -1n)).toThrow();
  expect(money.hopFee(money.parseMsat('1000000'), money.parseMsat('1000'), 0n)).toBe(1000n);
});
