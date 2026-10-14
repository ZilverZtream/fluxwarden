import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { expect, it } from 'vitest';
import { loadCore, type Bolt11 } from '../helpers/cp004-reference.js';
import { hashField, syntheticInvoice } from '../helpers/cp004-invoice.js';
import { readJson } from '../helpers/cli.js';

// Upstream payment-lab-payer-audit.test.ts offline-reader vectors, plus explicit size/case boundaries.
it('CP-004/B5 checksum-valid invoice hashes preserve case semantics and reject Unicode look-alikes', async () => {
  const decoder = await loadCore<Bolt11>('bolt11');
  const hash = 'ab'.repeat(32);
  const invoice = syntheticInvoice(hash);
  expect(decoder.bolt11PaymentHash(invoice)).toBe(hash);
  expect(decoder.bolt11PaymentHash(invoice.toUpperCase())).toBe(hash);
  expect(decoder.bolt11PaymentHash(syntheticInvoice('00'.repeat(32), [13, 0, 1, 7]))).toBe('00'.repeat(32));
  const kelvin = invoice.replace('k', '\u212a');
  expect(kelvin === invoice, 'vector contains the look-alike').toBe(false);
  const corrupted = `${invoice.slice(0, -1)}${invoice.endsWith('q') ? 'p' : 'q'}`;
  expect(corrupted === invoice, 'checksum-corruption vector changes the invoice').toBe(false);
  for (const variant of [kelvin, kelvin.toUpperCase(), invoice.replace('k', '\u017f'), `${invoice.slice(0, -1)}\u0130`, `L${invoice.slice(1)}`, corrupted, 'lnbcrt1!']) {
    expect(decoder.bolt11PaymentHash(variant), 'invalid invoice').toBeUndefined();
  }
  expect(decoder.damagedPaymentRequest(kelvin)).toBe(true);
  expect(decoder.damagedPaymentRequest(invoice)).toBe(false);
});

it('CP-004/B5 oversized and repeated-separator invoices are rejected without quadratic backtracking', async () => {
  const decoder = await loadCore<Bolt11>('bolt11');
  const oversized = `ln${'a1'.repeat(4096)}`;
  expect(decoder.bolt11PaymentHash(oversized)).toBeUndefined();
  const long = `ln${'a1'.repeat(100000)}!`;
  const began = performance.now();
  expect(decoder.damagedPaymentRequest(long)).toBe(true);
  expect(performance.now() - began).toBeLessThan(2000);
  expect(decoder.bolt11PaymentHash(long)).toBeUndefined();
  expect(decoder.damagedPaymentRequest('ln1')).toBe(true);
  expect(decoder.damagedPaymentRequest('ln1q')).toBe(true);
});

interface Examples { source: string; valid: { name: string; invoice: string; paymentHash: string }[]; invalid: { name: string; invoice: string }[] }

it('CP-004/B5 the BOLT #11 example invoices give their exact documented payment hashes whichever field comes first', async () => {
  const decoder = await loadCore<Bolt11>('bolt11');
  const examples = readJson('test/fixtures/bolt11/bolt11-examples.json') as Examples;
  expect(examples.valid.length, 'every recorded example is checked').toBe(7);
  for (const example of examples.valid) {
    expect(decoder.bolt11PaymentHash(example.invoice), example.name).toBe(example.paymentHash);
    expect(decoder.damagedPaymentRequest(example.invoice), `${example.name}: not damaged`).toBe(false);
  }
  for (const example of examples.invalid) expect(decoder.bolt11PaymentHash(example.invoice), example.name).toBeUndefined();
});

it('CP-004/B5 a regtest invoice reads the 52-word p field and skips the payment secret, unknown fields and wrong-length p fields', async () => {
  const decoder = await loadCore<Bolt11>('bolt11');
  // Field types are bech32 word values: p = 1, s = 16, unknown "2" = 10 (BOLT #11 tagged fields).
  const hash = createHash('sha256').update('regtest payment hash vector').digest('hex');
  const secret = createHash('sha256').update('regtest payment secret vector').digest('hex');
  const shortP = [1, 1, 19, ...Array<number>(51).fill(7)];
  const longP = [1, 1, 21, ...Array<number>(53).fill(9)];
  for (const extra of [hashField(16, secret), [...shortP, ...hashField(16, secret)], [...longP, 10, 0, 3, 1, 2, 3]]) {
    const invoice = syntheticInvoice(hash, extra);
    expect(invoice.startsWith('lnbcrt1'), 'regtest prefix').toBe(true);
    expect(decoder.bolt11PaymentHash(invoice)).toBe(hash);
  }
  const reversed = Buffer.from(hash, 'hex').reverse().toString('hex');
  expect(reversed === hash, 'the vector distinguishes byte order').toBe(false);
});

it('CP-004/B5 a checksum-valid invoice longer than the 8192-character reader bound is refused', async () => {
  const decoder = await loadCore<Bolt11>('bolt11');
  const hash = createHash('sha256').update('bounded reader vector').digest('hex');
  // Unknown fields of 1023 words each (the largest a 10-bit length allows) grow a valid invoice.
  const filler = (count: number): number[] => Array.from({ length: count }, () => [10, 31, 31, ...Array<number>(1023).fill(0)]).flat();
  const within = syntheticInvoice(hash, filler(7));
  const beyond = syntheticInvoice(hash, filler(8));
  expect(within.length).toBeLessThanOrEqual(8192);
  expect(beyond.length).toBeGreaterThan(8192);
  expect(decoder.bolt11PaymentHash(within), 'a long valid invoice within the bound is read').toBe(hash);
  expect(decoder.bolt11PaymentHash(beyond), 'the same structure beyond the bound is refused').toBeUndefined();
});
