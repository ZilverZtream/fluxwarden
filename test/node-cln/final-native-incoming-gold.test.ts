// SPEC §8.7 step4 and §9.2 require the receiver's actual channel, not the planned
// payer route. Native sources: LND v0.21.4-beta lightning.proto InvoiceHTLC
// (state SETTLED=1, chan_id, amt_msat); CLN v26.06.9 listhtlcs.json (readonly,
// created_index/short_channel_id/direction/amount_msat/payment_hash/state), plus
// a PAID listinvoices receipt. No incoming-channel field is invented on CLN invoices.
import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { clnInvoice, sendpay } from '../fakes/cln/responses.js';
import { attempt, b64, invoice, payment } from '../fakes/lnd/responses.js';
import type { ClnRest, LndRest } from '../helpers/adapter-interfaces.js';
import { loadClnExecute, loadLndExecute, sha256 } from '../helpers/cp030-execution.js';
import { testRoot } from '../helpers/env.js';

const preimage = randomBytes(32);
const hash = sha256(preimage);
writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `incoming-${randomBytes(8).toString('hex')}.bin`), preimage, { mode: 0o600 });
const actualLnd = '369435907129344';
const actualCln = '108x3x0';
const principal = 100_000_000;

function incomingLnd(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { chan_id: actualLnd, htlc_index: '7', amt_msat: '100000000', accept_height: 800,
    accept_time: '1760000000', resolve_time: '1760000001', expiry_height: 830,
    state: 'SETTLED', custom_records: {}, mpp_total_amt_msat: '100000000', amp: null,
    custom_channel_data: '', ...over };
}

async function lndReceipt(htlcs: readonly Record<string, unknown>[]) {
  const calls: { method: string; path: string }[] = [];
  const settled = payment({ payment_hash: hash, payment_preimage: preimage.toString('hex'),
    status: 'SUCCEEDED', value_msat: '100000000', fee_msat: '202101',
    htlcs: [{ ...attempt('SUCCEEDED', '4'), preimage: b64(preimage.toString('hex')) }] });
  const rest: LndRest = {
    call: (method, path) => {
      calls.push({ method, path });
      if (method === 'GET' && path.startsWith('/v1/invoice/')) {
        return Promise.resolve(invoice({ r_hash: b64(hash), state: 'SETTLED', settled: true,
          value_msat: '100000000', amt_paid_msat: '100000000', htlcs }));
      }
      return Promise.reject(new Error(`Unexpected public read ${method} ${path}`));
    },
    stream: (method, path, _body, onMessage) => {
      calls.push({ method, path });
      onMessage(settled);
      return Promise.resolve('ended');
    },
  };
  const { LndExecutionAdapter } = await loadLndExecute();
  const lnd = new LndExecutionAdapter(rest, { trackDeadlineMs: 1_000 });
  return { observed: await lnd.observePayment(hash), calls };
}

function incomingCln(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { created_index: 7, updated_index: 9, short_channel_id: actualCln, id: 3,
    expiry: 830, direction: 'in', amount_msat: principal, payment_hash: hash,
    state: 'SENT_REMOVE_ACK_REVOCATION', ...over };
}

async function clnReceipt(htlcs: readonly Record<string, unknown>[], truncated = false) {
  const calls: { method: string; params: Record<string, unknown> | undefined }[] = [];
  let pages = 0;
  const rest: ClnRest = { call: (method, params) => {
    calls.push({ method, params });
    if (method === 'listsendpays') return Promise.resolve({ payments: [sendpay({ payment_hash: hash,
      status: 'complete', amount_msat: principal, amount_sent_msat: 100202101, payment_preimage: preimage.toString('hex') })] });
    if (method === 'listinvoices') return Promise.resolve({ invoices: [clnInvoice({ payment_hash: hash,
      status: 'paid', amount_msat: principal, amount_received_msat: principal })] });
    if (method === 'listhtlcs') {
      pages += 1;
      if (truncated && pages > 1) return Promise.reject(new Error('ordinary transport closed before the next history page'));
      return Promise.resolve({ htlcs });
    }
    return Promise.reject(new Error(`Unexpected public RPC ${method}`));
  } };
  const { ClnExecutionAdapter } = await loadClnExecute();
  const cln = new ClnExecutionAdapter(rest, { ownId: '03' + 'd4'.repeat(32), waitChunkSeconds: 1, attemptDeadlineMs: 1_000 });
  return { observed: await cln.observePayment(hash), calls };
}

it('CP-030/B6 LND settled receiver InvoiceHTLC preserves an alternate actual incoming uint64 channel through read-only lookup', async () => {
  const r = await lndReceipt([incomingLnd()]);
  expect(r.observed).toMatchObject({ kind: 'SUCCEEDED', settledChannelKey: actualLnd, feeMsat: 202_101n });
  expect(r.calls.every(call => call.method === 'GET')).toBe(true);
});

for (const [name, htlcs] of [
  ['missing', []],
  ['ambiguous', [incomingLnd(), incomingLnd({ chan_id: '492581209505792', htlc_index: '8' })]],
  ['accepted rather than settled', [incomingLnd({ state: 'ACCEPTED' })]],
] as const) {
  it(`CP-030/B6 LND ${name} receiver HTLC leaves actual incoming channel unresolved`, async () => {
    expect((await lndReceipt(htlcs)).observed).toMatchObject({ kind: 'SUCCEEDED', settledChannelKey: null });
  });
}

it('CP-031/B3 CLN paid receiver and unique completed incoming history preserve actual SCID with bounded read-only calls', async () => {
  const r = await clnReceipt([incomingCln(), incomingCln({ direction: 'out', state: 'RCVD_REMOVE_ACK_REVOCATION', short_channel_id: '103x1x0', created_index: 8 })]);
  expect(r.observed).toMatchObject({ kind: 'SUCCEEDED', settledChannelKey: actualCln, feeMsat: 202_101n });
  expect(r.calls.every(call => ['listsendpays', 'listinvoices', 'listhtlcs'].includes(call.method))).toBe(true);
  const reads = r.calls.filter(call => call.method === 'listhtlcs');
  expect(reads.length).toBeGreaterThanOrEqual(1);
  for (const read of reads) {
    expect(read.params?.['index']).toBe('created');
    expect(Number(read.params?.['limit'])).toBeGreaterThan(0);
    expect(Number(read.params?.['limit'])).toBeLessThanOrEqual(500);
  }
});

for (const [name, htlcs] of [
  ['missing', []],
  ['ambiguous', [incomingCln(), incomingCln({ short_channel_id: '109x3x0', created_index: 8, id: 4 })]],
  ['unresolved incoming state', [incomingCln({ state: 'RCVD_ADD_ACK_REVOCATION' })]],
] as const) {
  it(`CP-031/B3 CLN ${name} receiver history cannot invent an incoming channel`, async () => {
    expect((await clnReceipt(htlcs)).observed).toMatchObject({ kind: 'SUCCEEDED', settledChannelKey: null });
  });
}

it('CP-031/B3 CLN truncated history after an apparent incoming match stays unresolved', async () => {
  const htlcs = Array.from({ length: 500 }, (_, index) => incomingCln({ created_index: index + 1, id: index,
    payment_hash: index === 0 ? hash : 'ab'.repeat(32), amount_msat: index === 0 ? principal : 1 }));
  expect((await clnReceipt(htlcs, true)).observed).toMatchObject({ kind: 'SUCCEEDED', settledChannelKey: null });
});
