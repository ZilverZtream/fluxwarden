// Pinned CLN v26.06.9 doc/schemas/listhtlcs.json: created-index pagination,
// inclusive start, limit, incoming HTLC state and SCID. listinvoices has no incoming channel.
// SPEC recovery/accounting and independent AUDIT-07 require complete native attribution.
import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { clnInvoice, sendpay } from '../fakes/cln/responses.js';
import type { ClnRest } from '../helpers/adapter-interfaces.js';
import { loadClnExecute, sha256 } from '../helpers/cp030-execution.js';
import { testRoot } from '../helpers/env.js';

const preimage = randomBytes(32);
const hash = sha256(preimage);
writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `pagination-${randomBytes(8).toString('hex')}.bin`), preimage, { mode: 0o600 });
const actual = '105x1x0';

async function receipt(matchIndex: number) {
  const starts: number[] = [];
  let interrupt = false;
  const history = Array.from({ length: 501 }, (_, offset) => ({ created_index: offset + 1, updated_index: offset + 1,
    short_channel_id: offset + 1 === matchIndex ? actual : '100x1x0', id: offset, expiry: 830,
    direction: 'in', amount_msat: offset + 1 === matchIndex ? 100_000_000 : 1,
    payment_hash: offset + 1 === matchIndex ? hash : 'ab'.repeat(32), state: 'SENT_REMOVE_ACK_REVOCATION' }));
  const rest: ClnRest = { call: async (method, params) => {
    await Promise.resolve();
    if (method === 'listsendpays') return { payments: [sendpay({ payment_hash: hash, status: 'complete',
      amount_msat: 100_000_000, amount_sent_msat: 100_150_000, payment_preimage: preimage.toString('hex') })] };
    if (method === 'listinvoices') return { invoices: [clnInvoice({ payment_hash: hash, status: 'paid',
      amount_msat: 100_000_000, amount_received_msat: 100_000_000 })] };
    if (method !== 'listhtlcs') throw new Error(`unexpected read-only RPC ${method}`);
    expect(params?.['index']).toBe('created');
    const start = Number(params?.['start']);
    const limit = Number(params?.['limit']);
    expect(Number.isSafeInteger(start) && start >= 0).toBe(true);
    expect(Number.isSafeInteger(limit) && limit > 0 && limit <= 500).toBe(true);
    starts.push(start);
    if (interrupt && start > 0) throw new Error('transport closed during the next HTLC history page');
    return { htlcs: history.filter(item => item.created_index >= start).slice(0, limit) };
  } };
  const { ClnExecutionAdapter } = await loadClnExecute();
  const adapter = new ClnExecutionAdapter(rest, { ownId: '03' + 'cd'.repeat(32), waitChunkSeconds: 1, attemptDeadlineMs: 1_000 });
  return { adapter, starts, setInterrupted: (value: boolean) => { interrupt = value; } };
}

it('CP-031/AUDIT-07 complete incoming history beyond 500 HTLCs attributes the actual receiving SCID', async () => {
  const r = await receipt(501);
  const observation = await r.adapter.observePayment(hash);
  expect.soft(observation).toMatchObject({ kind: 'SUCCEEDED', feeMsat: 150_000n, settledChannelKey: actual });
  expect.soft(r.starts.some(start => start > 0), 'a full first page must be followed by a later page').toBe(true);
  for (let i = 1; i < r.starts.length; i++) expect(r.starts[i]).toBeGreaterThan(r.starts[i - 1] ?? -1);
});

it('CP-031/AUDIT-07 a real second-page transport failure leaves an apparent incoming match unresolved and a later complete read recovers it', async () => {
  const r = await receipt(1);
  r.setInterrupted(true);
  expect(await r.adapter.observePayment(hash)).toMatchObject({ kind: 'SUCCEEDED', settledChannelKey: null });
  expect.soft(r.starts.some(start => start > 0), 'the injected failure must actually be reached').toBe(true);
  r.setInterrupted(false);
  expect.soft(await r.adapter.observePayment(hash)).toMatchObject({ kind: 'SUCCEEDED', feeMsat: 150_000n, settledChannelKey: actual });
});
