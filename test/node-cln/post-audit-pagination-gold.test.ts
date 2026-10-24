// Pinned CLN v26.06.9 doc/schemas/listhtlcs.json: created-index pagination,
// inclusive start, limit, incoming HTLC state and SCID. listinvoices has no incoming channel.
// SPEC recovery/accounting and independent AUDIT-07 require complete native attribution.
// D29 2026-10-24: peer_htlcs.c remove_htlc_in L1880-1926 accepts failed as
// well as fulfilled terminal removals. HTLC state alone is not credited-channel
// evidence. Positive attribution uses native bookkeeper channel credit; actual
// native invoice pagination and interruption remain covered below.
import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { accountEvent, clnInvoice, peerChannel, sendpay } from '../fakes/cln/responses.js';
import { certificatePath, type FakeServer } from '../fakes/https.js';
import type { ClnRest, ClnRestOptions } from '../helpers/adapter-interfaces.js';
import { loadClnExecute, sha256 } from '../helpers/cp030-execution.js';
import { demo } from '../helpers/cpw-cli.js';
import { testRoot } from '../helpers/env.js';
import { loadSrc } from '../helpers/load-src.js';
import { registerMoneySafetyCredentials } from '../helpers/public-money-safety.js';

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
    if (method === 'bkpr-listaccountevents') {
      if (interrupt) throw new Error('transport closed before native channel credit history completed');
      return { events: [accountEvent({ account: '78'.repeat(32), payment_id: hash,
        credit_msat: 100_000_000, debit_msat: 0, fees_msat: 0 })] };
    }
    if (method === 'listpeerchannels') return { channels: [peerChannel({ short_channel_id: actual })] };
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

it('CP-031/AUDIT-07 independent native channel credit attributes the actual SCID alongside 501 terminal HTLCs', async () => {
  const r = await receipt(501);
  const observation = await r.adapter.observePayment(hash);
  expect.soft(observation).toMatchObject({ kind: 'SUCCEEDED', feeMsat: 150_000n, settledChannelKey: actual });
  // A complete native account credit is conclusive without scanning unrelated
  // terminal HTLCs; any chosen history scan still obeys native forward cursors.
  for (let i = 1; i < r.starts.length; i++) expect(r.starts[i]).toBeGreaterThan(r.starts[i - 1] ?? -1);
});

it('CP-031/AUDIT-07 unavailable independent credit leaves an apparent HTLC match unresolved and later native credit recovers it', async () => {
  const r = await receipt(1);
  r.setInterrupted(true);
  expect(await r.adapter.observePayment(hash)).toMatchObject({ kind: 'SUCCEEDED', settledChannelKey: null });
  r.setInterrupted(false);
  expect.soft(await r.adapter.observePayment(hash)).toMatchObject({ kind: 'SUCCEEDED', feeMsat: 150_000n, settledChannelKey: actual });
});

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

interface IncomingReader {
  incomingHistory(): Promise<{ complete: boolean; receipts: readonly { channelKey: string; settledAt: number; amountMsat: bigint }[] }>;
}
interface ReaderModule { readonly openClnReader: (options: ClnRestOptions) => Promise<IncomingReader> }

it('CP-031/AUDIT-07 native paid invoice pagination reaches receipt 501 and refuses incomplete history until the next page recovers', async () => {
  const d = await demo(open, { withKey: false });
  registerMoneySafetyCredentials([d.cln.runeFile]);
  const at = Math.floor(Date.now() / 1000) - 60;
  const history = Array.from({ length: 501 }, (_, index) => ({ index: index + 1,
    hash: sha256(Buffer.from(`external-paginated-receipt-${String(index + 1)}`)) }));
  const starts: number[] = [];
  let interrupted = true, failedSecondPage = false;
  const respond = d.cln.fake.result;
  d.cln.fake.result = (context, behavior, value) => {
    if (context.request.url === '/v1/listinvoices') {
      // CLN v26.06.9 listinvoices.json index/start/limit, inclusive created index.
      expect(context.params['index']).toBe('created');
      const start = Number(context.params['start'] ?? 0), limit = Number(context.params['limit']);
      expect(limit > 0 && limit <= 500).toBe(true);
      starts.push(start);
      if (interrupted && start > 0) {
        failedSecondPage = true;
        d.cln.fake.reset(context, 'connection-reset');
        return;
      }
      value = { invoices: history.filter(row => row.index >= start).slice(0, limit).map(row => clnInvoice({
        label: `external-${String(row.index)}`, payment_hash: row.hash, status: 'paid', paid_at: at,
        amount_msat: 1_000, amount_received_msat: 1_000, created_index: row.index, pay_index: row.index,
      })) };
    }
    if (context.request.url === '/v1/bkpr-listaccountevents') value = { events: history.map(row => accountEvent({
      account: '25'.repeat(32), payment_id: row.hash, credit_msat: 1_000, debit_msat: 0,
      fees_msat: 0, timestamp: at, is_rebalance: false,
    })) };
    // Keep native incoming history available for readers which corroborate it
    // with bookkeeper. The terminal state is never the only success evidence.
    if (context.request.url === '/v1/listhtlcs') {
      const start = Number(context.params['start'] ?? 0), limit = Number(context.params['limit'] ?? 500);
      value = { htlcs: history.filter(row => row.index >= start).slice(0, limit).map(row => ({
        created_index: row.index, updated_index: row.index, short_channel_id: actual, id: row.index,
        expiry: 830, direction: 'in', amount_msat: 1_000, payment_hash: row.hash, state: 'SENT_REMOVE_ACK_REVOCATION',
      })) };
    }
    respond(context, behavior, value);
  };
  const endpoint = new URL(d.cln.url);
  const { openClnReader } = await loadSrc<ReaderModule>('node-cln/reader.ts');
  const reader = await openClnReader({ host: endpoint.hostname, port: Number(endpoint.port),
    tlsCertPath: certificatePath('node'), runePath: d.cln.runeFile, timeoutMs: 1_000 });
  const partial = await reader.incomingHistory().then(value => value, () => null);
  expect(failedSecondPage, 'the failure must actually occur on a native next-page read').toBe(true);
  expect(partial === null || !partial.complete, 'partial invoice history cannot certify complete receipt evidence').toBe(true);
  interrupted = false;
  starts.length = 0;
  const complete = await reader.incomingHistory();
  expect(complete.complete).toBe(true);
  expect(complete.receipts).toHaveLength(501);
  expect(complete.receipts.every(receipt => receipt.channelKey === actual && receipt.amountMsat === 1_000n && receipt.settledAt === at * 1_000)).toBe(true);
  expect(complete.receipts.reduce((total, receipt) => total + receipt.amountMsat, 0n)).toBe(501_000n);
  expect(starts.length).toBeGreaterThan(1);
  for (let i = 1; i < starts.length; i++) expect(starts[i]).toBeGreaterThan(starts[i - 1] ?? -1);
});
