// Interface: existing wire fakes and real adapter ports (test/helpers/chaos-wire.ts).
// SPEC §11.6; the fake route definitions cite pinned node response semantics.
import { expect, it } from 'vitest';
import { attempt, channel, payment } from '../fakes/lnd/responses.js';
import { clnInvoice, getinfo, peerChannel, sendpay } from '../fakes/cln/responses.js';
import { askrene } from '../fakes/cln/askrene.js';
import { circularRoute } from '../fakes/preflight-node.js';
import { loadClnProbe, loadErrors, rejection } from '../helpers/adapter-interfaces.js';
import { clnWire, lndWire, trackRecord, WIRE_HASH, WIRE_PREIMAGE } from '../helpers/chaos-wire.js';

const complete = () => payment({ payment_hash: WIRE_HASH, status: 'SUCCEEDED', payment_preimage: WIRE_PREIMAGE.toString('hex'), fee_msat: '150000', failure_reason: 'FAILURE_REASON_TIMEOUT', htlcs: [attempt('SUCCEEDED', '1')] });

it('CP-033/B1 T-11 LND SUCCEEDED preimage beats failure_reason TIMEOUT', async () => {
  const w = await lndWire({ 'GET /v2/router/track/{payment_hash}': trackRecord(complete()) });
  try { expect(await w.execution.observePayment(WIRE_HASH)).toMatchObject({ kind: 'SUCCEEDED', preimageMatchesHash: true, feeMsat: 150_000n, htlcCount: 1 }); }
  finally { await w.close(); }
});

it('CP-033/B1 T-11 CLN 209 loses to the stored complete record with matching preimage', async () => {
  const w = await clnWire({
    sendpay: (c, f) => { f.result(c, 'pending', sendpay({ payment_hash: WIRE_HASH, status: 'pending' })); },
    waitsendpay: (c, f) => { f.rpcError(c, 'error209', 209, 'failed without stored reason'); },
    listsendpays: (c, f) => { f.result(c, 'complete', { payments: [sendpay({ payment_hash: WIRE_HASH, status: 'complete', amount_msat: '100000000msat', amount_sent_msat: '100150000msat', payment_preimage: WIRE_PREIMAGE.toString('hex') })] }); },
    listinvoices: (c, f) => { f.result(c, 'invoice-paid', { invoices: [clnInvoice({ payment_hash: WIRE_HASH, status: 'paid', amount_received_msat: 100_000_000, paid_at: 1760000001 })] }); },
  });
  try {
    const observation = await w.execution.sendOnRoute(circularRoute('112x1x0', '224x1x0', 150_000n, 80), WIRE_HASH, '55'.repeat(32));
    // The initial refusal is ambiguous; the reconciler's evidence lookup must prefer the matching preimage.
    expect(observation.kind).toBe('AMBIGUOUS');
    expect(await w.execution.observePayment(WIRE_HASH)).toMatchObject({ kind: 'SUCCEEDED', preimageMatchesHash: true, feeMsat: 150_000n });
  }
  finally { await w.close(); }
});

it('CP-033/B1 T-12 listsendpays failed pending complete swing waits for terminal evidence', async () => {
  let read = 0;
  const w = await clnWire({
    listsendpays: (c, f) => { const status = ['failed', 'pending', 'complete'][Math.min(read++, 2)]; f.result(c, 'swing', { payments: [sendpay({ payment_hash: WIRE_HASH, status, payment_preimage: status === 'complete' ? WIRE_PREIMAGE.toString('hex') : undefined, amount_msat: 100_000_000, amount_sent_msat: 100_150_000 })] }); },
    waitsendpay: (c, f) => { f.rpcError(c, 'still-in-flight', 200, 'still in progress'); },
  });
  try {
    expect(await w.execution.observePayment(WIRE_HASH)).toMatchObject({ kind: 'IN_FLIGHT' });
    expect(await w.execution.observePayment(WIRE_HASH)).toMatchObject({ kind: 'IN_FLIGHT' });
    expect(await w.execution.observePayment(WIRE_HASH)).toMatchObject({ kind: 'SUCCEEDED', preimageMatchesHash: true, feeMsat: 150_000n });
    expect(w.fake.requests.filter(r => r.url === '/v1/waitsendpay')).toHaveLength(1);
    expect(w.fake.requests.filter(r => r.url === '/v1/sendpay')).toHaveLength(0);
  } finally { await w.close(); }
});

it('CP-034/B1 T-13 LND FAILED with one attempt still in flight is not terminal and later settles', async () => {
  let read = 0;
  const w = await lndWire({ 'GET /v2/router/track/{payment_hash}': (c, f) => {
    const record = read++ === 0 ? payment({ payment_hash: WIRE_HASH, status: 'FAILED', failure_reason: 'FAILURE_REASON_TIMEOUT', htlcs: [attempt('FAILED', '1'), attempt('IN_FLIGHT', '2')] }) : complete();
    f.stream(c, 'failed-then-success', [`${JSON.stringify({ result: record })}\n`], 'finish');
  } });
  try { expect(await w.execution.observePayment(WIRE_HASH)).toEqual({ kind: 'IN_FLIGHT' }); expect(await w.execution.observePayment(WIRE_HASH)).toMatchObject({ kind: 'SUCCEEDED', preimageMatchesHash: true }); }
  finally { await w.close(); }
});

it('CP-034/B1 T-22 uint64 max_pending_amt_msat remains positive and exact', async () => {
  const w = await lndWire({ 'GET /v1/channels': (c, f) => { const raw = channel(); const constraints = raw['local_constraints'] as Record<string, unknown>; constraints['max_pending_amt_msat'] = '18446744073709551615'; f.answer(c, 'uint64', { channels: [raw] }); } });
  try { expect((await w.api.listChannels())[0]?.localConstraints.maxPendingAmtMsat).toBe(18_446_744_073_709_551_615n); }
  finally { await w.close(); }
});

it('CP-034/B1 T-22 CLN msat strings preserve values above Number.MAX_SAFE_INTEGER', async () => {
  const w = await clnWire({ listpeerchannels: (c, f) => { f.result(c, 'msat-strings', { channels: [peerChannel({ spendable_msat: '9007199254740993msat', receivable_msat: '1000msat' })] }); } });
  try { expect((await w.api.listPeerChannels())[0]).toMatchObject({ spendableMsat: 9_007_199_254_740_993n, receivableMsat: 1000n }); }
  finally { await w.close(); }
});

it('CP-034/B1 T-22 split frames reassemble Unicode and classify an in-stream error envelope', async () => {
  const errors = await loadErrors(), raw = Buffer.from(`${JSON.stringify({ result: { value: 'é€' } })}\n${JSON.stringify({ error: { code: 5, message: 'not found' } })}\n`, 'utf8');
  const chunks: Buffer[] = []; for (let i = 0; i < raw.length; i += 3) chunks.push(raw.subarray(i, i + 3));
  const w = await lndWire({ 'GET /v2/router/track/{payment_hash}': (c, f) => { f.stream(c, 'split-stream', chunks, 'finish'); } });
  try {
    const encoded = Buffer.from(WIRE_HASH, 'hex').toString('base64').replaceAll('+', '-').replaceAll('/', '_');
    const seen: unknown[] = [], error = await rejection(w.rest.stream('GET', `/v2/router/track/${encodeURIComponent(encoded)}`, undefined, record => { seen.push(record); return 'continue'; }));
    expect(seen).toEqual([{ value: 'é€' }]); expect(error).toBeInstanceOf(errors.LndError); expect(error).toMatchObject({ grpcCode: 5, notFound: true });
  } finally { await w.close(); }
});

for (const [name, body] of [['direct', { code: 5, message: 'not found', details: [] }], ['nested', { error: { code: 5, message: 'not found', details: [] } }], ['legacy', { error: 'not found', code: 5, message: 'not found', details: [] }]] as const) {
  it(`CP-034/B1 T-22 ${name} REST error envelope is classified without treating it as payment evidence`, async () => {
    const w = await lndWire({ 'GET /v2/router/track/{payment_hash}': (c, f) => { f.raw(c, 'envelope', 404, JSON.stringify(body)); } });
    try { expect(await w.execution.observePayment(WIRE_HASH)).toEqual({ kind: 'NOT_FOUND' }); }
    finally { await w.close(); }
  });
}

it('CP-034/B1 T-22 hash path uses base64url and cannot introduce an extra slash', async () => {
  const hash = 'ff'.repeat(32), w = await lndWire({ 'GET /v2/router/track/{payment_hash}': trackRecord(payment({ payment_hash: hash, status: 'IN_FLIGHT' })) });
  try {
    expect(await w.execution.observePayment(hash)).toEqual({ kind: 'IN_FLIGHT' });
    const url = w.fake.requests[0]?.url ?? ''; const segment = new URL(url, 'https://localhost').pathname.split('/')[4] ?? '';
    expect(segment).not.toMatch(/[+/]/); expect(Buffer.from(decodeURIComponent(segment), 'base64url').toString('hex')).toBe(hash);
  } finally { await w.close(); }
});

for (const mode of ['refusal', 'transport-error'] as const) {
  it(`CP-034/B1 T-24 askrene layer is removed after ${mode}`, async () => {
    const layers = askrene(), own = `03${'cd'.repeat(32)}`, out = `02${'aa'.repeat(32)}`, incoming = `02${'bb'.repeat(32)}`;
    const w = await clnWire({ ...layers.methods,
      getinfo: (c, f) => { f.result(c, 'getinfo', getinfo({ id: own, blockheight: 500 })); },
      listpeerchannels: (c, f) => { f.result(c, 'listpeerchannels', { channels: [peerChannel({ short_channel_id: '112x1x0', peer_id: out }), peerChannel({ short_channel_id: '224x1x0', peer_id: incoming,
        updates: { remote: { fee_base_msat: 1000, fee_proportional_millionths: 1000, cltv_expiry_delta: 34, htlc_minimum_msat: 1, htlc_maximum_msat: 5_000_000_000 } } })] }); },
      getroutes: (c, f) => { if (mode === 'refusal') f.rpcError(c, 'no-route', 205, 'no route'); else f.raw(c, 'proxy-error', 502, 'gateway unavailable'); },
    });
    try {
      try { await w.execution.findCircularRoute({ sourceChannelKey: '112x1x0', targetChannelKey: '224x1x0', principalMsat: 100_000_000n, maxFeeMsat: 300_000n, maxFeePpm: 2500n, exemptFeeMsat: 5000n, maxCltvDelta: 144 }); } catch { /* An unreadable proxy response is allowed to reject; cleanup is unconditional. */ }
      expect(layers.state.layers.size).toBe(0);
      expect(w.fake.requests.filter(r => r.url === '/v1/getroutes')).toHaveLength(1);
      expect(w.fake.requests.filter(r => r.url === '/v1/askrene-remove-layer')).toHaveLength(1);
      expect(w.fake.requests.filter(r => ['/v1/sendpay', '/v1/pay', '/v1/xpay'].includes(r.url))).toEqual([]);
    } finally { await w.close(); }
  });
}

it('CP-034/B1 T-23 a custom unparseable CLN version fails closed at the real handshake', async () => {
  const own = `03${'cd'.repeat(32)}`, w = await clnWire({ getinfo: (c, f) => { f.result(c, 'custom-version', getinfo({ id: own, version: 'merchant-custom-build' })); } });
  try {
    const { probeCln } = await loadClnProbe(), updates: unknown[] = [];
    const error = await rejection(probeCln(w.rest, { nodeId: 'cln-m', expectedNetwork: 'regtest', expectedPubkey: own, mutating: true, now: () => 1,
      store: { recordProbe: update => { updates.push(update); return Promise.resolve(); } } }));
    expect(error).toMatchObject({ name: 'CapabilityUnsupported' }); expect(updates).toEqual([]);
    expect(w.fake.requests).toHaveLength(1);
  } finally { await w.close(); }
});
