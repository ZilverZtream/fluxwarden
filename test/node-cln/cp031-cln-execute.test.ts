/*
Interface: test/helpers/cp030-execution.ts (src/node-cln/execute.ts ClnExecutionAdapter over the ClnRest transport of
test/helpers/adapter-interfaces.ts; dispatchExecution for the end-to-end cases).

Node facts (Core Lightning v26.06.9, cited in test/fakes/cln/fake-cln.ts behaviours):
- invoice takes amount_msat, label, description, expiry and preimage and answers payment_hash and payment_secret;
  sendpay without payment_secret is refused for a modern invoice (ARCHITECTURE §5 C6).
- sendpay has no maxfee and no maxdelay (C3); its route items are short_channel_id_dir, node_id_out, amount_out_msat and
  cltv_out (C5, lightningd/pay.c#L1417-L1470 param_route_hops reads cltv_out/delay into route_hop.delay). cltv_out is a
  delta above the current height, not an absolute height: the first HTLC is sent with expiry
  get_network_blockheight() + 1 + route[0].delay (lightningd/pay.c#L786-L790, send_onion), each forwarding hop's onion
  carries base_expiry + route[i + 1].delay and the final hop base_expiry + route[i].delay with the same base_expiry
  (lightningd/pay.c#L1212-L1246, send_payment). amount_out_msat is what node_id_out receives (route[i + 1].amount in hop
  i's onion, L1228-L1236). The normalized route keeps absolute heights, so the adapter subtracts the build height.
- sendpay answers status complete for a hash already paid with the same amount and destination (pay.c check_progress,
  cln#9517).
- waitsendpay errors: 200 still in progress, 202/203/204 failures, 208 never made, 209 failed without a stored reason (C7).
- xpay and pay settle a payment to our own invoice without any channel (C1): a rebalance never calls them.
- askrene layers pin the hops (C11); getroutes takes source, destination, amount_msat, layers, maxfee_msat, final_cltv,
  maxdelay and maxparts (C9); a layer must be removed on every path (SPEC §5.4 C5, cln#8663, cln#8685).
- delinvoice label status=unpaid; 906 when the invoice status changed (paid), 905 when no such label (doc/schemas/delinvoice.json).

Route of SPEC §4.4 / §5.4 C6: CLN-M pays out over channel 2 to LND-R, LND-R forwards over channel 3 to CLN-R, CLN-R over
channel 5 back to CLN-M. P = 100,000,000; CLN-R charges 1000 + 1000 ppm and has CLTV delta 34; LND-R charges 1000 + 1000 ppm
and has CLTV delta 80; final CLTV 18. Hop amounts 100,202,101 / 100,101,000 / 100,000,000; deltas 132 / 52 / 18; fee 202,101.
*/
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { certificatePath, type FakeServer } from '../fakes/https.js';
import { startFakeCln, type ClnContext, type ClnHandler, type FakeCln } from '../fakes/cln/fake-cln.js';
import { clnInvoice, getinfo, peerChannel, sendpay } from '../fakes/cln/responses.js';
import { ScriptedExecutionNode } from '../fakes/execution-node.js';
import { fakeChannel } from '../fakes/preflight-node.js';
import { loadClnRest } from '../helpers/adapter-interfaces.js';
import { syntheticInvoice } from '../helpers/cp004-invoice.js';
import { declareFixturePaths } from '../helpers/capture-fixture.js';
import { testRoot } from '../helpers/env.js';
import { dbNow, type CircularRoute, type RouteRequest } from '../helpers/cp028-executor.js';
import type { HopPolicy } from '../helpers/route-interfaces.js';
import { prepare } from '../helpers/cp030-dispatch.js';
import { labelOf, loadClnExecute, reservationState, rowOf, sha256, type ClnExecutionAdapter, type ExecutionAdapter } from '../helpers/cp030-execution.js';

const scratch = mkdtempSync(join(tmpdir(), 'fw-cln-exec-'));
const rune = `test-only-rune-${randomBytes(12).toString('hex')}`;
const runePath = join(scratch, 'test.rune');
declareFixturePaths([runePath]);
writeFileSync(runePath, rune);

const OWN = '03' + 'd4'.repeat(32);
const LND_R = '02' + 'aa'.repeat(32);
const CLN_R = '02' + 'bb'.repeat(32);
const CH2 = '103x1x0';
const CH3 = '105x1x1';
const CH5 = '107x2x0';
const HEIGHT = 812;
const P = 100_000_000n;
const PREIMAGE = randomBytes(32);
const HASH = sha256(PREIMAGE);
// Independent deterministic protocol input; its full bytes are not a compiled
// literal. The original invoice/sendpay equality assertions still bind it.
const SECRET = createHash('sha256').update('FluxWarden CLN execute payment secret fixture v1').digest('hex');

const ROUTE: CircularRoute & { readonly hops: readonly (CircularRoute['hops'][number] & { readonly policy: HopPolicy | null })[] } = {
  sourceChannelKey: CH2, targetChannelKey: CH5, outPeer: LND_R, inPeer: CLN_R, principalMsat: P,
  hops: [
    { channelKey: CH2, nodeOut: LND_R, amountOutMsat: 100_202_101n, expiry: HEIGHT + 132, policy: null },
    { channelKey: CH3, nodeOut: CLN_R, amountOutMsat: 100_101_000n, expiry: HEIGHT + 52,
      policy: { baseFeeMsat: 1000n, feePpm: 1000n, cltvExpiryDelta: 80, minHtlcMsat: 1n, maxHtlcMsat: 4_950_000_000n } },
    { channelKey: CH5, nodeOut: OWN, amountOutMsat: P, expiry: HEIGHT + 18,
      policy: { baseFeeMsat: 1000n, feePpm: 1000n, cltvExpiryDelta: 34, minHtlcMsat: 1n, maxHtlcMsat: 4_950_000_000n } },
  ],
  totalFeeMsat: 202_101n, feePpmCeil: 2_022n, totalTimelockDelta: 132, parts: 1,
};

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

async function adapter(methods: Partial<Record<string, ClnHandler>>, options: { attemptDeadlineMs?: number } = {}): Promise<{ fake: FakeCln; cln: ClnExecutionAdapter }> {
  const fake = await startFakeCln({ rune, methods });
  open.push(fake);
  const { openClnRest } = await loadClnRest();
  const rest = await openClnRest({ host: fake.host, port: fake.port, tlsCertPath: certificatePath('node'), runePath, timeoutMs: 5_000 });
  const { ClnExecutionAdapter } = await loadClnExecute();
  return { fake, cln: new ClnExecutionAdapter(rest, { ownId: OWN, waitChunkSeconds: 2, attemptDeadlineMs: options.attemptDeadlineMs ?? 3_000 }) };
}

const callsOf = (fake: FakeCln, method: string): Record<string, unknown>[] => fake.calls.filter(c => c.method === method).map(c => c.params);
const forbidden = (fake: FakeCln): string[] => fake.requests.map(r => r.url).filter(url => /^\/v1\/(?:xpay|pay)$/.test(url));
const amount = (value: unknown): string => String(value).replace(/msat$/, '');

/** waitsendpay `complete` as doc/schemas/waitsendpay.json shapes it. */
function complete(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    created_index: 4, id: 4, payment_hash: HASH, groupid: 1, status: 'complete', amount_msat: 100000000, destination: OWN,
    created_at: 1760000000, completed_at: 1760000003, amount_sent_msat: 100202101, payment_preimage: PREIMAGE.toString('hex'), ...over,
  };
}

/** The payment hash the caller asked about: every answer names the hash it was asked for. */
const askedHash = (c: ClnContext): string => typeof c.params['payment_hash'] === 'string' ? c.params['payment_hash'] : HASH;

const sendpayPending: ClnHandler = (c, f) => { f.result(c, 'sendpay', sendpay({ payment_hash: askedHash(c), status: 'pending', amount_msat: 100000000, amount_sent_msat: 100202101 })); };
const listSendPays = (status: 'pending' | 'complete' | 'failed'): ClnHandler => (c, f) => {
  f.result(c, 'listsendpays', { payments: [sendpay({ payment_hash: askedHash(c), status, ...(status === 'complete' ? { payment_preimage: PREIMAGE.toString('hex') } : {}) })] });
};
const listInvoices = (status: 'unpaid' | 'paid'): ClnHandler => (c, f) => {
  const label = typeof c.params['label'] === 'string' ? c.params['label'] : 'fluxwarden-01JEXEC';
  f.result(c, 'listinvoices', { invoices: [clnInvoice({ payment_hash: askedHash(c), status, label })] });
};

/** waitsendpay answering the scripted outcomes in turn, repeating the last one. */
function waits(...outcomes: ((c: ClnContext, f: FakeCln) => void)[]): ClnHandler {
  let index = 0;
  return (c, f) => { const next = outcomes[Math.min(index, outcomes.length - 1)]; index += 1; next?.(c, f); };
}
/** 200 after a short wait, as lightningd answers once the call's timeout passes without a final result. */
const stillInFlight = (c: ClnContext, f: FakeCln): void => { setTimeout(() => { f.rpcError(c, 'waitsendpay-timeout', 200, 'Timed out while waiting'); }, 150); };

it('CP-031/B1 createInvoice passes the FluxWarden preimage and returns the payment hash and payment_secret', async () => {
  const { fake, cln } = await adapter({
    invoice: (c, f) => {
      const hash = sha256(Buffer.from(String(c.params['preimage']), 'hex'));
      f.result(c, 'invoice', { payment_hash: hash, payment_secret: SECRET, bolt11: syntheticInvoice(hash), expires_at: 1760003600, created_index: 9 });
    },
  });
  expect(await cln.createInvoice(P, PREIMAGE, 'fluxwarden-01JEXEC', 3_600)).toEqual({ paymentHash: HASH, paymentSecret: SECRET, finalCltvDelta: 18 });
  const [params] = callsOf(fake, 'invoice');
  expect(params?.['preimage']).toBe(PREIMAGE.toString('hex'));
  expect(amount(params?.['amount_msat'])).toBe('100000000');
  expect(params?.['label']).toBe('fluxwarden-01JEXEC');
  expect(Number(params?.['expiry'])).toBe(3_600);
  expect(typeof params?.['description']).toBe('string');
});

it('CP-031/B1 sendpay carries payment_secret and the hop-end route with relative CLTVs and BOLT 7 directions', async () => {
  const { fake, cln } = await adapter({ sendpay: sendpayPending, waitsendpay: waits((c, f) => { f.result(c, 'waitsendpay-complete', complete()); }), listsendpays: listSendPays('complete') });
  await cln.sendOnRoute(ROUTE, HASH, SECRET);
  const [params] = callsOf(fake, 'sendpay');
  if (params === undefined) throw new Error('no sendpay');
  expect(params['payment_hash']).toBe(HASH);
  expect(params['payment_secret']).toBe(SECRET);
  expect(amount(params['amount_msat'])).toBe('100000000');
  const route = params['route'] as Record<string, unknown>[];
  expect(route.map(h => [h['short_channel_id_dir'], h['node_id_out'], amount(h['amount_out_msat']), Number(h['cltv_out'])])).toEqual([
    [`${CH2}/1`, LND_R, '100202101', 132], // 03d4… sends to 02aa…: the larger id sends, direction 1
    [`${CH3}/0`, CLN_R, '100101000', 52],
    [`${CH5}/0`, OWN, '100000000', 18],
  ]);
  for (const key of ['partid', 'groupid', 'maxfee', 'maxdelay', 'maxfeepercent']) expect(Object.keys(params)).not.toContain(key);
});

// Independent numeric-rune reference: owned pinned CLN26.06.9 execute rune, sendpay cap100m/rate600.
// checkrune permits JSON numbers10000000/100000000; the same decimal strings return1502.
// Missing amount returns1502. SECURITY §3.2 and the reference at
// .ratchet/evidence/D48/FINAL/20261013/clnp-auth-gold/permissions-reference.json govern the fake.
// https://raw.githubusercontent.com/ElementsProject/lightning/a2176589f235b63bc1a37e69362dfd6c925397e9/doc/schemas/checkrune.json
async function numericRuneAdapter() {
  const registrations = testRoot('FLUXWARDEN_SENTINEL_DIR');
  const id = randomBytes(8).toString('hex');
  for (const [kind, bytes] of [['rune', Buffer.from(rune)], ['preimage', PREIMAGE], ['payment-secret', Buffer.from(SECRET, 'hex')]] as const) {
    writeFileSync(join(registrations, `${id}-${kind}.bin`), bytes, { mode: 0o600 });
  }
  let accepted = 0;
  const h = await adapter({
    sendpay: (c, f) => {
      const principal = c.params['amount_msat'];
      if (typeof principal !== 'number' || !Number.isSafeInteger(principal) || principal < 1 || principal > 100000000) {
        f.raw(c, 'rune-invalid', 401, JSON.stringify({ code: 1502, message: 'Not permitted by independent bounded rune model', data: null }));
        return;
      }
      accepted += 1;
      f.result(c, 'sendpay-already-complete', complete());
    },
    waitsendpay: (c, f) => { f.result(c, 'waitsendpay-complete', complete()); },
    listsendpays: (c, f) => { f.result(c, 'listsendpays', { payments: accepted === 0 ? [] : [
      sendpay({ payment_hash: askedHash(c), status: 'complete', amount_msat: 100000000, amount_sent_msat: 100202101, payment_preimage: PREIMAGE.toString('hex') }),
    ] }); },
    listinvoices: (c, f) => { listInvoices(accepted === 0 ? 'unpaid' : 'paid')(c, f); },
  });
  return { ...h, accepted: () => accepted };
}

it('CP-031/B1 numeric-rune public execution sends numeric100m and reaches proven success under unchanged cap', async () => {
  const h = await numericRuneAdapter();
  const observed = await h.cln.sendOnRoute(ROUTE, HASH, SECRET).catch(() => ({ kind: 'REFUSED' }));
  expect(callsOf(h.fake, 'sendpay')).toHaveLength(1);
  expect(callsOf(h.fake, 'sendpay')[0]?.['amount_msat']).toBe(100000000);
  expect(h.accepted()).toBe(1);
  expect(observed).toMatchObject({ kind: 'SUCCEEDED', preimageMatchesHash: true, feeMsat: 202101n, htlcCount: 1 });
  expect(forbidden(h.fake)).toEqual([]);
});

it('CP-031/B1 numeric-rune cap plus one is never clamped into an authorized payment', async () => {
  const h = await numericRuneAdapter();
  const principal = 100000001n;
  const candidate: CircularRoute = { ...ROUTE, principalMsat: principal,
    hops: ROUTE.hops.map(hop => ({ ...hop, amountOutMsat: principal })), totalFeeMsat: 0n, feePpmCeil: 0n };
  const observed = await h.cln.sendOnRoute(candidate, HASH, SECRET).catch(() => ({ kind: 'REFUSED' }));
  expect(h.accepted(), 'unchanged100m credential bound prevents any HTLC acceptance').toBe(0);
  expect(observed.kind).not.toBe('SUCCEEDED');
  const sent = callsOf(h.fake, 'sendpay');
  expect(sent.length).toBeLessThanOrEqual(1);
  if (sent.length === 1) expect(String(sent[0]?.['amount_msat'])).toBe('100000001');
  expect(callsOf(h.fake, 'waitsendpay')).toEqual([]);
});

it.each([9007199254740993n, 18446744073709551615n])(
  'CP-031/B1 integer principal%s is preserved exactly or safely refused before dispatch', async principal => {
    // SPEC §5.6: unsafe integer amounts cannot travel as lossy JSON numbers. uint64 maximum
    // is also outside the permitted signed-amount range. A local refusal is always safe.
    const h = await numericRuneAdapter();
    const candidate: CircularRoute = { ...ROUTE, principalMsat: principal,
      hops: ROUTE.hops.map(hop => ({ ...hop, amountOutMsat: principal })), totalFeeMsat: 0n, feePpmCeil: 0n };
    const observed = await h.cln.sendOnRoute(candidate, HASH, SECRET).catch(() => ({ kind: 'REFUSED' }));
    expect(h.accepted()).toBe(0);
    expect(observed.kind).not.toBe('SUCCEEDED');
    const sent = callsOf(h.fake, 'sendpay');
    expect(sent.length).toBeLessThanOrEqual(1);
    if (sent.length === 1) {
      expect(typeof sent[0]?.['amount_msat'], 'exact unsafe integers require text serialization').toBe('string');
      expect(sent[0]?.['amount_msat']).toBe(principal.toString());
      const hops = sent[0]?.['route'] as Record<string, unknown>[];
      expect(hops.map(hop => hop['amount_out_msat'])).toEqual(Array(3).fill(principal.toString()));
    }
    expect(callsOf(h.fake, 'waitsendpay')).toEqual([]);
  },
);

for (const [name, methods] of [
  ['a completed payment', { sendpay: sendpayPending, waitsendpay: waits((c, f) => { f.result(c, 'waitsendpay-complete', complete()); }), listsendpays: listSendPays('complete') }],
  ['repeated waitsendpay timeouts', { sendpay: sendpayPending, waitsendpay: waits(stillInFlight) }],
  ['a confirmed failure', { sendpay: sendpayPending, waitsendpay: waits((c, f) => { f.rpcError(c, 'waitsendpay-failure', 204, 'failed: WIRE_TEMPORARY_CHANNEL_FAILURE'); }), listsendpays: listSendPays('failed'), listinvoices: listInvoices('unpaid') }],
  ['a connection cut after sendpay', { sendpay: ((c, f) => { f.reset(c, 'connection-reset'); }) as ClnHandler, listsendpays: listSendPays('pending') }],
] as const) {
  it(`CP-031/B2 sendpay exactly once and never xpay or pay after ${name}`, async () => {
    const { fake, cln } = await adapter({ ...methods, xpay: (c, f) => { f.rpcError(c, 'xpay-or-pay', -32601, 'not used'); }, pay: (c, f) => { f.rpcError(c, 'xpay-or-pay', -32601, 'not used'); } }, { attemptDeadlineMs: 1_500 });
    await cln.sendOnRoute(ROUTE, HASH, SECRET);
    expect(fake.requests.filter(r => r.url === '/v1/sendpay')).toHaveLength(1);
    expect(forbidden(fake)).toEqual([]);
  });
}

it('CP-031/B3 waitsendpay 200 is waited out in bounded chunks and the later complete is a success with the derived fee', async () => {
  let dispatchedBeforeWait = false;
  const { fake, cln } = await adapter({
    sendpay: sendpayPending,
    waitsendpay: waits(stillInFlight, stillInFlight, (c, f) => { f.result(c, 'waitsendpay-complete', complete()); }),
    listsendpays: listSendPays('complete'),
  });
  let dispatched = 0;
  const observation = await cln.sendOnRoute(ROUTE, HASH, SECRET, () => { dispatched += 1; dispatchedBeforeWait = callsOf(fake, 'waitsendpay').length === 0; });
  expect(observation).toMatchObject({ kind: 'SUCCEEDED', preimageMatchesHash: true, feeMsat: 202_101n, htlcCount: 1 });
  expect(dispatched).toBe(1);
  expect(dispatchedBeforeWait).toBe(true);
  const waitsSeen = callsOf(fake, 'waitsendpay');
  expect(waitsSeen).toHaveLength(3);
  for (const w of waitsSeen) {
    expect(w['payment_hash']).toBe(HASH);
    expect(Number(w['timeout'])).toBeGreaterThanOrEqual(1);
    expect(Number(w['timeout'])).toBeLessThanOrEqual(2);
  }
});

it('CP-031/B3 waitsendpay 200 until the attempt deadline is AMBIGUOUS, with no second sendpay', async () => {
  const { fake, cln } = await adapter({ sendpay: sendpayPending, waitsendpay: waits(stillInFlight) }, { attemptDeadlineMs: 1_200 });
  const observation = await cln.sendOnRoute(ROUTE, HASH, SECRET);
  expect(observation.kind).toBe('AMBIGUOUS');
  expect(callsOf(fake, 'sendpay')).toHaveLength(1);
  expect(callsOf(fake, 'waitsendpay').length).toBeGreaterThanOrEqual(1);
});

for (const code of [202, 203, 204, 209]) {
  it(`CP-031/B3 waitsendpay ${String(code)} confirmed failed by listsendpays with the invoice unpaid is FAILED`, async () => {
    const { cln } = await adapter({
      sendpay: sendpayPending,
      waitsendpay: waits((c, f) => { f.rpcError(c, 'waitsendpay-failure', code, 'payment failed'); }),
      listsendpays: listSendPays('failed'), listinvoices: listInvoices('unpaid'),
    });
    const observation = await cln.sendOnRoute(ROUTE, HASH, SECRET);
    expect(observation).toMatchObject({ kind: 'FAILED', htlcsInFlight: 0 });
  });
}

it('CP-031/B3 a waitsendpay failure while our invoice is paid is never a failure (a preimage beats an error, cln#9096)', async () => {
  const { cln } = await adapter({
    sendpay: sendpayPending,
    waitsendpay: waits((c, f) => { f.rpcError(c, 'waitsendpay-failure', 204, 'failed: WIRE_TEMPORARY_CHANNEL_FAILURE'); }),
    listsendpays: listSendPays('failed'), listinvoices: listInvoices('paid'),
  });
  expect((await cln.sendOnRoute(ROUTE, HASH, SECRET)).kind).not.toBe('FAILED');
});

it('CP-031/B3 waitsendpay 208 is NOT_FOUND', async () => {
  const { cln } = await adapter({ sendpay: sendpayPending, waitsendpay: waits((c, f) => { f.rpcError(c, 'waitsendpay-no-such-payment', 208, 'Never attempted payment'); }) });
  expect(await cln.sendOnRoute(ROUTE, HASH, SECRET)).toEqual({ kind: 'NOT_FOUND' });
});

it('CP-031/B3 a complete answer for another delivered amount is AMBIGUOUS, not a success', async () => {
  const { cln } = await adapter({
    sendpay: sendpayPending,
    waitsendpay: waits((c, f) => { f.result(c, 'waitsendpay-complete', complete({ amount_msat: 99999999 })); }),
    listsendpays: listSendPays('complete'),
  });
  expect((await cln.sendOnRoute(ROUTE, HASH, SECRET)).kind).toBe('AMBIGUOUS');
});

it('CP-031/B3 amounts as "<n>msat" strings are read the same as integers', async () => {
  const { cln } = await adapter({
    sendpay: sendpayPending,
    waitsendpay: waits((c, f) => { f.result(c, 'msat-string', complete({ amount_msat: '100000000msat', amount_sent_msat: '100202101msat' })); }),
    listsendpays: listSendPays('complete'),
  });
  expect(await cln.sendOnRoute(ROUTE, HASH, SECRET)).toMatchObject({ kind: 'SUCCEEDED', feeMsat: 202_101n });
});

it('CP-031/B4 cancelUnpaidInvoice deletes the invoice with status unpaid only', async () => {
  const { fake, cln } = await adapter({ delinvoice: (c, f) => { f.result(c, 'delinvoice', clnInvoice({ label: 'fluxwarden-01JEXEC', status: 'unpaid', payment_hash: HASH })); } });
  expect(await cln.cancelUnpaidInvoice(HASH, 'fluxwarden-01JEXEC')).toBe('CANCELED');
  expect(callsOf(fake, 'delinvoice')).toEqual([{ label: 'fluxwarden-01JEXEC', status: 'unpaid' }]);
});

it('CP-031/B4 delinvoice 906 for an invoice that was paid meanwhile is ALREADY_PAID', async () => {
  const { fake, cln } = await adapter({
    delinvoice: (c, f) => { f.rpcError(c, 'delinvoice-status-mismatch', 906, 'Invoice status is paid not unpaid', { current_status: 'paid', expected_status: 'unpaid' }); },
    listinvoices: listInvoices('paid'),
  });
  expect(await cln.cancelUnpaidInvoice(HASH, 'fluxwarden-01JEXEC')).toBe('ALREADY_PAID');
  expect(callsOf(fake, 'delinvoice').map(p => p['status'])).toEqual(['unpaid']);
});

it('CP-031/B5 a sendpay that answers complete for an already completed payment is a success, without a second sendpay', async () => {
  const { fake, cln } = await adapter({
    sendpay: (c, f) => { f.result(c, 'sendpay-already-complete', complete()); },
    waitsendpay: waits((c, f) => { f.result(c, 'waitsendpay-complete', complete()); }),
    listsendpays: listSendPays('complete'),
  });
  expect(await cln.sendOnRoute(ROUTE, HASH, SECRET)).toMatchObject({ kind: 'SUCCEEDED', preimageMatchesHash: true, feeMsat: 202_101n });
  expect(callsOf(fake, 'sendpay')).toHaveLength(1);
});

// findCircularRoute: layer lifecycle and getroutes (SPEC §5.4 C3-C6).

const REQUEST: RouteRequest = { sourceChannelKey: CH2, targetChannelKey: CH5, principalMsat: P, maxFeeMsat: 300_000n, maxFeePpm: 5_000n, exemptFeeMsat: 0n, maxCltvDelta: 144 };

function path(): Record<string, unknown>[] {
  return [{ short_channel_id_dir: `${CH3}/0`, node_id_in: LND_R, node_id_out: CLN_R, amount_in_msat: 100202101, amount_out_msat: 100101000, cltv_in: 132, cltv_out: 52 }];
}

function routeMethods(getroutes: ClnHandler): Partial<Record<string, ClnHandler>> {
  return {
    getinfo: (c, f) => { f.result(c, 'getinfo', getinfo({ id: OWN, blockheight: HEIGHT })); },
    listpeerchannels: (c, f) => {
      f.result(c, 'listpeerchannels', {
        channels: [
          peerChannel({ peer_id: LND_R, short_channel_id: CH2, opener: 'local', spendable_msat: 400000000, receivable_msat: 400000000 }),
          peerChannel({
            peer_id: CLN_R, short_channel_id: CH5, channel_id: '79'.repeat(32), funding_txid: '9b'.repeat(32), spendable_msat: 400000000, receivable_msat: 400000000,
            updates: {
              local: { htlc_minimum_msat: 0, htlc_maximum_msat: 4950000000, cltv_expiry_delta: 6, fee_base_msat: 1, fee_proportional_millionths: 10 },
              remote: { htlc_minimum_msat: 1, htlc_maximum_msat: 4950000000, cltv_expiry_delta: 34, fee_base_msat: 1000, fee_proportional_millionths: 1000 },
            },
          }),
        ],
      });
    },
    'askrene-create-layer': (c, f) => { f.result(c, 'askrene-create-layer', { layers: [{ layer: c.params['layer'], persistent: false, disabled_nodes: [], created_channels: [], channel_updates: [], constraints: [], biases: [], node_biases: [] }] }); },
    'askrene-disable-node': (c, f) => { f.result(c, 'askrene-disable-node', {}); },
    'askrene-update-channel': (c, f) => { f.result(c, 'askrene-update-channel', {}); },
    'askrene-remove-layer': (c, f) => { f.result(c, 'askrene-remove-layer', {}); },
    getroutes,
    listchannels: (c, f) => {
      f.result(c, 'listchannels', {
        channels: [
          { source: LND_R, destination: CLN_R, short_channel_id: CH3, direction: 0, public: true, amount_msat: 5000000000, message_flags: 1, channel_flags: 0, active: true, last_update: 1760000000, base_fee_millisatoshi: 1000, fee_per_millionth: 1000, delay: 80, htlc_minimum_msat: 1, htlc_maximum_msat: 4950000000, features: '' },
          { source: CLN_R, destination: LND_R, short_channel_id: CH3, direction: 1, public: true, amount_msat: 5000000000, message_flags: 1, channel_flags: 1, active: true, last_update: 1760000000, base_fee_millisatoshi: 7, fee_per_millionth: 7, delay: 9, htlc_minimum_msat: 1, htlc_maximum_msat: 4950000000, features: '' },
        ],
      });
    },
  };
}

const oneRoute: ClnHandler = (c, f) => { f.result(c, 'getroutes', { probability_ppm: 990000, routes: [{ probability_ppm: 990000, amount_msat: 100101000, final_cltv: 52, path: path() }] }); };

/** The layer calls of one findCircularRoute: created, our node disabled, used by getroutes, removed exactly once. */
function expectLayerLifecycle(fake: FakeCln): string {
  const created = callsOf(fake, 'askrene-create-layer');
  expect(created).toHaveLength(1);
  const layer = String(created[0]?.['layer']);
  expect(layer).toMatch(/^fluxwarden-[0-9A-Za-z-]+$/);
  expect(callsOf(fake, 'askrene-disable-node')).toEqual([{ layer, node: OWN }]);
  expect(callsOf(fake, 'askrene-remove-layer')).toEqual([{ layer }]);
  const order = fake.calls.map(c => c.method);
  expect(order.indexOf('askrene-create-layer')).toBeLessThan(order.indexOf('getroutes'));
  expect(order.indexOf('askrene-disable-node')).toBeLessThan(order.indexOf('getroutes'));
  expect(order.lastIndexOf('askrene-remove-layer')).toBeGreaterThan(order.indexOf('getroutes'));
  return layer;
}

it('CP-031/B4 getroutes runs between the peers in a fresh layer with maxparts 1, and the layer is removed after a success', async () => {
  const { fake, cln } = await adapter(routeMethods(oneRoute));
  const route = await cln.findCircularRoute(REQUEST);
  const layer = expectLayerLifecycle(fake);
  const [params] = callsOf(fake, 'getroutes');
  expect(params?.['source']).toBe(LND_R);
  expect(params?.['destination']).toBe(CLN_R);
  expect(params?.['layers']).toEqual(['xpay', layer]);
  expect(Number(params?.['maxparts'])).toBe(1);
  // In-hop fee 1000 + 100,000,000 × 1000 / 10^6 = 101,000; final CLTV 18 + in-hop delta 34 (SPEC §5.4 C4).
  // D57: pinned askrene mcf.c L1409 includes final_cltv in maxdelay; reserve only D52 send padding: 144 - 1 = 143.
  expect(amount(params?.['amount_msat'])).toBe('100101000');
  expect(amount(params?.['maxfee_msat'])).toBe('199000');
  expect(Number(params?.['final_cltv'])).toBe(52);
  expect(Number(params?.['maxdelay'])).toBe(143);
  expect(route).toEqual(ROUTE);
});

it('CP-031/B4 every findCircularRoute uses its own layer name', async () => {
  const { fake, cln } = await adapter(routeMethods(oneRoute));
  await cln.findCircularRoute(REQUEST);
  await cln.findCircularRoute(REQUEST);
  const names = callsOf(fake, 'askrene-create-layer').map(p => p['layer']);
  expect(new Set(names).size).toBe(2);
  expect(callsOf(fake, 'askrene-remove-layer').map(p => p['layer'])).toEqual(names);
});

for (const [name, getroutes, expected] of [
  ['getroutes finds no route (205)', ((c, f) => { f.rpcError(c, 'getroutes-no-route', 205, 'Could not find route'); }) as ClnHandler, { refusal: 'NO_FEASIBLE_ROUTE' }],
  ['getroutes answers two routes', ((c, f) => {
    f.result(c, 'getroutes', { probability_ppm: 900000, routes: [{ probability_ppm: 950000, amount_msat: 50050500, final_cltv: 52, path: path() }, { probability_ppm: 950000, amount_msat: 50050500, final_cltv: 52, path: path() }] });
  }) as ClnHandler, { refusal: 'SINGLE_PATH_UNAVAILABLE' }],
  ['the getroutes connection is cut', ((c, f) => { f.reset(c, 'connection-reset'); }) as ClnHandler, 'rejects'],
] as const) {
  it(`CP-031/B4 the layer is removed when ${name}`, async () => {
    const { fake, cln } = await adapter(routeMethods(getroutes));
    let result: unknown;
    try { result = await cln.findCircularRoute(REQUEST); } catch { result = 'rejects'; }
    expect(result).toEqual(expected);
    expectLayerLifecycle(fake);
  });
}

// End to end with dispatchExecution: the CLN adapter behind the executor (SPEC §5.4 C9-C10, §8.2).

function composite(node: ScriptedExecutionNode, cln: ClnExecutionAdapter): ExecutionAdapter {
  return {
    listChannels: () => node.listChannels(),
    createInvoice: (a, p, l, e) => cln.createInvoice(a, p, l, e),
    sendOnRoute: (r, h, s, d) => cln.sendOnRoute(r, h, s, d),
    observePayment: (h, m) => cln.observePayment(h, m),
    invoiceState: h => cln.invoiceState(h),
    cancelUnpaidInvoice: (h, l) => cln.cancelUnpaidInvoice(h, l),
  };
}

const invoiceHandler: ClnHandler = (c, f) => {
  const hash = sha256(Buffer.from(String(c.params['preimage']), 'hex'));
  f.result(c, 'invoice', { payment_hash: hash, payment_secret: SECRET, bolt11: syntheticInvoice(hash), expires_at: 1760003600, created_index: 9 });
};

async function endToEnd(prefix: string, methods: Partial<Record<string, ClnHandler>>, attemptDeadlineMs: number) {
  const r = await prepare(prefix, {
    attemptDeadlineMs: 30_000,
    route: () => ROUTE,
    // The worked-example route costs 202,101 msat over 132 blocks: approved at the policy caps 300,000 msat / 144 blocks.
    approval: a => ({ ...a, approvedMaxFeeMsat: 300_000n, approvedMaxCltvDelta: 144 }),
    script: ({ path }) => {
      // Admitted observations share the database clock used by dispatch.
      // Explicit stale/future cases elsewhere retain their own timestamps.
      const balances = () => {
        const observedAt = dbNow(path);
        return [fakeChannel(CH2, LND_R, { observedAt }), fakeChannel(CH5, CLN_R, { observedAt })];
      };
      return { before: balances, after: balances };
    },
  });
  const { fake, cln } = await adapter({ invoice: invoiceHandler, ...methods }, { attemptDeadlineMs });
  const outcome = await r.run(composite(r.node, cln));
  return { r, fake, outcome };
}

it('CP-031/B3 end to end: waitsendpay 200 until the deadline leaves the execution UNKNOWN (exit 7), one sendpay, the invoice kept', async () => {
  const { r, fake, outcome } = await endToEnd('cln-e2e-200', { sendpay: sendpayPending, waitsendpay: waits(stillInFlight), listsendpays: listSendPays('pending') }, 1_200);
  expect(outcome).toEqual({ executionId: r.executionId, exit: 7, step: 'OUTCOME_UNKNOWN' });
  expect(rowOf(r.path, r.executionId).status).toBe('UNKNOWN');
  expect(callsOf(fake, 'sendpay')).toHaveLength(1);
  expect(callsOf(fake, 'delinvoice')).toEqual([]);
  expect(forbidden(fake)).toEqual([]);
});

it('CP-031/B4 end to end: a confirmed failure deletes the unpaid invoice by its label, then VERIFIED_FAILURE (exit 5)', async () => {
  const { r, fake, outcome } = await endToEnd('cln-e2e-fail', {
    sendpay: sendpayPending,
    waitsendpay: waits((c, f) => { f.rpcError(c, 'waitsendpay-failure', 204, 'failed: WIRE_TEMPORARY_CHANNEL_FAILURE'); }),
    listsendpays: listSendPays('failed'), listinvoices: listInvoices('unpaid'),
    delinvoice: (c, f) => { f.result(c, 'delinvoice', clnInvoice({ label: String(c.params['label']), status: 'unpaid', payment_hash: HASH })); },
  }, 3_000);
  expect(outcome.exit).toBe(5);
  expect(rowOf(r.path, r.executionId).status).toBe('VERIFIED_FAILURE');
  expect(callsOf(fake, 'delinvoice')).toEqual([{ label: labelOf(r.executionId), status: 'unpaid' }]);
  expect(callsOf(fake, 'sendpay')).toHaveLength(1);
});

// Repair round: classification of code-less answers, the result checks and V5 with CLN padding.

const codeless: readonly (readonly [string, ClnHandler])[] = [
  ['a proxy 502', (c, f) => { f.raw(c, 'proxy-status', 502, '<html><body>502 Bad Gateway</body></html>'); }],
  ['a proxy 504', (c, f) => { f.raw(c, 'proxy-status', 504, '<html><body>504 Gateway Timeout</body></html>'); }],
  ['a 500 that is not JSON', (c, f) => { f.raw(c, 'malformed', 500, 'Internal Server Error'); }],
  ['a 500 JSON body without a lightningd code', (c, f) => { f.raw(c, 'malformed', 500, JSON.stringify({ message: 'upstream connect error' })); }],
];

const noPayments: ClnHandler = (c, f) => { f.result(c, 'listsendpays', { payments: [] }); };

for (const [name, answer] of codeless) {
  it(`CP-032/B1 ${name} to sendpay is AMBIGUOUS, never a failure before initiation (INV-04)`, async () => {
    const { fake, cln } = await adapter({ sendpay: answer, listsendpays: noPayments, listinvoices: listInvoices('unpaid') });
    const observation = await cln.sendOnRoute(ROUTE, HASH, SECRET);
    expect(observation.kind).toBe('AMBIGUOUS');
    expect(callsOf(fake, 'sendpay')).toHaveLength(1);
    expect(callsOf(fake, 'delinvoice')).toEqual([]);
  });

  it(`CP-032/B1 ${name} to waitsendpay is AMBIGUOUS even while listsendpays shows the part failed`, async () => {
    const { cln } = await adapter({ sendpay: sendpayPending, waitsendpay: waits(answer), listsendpays: listSendPays('failed'), listinvoices: listInvoices('unpaid') });
    expect((await cln.sendOnRoute(ROUTE, HASH, SECRET)).kind).toBe('AMBIGUOUS');
  });
}

it('CP-032/B1 end to end: a proxy 502 to sendpay leaves the execution UNKNOWN with its invoice kept and its budget held', async () => {
  const { r, fake, outcome } = await endToEnd('cln-e2e-502', {
    sendpay: (c, f) => { f.raw(c, 'proxy-status', 502, '<html><body>502 Bad Gateway</body></html>'); },
    listsendpays: noPayments, listinvoices: listInvoices('unpaid'),
    delinvoice: (c, f) => { f.result(c, 'delinvoice', clnInvoice({ label: String(c.params['label']), status: 'unpaid' })); },
  }, 3_000);
  expect(outcome).toEqual({ executionId: r.executionId, exit: 7, step: 'OUTCOME_UNKNOWN' });
  expect(rowOf(r.path, r.executionId).status).toBe('UNKNOWN');
  expect(callsOf(fake, 'delinvoice')).toEqual([]);
  expect(reservationState(r.path, r.executionId).state).toBe('HELD');
});

it('CP-031/B3 sendpay 204 returned before any HTLC was added, with no payment stored and the invoice unpaid, is a failure before initiation', async () => {
  const { cln } = await adapter({
    sendpay: (c, f) => { f.rpcError(c, 'sendpay-first-hop-refused', 204, 'No connection to first peer found'); },
    listsendpays: noPayments, listinvoices: listInvoices('unpaid'),
  });
  expect(await cln.sendOnRoute(ROUTE, HASH, SECRET)).toMatchObject({ kind: 'FAILED', reason: 'REJECTED_BEFORE_INITIATION', local: true, htlcsInFlight: 0 });
});

it('CP-031/B3 a waitsendpay failure while another part of the payment is still pending is not a failure', async () => {
  const { cln } = await adapter({
    sendpay: sendpayPending,
    waitsendpay: waits((c, f) => { f.rpcError(c, 'waitsendpay-failure', 204, 'failed: WIRE_TEMPORARY_CHANNEL_FAILURE'); }),
    listsendpays: (c, f) => {
      f.result(c, 'listsendpays', { payments: [sendpay({ payment_hash: askedHash(c), status: 'failed', id: 4 }), sendpay({ payment_hash: askedHash(c), status: 'pending', id: 5, partid: 1 })] });
    },
    listinvoices: listInvoices('unpaid'),
  });
  expect((await cln.sendOnRoute(ROUTE, HASH, SECRET)).kind).not.toBe('FAILED');
});

it('CP-031/B3 a complete answer that delivered more than the principal is AMBIGUOUS, not a success', async () => {
  const { cln } = await adapter({
    sendpay: sendpayPending,
    waitsendpay: waits((c, f) => { f.result(c, 'waitsendpay-complete', complete({ amount_msat: 100000001 })); }),
    listsendpays: listSendPays('complete'),
  });
  expect((await cln.sendOnRoute(ROUTE, HASH, SECRET)).kind).toBe('AMBIGUOUS');
});

it('CP-031/B3 a complete answer for another payment hash is not our success, even with that payment own preimage', async () => {
  const otherPreimage = randomBytes(32);
  const { cln } = await adapter({
    sendpay: sendpayPending,
    waitsendpay: waits((c, f) => { f.result(c, 'waitsendpay-complete', complete({ payment_hash: sha256(otherPreimage), payment_preimage: otherPreimage.toString('hex') })); }),
    listsendpays: listSendPays('complete'),
  });
  expect((await cln.sendOnRoute(ROUTE, HASH, SECRET)).kind).not.toBe('SUCCEEDED');
});

it('CP-031/B1 a hop whose CLTV would be zero blocks above the build height is never sent', async () => {
  const [h0, h1, h2] = ROUTE.hops;
  if (h0 === undefined || h1 === undefined || h2 === undefined) throw new Error('route');
  const flat: CircularRoute = { ...ROUTE, hops: [h0, h1, { ...h2, expiry: HEIGHT }] };
  const { fake, cln } = await adapter({ sendpay: sendpayPending, waitsendpay: waits((c, f) => { f.result(c, 'waitsendpay-complete', complete()); }), listsendpays: listSendPays('complete') });
  let kind: string;
  try { kind = (await cln.sendOnRoute(flat, HASH, SECRET)).kind; } catch { kind = 'rejected'; }
  expect(kind).not.toBe('SUCCEEDED');
  expect(fake.requests.filter(r => r.url === '/v1/sendpay')).toHaveLength(0);
});

it('CP-031/B4 delinvoice 906 while the invoice is still unpaid is never reported as cancelled', async () => {
  const { cln } = await adapter({
    delinvoice: (c, f) => { f.rpcError(c, 'delinvoice-status-mismatch', 906, 'Invoice status changed', { current_status: 'unpaid', expected_status: 'unpaid' }); },
    listinvoices: listInvoices('unpaid'),
  });
  let result: string;
  try { result = await cln.cancelUnpaidInvoice(HASH, 'fluxwarden-01JEXEC'); } catch { result = 'rejected'; }
  expect(result).not.toBe('CANCELED');
});

it('CP-032/B2 observePayment with two complete parts of which one preimage does not match reports no proven success', async () => {
  const { cln } = await adapter({
    listsendpays: (c, f) => {
      f.result(c, 'listsendpays', {
        payments: [
          sendpay({ payment_hash: askedHash(c), status: 'complete', id: 4, payment_preimage: PREIMAGE.toString('hex') }),
          sendpay({ payment_hash: askedHash(c), status: 'complete', id: 5, partid: 1, payment_preimage: randomBytes(32).toString('hex') }),
        ],
      });
    },
  });
  expect(await cln.observePayment(HASH)).not.toMatchObject({ kind: 'SUCCEEDED', preimageMatchesHash: true });
});

it('CP-031/B4 V5 with CLN padding 1: a route of delta exactly max_cltv_delta is refused, one block more of budget passes', async () => {
  // Decision D52: lightningd sends each HTLC at height + 1 + cltv_out (lightningd/pay.c L786-L790), so delta 132 occupies
  // 133 blocks above the current height.
  const refused = await adapter(routeMethods(oneRoute));
  expect(await refused.cln.findCircularRoute({ ...REQUEST, maxCltvDelta: 132 })).toEqual({ refusal: 'CLTV_DELTA_UNSAFE' });
  expectLayerLifecycle(refused.fake);
  const passing = await adapter(routeMethods(oneRoute));
  expect(await passing.cln.findCircularRoute({ ...REQUEST, maxCltvDelta: 133 })).toEqual(ROUTE);
  // D57: maxdelay includes the final 18 + inbound 34; only D52 padding is reserved: 133 - 1 = 132.
  expect(Number(callsOf(passing.fake, 'getroutes')[0]?.['maxdelay'])).toBe(132);
});

it('CP-031/B4 the layer is removed even when the askrene-create-layer connection is cut after the request', async () => {
  const cut: ClnHandler = (c, f) => { f.reset(c, 'connection-reset'); };
  const { fake, cln } = await adapter({ ...routeMethods(oneRoute), 'askrene-create-layer': cut });
  try { await cln.findCircularRoute(REQUEST); } catch { /* the caller classifies the failure */ }
  const created = callsOf(fake, 'askrene-create-layer').map(p => p['layer']);
  expect(created).toHaveLength(1);
  expect(callsOf(fake, 'askrene-remove-layer').map(p => p['layer'])).toEqual(created);
  expect(callsOf(fake, 'getroutes')).toEqual([]);
});

// Round 3: gateway statuses carrying a code, coded refusals, waitsendpay confirmation in observePayment.

for (const status of [408, 499, 502, 503, 504]) {
  it(`CP-032/B1 a gateway ${String(status)} whose body carries a lightningd-looking code 204 is not lightningd's refusal: AMBIGUOUS, invoice kept`, async () => {
    const { fake, cln } = await adapter({
      sendpay: (c, f) => { f.raw(c, 'proxy-status', status, JSON.stringify({ code: 204, message: 'First peer not ready' })); },
      listsendpays: noPayments, listinvoices: listInvoices('unpaid'),
    });
    expect((await cln.sendOnRoute(ROUTE, HASH, SECRET)).kind).toBe('AMBIGUOUS');
    expect(callsOf(fake, 'delinvoice')).toEqual([]);
  });
}

it('CP-032/B1 end to end: a proxy 502 relaying code 204 leaves the execution UNKNOWN with its invoice kept', async () => {
  const { r, fake, outcome } = await endToEnd('cln-e2e-502-coded', {
    sendpay: (c, f) => { f.raw(c, 'proxy-status', 502, JSON.stringify({ code: 204, message: 'First peer not ready' })); },
    listsendpays: noPayments, listinvoices: listInvoices('unpaid'),
    delinvoice: (c, f) => { f.result(c, 'delinvoice', clnInvoice({ label: String(c.params['label']), status: 'unpaid' })); },
  }, 3_000);
  expect(outcome).toEqual({ executionId: r.executionId, exit: 7, step: 'OUTCOME_UNKNOWN' });
  expect(callsOf(fake, 'delinvoice')).toEqual([]);
  expect(reservationState(r.path, r.executionId).state).toBe('HELD');
});

it('CP-031/B3 sendpay -32602 (parameters refused while parsing, nothing stored) with no record and the invoice unpaid is a failure before initiation', async () => {
  const { cln } = await adapter({
    sendpay: (c, f) => { f.rpcError(c, 'sendpay-params-refused', -32602, "payment_secret: should be a 32 byte hex value: invalid token '\"zz\"'"); },
    listsendpays: noPayments, listinvoices: listInvoices('unpaid'),
  });
  expect(await cln.sendOnRoute(ROUTE, HASH, SECRET)).toMatchObject({ kind: 'FAILED', reason: 'REJECTED_BEFORE_INITIATION', local: true, htlcsInFlight: 0 });
});

it('CP-031/B3 a waitsendpay error code outside the documented set is AMBIGUOUS even while listsendpays shows failed', async () => {
  const { cln } = await adapter({
    sendpay: sendpayPending,
    // 205 is a pay / getroute code (common/jsonrpc_errors.h L40), not one waitsendpay documents.
    waitsendpay: waits((c, f) => { f.rpcError(c, 'waitsendpay-failure', 205, 'Could not find a route'); }),
    listsendpays: listSendPays('failed'), listinvoices: listInvoices('unpaid'),
  });
  expect((await cln.sendOnRoute(ROUTE, HASH, SECRET)).kind).toBe('AMBIGUOUS');
});

for (const [name, wait, expected] of [
  ['200 (still in flight)', stillInFlight, { kind: 'IN_FLIGHT' }],
  ['204 (the attempt failed)', ((c, f) => { f.rpcError(c, 'waitsendpay-failure', 204, 'failed: WIRE_TEMPORARY_CHANNEL_FAILURE'); }) as (c: ClnContext, f: FakeCln) => void, { kind: 'FAILED', htlcsInFlight: 0 }],
] as const) {
  it(`CP-032/B2 observePayment confirms a listsendpays failed with waitsendpay: ${name}`, async () => {
    const { fake, cln } = await adapter({ listsendpays: listSendPays('failed'), waitsendpay: waits(wait) });
    expect(await cln.observePayment(HASH)).toMatchObject(expected);
    const [params] = callsOf(fake, 'waitsendpay');
    expect(params?.['payment_hash']).toBe(HASH);
    expect(Number(params?.['timeout'])).toBe(1);
  });
}

it('CP-032/B2 observePayment never reports FAILED when waitsendpay answers the payment complete', async () => {
  const { cln } = await adapter({ listsendpays: listSendPays('failed'), waitsendpay: waits((c, f) => { f.result(c, 'waitsendpay-complete', complete()); }) });
  expect((await cln.observePayment(HASH)).kind).not.toBe('FAILED');
});

for (const [name, answer] of [
  ['a 500 without a lightningd code', ((c, f) => { f.raw(c, 'malformed', 500, JSON.stringify({ message: 'upstream reset' })); }) as ClnHandler],
  ['a proxy 502 carrying a code', ((c, f) => { f.raw(c, 'proxy-status', 502, JSON.stringify({ code: -32602, message: 'relayed' })); }) as ClnHandler],
] as const) {
  it(`CP-031/B4 the layer is removed when askrene-create-layer answers ${name}`, async () => {
    const { fake, cln } = await adapter({ ...routeMethods(oneRoute), 'askrene-create-layer': answer });
    try { await cln.findCircularRoute(REQUEST); } catch { /* the caller classifies the failure */ }
    const created = callsOf(fake, 'askrene-create-layer').map(p => p['layer']);
    expect(created).toHaveLength(1);
    expect(callsOf(fake, 'askrene-remove-layer').map(p => p['layer'])).toEqual(created);
  });
}
