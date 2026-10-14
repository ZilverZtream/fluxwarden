/*
Interface: test/helpers/cp030-execution.ts (src/node-lnd/execute.ts LndExecutionAdapter over the LndRest transport of
test/helpers/adapter-interfaces.ts).

Node facts (lnd v0.21.4-beta, cited in test/fakes/lnd/fake-lnd.ts behaviours):
- AddInvoice POST /v1/invoices takes r_preimage (bytes, base64 over REST) and value_msat (int64, decimal text) and answers
  r_hash and payment_addr (bytes) (lnrpc/lightning.proto Invoice, AddInvoiceResponse).
- SendToRouteV2 POST /v2/router/route/send {payment_hash (bytes), route} (routerrpc/router.proto SendToRouteRequest). The
  route is read by routerrpc/router_backend.go UnmarshallRoute: total_amt_msat, total_time_lock and per hop chan_id,
  pub_key, amt_to_forward_msat, expiry (the hop's outgoing time lock), mpp_record {payment_addr, total_amt_msat}; the
  top-level hop total_amt_msat is for blinded hops only and is refused without encrypted data. payment_addr is required
  since lnd#10801 (ARCHITECTURE §5 L8) and total_amt_msat must equal the delivered amount (L9). It sends one HTLC (L7).
- SendToRouteV2 answers the stored HTLCAttempt, or codes.AlreadyExists for an existing, in-flight or paid hash
  (router_server.go); TrackPaymentV2 answers NotFound "payment isn't initiated" for an unknown hash (L28).
- Payment.status SUCCEEDED with a preimage decides success whatever failure_reason says (L6, lnd#8884); FAILED with an HTLC
  in flight is not terminal (lnd#8975); INITIATED and IN_FLIGHT are in flight (L5).
- CancelInvoice POST /v2/invoices/cancel {payment_hash (bytes)}: idempotent for a cancelled invoice, "invoice already
  settled" for a settled one, and success without cancelling an ACCEPTED one (invoices/invoiceregistry.go).
*/
import { randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { certificatePath, type FakeServer } from '../fakes/https.js';
import { startFakeLnd, type FakeLnd, type LndContext, type LndRoute } from '../fakes/lnd/fake-lnd.js';
import { addInvoiceResponse, attempt, b64, htlcAttempt, invoice, payment } from '../fakes/lnd/responses.js';
import { circularRoute } from '../fakes/preflight-node.js';
import { loadErrors, loadLndRest, rejection } from '../helpers/adapter-interfaces.js';
import { syntheticInvoice } from '../helpers/cp004-invoice.js';
import { IN_PEER, NODE_PUBKEY, OUT_PEER, PRINCIPAL } from '../helpers/cp028-executor.js';
import { loadLndExecute, sha256, type LndExecutionAdapter, type PaymentObservation } from '../helpers/cp030-execution.js';

const scratch = mkdtempSync(join(tmpdir(), 'fw-lnd-exec-'));
const macaroon = randomBytes(96);
const macaroonHex = macaroon.toString('hex');
const macaroonPath = join(scratch, 'test.macaroon');
writeFileSync(macaroonPath, macaroon);

const SOURCE = '123145302376448';
const MIDDLE = '369435906932736';
const TARGET = '246290604752896';
const ROUTE = circularRoute(SOURCE, TARGET, 150_000n, 80);
const PREIMAGE = randomBytes(32);
const HASH = sha256(PREIMAGE);
const SECRET = 'a7'.repeat(32);

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

async function adapter(routes: Partial<Record<string, LndRoute>>, timeoutMs = 5_000): Promise<{ fake: FakeLnd; lnd: LndExecutionAdapter }> {
  const fake = await startFakeLnd({ macaroonHex, routes });
  open.push(fake);
  const { openLndRest } = await loadLndRest();
  const rest = await openLndRest({ host: fake.host, port: fake.port, tlsCertPath: certificatePath('node'), macaroonPath, timeoutMs });
  const { LndExecutionAdapter } = await loadLndExecute();
  return { fake, lnd: new LndExecutionAdapter(rest, { trackDeadlineMs: 2_000 }) };
}

const bodyOf = (fake: FakeLnd, method: string, url: string): Record<string, unknown>[] =>
  fake.requests.filter(r => r.method === method && r.url.split('?')[0] === url).map(r => JSON.parse(r.body) as Record<string, unknown>);

const sends = (fake: FakeLnd): number => fake.requests.filter(r => r.url === '/v2/router/route/send').length;
const paymentV2 = (fake: FakeLnd): number => fake.requests.filter(r => r.url === '/v2/router/send').length;

const line = (message: Record<string, unknown>): string => `${JSON.stringify({ result: message })}\n`;

/** A TrackPaymentV2 route answering the given Payment records as stream lines, then ending the stream. */
function track(...records: Record<string, unknown>[]): LndRoute {
  return (context, lnd) => { lnd.stream(context, 'trackpayment-stream', records.map(line), 'finish'); };
}

function settledPayment(over: Record<string, unknown> = {}): Record<string, unknown> {
  return payment({
    payment_hash: HASH, status: 'SUCCEEDED', payment_preimage: PREIMAGE.toString('hex'), value_msat: '100000000', fee_msat: '150000',
    htlcs: [{ ...attempt('SUCCEEDED', '41'), preimage: b64(PREIMAGE.toString('hex')) }], failure_reason: 'FAILURE_REASON_NONE', ...over,
  });
}

function failedPayment(reason: string, htlcs: Record<string, unknown>[] = [attempt('FAILED', '41')]): Record<string, unknown> {
  return payment({ payment_hash: HASH, status: 'FAILED', payment_preimage: '0'.repeat(64), fee_msat: '0', htlcs, failure_reason: reason });
}

const answerAttempt = (status: 'SUCCEEDED' | 'FAILED'): LndRoute => (context, lnd) => {
  lnd.answer(context, 'sendtoroute-attempt', htlcAttempt(status, status === 'SUCCEEDED' ? PREIMAGE.toString('hex') : '', status === 'FAILED' ? 'INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS' : null));
};

it('CP-030/B1 createInvoice sends the FluxWarden preimage and principal to AddInvoice and returns the hash and payment address', async () => {
  const { fake, lnd } = await adapter({
    'POST /v1/invoices': (context: LndContext, f) => {
      const body = JSON.parse(context.request.body) as { r_preimage: string };
      const hash = sha256(Buffer.from(body.r_preimage, 'base64'));
      f.answer(context, 'addinvoice', addInvoiceResponse(hash, SECRET, syntheticInvoice(hash)));
    },
  });
  const result = await lnd.createInvoice(PRINCIPAL, PREIMAGE, 'fluxwarden-01JEXEC', 3_600);
  expect(result).toEqual({ paymentHash: HASH, paymentSecret: SECRET, finalCltvDelta: 18 });
  const [body] = bodyOf(fake, 'POST', '/v1/invoices');
  expect(body?.['r_preimage']).toBe(PREIMAGE.toString('base64'));
  expect(String(body?.['value_msat'])).toBe('100000000');
  expect(String(body?.['expiry'])).toBe('3600');
  expect(body?.['memo']).toBe('fluxwarden-01JEXEC');
  expect(sends(fake)).toBe(0);
});

it('CP-030/B1 an AddInvoice answer naming another hash is a protocol error', async () => {
  const errors = await loadErrors();
  const other = 'cd'.repeat(32);
  const { lnd } = await adapter({ 'POST /v1/invoices': (context, f) => { f.answer(context, 'addinvoice', addInvoiceResponse(other, SECRET, syntheticInvoice(other))); } });
  expect(await rejection(lnd.createInvoice(PRINCIPAL, PREIMAGE, 'fluxwarden-01JEXEC', 3_600))).toBeInstanceOf(errors.ProtocolError);
});

it('CP-030/B2 SendToRouteV2 carries the payment hash and the route with payment_addr and total_amt_msat = principal on the last hop only', async () => {
  const { fake, lnd } = await adapter({ 'POST /v2/router/route/send': answerAttempt('SUCCEEDED'), 'GET /v2/router/track/{payment_hash}': track(settledPayment()) });
  await lnd.sendOnRoute(ROUTE, HASH, SECRET);
  const [body] = bodyOf(fake, 'POST', '/v2/router/route/send');
  if (body === undefined) throw new Error('no SendToRouteV2 request');
  expect(body['payment_hash']).toBe(Buffer.from(HASH, 'hex').toString('base64'));
  expect(body['skip_temp_err'] === true).toBe(false);
  const route = body['route'] as { total_amt_msat: unknown; total_time_lock: unknown; hops: Record<string, unknown>[] };
  // ROUTE: us -S-> OUT_PEER receives 100,150,000 at 580; OUT_PEER -> IN_PEER receives 100,075,000 at 552; IN_PEER -T-> us
  // receives 100,000,000 at 518. LND's hop i forwards hops[i+1]'s amount with hops[i+1]'s expiry as its outgoing time lock.
  expect(String(route.total_amt_msat)).toBe('100150000');
  expect(Number(route.total_time_lock)).toBe(580);
  expect(route.hops.map(h => [String(h['chan_id']), h['pub_key'], String(h['amt_to_forward_msat']), Number(h['expiry'])])).toEqual([
    [SOURCE, OUT_PEER, '100075000', 552],
    [MIDDLE, IN_PEER, '100000000', 518],
    [TARGET, NODE_PUBKEY, '100000000', 518],
  ]);
  const last = route.hops[2] ?? {};
  const mpp = last['mpp_record'] as { payment_addr: unknown; total_amt_msat: unknown } | undefined;
  expect(mpp?.payment_addr).toBe(Buffer.from(SECRET, 'hex').toString('base64'));
  expect(String(mpp?.total_amt_msat)).toBe('100000000');
  for (const hop of route.hops.slice(0, 2)) expect(hop['mpp_record'] ?? null).toBeNull();
  for (const hop of route.hops) {
    expect(hop['amp_record'] ?? null).toBeNull();
    expect(String(hop['total_amt_msat'] ?? '0')).toBe('0');
  }
});

for (const [name, routes] of [
  ['a settled attempt', { 'POST /v2/router/route/send': answerAttempt('SUCCEEDED'), 'GET /v2/router/track/{payment_hash}': track(settledPayment()) }],
  ['a failed attempt', { 'POST /v2/router/route/send': answerAttempt('FAILED'), 'GET /v2/router/track/{payment_hash}': track(failedPayment('FAILURE_REASON_INCORRECT_PAYMENT_DETAILS')) }],
  ['a connection cut after the request', { 'POST /v2/router/route/send': ((c, f) => { f.reset(c, 'reset-after-request'); }) as LndRoute, 'GET /v2/router/track/{payment_hash}': track(payment({ payment_hash: HASH, status: 'IN_FLIGHT' })) }],
  ['AlreadyExists', { 'POST /v2/router/route/send': ((c, f) => { f.grpcError(c, 'sendtoroute-already-exists', 6, 'payment is in transition'); }) as LndRoute, 'GET /v2/router/track/{payment_hash}': track(payment({ payment_hash: HASH, status: 'IN_FLIGHT' })) }],
] as const) {
  it(`CP-030/B3 exactly one SendToRouteV2 and no SendPaymentV2 after ${name}`, async () => {
    const { fake, lnd } = await adapter({ ...routes, 'POST /v2/router/send': (c, f) => { f.grpcError(c, 'sendpayment-v2', 2, 'permission denied'); } });
    await lnd.sendOnRoute(ROUTE, HASH, SECRET);
    expect(sends(fake)).toBe(1);
    expect(paymentV2(fake)).toBe(0);
  });
}

it('CP-030/B3 the request is reported as written while SendToRouteV2 still blocks', async () => {
  const { lnd } = await adapter({ 'POST /v2/router/route/send': (c, f) => { f.hold(c, 'no-answer'); } }, 800);
  let dispatched = 0;
  const observation = await lnd.sendOnRoute(ROUTE, HASH, SECRET, () => { dispatched += 1; });
  expect(dispatched).toBe(1);
  expect(observation.kind).toBe('AMBIGUOUS');
});

it('CP-030/B4 a settled attempt is confirmed by TrackPaymentV2: one HTLC and the node-reported fee', async () => {
  const { fake, lnd } = await adapter({ 'POST /v2/router/route/send': answerAttempt('SUCCEEDED'), 'GET /v2/router/track/{payment_hash}': track(settledPayment({ fee_msat: '150123' })) });
  const observation = await lnd.sendOnRoute(ROUTE, HASH, SECRET);
  expect(observation).toMatchObject({ kind: 'SUCCEEDED', preimageMatchesHash: true, feeMsat: 150_123n, htlcCount: 1 });
  expect(fake.requests.some(r => r.method === 'GET' && r.url.startsWith('/v2/router/track/'))).toBe(true);
});

it('CP-030/B4 two settled HTLCs on the payment record are reported as htlcCount 2', async () => {
  const two = settledPayment({ htlcs: [attempt('SUCCEEDED', '41'), attempt('SUCCEEDED', '42')] });
  const { lnd } = await adapter({ 'POST /v2/router/route/send': answerAttempt('SUCCEEDED'), 'GET /v2/router/track/{payment_hash}': track(two) });
  expect(await lnd.sendOnRoute(ROUTE, HASH, SECRET)).toMatchObject({ kind: 'SUCCEEDED', htlcCount: 2 });
});

it('CP-030/B5 a failed attempt confirmed FAILED with no HTLC in flight is a failure with the node reason', async () => {
  const { lnd } = await adapter({
    'POST /v2/router/route/send': answerAttempt('FAILED'),
    'GET /v2/router/track/{payment_hash}': track(failedPayment('FAILURE_REASON_INCORRECT_PAYMENT_DETAILS')),
  });
  expect(await lnd.sendOnRoute(ROUTE, HASH, SECRET)).toMatchObject({ kind: 'FAILED', reason: 'FAILURE_REASON_INCORRECT_PAYMENT_DETAILS', htlcsInFlight: 0 });
});

it('CP-030/B5 cancelUnpaidInvoice calls CancelInvoice with the hash and confirms CANCELED by LookupInvoice', async () => {
  const { fake, lnd } = await adapter({
    'POST /v2/invoices/cancel': (c, f) => { f.answer(c, 'cancelinvoice', {}); },
    'GET /v1/invoice/{r_hash_str}': (c, f) => { f.answer(c, 'lookupinvoice', invoice({ r_hash: b64(HASH), state: 'CANCELED' })); },
  });
  expect(await lnd.cancelUnpaidInvoice(HASH, 'fluxwarden-01JEXEC')).toBe('CANCELED');
  expect(bodyOf(fake, 'POST', '/v2/invoices/cancel')).toEqual([{ payment_hash: Buffer.from(HASH, 'hex').toString('base64') }]);
});

it('CP-030/B5 an invoice already settled is reported as ALREADY_PAID, never as cancelled', async () => {
  const { lnd } = await adapter({
    'POST /v2/invoices/cancel': (c, f) => { f.grpcError(c, 'cancelinvoice-settled', 2, 'invoice already settled'); },
    'GET /v1/invoice/{r_hash_str}': (c, f) => { f.answer(c, 'lookupinvoice', invoice({ r_hash: b64(HASH), state: 'SETTLED', settled: true, amt_paid_msat: '100000000' })); },
  });
  expect(await lnd.cancelUnpaidInvoice(HASH, 'fluxwarden-01JEXEC')).toBe('ALREADY_PAID');
});

it('CP-030/B5 a CancelInvoice success that left the invoice SETTLED is ALREADY_PAID (lnd answers success without cancelling an accepted invoice)', async () => {
  const { lnd } = await adapter({
    'POST /v2/invoices/cancel': (c, f) => { f.answer(c, 'cancelinvoice', {}); },
    'GET /v1/invoice/{r_hash_str}': (c, f) => { f.answer(c, 'lookupinvoice', invoice({ r_hash: b64(HASH), state: 'SETTLED', settled: true, amt_paid_msat: '100000000' })); },
  });
  expect(await lnd.cancelUnpaidInvoice(HASH, 'fluxwarden-01JEXEC')).toBe('ALREADY_PAID');
});

for (const [name, sendRoute, trackRoute] of [
  ['a connection cut after the request', ((c, f) => { f.reset(c, 'reset-after-request'); }) as LndRoute, track(payment({ payment_hash: HASH, status: 'IN_FLIGHT' }))],
  ['a 504 from a proxy', ((c, f) => { f.raw(c, 'proxy-status', 504, '<html>Gateway Timeout</html>'); }) as LndRoute, track(payment({ payment_hash: HASH, status: 'IN_FLIGHT' }))],
  ['a tracking stream that ends without a terminal status', answerAttempt('SUCCEEDED'), track(payment({ payment_hash: HASH, status: 'IN_FLIGHT', htlcs: [attempt('IN_FLIGHT', '41')] }))],
] as const) {
  it(`CP-032/B1 ${name} is AMBIGUOUS, never a failure`, async () => {
    const { fake, lnd } = await adapter({ 'POST /v2/router/route/send': sendRoute, 'GET /v2/router/track/{payment_hash}': trackRoute });
    const observation = await lnd.sendOnRoute(ROUTE, HASH, SECRET);
    expect(observation.kind).toBe('AMBIGUOUS');
    expect(sends(fake)).toBe(1);
  });
}

for (const [name, record, expected] of [
  ['SUCCEEDED with a matching preimage and failure_reason TIMEOUT', settledPayment({ failure_reason: 'FAILURE_REASON_TIMEOUT' }), { kind: 'SUCCEEDED', preimageMatchesHash: true, feeMsat: 150_000n, htlcCount: 1 }],
  ['FAILED with an HTLC still in flight', failedPayment('FAILURE_REASON_TIMEOUT', [attempt('FAILED', '41'), attempt('IN_FLIGHT', '42')]), { kind: 'IN_FLIGHT' }],
  ['INITIATED', payment({ payment_hash: HASH, status: 'INITIATED' }), { kind: 'IN_FLIGHT' }],
  ['FAILED with no HTLC in flight', failedPayment('FAILURE_REASON_NO_ROUTE', []), { kind: 'FAILED', reason: 'FAILURE_REASON_NO_ROUTE', htlcsInFlight: 0 }],
] as const) {
  it(`CP-032/B2 observePayment reads ${name}`, async () => {
    const { lnd } = await adapter({ 'GET /v2/router/track/{payment_hash}': track(record) });
    expect(await lnd.observePayment(HASH)).toMatchObject(expected as PaymentObservation);
  });
}

it('CP-032/B2 observePayment maps TrackPaymentV2 NotFound to NOT_FOUND', async () => {
  const { lnd } = await adapter({ 'GET /v2/router/track/{payment_hash}': (c, f) => { f.grpcError(c, 'trackpayment-not-initiated', 5, "payment isn't initiated"); } });
  expect(await lnd.observePayment(HASH)).toEqual({ kind: 'NOT_FOUND' });
});

it('CP-032/B3 SendToRouteV2 AlreadyExists for a paid hash is resolved by TrackPaymentV2 to the settled payment', async () => {
  const { fake, lnd } = await adapter({
    'POST /v2/router/route/send': (c, f) => { f.grpcError(c, 'sendtoroute-already-exists', 6, 'invoice is already paid'); },
    'GET /v2/router/track/{payment_hash}': track(settledPayment()),
  });
  expect(await lnd.sendOnRoute(ROUTE, HASH, SECRET)).toMatchObject({ kind: 'SUCCEEDED', preimageMatchesHash: true, htlcCount: 1 });
  expect(sends(fake)).toBe(1);
});

it('CP-032/B3 a refusal before initiation whose TrackPaymentV2 answers NotFound is FAILED REJECTED_BEFORE_INITIATION', async () => {
  const { lnd } = await adapter({
    'POST /v2/router/route/send': (c, f) => { f.grpcError(c, 'sendtoroute-refused', 2, 'unable to send, no routes provided'); },
    'GET /v2/router/track/{payment_hash}': (c, f) => { f.grpcError(c, 'trackpayment-not-initiated', 5, "payment isn't initiated"); },
  });
  expect(await lnd.sendOnRoute(ROUTE, HASH, SECRET)).toMatchObject({ kind: 'FAILED', reason: 'REJECTED_BEFORE_INITIATION', local: true, htlcsInFlight: 0 });
});

it('CP-032/B1 an HTLCAttempt answer followed by TrackPaymentV2 NotFound is AMBIGUOUS: the answer proves the payment was initiated', async () => {
  const { lnd } = await adapter({
    'POST /v2/router/route/send': answerAttempt('FAILED'),
    'GET /v2/router/track/{payment_hash}': (c, f) => { f.grpcError(c, 'trackpayment-not-initiated', 5, "payment isn't initiated"); },
  });
  expect((await lnd.sendOnRoute(ROUTE, HASH, SECRET)).kind).toBe('AMBIGUOUS');
});

it('CP-030/B5 CancelInvoice answering "unable to locate invoice" is NOT_FOUND, never CANCELED', async () => {
  const { lnd } = await adapter({
    'POST /v2/invoices/cancel': (c, f) => { f.grpcError(c, 'cancelinvoice-not-found', 2, 'unable to locate invoice'); },
    'GET /v1/invoice/{r_hash_str}': (c, f) => { f.grpcError(c, 'lookupinvoice-not-found', 5, 'there are no existing invoices'); },
  });
  expect(await lnd.cancelUnpaidInvoice(HASH, 'fluxwarden-01JEXEC')).toBe('NOT_FOUND');
});
