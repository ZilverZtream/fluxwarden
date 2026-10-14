import { randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { loadErrors, loadLndApi, loadLndRest, rejection, type LndRest, type LndRestOptions } from '../helpers/adapter-interfaces.js';
import { certificatePath, type FakeServer } from '../fakes/https.js';
import { startFakeLnd, type FakeLnd, type LndRoute } from '../fakes/lnd/fake-lnd.js';
import { b64, channel, getInfo, payment } from '../fakes/lnd/responses.js';

const scratch = mkdtempSync(join(tmpdir(), 'fw-lnd-final-'));
const macaroon = randomBytes(64);
const macaroonPath = join(scratch, 'test.macaroon');
writeFileSync(macaroonPath, macaroon);

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

async function fakeLnd(routes: Partial<Record<string, LndRoute>>): Promise<FakeLnd> {
  const fake = await startFakeLnd({ macaroonHex: macaroon.toString('hex'), routes });
  open.push(fake);
  return fake;
}

async function rest(server: { host: string; port: number }, overrides: Partial<LndRestOptions> = {}): Promise<LndRest> {
  const { openLndRest } = await loadLndRest();
  return openLndRest({ host: server.host, port: server.port, tlsCertPath: certificatePath('node'), macaroonPath, timeoutMs: 5000, ...overrides });
}

const TRACK = `/v2/router/track/${encodeURIComponent(b64('11'.repeat(32)).replaceAll('+', '-').replaceAll('/', '_'))}`;
const frame = (value: unknown): string => JSON.stringify(value) + '\n';

it('CP-011/B4 a stream resolves stopped when the handler stops it, ended when the server ends it and aborted when the caller aborts', async () => {
  let end: 'finish' | 'hold' = 'finish';
  const frames = [frame({ result: { n: 1 } }), frame({ result: { n: 2 } })];
  const fake = await fakeLnd({ 'GET /v2/router/track/{payment_hash}': (context, lnd) => { lnd.stream(context, 'trackpayment-stream', frames, end); } });
  const client = await rest(fake);
  // The server finishing the body without a terminal update is not the caller's stop (a later tracker must tell them apart).
  expect(await client.stream('GET', TRACK, undefined, () => 'continue')).toBe('ended');
  expect(await client.stream('GET', TRACK, undefined, message => message['n'] === 1 ? 'stop' : 'continue')).toBe('stopped');
  end = 'hold';
  const controller = new AbortController();
  const seen: unknown[] = [];
  const outcome = client.stream('GET', TRACK, undefined, message => { seen.push(message); if (seen.length === 2) setTimeout(() => { controller.abort(); }, 50); return 'continue'; }, controller.signal);
  expect(await outcome).toBe('aborted');
  expect(seen).toHaveLength(2);
  const { LndReadApi } = await loadLndApi();
  end = 'finish';
  const hash = '11'.repeat(32);
  const tracked = await startFakeLnd({ macaroonHex: macaroon.toString('hex'), routes: { 'GET /v2/router/track/{payment_hash}': (context, lnd) => { lnd.stream(context, 'trackpayment-stream', [frame({ result: payment({ payment_hash: hash }) })], 'finish'); } } });
  open.push(tracked);
  expect(await new LndReadApi(await rest(tracked)).trackPayment(hash, () => 'continue')).toBe('ended');
});

it('CP-011/B2 a macaroon refusal is authentication only as HTTP 500 with gRPC code 2', async () => {
  const errors = await loadErrors();
  const text = 'verification failed: signature mismatch after caveat verification';
  let answer: (context: Parameters<LndRoute>[0], lnd: FakeLnd) => void = () => undefined;
  const fake = await fakeLnd({
    'GET /v1/getinfo': (context, lnd) => { answer(context, lnd); },
    'GET /v2/router/track/{payment_hash}': (context, lnd) => { lnd.stream(context, 'stream-error-frame', [frame({ error: { code: 2, message: text, details: [] } })], 'finish'); },
  });
  const client = await rest(fake);
  answer = (context, lnd) => { lnd.grpcError(context, 'grpc-error', 2, text); };
  expect(await rejection(client.call('GET', '/v1/getinfo'))).toBeInstanceOf(errors.AuthError);
  // The same text with another code, behind a proxy status, or inside a 200 stream is not the macaroon interceptor's answer.
  answer = (context, lnd) => { lnd.raw(context, 'grpc-error', 500, JSON.stringify({ code: 13, message: text, details: [] })); };
  const otherCode = await rejection(client.call('GET', '/v1/getinfo'));
  expect(otherCode).toBeInstanceOf(errors.LndError);
  expect(otherCode).not.toBeInstanceOf(errors.AuthError);
  answer = (context, lnd) => { lnd.raw(context, 'proxy-status', 502, JSON.stringify({ code: 2, message: text, details: [] })); };
  const proxied = await rejection(client.call('GET', '/v1/getinfo'));
  expect(proxied).toBeInstanceOf(errors.LndError);
  expect(proxied).not.toBeInstanceOf(errors.AuthError);
  const framed = await rejection(client.stream('GET', TRACK, undefined, () => 'continue'));
  expect(framed).toBeInstanceOf(errors.LndError);
  expect(framed).not.toBeInstanceOf(errors.AuthError);
});

it('CP-011/B3 timeouts that are not positive integers are refused before any connection', async () => {
  const fake = await fakeLnd({ 'GET /v1/getinfo': (context, lnd) => { lnd.answer(context, 'getinfo', getInfo()); } });
  for (const [key, value] of [['timeoutMs', 0], ['timeoutMs', -1], ['timeoutMs', 1.5], ['timeoutMs', Number.NaN], ['streamConnectTimeoutMs', 0], ['streamDeadlineMs', 0], ['streamDeadlineMs', Number.POSITIVE_INFINITY]] as const) {
    let error: unknown;
    try { await (await rest(fake, { [key]: value })).call('GET', '/v1/getinfo'); } catch (caught) { error = caught; }
    expect(error, `${key}=${String(value)}`).toBeInstanceOf(Error);
  }
  expect(fake.connections()).toBe(0);
});

it('CP-011/B1 a TLS error code after the connect phase is a transport failure in that phase, not a TLS failure', async () => {
  const errors = await loadErrors();
  const tls = { code: 'ERR_TLS_CERT_ALTNAME_INVALID' };
  const atConnect = errors.transportFailure(tls, 'connect');
  expect(atConnect).toBeInstanceOf(errors.TlsError);
  for (const phase of ['request', 'response'] as const) {
    const later = errors.transportFailure(tls, phase);
    expect(later, phase).toBeInstanceOf(errors.TransportError);
    expect(later, phase).not.toBeInstanceOf(errors.TlsError);
    expect(later.phase).toBe(phase);
  }
  const reset = errors.transportFailure({ code: 'ECONNRESET' }, 'connect');
  expect(reset).not.toBeInstanceOf(errors.TlsError);
  expect(reset.phase).toBe('connect');
});

it('CP-011/B7 a repeated payment_index, a null required amount and a chain name other than bitcoin are protocol errors', async () => {
  const errors = await loadErrors();
  let payments: unknown[] = [];
  let channels: unknown[] = [];
  let chains: unknown[] = [];
  const fake = await fakeLnd({
    'GET /v1/payments': (context, lnd) => { lnd.answer(context, 'listpayments', { payments, first_index_offset: '1', last_index_offset: '2', total_num_payments: '0' }); },
    'GET /v1/channels': (context, lnd) => { lnd.answer(context, 'listchannels', { channels }); },
    'GET /v1/getinfo': (context, lnd) => { lnd.answer(context, 'getinfo', { ...getInfo(), chains }); },
  });
  const { LndReadApi } = await loadLndApi();
  const client = new LndReadApi(await rest(fake));
  payments = [payment({ payment_hash: '21'.repeat(32), payment_index: '4' }), payment({ payment_hash: '22'.repeat(32), payment_index: '4' })];
  expect(await rejection(client.listPayments({ indexOffset: 0n, maxPayments: 10, includeIncomplete: true }))).toBeInstanceOf(errors.ProtocolError);
  // EmitUnpopulated writes "0" for a zero int64 and a message for a set field; null is not LND's rendering of a required value.
  for (const [key, value] of [['local_balance', null], ['capacity', null], ['local_constraints', null], ['remote_constraints', null]] as const) {
    channels = [channel({ [key]: value })];
    expect(await rejection(client.listChannels()), key).toBeInstanceOf(errors.ProtocolError);
  }
  // SPEC 4.7 networks are bitcoin networks; the deprecated chain field reads exactly "bitcoin" (rpcserver.go BitcoinChainName).
  for (const name of ['Bitcoin', 'BITCOIN', 'bitcoin ', 'litecoin']) {
    chains = [{ chain: name, network: 'regtest' }];
    expect(await rejection(client.getInfo()), name).toBeInstanceOf(errors.ProtocolError);
  }
});

it('CP-011/B2 the macaroon rule matches LND interceptor texts only at the start and in their exact case', async () => {
  const errors = await loadErrors();
  let message = '';
  const fake = await fakeLnd({ 'GET /v1/getinfo': (context, lnd) => { lnd.grpcError(context, 'grpc-error', 2, message); } });
  const client = await rest(fake);
  // macaroons/service.go and macaroon-bakery produce these texts in lower case at the start of the message.
  for (const text of ['verification failed: signature mismatch after caveat verification', 'permission denied', 'expected 1 macaroon, got 0']) {
    message = text;
    expect(await rejection(client.call('GET', '/v1/getinfo')), text).toBeInstanceOf(errors.AuthError);
  }
  // An application error that merely mentions the words, or a differently cased text, is LND's own refusal.
  for (const text of ['unable to locate invoice: permission denied by peer alias', 'invoice memo: verification failed', 'Permission Denied', 'VERIFICATION FAILED: x']) {
    message = text;
    const error = await rejection(client.call('GET', '/v1/getinfo'));
    expect(error, text).toBeInstanceOf(errors.LndError);
    expect(error, text).not.toBeInstanceOf(errors.AuthError);
  }
});
