import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspect } from 'node:util';
import { afterEach, expect, it } from 'vitest';
import {
  loadErrors, loadLndApi, loadLndRest, rejection, serialise,
  type LndApi, type LndRest, type LndRestOptions,
} from '../helpers/adapter-interfaces.js';
import { certificatePath, closedPort, startResettingListener, type FakeServer, type Identity } from '../fakes/https.js';
import { behaviours, startFakeLnd, type FakeLnd, type LndRoute } from '../fakes/lnd/fake-lnd.js';
import { attempt, b64, channel, forward, getInfo, invoice, LND_PUBKEY, payment, pendingChannel } from '../fakes/lnd/responses.js';
import { behaviours as clnBehaviours } from '../fakes/cln/fake-cln.js';

const MiB = 1024 * 1024;
const scratch = mkdtempSync(join(tmpdir(), 'fw-lnd-'));
// Throwaway credential bytes for local servers. High bytes make the hex case observable.
const macaroon = Buffer.concat([Buffer.from('fe0102abcdef', 'hex'), randomBytes(90)]);
const macaroonHex = macaroon.toString('hex');
const macaroonPath = join(scratch, 'test.macaroon');
writeFileSync(macaroonPath, macaroon);

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

async function fakeLnd(routes: Partial<Record<string, LndRoute>>, identity: Identity = 'node'): Promise<FakeLnd> {
  const fake = await startFakeLnd({ macaroonHex, routes, identity });
  open.push(fake);
  return fake;
}

async function rest(server: { host: string; port: number }, overrides: Partial<LndRestOptions> = {}): Promise<LndRest> {
  const { openLndRest } = await loadLndRest();
  return openLndRest({ host: server.host, port: server.port, tlsCertPath: certificatePath('node'), macaroonPath, timeoutMs: 5000, ...overrides });
}

async function api(server: { host: string; port: number }): Promise<LndApi> {
  const { LndReadApi } = await loadLndApi();
  return new LndReadApi(await rest(server));
}

const pause = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms));

/** Padded URL-safe base64, the only path form LND's gateway decodes for a hash containing '/' (runtime/convert.go). */
function urlSafe(hex: string): string { return b64(hex).replaceAll('+', '-').replaceAll('/', '_'); }

it('CP-011/B1 a certificate from another CA is a TLS failure in phase connect and nothing is sent', async () => {
  const errors = await loadErrors();
  const fake = await fakeLnd({ 'GET /v1/getinfo': (context, lnd) => { lnd.answer(context, 'getinfo', getInfo()); } }, 'other');
  const error = await rejection((await rest(fake)).call('GET', '/v1/getinfo'));
  expect(error).toBeInstanceOf(errors.TlsError);
  expect(error).toBeInstanceOf(errors.TransportError);
  expect((error as InstanceType<typeof errors.TlsError>).phase).toBe('connect');
  expect((error as InstanceType<typeof errors.TlsError>).notDelivered).toBe(true);
  expect(fake.requests).toHaveLength(0);
});

it('CP-011/B1 a certificate for another host name is a TLS failure in phase connect', async () => {
  const errors = await loadErrors();
  const fake = await fakeLnd({ 'GET /v1/getinfo': (context, lnd) => { lnd.answer(context, 'getinfo', getInfo()); } }, 'wrong-host');
  // The pinned file is the server's own certificate; only the name 127.0.0.1 does not match it.
  const error = await rejection((await rest(fake, { tlsCertPath: certificatePath('wrong-host') })).call('GET', '/v1/getinfo'));
  expect(error).toBeInstanceOf(errors.TlsError);
  expect((error as InstanceType<typeof errors.TlsError>).phase).toBe('connect');
  expect(fake.requests).toHaveLength(0);
});

it('CP-011/B2 LND macaroon rejections and a proxy 403 are authentication failures', async () => {
  const errors = await loadErrors();
  let next: 'permission' | 'proxy403' = 'permission';
  const fake = await fakeLnd({
    'GET /v1/getinfo': (context, lnd) => {
      if (next === 'permission') lnd.grpcError(context, 'macaroon-permission-denied', 2, 'permission denied');
      else lnd.raw(context, 'proxy-status', 403, '<html><body>Forbidden</body></html>');
    },
  });
  // LND rejects a macaroon with a plain error, which its gateway sends as HTTP 500 with gRPC 2.
  const permission = await rejection((await rest(fake)).call('GET', '/v1/getinfo'));
  expect(permission).toBeInstanceOf(errors.AuthError);
  expect((permission as InstanceType<typeof errors.AuthError>).httpStatus).toBe(500);
  writeFileSync(join(scratch, 'other.macaroon'), randomBytes(64));
  const mismatch = await rejection((await rest(fake, { macaroonPath: join(scratch, 'other.macaroon') })).call('GET', '/v1/getinfo'));
  expect(mismatch).toBeInstanceOf(errors.AuthError);
  expect((mismatch as InstanceType<typeof errors.AuthError>).httpStatus).toBe(500);
  next = 'proxy403';
  const forbidden = await rejection((await rest(fake)).call('GET', '/v1/getinfo'));
  expect(forbidden).toBeInstanceOf(errors.AuthError);
  expect((forbidden as InstanceType<typeof errors.AuthError>).httpStatus).toBe(403);
  expect(fake.served.map(item => item.behaviour)).toEqual(['macaroon-permission-denied', 'macaroon-mismatch', 'proxy-status']);
});

it('CP-011/B2 a 500 error body becomes an LND error with its gRPC code and message', async () => {
  const errors = await loadErrors();
  const fake = await fakeLnd({ 'GET /v1/getinfo': (context, lnd) => { lnd.grpcError(context, 'grpc-error', 2, 'invoice with payment hash already exists'); } });
  const error = await rejection((await rest(fake)).call('GET', '/v1/getinfo'));
  expect(error).toBeInstanceOf(errors.LndError);
  const lnd = error as InstanceType<typeof errors.LndError>;
  expect(lnd.grpcCode).toBe(2);
  expect(lnd.httpStatus).toBe(500);
  expect(lnd.message).toContain('invoice with payment hash already exists');
  expect(errors.definiteRefusal(lnd)).toBe(true);
});

it('CP-011/B2 502 and 504 relaying an LND body stay ambiguous', async () => {
  const errors = await loadErrors();
  let status = 502;
  // The relayed body claims HTTP 500, which on its own would read as a definite refusal.
  const relayed = JSON.stringify({ code: 2, message: 'invoice with payment hash already exists', details: [], http_code: 500 });
  const fake = await fakeLnd({ 'GET /v1/getinfo': (context, lnd) => { lnd.raw(context, 'proxy-status', status, relayed); } });
  const client = await rest(fake);
  for (const expected of [502, 504]) {
    status = expected;
    const error = await rejection(client.call('GET', '/v1/getinfo'));
    expect(error, String(expected)).toBeInstanceOf(errors.LndError);
    expect((error as InstanceType<typeof errors.LndError>).httpStatus).toBe(expected);
    expect(errors.definiteRefusal(error), String(expected)).toBe(false);
    expect(error).not.toBeInstanceOf(errors.AuthError);
  }
});

it('CP-011/B3 a call without an answer times out as a delivered transport failure after exactly one request', async () => {
  const errors = await loadErrors();
  const fake = await fakeLnd({ 'GET /v1/getinfo': (context, lnd) => { lnd.hold(context, 'no-answer'); } });
  const started = performance.now();
  const error = await rejection((await rest(fake, { timeoutMs: 300 })).call('GET', '/v1/getinfo'));
  expect(performance.now() - started).toBeLessThan(5000);
  expect(error).toBeInstanceOf(errors.TransportError);
  expect(error).not.toBeInstanceOf(errors.TlsError);
  // The request was written before the wait began, so the failure is in phase response.
  expect((error as InstanceType<typeof errors.TransportError>).phase).toBe('response');
  expect((error as InstanceType<typeof errors.TransportError>).notDelivered).toBe(false);
  await pause(600);
  expect(fake.requests).toHaveLength(1);
  expect(fake.connections()).toBe(1);
});

it('CP-011/B3 a refused or reset connection is an undelivered transport failure without retry', async () => {
  const errors = await loadErrors();
  const refused = await rejection((await rest({ host: '127.0.0.1', port: await closedPort() })).call('GET', '/v1/getinfo'));
  expect(refused).toBeInstanceOf(errors.TransportError);
  expect(refused).not.toBeInstanceOf(errors.TlsError);
  expect((refused as InstanceType<typeof errors.TransportError>).phase).toBe('connect');
  expect((refused as InstanceType<typeof errors.TransportError>).notDelivered).toBe(true);
  const listener = await startResettingListener();
  open.push(listener);
  const reset = await rejection((await rest(listener)).call('GET', '/v1/getinfo'));
  expect(reset).toBeInstanceOf(errors.TransportError);
  expect((reset as InstanceType<typeof errors.TransportError>).phase).toBe('connect');
  await pause(400);
  expect(listener.connections()).toBe(1);
});

const TRACK = `/v2/router/track/${encodeURIComponent(urlSafe('11'.repeat(32)))}`;

it('CP-011/B4 result frames split across chunks reach the handler in order and an error frame is an LND error', async () => {
  const errors = await loadErrors();
  const text = [
    JSON.stringify({ result: { n: 1, text: 'é€' } }), JSON.stringify({ result: { n: 2, text: 'ü' } }),
    JSON.stringify({ error: { code: 5, message: "payment isn't initiated", details: [] } }),
  ].join('\n') + '\n';
  const bytes = Buffer.from(text, 'utf8');
  // Three-byte chunks cut lines and multi-byte characters apart.
  const chunks: Buffer[] = [];
  for (let offset = 0; offset < bytes.length; offset += 3) chunks.push(bytes.subarray(offset, offset + 3));
  const fake = await fakeLnd({ 'GET /v2/router/track/{payment_hash}': (context, lnd) => { lnd.stream(context, 'stream-error-frame', chunks, 'finish'); } });
  const seen: Record<string, unknown>[] = [];
  const error = await rejection((await rest(fake)).stream('GET', TRACK, undefined, message => { seen.push(message); return 'continue'; }));
  expect(seen).toEqual([{ n: 1, text: 'é€' }, { n: 2, text: 'ü' }]);
  expect(error).toBeInstanceOf(errors.LndError);
  const lnd = error as InstanceType<typeof errors.LndError>;
  expect(lnd.grpcCode).toBe(5);
  expect(lnd.notFound).toBe(true);
  expect(lnd.httpStatus).toBeUndefined();
});

it('CP-011/B4 a stream error before any frame arrives as one non-200 error body', async () => {
  const errors = await loadErrors();
  const body = JSON.stringify({ error: { code: 5, message: "payment isn't initiated", details: [] } });
  const fake = await fakeLnd({ 'GET /v2/router/track/{payment_hash}': (context, lnd) => { lnd.raw(context, 'trackpayment-not-initiated', 404, body); } });
  let calls = 0;
  const error = await rejection((await rest(fake)).stream('GET', TRACK, undefined, () => { calls += 1; return 'continue'; }));
  expect(calls).toBe(0);
  expect(error).toBeInstanceOf(errors.LndError);
  expect((error as InstanceType<typeof errors.LndError>).grpcCode).toBe(5);
  expect((error as InstanceType<typeof errors.LndError>).httpStatus).toBe(404);
});

function paddedLine(size: number): Buffer {
  const head = '{"result":{"pad":true}', tail = '}';
  return Buffer.from(head + ' '.repeat(size - head.length - tail.length) + tail, 'utf8');
}

function slices(buffer: Buffer, size: number): Buffer[] {
  const parts: Buffer[] = [];
  for (let offset = 0; offset < buffer.length; offset += size) parts.push(buffer.subarray(offset, offset + size));
  return parts;
}

it('CP-011/B4 a stream line of exactly 16 MiB is read and one byte more is a protocol error', async () => {
  const errors = await loadErrors();
  let size = 16 * MiB;
  const fake = await fakeLnd({
    'GET /v2/router/track/{payment_hash}': (context, lnd) => {
      lnd.stream(context, 'oversized-body', [...slices(paddedLine(size), MiB), '\n'], 'finish');
    },
  });
  const client = await rest(fake);
  const seen: unknown[] = [];
  await client.stream('GET', TRACK, undefined, message => { seen.push(message); return 'continue'; });
  expect(seen).toEqual([{ pad: true }]);
  size = 16 * MiB + 1;
  const error = await rejection(client.stream('GET', TRACK, undefined, message => { seen.push(message); return 'continue'; }));
  expect(error).toBeInstanceOf(errors.ProtocolError);
  expect(seen).toHaveLength(1);
}, 60_000);

it('CP-011/B4 a unary body of exactly 16 MiB is read and one byte more is a protocol error', async () => {
  const errors = await loadErrors();
  let size = 16 * MiB;
  const body = (): string => { const head = '{"alias":"big"', tail = '}'; return head + ' '.repeat(size - head.length - tail.length) + tail; };
  const fake = await fakeLnd({ 'GET /v1/getinfo': (context, lnd) => { lnd.raw(context, 'oversized-body', 200, body()); } });
  const client = await rest(fake);
  expect(await client.call('GET', '/v1/getinfo')).toEqual({ alias: 'big' });
  size = 16 * MiB + 1;
  expect(await rejection(client.call('GET', '/v1/getinfo'))).toBeInstanceOf(errors.ProtocolError);
}, 60_000);

it('CP-011/B4 a stream cut before the server ends it is a transport failure in phase response', async () => {
  const errors = await loadErrors();
  const frame = JSON.stringify({ result: { n: 1 } }) + '\n';
  const fake = await fakeLnd({ 'GET /v2/router/track/{payment_hash}': (context, lnd) => { lnd.stream(context, 'stream-cut', [frame], 'cut'); } });
  const seen: unknown[] = [];
  const error = await rejection((await rest(fake)).stream('GET', TRACK, undefined, message => { seen.push(message); return 'continue'; }));
  expect(seen).toEqual([{ n: 1 }]);
  expect(error).toBeInstanceOf(errors.TransportError);
  expect((error as InstanceType<typeof errors.TransportError>).notDelivered).toBe(false);
  expect((error as InstanceType<typeof errors.TransportError>).phase).toBe('response');
});

it('CP-011/B5 the macaroon travels as lowercase hex in Grpc-Metadata-macaroon', async () => {
  const fake = await fakeLnd({ 'GET /v1/getinfo': (context, lnd) => { lnd.answer(context, 'getinfo', getInfo()); } });
  expect(await (await rest(fake)).call('GET', '/v1/getinfo')).toMatchObject({ identity_pubkey: LND_PUBKEY });
  expect(fake.requests).toHaveLength(1);
  expect(fake.requests[0]?.headers['grpc-metadata-macaroon']).toBe(macaroonHex);
});

it('CP-011/B5 a macaroon or certificate file over 64 KiB is refused before any connection and 64 KiB is accepted', async () => {
  const errors = await loadErrors();
  const tryCall = async (overrides: Partial<LndRestOptions>, fake: FakeLnd): Promise<unknown> => {
    try { return await (await rest(fake, overrides)).call('GET', '/v1/getinfo'); } catch (error) { return error; }
  };
  const largeMacaroon = randomBytes(65536);
  const accepting = await startFakeLnd({ macaroonHex: largeMacaroon.toString('hex'), routes: { 'GET /v1/getinfo': (context, lnd) => { lnd.answer(context, 'getinfo', getInfo()); } } });
  open.push(accepting);
  writeFileSync(join(scratch, 'max.macaroon'), largeMacaroon);
  expect(await tryCall({ macaroonPath: join(scratch, 'max.macaroon') }, accepting)).toMatchObject({ alias: 'lnd-r' });
  const before = accepting.connections();
  writeFileSync(join(scratch, 'over.macaroon'), randomBytes(65537));
  writeFileSync(join(scratch, 'empty.macaroon'), Buffer.alloc(0));
  for (const name of ['over.macaroon', 'empty.macaroon']) {
    const error = await tryCall({ macaroonPath: join(scratch, name) }, accepting);
    expect(error, name).toBeInstanceOf(Error);
    expect(error, name).not.toBeInstanceOf(errors.TransportError);
    expect(error, name).not.toBeInstanceOf(errors.LndError);
  }
  expect(accepting.connections()).toBe(before);
  // Text before the PEM block is ignored by the TLS stack, so padding changes only the size.
  const pem = readFileSync(certificatePath('node'));
  const padded = (size: number): Buffer => Buffer.concat([Buffer.from('#'.repeat(size - pem.length - 1) + '\n'), pem]);
  writeFileSync(join(scratch, 'max.pem'), padded(65536));
  writeFileSync(join(scratch, 'over.pem'), padded(65537));
  const fake = await fakeLnd({ 'GET /v1/getinfo': (context, lnd) => { lnd.answer(context, 'getinfo', getInfo()); } });
  expect(await tryCall({ tlsCertPath: join(scratch, 'max.pem') }, fake)).toMatchObject({ alias: 'lnd-r' });
  const connections = fake.connections();
  const error = await tryCall({ tlsCertPath: join(scratch, 'over.pem') }, fake);
  expect(error).toBeInstanceOf(Error);
  expect(error).not.toBeInstanceOf(errors.TransportError);
  expect(fake.connections()).toBe(connections);
});

it('CP-011/B5 certificate verification stays on with NODE_TLS_REJECT_UNAUTHORIZED=0', async () => {
  const errors = await loadErrors();
  const fake = await fakeLnd({ 'GET /v1/getinfo': (context, lnd) => { lnd.answer(context, 'getinfo', getInfo()); } }, 'other');
  const previous = process.env['NODE_TLS_REJECT_UNAUTHORIZED'];
  process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';
  try {
    const error = await rejection((await rest(fake)).call('GET', '/v1/getinfo'));
    expect(error).toBeInstanceOf(errors.TlsError);
    expect(fake.requests).toHaveLength(0);
  } finally {
    if (previous === undefined) delete process.env['NODE_TLS_REJECT_UNAUTHORIZED'];
    else process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = previous;
  }
});

it('CP-011/B6 TrackPaymentV2 carries the hash as padded URL-safe base64 and LookupInvoice as hex', async () => {
  // Standard base64 of this hash contains both '+' and '/'; a '/' splits the path and the
  // gateway answers 404 with gRPC 5, which would read as "payment not found" (lnd#7821).
  const hash = Buffer.from('fbffbf'.repeat(10) + 'fbff', 'hex').toString('hex');
  expect(b64(hash)).toMatch(/\+/);
  expect(b64(hash)).toMatch(/\//);
  const fake = await fakeLnd({
    'GET /v2/router/track/{payment_hash}': (context, lnd) => {
      const update = payment({ payment_hash: context.params['payment_hash'], status: 'IN_FLIGHT' });
      lnd.stream(context, 'trackpayment-stream', [JSON.stringify({ result: update }) + '\n'], 'finish');
    },
    'GET /v1/invoice/{r_hash_str}': (context, lnd) => {
      lnd.answer(context, 'lookupinvoice', invoice({ r_hash: b64(context.params['r_hash_str'] ?? '') }));
    },
  });
  const client = await api(fake);
  const updates: string[] = [];
  await client.trackPayment(hash, update => { updates.push(update.paymentHash); return 'continue'; });
  expect(updates).toEqual([hash]);
  const trackUrl = fake.requests[0]?.url ?? '';
  const segment = new URL(trackUrl, 'https://x.invalid').pathname.split('/')[4] ?? '';
  expect(decodeURIComponent(segment)).toBe(urlSafe(hash));
  expect((await client.lookupInvoice(hash)).rHash).toBe(hash);
  expect(new URL(fake.requests[1]?.url ?? '', 'https://x.invalid').pathname).toBe(`/v1/invoice/${hash}`);
  expect(fake.served.map(item => item.behaviour)).toEqual(['trackpayment-stream', 'lookupinvoice']);
});

it('CP-011/B7 GetInfo maps identity network version height and sync', async () => {
  const fake = await fakeLnd({ 'GET /v1/getinfo': (context, lnd) => { lnd.answer(context, 'getinfo', getInfo({ synced: false })); } });
  // chains[].chain is the deprecated "bitcoin"; the network is chains[].network.
  expect(await (await api(fake)).getInfo()).toMatchObject({
    identityPubkey: LND_PUBKEY, alias: 'lnd-r', version: '0.21.4-beta commit=v0.21.4-beta', commitHash: 'f'.repeat(40),
    network: 'regtest', blockHeight: 812, blockHash: '0f'.repeat(32), syncedToChain: false, syncedToGraph: true,
  });
});

it('CP-011/B7 ListChannels maps satoshi balances local_constraints and pending HTLCs with uint64 as bigint', async () => {
  const errors = await loadErrors();
  const hashLock = '22'.repeat(32);
  const second = channel({
    chan_id: '18446744073709551615', capacity: '9223372036854775807', active: false, initiator: false, private: true,
    local_chan_reserve_sat: '0', remote_chan_reserve_sat: '0',
    local_constraints: { csv_delay: 144, chan_reserve_sat: '20000', dust_limit_sat: '354', max_pending_amt_msat: '18446744073709551615', min_htlc_msat: '1000', max_accepted_htlcs: 30 },
    remote_constraints: { csv_delay: 720, chan_reserve_sat: '30000', dust_limit_sat: '573', max_pending_amt_msat: '990000000', min_htlc_msat: '1', max_accepted_htlcs: 483 },
    pending_htlcs: [{ incoming: false, amount: '100101', hash_lock: b64(hashLock), expiration_height: 950, htlc_index: '3', forwarding_channel: '0', forwarding_htlc_index: '0', locked_in: true }],
  });
  let body = JSON.stringify({ channels: [channel(), second] });
  const fake = await fakeLnd({ 'GET /v1/channels': (context, lnd) => { lnd.raw(context, 'listchannels', 200, body); } });
  const client = await api(fake);
  const channels = await client.listChannels();
  expect(channels).toHaveLength(2);
  expect(channels[0]).toMatchObject({
    active: true, remotePubkey: '03' + 'b2'.repeat(32), channelPoint: `${'ab'.repeat(32)}:1`, chanId: '892945371103232001',
    capacitySat: 5000000n, localBalanceSat: 3746530n, remoteBalanceSat: 1250000n, commitFeeSat: 2810n, commitWeight: 1116n,
    feePerKw: 2500n, unsettledBalanceSat: 0n, initiator: true, private: false, pendingHtlcs: [],
  });
  expect(channels[1]).toMatchObject({
    chanId: '18446744073709551615', capacitySat: 9223372036854775807n, active: false, initiator: false, private: true,
    localConstraints: { csvDelay: 144, chanReserveSat: 20000n, dustLimitSat: 354n, maxPendingAmtMsat: 18446744073709551615n, minHtlcMsat: 1000n, maxAcceptedHtlcs: 30 },
    remoteConstraints: { csvDelay: 720, chanReserveSat: 30000n, dustLimitSat: 573n, maxPendingAmtMsat: 990000000n, minHtlcMsat: 1n, maxAcceptedHtlcs: 483 },
    pendingHtlcs: [{ incoming: false, amountSat: 100101n, hashLock, expirationHeight: 950, htlcIndex: '3', forwardingChannel: '0', forwardingHtlcIndex: '0', lockedIn: true }],
  });
  // An int64 written as a JSON number beyond 2^53 has already lost its value in the parser.
  body = JSON.stringify({ channels: [channel()] }).replace('"capacity":"5000000"', '"capacity":9007199254740993');
  expect(await rejection(client.listChannels())).toBeInstanceOf(errors.ProtocolError);
  body = JSON.stringify({ channels: [channel({ local_balance: true })] });
  expect(await rejection(client.listChannels())).toBeInstanceOf(errors.ProtocolError);
});

it('CP-011/B7 PendingChannels maps pending open waiting close and force closing channels', async () => {
  const response = {
    total_limbo_balance: '150000',
    pending_open_channels: [{ channel: pendingChannel(), commit_fee: '2810', commit_weight: '1116', fee_per_kw: '2500', funding_expiry_blocks: 2010, confirmations_until_active: 3, confirmation_height: 0 }],
    pending_closing_channels: [],
    pending_force_closing_channels: [{
      channel: pendingChannel({ channel_point: `${'ef'.repeat(32)}:1`, initiator: 2 }), closing_txid: '34'.repeat(32), limbo_balance: '150000',
      maturity_height: 1100, blocks_til_maturity: 144, recovered_balance: '0', pending_htlcs: [], anchor: 'LIMBO',
    }],
    waiting_close_channels: [{
      channel: pendingChannel({ channel_point: `${'12'.repeat(32)}:0`, initiator: 'INITIATOR_REMOTE' }), limbo_balance: '0',
      commitments: { local_txid: '', remote_txid: '', remote_pending_txid: '', local_commit_fee_sat: '0', remote_commit_fee_sat: '0', remote_pending_commit_fee_sat: '0' },
      closing_txid: '56'.repeat(32), closing_tx_hex: '', blocks_til_close_confirmed: 0, close_height: 0,
    }],
  };
  const fake = await fakeLnd({ 'GET /v1/channels/pending': (context, lnd) => { lnd.answer(context, 'pendingchannels', response); } });
  const pending = await (await api(fake)).pendingChannels();
  expect(pending.totalLimboBalanceSat).toBe(150000n);
  expect(pending.pendingOpenChannels).toHaveLength(1);
  expect(pending.pendingOpenChannels[0]).toMatchObject({
    channel: { remoteNodePub: '02' + 'c3'.repeat(32), channelPoint: `${'cd'.repeat(32)}:0`, capacitySat: 2000000n, localBalanceSat: 1996530n, remoteBalanceSat: 0n, localChanReserveSat: 20000n, remoteChanReserveSat: 20000n, initiator: 'INITIATOR_LOCAL' },
    commitFeeSat: 2810n, commitWeight: 1116n, feePerKw: 2500n, confirmationsUntilActive: 3,
  });
  expect(pending.pendingForceClosingChannels).toHaveLength(1);
  // Enums arrive by name or by number (protojson accepts both); 2 is INITIATOR_REMOTE.
  expect(pending.pendingForceClosingChannels[0]).toMatchObject({
    channel: { channelPoint: `${'ef'.repeat(32)}:1`, initiator: 'INITIATOR_REMOTE' }, closingTxid: '34'.repeat(32), limboBalanceSat: 150000n, maturityHeight: 1100, blocksTilMaturity: 144,
  });
  expect(pending.waitingCloseChannels).toHaveLength(1);
  expect(pending.waitingCloseChannels[0]).toMatchObject({ channel: { channelPoint: `${'12'.repeat(32)}:0`, initiator: 'INITIATOR_REMOTE' }, limboBalanceSat: 0n, closingTxid: '56'.repeat(32) });
});

it('CP-011/B7 ListPayments sends the pagination parameters and maps payments without exposing preimages', async () => {
  const preimage = randomBytes(32).toString('hex');
  const hash = createHash('sha256').update(Buffer.from(preimage, 'hex')).digest('hex');
  const queries: URLSearchParams[] = [];
  const fake = await fakeLnd({
    'GET /v1/payments': (context, lnd) => {
      queries.push(context.query);
      lnd.answer(context, 'listpayments', {
        payments: [
          payment({ payment_hash: hash, payment_preimage: preimage, status: 'SUCCEEDED', fee_sat: '101', fee_msat: '101123', payment_index: '8', htlcs: [attempt('SUCCEEDED', '5')] }),
          payment({ payment_hash: '33'.repeat(32), status: 'FAILED', failure_reason: 'FAILURE_REASON_NO_ROUTE', payment_index: '9', htlcs: [attempt('FAILED', '6'), attempt('IN_FLIGHT', '7')] }),
          payment({ payment_hash: '44'.repeat(32), payment_preimage: '55'.repeat(32), status: 4, payment_index: '10' }),
        ],
        first_index_offset: '8', last_index_offset: '10', total_num_payments: '0',
      });
    },
  });
  const client = await api(fake);
  const page = await client.listPayments({ indexOffset: 7n, maxPayments: 3, includeIncomplete: true });
  expect(queries[0]?.get('include_incomplete')).toBe('true');
  expect(queries[0]?.get('index_offset')).toBe('7');
  expect(queries[0]?.get('max_payments')).toBe('3');
  expect(page.firstIndexOffset).toBe(8n);
  expect(page.lastIndexOffset).toBe(10n);
  expect(page.payments).toHaveLength(3);
  expect(page.payments[0]).toMatchObject({
    paymentHash: hash, valueMsat: 100000000n, feeMsat: 101123n, status: 'SUCCEEDED', failureReason: 'FAILURE_REASON_NONE',
    creationTimeNs: 1760000000123456789n, paymentIndex: 8n, preimageMatchesHash: true, htlcs: [{ attemptId: '5', status: 'SUCCEEDED' }],
  });
  expect(page.payments[1]).toMatchObject({ status: 'FAILED', failureReason: 'FAILURE_REASON_NO_ROUTE', preimageMatchesHash: false, htlcs: [{ attemptId: '6', status: 'FAILED' }, { attemptId: '7', status: 'IN_FLIGHT' }] });
  // A preimage that does not hash to the payment hash proves nothing.
  expect(page.payments[2]).toMatchObject({ status: 'INITIATED', preimageMatchesHash: false, paymentIndex: 10n });
  const text = serialise(page) + inspect(page, { depth: 10 });
  expect(text).not.toContain(preimage);
  expect(text).not.toContain(b64(preimage));
  await client.listPayments({ indexOffset: 0n, maxPayments: 1, includeIncomplete: false });
  expect(queries[1]?.get('include_incomplete')).not.toBe('true');
});

it('CP-011/B7 ForwardingHistory posts the time window and offset and maps msat amounts', async () => {
  const bodies: Record<string, unknown>[] = [];
  const fake = await fakeLnd({
    'POST /v1/switch': (context, lnd) => {
      bodies.push(JSON.parse(context.request.body) as Record<string, unknown>);
      lnd.answer(context, 'forwardinghistory', { forwarding_events: [forward()], last_offset_index: 6 });
    },
  });
  const page = await (await api(fake)).forwardingHistory({ startTime: 1760000000n, endTime: 1760086400n, indexOffset: 5, numMaxEvents: 50 });
  // uint64 fields may be sent as JSON strings or numbers; uint32 fields are numbers (protojson).
  expect(String(bodies[0]?.['start_time'])).toBe('1760000000');
  expect(String(bodies[0]?.['end_time'])).toBe('1760086400');
  expect(bodies[0]?.['index_offset']).toBe(5);
  expect(bodies[0]?.['num_max_events']).toBe(50);
  expect(page.lastOffsetIndex).toBe(6);
  expect(page.events).toEqual([{
    timestampNs: 1760000100123456789n, chanIdIn: '892945371103232001', chanIdOut: '892946470614859777',
    amtInMsat: 100101000n, amtOutMsat: 100000000n, feeMsat: 101000n,
  }]);
});

it('CP-011/B7 LookupInvoice maps state and amounts never the preimage and NotFound keeps gRPC code 5', async () => {
  const errors = await loadErrors();
  const preimage = randomBytes(32).toString('hex');
  const hash = createHash('sha256').update(Buffer.from(preimage, 'hex')).digest('hex');
  const fake = await fakeLnd({
    'GET /v1/invoice/{r_hash_str}': (context, lnd) => {
      if (context.params['r_hash_str'] !== hash) { lnd.grpcError(context, 'lookupinvoice-not-found', 5, 'unable to locate invoice'); return; }
      // invoices:read callers receive r_preimage (lnd#11196).
      lnd.answer(context, 'lookupinvoice', invoice({
        r_hash: b64(hash), r_preimage: b64(preimage), state: 'SETTLED', settled: true, amt_paid: '100000', amt_paid_sat: '100000',
        amt_paid_msat: '100000000', settle_date: '1760000200', settle_index: '3',
      }));
    },
  });
  const client = await api(fake);
  const found = await client.lookupInvoice(hash);
  expect(found).toMatchObject({
    rHash: hash, memo: 'fluxwarden exec', valueMsat: 100000000n, amtPaidMsat: 100000000n, state: 'SETTLED',
    creationDate: 1760000000n, settleDate: 1760000200n, expiry: 3600n, cltvExpiry: 80n, addIndex: 7n, settleIndex: 3n,
    paymentRequest: 'lnbcrt1m1pfixture',
  });
  const text = serialise(found) + inspect(found, { depth: 10 });
  for (const form of [preimage, b64(preimage), Buffer.from(preimage, 'hex').toString('base64url')]) expect(text).not.toContain(form);
  const missing = await rejection(client.lookupInvoice('66'.repeat(32)));
  expect(missing).toBeInstanceOf(errors.LndError);
  expect((missing as InstanceType<typeof errors.LndError>).notFound).toBe(true);
  expect((missing as InstanceType<typeof errors.LndError>).httpStatus).toBe(404);
});

const CITATION = /^(?:https:\/\/github\.com\/(?:lightningnetwork\/lnd\/blob\/v0\.21\.4-beta|grpc-ecosystem\/grpc-gateway\/blob\/v2\.16\.0|grpc-ecosystem\/grpc-gateway\/blob\/v1\.16\.0|go-macaroon-bakery\/macaroon-bakery\/blob\/v2\.0\.1|ElementsProject\/lightning\/blob\/v26\.06\.9)\/[\w./-]+#L\d+(?:-L\d+)?|https:\/\/github\.com\/(?:lightningnetwork\/lnd|alexbosworth\/lightning|ElementsProject\/lightning)\/issues\/\d+|https:\/\/www\.rfc-editor\.org\/rfc\/rfc\d+#section-[\d.]+)(?: \(.+\))?$/;

it('CP-011/B8 every fake LND behaviour cites a pinned upstream source and every served answer is attributed', async () => {
  for (const [id, behaviour] of Object.entries(behaviours)) {
    for (const part of behaviour.source.split('; ')) expect(part, id).toMatch(CITATION);
  }
  const fake = await fakeLnd({ 'GET /v1/getinfo': (context, lnd) => { lnd.answer(context, 'getinfo', getInfo()); } });
  const client = await rest(fake);
  await client.call('GET', '/v1/getinfo');
  await rejection(client.call('GET', '/v1/not-a-route'));
  await rejection(client.call('POST', '/v1/getinfo', {}));
  await rejection(client.call('GET', `/v2/router/track/${'A'.repeat(43)}`));
  const unregistered = await rejection(client.call('GET', '/v1/channels'));
  expect(unregistered).toBeDefined();
  expect(fake.served.map(item => item.behaviour)).toEqual(['getinfo', 'route-not-found', 'method-not-allowed', 'track-hash-type-mismatch', 'route-not-found']);
  expect(fake.served).toHaveLength(fake.requests.length);
});

it('CP-011/B8 every fake CLN behaviour cites a pinned upstream source', () => {
  for (const [id, behaviour] of Object.entries(clnBehaviours)) {
    for (const part of behaviour.source.split('; ')) expect(part, id).toMatch(CITATION);
  }
});

it('CP-011/B9 errors carry no macaroon in any encoding', async () => {
  // A hostile or echoing peer puts the credential into the error text it returns.
  const echo = `bad macaroon ${macaroonHex} ${macaroonHex.toUpperCase()} ${macaroon.toString('base64')} ${macaroon.toString('base64url')}`;
  const fake = await fakeLnd({
    'GET /v1/getinfo': (context, lnd) => { lnd.grpcError(context, 'grpc-error', 2, echo); },
    'GET /v2/router/track/{payment_hash}': (context, lnd) => {
      lnd.stream(context, 'stream-error-frame', [JSON.stringify({ error: { code: 2, message: echo, details: [] } }) + '\n'], 'finish');
    },
  });
  const tlsFake = await fakeLnd({}, 'other');
  const client = await rest(fake);
  const failures = [
    await rejection(client.call('GET', '/v1/getinfo')),
    await rejection(client.stream('GET', TRACK, undefined, () => 'continue')),
    await rejection((await rest(tlsFake)).call('GET', '/v1/getinfo')),
    await rejection((await rest({ host: '127.0.0.1', port: await closedPort() })).call('GET', '/v1/getinfo')),
  ];
  for (const [index, failure] of failures.entries()) {
    expect(failure, String(index)).toBeInstanceOf(Error);
    const error = failure as Error;
    const text = [error.message, String(error), error.stack ?? '', inspect(error, { depth: 10, showHidden: true }), serialise(error)].join('\n');
    for (const form of [macaroonHex, macaroonHex.toUpperCase(), macaroon.toString('base64'), macaroon.toString('base64url')]) {
      expect(text.includes(form), `failure ${String(index)} leaks a credential form`).toBe(false);
    }
  }
});
