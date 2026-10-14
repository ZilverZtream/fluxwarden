import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { loadErrors, loadLndApi, loadLndRest, rejection, type LndApi, type LndRest, type LndRestOptions } from '../helpers/adapter-interfaces.js';
import { certificatePath, startSilentListener, type FakeServer } from '../fakes/https.js';
import { startFakeLnd, type FakeLnd, type LndRoute } from '../fakes/lnd/fake-lnd.js';
import { b64, channel, getInfo, invoice, payment, pendingChannel } from '../fakes/lnd/responses.js';

const scratch = mkdtempSync(join(tmpdir(), 'fw-lnd-hostile-'));
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

async function api(server: { host: string; port: number }): Promise<LndApi> {
  const { LndReadApi } = await loadLndApi();
  return new LndReadApi(await rest(server));
}

const sha256 = (hex: string): string => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
const TRACK = `/v2/router/track/${encodeURIComponent(b64('11'.repeat(32)).replaceAll('+', '-').replaceAll('/', '_'))}`;
const frame = (value: unknown): string => JSON.stringify(value) + '\n';

it('CP-011/B1 only certificate verification failures are TLS failures and a handshake timeout is not', async () => {
  const { isTlsFailureCode } = await loadErrors();
  // Node's verification codes (tls.TLSSocket authorizationError / checkServerIdentity).
  for (const code of ['DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_HAS_EXPIRED']) {
    expect(isTlsFailureCode(code), code).toBe(true);
  }
  for (const code of ['ERR_TLS_HANDSHAKE_TIMEOUT', 'ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', undefined, 5]) {
    expect(isTlsFailureCode(code), String(code)).toBe(false);
  }
});

it('CP-011/B2 only HTTP 200 is a result and a 202 with a JSON body is an error', async () => {
  const errors = await loadErrors();
  const fake = await fakeLnd({ 'GET /v1/getinfo': (context, lnd) => { lnd.raw(context, 'proxy-status', 202, JSON.stringify(getInfo())); } });
  const error = await rejection((await rest(fake)).call('GET', '/v1/getinfo'));
  expect(error).toBeInstanceOf(errors.LndError);
  expect((error as InstanceType<typeof errors.LndError>).httpStatus).toBe(202);
});

it('CP-011/B3 a stream whose TLS session never starts fails in phase connect within the stream connect timeout', async () => {
  const errors = await loadErrors();
  const listener = await startSilentListener();
  open.push(listener);
  const started = performance.now();
  const error = await rejection((await rest(listener, { streamConnectTimeoutMs: 300, timeoutMs: 20_000 })).stream('GET', TRACK, undefined, () => 'continue'));
  expect(performance.now() - started).toBeLessThan(5000);
  expect(error).toBeInstanceOf(errors.TransportError);
  expect(error).not.toBeInstanceOf(errors.TlsError);
  expect((error as InstanceType<typeof errors.TransportError>).phase).toBe('connect');
  expect(listener.connections()).toBe(1);
});

it('CP-011/B4 a connected stream outlives the connect timeout and a stalled stream ends at its deadline in phase response', async () => {
  const errors = await loadErrors();
  let mode: 'slow' | 'stall' = 'slow';
  const frames = Array.from({ length: 8 }, (_unused, index) => frame({ result: { n: index } }));
  const fake = await fakeLnd({
    'GET /v2/router/track/{payment_hash}': (context, lnd) => {
      if (mode === 'slow') lnd.stream(context, 'trackpayment-stream', frames, 'finish', 100);
      else lnd.stream(context, 'stream-stall', [frame({ result: { n: 0 } })], 'hold');
    },
  });
  // Eight frames 100 ms apart run well past a 200 ms connect timeout; only the connect phase is bounded by it.
  const slow = await rest(fake, { streamConnectTimeoutMs: 200, streamDeadlineMs: 10_000 });
  const seen: unknown[] = [];
  await slow.stream('GET', TRACK, undefined, message => { seen.push(message); return 'continue'; });
  expect(seen).toHaveLength(8);
  mode = 'stall';
  // A gateway that keeps the connection open but forwards nothing (alexbosworth/lightning#133).
  const stalled = await rest(fake, { streamDeadlineMs: 400 });
  const stalledSeen: unknown[] = [];
  const started = performance.now();
  const error = await rejection(stalled.stream('GET', TRACK, undefined, message => { stalledSeen.push(message); return 'continue'; }));
  const elapsed = performance.now() - started;
  expect(elapsed).toBeGreaterThanOrEqual(350);
  expect(elapsed).toBeLessThan(5000);
  expect(stalledSeen).toEqual([{ n: 0 }]);
  expect(error).toBeInstanceOf(errors.TransportError);
  expect((error as InstanceType<typeof errors.TransportError>).phase).toBe('response');
}, 20_000);

it('CP-011/B4 legacy grpc_code frames and in-stream code-message frames are LND errors and blank lines are skipped', async () => {
  const errors = await loadErrors();
  let body: string[] = [];
  const fake = await fakeLnd({ 'GET /v2/router/track/{payment_hash}': (context, lnd) => { lnd.stream(context, 'stream-code-message-frame', body, 'finish'); } });
  const client = await rest(fake);
  const seen: unknown[] = [];
  const read = () => client.stream('GET', TRACK, undefined, message => { seen.push(message); return 'continue'; });
  body = [frame({ result: { n: 1 } }), '\n', '\n', frame({ result: { n: 2 } }), '\n'];
  await read();
  expect(seen).toEqual([{ n: 1 }, { n: 2 }]);
  // grpc-gateway v1 error chunks carry grpc_code (lnd#5237); the send and track endpoints also answer {code, message} (lnd#6751).
  body = [frame({ result: { n: 3 } }), frame({ error: { grpc_code: 5, http_code: 404, message: "payment isn't initiated", http_status: 'Not Found' } })];
  const legacy = await rejection(read());
  expect(legacy).toBeInstanceOf(errors.LndError);
  expect((legacy as InstanceType<typeof errors.LndError>).grpcCode).toBe(5);
  body = [frame({ code: 2, message: 'invoice is already paid' })];
  const plain = await rejection(read());
  expect(plain).toBeInstanceOf(errors.LndError);
  expect((plain as InstanceType<typeof errors.LndError>).grpcCode).toBe(2);
  expect((plain as InstanceType<typeof errors.LndError>).httpStatus).toBeUndefined();
  expect(seen).toEqual([{ n: 1 }, { n: 2 }, { n: 3 }]);
});

it('CP-011/B7 a repeated chan_id and an answer naming another payment hash are protocol errors', async () => {
  const errors = await loadErrors();
  const asked = '77'.repeat(32), other = '88'.repeat(32);
  const fake = await fakeLnd({
    'GET /v1/channels': (context, lnd) => { lnd.answer(context, 'listchannels', { channels: [channel(), channel({ channel_point: `${'cd'.repeat(32)}:0` })] }); },
    'GET /v1/invoice/{r_hash_str}': (context, lnd) => { lnd.answer(context, 'lookupinvoice', invoice({ r_hash: b64(other) })); },
    'GET /v2/router/track/{payment_hash}': (context, lnd) => { lnd.stream(context, 'trackpayment-stream', [frame({ result: payment({ payment_hash: other }) })], 'finish'); },
  });
  const client = await api(fake);
  expect(await rejection(client.listChannels())).toBeInstanceOf(errors.ProtocolError);
  expect(await rejection(client.lookupInvoice(asked))).toBeInstanceOf(errors.ProtocolError);
  const updates: string[] = [];
  expect(await rejection(client.trackPayment(asked, update => { updates.push(update.paymentHash); return 'continue'; }))).toBeInstanceOf(errors.ProtocolError);
  expect(updates).toEqual([]);
});

it('CP-011/B7 int32 fields keep negative values and an all-zero preimage proves nothing', async () => {
  // blocks_til_maturity is int32 and negative once the output has matured (lightning.proto ForceClosedChannel).
  const zero = '00'.repeat(32);
  const fake = await fakeLnd({
    'GET /v1/channels/pending': (context, lnd) => {
      lnd.answer(context, 'pendingchannels', {
        total_limbo_balance: '0', pending_open_channels: [], pending_closing_channels: [], waiting_close_channels: [],
        pending_force_closing_channels: [{ channel: pendingChannel(), closing_txid: '34'.repeat(32), limbo_balance: '0', maturity_height: 700, blocks_til_maturity: -12, recovered_balance: '0', pending_htlcs: [], anchor: 'LIMBO' }],
      });
    },
    // LND reports an absent preimage as 32 zero bytes; the hash of zero bytes must not make it a proof.
    'GET /v1/payments': (context, lnd) => { lnd.answer(context, 'listpayments', { payments: [payment({ payment_hash: sha256(zero), payment_preimage: zero, status: 'SUCCEEDED' })], first_index_offset: '1', last_index_offset: '1', total_num_payments: '0' }); },
  });
  const client = await api(fake);
  expect((await client.pendingChannels()).pendingForceClosingChannels[0]?.blocksTilMaturity).toBe(-12);
  expect((await client.listPayments({ indexOffset: 0n, maxPayments: 1, includeIncomplete: true })).payments[0]?.preimageMatchesHash).toBe(false);
});

it('CP-011/B7 GetInfo reads the network from every chains entry and refuses entries that disagree', async () => {
  const errors = await loadErrors();
  let chains: unknown[] = [];
  const fake = await fakeLnd({ 'GET /v1/getinfo': (context, lnd) => { lnd.answer(context, 'getinfo', { ...getInfo(), chains }); } });
  const client = await api(fake);
  chains = [{ chain: 'bitcoin', network: 'regtest' }, { chain: 'bitcoin', network: 'regtest' }];
  expect((await client.getInfo()).network).toBe('regtest');
  for (const hostile of [
    [{ chain: 'bitcoin', network: 'regtest' }, { chain: 'bitcoin', network: 'mainnet' }],
    [{ chain: 'litecoin', network: 'regtest' }],
    [{ chain: 'bitcoin', network: 'regtest' }, { chain: 'litecoin', network: 'regtest' }],
  ]) {
    chains = hostile;
    expect(await rejection(client.getInfo()), JSON.stringify(hostile)).toBeInstanceOf(errors.ProtocolError);
  }
});

it('CP-011/B7 a channel without its balances or reserve constraints is refused rather than read as zero', async () => {
  const errors = await loadErrors();
  // The gateway emits every field (EmitUnpopulated, lnrpc/rpc_utils.go#L47-L50); an absent one is not LND's answer,
  // and a reserve read as 0 would overstate spendable.
  const full = channel();
  const omit = (value: Record<string, unknown>, key: string): Record<string, unknown> => Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
  const cases: Record<string, unknown>[] = [{ ...full, local_constraints: omit(full['local_constraints'] as Record<string, unknown>, 'chan_reserve_sat') }];
  for (const key of ['local_balance', 'remote_balance', 'capacity', 'local_constraints', 'remote_constraints']) cases.push(omit(full, key));
  let current: Record<string, unknown> = full;
  const fake = await fakeLnd({ 'GET /v1/channels': (context, lnd) => { lnd.answer(context, 'listchannels', { channels: [current] }); } });
  const client = await api(fake);
  expect(await client.listChannels()).toHaveLength(1);
  for (const [index, broken] of cases.entries()) {
    current = broken;
    expect(await rejection(client.listChannels()), `case ${String(index)}`).toBeInstanceOf(errors.ProtocolError);
  }
});

it('CP-011/B9 peer error text is bounded', async () => {
  const errors = await loadErrors();
  const long = 'x'.repeat(100_000);
  const fake = await fakeLnd({
    'GET /v1/getinfo': (context, lnd) => { lnd.grpcError(context, 'grpc-error', 2, long); },
    'GET /v2/router/track/{payment_hash}': (context, lnd) => { lnd.stream(context, 'stream-error-frame', [frame({ error: { code: 2, message: long, details: [] } })], 'finish'); },
  });
  const client = await rest(fake);
  for (const error of [await rejection(client.call('GET', '/v1/getinfo')), await rejection(client.stream('GET', TRACK, undefined, () => 'continue'))]) {
    expect(error).toBeInstanceOf(errors.LndError);
    expect((error as Error).message.startsWith('x') || (error as Error).message.includes('xxxx')).toBe(true);
    expect((error as Error).message.length).toBeLessThan(2000);
  }
});
