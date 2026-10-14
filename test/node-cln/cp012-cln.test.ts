import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspect } from 'node:util';
import { afterEach, expect, it } from 'vitest';
import {
  loadClnApi, loadClnRest, loadClnTypes, loadErrors, rejection, serialise,
  type ClnApi, type ClnRest, type ClnRestOptions,
} from '../helpers/adapter-interfaces.js';
import { certificatePath, closedPort, type FakeServer, type Identity } from '../fakes/https.js';
import { startFakeCln, type ClnHandler, type FakeCln } from '../fakes/cln/fake-cln.js';
import { accountEvent, CLN_PEER, CLN_PUBKEY, clnInvoice, getinfo, pay, peerChannel, sendpay } from '../fakes/cln/responses.js';

const scratch = mkdtempSync(join(tmpdir(), 'fw-cln-'));
// A throwaway rune-shaped token for local servers (runes are URL-safe base64 text).
const rune = randomBytes(48).toString('base64url');
const runePath = join(scratch, 'test.rune');
writeFileSync(runePath, `${rune}\n`);

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

async function fakeCln(methods: Partial<Record<string, ClnHandler>>, identity: Identity = 'node'): Promise<FakeCln> {
  const fake = await startFakeCln({ rune, methods, identity });
  open.push(fake);
  return fake;
}

async function rest(server: { host: string; port: number }, overrides: Partial<ClnRestOptions> = {}): Promise<ClnRest> {
  const { openClnRest } = await loadClnRest();
  return openClnRest({ host: server.host, port: server.port, tlsCertPath: certificatePath('node'), runePath, timeoutMs: 5000, ...overrides });
}

async function api(server: { host: string; port: number }): Promise<ClnApi> {
  const { ClnReadApi } = await loadClnApi();
  return new ClnReadApi(await rest(server));
}

const sha256 = (hex: string): string => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');

it('CP-012/B1 every call is POST /v1/<method> with the trimmed rune header and a JSON object body', async () => {
  const fake = await fakeCln({
    getinfo: (context, cln) => { cln.result(context, 'getinfo', getinfo()); },
    listinvoices: (context, cln) => { cln.result(context, 'listinvoices', { invoices: [] }); },
  });
  const client = await api(fake);
  expect((await client.getInfo()).id).toBe(CLN_PUBKEY);
  await client.listInvoices({ paymentHash: 'ab'.repeat(32) });
  expect(fake.requests).toHaveLength(2);
  const [first, second] = fake.requests;
  expect(first?.method).toBe('POST');
  expect(first?.url).toBe('/v1/getinfo');
  expect(first?.headers['rune']).toBe(rune);
  expect(first?.headers['content-type']).toMatch(/^application\/json/);
  expect(JSON.parse(first?.body ?? '')).toEqual({});
  expect(second?.url).toBe('/v1/listinvoices');
  expect(JSON.parse(second?.body ?? '')).toEqual({ payment_hash: 'ab'.repeat(32) });
});

it('CP-012/B1 a missing rune 1501 and a rejected rune 1502 are authentication failures', async () => {
  const errors = await loadErrors();
  const fake = await fakeCln({
    // clnrest's answer when the header is absent (the adapter always sends it, so it is scripted here).
    getinfo: (context, cln) => { cln.raw(context, 'rune-missing', 403, JSON.stringify({ code: 1501, message: 'Not authorized: Missing rune', data: null })); },
  });
  const missing = await rejection((await rest(fake)).call('getinfo'));
  expect(missing).toBeInstanceOf(errors.AuthError);
  expect((missing as InstanceType<typeof errors.AuthError>).code).toBe(1501);
  expect((missing as InstanceType<typeof errors.AuthError>).httpStatus).toBe(403);
  writeFileSync(join(scratch, 'other.rune'), randomBytes(48).toString('base64url'));
  const rejected = await rejection((await rest(fake, { runePath: join(scratch, 'other.rune') })).call('getinfo'));
  expect(rejected).toBeInstanceOf(errors.AuthError);
  expect((rejected as InstanceType<typeof errors.AuthError>).code).toBe(1502);
  expect((rejected as InstanceType<typeof errors.AuthError>).httpStatus).toBe(401);
  expect(fake.served.map(item => item.behaviour)).toEqual(['rune-missing', 'rune-invalid']);
  const before = fake.connections();
  writeFileSync(join(scratch, 'empty.rune'), '');
  writeFileSync(join(scratch, 'over.rune'), 'a'.repeat(65537));
  for (const name of ['empty.rune', 'over.rune']) {
    let error: unknown;
    try { await (await rest(fake, { runePath: join(scratch, name) })).call('getinfo'); } catch (caught) { error = caught; }
    expect(error, name).toBeInstanceOf(Error);
    expect(error, name).not.toBeInstanceOf(errors.TransportError);
  }
  expect(fake.connections()).toBe(before);
});

it('CP-012/B2 getinfo maps identity version height network and sync warnings', async () => {
  let answer = getinfo();
  const fake = await fakeCln({ getinfo: (context, cln) => { cln.result(context, 'getinfo', answer); } });
  const client = await api(fake);
  expect(await client.getInfo()).toEqual({
    id: CLN_PUBKEY, alias: 'cln-m', version: 'v26.06.9', blockheight: 812, network: 'regtest',
    warningBitcoindSync: null, warningLightningdSync: null,
  });
  answer = getinfo({ warning_bitcoind_sync: 'Bitcoind is not up-to-date with network.', warning_lightningd_sync: 'Still loading latest blocks from bitcoind.' });
  expect(await client.getInfo()).toMatchObject({
    warningBitcoindSync: 'Bitcoind is not up-to-date with network.', warningLightningdSync: 'Still loading latest blocks from bitcoind.',
  });
});

it('CP-012/B2 listpeerchannels maps funding outpoint htlcs state and amounts given as numbers or msat strings', async () => {
  const outgoing = { direction: 'out', id: 7, amount_msat: '100202101msat', expiry: 950, payment_hash: 'cd'.repeat(32), state: 'SENT_ADD_ACK_REVOCATION' };
  const incoming = { direction: 'in', id: 18446744073709551615n.toString(), amount_msat: 5000, expiry: 951, payment_hash: 'ef'.repeat(32), local_trimmed: true, status: 'htlc_accepted hook: myplugin', state: 'RCVD_ADD_ACK_REVOCATION' };
  const channels = [
    peerChannel(),
    peerChannel({
      peer_id: CLN_PUBKEY, peer_connected: false, state: 'CHANNELD_AWAITING_SPLICE', short_channel_id: '812x2x1', funding_outnum: 3,
      opener: 'local', private: true, to_us_msat: '3700000000msat', total_msat: '5000000000msat', spendable_msat: '9007199254740993msat',
      receivable_msat: 0, our_reserve_msat: '50000000msat', their_reserve_msat: 49999999, fee_base_msat: '0msat',
      fee_proportional_millionths: 1, minimum_htlc_out_msat: '1000msat', maximum_htlc_out_msat: '1250000000msat', htlcs: [outgoing, incoming],
    }),
  ];
  // The 9007199254740993 must survive: it is beyond 2^53 and arrives only as text.
  const body = JSON.stringify({ channels });
  const fake = await fakeCln({ listpeerchannels: (context, cln) => { cln.raw(context, 'msat-string', 201, body); } });
  const result = await (await api(fake)).listPeerChannels();
  expect(result).toHaveLength(2);
  expect(result[0]).toMatchObject({
    peerId: CLN_PEER, peerConnected: true, state: 'CHANNELD_NORMAL', shortChannelId: '812x1x0', channelId: '78'.repeat(32),
    fundingTxid: '9a'.repeat(32), fundingOutnum: 0, opener: 'remote', private: false, totalMsat: 5000000000n, toUsMsat: 1250000000n,
    spendableMsat: 1199000000n, receivableMsat: 3699000000n, ourReserveMsat: 50000000n, theirReserveMsat: 50000000n,
    feeBaseMsat: 1000n, feeProportionalMillionths: 1000, minimumHtlcOutMsat: 0n, maximumHtlcOutMsat: 4950000000n, htlcs: [],
  });
  expect(result[1]).toMatchObject({
    peerConnected: false, state: 'CHANNELD_AWAITING_SPLICE', shortChannelId: '812x2x1', fundingOutnum: 3, opener: 'local', private: true,
    toUsMsat: 3700000000n, totalMsat: 5000000000n, spendableMsat: 9007199254740993n, receivableMsat: 0n, ourReserveMsat: 50000000n,
    theirReserveMsat: 49999999n, feeBaseMsat: 0n, feeProportionalMillionths: 1, minimumHtlcOutMsat: 1000n, maximumHtlcOutMsat: 1250000000n,
    htlcs: [
      { direction: 'out', id: '7', amountMsat: 100202101n, expiry: 950, paymentHash: 'cd'.repeat(32), state: 'SENT_ADD_ACK_REVOCATION', status: null, localTrimmed: false },
      { direction: 'in', id: '18446744073709551615', amountMsat: 5000n, expiry: 951, paymentHash: 'ef'.repeat(32), state: 'RCVD_ADD_ACK_REVOCATION', status: 'htlc_accepted hook: myplugin', localTrimmed: true },
    ],
  });
});

it('CP-012/B2 listsendpays and listpays map status amounts and preimage proof and pass the hash filter', async () => {
  const preimage = randomBytes(32).toString('hex');
  const hash = sha256(preimage);
  const fake = await fakeCln({
    listsendpays: (context, cln) => {
      cln.result(context, 'listsendpays', { payments: [
        sendpay({ payment_hash: hash, status: 'complete', partid: 0, completed_at: 1760000050, payment_preimage: preimage, amount_sent_msat: '100202101msat' }),
        sendpay({ id: 5, created_index: 5, payment_hash: hash, status: 'failed', groupid: 2, amount_msat: undefined, label: undefined, destination: undefined }),
        sendpay({ id: 6, created_index: 6, payment_hash: hash, status: 'pending', groupid: 3, payment_preimage: 'ee'.repeat(32) }),
      ] });
    },
    listpays: (context, cln) => {
      cln.result(context, 'listpays', { pays: [pay({ payment_hash: hash, status: 'complete', preimage, number_of_parts: 1, completed_at: 1760000050 }), pay({ payment_hash: hash, status: 'failed', amount_msat: undefined, amount_sent_msat: undefined })] });
    },
  });
  const client = await api(fake);
  const sendpays = await client.listSendPays({ paymentHash: hash });
  expect(fake.calls[0]).toEqual({ method: 'listsendpays', params: { payment_hash: hash } });
  expect(sendpays).toHaveLength(3);
  expect(sendpays[0]).toMatchObject({
    id: '4', groupid: '1', partid: '0', paymentHash: hash, status: 'complete', amountMsat: 100000000n, amountSentMsat: 100202101n,
    createdAt: 1760000000, completedAt: 1760000050, label: 'fluxwarden-exec', destination: CLN_PUBKEY, createdIndex: '4', preimageMatchesHash: true,
  });
  expect(sendpays[1]).toMatchObject({ id: '5', status: 'failed', groupid: '2', amountMsat: null, label: null, destination: null, completedAt: null, preimageMatchesHash: false });
  // A preimage that does not hash to the payment hash proves nothing.
  expect(sendpays[2]).toMatchObject({ status: 'pending', preimageMatchesHash: false });
  const pays = await client.listPays({ paymentHash: hash });
  expect(fake.calls[1]).toEqual({ method: 'listpays', params: { payment_hash: hash } });
  expect(pays).toEqual([
    { paymentHash: hash, status: 'complete', amountMsat: 100000000n, amountSentMsat: 100202101n, numberOfParts: 1, createdAt: 1760000000, completedAt: 1760000050, label: 'fluxwarden-exec', preimageMatchesHash: true },
    { paymentHash: hash, status: 'failed', amountMsat: null, amountSentMsat: null, numberOfParts: null, createdAt: 1760000000, completedAt: null, label: 'fluxwarden-exec', preimageMatchesHash: false },
  ]);
  const text = serialise([sendpays, pays]) + inspect([sendpays, pays], { depth: 10 });
  expect(text).not.toContain(preimage);
});

it('CP-012/B2 listinvoices maps status and amounts, passes the label filter and never returns the preimage', async () => {
  const preimage = randomBytes(32).toString('hex');
  const hash = sha256(preimage);
  const fake = await fakeCln({
    listinvoices: (context, cln) => {
      const all = [
        clnInvoice({ payment_hash: hash, status: 'paid', pay_index: 2, amount_received_msat: '100000000msat', paid_at: 1760000060, payment_preimage: preimage }),
        clnInvoice({ label: 'other', payment_hash: 'cd'.repeat(32), status: 'expired', amount_msat: undefined, description: undefined }),
      ];
      // A label filter returns at most the one invoice with exactly that label (lightningd/invoice.c#L1301-L1307 at v26.06.9).
      cln.result(context, 'listinvoices', { invoices: context.params['label'] === undefined ? all : all.filter(item => item['label'] === context.params['label']) });
    },
  });
  const client = await api(fake);
  const invoices = await client.listInvoices();
  expect(fake.calls[0]).toEqual({ method: 'listinvoices', params: {} });
  expect(invoices).toEqual([
    { label: 'fluxwarden-exec', paymentHash: hash, status: 'paid', amountMsat: 100000000n, amountReceivedMsat: 100000000n, expiresAt: 1760003600, paidAt: 1760000060, payIndex: '2', createdIndex: '9', description: 'fluxwarden rebalance' },
    { label: 'other', paymentHash: 'cd'.repeat(32), status: 'expired', amountMsat: null, amountReceivedMsat: null, expiresAt: 1760003600, paidAt: null, payIndex: null, createdIndex: '9', description: null },
  ]);
  expect(serialise(invoices) + inspect(invoices, { depth: 10 })).not.toContain(preimage);
  const byLabel = await client.listInvoices({ label: 'fluxwarden-exec' });
  expect(fake.calls[1]).toEqual({ method: 'listinvoices', params: { label: 'fluxwarden-exec' } });
  expect(byLabel.map(item => item.paymentHash)).toEqual([hash]);
});

it('CP-012/B2 bkpr-listaccountevents maps fees_msat and is_rebalance and askrene-listlayers maps layers', async () => {
  const fake = await fakeCln({
    'bkpr-listaccountevents': (context, cln) => {
      cln.result(context, 'bkpr-listaccountevents', { events: [
        accountEvent(),
        accountEvent({ type: 'chain', tag: 'deposit', credit_msat: '5000000000msat', debit_msat: 0, fees_msat: undefined, is_rebalance: undefined, payment_id: undefined, part_id: undefined, outpoint: `${'9a'.repeat(32)}:0`, blockheight: 700 }),
      ] });
    },
    'askrene-listlayers': (context, cln) => {
      cln.result(context, 'askrene-listlayers', { layers: [{
        layer: 'fluxwarden-exec', persistent: false, disabled_nodes: [CLN_PUBKEY], disabled_channels: ['812x1x0/1'], created_channels: [],
        channel_updates: [{ short_channel_id_dir: '812x2x1/0', enabled: false }, { short_channel_id_dir: '812x3x0/1', fee_base_msat: 0, fee_proportional_millionths: 10, cltv_expiry_delta: 40 }],
        constraints: [], biases: [], node_biases: [],
      }] });
    },
  });
  const client = await api(fake);
  expect(await client.listAccountEvents()).toEqual([
    { account: '78'.repeat(32), type: 'channel', tag: 'invoice', creditMsat: 0n, debitMsat: 100000000n, currency: 'bcrt', timestamp: 1760000300, feesMsat: 202101n, isRebalance: true, paymentId: 'ab'.repeat(32), partId: 0 },
    { account: '78'.repeat(32), type: 'chain', tag: 'deposit', creditMsat: 5000000000n, debitMsat: 0n, currency: 'bcrt', timestamp: 1760000300, feesMsat: null, isRebalance: null, paymentId: null, partId: null },
  ]);
  expect(await client.listLayers()).toEqual([{
    layer: 'fluxwarden-exec', persistent: false, disabledNodes: [CLN_PUBKEY], disabledChannels: ['812x1x0/1'],
    channelUpdates: [
      { shortChannelIdDir: '812x2x1/0', enabled: false, feeBaseMsat: null, feeProportionalMillionths: null, cltvExpiryDelta: null },
      { shortChannelIdDir: '812x3x0/1', enabled: null, feeBaseMsat: 0n, feeProportionalMillionths: 10, cltvExpiryDelta: 40 },
    ],
  }]);
  expect(fake.calls.map(call => call.method)).toEqual(['bkpr-listaccountevents', 'askrene-listlayers']);
});

it('CP-012/B3 malformed JSON and schema violations are protocol errors', async () => {
  const errors = await loadErrors();
  let body = '';
  const fake = await fakeCln({
    getinfo: (context, cln) => { cln.raw(context, 'malformed', 201, body); },
    listpeerchannels: (context, cln) => { cln.raw(context, 'malformed', 201, body); },
    listsendpays: (context, cln) => { cln.raw(context, 'malformed', 201, body); },
  });
  const client = await api(fake);
  const cases: [string, () => Promise<unknown>][] = [
    ['{"id": "03', () => client.getInfo()],
    ['[]', () => client.getInfo()],
    [JSON.stringify(getinfo({ id: 42 })), () => client.getInfo()],
    [JSON.stringify(getinfo({ blockheight: '812' })), () => client.getInfo()],
    [JSON.stringify({ channels: {} }), () => client.listPeerChannels()],
    [JSON.stringify({ channels: [peerChannel({ spendable_msat: '12.5msat' })] }), () => client.listPeerChannels()],
    [JSON.stringify({ channels: [peerChannel({ spendable_msat: '-5msat' })] }), () => client.listPeerChannels()],
    [JSON.stringify({ channels: [peerChannel({ spendable_msat: 'msat' })] }), () => client.listPeerChannels()],
    [JSON.stringify({ channels: [peerChannel()] }).replace('"spendable_msat":1199000000', '"spendable_msat":9007199254740993'), () => client.listPeerChannels()],
    [JSON.stringify({ channels: [peerChannel({ opener: 'both' })] }), () => client.listPeerChannels()],
    [JSON.stringify({ channels: [peerChannel({ htlcs: [{ direction: 'sideways', id: 1, amount_msat: 1, expiry: 1, payment_hash: 'ab'.repeat(32), state: 'SENT_ADD_HTLC' }] })] }), () => client.listPeerChannels()],
    [JSON.stringify({ payments: [sendpay({ status: 'settled' })] }), () => client.listSendPays()],
    [JSON.stringify({ payments: [sendpay({ amount_sent_msat: 1.5 })] }), () => client.listSendPays()],
  ];
  for (const [index, [text, call]] of cases.entries()) {
    body = text;
    expect(await rejection(call()), `case ${String(index)}`).toBeInstanceOf(errors.ProtocolError);
  }
});

it('CP-012/B3 an error body is a CLN error with its code and never a result', async () => {
  const errors = await loadErrors();
  const fake = await fakeCln({ listinvoices: (context, cln) => { cln.rpcError(context, 'rpc-error', -32602, 'label: should be a string or number'); } });
  const client = await rest(fake);
  const invalid = await rejection(client.call('listinvoices', { label: [] }));
  expect(invalid).toBeInstanceOf(errors.ClnError);
  expect((invalid as InstanceType<typeof errors.ClnError>).code).toBe(-32602);
  expect((invalid as InstanceType<typeof errors.ClnError>).httpStatus).toBe(500);
  const unknown = await rejection(client.call('askrene-listlayers'));
  expect(unknown).toBeInstanceOf(errors.ClnError);
  expect((unknown as InstanceType<typeof errors.ClnError>).code).toBe(-32601);
  expect((unknown as InstanceType<typeof errors.ClnError>).httpStatus).toBe(404);
});

it('CP-012/B4 version strings parse for releases and custom builds and unknown forms are refused', async () => {
  const { parseClnVersion } = await loadClnTypes();
  // Releases are v<year>.<month>[.<patch>]* (common/version.c#L30-L39); builds from git add
  // "-<commits>-g<hash>" and "-modded" (Makefile#L5 git describe --dirty=-modded).
  expect(parseClnVersion('v26.06.9')).toEqual({ year: 26, month: 6, patch: 9 });
  expect(parseClnVersion('v26.06')).toEqual({ year: 26, month: 6, patch: 0 });
  expect(parseClnVersion('v26.04.1')).toEqual({ year: 26, month: 4, patch: 1 });
  expect(parseClnVersion('v26.06.9-modded')).toEqual({ year: 26, month: 6, patch: 9 });
  expect(parseClnVersion('v26.06.9-14-gab12cd3')).toEqual({ year: 26, month: 6, patch: 9 });
  expect(parseClnVersion('v26.06.9-14-gab12cd3-modded')).toEqual({ year: 26, month: 6, patch: 9 });
  for (const unknown of ['', 'v', 'ab12cd3-modded', 'v26', '26.06.9', 'v26.6x', 'vXX.06.1', 'basedon-v26.06.9', 'v26.13.0', ' v26.06.9']) {
    expect(parseClnVersion(unknown), JSON.stringify(unknown)).toBeNull();
  }
});

it('CP-012/B5 channels without short_channel_id or funding outpoint are listed with null identifiers', async () => {
  const awaiting = peerChannel({ state: 'CHANNELD_AWAITING_LOCKIN', short_channel_id: undefined, direction: undefined, spendable_msat: 0 });
  const opening = { peer_id: CLN_PEER, peer_connected: true, state: 'OPENINGD', opener: 'local', features: [] };
  const fake = await fakeCln({ listpeerchannels: (context, cln) => { cln.result(context, 'listpeerchannels', { channels: [awaiting, opening] }); } });
  const result = await (await api(fake)).listPeerChannels();
  expect(result).toHaveLength(2);
  expect(result[0]).toMatchObject({ state: 'CHANNELD_AWAITING_LOCKIN', shortChannelId: null, channelId: '78'.repeat(32), fundingTxid: '9a'.repeat(32), fundingOutnum: 0, totalMsat: 5000000000n, spendableMsat: 0n });
  expect(result[1]).toMatchObject({ peerId: CLN_PEER, state: 'OPENINGD', opener: 'local', shortChannelId: null, channelId: null, fundingTxid: null, fundingOutnum: null, htlcs: [] });
});

it('CP-012/B6 errors carry no rune in any encoding', async () => {
  const errors = await loadErrors();
  const echo = `checkrune failed for ${rune} (${Buffer.from(rune).toString('hex')}) ${Buffer.from(rune).toString('base64')}`;
  const fake = await fakeCln({
    getinfo: (context, cln) => { cln.rpcError(context, 'rpc-error', 1502, echo); },
    listinvoices: (context, cln) => { cln.raw(context, 'rune-invalid', 401, JSON.stringify({ code: 1502, message: echo, data: null })); },
  });
  const tlsFake = await fakeCln({}, 'other');
  const client = await rest(fake);
  const failures = [
    await rejection(client.call('getinfo')),
    await rejection(client.call('listinvoices')),
    await rejection((await rest(tlsFake)).call('getinfo')),
    await rejection((await rest({ host: '127.0.0.1', port: await closedPort() })).call('getinfo')),
  ];
  expect(failures[2]).toBeInstanceOf(errors.TlsError);
  for (const [index, failure] of failures.entries()) {
    expect(failure, String(index)).toBeInstanceOf(Error);
    const error = failure as Error;
    const text = [error.message, String(error), error.stack ?? '', inspect(error, { depth: 10, showHidden: true }), serialise(error)].join('\n');
    for (const form of [rune, Buffer.from(rune).toString('hex'), Buffer.from(rune).toString('base64')]) {
      expect(text.includes(form), `failure ${String(index)} leaks a credential form`).toBe(false);
    }
  }
});
