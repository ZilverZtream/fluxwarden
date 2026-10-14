import { randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { loadClnApi, loadClnRest, loadClnTypes, loadErrors, rejection, type ClnApi, type ClnRest, type ClnRestOptions } from '../helpers/adapter-interfaces.js';
import { certificatePath, closedPort, startResettingListener, type FakeServer, type Identity } from '../fakes/https.js';
import { startFakeCln, type ClnHandler, type FakeCln } from '../fakes/cln/fake-cln.js';
import { clnInvoice, getinfo, pay, peerChannel, sendpay, accountEvent } from '../fakes/cln/responses.js';

const MiB = 1024 * 1024;
const scratch = mkdtempSync(join(tmpdir(), 'fw-cln-hostile-'));
const rune = randomBytes(48).toString('base64url');
const runePath = join(scratch, 'test.rune');
writeFileSync(runePath, rune);

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

const pause = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms));

it('CP-012/B1 clnrest TLS is pinned by certificate and host name even with NODE_TLS_REJECT_UNAUTHORIZED=0', async () => {
  const errors = await loadErrors();
  const handler: ClnHandler = (context, cln) => { cln.result(context, 'getinfo', getinfo()); };
  const otherCa = await fakeCln({ getinfo: handler }, 'other');
  const wrongHost = await fakeCln({ getinfo: handler }, 'wrong-host');
  const previous = process.env['NODE_TLS_REJECT_UNAUTHORIZED'];
  process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';
  try {
    for (const [fake, certificate] of [[otherCa, certificatePath('node')], [wrongHost, certificatePath('wrong-host')]] as const) {
      const error = await rejection((await rest(fake, { tlsCertPath: certificate })).call('getinfo'));
      expect(error).toBeInstanceOf(errors.TlsError);
      expect((error as InstanceType<typeof errors.TlsError>).phase).toBe('connect');
      expect(fake.requests).toHaveLength(0);
    }
  } finally {
    if (previous === undefined) delete process.env['NODE_TLS_REJECT_UNAUTHORIZED'];
    else process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = previous;
  }
});

it('CP-012/B1 a timeout is phase response after one request and refused or reset connections are phase connect', async () => {
  const errors = await loadErrors();
  const fake = await fakeCln({ getinfo: (context, cln) => { cln.hold(context, 'no-answer'); } });
  const started = performance.now();
  const timeout = await rejection((await rest(fake, { timeoutMs: 300 })).call('getinfo'));
  expect(performance.now() - started).toBeLessThan(5000);
  expect(timeout).toBeInstanceOf(errors.TransportError);
  expect((timeout as InstanceType<typeof errors.TransportError>).phase).toBe('response');
  await pause(500);
  expect(fake.requests).toHaveLength(1);
  const refused = await rejection((await rest({ host: '127.0.0.1', port: await closedPort() })).call('getinfo'));
  expect(refused).toBeInstanceOf(errors.TransportError);
  expect(refused).not.toBeInstanceOf(errors.TlsError);
  expect((refused as InstanceType<typeof errors.TransportError>).phase).toBe('connect');
  const listener = await startResettingListener();
  open.push(listener);
  const reset = await rejection((await rest(listener)).call('getinfo'));
  expect((reset as InstanceType<typeof errors.TransportError>).phase).toBe('connect');
  await pause(300);
  expect(listener.connections()).toBe(1);
});

it('CP-012/B1 the rune file must hold exactly one printable rune and is refused before any connection otherwise', async () => {
  const errors = await loadErrors();
  const fake = await fakeCln({ getinfo: (context, cln) => { cln.result(context, 'getinfo', getinfo()); } });
  for (const [name, content] of [['two.rune', `${rune}\n${rune}\n`], ['space.rune', `${rune.slice(0, 10)} ${rune.slice(10)}`], ['control.rune', `${rune}\u0000`], ['header.rune', `${rune}\r\nX-Injected: 1`]] as const) {
    writeFileSync(join(scratch, name), content);
    let error: unknown;
    try { await (await rest(fake, { runePath: join(scratch, name) })).call('getinfo'); } catch (caught) { error = caught; }
    expect(error, name).toBeInstanceOf(Error);
    expect(error, name).not.toBeInstanceOf(errors.TransportError);
  }
  expect(fake.connections()).toBe(0);
});

it('CP-012/B3 an answer of exactly 16 MiB is read and one byte more is a protocol error', async () => {
  const errors = await loadErrors();
  let size = 16 * MiB;
  const body = (): string => { const head = '{"layers":[]', tail = '}'; return head + ' '.repeat(size - head.length - tail.length) + tail; };
  const fake = await fakeCln({ 'askrene-listlayers': (context, cln) => { cln.raw(context, 'oversized-body', 201, body()); } });
  const client = await rest(fake);
  expect(await client.call('askrene-listlayers')).toEqual({ layers: [] });
  size = 16 * MiB + 1;
  expect(await rejection(client.call('askrene-listlayers'))).toBeInstanceOf(errors.ProtocolError);
}, 60_000);

it('CP-012/B3 amounts of 2^63 msat or more and missing required fields are protocol errors', async () => {
  const errors = await loadErrors();
  let body = '';
  const fake = await fakeCln({
    getinfo: (context, cln) => { cln.raw(context, 'malformed', 201, body); },
    listpeerchannels: (context, cln) => { cln.raw(context, 'malformed', 201, body); },
    listsendpays: (context, cln) => { cln.raw(context, 'malformed', 201, body); },
    listinvoices: (context, cln) => { cln.raw(context, 'malformed', 201, body); },
    'bkpr-listaccountevents': (context, cln) => { cln.raw(context, 'malformed', 201, body); },
  });
  const client = await api(fake);
  body = JSON.stringify({ channels: [peerChannel({ spendable_msat: '9223372036854775807msat' })] });
  expect((await client.listPeerChannels())[0]?.spendableMsat).toBe(9223372036854775807n);
  const without = (value: Record<string, unknown>, key: string): Record<string, unknown> => Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
  const cases: [string, () => Promise<unknown>][] = [
    [JSON.stringify({ channels: [peerChannel({ spendable_msat: '9223372036854775808msat' })] }), () => client.listPeerChannels()],
    [JSON.stringify({ channels: [peerChannel({ to_us_msat: '18446744073709551616' })] }), () => client.listPeerChannels()],
    // getinfo.json requires id, version, blockheight and network.
    ...['id', 'version', 'blockheight', 'network'].map((key): [string, () => Promise<unknown>] => [JSON.stringify(without(getinfo(), key)), () => client.getInfo()]),
    // listsendpays.json payments[] requires created_at; listinvoices.json invoices[] requires expires_at and created_index.
    [JSON.stringify({ payments: [without(sendpay(), 'created_at')] }), () => client.listSendPays()],
    [JSON.stringify({ invoices: [without(clnInvoice(), 'expires_at')] }), () => client.listInvoices()],
    [JSON.stringify({ invoices: [without(clnInvoice(), 'created_index')] }), () => client.listInvoices()],
    [JSON.stringify({ events: [without(accountEvent(), 'timestamp')] }), () => client.listAccountEvents()],
  ];
  for (const [index, [text, call]] of cases.entries()) {
    body = text;
    expect(await rejection(call()), `case ${String(index)}`).toBeInstanceOf(errors.ProtocolError);
  }
});

it('CP-012/B2 a committed channel without balances or reserves is refused and unknown states are flagged', async () => {
  const errors = await loadErrors();
  let channels: unknown[] = [];
  const fake = await fakeCln({ listpeerchannels: (context, cln) => { cln.result(context, 'listpeerchannels', { channels }); } });
  const client = await api(fake);
  // lightningd always writes these for a committed channel (lightningd/peer_control.c#L1276-L1321); only an
  // uncommitted OPENINGD channel may lack them (lightningd/opening_control.c json_add_uncommitted_channel).
  for (const key of ['to_us_msat', 'total_msat', 'spendable_msat', 'receivable_msat', 'our_reserve_msat', 'their_reserve_msat']) {
    channels = [Object.fromEntries(Object.entries(peerChannel()).filter(([name]) => name !== key))];
    expect(await rejection(client.listPeerChannels()), key).toBeInstanceOf(errors.ProtocolError);
  }
  const states = ['OPENINGD', 'CHANNELD_AWAITING_LOCKIN', 'CHANNELD_NORMAL', 'CHANNELD_SHUTTING_DOWN', 'CLOSINGD_SIGEXCHANGE', 'CLOSINGD_COMPLETE', 'AWAITING_UNILATERAL', 'FUNDING_SPEND_SEEN', 'ONCHAIN', 'DUALOPEND_OPEN_INIT', 'DUALOPEND_AWAITING_LOCKIN', 'CHANNELD_AWAITING_SPLICE', 'DUALOPEND_OPEN_COMMITTED', 'DUALOPEND_OPEN_COMMIT_READY'];
  channels = [...states, 'SOME_NEW_STATE'].map((state, index) => peerChannel({ state, short_channel_id: `812x${String(index + 1)}x0`, channel_id: index.toString(16).padStart(64, '0') }));
  const result = await client.listPeerChannels();
  // The state enum of doc/schemas/listpeerchannels.json; a new state name is kept but marked unknown.
  expect(result.map(item => [item.state, item.stateKnown])).toEqual([...states.map(state => [state, true]), ['SOME_NEW_STATE', false]]);
  // Text that is not a state name at all (lightningd's names are upper-case identifiers) is refused.
  for (const state of ['channeld_normal', '', 'CHANNELD NORMAL', 'X'.repeat(200)]) {
    channels = [peerChannel({ state })];
    expect(await rejection(client.listPeerChannels()), JSON.stringify(state.slice(0, 20))).toBeInstanceOf(errors.ProtocolError);
  }
});

it('CP-012/B2 a repeated short channel id and entries naming another payment hash are protocol errors', async () => {
  const errors = await loadErrors();
  const asked = '77'.repeat(32), other = '88'.repeat(32);
  const fake = await fakeCln({
    listpeerchannels: (context, cln) => { cln.result(context, 'listpeerchannels', { channels: [peerChannel(), peerChannel({ channel_id: '99'.repeat(32) })] }); },
    listsendpays: (context, cln) => { cln.result(context, 'listsendpays', { payments: [sendpay({ payment_hash: asked }), sendpay({ id: 5, created_index: 5, payment_hash: other, status: 'complete' })] }); },
    listpays: (context, cln) => { cln.result(context, 'listpays', { pays: [pay({ payment_hash: other, status: 'complete' })] }); },
    listinvoices: (context, cln) => { cln.result(context, 'listinvoices', { invoices: [clnInvoice({ payment_hash: other, status: 'paid' })] }); },
  });
  const client = await api(fake);
  expect(await rejection(client.listPeerChannels())).toBeInstanceOf(errors.ProtocolError);
  expect(await rejection(client.listSendPays({ paymentHash: asked }))).toBeInstanceOf(errors.ProtocolError);
  expect(await rejection(client.listPays({ paymentHash: asked }))).toBeInstanceOf(errors.ProtocolError);
  expect(await rejection(client.listInvoices({ paymentHash: asked }))).toBeInstanceOf(errors.ProtocolError);
  // Without a hash filter, entries for several payments are an ordinary answer.
  expect(await client.listSendPays()).toHaveLength(2);
});

it('CP-012/B4 version strings with trailing text are refused', async () => {
  const { parseClnVersion } = await loadClnTypes();
  for (const unknown of ['v26.06.9garbage', 'v26.06.9-modded2', 'v26.06.9-modded-x', 'v26.06.9 ', 'v26.06.9\n', 'v26.06.9-14-gab12cd3x']) {
    expect(parseClnVersion(unknown), JSON.stringify(unknown)).toBeNull();
  }
});

it('CP-012/B6 peer error text is bounded', async () => {
  const errors = await loadErrors();
  const fake = await fakeCln({ getinfo: (context, cln) => { cln.rpcError(context, 'rpc-error', -1, 'y'.repeat(100_000)); } });
  const error = await rejection((await rest(fake)).call('getinfo'));
  expect(error).toBeInstanceOf(errors.ClnError);
  expect((error as Error).message).toContain('yyyy');
  expect((error as Error).message.length).toBeLessThan(2000);
});
