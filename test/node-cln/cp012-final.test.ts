import { randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { loadClnApi, loadClnRest, loadErrors, rejection, type ClnApi, type ClnRestOptions } from '../helpers/adapter-interfaces.js';
import { certificatePath, type FakeServer } from '../fakes/https.js';
import { startFakeCln, type ClnHandler, type FakeCln } from '../fakes/cln/fake-cln.js';
import { clnInvoice, getinfo, peerChannel, sendpay } from '../fakes/cln/responses.js';

const scratch = mkdtempSync(join(tmpdir(), 'fw-cln-final-'));
const rune = randomBytes(48).toString('base64url');
const runePath = join(scratch, 'test.rune');
writeFileSync(runePath, rune);

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

async function fakeCln(methods: Partial<Record<string, ClnHandler>>): Promise<FakeCln> {
  const fake = await startFakeCln({ rune, methods });
  open.push(fake);
  return fake;
}

async function api(server: { host: string; port: number }, overrides: Partial<ClnRestOptions> = {}): Promise<ClnApi> {
  const [{ openClnRest }, { ClnReadApi }] = await Promise.all([loadClnRest(), loadClnApi()]);
  return new ClnReadApi(await openClnRest({ host: server.host, port: server.port, tlsCertPath: certificatePath('node'), runePath, timeoutMs: 5000, ...overrides }));
}

const omit = (value: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> => Object.fromEntries(Object.entries(value).filter(([name]) => !keys.includes(name)));

it('CP-012/B2 a repeated sendpay id or invoice label and an invoice answer naming another label are protocol errors', async () => {
  const errors = await loadErrors();
  const fake = await fakeCln({
    listsendpays: (context, cln) => { cln.result(context, 'listsendpays', { payments: [sendpay({ id: 4 }), sendpay({ id: 4, created_index: 5, groupid: 2 })] }); },
    listinvoices: (context, cln) => {
      const label = context.params['label'];
      cln.result(context, 'listinvoices', { invoices: label === 'asked' ? [clnInvoice({ label: 'other' })] : [clnInvoice({ label: 'same', payment_hash: '01'.repeat(32) }), clnInvoice({ label: 'same', payment_hash: '02'.repeat(32), created_index: 10 })] });
    },
  });
  const client = await api(fake);
  expect(await rejection(client.listSendPays())).toBeInstanceOf(errors.ProtocolError);
  expect(await rejection(client.listInvoices())).toBeInstanceOf(errors.ProtocolError);
  // lightningd answers a label filter with only the exact-label invoice (lightningd/invoice.c#L1301-L1307 at v26.06.9).
  expect(await rejection(client.listInvoices({ label: 'asked' }))).toBeInstanceOf(errors.ProtocolError);
});

it('CP-012/B2 a normal channel without its funding outpoint does not escape the balance requirement', async () => {
  const errors = await loadErrors();
  const balances = ['to_us_msat', 'total_msat', 'spendable_msat', 'receivable_msat', 'our_reserve_msat', 'their_reserve_msat'];
  let channels: unknown[] = [];
  const fake = await fakeCln({ listpeerchannels: (context, cln) => { cln.result(context, 'listpeerchannels', { channels }); } });
  const client = await api(fake);
  for (const variant of [omit(peerChannel(), ['funding_txid', ...balances]), { ...omit(peerChannel(), balances), funding_txid: null }, omit(peerChannel(), ['funding_txid', 'funding_outnum', ...balances])]) {
    channels = [variant];
    expect(await rejection(client.listPeerChannels())).toBeInstanceOf(errors.ProtocolError);
  }
  // A null amount is not lightningd's rendering of a committed channel's balance either.
  channels = [peerChannel({ to_us_msat: null })];
  expect(await rejection(client.listPeerChannels())).toBeInstanceOf(errors.ProtocolError);
});

it('CP-012/B1 a timeout that is not a positive integer is refused before any connection', async () => {
  const fake = await fakeCln({ getinfo: (context, cln) => { cln.result(context, 'getinfo', getinfo()); } });
  for (const value of [0, -5, 2.5, Number.NaN]) {
    let error: unknown;
    try { await (await api(fake, { timeoutMs: value })).getInfo(); } catch (caught) { error = caught; }
    expect(error, String(value)).toBeInstanceOf(Error);
  }
  expect(fake.connections()).toBe(0);
});
