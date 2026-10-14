// Lab facts for Core Lightning v26.06.9 (ARCHITECTURE.md §6). Expected values come from
// the pinned schemas and source cited per test and from labs/topology.json (base fee
// 1000 msat, 1000 ppm, LND delta 80, CLN delta 34). Oracles: lightning-cli and lncli in the
// containers; clnrest only where the assumption is about clnrest.
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  background, cleanProxies, clnRest, copiedCertificate, direction, holdInvoice, invoiceState, lab, list, lndChannel,
  clnInvoice, lndInvoice, newPreimage, record, settleInvoice, text, until, LabInvalidError, type Lab, type Node,
} from '../../helpers/lab.js';

const label = (what: string): string => `fact-${what}-${randomBytes(6).toString('hex')}`;
function clnScid(l: Lab, node: 'cln-p' | 'cln-r' | 'cln-m', peer: Node): string {
  const found = list(l.ok(node, ['listpeerchannels', `id=${l.pubkeys[peer]}`])['channels'], 'peer channels');
  if (found.length !== 1 || !found[0]) throw new LabInvalidError(`${node} has no single channel with ${peer}`);
  return text(found[0]['short_channel_id'], 'short channel id');
}
/** The gossip view of one direction of a channel (listchannels, C14 policy names). */
function policy(l: Lab, viewer: 'cln-m' | 'cln-r', scid: string, source: Node): Record<string, unknown> {
  const found = list(l.ok(viewer, ['listchannels', `short_channel_id=${scid}`])['channels'], 'channels').filter(row => row['source'] === l.pubkeys[source]);
  if (found.length !== 1 || !found[0]) throw new LabInvalidError(`${viewer} has no gossip for ${scid} from ${source}`);
  return found[0];
}
const forwardFee = (edge: Record<string, unknown>, amount: bigint): bigint =>
  BigInt(Number(edge['base_fee_millisatoshi'])) + amount * BigInt(Number(edge['fee_per_millionth'])) / 1_000_000n;
interface Hop { short_channel_id_dir: string; node_id_out: string; amount_out_msat: string; cltv_out: number }

/**
 * Route for the CLN-M cycle out through channel 2 and back through channel 5 (C11; lightningd/plugins rebalance.py setup_routing_fees):
 * a layer disabling our node, getroutes between the two peers, our out-hop prepended and the
 * in-hop appended with amounts and deltas computed backwards from the final CLTV.
 */
function cycle(l: Lab, amount: bigint, finalCltv: number): { route: Hop[]; fee: bigint } {
  const ch2 = clnScid(l, 'cln-m', 'lnd-r'), ch5 = clnScid(l, 'cln-m', 'cln-r');
  const inEdge = policy(l, 'cln-m', ch5, 'cln-r');
  const atInPeer = amount + forwardFee(inEdge, amount), cltvAtInPeer = finalCltv + Number(inEdge['delay']);
  const layer = label('layer');
  l.ok('cln-m', ['askrene-create-layer', `layer=${layer}`]);
  try {
    l.ok('cln-m', ['askrene-disable-node', `layer=${layer}`, `node=${l.pubkeys['cln-m']}`]);
    const answer = l.ok('cln-m', ['getroutes', `source=${l.pubkeys['lnd-r']}`, `destination=${l.pubkeys['cln-r']}`, `amount_msat=${atInPeer.toString()}`,
      `layers=${JSON.stringify([layer])}`, 'maxfee_msat=10000000', `final_cltv=${String(cltvAtInPeer)}`, 'maxparts=1']);
    const routes = list(answer['routes'], 'routes');
    const path = list(routes[0]?.['path'], 'path');
    const first = path[0];
    if (routes.length !== 1 || !first) throw new LabInvalidError('getroutes did not return one path');
    const route: Hop[] = [
      { short_channel_id_dir: `${ch2}/${String(direction(l.pubkeys['cln-m'], l.pubkeys['lnd-r']))}`, node_id_out: l.pubkeys['lnd-r'], amount_out_msat: String(first['amount_in_msat']), cltv_out: Number(first['cltv_in']) },
      ...path.map(hop => ({ short_channel_id_dir: text(hop['short_channel_id_dir'], 'dir'), node_id_out: text(hop['node_id_out'], 'node'), amount_out_msat: String(hop['amount_out_msat']), cltv_out: Number(hop['cltv_out']) })),
      { short_channel_id_dir: `${ch5}/${String(direction(l.pubkeys['cln-r'], l.pubkeys['cln-m']))}`, node_id_out: l.pubkeys['cln-m'], amount_out_msat: amount.toString(), cltv_out: finalCltv },
    ];
    return { route, fee: BigInt(String(first['amount_in_msat'])) - amount };
  } finally { l.run('cln-m', ['askrene-remove-layer', `layer=${layer}`]); }
}
async function ownInvoice(l: Lab, amount: bigint, what: string): Promise<{ hash: string; preimage: string; secret: string; label: string }> {
  const { preimage, hash } = newPreimage();
  const name = label(what);
  const invoice = await clnInvoice(l, amount, name, what, preimage);
  if (invoice['payment_hash'] !== hash) throw new LabInvalidError('invoice hash differs from the supplied preimage');
  return { hash, preimage, secret: text(invoice['payment_secret'], 'payment secret'), label: name };
}
function sendpay(l: Lab, route: Hop[], hash: string, secret: string, amount: bigint): Record<string, unknown> {
  l.ok('cln-m', ['sendpay', `route=${JSON.stringify(route)}`, `payment_hash=${hash}`, `payment_secret=${secret}`, `amount_msat=${amount.toString()}`]);
  return l.ok('cln-m', ['waitsendpay', `payment_hash=${hash}`, 'timeout=60']);
}

describe('CLN facts', () => {
  // A3 / cln#9032: askrene getroutes refuses a circular request; 26.06.9 has no allow_circular.
  it('CP-010/RA3 getroutes with our own id as source and destination is refused and allow_circular is unknown', () => {
    const l = lab();
    const self = l.pubkeys['cln-m'];
    const base = ['getroutes', `source=${self}`, `destination=${self}`, 'amount_msat=1000000', 'layers=["auto.localchans"]', 'maxfee_msat=100000', 'final_cltv=18'];
    expect(l.run('cln-m', base)).toEqual({ kind: 'rejected', code: -32602, message: 'source and destination must be different' });
    const circular = l.run('cln-m', [...base, 'allow_circular=true']);
    expect(circular.kind === 'rejected' && circular.code === -32602 && circular.message.startsWith('unknown parameter: allow_circular')).toBe(true);
  });

  // A4 / C19: the clnrest CA copied out of the container pins the server; the server
  // certificate names cln and localhost (plugins/grpc-plugin tls.rs certificate generation).
  it('CP-010/RA4 the copied clnrest CA pins the server with hostname verification and another CA is refused', async () => {
    const l = lab();
    await cleanProxies(l);
    const answer = await clnRest(l, 'getinfo', {}, 'read');
    expect([answer.status, record(answer.body, 'getinfo')['id']]).toEqual([201, l.pubkeys['cln-m']]);
    await expect(clnRest(l, 'getinfo', {}, 'read', copiedCertificate(l, 'lnd-r'))).rejects.toMatchObject({ code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' });
    await expect(clnRest(l, 'getinfo', {}, 'read', copiedCertificate(l, 'cln-m'), 'cln-m')).rejects.toMatchObject({ code: 'ERR_TLS_CERT_ALTNAME_INVALID' });
  }, 180_000);

  // A9 / SPEC 11.1: the pinned index digest and the 26.06.9 clnrest option names.
  it('CP-010/RA9 CLN-M runs the pinned v26.06.9 digest with clnrest-port, clnrest-host and clnrest-protocol', async () => {
    const l = lab();
    const id = spawnSync('docker', ['ps', '-q', '--filter', `label=com.docker.compose.project=${l.declaration.project}`, '--filter', 'label=com.docker.compose.service=cln-m'], { shell: false, windowsHide: true, encoding: 'utf8' }).stdout.trim();
    const image = spawnSync('docker', ['inspect', '--format', '{{.Image}}', id], { shell: false, windowsHide: true, encoding: 'utf8' }).stdout.trim();
    const digests = JSON.parse(spawnSync('docker', ['image', 'inspect', '--format', '{{json .RepoDigests}}', image], { shell: false, windowsHide: true, encoding: 'utf8' }).stdout) as unknown;
    expect(digests).toContain('elementsproject/lightningd@sha256:de74289ddcccb68cd60543b08b2b8594002d819125d200492e17a95166d56577');
    const option = (name: string): Record<string, unknown> => record(record(l.ok('cln-m', ['listconfigs', `config=${name}`])['configs'], 'configs')[name], name);
    expect(option('clnrest-port')).toMatchObject({ value_int: 3010, source: 'cmdline' });
    expect(option('clnrest-host')).toMatchObject({ value_str: '0.0.0.0', source: 'cmdline' });
    expect(option('clnrest-protocol')).toMatchObject({ value_str: 'https' });
    await cleanProxies(l);
    expect((await clnRest(l, 'getinfo', {}, 'read')).status).toBe(201);
  }, 180_000);

  // A14: clnrest answers success with 201 and a failed command with a non-2xx status whose
  // JSON body carries the lightningd code and message (waitsendpay 208, getroutes 205; C7, C9).
  it('CP-010/RA14 clnrest reports lightningd errors as a non-2xx status with the code and message', async () => {
    const l = lab();
    await cleanProxies(l);
    const unknown = await clnRest(l, 'waitsendpay', { payment_hash: '00'.repeat(32), timeout: 0 });
    const noRoute = await clnRest(l, 'getroutes', { source: l.pubkeys['cln-m'], destination: l.pubkeys['cln-p'], amount_msat: 100_000_000_000, layers: ['auto.localchans'], maxfee_msat: 1_000_000, final_cltv: 18 });
    for (const [answer, code] of [[unknown, 208], [noRoute, 205]] as const) {
      expect(answer.status >= 400 && answer.status <= 599, `status ${String(answer.status)}`).toBe(true);
      const body = record(answer.body, 'clnrest error');
      expect([body['code'], typeof body['message']]).toEqual([code, 'string']);
    }
  }, 180_000);

  // A16 / doc/schemas/askrene-listlayers.json, askrene-remove-layer.json: askrene presence is probed read-only and a created layer is removed.
  it('CP-010/RA16 askrene-listlayers works with the read rune and askrene-remove-layer removes a created layer', async () => {
    const l = lab();
    await cleanProxies(l);
    const name = label('a16');
    l.ok('cln-m', ['askrene-create-layer', `layer=${name}`]);
    const names = async (): Promise<unknown[]> => {
      const answer = await clnRest(l, 'askrene-listlayers', {}, 'read');
      if (answer.status !== 201) throw new LabInvalidError(`askrene-listlayers answered ${String(answer.status)}`);
      return list(record(answer.body, 'layers')['layers'], 'layers').map(layer => layer['layer']);
    };
    try { expect(await names()).toContain(name); }
    finally { expect(l.run('cln-m', ['askrene-remove-layer', `layer=${name}`]).kind).toBe('accepted'); }
    expect(await names()).not.toContain(name);
  }, 180_000);

  // A27: updates.remote is the in-peer's policy for forwarding to us, the same as its gossip.
  it('CP-010/RA27 listpeerchannels updates.remote equals the peer direction in listchannels', () => {
    const l = lab();
    const channels = list(l.ok('cln-m', ['listpeerchannels'])['channels'], 'peer channels');
    expect(channels).toHaveLength(2);
    for (const channel of channels) {
      const peer = (Object.keys(l.pubkeys) as Node[]).find(node => l.pubkeys[node] === channel['peer_id']);
      if (!peer) throw new LabInvalidError('unknown peer');
      const remote = record(record(channel['updates'], 'updates')['remote'], 'updates.remote');
      const gossip = policy(l, 'cln-m', text(channel['short_channel_id'], 'scid'), peer);
      expect([remote['fee_base_msat'], remote['fee_proportional_millionths'], remote['cltv_expiry_delta'], remote['htlc_minimum_msat'], remote['htlc_maximum_msat']])
        .toEqual([gossip['base_fee_millisatoshi'], gossip['fee_per_millionth'], gossip['delay'], gossip['htlc_minimum_msat'], gossip['htlc_maximum_msat']]);
      expect([remote['fee_base_msat'], remote['fee_proportional_millionths'], remote['cltv_expiry_delta']]).toEqual([1000, 1000, peer.startsWith('lnd-') ? 80 : 34]);
    }
  });

  // A26: invoice defaults. lnd AddInvoice uses the node's time lock delta, 80 by default
  // (chainreg DefaultBitcoinTimeLockDelta); CLN invoice uses cltv-final, 10 on test networks
  // (lightningd/options.c testnet_config).
  it('CP-010/RA26 default minimum final CLTV is 80 for LND AddInvoice and 10 for a regtest CLN invoice', async () => {
    const l = lab();
    const lnd = await lndInvoice(l, 'lnd-r', 1_000_000n, newPreimage().preimage);
    expect(l.ok('lnd-r', ['decodepayreq', text(lnd['payment_request'], 'bolt11')])['cltv_expiry']).toBe('80');
    const cln = await clnInvoice(l, 1_000_000n, label('a26'), 'a26', newPreimage().preimage);
    expect(l.ok('cln-m', ['decode', `string=${text(cln['bolt11'], 'bolt11')}`])['min_final_cltv_expiry']).toBe(10);
  });

  // A13 / C8: listinvoices filters by label and payment_hash; listsendpays carries amount_msat,
  // amount_sent_msat and payment_preimage, and their difference is the fee the bookkeeper posts.
  it('CP-010/RA13 a CLN-M rebalance fee from listsendpays equals the route fee and the bookkeeper invoice event', async () => {
    const l = lab();
    const amount = 100_000_000n;
    const invoice = await ownInvoice(l, amount, 'a13');
    const { route, fee } = cycle(l, amount, 18);
    // lnd-r forwards 100 101 000 at 1000 + 1000 ppm, cln-r forwards 100 000 000 at 1000 + 1000 ppm
    expect(fee).toBe(202_101n);
    expect(sendpay(l, route, invoice.hash, invoice.secret, amount)['status']).toBe('complete');
    // doc/schemas/listinvoices.json: optional label, invstring, payment_hash filters.
    const byLabel = list(l.ok('cln-m', ['listinvoices', `label=${invoice.label}`])['invoices'], 'invoices');
    const byHash = list(l.ok('cln-m', ['listinvoices', `payment_hash=${invoice.hash}`])['invoices'], 'invoices');
    expect(byLabel.map(row => [row['label'], row['status'], row['payment_hash'], row['amount_received_msat']])).toEqual([[invoice.label, 'paid', invoice.hash, Number(amount)]]);
    expect(byHash.map(row => row['label'])).toEqual([invoice.label]);
    const parts = list(l.ok('cln-m', ['listsendpays', `payment_hash=${invoice.hash}`])['payments'], 'sendpays');
    expect(parts.map(part => [part['status'], part['amount_msat'], part['amount_sent_msat'], part['payment_preimage']]))
      .toEqual([['complete', Number(amount), Number(amount + fee), invoice.preimage]]);
    const events = list(l.ok('cln-m', ['bkpr-listaccountevents'])['events'], 'events').filter(event => event['payment_id'] === invoice.hash && event['tag'] === 'invoice');
    expect(events.reduce((sum, event) => sum + BigInt(Number(event['fees_msat'] ?? 0)), 0n)).toBe(fee);
  }, 180_000);

  // A28 / C5, observed in the lab: each sendpay entry carries what node_id_out receives, and
  // cltv_out is a CLTV delta that lightningd adds to the current block height, exactly as the
  // getroutes path reports it (lightningd/pay.c: base expiry = block height + 1 + delay).
  it('CP-010/RA28 sendpay settles a route whose cltv_out values are the getroutes deltas relative to the height', async () => {
    const l = lab();
    const amount = 50_000_000n;
    const invoice = await ownInvoice(l, amount, 'a28');
    const planned = cycle(l, amount, 18);
    // Deltas, not heights: the final 18, plus cln-r's 34, plus lnd-r's 80 (labs/topology.json policies).
    expect(planned.route.map(hop => hop.cltv_out)).toEqual([18 + 34 + 80, 18 + 34, 18]);
    expect(sendpay(l, planned.route, invoice.hash, invoice.secret, amount)['status']).toBe('complete');
    const paid = list(l.ok('cln-m', ['listinvoices', `payment_hash=${invoice.hash}`])['invoices'], 'invoices');
    expect(paid.map(row => [row['label'], row['payment_hash']])).toEqual([[invoice.label, invoice.hash]]);
    expect(paid.map(row => [row['status'], row['amount_received_msat']])).toEqual([['paid', Number(amount)]]);
  }, 180_000);

  // A7 / C7, C8: waitsendpay 200 means still in flight; listsendpays then reports pending and later
  // complete. The HTLC is held by a hold invoice at lnd-p (route cln-m -> lnd-r -> lnd-p); a CLN
  // node cannot hold its own invoice, so the receiver-side state is read at lnd-p.
  it('CP-010/RA7 after waitsendpay 200 listsendpays reports pending and then complete in step with the held invoice', async () => {
    const l = lab();
    const amount = 50_000_000n;
    const hold = holdInvoice(l, 'lnd-p', Number(amount / 1000n));
    const ch2 = clnScid(l, 'cln-m', 'lnd-r');
    const ch1 = text(lndChannel(l, 'lnd-r', 'lnd-p')['scid_str'], 'channel 1');
    const lastEdge = policy(l, 'cln-m', ch1, 'lnd-r');
    const route: Hop[] = [
      { short_channel_id_dir: `${ch2}/${String(direction(l.pubkeys['cln-m'], l.pubkeys['lnd-r']))}`, node_id_out: l.pubkeys['lnd-r'], amount_out_msat: (amount + forwardFee(lastEdge, amount)).toString(), cltv_out: 80 + Number(lastEdge['delay']) },
      { short_channel_id_dir: `${ch1}/${String(direction(l.pubkeys['lnd-r'], l.pubkeys['lnd-p']))}`, node_id_out: l.pubkeys['lnd-p'], amount_out_msat: amount.toString(), cltv_out: 80 },
    ];
    let settled = false;
    try {
      l.ok('cln-m', ['sendpay', `route=${JSON.stringify(route)}`, `payment_hash=${hold.hash}`, `payment_secret=${hold.paymentAddr}`, `amount_msat=${amount.toString()}`]);
      await invoiceState(l, 'lnd-p', hold.hash, 'ACCEPTED');
      const waiting = l.run('cln-m', ['waitsendpay', `payment_hash=${hold.hash}`, 'timeout=1']);
      expect(waiting.kind === 'rejected' ? waiting.code : waiting.kind).toBe(200);
      expect(list(l.ok('cln-m', ['listsendpays', `payment_hash=${hold.hash}`])['payments'], 'sendpays').map(part => part['status'])).toEqual(['pending']);
      await settleInvoice(l, 'lnd-p', hold.preimage); settled = true;
      expect(l.ok('cln-m', ['waitsendpay', `payment_hash=${hold.hash}`, 'timeout=60'])['status']).toBe('complete');
      expect(list(l.ok('cln-m', ['listsendpays', `payment_hash=${hold.hash}`])['payments'], 'sendpays').map(part => part['status'])).toEqual(['complete']);
      expect((await invoiceState(l, 'lnd-p', hold.hash, 'SETTLED'))['amt_paid_msat']).toBe(amount.toString());
    } finally {
      if (!settled) l.run('lnd-p', ['cancelinvoice', hold.hash]);
    }
  }, 180_000);

  // A20 / C23: a forward through CLN-R is booked with a tag other than `invoice`, and its
  // credit minus debit is the routing fee (1000 msat + 1000 ppm on the forwarded amount).
  it('CP-010/RA20 a payment forwarded by CLN-R is booked with a non-invoice tag whose net credit is the routing fee', async () => {
    const l = lab();
    const amount = 20_000_000n;
    const { preimage, hash } = newPreimage();
    const invoice = await clnInvoice(l, amount, label('a20'), 'a20', preimage);
    const paying = background(l.declaration.project, 'cln-p', ['xpay', `invstring=${text(invoice['bolt11'], 'bolt11')}`]);
    expect((await paying).exitCode).toBe(0);
    const events = await until(() => {
      const found = list(l.ok('cln-r', ['bkpr-listaccountevents'])['events'], 'events').filter(event => event['payment_id'] === hash);
      return found.length >= 2 ? found : undefined;
    }, 'bookkeeper forward events at cln-r');
    expect(events.every(event => event['type'] === 'channel' && event['tag'] !== 'invoice')).toBe(true);
    const net = events.reduce((sum, event) => sum + BigInt(Number(event['credit_msat'] ?? 0)) - BigInt(Number(event['debit_msat'] ?? 0)), 0n);
    expect(net).toBe(1000n + amount * 1000n / 1_000_000n);
  }, 180_000);
});
