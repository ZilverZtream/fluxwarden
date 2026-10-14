// Committed recordings (labs/fixtures/recordings, layout in test/labs/cp009-recordings.test.ts)
// against fresh answers of the running lab: the same request again over REST through the
// proxies, with lncli / lightning-cli as the independent oracle for the node identity and for
// every CLN result body. A recording comes from another lab instance, so instance identifiers,
// heights, times, balances and counters are compared by JSON type only (the list below);
// every other member, the key sets and the array lengths must be equal.
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';
import { same } from '../helpers/recording.js';
import {
  background, cleanProxies, clnRest, direction, holdInvoice, invoiceState, lab, list, lndChannel, lndRest, lndScid, lndStream,
  newPreimage, oneHopRoute, record, settleInvoice, text, LabInvalidError,
} from '../helpers/lab.js';

interface Recording { request: { method: string; path: string; body: unknown }; status: number; body?: unknown; lines?: unknown[] }
function recording(impl: 'lnd' | 'cln', id: string): Recording {
  const version = impl === 'lnd' ? '0.21.4-beta' : 'v26.06.9';
  const file = record(JSON.parse(readFileSync(join(repoRoot, 'labs', 'fixtures', 'recordings', impl, version, `${id}.json`), 'utf8')) as unknown, id);
  const response = record(file['response'], `${id} response`), request = record(file['request'], `${id} request`);
  const raw = response['body'], rawLines = response['lines'];
  return {
    request: { method: text(request['method'], 'method'), path: text(request['path'], 'path'), body: request['body'] },
    status: Number(response['status']),
    ...(typeof raw === 'string' ? { body: JSON.parse(raw) as unknown } : {}),
    ...(Array.isArray(rawLines) ? { lines: rawLines.map(line => JSON.parse(text(line, 'line')) as unknown) } : {}),
  };
}
const b64 = (hex: string): string => Buffer.from(hex, 'hex').toString('base64');
const b64url = (hex: string): string => `${Buffer.from(hex, 'hex').toString('base64url')}=`;
const statuses = (lines: unknown[]): unknown[] => lines.map(line => record(record(line, 'line')['result'], 'result')['status']);

describe('recordings equal fresh lab answers', () => {
  it('CP-009/R1 LND snapshot recordings equal fresh REST answers whose identity lncli confirms', async () => {
    const l = lab();
    await cleanProxies(l);
    for (const id of ['getinfo', 'listchannels', 'pendingchannels']) {
      const recorded = recording('lnd', id);
      const fresh = await lndRest(l, 'GET', recorded.request.path, undefined, 'read');
      expect(fresh.status, id).toBe(recorded.status);
      expect(same(recorded.body, fresh.body), id).toBeNull();
      if (id === 'getinfo') expect(record(fresh.body, 'getinfo')['identity_pubkey']).toBe(l.pubkeys['lnd-r']);
      // REST chan_id is the decimal short channel id lncli prints as scid (L29).
      if (id === 'listchannels') {
        expect(list(record(fresh.body, 'channels')['channels'], 'channels').map(channel => channel['chan_id']).sort())
          .toEqual(list(l.ok('lnd-r', ['listchannels'])['channels'], 'lncli channels').map(channel => channel['scid']).sort());
      }
    }
  }, 180_000);

  it('CP-009/R1 CLN snapshot recordings equal fresh lightning-cli results and clnrest statuses', async () => {
    const l = lab();
    await cleanProxies(l);
    for (const id of ['getinfo', 'listpeerchannels', 'listchannels']) {
      const recorded = recording('cln', id);
      expect(recorded.request).toEqual({ method: 'POST', path: `/v1/${id}`, body: {} });
      expect(same(recorded.body, l.ok('cln-m', [id])), id).toBeNull();
      expect((await clnRest(l, id, {}, 'read')).status, id).toBe(recorded.status);
    }
  }, 180_000);

  it('CP-009/R2 route query recordings equal fresh QueryRoutes and getroutes answers for the same live request', async () => {
    const l = lab();
    await cleanProxies(l);
    const queryroutes = recording('lnd', 'queryroutes');
    expect(queryroutes.request.path).toMatch(/^\/v1\/graph\/routes\/0[23][0-9a-f]{64}\/0$/);
    const request = { amt_msat: '100000000', outgoing_chan_ids: [lndScid(l, 'lnd-r', 'cln-r')], last_hop_pubkey: b64(l.pubkeys['cln-m']), fee_limit: { fixed_msat: '10000000' }, use_mission_control: true };
    expect(same(queryroutes.request.body, request)).toBeNull();
    const fresh = await lndRest(l, 'POST', `/v1/graph/routes/${l.pubkeys['lnd-r']}/0`, request);
    expect([fresh.status, same(queryroutes.body, fresh.body)]).toEqual([queryroutes.status, null]);
    expect(list(record(fresh.body, 'routes')['routes'], 'routes').map(route => list(route['hops'], 'hops').map(hop => hop['pub_key'])))
      .toEqual([[l.pubkeys['cln-r'], l.pubkeys['cln-m'], l.pubkeys['lnd-r']]]);
    const getroutes = recording('cln', 'getroutes');
    const params = { source: l.pubkeys['lnd-r'], destination: l.pubkeys['cln-r'], amount_msat: 100000000, layers: ['auto.localchans'], maxfee_msat: 10000000, final_cltv: 34, maxparts: 1 };
    expect(same(getroutes.request.body, params)).toBeNull();
    const live = l.ok('cln-m', ['getroutes', ...Object.entries(params).map(([key, value]) => `${key}=${typeof value === 'string' ? value : JSON.stringify(value)}`)]);
    expect(same(getroutes.body, live)).toBeNull();
  }, 180_000);

  it('CP-009/R3 the LND error envelope recordings equal the fresh answers exactly', async () => {
    const l = lab();
    await cleanProxies(l);
    for (const id of ['error-code-message', 'error-envelope']) {
      const recorded = recording('lnd', id);
      const fresh = await lndRest(l, 'GET', recorded.request.path, undefined, 'read');
      expect([fresh.status, fresh.body], id).toEqual([recorded.status, recorded.body]);
    }
  }, 180_000);

  it('CP-009/R4 TrackPaymentV2 recordings equal fresh streams of a held then settled payment and of a failed one', async () => {
    const l = lab();
    await cleanProxies(l);
    const hold = holdInvoice(l, 'lnd-p', 50_000);
    const route = JSON.parse(oneHopRoute(lndScid(l, 'lnd-r', 'lnd-p'), l.pubkeys['lnd-p'], 50_000_000n, l.height() + 100)) as { route: { hops: Record<string, unknown>[] } };
    const hop = route.route.hops[0];
    if (!hop) throw new LabInvalidError('route without hop');
    hop['mpp_record'] = { payment_addr: hold.paymentAddr, total_amt_msat: '50000000' };
    const sending = background(l.declaration.project, 'lnd-r', ['sendtoroute', '--payment_hash', hold.hash, '--routes', JSON.stringify(route)]);
    let settled = false, succeeded: { status: number; lines: unknown[] };
    try {
      await invoiceState(l, 'lnd-p', hold.hash, 'ACCEPTED');
      const deadline = performance.now() + 60_000;
      const path = `/v2/router/track/${b64url(hold.hash)}`;
      // LND-P settlement retargets the shared proxy. Close the initial subscription
      // first, then observe the actual terminal update on reconnection (router.proto).
      const heldStream = await lndStream(l, path, lines => statuses(lines).at(-1) === 'IN_FLIGHT', 60_000);
      expect([heldStream.status, statuses(heldStream.lines)]).toEqual([200, ['IN_FLIGHT']]);
      await settleInvoice(l, 'lnd-p', hold.preimage); settled = true;
      const terminal = await lndStream(l, path, lines => statuses(lines).at(-1) === 'SUCCEEDED', Math.max(1, deadline - performance.now()));
      succeeded = { status: terminal.status, lines: [...heldStream.lines, ...terminal.lines] };
    } finally {
      if (!settled) l.run('lnd-p', ['cancelinvoice', hold.hash]);
      await sending;
    }
    const recordedSucceeded = recording('lnd', 'track-succeeded');
    expect(statuses(succeeded.lines)).toEqual(statuses(recordedSucceeded.lines ?? []));
    expect([succeeded.status, same(recordedSucceeded.lines, succeeded.lines)]).toEqual([recordedSucceeded.status, null]);

    const unknown = newPreimage();
    l.run('lnd-r', ['sendtoroute', '--payment_hash', unknown.hash, '--routes', oneHopRoute(lndScid(l, 'lnd-r', 'lnd-p'), l.pubkeys['lnd-p'], 10_000_000n, l.height() + 100)]);
    const failed = await lndStream(l, `/v2/router/track/${b64url(unknown.hash)}`, lines => statuses(lines).at(-1) === 'FAILED');
    const recordedFailed = recording('lnd', 'track-failed');
    expect([failed.status, same(recordedFailed.lines, failed.lines)]).toEqual([recordedFailed.status, null]);
  }, 180_000);

  it('CP-009/R5 waitsendpay 200, listsendpays, listpays and bookkeeper recordings equal a fresh held CLN payment', async () => {
    const l = lab();
    await cleanProxies(l);
    const amount = 50_000_000n;
    const hold = holdInvoice(l, 'lnd-p', Number(amount / 1000n));
    const ch2 = list(l.ok('cln-m', ['listpeerchannels', `id=${l.pubkeys['lnd-r']}`])['channels'], 'channels')[0]?.['short_channel_id'];
    const ch1 = text(lndChannel(l, 'lnd-r', 'lnd-p')['scid_str'], 'channel 1');
    const edge = list(l.ok('cln-m', ['listchannels', `short_channel_id=${ch1}`])['channels'], 'edges').find(row => row['source'] === l.pubkeys['lnd-r']);
    if (typeof ch2 !== 'string' || !edge) throw new LabInvalidError('channels 1 and 2 are not visible from cln-m');
    const fee = BigInt(Number(edge['base_fee_millisatoshi'])) + amount * BigInt(Number(edge['fee_per_millionth'])) / 1_000_000n;
    const route = [
      { short_channel_id_dir: `${ch2}/${String(direction(l.pubkeys['cln-m'], l.pubkeys['lnd-r']))}`, node_id_out: l.pubkeys['lnd-r'], amount_out_msat: (amount + fee).toString(), cltv_out: 80 + Number(edge['delay']) },
      { short_channel_id_dir: `${ch1}/${String(direction(l.pubkeys['lnd-r'], l.pubkeys['lnd-p']))}`, node_id_out: l.pubkeys['lnd-p'], amount_out_msat: amount.toString(), cltv_out: 80 },
    ];
    let settled = false;
    try {
      l.ok('cln-m', ['sendpay', `route=${JSON.stringify(route)}`, `payment_hash=${hold.hash}`, `payment_secret=${hold.paymentAddr}`, `amount_msat=${amount.toString()}`]);
      await invoiceState(l, 'lnd-p', hold.hash, 'ACCEPTED');
      const waiting = await clnRest(l, 'waitsendpay', { payment_hash: hold.hash, timeout: 1 });
      const recorded = recording('cln', 'waitsendpay-200');
      expect([waiting.status, same(recorded.body, waiting.body)]).toEqual([recorded.status, null]);
      await settleInvoice(l, 'lnd-p', hold.preimage); settled = true;
      expect(l.ok('cln-m', ['waitsendpay', `payment_hash=${hold.hash}`, 'timeout=60'])['status']).toBe('complete');
    } finally { if (!settled) l.run('lnd-p', ['cancelinvoice', hold.hash]); }
    for (const id of ['listsendpays', 'listpays']) {
      const recorded = recording('cln', id);
      expect(same(recorded.body, l.ok('cln-m', [id, `payment_hash=${hold.hash}`])), id).toBeNull();
    }
    // The bookkeeper history grows; every recorded event has a fresh counterpart of the same shape.
    const events = list(record(recording('cln', 'bkpr-listaccountevents').body, 'events')['events'], 'recorded events');
    const now = list(l.ok('cln-m', ['bkpr-listaccountevents'])['events'], 'events');
    for (const event of events) expect(now.some(candidate => same(event, candidate) === null), `${String(event['type'])}/${String(event['tag'])}`).toBe(true);
  }, 180_000);

  // INV-11 on live tool output: a fresh run of the tool against this lab writes no registered
  // secret (credentials it read or created, preimages it generated) in any encoding.
  it('CP-009/Rleak a fresh recording run writes no registered credential or preimage in any encoding', async () => {
    const l = lab();
    const owner = process.env['FLUXWARDEN_LAB_OWNER'], tmp = process.env['FLUXWARDEN_TEST_TMP'], evidenceDir = process.env['FLUXWARDEN_EVIDENCE_DIR'];
    const sentinelRoot = l.declaration.sentinelRoot;
    if (!owner || !tmp || !evidenceDir || !sentinelRoot) throw new LabInvalidError('owner, private temporary, evidence and sentinel roots are required');
    const out = join(tmp, `cp009-run-${randomBytes(4).toString('hex')}`);
    const run = spawnSync(process.execPath, [join(repoRoot, 'scripts', 'make-fixtures.mjs'), '--owner', owner, '--out', out], { shell: false, windowsHide: true, encoding: 'utf8', timeout: 170_000 });
    expect(run.status).toBe(0);
    const scanner = await import(pathToFileURL(join(repoRoot, 'scripts', 'leak-check.mjs')).href) as { findLeaks(options: Record<string, unknown>): unknown };
    const registered = readdirSync(sentinelRoot).filter(name => name.startsWith('recording-'));
    expect(registered.length).toBeGreaterThan(0);
    expect(scanner.findLeaks({ root: repoRoot, sentinels: join(repoRoot, 'test', 'sentinels.json'), sentinelDir: sentinelRoot, testTmp: tmp, evidenceDir, paths: [out], commandOutput: `${run.stdout}${run.stderr}` })).toBeNull();
  }, 180_000);
});
