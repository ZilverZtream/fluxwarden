// Lab facts for LND (ARCHITECTURE.md §6). Expected values come from the pinned lnd
// v0.21.4-beta behaviour cited per test and from the lab topology (labs/topology.json:
// every channel 5 000 000 sat, base fee 1000 msat, 1000 ppm, LND delta 80, CLN delta 34).
// Oracles: lncli in the containers; REST only where the assumption is about REST.
// Payment amounts are whole multiples of 1000 sat so LND's sat-denominated balances stay exact.
import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  background, cleanProxies, holdInvoice, invoiceState, lab, list, lndChannel, lndRest, lndScid, lndStream,
  clnInvoice, lndInvoice, newPreimage, oneHopRoute, record, settleInvoice, text, toxiproxy, until, LabInvalidError, type Lab,
} from '../../helpers/lab.js';

const b64 = (hex: string): string => Buffer.from(hex, 'hex').toString('base64');
// TrackPaymentV2 takes the hash as padded base64url in the path (L24; unpadded is a 400).
const b64url = (hex: string): string => `${Buffer.from(hex, 'hex').toString('base64url')}=`;
const htlcWeight = 172n; // lnd input.HTLCWeight

/** One first-hop probe: accepted when the HTLC left our node and the destination refused the unknown hash. */
function probe(l: Lab, chanId: string, pubkey: string, amountMsat: bigint): boolean {
  const { hash } = newPreimage();
  const attempt = l.ok('lnd-r', ['sendtoroute', '--payment_hash', hash, '--routes', oneHopRoute(chanId, pubkey, amountMsat, l.height() + 100)]);
  const failure = record(attempt['failure'], 'probe failure');
  if (attempt['status'] !== 'FAILED') throw new LabInvalidError('a probe to an unknown hash settled');
  if (failure['failure_source_index'] === 1 && failure['code'] === 'INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS') return true;
  if (failure['failure_source_index'] === 0) return false;
  throw new LabInvalidError(`unexpected probe failure ${String(failure['code'])}`);
}
/** Largest single first-hop HTLC lnd accepts, by bisection between an accepted and a refused amount. */
function largestAccepted(l: Lab, chanId: string, pubkey: string, accepted: bigint, refused: bigint): bigint {
  let low = accepted, high = refused;
  while (high - low > 1n) { const middle = (low + high) / 2n; if (probe(l, chanId, pubkey, middle)) low = middle; else high = middle; }
  return low;
}

/** QueryRoutes POST for the LND-R cycle out through channel 3 and back in through channel 2 (A5 field encodings). */
async function cycleRoute(l: Lab, amountMsat: bigint, extra: Record<string, unknown> = {}): Promise<{ status: number; body: Record<string, unknown> }> {
  const answer = await lndRest(l, 'POST', `/v1/graph/routes/${l.pubkeys['lnd-r']}/0`, {
    amt_msat: amountMsat.toString(), outgoing_chan_ids: [lndScid(l, 'lnd-r', 'cln-r')], last_hop_pubkey: b64(l.pubkeys['cln-m']), use_mission_control: true, ...extra,
  });
  return { status: answer.status, body: record(answer.body, 'QueryRoutes answer') };
}
function onlyRoute(body: Record<string, unknown>): Record<string, unknown> {
  const routes = list(body['routes'], 'routes');
  if (routes.length !== 1 || !routes[0]) throw new LabInvalidError('QueryRoutes did not return one route');
  return routes[0];
}
/** A circular LND-R rebalance: own invoice, QueryRoutes, mpp_record on the last hop (L8, L9), one SendToRouteV2. */
async function lndRebalance(l: Lab, amountMsat: bigint): Promise<{ hash: string; route: Record<string, unknown>; attempt: Record<string, unknown> }> {
  const { preimage, hash } = newPreimage();
  const invoice = await lndInvoice(l, 'lnd-r', amountMsat, preimage);
  const route = onlyRoute((await cycleRoute(l, amountMsat, { fee_limit: { fixed_msat: '10000000' } })).body);
  const hops = list(route['hops'], 'route hops');
  const last = hops.at(-1);
  if (!last) throw new LabInvalidError('route without hops');
  last['mpp_record'] = { payment_addr: b64(text(invoice['payment_addr'], 'payment addr')), total_amt_msat: amountMsat.toString() };
  const sent = await lndRest(l, 'POST', '/v2/router/route/send', { payment_hash: b64(hash), route });
  return { hash, route, attempt: record(sent.body, 'SendToRouteV2 answer') };
}
function payment(l: Lab, node: 'lnd-p' | 'lnd-r', hash: string): Record<string, unknown> {
  const found = list(l.ok(node, ['listpayments', '--include_incomplete', '--max_payments', '1000'])['payments'], 'payments').filter(row => row['payment_hash'] === hash);
  if (found.length !== 1 || !found[0]) throw new LabInvalidError(`${node} lists no single payment ${hash}`);
  return found[0];
}

describe('LND facts', () => {
  // A2: lnd AvailableBalance (lnwallet/channel.go availableCommitmentBalance) versus
  // ARCHITECTURE 4.1: local_balance - chan_reserve - [opener: 2*fee_per_kw*(commit_weight+172)/1000 + 2*330] sat.
  it('CP-010/RA2 the derived LND spendable never exceeds the largest first-hop HTLC lnd accepts on opener and non-opener channels', () => {
    const l = lab();
    for (const peer of ['cln-m', 'lnd-p'] as const) {
      const channel = lndChannel(l, 'lnd-r', peer);
      if (list(channel['pending_htlcs'], 'pending htlcs').length) throw new LabInvalidError('channel has HTLCs in flight');
      const opener = channel['initiator'] === true;
      const reserve = BigInt(text(record(channel['local_constraints'], 'constraints')['chan_reserve_sat'], 'reserve'));
      const buffer = opener ? 2n * BigInt(text(channel['fee_per_kw'], 'fee rate')) * (BigInt(text(channel['commit_weight'], 'weight')) + htlcWeight) / 1000n + 660n : 0n;
      const derived = (BigInt(text(channel['local_balance'], 'local balance')) - reserve - buffer) * 1000n;
      const chanId = text(channel['scid'], 'scid');
      expect(probe(l, chanId, l.pubkeys[peer], derived), `${peer} channel: an HTLC of the derived spendable is accepted`).toBe(true);
      const ceiling = derived + 10_000_000n;
      if (probe(l, chanId, l.pubkeys[peer], ceiling)) throw new LabInvalidError('probe ceiling was accepted');
      // Observed 2026-10-13: non-opener channel exact (950 000 sat accepted, +1 msat refused); opener channel
      // lnd accepted 3 692 000 sat against a derived 3 689 430 sat, a conservative gap of 2 570 sat.
      expect(largestAccepted(l, chanId, l.pubkeys[peer], derived, ceiling), `${peer} channel (${opener ? 'opener' : 'non-opener'}): lnd accepts at least the derived spendable`).toBeGreaterThanOrEqual(derived);
    }
  }, 180_000);

  // A1 (charge-lnd and LNDg add pending outgoing HTLCs back): local_balance already excludes a pending outgoing HTLC; channel 1
  // was opened by lnd-p, so lnd-r's balance moves by the HTLC amount alone.
  it('CP-010/RA1 an outgoing HTLC held at the far end lowers local_balance by exactly its amount and is listed once', async () => {
    const l = lab();
    const before = lndChannel(l, 'lnd-r', 'lnd-p');
    if (before['initiator'] !== false || list(before['pending_htlcs'], 'pending htlcs').length) throw new LabInvalidError('channel 1 must be peer-opened and idle');
    const hold = holdInvoice(l, 'lnd-p', 100_000);
    const paying = background(l.declaration.project, 'lnd-r', ['payinvoice', '--force', '--json', hold.bolt11]);
    try {
      await invoiceState(l, 'lnd-p', hold.hash, 'ACCEPTED');
      const during = lndChannel(l, 'lnd-r', 'lnd-p');
      expect(BigInt(text(before['local_balance'], 'before')) - BigInt(text(during['local_balance'], 'during'))).toBe(100_000n);
      expect(list(during['pending_htlcs'], 'pending htlcs').map(htlc => ({ incoming: htlc['incoming'], amount: htlc['amount'], hash: htlc['hash_lock'] })))
        .toEqual([{ incoming: false, amount: '100000', hash: hold.hash }]);
      expect(during['unsettled_balance']).toBe('100000');
    } finally {
      l.run('lnd-p', ['cancelinvoice', hold.hash]);
      await paying;
    }
    expect(lndChannel(l, 'lnd-r', 'lnd-p')['local_balance']).toBe(before['local_balance']);
  }, 180_000);

  // A5 / L11, L12: QueryRoutes POST /v1/graph/routes/{self}/0 with uint64 ids as strings and
  // bytes as base64; cltv_limit counts the final delta. Topology: the cycle 3 -> 5 -> 2 is unique.
  it('CP-010/RA5 QueryRoutes POST honours outgoing_chan_ids, last_hop_pubkey, ignored_pairs and cltv_limit', async () => {
    const l = lab();
    await cleanProxies(l);
    const height = l.height();
    const route = onlyRoute((await cycleRoute(l, 100_000_000n, { cltv_limit: 148 })).body);
    const hops = list(route['hops'], 'hops');
    expect(hops.map(hop => hop['pub_key'])).toEqual([l.pubkeys['cln-r'], l.pubkeys['cln-m'], l.pubkeys['lnd-r']]);
    expect(hops[0]?.['chan_id']).toBe(lndScid(l, 'lnd-r', 'cln-r'));
    expect(hops[2]?.['chan_id']).toBe(lndScid(l, 'lnd-r', 'cln-m'));
    // default final delta 80 plus the two CLN deltas of 34 is exactly the limit
    expect(Number(route['total_time_lock']) - height).toBe(148);
    const tighter = await cycleRoute(l, 100_000_000n, { cltv_limit: 147 });
    expect(tighter).toEqual({ status: 500, body: { code: 2, message: 'unable to find a path to destination', details: [] } });
    const ignored = await cycleRoute(l, 100_000_000n, { ignored_pairs: [{ from: b64(l.pubkeys['cln-r']), to: b64(l.pubkeys['cln-m']) }] });
    expect(ignored).toEqual({ status: 500, body: { code: 2, message: 'unable to find a path to destination', details: [] } });
  }, 180_000);

  // A10 / L13: paths over fee_limit are dropped in pathfinding; the answer is NO_ROUTE.
  it('CP-010/RA10 a fee limit one msat below the cheapest route fee is reported only as no path', async () => {
    const l = lab();
    const fee = BigInt(text(onlyRoute((await cycleRoute(l, 100_000_000n)).body)['total_fees_msat'], 'route fee'));
    // two forwarding hops at 1000 msat + 1000 ppm: 101000 (cln-m on 100 000 000) + 101101 (cln-r on 100 101 000)
    expect(fee).toBe(202_101n);
    expect((await cycleRoute(l, 100_000_000n, { fee_limit: { fixed_msat: fee.toString() } })).status).toBe(200);
    expect(await cycleRoute(l, 100_000_000n, { fee_limit: { fixed_msat: (fee - 1n).toString() } }))
      .toEqual({ status: 500, body: { code: 2, message: 'unable to find a path to destination', details: [] } });
  }, 180_000);

  // A22 / L12: QueryRoutes subtracts only the final delta; BlockPadding (3) is added by
  // SendPaymentV2's payment session, not by QueryRoutes. A22 is therefore not true: the
  // returned total_time_lock excludes padding and FluxWarden keeps adding 3 (SPEC 4.5 V5).
  it('CP-010/RA22 QueryRoutes total_time_lock is height plus final delta plus hop deltas without block padding', async () => {
    const l = lab();
    const height = l.height();
    const route = onlyRoute((await cycleRoute(l, 100_000_000n)).body);
    const hops = list(route['hops'], 'hops');
    expect(hops.at(-1)?.['expiry']).toBe(height + 80);
    expect(route['total_time_lock']).toBe(height + 80 + 34 + 34);
  }, 180_000);

  // A24 / lnrpc QueryRoutesRequest.final_cltv_delta (tag 4).
  it('CP-010/RA24 QueryRoutes takes final_cltv_delta from the request body', async () => {
    const l = lab();
    const height = l.height();
    const route = onlyRoute((await cycleRoute(l, 100_000_000n, { final_cltv_delta: 40 })).body);
    expect(list(route['hops'], 'hops').at(-1)?.['expiry']).toBe(height + 40);
    expect(route['total_time_lock']).toBe(height + 40 + 68);
  }, 180_000);

  // A6 / L7, L8, L9: one SendToRouteV2 with total_amt_msat equal to the amount is one HTLC that settles the invoice.
  it('CP-010/RA6 a circular SendToRouteV2 with total_amt_msat equal to the amount settles with exactly one HTLC', async () => {
    const l = lab();
    await cleanProxies(l);
    const { hash, attempt } = await lndRebalance(l, 100_000_000n);
    expect(attempt['status']).toBe('SUCCEEDED');
    const tracked = await lndStream(l, `/v2/router/track/${b64url(hash)}`, lines => lines.length >= 1);
    expect(tracked.status).toBe(200);
    const first = record(record(tracked.lines[0], 'track line')['result'], 'track result');
    expect(first['status']).toBe('SUCCEEDED');
    expect(list(first['htlcs'], 'htlcs').map(htlc => htlc['status'])).toEqual(['SUCCEEDED']);
    const invoice = l.ok('lnd-r', ['lookupinvoice', hash]);
    expect([invoice['state'], invoice['amt_paid_msat']]).toEqual(['SETTLED', '100000000']);
    expect(list(invoice['htlcs'], 'invoice htlcs').filter(htlc => htlc['state'] === 'SETTLED')).toHaveLength(1);
  }, 180_000);

  // A29: ListPayments fee_msat versus the route's total_fees_msat for a SendToRouteV2 payment.
  it('CP-010/RA29 ListPayments fee_msat equals the dispatched route total_fees_msat', async () => {
    const l = lab();
    const { hash, route, attempt } = await lndRebalance(l, 100_000_000n);
    expect(attempt['status']).toBe('SUCCEEDED');
    const paid = payment(l, 'lnd-r', hash);
    expect(paid['status']).toBe('SUCCEEDED');
    expect(paid['fee_msat']).toBe(route['total_fees_msat']);
    expect(paid['fee_msat']).toBe('202101');
  }, 180_000);

  // A8 / L25: after a REST gap the first TrackPaymentV2 message is the terminal state.
  it('CP-010/RA8 TrackPaymentV2 opened after a proxy cut returns the payment settled meanwhile as its first message', async () => {
    const l = lab();
    await cleanProxies(l);
    const hold = holdInvoice(l, 'lnd-p', 50_000);
    const paying = background(l.declaration.project, 'lnd-r', ['payinvoice', '--force', '--json', hold.bolt11]);
    let settled = false;
    try {
      await invoiceState(l, 'lnd-p', hold.hash, 'ACCEPTED');
      const live = await lndStream(l, `/v2/router/track/${b64url(hold.hash)}`, lines => lines.length >= 1);
      expect(record(record(live.lines[0], 'line')['result'], 'result')['status']).toBe('IN_FLIGHT');
      await toxiproxy(l, 'POST', '/proxies/lnd-r-rest', { enabled: false });
      await settleInvoice(l, 'lnd-p', hold.preimage); settled = true;
      const done = await paying;
      expect(JSON.parse(done.stdout) as unknown).toMatchObject({ status: 'SUCCEEDED' });
    } finally {
      await toxiproxy(l, 'POST', '/proxies/lnd-r-rest', { enabled: true });
      if (!settled) { l.run('lnd-p', ['cancelinvoice', hold.hash]); await paying; }
    }
    const after = await lndStream(l, `/v2/router/track/${b64url(hold.hash)}`, lines => lines.length >= 1);
    const first = record(record(after.lines[0], 'line')['result'], 'result');
    expect([first['status'], first['payment_preimage']]).toEqual(['SUCCEEDED', hold.preimage]);
  }, 180_000);

  // A11 / invoicesrpc CancelInvoice: open regular invoices are cancelled, settled ones are refused,
  // and an HTLC arriving after cancellation fails with incorrect payment details.
  it('CP-010/RA11 CancelInvoice cancels an open regular invoice, refuses a settled one and later HTLCs fail', async () => {
    const l = lab();
    const cancelled = newPreimage();
    const open = await lndInvoice(l, 'lnd-p', 20_000_000n, cancelled.preimage);
    expect(l.run('lnd-p', ['cancelinvoice', cancelled.hash]).kind).toBe('accepted');
    // lncli payinvoice prints the final Payment and exits 1 when it failed; ListPayments is the oracle.
    l.run('lnd-r', ['payinvoice', '--force', '--json', text(open['payment_request'], 'bolt11')]);
    const failed = payment(l, 'lnd-r', cancelled.hash);
    expect([failed['status'], failed['failure_reason']]).toEqual(['FAILED', 'FAILURE_REASON_INCORRECT_PAYMENT_DETAILS']);
    const invoice = l.ok('lnd-p', ['lookupinvoice', cancelled.hash]);
    expect([invoice['state'], invoice['amt_paid_msat']]).toEqual(['CANCELED', '0']);
    const settledInvoice = newPreimage();
    const paidInvoice = await lndInvoice(l, 'lnd-p', 20_000_000n, settledInvoice.preimage);
    expect(l.ok('lnd-r', ['payinvoice', '--force', '--json', text(paidInvoice['payment_request'], 'bolt11')])['status']).toBe('SUCCEEDED');
    const refusal = l.run('lnd-p', ['cancelinvoice', settledInvoice.hash]);
    expect(refusal.kind).toBe('rejected');
    expect(l.ok('lnd-p', ['lookupinvoice', settledInvoice.hash])['state']).toBe('SETTLED');
  }, 180_000);

  // A12: a FAILED HTLCAttempt from SendToRouteV2 (skip_temp_err unset) agrees with TrackPaymentV2
  // and ListPayments, with no HTLC in flight. The middle hop cln-m holds 1 250 000 sat on channel 5.
  it('CP-010/RA12 a SendToRouteV2 failed at a middle hop is FAILED in TrackPaymentV2 and ListPayments with nothing in flight', async () => {
    const l = lab();
    const { hash } = newPreimage();
    // An amount the middle hop cannot forward: 10 000 sat above cln-m's own spendable on channel 5.
    const middle = list(l.ok('cln-m', ['listpeerchannels', `id=${l.pubkeys['cln-r']}`])['channels'], 'channel 5')[0];
    const amountSat = BigInt(Number(middle?.['spendable_msat'])) / 1000n + 10_000n;
    if (amountSat * 1000n + 10_000_000n > BigInt(text(lndChannel(l, 'lnd-r', 'cln-m')['local_balance'], 'channel 2 balance')) * 1000n) throw new LabInvalidError('channel 2 cannot carry the probe amount');
    const built = l.ok('lnd-r', ['buildroute', '--amt', amountSat.toString(), '--hops', `${l.pubkeys['cln-m']},${l.pubkeys['cln-r']}`,
      '--outgoing_chan_id', lndScid(l, 'lnd-r', 'cln-m'), '--payment_addr', randomBytes(32).toString('hex')]);
    const attempt = l.ok('lnd-r', ['sendtoroute', '--payment_hash', hash, '--routes', JSON.stringify(built)]);
    expect(attempt['status']).toBe('FAILED');
    expect(record(attempt['failure'], 'failure')['failure_source_index']).toBe(1);
    const tracked = await lndStream(l, `/v2/router/track/${b64url(hash)}`, lines => lines.length >= 1);
    const first = record(record(tracked.lines[0], 'line')['result'], 'result');
    expect(first['status']).toBe('FAILED');
    expect(list(first['htlcs'], 'htlcs').map(htlc => htlc['status'])).toEqual(['FAILED']);
    const listed = payment(l, 'lnd-r', hash);
    expect(listed['status']).toBe('FAILED');
    expect(list(listed['htlcs'], 'htlcs').map(htlc => htlc['status'])).toEqual(['FAILED']);
  }, 180_000);

  // A18 / L19: v1 LookupInvoice with the hash in hex, callable with invoices:read.
  it('CP-010/RA18 GET /v1/invoice/{hex} with the read macaroon reports OPEN, SETTLED and CANCELED with amt_paid_msat', async () => {
    const l = lab();
    await cleanProxies(l);
    const [open, settled, cancelled] = [newPreimage(), newPreimage(), newPreimage()];
    for (const invoice of [open, settled, cancelled]) await lndInvoice(l, 'lnd-r', 10_000_000n, invoice.preimage);
    const bolt11 = text(l.ok('lnd-r', ['lookupinvoice', settled.hash])['payment_request'], 'bolt11');
    expect(l.ok('lnd-p', ['payinvoice', '--force', '--json', bolt11])['status']).toBe('SUCCEEDED');
    l.ok('lnd-r', ['cancelinvoice', cancelled.hash]);
    const states = [];
    for (const invoice of [open, settled, cancelled]) {
      const answer = await lndRest(l, 'GET', `/v1/invoice/${invoice.hash}`, undefined, 'read');
      const body = record(answer.body, 'invoice');
      states.push([answer.status, body['state'], body['amt_paid_msat']]);
    }
    expect(states).toEqual([[200, 'OPEN', '0'], [200, 'SETTLED', '10000000'], [200, 'CANCELED', '0']]);
  }, 180_000);

  // A21 / L31: ForwardingHistory is POST /v1/switch and pages by index_offset despite lnd#10496.
  it('CP-010/RA21 POST /v1/switch pages forwards one at a time by index_offset and matches lncli fwdinghistory', async () => {
    const l = lab();
    await cleanProxies(l);
    const start = Math.floor(Date.now() / 1000) - 1;
    for (let index = 0; index < 3; index += 1) {
      const { preimage } = newPreimage();
      const invoice = await clnInvoice(l, 10_000_000n, `fact-a21-${randomBytes(6).toString('hex')}`, 'a21', preimage);
      expect(l.ok('lnd-p', ['payinvoice', '--force', '--json', text(invoice['bolt11'], 'bolt11')])['status']).toBe('SUCCEEDED');
    }
    const end = Math.floor(Date.now() / 1000) + 60;
    const expected = await until(() => {
      const events = list(l.ok('lnd-r', ['fwdinghistory', '--start_time', String(start), '--end_time', String(end), '--max_events', '1000'])['forwarding_events'], 'forwards');
      return events.length >= 3 ? events : undefined;
    }, 'three forwards in lncli fwdinghistory');
    const paged: Record<string, unknown>[] = [];
    let offset = 0;
    for (let page = 0; page < expected.length + 2; page += 1) {
      const answer = await lndRest(l, 'POST', '/v1/switch', { start_time: String(start), end_time: String(end), index_offset: offset, num_max_events: 1 }, 'read');
      const body = record(answer.body, 'switch page');
      const events = list(body['forwarding_events'], 'forwarding events');
      if (!events.length) break;
      expect(events).toHaveLength(1);
      paged.push(...events);
      offset = Number(body['last_offset_index']);
    }
    const key = (event: Record<string, unknown>): string => `${String(event['timestamp_ns'])}:${String(event['amt_in_msat'])}:${String(event['amt_out_msat'])}`;
    expect(paged.map(key)).toEqual(expected.map(key));
  }, 180_000);

  // A25: the payments db ErrAlreadyPaid ("invoice is already paid"), which routerrpc SendToRouteV2
  // returns as gRPC AlreadyExists (routerrpc/router_server.go).
  it('CP-010/RA25 a second SendToRouteV2 for a settled hash is refused as already paid and the payment stays settled', async () => {
    const l = lab();
    const { preimage, hash } = newPreimage();
    const invoice = await lndInvoice(l, 'lnd-p', 10_000_000n, preimage);
    const route = JSON.parse(oneHopRoute(lndScid(l, 'lnd-r', 'lnd-p'), l.pubkeys['lnd-p'], 10_000_000n, l.height() + 100)) as { route: { hops: Record<string, unknown>[] } };
    const hop = route.route.hops[0];
    if (!hop) throw new LabInvalidError('route without hop');
    hop['mpp_record'] = { payment_addr: text(invoice['payment_addr'], 'payment addr'), total_amt_msat: '10000000' };
    expect(l.ok('lnd-r', ['sendtoroute', '--payment_hash', hash, '--routes', JSON.stringify(route)])['status']).toBe('SUCCEEDED');
    const again = l.run('lnd-r', ['sendtoroute', '--payment_hash', hash, '--routes', JSON.stringify(route)]);
    expect(again).toEqual({ kind: 'rejected', code: 'AlreadyExists', message: 'invoice is already paid' });
    const paid = payment(l, 'lnd-r', hash);
    expect([paid['status'], list(paid['htlcs'], 'htlcs').filter(htlc => htlc['status'] === 'SUCCEEDED').length]).toEqual(['SUCCEEDED', 1]);
  }, 180_000);
});
