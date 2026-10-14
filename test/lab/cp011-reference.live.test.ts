import { randomBytes } from 'node:crypto';
import { expect, it } from 'vitest';
import { adapterLabPlan, big, expectNoSentinelLeak, lncli, rows, type AdapterLabPlan } from '../helpers/adapter-lab.js';
import { loadErrors, loadLndApi, loadLndRest, rejection, type LndApi, type LndRestOptions } from '../helpers/adapter-interfaces.js';

// Plan refusal comes first, before any Docker call, on every host.
async function adapter(plan: AdapterLabPlan, overrides: Partial<LndRestOptions> = {}): Promise<LndApi> {
  const [{ openLndRest }, { LndReadApi }] = await Promise.all([loadLndRest(), loadLndApi()]);
  return new LndReadApi(await openLndRest({ host: plan.lnd.host, port: plan.lnd.port, tlsCertPath: plan.lnd.tlsCert, macaroonPath: plan.lnd.credential, ...overrides }));
}

// These references need the owned regtest lab. The lab config selects this file only when a validation plan is
// supplied (decision D53); every missing plan input then fails closed.
it('CP-011/R1 adapter GetInfo ListChannels and PendingChannels equal lncli on LND-R', async () => {
  const plan = adapterLabPlan();
  const client = await adapter(plan);
  const before = lncli(plan, ['getinfo']);
  const info = await client.getInfo();
  const after = lncli(plan, ['getinfo']);
  expect(info.identityPubkey).toBe(plan.lnd.pubkey);
  expect(info.identityPubkey).toBe(before['identity_pubkey']);
  expect(info.network).toBe(rows(before['chains'], 'chains')[0]?.['network']);
  expect(info.network).toBe('regtest');
  expect(info.version).toBe(before['version']);
  expect(info.commitHash).toBe(before['commit_hash']);
  expect(info.alias).toBe(before['alias']);
  expect([before['block_height'], after['block_height']]).toContain(info.blockHeight);
  expect(info.syncedToChain).toBe(after['synced_to_chain']);

  const channels = await client.listChannels();
  const expected = rows(lncli(plan, ['listchannels'])['channels'], 'listchannels');
  expect(channels.map(item => item.channelPoint).sort()).toEqual(expected.map(item => String(item['channel_point'])).sort());
  for (const reference of expected) {
    const actual = channels.find(item => item.channelPoint === reference['channel_point']);
    // lncli's listchannels output renames the short channel id to `scid` and reuses `chan_id`
    // for the 32-byte channel id (cmd/commands/commands.go replaceAndAppendScid, appendChanID).
    expect(actual?.chanId).toBe(reference['scid']);
    expect(actual?.remotePubkey).toBe(reference['remote_pubkey']);
    expect(actual?.active).toBe(reference['active']);
    expect(actual?.initiator).toBe(reference['initiator']);
    expect(actual?.capacitySat).toBe(big(reference['capacity']));
    expect(actual?.localBalanceSat).toBe(big(reference['local_balance']));
    expect(actual?.remoteBalanceSat).toBe(big(reference['remote_balance']));
    expect(actual?.commitFeeSat).toBe(big(reference['commit_fee']));
    expect(actual?.unsettledBalanceSat).toBe(big(reference['unsettled_balance']));
    for (const side of ['local', 'remote'] as const) {
      const constraints = reference[`${side}_constraints`] as Record<string, unknown>;
      const mapped = side === 'local' ? actual?.localConstraints : actual?.remoteConstraints;
      expect(mapped?.chanReserveSat).toBe(big(constraints['chan_reserve_sat']));
      expect(mapped?.maxPendingAmtMsat).toBe(big(constraints['max_pending_amt_msat']));
      expect(mapped?.minHtlcMsat).toBe(big(constraints['min_htlc_msat']));
    }
    const htlcs = rows(reference['pending_htlcs'], 'pending htlcs');
    expect(actual?.pendingHtlcs.map(htlc => htlc.hashLock).sort()).toEqual(htlcs.map(htlc => String(htlc['hash_lock'])).sort());
  }

  const pending = await client.pendingChannels();
  const reference = lncli(plan, ['pendingchannels']);
  const points = (value: unknown): string[] => rows(value, 'pending').map(item => String((item['channel'] as Record<string, unknown>)['channel_point'])).sort();
  expect(pending.pendingOpenChannels.map(item => item.channel.channelPoint).sort()).toEqual(points(reference['pending_open_channels']));
  expect(pending.waitingCloseChannels.map(item => item.channel.channelPoint).sort()).toEqual(points(reference['waiting_close_channels']));
  expect(pending.pendingForceClosingChannels.map(item => item.channel.channelPoint).sort()).toEqual(points(reference['pending_force_closing_channels']));
  expect(pending.totalLimboBalanceSat).toBe(big(reference['total_limbo_balance']));
});

it('CP-011/R2 adapter ListPayments ForwardingHistory and LookupInvoice equal lncli on LND-R', async () => {
  const plan = adapterLabPlan();
  const errors = await loadErrors();
  const client = await adapter(plan);
  const page = await client.listPayments({ indexOffset: 0n, maxPayments: 1000, includeIncomplete: true });
  const payments = lncli(plan, ['listpayments', '--include_incomplete', '--index_offset=0', '--max_payments=1000']);
  const expected = rows(payments['payments'], 'payments');
  expect(page.payments.map(item => item.paymentHash)).toEqual(expected.map(item => item['payment_hash']));
  for (const [index, reference] of expected.entries()) {
    const actual = page.payments[index];
    expect(actual?.status).toBe(reference['status']);
    expect(actual?.valueMsat).toBe(big(reference['value_msat']));
    expect(actual?.feeMsat).toBe(big(reference['fee_msat']));
    expect(actual?.paymentIndex).toBe(big(reference['payment_index']));
    expect(actual?.failureReason).toBe(reference['failure_reason']);
    expect(actual?.htlcs.length).toBe(rows(reference['htlcs'], 'htlcs').length);
  }
  expect(page.lastIndexOffset).toBe(big(payments['last_index_offset']));

  const end = BigInt(Math.floor(Date.now() / 1000) + 60);
  const forwards = await client.forwardingHistory({ startTime: 1n, endTime: end, indexOffset: 0, numMaxEvents: 1000 });
  const history = lncli(plan, ['fwdinghistory', '--start_time=1', `--end_time=${end.toString()}`, '--index_offset=0', '--max_events=1000']);
  const events = rows(history['forwarding_events'], 'forwarding events');
  expect(forwards.events.map(event => [event.timestampNs, event.chanIdIn, event.chanIdOut, event.amtInMsat, event.amtOutMsat, event.feeMsat]))
    .toEqual(events.map(event => [big(event['timestamp_ns']), event['chan_id_in'], event['chan_id_out'], big(event['amt_in_msat']), big(event['amt_out_msat']), big(event['fee_msat'])]));
  expect(forwards.lastOffsetIndex).toBe(history['last_offset_index']);

  const memo = `fluxwarden-reference-${randomBytes(4).toString('hex')}`;
  const created = lncli(plan, ['addinvoice', '--amt_msat=1000', `--memo=${memo}`, '--expiry=600']);
  const hash = String(created['r_hash']);
  expect(hash).toMatch(/^[0-9a-f]{64}$/);
  const invoice = await client.lookupInvoice(hash);
  const reference = lncli(plan, ['lookupinvoice', hash]);
  expect(invoice.rHash).toBe(reference['r_hash']);
  expect(invoice.memo).toBe(memo);
  expect(invoice.state).toBe(reference['state']);
  expect(invoice.valueMsat).toBe(big(reference['value_msat']));
  expect(invoice.amtPaidMsat).toBe(big(reference['amt_paid_msat']));
  expect(invoice.addIndex).toBe(big(reference['add_index']));
  expect(invoice.expiry).toBe(big(reference['expiry']));
  const missing = await rejection(client.lookupInvoice(randomBytes(32).toString('hex')));
  expect(missing).toBeInstanceOf(errors.LndError);
  expect((missing as InstanceType<typeof errors.LndError>).notFound).toBe(true);
});

it('CP-011/R3 a wrong tls.cert is rejected in phase connect on LND-R', async () => {
  const plan = adapterLabPlan();
  const errors = await loadErrors();
  const error = await rejection((await adapter(plan, { tlsCertPath: plan.wrongCert })).getInfo());
  expect(error).toBeInstanceOf(errors.TlsError);
  expect((error as InstanceType<typeof errors.TlsError>).phase).toBe('connect');
});

it('CP-011/Rleak independent nonempty sentinels are absent from product files scratch and retained output', async () => {
  await expectNoSentinelLeak();
});
