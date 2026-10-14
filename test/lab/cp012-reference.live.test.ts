import { expect, it } from 'vitest';
import { adapterLabPlan, big, expectNoSentinelLeak, lightningCli, rows, type AdapterLabPlan } from '../helpers/adapter-lab.js';
import { loadClnApi, loadClnRest, loadErrors, rejection, type ClnApi, type ClnRestOptions } from '../helpers/adapter-interfaces.js';

const optional = (value: unknown): bigint | null => value === undefined ? null : big(value);

async function adapter(plan: AdapterLabPlan, overrides: Partial<ClnRestOptions> = {}): Promise<ClnApi> {
  const [{ openClnRest }, { ClnReadApi }] = await Promise.all([loadClnRest(), loadClnApi()]);
  return new ClnReadApi(await openClnRest({ host: plan.cln.host, port: plan.cln.port, tlsCertPath: plan.cln.tlsCert, runePath: plan.cln.credential, ...overrides }));
}

// These references need the owned regtest lab. The lab config selects this file only when a validation plan is
// supplied (decision D53); every missing plan input then fails closed.
it('CP-012/R1 adapter getinfo and listpeerchannels equal lightning-cli on CLN-M', async () => {
  const plan = adapterLabPlan();
  const client = await adapter(plan);
  const before = lightningCli(plan, ['getinfo']);
  const info = await client.getInfo();
  const after = lightningCli(plan, ['getinfo']);
  expect(info.id).toBe(plan.cln.pubkey);
  expect(info.id).toBe(before['id']);
  expect(info.version).toBe(before['version']);
  expect(info.network).toBe('regtest');
  expect(info.network).toBe(before['network']);
  expect([before['blockheight'], after['blockheight']]).toContain(info.blockheight);

  const channels = await client.listPeerChannels();
  const expected = rows(lightningCli(plan, ['listpeerchannels'])['channels'], 'listpeerchannels');
  expect(channels.map(item => item.channelId).sort()).toEqual(expected.map(item => item['channel_id'] ?? null).sort());
  for (const reference of expected) {
    const actual = channels.find(item => item.channelId === (reference['channel_id'] ?? null));
    expect(actual?.peerId).toBe(reference['peer_id']);
    expect(actual?.state).toBe(reference['state']);
    expect(actual?.shortChannelId).toBe(reference['short_channel_id'] ?? null);
    expect(actual?.fundingTxid).toBe(reference['funding_txid'] ?? null);
    expect(actual?.fundingOutnum).toBe(reference['funding_outnum'] ?? null);
    expect(actual?.opener).toBe(reference['opener']);
    expect(actual?.totalMsat).toBe(big(reference['total_msat']));
    expect(actual?.toUsMsat).toBe(big(reference['to_us_msat']));
    expect(actual?.spendableMsat).toBe(big(reference['spendable_msat']));
    expect(actual?.receivableMsat).toBe(big(reference['receivable_msat']));
    expect(actual?.ourReserveMsat).toBe(big(reference['our_reserve_msat']));
    expect(actual?.theirReserveMsat).toBe(big(reference['their_reserve_msat']));
    expect(actual?.feeBaseMsat).toBe(big(reference['fee_base_msat']));
    expect(actual?.feeProportionalMillionths).toBe(reference['fee_proportional_millionths']);
    expect(actual?.maximumHtlcOutMsat).toBe(big(reference['maximum_htlc_out_msat']));
    expect(actual?.htlcs.map(htlc => [htlc.id, htlc.direction, htlc.amountMsat, htlc.state]))
      .toEqual(rows(reference['htlcs'] ?? [], 'htlcs').map(htlc => [String(htlc['id']), htlc['direction'], big(htlc['amount_msat']), htlc['state']]));
  }
});

it('CP-012/R2 adapter payment invoice bookkeeper and layer reads equal lightning-cli on CLN-M', async () => {
  const plan = adapterLabPlan();
  const client = await adapter(plan);
  const sendpays = await client.listSendPays();
  const sendpayReference = rows(lightningCli(plan, ['listsendpays'])['payments'], 'listsendpays');
  expect(sendpays.map(item => [item.id, item.paymentHash, item.status, item.amountSentMsat, item.amountMsat]))
    .toEqual(sendpayReference.map(item => [String(item['id']), item['payment_hash'], item['status'], big(item['amount_sent_msat']), optional(item['amount_msat'])]));
  const pays = await client.listPays();
  const payReference = rows(lightningCli(plan, ['listpays'])['pays'], 'listpays');
  expect(pays.map(item => [item.paymentHash, item.status, item.amountSentMsat]))
    .toEqual(payReference.map(item => [item['payment_hash'], item['status'], optional(item['amount_sent_msat'])]));
  const invoices = await client.listInvoices();
  const invoiceReference = rows(lightningCli(plan, ['listinvoices'])['invoices'], 'listinvoices');
  expect(invoices.map(item => [item.label, item.paymentHash, item.status, item.amountMsat, item.amountReceivedMsat]))
    .toEqual(invoiceReference.map(item => [item['label'], item['payment_hash'], item['status'], optional(item['amount_msat']), optional(item['amount_received_msat'])]));
  const events = await client.listAccountEvents();
  const eventReference = rows(lightningCli(plan, ['bkpr-listaccountevents'])['events'], 'bkpr-listaccountevents');
  expect(events.map(item => [item.account, item.type, item.tag, item.creditMsat, item.debitMsat, item.feesMsat, item.isRebalance]))
    .toEqual(eventReference.map(item => [item['account'], item['type'], item['tag'], big(item['credit_msat']), big(item['debit_msat']), optional(item['fees_msat']), item['is_rebalance'] ?? null]));
  const layers = await client.listLayers();
  const layerReference = rows(lightningCli(plan, ['askrene-listlayers'])['layers'], 'askrene-listlayers');
  expect(layers.map(item => [item.layer, item.persistent, item.disabledNodes]))
    .toEqual(layerReference.map(item => [item['layer'], item['persistent'], item['disabled_nodes']]));
});

it('CP-012/R3 a wrong clnrest certificate is rejected in phase connect on CLN-M', async () => {
  const plan = adapterLabPlan();
  const errors = await loadErrors();
  const error = await rejection((await adapter(plan, { tlsCertPath: plan.wrongCert })).getInfo());
  expect(error).toBeInstanceOf(errors.TlsError);
  expect((error as InstanceType<typeof errors.TlsError>).phase).toBe('connect');
});

it('CP-012/Rleak independent nonempty sentinels are absent from product files scratch and retained output', async () => {
  await expectNoSentinelLeak();
});
