// AUDIT-11: accepted EWMA configuration must use settled incoming history,
// and SPEC Policy's insufficient-history refusal must prevent a static plan.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { afterEach, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { accountEvent, clnInvoice } from '../fakes/cln/responses.js';
import { MUTATING, methodsOf, S, T } from '../fakes/cln/rebalance-node.js';
import { demo, documentOf, jsonDocument, list, rec, rows } from '../helpers/cpw-cli.js';
import { registerMoneySafetyCredentials } from '../helpers/public-money-safety.js';

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

it('CP-040/AUDIT-11 EWMA with no payment history refuses instead of planning from static targets', async () => {
  const d = await demo(open, { withKey: false });
  registerMoneySafetyCredentials([d.cln.runeFile]);
  writeFileSync(d.policy, readFileSync(d.policy, 'utf8').replace('  mode: targets', '  mode: ewma'));
  const run = await d.run(['--json', 'liquidity', 'plan', '--refresh']);
  const document = jsonDocument(run);
  // SPEC Output: history needed by EWMA is a safety prerequisite (exit 5).
  expect(run.status).toBe(5);
  expect(document['ok']).toBe(false);
  expect(document['result']).toBeNull();
  expect(rec(document['error'])['step']).toBe('INSUFFICIENT_HISTORY');
  expect(rows(d.database, "SELECT id FROM liquidity_proposals WHERE action_type = 'CIRCULAR_REBALANCE'")).toEqual([]);
  expect(methodsOf(d.cln.fake).filter(method => MUTATING.includes(method))).toEqual([]);
});

async function usableHistory(retried = false) {
  const d = await demo(open, { withKey: false, targets: { 'cln-m': { [S]: '50000000', [T]: '50000000' } } });
  registerMoneySafetyCredentials([d.cln.runeFile]);
  writeFileSync(d.policy, readFileSync(d.policy, 'utf8').replace('  mode: targets', '  mode: ewma'));
  const newest = Math.floor(Date.now() / 3_600_000) * 3600 - 3600;
  // CP-040's normalized weights sum to one. Twelve constant complete hourly
  // buckets at 75m msat require 75m * 6 * 1.4 = 630m inbound on S.
  // S currently has 100m; T has 2b and requires only 1m * 6 * 1.4 = 8.4m.
  // Thus principal min(530m, 1991.6m, reserve availability, 100m cap) = 100m.
  const history = Array.from({ length: 12 }, (_, i) => [
    { scid: S, account: '21'.repeat(32), volume: retried ? 100_000_000 : 75_000_000 },
    { scid: T, account: '25'.repeat(32), volume: 1_000_000 },
  ].map((channel, c) => ({ ...channel, index: i * 2 + c + 1,
    at: newest - (11 - i) * 3600 + 60,
    hash: createHash('sha256').update(`external-incoming-${String(i)}-${String(c)}`).digest('hex') }))).flat();
  const original = d.cln.fake.result;
  // Native CLN v26.06.9 schemas: listinvoices paid_at/amount_received_msat,
  // bkpr-listaccountevents account/credit_msat/timestamp/is_rebalance, and
  // listhtlcs incoming terminal receipts. The fake's existing schema helpers
  // cite those upstream schemas; no planner internals are mocked.
  d.cln.fake.result = (context, behavior, value) => {
    if (context.request.url === '/v1/listinvoices') value = { invoices: [...history.map(row => clnInvoice({
      label: `customer-${String(row.index)}`, payment_hash: row.hash, status: 'paid',
      amount_msat: row.volume, amount_received_msat: row.volume, paid_at: row.at,
      created_index: row.index, pay_index: row.index, expires_at: row.at + 3600,
    })), ...(retried ? [clnInvoice({ label: 'old-customer', payment_hash: 'e4'.repeat(32), status: 'paid',
      amount_msat: 900_000_000, amount_received_msat: 900_000_000, paid_at: newest - 14 * 3600,
      created_index: 25, pay_index: 25, expires_at: newest - 13 * 3600 })] : [])] };
    if (context.request.url === '/v1/bkpr-listaccountevents') value = { events: [...history.map(row => accountEvent({
      account: row.account, payment_id: row.hash, credit_msat: row.volume, debit_msat: 0,
      fees_msat: 0, timestamp: row.at, is_rebalance: false,
    })), ...(retried ? [accountEvent({ account: '99'.repeat(32), payment_id: 'e4'.repeat(32),
      credit_msat: 900_000_000, debit_msat: 0, fees_msat: 0,
      timestamp: newest - 14 * 3600, is_rebalance: false })] : [])] };
    if (context.request.url === '/v1/listhtlcs') value = { htlcs: [...history.map(row => ({
      created_index: row.index * 2, updated_index: row.index * 2, short_channel_id: row.scid,
      id: row.index * 2, expiry: 830, direction: 'in', amount_msat: row.volume,
      payment_hash: row.hash, state: 'SENT_REMOVE_ACK_REVOCATION',
    })), ...(retried ? [{ created_index: 45, updated_index: 45, short_channel_id: S,
      id: 45, expiry: 830, direction: 'in', amount_msat: 50_000_000,
      payment_hash: createHash('sha256').update('external-incoming-11-0').digest('hex'),
      state: 'SENT_REMOVE_ACK_REVOCATION' }] : [])].sort((a, b) => a.created_index - b.created_index) };
    original(context, behavior, value);
  };
  return d;
}

it('CP-040/AUDIT-11 usable incoming payment history creates an EWMA plan even when static targets are met', async () => {
  const d = await usableHistory();
  const run = await d.run(['--json', 'liquidity', 'plan', '--refresh']);
  expect(run.status).toBe(0);
  const result = rec(documentOf(run, 'liquidity-plan')['result']);
  expect(result).toMatchObject({ action: 'CIRCULAR_REBALANCE', demand_source: 'EWMA',
    source_channel: S, target_channel: T, principal_msat: '100000000' });
  expect(rows(d.database, 'SELECT demand_source, principal_msat FROM liquidity_proposals'))
    .toEqual([{ demand_source: 'EWMA', principal_msat: 100000000 }]);
  expect(methodsOf(d.cln.fake).filter(method => MUTATING.includes(method))).toEqual([]);
});

function expectDiagnosis(value: unknown, requiredInbound: string, deficit: string) {
  const result = rec(value);
  expect(result).toMatchObject({ action: 'DEFICIT', reason: null, node: 'cln-m',
    demand_source: 'EWMA', horizon_seconds: 21600, starved: [S], donors: [T] });
  const channels = new Map(list(result['channels']).map(value => { const channel = rec(value); return [channel['channel'], channel]; }));
  expect([...channels.keys()].sort()).toEqual([S, T]);
  expect(channels.get(S)).toMatchObject({ spendable_msat: '1820000000', receivable_msat: '100000000',
    confidence: 'NODE_REPORTED', inbound_target_msat: requiredInbound,
    inbound_deficit_msat: deficit, inbound_surplus_msat: '0' });
  expect(channels.get(T)).toMatchObject({ spendable_msat: '350000000', receivable_msat: '2000000000',
    confidence: 'NODE_REPORTED', inbound_target_msat: '8400000',
    inbound_deficit_msat: '0', inbound_surplus_msat: '1991600000' });
}

it('CP-040/AUDIT-11 repair diagnosis uses complete incoming history alongside fresh stored snapshots', async () => {
  const d = await usableHistory();
  const planned = await d.run(['--json', 'liquidity', 'plan', '--refresh']);
  expect(planned.status).toBe(0);
  expect(rec(jsonDocument(planned)['result'])).toMatchObject({ action: 'CIRCULAR_REBALANCE', demand_source: 'EWMA' });
  // The plan just persisted fresh channel snapshots. Diagnosis must still
  // obtain payment history: fresh balances do not imply absent demand.
  const diagnosed = await d.run(['--json', 'liquidity', 'diagnose', '--node', 'cln-m']);
  expect(diagnosed.status).toBe(0);
  expectDiagnosis(documentOf(diagnosed, 'liquidity-diagnose')['result'], '630000000', '530000000');
  expect(methodsOf(d.cln.fake).filter(method => MUTATING.includes(method))).toEqual([]);
});

it('CP-040/AUDIT-11 repair failed incoming HTLC retry does not inflate paid history or invalidate EWMA', async () => {
  const d = await usableHistory(true);
  // Primary CLN v26.06.9 common/htlc_state.h#L22-L33 and
  // doc/schemas/listhtlcs.json#L126-L152 describe removal progression,
  // including failed and fulfilled HTLCs. No success flag exists here.
  // The extra 50m terminal attempt shares the newest 100m paid invoice hash.
  // bkpr-listaccountevents.json#L57-L83 supplies the actual channel credit;
  // therefore the hourly volume is 100m, never the terminal-attempt sum150m.
  // An old paid invoice belongs to a closed, unrelated channel outside the
  // twelve-bucket window (listhtlcs retains history while channels are open).
  const planned = await d.run(['--json', 'liquidity', 'plan', '--refresh']);
  expect(planned.status, 'failed retry does not make complete paid history unusable').toBe(0);
  expect(rec(jsonDocument(planned)['result'])).toMatchObject({ action: 'CIRCULAR_REBALANCE',
    demand_source: 'EWMA', source_channel: S, target_channel: T, principal_msat: '100000000' });
  const diagnosed = await d.run(['--json', 'liquidity', 'diagnose', '--node', 'cln-m']);
  expect(diagnosed.status).toBe(0);
  // Constant 100m/hour * 6h * 1.4 = 840m; less 100m receivable = 740m.
  expectDiagnosis(documentOf(diagnosed, 'liquidity-diagnose')['result'], '840000000', '740000000');
  expect(methodsOf(d.cln.fake).filter(method => MUTATING.includes(method))).toEqual([]);
});
