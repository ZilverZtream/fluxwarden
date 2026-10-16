// Interface: built execution CLI; paid results keep their execution and journal receipts (SPEC 10.3 AE13).
import { afterEach, beforeAll, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { T } from '../fakes/cln/rebalance-node.js';
import { approve, demo, jsonDocument, plan, prepareDemoFixtures, rec, rows, type DemoFixtures } from '../helpers/cpw-cli.js';

const servers: FakeServer[] = [];
let fixtures: DemoFixtures;
beforeAll(async () => { fixtures = await prepareDemoFixtures(); });
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });

it('CP-031/B1 REG-CLN003 the single sendpay carries the exact owned execution label and persisted hash', async () => {
  const d = await demo(servers, { fixtures });
  const proposal = String((await plan(d))['proposal_id']);
  await approve(d, proposal);
  const result = await d.run(['--json', 'actions', 'execute', proposal, '--require-regtest']);
  expect(result.status, result.stdout + result.stderr).toBe(0);
  const execution = rows(d.database, 'SELECT id, payment_hash, status FROM executions')[0];
  expect(execution?.['status']).toBe('VERIFIED_SUCCESS');
  const sends = d.cln.fake.calls.filter(call => call.method === 'sendpay');
  expect(sends).toHaveLength(1);
  expect(sends[0]?.params).toMatchObject({ label: `fluxwarden-${String(execution?.['id'])}`, payment_hash: execution?.['payment_hash'] });
  expect(String(sends[0]?.params['amount_msat']).replace(/msat$/, '')).toBe('100000000');
  expect(sends[0]?.params).not.toHaveProperty('partid');
  expect(sends[0]?.params).not.toHaveProperty('groupid');
  expect(d.cln.fake.calls.filter(call => ['pay', 'xpay'].includes(call.method))).toEqual([]);
});

it('CP-026/B3 REG-CLI016 a paid delta mismatch exposes terminal identity economics and journal receipts with exit 9', async () => {
  const d = await demo(servers, { fixtures });
  const proposal = String((await plan(d))['proposal_id']);
  await approve(d, proposal);
  const respond = d.cln.fake.result;
  d.cln.fake.result = (context, behaviour, value) => {
    if (behaviour === 'listpeerchannels' && d.cln.state.settledAt !== null) {
      for (const entry of rec(value)['channels'] as Record<string, unknown>[]) {
        if (entry['short_channel_id'] !== T) continue;
        for (const key of ['to_us_msat', 'max_to_us_msat', 'spendable_msat']) entry[key] = Number(entry[key]) + 2_000;
        entry['receivable_msat'] = Number(entry['receivable_msat']) - 2_000;
      }
    }
    respond(context, behaviour, value);
  };
  const result = await d.run(['--json', 'actions', 'execute', proposal, '--require-regtest']);
  const execution = rows(d.database, 'SELECT id, status, delta_status, actual_fee_msat FROM executions')[0];
  expect(execution).toMatchObject({ status: 'VERIFIED_SUCCESS', delta_status: 'MISMATCH', actual_fee_msat: 202101 });
  expect(result.status, result.stdout + result.stderr).toBe(9);
  const document = jsonDocument(result);
  const journals = rows(d.database, 'SELECT id FROM ledger_journals WHERE execution_id = ? ORDER BY id', String(execution?.['id'])).map(row => String(row['id']));
  expect(journals).toHaveLength(2);
  expect(document['result']).toMatchObject({ execution_id: execution?.['id'], proposal_id: proposal, status: 'VERIFIED_SUCCESS', principal_msat: '100000000', actual_fee_msat: '202101', fee_ppm: 2022, cltv_delta: 132,
    source_delta_msat: '-100202101', target_delta_msat: '100002000', delta_status: 'MISMATCH' });
  expect([...(rec(document['result'])['journal_ids'] as string[])].sort()).toEqual([...journals].sort());
  expect(document['ok']).toBe(document['error'] === null);
  if (document['error'] !== null) {
    const error = rec(document['error']);
    expect(error['code']).toBe(9);
    expect(`${String(error['step'])} ${String(error['message'])}`).toMatch(/mismatch/i);
  } else {
    expect((document['warnings'] as unknown[]).some(warning => /mismatch/i.test(String(warning)))).toBe(true);
  }
});
