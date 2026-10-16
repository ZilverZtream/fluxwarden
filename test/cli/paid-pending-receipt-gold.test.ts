// SPEC 10.3 AE13 / 8.7 and SECURITY INV-07/08: paid truth and balanced journal
// receipts survive unavailable current balance observations. Unknown measurements
// are explicit nulls; MATCH/MISMATCH continue to require measured signed deltas.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeAll, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { S, T } from '../fakes/cln/rebalance-node.js';
import { approve, demo, jsonDocument, plan, prepareDemoFixtures, rec, rows, schemaErrors, type DemoFixtures } from '../helpers/cpw-cli.js';
import { testRoot } from '../helpers/env.js';
import { declareDeliberateOutputs } from '../helpers/output.js';

const servers: FakeServer[] = [];
let fixtures: DemoFixtures;
const register = (kind: string, bytes: Buffer) => {
  const fingerprint = createHash('sha256').update(bytes).digest('hex').slice(0, 16);
  writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `paid-pending-${kind}-${fingerprint}.bin`), bytes, { mode: 0o600 });
};
beforeAll(async () => {
  fixtures = await prepareDemoFixtures();
  declareDeliberateOutputs([fixtures.key.keyFile]);
  register('approval-key', readFileSync(fixtures.key.keyFile));
});
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });

const measured = {
  execution_id: 'exec_01K7ZQ8M3V6W9X2Y4Z5A7B8C9F', proposal_id: 'prop_01K7ZQ8M3V6W9X2Y4Z5A7B8C9E',
  status: 'VERIFIED_SUCCESS', principal_msat: '100000000', actual_fee_msat: '202101', fee_ppm: 2022, cltv_delta: 132,
  source_delta_msat: '-100202101', target_delta_msat: '100000000', delta_status: 'MATCH', journal_ids: ['journal-sent', 'journal-settled'],
};
const document = (result: Record<string, unknown>) => ({ schema: 1, command: 'actions execute', ok: true,
  warnings: [], result, error: null });

it('CP-026/REG-CLI016 receipt schema retains measured examples and permits explicit unavailable pending measurements', () => {
  expect(schemaErrors('actions-execute', document(measured))).toEqual([]);
  expect(schemaErrors('actions-execute', document({ ...measured, delta_status: 'MISMATCH', target_delta_msat: '100002000' }))).toEqual([]);
  expect(schemaErrors('actions-execute', document({ ...measured, delta_status: 'PENDING',
    actual_fee_msat: null, fee_ppm: null, cltv_delta: null, source_delta_msat: null, target_delta_msat: null }))).toEqual([]);
  for (const status of ['MATCH', 'MISMATCH']) {
    for (const field of ['source_delta_msat', 'target_delta_msat']) {
      expect(schemaErrors('actions-execute', document({ ...measured, delta_status: status, [field]: null })),
        `${status} cannot claim an unobserved ${field}`).not.toEqual([]);
    }
  }
  for (const [field, invalid] of [
    ['actual_fee_msat', '-1'], ['actual_fee_msat', '01'], ['fee_ppm', -1], ['fee_ppm', 1.5],
    ['cltv_delta', -1], ['cltv_delta', 2017], ['cltv_delta', 1.5], ['source_delta_msat', '+1'], ['target_delta_msat', '-0'],
    ['principal_msat', null], ['status', 'UNKNOWN'], ['execution_id', ''], ['journal_ids', null],
  ] as const) expect(schemaErrors('actions-execute', document({ ...measured, [field]: invalid })),
    `${field} retains its existing observed-value bounds`).not.toEqual([]);
  for (const field of Object.keys(measured)) {
    const omitted: Record<string, unknown> = { ...measured };
    Reflect.deleteProperty(omitted, field);
    expect(schemaErrors('actions-execute', document(omitted)), `${field} remains required`).not.toEqual([]);
  }
});

it('CP-026/REG-CLI016 paid pending execution exposes known economics null deltas and balanced journal receipts with exit 9', async () => {
  const d = await demo(servers, { fixtures });
  declareDeliberateOutputs([d.key.keyFile, d.cln.runeFile]);
  register('rune', Buffer.from(d.cln.rune));
  const proposal = String((await plan(d))['proposal_id']);
  await approve(d, proposal);
  const respond = d.cln.fake.result;
  let missingCurrentListing = false;
  d.cln.fake.result = (context, behaviour, value) => {
    if (behaviour === 'invoice') {
      register('preimage', Buffer.from(String(context.params['preimage']), 'hex'));
      register('payment-secret', Buffer.from(String(rec(value)['payment_secret']), 'hex'));
    }
    // listpeerchannels.json permits an empty current listing. Native paid
    // payer/invoice/incoming-HTLC receipts remain unchanged and prove settlement.
    if (behaviour === 'listpeerchannels' && d.cln.state.settledAt !== null) {
      missingCurrentListing = true;
      respond(context, behaviour, { channels: [] });
      return;
    }
    respond(context, behaviour, value);
  };
  const run = await d.run(['--json', 'actions', 'execute', proposal, '--require-regtest']);
  expect(missingCurrentListing).toBe(true);
  const executions = rows(d.database, 'SELECT id, status, delta_status, actual_fee_msat FROM executions');
  expect(executions).toHaveLength(1);
  const execution = executions[0], executionId = String(execution?.['id']);
  expect(execution).toMatchObject({ status: 'VERIFIED_SUCCESS', delta_status: 'PENDING', actual_fee_msat: 202101 });
  const journals = rows(d.database, 'SELECT id, event_type FROM ledger_journals WHERE execution_id = ? ORDER BY event_type', executionId);
  expect(journals.map(row => row['event_type'])).toEqual(['REBALANCE_SENT', 'REBALANCE_SETTLED']);
  const journalLines = (id: unknown) => rows(d.database,
    'SELECT account_code, debit_msat, credit_msat FROM ledger_lines WHERE journal_id = ? ORDER BY account_code', String(id));
  expect(journalLines(journals[0]?.['id'])).toEqual([
    { account_code: `channel:cln-m:${S}:local`, debit_msat: 0, credit_msat: 100202101 },
    { account_code: 'clearing:inflight', debit_msat: 100202101, credit_msat: 0 },
  ]);
  expect(journalLines(journals[1]?.['id'])).toEqual([
    { account_code: `channel:cln-m:${T}:local`, debit_msat: 100000000, credit_msat: 0 },
    { account_code: 'clearing:inflight', debit_msat: 0, credit_msat: 100202101 },
    { account_code: 'expense:routing_fees', debit_msat: 202101, credit_msat: 0 },
  ]);
  for (const journal of journals) expect(journalLines(journal['id']).reduce((sum, line) =>
    sum + Number(line['debit_msat']) - Number(line['credit_msat']), 0)).toBe(0);
  expect(d.cln.fake.calls.filter(call => call.method === 'invoice')).toHaveLength(1);
  expect(d.cln.fake.calls.filter(call => call.method === 'sendpay')).toHaveLength(1);
  expect(d.cln.fake.calls.filter(call => ['pay', 'xpay', 'delinvoice'].includes(call.method))).toEqual([]);
  expect(run.status).toBe(9);
  const doc = jsonDocument(run);
  expect(doc['result']).toMatchObject({ execution_id: executionId, proposal_id: proposal, status: 'VERIFIED_SUCCESS',
    principal_msat: '100000000', actual_fee_msat: '202101', fee_ppm: 2022, cltv_delta: 132,
    source_delta_msat: null, target_delta_msat: null, delta_status: 'PENDING' });
  expect(schemaErrors('actions-execute', doc)).toEqual([]);
  const result = rec(doc['result']);
  expect(Object.keys(result).sort()).toEqual(Object.keys(measured).sort());
  expect([...(result['journal_ids'] as string[])].sort()).toEqual(journals.map(row => String(row['id'])).sort());
  expect((doc['warnings'] as unknown[]).some(warning => String(warning).includes('DELTA_UNVERIFIED'))).toBe(true);
});
