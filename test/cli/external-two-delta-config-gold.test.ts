// SPEC §10.1 exposes delta_tolerance_msat; §8.7(5) defines its inclusive msat
// boundary. Exercise the complete ordinary plan/approve/execute command path.
import { copyFileSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeAll, expect, it } from 'vitest';
import { FEE, S, T, callsOf } from '../fakes/cln/rebalance-node.js';
import type { FakeServer } from '../fakes/https.js';
import { approve, demo, documentOf, plan, prepareDemoFixtures, resultOf, rows, type DemoFixtures } from '../helpers/cpw-cli.js';
import { testRoot } from '../helpers/env.js';
import { declareDeliberateOutputs, registerSentinels } from '../helpers/output.js';

const open: FakeServer[] = [];
let fixtures: DemoFixtures;
beforeAll(async () => {
  registerSentinels();
  fixtures = await prepareDemoFixtures();
  // This immutable original key is consumed by demo's per-scenario copies.
  copyFileSync(fixtures.key.keyFile, join(testRoot('FLUXWARDEN_SENTINEL_DIR'), 'delta-original-approval-key.pem'));
  declareDeliberateOutputs([fixtures.key.keyFile]);
});
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

for (const c of [
  { name: 'configured inclusive boundary', tolerance: '1000', difference: 1000, exit: 0, delta: 'MATCH' },
  { name: 'omitted zero default', tolerance: null, difference: 1000, exit: 9, delta: 'MISMATCH' },
  { name: 'one msat beyond configured boundary', tolerance: '1000', difference: 1001, exit: 9, delta: 'MISMATCH' },
] as const) {
  it(`CP-030/REG-EXEC015 ordinary actions execute honors delta tolerance: ${c.name}`, async () => {
    const d = await demo(open, { fixtures });
    // Register only actual credential inputs, before any command consumes them.
    for (const [index, file] of [d.cln.runeFile, d.key.keyFile].entries()) {
      copyFileSync(file, join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `delta-${String(c.difference)}-${c.tolerance ?? 'default'}-${String(index)}.bin`));
    }
    declareDeliberateOutputs([d.cln.runeFile, d.key.keyFile]);
    if (c.tolerance !== null) writeFileSync(d.config, `delta_tolerance_msat: "${c.tolerance}"\n${readFileSync(d.config, 'utf8')}`);
    // A concurrent small local channel movement is a native listpeerchannels
    // observation (CLN v26.06.9 listpeerchannels.json to_us_msat). The settled
    // payment's fee and native incoming HTLC receipt remain independently scripted.
    const answer = d.cln.fake.result;
    d.cln.fake.result = (context, behaviour, value) => {
      if (behaviour === 'listpeerchannels' && d.cln.state.settledAt !== null) {
        const body = value as { channels: Record<string, unknown>[] };
        value = { channels: body.channels.map(channel => channel['short_channel_id'] === S ? {
          ...channel, to_us_msat: Number(channel['to_us_msat']) + c.difference,
          max_to_us_msat: Number(channel['max_to_us_msat']) + c.difference,
          spendable_msat: Number(channel['spendable_msat']) + c.difference,
          receivable_msat: Number(channel['receivable_msat']) - c.difference,
        } : channel) };
      }
      answer(context, behaviour, value);
    };
    const proposal = await plan(d), proposalId = String(proposal['proposal_id']);
    await approve(d, proposalId);
    const run = await d.run(['--json', 'actions', 'execute', proposalId, '--require-regtest']);
    expect.soft(run.status).toBe(c.exit);
    const doc = documentOf(run, 'actions-execute'), receipt = resultOf(doc), executionId = String(receipt['execution_id']);
    const journalIds = rows(d.database, 'SELECT id FROM ledger_journals WHERE execution_id = ? ORDER BY id', executionId).map(row => String(row['id']));
    expect.soft(journalIds).toHaveLength(2);
    expect.soft({ ...receipt, journal_ids: [...receipt['journal_ids'] as string[]].sort() }).toEqual({
      execution_id: executionId, proposal_id: proposalId, status: 'VERIFIED_SUCCESS', principal_msat: '100000000',
      actual_fee_msat: '202101', fee_ppm: 2022, cltv_delta: 132,
      source_delta_msat: c.difference === 1000 ? '-100201101' : '-100201100',
      target_delta_msat: '100000000', delta_status: c.delta, journal_ids: journalIds.sort(),
    });
    expect.soft(rows(d.database, 'SELECT status, actual_fee_msat, delta_status FROM executions WHERE id = ?', executionId)).toEqual([
      { status: 'VERIFIED_SUCCESS', actual_fee_msat: 202101, delta_status: c.delta },
    ]);
    expect.soft(rows(d.database, 'SELECT state, reserved_msat, consumed_msat FROM budget_reservations WHERE execution_id = ?', executionId)).toEqual([
      { state: 'CONSUMED', reserved_msat: 300000, consumed_msat: Number(FEE) },
    ]);
    expect.soft(rows(d.database, `SELECT j.event_type, l.account_code, l.debit_msat, l.credit_msat FROM ledger_journals j
      JOIN ledger_lines l ON l.journal_id = j.id WHERE j.execution_id = ? ORDER BY j.event_type, l.sequence_no`, executionId)).toEqual([
      { event_type: 'REBALANCE_SENT', account_code: 'clearing:inflight', debit_msat: 100202101, credit_msat: 0 },
      { event_type: 'REBALANCE_SENT', account_code: `channel:cln-m:${S}:local`, debit_msat: 0, credit_msat: 100202101 },
      { event_type: 'REBALANCE_SETTLED', account_code: `channel:cln-m:${T}:local`, debit_msat: 100000000, credit_msat: 0 },
      { event_type: 'REBALANCE_SETTLED', account_code: 'expense:routing_fees', debit_msat: 202101, credit_msat: 0 },
      { event_type: 'REBALANCE_SETTLED', account_code: 'clearing:inflight', debit_msat: 0, credit_msat: 100202101 },
    ]);
    expect.soft(callsOf(d.cln.fake, 'sendpay')).toHaveLength(1);
    expect.soft(callsOf(d.cln.fake, 'invoice')).toHaveLength(1);
    // D29 native oracle clarification: bookkeeper credit mapped by full native
    // channel_id proves receipt independently. listhtlcs terminal removal state
    // also covers failure (CLN v26.06.9 peer_htlcs.c remove_htlc_in), so that
    // unrelated read is not required by the exact money/delta contract above.
    expect.soft((await d.run(['--json', 'ledger', 'verify'])).status).toBe(0);
  });
}
