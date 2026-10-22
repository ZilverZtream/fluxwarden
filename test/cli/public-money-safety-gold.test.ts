/* SECURITY §4.2 / INV-03 / INV-09 and SPEC §7.1 exclude_channels.
 * The public CLI creates real policy digests and Ed25519 approvals. Stateful CLN
 * fixtures retain their real paid invoice and incoming HTLC history. Only the
 * reported fee or the middle SCID changes, within the existing CLN wire schema.
 */
import { createHmac } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterEach, beforeAll, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { CH3, CLN_R, LND_R, FEE, MUTATING, PRINCIPAL, S, methodsOf } from '../fakes/cln/rebalance-node.js';
import { channelDirection } from '../fakes/cln/responses.js';
import {
  approve, demo, documentOf, plan, prepareDemoFixtures, rec, rows, storedId,
  type Demo, type DemoFixtures,
} from '../helpers/cpw-cli.js';
import { raw } from '../helpers/cp028-executor.js';
import { prepareMoneySafetyAlertKey, registerMoneySafetyCredentials } from '../helpers/public-money-safety.js';

const servers: FakeServer[] = [];
let fixtures: DemoFixtures;
beforeAll(async () => {
  fixtures = await prepareDemoFixtures();
  registerMoneySafetyCredentials([fixtures.key.keyFile]);
});
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });

const execute = (d: Demo, proposal: string) => d.run(['--json', 'actions', 'execute', proposal, '--require-regtest']);
const moneyCalls = (d: Demo) => methodsOf(d.cln.fake).filter(method => MUTATING.includes(method));

/** CLN waitsendpay/listsendpays complete record: fee = amount_sent_msat - amount_msat.
 * Source: pinned CLN v26.06.9 doc/schemas/{waitsendpay,listsendpays,listpeerchannels}.json.
 * The fake has already applied the paid receipt; balances and bookkeeper are adjusted
 * independently by the same literal fee difference, so no delta/accounting error masks it.
 */
function reportActualFee(d: Demo, actual: bigint): void {
  d.cln.state.bkprFeeMsat = actual;
  const respond = d.cln.fake.result;
  d.cln.fake.result = (context, behaviour, value) => {
    const result = rec(value);
    if (behaviour === 'waitsendpay-complete') result['amount_sent_msat'] = Number(PRINCIPAL + actual);
    if (behaviour === 'listsendpays') {
      for (const record of result['payments'] as Record<string, unknown>[]) {
        if (record['status'] === 'complete') record['amount_sent_msat'] = Number(PRINCIPAL + actual);
      }
    }
    if (behaviour === 'listpeerchannels' && d.cln.state.settledAt !== null) {
      for (const channel of result['channels'] as Record<string, unknown>[]) {
        if (channel['short_channel_id'] !== S) continue;
        for (const key of ['to_us_msat', 'max_to_us_msat', 'spendable_msat']) channel[key] = Number(channel[key]) - Number(actual - FEE);
      }
    }
    respond(context, behaviour, result);
  };
}

function persistentAlerts(d: Demo): { name: string; bytes: string; fields: Record<string, unknown> }[] {
  const dir = join(d.dir, 'alerts');
  return readdirSync(dir).filter(name => name.endsWith('.json')).map(name => {
    const bytes = readFileSync(join(dir, name), 'utf8');
    return { name, bytes, fields: rec(JSON.parse(bytes)) };
  });
}

for (const [family, actual] of [['PUB003', 300_001n], ['PUB002', 250_001n]] as const) {
for (const mode of ['dispatch', 'recovery'] as const) {
  it(`${family}/${mode}/persistent reported fee above its ceiling persists a breach and quarantine while retaining immutable paid audit`, async () => {
    // The CLI policy approves 300000 msat, 2500 ppm, exemption 5000.
    // At P=100000000, 250001 msat violates only ppm (ceil=2501).
    const d = await demo(servers, { fixtures, ...(mode === 'recovery' ? { fake: { sendpay: 'lose-answer' as const } } : {}) });
    await prepareMoneySafetyAlertKey(d.database);
    registerMoneySafetyCredentials([d.key.keyFile, d.cln.runeFile]);
    d.rewrite({ attemptDeadline: '1s' });
    // Zero cooldown separates future refusal by quarantine from a cooldown refusal.
    writeFileSync(d.policy, readFileSync(d.policy, 'utf8').replace('cooldown_after_success: 30m', 'cooldown_after_success: 0s'));
    reportActualFee(d, actual);
    const first = String((await plan(d))['proposal_id']);
    await approve(d, first);
    const next = String((await plan(d))['proposal_id']);
    expect(next).not.toBe(first);
    await approve(d, next);
    const approvedAudit = rows(d.database, 'SELECT * FROM approvals ORDER BY id');
    const run = await execute(d, first);
    let breach = run;
    if (mode === 'recovery') {
      expect(run.status).toBe(7);
      expect(rows(d.database, 'SELECT status FROM executions')).toEqual([{ status: 'UNKNOWN' }]);
      d.cln.state.unreachable = false;
      breach = await d.run(['--json', 'reconcile', '--node', 'cln-m', '--since', '1h']);
      d.cln.state.sendpay = 'settle';
    }
    expect(breach.status, breach.stdout + breach.stderr).toBe(8);
    registerMoneySafetyCredentials([join(dirname(d.database), 'outbox.key')]);
    const execution = rows(d.database, 'SELECT id, status, actual_fee_msat, payment_hash FROM executions WHERE proposal_id = ?', storedId(first))[0];
    expect(execution).toMatchObject({ status: 'VERIFIED_SUCCESS', actual_fee_msat: Number(actual) });
    const id = String(execution?.['id']);
    const hash = String(execution?.['payment_hash']);
    expect(d.cln.state.sent).toEqual([hash]);
    expect(d.cln.state.invoices.get(hash)?.status).toBe('paid');
    expect(rows(d.database, 'SELECT state, consumed_msat FROM budget_reservations WHERE execution_id = ?', id)).toEqual([{ state: 'CONSUMED', consumed_msat: Number(actual) }]);
    expect(rows(d.database, 'SELECT * FROM approvals ORDER BY id')).toEqual(approvedAudit);
    const paidJournals = rows(d.database, 'SELECT * FROM ledger_journals WHERE execution_id = ? ORDER BY id', id);
    expect(paidJournals.length).toBeGreaterThan(0);
    const db = raw(d.database);
    try { expect(() => db.prepare('UPDATE ledger_journals SET reference = ? WHERE id = ?').run('changed', String(paidJournals[0]?.['id']))).toThrow(); }
    finally { db.close(); }

    const alerts = persistentAlerts(d);
    const invariant = alerts.filter(alert => alert.fields['kind'] === 'invariant-breach' && alert.fields['subject'] === id);
    expect.soft(invariant, 'an exit code alone cannot survive restart').toHaveLength(1);
    expect.soft(rows(d.database, 'SELECT state FROM nodes')).toEqual([{ state: 'QUARANTINED' }]);
    if (invariant.length > 0) {
      const keyPath = join(dirname(d.database), 'outbox.key');
      expect(existsSync(keyPath)).toBe(true);
      const key = readFileSync(keyPath);
      const { hmacSha256, ...fields } = invariant[0]?.fields ?? {};
      const canonical = JSON.stringify(Object.keys(fields).sort().map(name => [name, fields[name]]));
      expect(hmacSha256).toBe(createHmac('sha256', key).update(canonical).digest('hex'));
    }
    const beforeRefusal = moneyCalls(d);
    const future = await execute(d, next);
    expect.soft(future.status, future.stdout + future.stderr).toBe(5);
    expect.soft(moneyCalls(d)).toEqual(beforeRefusal);
    expect.soft(rows(d.database, 'SELECT id FROM executions WHERE proposal_id = ? AND status IN (\'CLAIMED\', \'PREFLIGHT\', \'SUBMITTING\', \'IN_FLIGHT\', \'UNKNOWN\')', storedId(next))).toEqual([]);
    // Successful node reads remain possible and must never lift quarantine.
    const read = await d.run(['--json', 'channels', '--node', 'cln-m']);
    expect(read.status, read.stdout + read.stderr).toBe(0);
    const recovered = await d.run(['--json', 'reconcile', '--node', 'cln-m', '--since', '1h']);
    expect([0, 8, 9]).toContain(recovered.status);
    expect.soft(rows(d.database, 'SELECT state FROM nodes')).toEqual([{ state: 'QUARANTINED' }]);
    expect.soft(moneyCalls(d)).toEqual(beforeRefusal);
    expect(rows(d.database, 'SELECT * FROM approvals ORDER BY id')).toEqual(approvedAudit);
    expect(rows(d.database, 'SELECT * FROM ledger_journals WHERE execution_id = ? ORDER BY id', id)).toEqual(paidJournals);
    const afterRestart = persistentAlerts(d);
    for (const alert of alerts) expect(afterRestart.find(entry => entry.name === alert.name)?.bytes).toBe(alert.bytes);
  }, 120_000);
}
}

function excludeMiddle(d: Demo): void {
  writeFileSync(d.policy, `${readFileSync(d.policy, 'utf8')}exclude_channels:\n  - "${CH3}"\n`);
}

it('PUB004/planner policy excludes a middle SCID even when both endpoint channels are allowed', async () => {
  const d = await demo(servers, { fixtures });
  registerMoneySafetyCredentials([d.key.keyFile, d.cln.runeFile]);
  excludeMiddle(d);
  const proposal = await plan(d);
  expect.soft(proposal['action']).toBe('NO_ACTION');
  expect.soft(rows(d.database, "SELECT id FROM liquidity_proposals WHERE action_type = 'CIRCULAR_REBALANCE'")).toEqual([]);
  expect(moneyCalls(d)).toEqual([]);
});

it('PUB004/preflight a signed allowed route cannot authorize a newly returned route through the excluded middle channel', async () => {
  const d = await demo(servers, { fixtures });
  registerMoneySafetyCredentials([d.key.keyFile, d.cln.runeFile]);
  excludeMiddle(d);
  // All fields remain within CLN's valid SCID contract. Only the initial middle
  // channel identity changes; the pinned endpoints and counterparties are identical.
  let permitted = true;
  const respond = d.cln.fake.result;
  d.cln.fake.result = (context, behaviour, value) => {
    if (permitted && behaviour === 'listchannels' && context.params['short_channel_id'] === '104x1x0') {
      respond(context, behaviour, { channels: [channelDirection({ scid: '104x1x0', source: LND_R, destination: CLN_R, base: 1000, ppm: 1000, delay: 80 })] });
      return;
    }
    let serialized = JSON.stringify(value);
    if (permitted && (behaviour === 'getroutes' || behaviour === 'listchannels')) serialized = serialized.replaceAll(CH3, '104x1x0');
    respond(context, behaviour, JSON.parse(serialized));
  };
  const proposal = await plan(d);
  expect(proposal['action']).toBe('CIRCULAR_REBALANCE');
  const id = String(proposal['proposal_id']);
  await approve(d, id);
  const approved = rows(d.database, 'SELECT * FROM approvals');
  const policy = rows(d.database, 'SELECT policy_sha256, policy_canonical_json FROM policy_versions');
  expect(String(policy[0]?.['policy_canonical_json'])).toContain(CH3);
  expect(proposal['policy_sha256']).toBe(policy[0]?.['policy_sha256']);
  permitted = false;
  const run = await execute(d, id);
  expect.soft(run.status, run.stdout + run.stderr).toBe(5);
  expect.soft(moneyCalls(d)).toEqual([]);
  expect.soft(d.cln.state.sent).toEqual([]);
  expect(rows(d.database, 'SELECT * FROM approvals')).toEqual(approved);
  expect(documentOf(run, 'actions-execute')['ok']).toBe(false);
}, 120_000);
