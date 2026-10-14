/*
 * Interface: `liquidity approve`, `actions execute`, `actions status` and `ledger verify` through the built CLI
 * (SPEC §10.3 items 7-9, §9.5), on the CLN-M fake of test/fakes/cln/rebalance-node.ts.
 *
 * Invocation:
 *   fluxwarden [--json] liquidity approve <proposal-id> --key <file> [--max-fee-msat <msat>] [--max-cltv-delta <n>]
 *                                         [--expires-in <dur>] --config <path>
 *   fluxwarden [--json] actions execute <proposal-id> --require-regtest --config <path>
 *   fluxwarden [--json] actions status <execution-id> [--watch] --config <path>
 *   fluxwarden [--json] ledger verify --config <path>
 *
 * Configuration (SPEC §10.1) adds to test/cli/cp016-commands.test.ts:
 *   approval_keys: [ { key_id: <32 hex>, public_key: <base64 raw Ed25519 key> } ]   as `keys generate --json` prints them
 *   alert_dir: <path>
 *
 * approve (LA1-LA5): unknown proposal id -> 2; proposal expired or not PROPOSED/APPROVED -> 5; unreadable key -> 2;
 *   caps looser than the proposal or policy -> 1 with error.step FEE_CEILING_EXCEEDED / CLTV_DELTA_UNSAFE; expiry beyond the
 *   proposal or approval_max_ttl -> 1; a key whose key_id is not configured -> 2; a malformed msat or count -> 2; a
 *   snapshot older than max_snapshot_age at approval time -> 5, error.step STALE_SNAPSHOT (CP-026/B6). Success stores one
 *   approvals row (SPEC §6.2) whose signature verifies over the SECURITY.md §4.1 message, sets the proposal APPROVED, and
 *   prints schemas/output/liquidity-approve.json { approval_id, proposal_id, key_id, max_fee_msat, max_cltv_delta,
 *   expires_at }. Stored nonce and signature are hex (or base64) of 32 and 64 bytes.
 * execute (AE1-AE13): --require-regtest missing -> 2 before any node call; a policy whose network is not regtest -> 1
 *   before any node call (G3, INV-15); no approval key configured -> 5 before any node call (INV-01); no stored approval
 *   that verifies (signature, key still configured, caps, expiry) -> 5 and no fund-moving node call (INV-02); a node
 *   reporting another network or identity -> 5, error.step identity, node QUARANTINED, nothing sent (H3, INV-12, INV-15).
 *   Success -> exit 0 with schemas/output/actions-execute.json { execution_id, proposal_id, status VERIFIED_SUCCESS,
 *   principal_msat, actual_fee_msat, fee_ppm, cltv_delta, source_delta_msat, target_delta_msat (signed decimal strings),
 *   delta_status, journal_ids (the journals this execution posted) }.
 * status (AS1-AS3): unknown id -> 2; schemas/output/actions-status.json; exit 0 VERIFIED_SUCCESS, 5 VERIFIED_FAILURE or
 *   CANCELLED, 7 unresolved with the message "outcome unknown — run `fluxwarden reconcile`; do not retry".
 * ledger verify: the four steps of SPEC §9.5 (step 4 needs the nodes, so `not-requested` here) as
 *   schemas/output/ledger-verify.json { journals, steps: [ { step, result } ] }; a failure of steps 1-3 -> exit 8 with
 *   error.message naming the journal id at fault.
 * Ledger accounts (SPEC §9.1): channel:<node name>:<channel key>:local, clearing:inflight, expense:routing_fees.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { CH3, CLN_R, FEE, LND_R, MUTATING, PRINCIPAL, S, SELF, T, callsOf, methodsOf } from '../fakes/cln/rebalance-node.js';
import { leakedForms, SENTINEL_MACAROON } from '../helpers/cp016-cli.js';
import {
  approvalMessage, approve, bytesOf, count, demo, documentOf, errorOf, generateKey, INVALID_INPUT, INVARIANT_BREACH, list, pause, plan,
  POLICY_VIOLATION, rec, resultOf, rows, SAFETY_REFUSAL, sha256Hex, storedId, SUCCESS, tamper, verifiesWith, writeDemoPolicy,
  type Demo, type Doc,
} from '../helpers/cpw-cli.js';

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

const fundMoving = (d: Demo): string[] => methodsOf(d.cln.fake).filter(method => MUTATING.includes(method));
const executeArgs = (id: string): string[] => ['--json', 'actions', 'execute', id, '--require-regtest'];

async function planned(d: Demo): Promise<{ id: string; doc: Doc }> {
  const doc = await plan(d);
  return { id: String(doc['proposal_id']), doc };
}

/** plan -> approve -> execute on the demo; returns the three documents. */
async function rebalance(d: Demo): Promise<{ proposal: Doc; approval: Doc; executed: Doc }> {
  const { id, doc } = await planned(d);
  const approval = await approve(d, id);
  const run = await d.run(executeArgs(id));
  if (run.status !== SUCCESS) throw new Error(`actions execute exited ${String(run.status)}: ${run.stdout}${run.stderr}`);
  return { proposal: doc, approval, executed: resultOf(documentOf(run, 'actions-execute')) };
}

describe('liquidity approve', () => {
  it('CP-026/B2 approve stores an approval whose signature verifies over the SECURITY §4.1 message with the configured key', async () => {
    const d = await demo(open);
    const { id, doc } = await planned(d);
    const approval = await approve(d, id);
    expect(approval).toMatchObject({ proposal_id: id, key_id: d.key.keyId, max_fee_msat: '300000', max_cltv_delta: 144 });
    expect(Number(approval['expires_at'])).toBeGreaterThan(Date.now());
    expect(Number(approval['expires_at'])).toBeLessThanOrEqual(Number(doc['expires_at']));

    const stored = rows(d.database, `SELECT a.id, a.key_id, a.nonce, a.expires_at, a.signature, a.max_fee_msat, a.max_cltv_delta, p.proposal_digest, p.status, v.policy_sha256
      FROM approvals a JOIN liquidity_proposals p ON p.id = a.proposal_id JOIN policy_versions v ON v.id = p.policy_version_id`);
    expect(stored).toHaveLength(1);
    const row = rec(stored[0]);
    expect(row['id']).toBe(approval['approval_id']);
    expect(row['status']).toBe('APPROVED');
    expect(row['proposal_digest']).toBe(doc['digest']);
    expect(row['policy_sha256']).toBe(doc['policy_sha256']);
    const nonce = bytesOf(String(row['nonce']), 32);
    const signature = bytesOf(String(row['signature']), 64);
    if (nonce === null || signature === null) throw new Error(`nonce or signature is not 32 / 64 bytes: ${String(row['nonce'])} ${String(row['signature'])}`);
    const message = approvalMessage({
      digest: String(row['proposal_digest']), policySha256: String(row['policy_sha256']), maxFeeMsat: BigInt(Number(row['max_fee_msat'])),
      maxCltvDelta: Number(row['max_cltv_delta']), expiresAt: BigInt(Number(row['expires_at'])), nonce, keyId: String(row['key_id']),
    });
    expect(verifiesWith(d.key.publicKey, message, signature)).toBe(true);
    // The approval's own caps are inside the signature (SPEC §7.7): a message with the proposal's looser cap does not verify.
    const loosened = approvalMessage({
      digest: String(row['proposal_digest']), policySha256: String(row['policy_sha256']), maxFeeMsat: 300_001n,
      maxCltvDelta: Number(row['max_cltv_delta']), expiresAt: BigInt(Number(row['expires_at'])), nonce, keyId: String(row['key_id']),
    });
    expect(verifiesWith(d.key.publicKey, loosened, signature)).toBe(false);

    const explained = resultOf(documentOf(await d.run(['--json', 'liquidity', 'explain', id]), 'liquidity-explain'));
    expect(explained['status']).toBe('APPROVED');
    expect(list(explained['approvals'])).toHaveLength(1);
    // Approval needs no node mutation.
    expect(fundMoving(d)).toEqual([]);
  }, 60_000);

  it('CP-026/B2 approve text output prints the approval id, key_id and expiry, and never the private key', async () => {
    const d = await demo(open);
    const { id } = await planned(d);
    const run = await d.run(['liquidity', 'approve', id, '--key', d.key.keyFile, '--max-fee-msat', '250000', '--max-cltv-delta', '140']);
    expect(run.status).toBe(SUCCESS);
    const stored = rows(d.database, 'SELECT id, max_fee_msat, max_cltv_delta FROM approvals');
    expect(stored).toEqual([{ id: stored[0]?.['id'], max_fee_msat: 250000, max_cltv_delta: 140 }]);
    expect(run.stdout).toContain(String(stored[0]?.['id']));
    expect(run.stdout).toContain(d.key.keyId);
    const pem = readFileSync(d.key.keyFile, 'utf8');
    const body = pem.split('\n').filter(line => !line.startsWith('-----')).join('');
    expect(run.stdout + run.stderr).not.toContain(body);
    expect(leakedForms(run.stdout + run.stderr, Buffer.from(body, 'base64'))).toEqual([]);
  }, 60_000);

  it('CP-026/B3 approve refuses caps or an expiry looser than proposal and policy with exit 1, and bad input with exit 2', async () => {
    const d = await demo(open);
    const { id } = await planned(d);
    const other = await generateKey(d.dir, 'unregistered.key');
    const base = ['--json', 'liquidity', 'approve', id, '--key', d.key.keyFile];
    const cases: { args: string[]; code: number; step?: string }[] = [
      { args: [...base, '--max-fee-msat', '300001', '--max-cltv-delta', '144'], code: POLICY_VIOLATION, step: 'FEE_CEILING_EXCEEDED' },
      { args: [...base, '--max-fee-msat', '300000', '--max-cltv-delta', '145'], code: POLICY_VIOLATION, step: 'CLTV_DELTA_UNSAFE' },
      { args: [...base, '--max-fee-msat', '300000', '--max-cltv-delta', '144', '--expires-in', '16m'], code: POLICY_VIOLATION },
      { args: [...base, '--max-fee-msat', '1.5', '--max-cltv-delta', '144'], code: INVALID_INPUT },
      { args: [...base, '--max-fee-msat', '-1', '--max-cltv-delta', '144'], code: INVALID_INPUT },
      { args: [...base, '--max-fee-msat', '300000', '--max-cltv-delta', 'many'], code: INVALID_INPUT },
      { args: ['--json', 'liquidity', 'approve', id, '--key', other.keyFile, '--max-fee-msat', '300000', '--max-cltv-delta', '144'], code: INVALID_INPUT },
      { args: ['--json', 'liquidity', 'approve', id, '--key', `${d.key.keyFile}.missing`, '--max-fee-msat', '300000', '--max-cltv-delta', '144'], code: INVALID_INPUT },
      { args: ['--json', 'liquidity', 'approve', 'prop_01JC0000000000000000000000', '--key', d.key.keyFile, '--max-fee-msat', '300000', '--max-cltv-delta', '144'], code: INVALID_INPUT },
      { args: ['--json', 'liquidity', 'approve', id, '--max-fee-msat', '300000', '--max-cltv-delta', '144'], code: INVALID_INPUT },
    ];
    for (const entry of cases) {
      const run = await d.run(entry.args);
      expect(run.status, entry.args.join(' ')).toBe(entry.code);
      const error = errorOf(documentOf(run, 'liquidity-approve'));
      expect(error['code']).toBe(entry.code);
      if (entry.step !== undefined) expect(error['step']).toBe(entry.step);
    }
    expect(count(d.database, 'approvals')).toBe(0);
    expect(rows(d.database, 'SELECT status FROM liquidity_proposals')).toEqual([{ status: 'PROPOSED' }]);
  }, 90_000);

  it('CP-026/B6 a snapshot older than max_snapshot_age at approval time refuses with exit 5 STALE_SNAPSHOT', async () => {
    const d = await demo(open, { maxSnapshotAge: '1s' });
    const { id } = await planned(d);
    await pause(1_600);
    const run = await d.run(['--json', 'liquidity', 'approve', id, '--key', d.key.keyFile, '--max-fee-msat', '300000', '--max-cltv-delta', '144']);
    expect(run.status).toBe(SAFETY_REFUSAL);
    expect(errorOf(documentOf(run, 'liquidity-approve'))).toMatchObject({ code: SAFETY_REFUSAL, step: 'STALE_SNAPSHOT' });
    expect(count(d.database, 'approvals')).toBe(0);
  }, 60_000);
});

describe('the demo flow on fakes', () => {
  it('CP-030/B4 plan, explain, approve, execute and status settle one HTLC with the SPEC fee and verified deltas', async () => {
    const d = await demo(open);
    const { id } = await planned(d);
    expect((await d.run(['--json', 'liquidity', 'explain', id])).status).toBe(SUCCESS);
    await approve(d, id);
    const run = await d.run(executeArgs(id));
    expect(run.status).toBe(SUCCESS);
    const executed = resultOf(documentOf(run, 'actions-execute'));
    expect(executed).toMatchObject({
      proposal_id: id, status: 'VERIFIED_SUCCESS', principal_msat: '100000000', actual_fee_msat: '202101', fee_ppm: 2022, cltv_delta: 132,
      // SPEC §14.1 / §8.7: channel 2 local -100,202,101, channel 5 local +100,000,000.
      source_delta_msat: '-100202101', target_delta_msat: '100000000', delta_status: 'MATCH',
    });

    // One invoice with FluxWarden's preimage, exactly one sendpay under its hash, nothing else that moves funds (INV-05, INV-17).
    const invoices = callsOf(d.cln.fake, 'invoice');
    const sends = callsOf(d.cln.fake, 'sendpay');
    expect(invoices).toHaveLength(1);
    expect(sends).toHaveLength(1);
    const hash = sha256Hex(Buffer.from(String(invoices[0]?.['preimage']), 'hex'));
    expect(sends[0]?.['payment_hash']).toBe(hash);
    expect(String(sends[0]?.['amount_msat']).replace(/msat$/, '')).toBe('100000000');
    const route = list(sends[0]?.['route']).map(rec);
    expect(route.map(hop => [String(hop['short_channel_id_dir']).split('/')[0], hop['node_id_out'], String(hop['amount_out_msat']).replace(/msat$/, '')])).toEqual([
      [S, LND_R, '100202101'], [CH3, CLN_R, '100101000'], [T, SELF, '100000000'],
    ]);
    expect(fundMoving(d).filter(method => method !== 'invoice' && method !== 'sendpay')).toEqual([]);

    const status = await d.run(['--json', 'actions', 'status', String(executed['execution_id'])]);
    expect(status.status).toBe(SUCCESS);
    const view = resultOf(documentOf(status, 'actions-status'));
    expect(view).toMatchObject({ execution_id: executed['execution_id'], status: 'VERIFIED_SUCCESS', payment_hash: hash, planned_fee_msat: '202101', actual_fee_msat: '202101', delta_status: 'MATCH' });
    const events = list(view['events']).map(rec);
    expect(events.map(event => event['to'])).toEqual(['CLAIMED', 'PREFLIGHT', 'SUBMITTING', 'IN_FLIGHT', 'VERIFIED_SUCCESS']);
    expect(events[0]?.['from']).toBeNull();
    const text = await d.run(['actions', 'status', String(executed['execution_id'])]);
    expect(text.status).toBe(SUCCESS);
    for (const expected of [String(executed['execution_id']), 'VERIFIED_SUCCESS', hash, '202101']) expect(text.stdout, expected).toContain(expected);

    // The approval authorised exactly one execution: a second execute of the same proposal moves nothing (SPEC §7.7).
    const again = await d.run(executeArgs(id));
    expect(again.status).toBe(SAFETY_REFUSAL);
    expect(callsOf(d.cln.fake, 'sendpay')).toHaveLength(1);
    expect(count(d.database, 'executions')).toBe(1);
  }, 90_000);

  it('CP-037/B2 the executed rebalance posts the SPEC §9.3 send and settle journals, exact to the msat', async () => {
    const d = await demo(open);
    const { executed } = await rebalance(d);
    const journals = rows(d.database, 'SELECT id, event_type FROM ledger_journals WHERE execution_id = ? ORDER BY event_type', String(executed['execution_id']));
    expect(journals.map(journal => journal['event_type'])).toEqual(['REBALANCE_SENT', 'REBALANCE_SETTLED']);
    expect([...list(executed['journal_ids'])].sort()).toEqual(journals.map(journal => journal['id']).sort());
    const lines = (journalId: unknown): unknown[][] => rows(d.database, 'SELECT account_code, debit_msat, credit_msat FROM ledger_lines WHERE journal_id = ?', String(journalId))
      .map(line => [line['account_code'], line['debit_msat'], line['credit_msat']]).sort((a, b) => String(a[0]).localeCompare(String(b[0])));
    const sent = Number(PRINCIPAL + FEE);
    expect(lines(journals[0]?.['id'])).toEqual([
      [`channel:cln-m:${S}:local`, 0, sent],
      ['clearing:inflight', sent, 0],
    ]);
    expect(lines(journals[1]?.['id'])).toEqual([
      [`channel:cln-m:${T}:local`, Number(PRINCIPAL), 0],
      ['clearing:inflight', 0, sent],
      ['expense:routing_fees', Number(FEE), 0],
    ]);
  }, 90_000);

  it('CP-037/B5 ledger verify passes after the rebalance and a tampered line fails with exit 8 naming its journal', async () => {
    const d = await demo(open);
    const { executed } = await rebalance(d);
    const run = await d.run(['--json', 'ledger', 'verify']);
    expect(run.status).toBe(SUCCESS);
    const result = resultOf(documentOf(run, 'ledger-verify'));
    expect(result['journals']).toBe(count(d.database, 'ledger_journals'));
    expect(result['steps']).toEqual([
      { step: 1, result: 'compared' }, { step: 2, result: 'compared' }, { step: 3, result: 'compared' }, { step: 4, result: 'not-requested' },
    ]);
    const settled = rows(d.database, "SELECT id FROM ledger_journals WHERE execution_id = ? AND event_type = 'REBALANCE_SETTLED'", String(executed['execution_id']));
    const journalId = String(settled[0]?.['id']);
    tamper(d.database, 'DROP TRIGGER ledger_lines_no_update',
      `UPDATE ledger_lines SET debit_msat = debit_msat + 1 WHERE journal_id = '${journalId}' AND account_code = 'expense:routing_fees'`);
    const broken = await d.run(['--json', 'ledger', 'verify']);
    expect(broken.status).toBe(INVARIANT_BREACH);
    const error = errorOf(documentOf(broken, 'ledger-verify'));
    expect(error['code']).toBe(INVARIANT_BREACH);
    expect(String(error['message'])).toContain(journalId);
    const text = await d.run(['ledger', 'verify']);
    expect(text.status).toBe(INVARIANT_BREACH);
    expect(text.stdout + text.stderr).toContain(journalId);
  }, 90_000);
});

describe('no execution without a stored, verified approval', () => {
  it('CP-026/B5 execute without an approval row refuses with exit 5 and sends nothing, even for a proposal marked APPROVED', async () => {
    const d = await demo(open);
    const { id } = await planned(d);
    const proposed = await d.run(executeArgs(id));
    expect(proposed.status).toBe(SAFETY_REFUSAL);
    expect(errorOf(documentOf(proposed, 'actions-execute'))['code']).toBe(SAFETY_REFUSAL);
    tamper(d.database, `UPDATE liquidity_proposals SET status = 'APPROVED' WHERE id = '${storedId(id)}'`);
    const forged = await d.run(executeArgs(id));
    expect(forged.status).toBe(SAFETY_REFUSAL);
    expect(fundMoving(d)).toEqual([]);
    expect(count(d.database, 'executions')).toBe(0);
  }, 60_000);

  it('CP-026/B3 a stored approval whose caps were changed in the database no longer verifies: exit 5, nothing sent', async () => {
    const d = await demo(open);
    const { id } = await planned(d);
    const run = await d.run(['--json', 'liquidity', 'approve', id, '--key', d.key.keyFile, '--max-fee-msat', '250000', '--max-cltv-delta', '144']);
    expect(run.status).toBe(SUCCESS);
    // Loosened up to the proposal's cap, still inside the policy: only the signature can tell (SPEC §7.7).
    tamper(d.database, 'DROP TRIGGER approvals_no_update', 'UPDATE approvals SET max_fee_msat = 300000');
    const executed = await d.run(executeArgs(id));
    expect(executed.status).toBe(SAFETY_REFUSAL);
    expect(fundMoving(d)).toEqual([]);
    expect(rows(d.database, "SELECT id FROM executions WHERE status <> 'CANCELLED'")).toEqual([]);
  }, 60_000);

  it('CP-026/B3 removing the signing key from approval_keys invalidates the unclaimed approval: exit 5, nothing sent', async () => {
    const d = await demo(open);
    const { id } = await planned(d);
    await approve(d, id);
    const replacement = await generateKey(d.dir, 'replacement.key');
    d.rewrite({ approvalKeys: [replacement] });
    const executed = await d.run(executeArgs(id));
    expect(executed.status).toBe(SAFETY_REFUSAL);
    expect(fundMoving(d)).toEqual([]);
    expect(rows(d.database, "SELECT id FROM executions WHERE status <> 'CANCELLED'")).toEqual([]);
  }, 60_000);

  it('CP-026/W1 execute with no approval key configured refuses with exit 5 before any node call (INV-01)', async () => {
    const d = await demo(open);
    const { id } = await planned(d);
    await approve(d, id);
    d.rewrite({ approvalKeys: [] });
    const connections = d.cln.fake.connections();
    const executed = await d.run(executeArgs(id));
    expect(executed.status).toBe(SAFETY_REFUSAL);
    expect(errorOf(documentOf(executed, 'actions-execute'))['code']).toBe(SAFETY_REFUSAL);
    expect(d.cln.fake.connections()).toBe(connections);
    expect(count(d.database, 'executions')).toBe(0);
  }, 60_000);

  it('CP-032/W1 execute without --require-regtest exits 2 before any node call', async () => {
    const d = await demo(open);
    const { id } = await planned(d);
    await approve(d, id);
    const connections = d.cln.fake.connections();
    const run = await d.run(['--json', 'actions', 'execute', id]);
    expect(run.status).toBe(INVALID_INPUT);
    expect(errorOf(documentOf(run, 'actions-execute'))['code']).toBe(INVALID_INPUT);
    expect(d.cln.fake.connections()).toBe(connections);
    expect(count(d.database, 'executions')).toBe(0);
  }, 60_000);

  it('CP-030/W1 a policy whose network is not regtest refuses execution with exit 1 before any node call (INV-15)', async () => {
    const d = await demo(open);
    const { id } = await planned(d);
    await approve(d, id);
    writeFileSync(d.policy, readFileSync(writeDemoPolicy(d.dir, { network: 'testnet' }, 'testnet-policy.yaml')));
    const connections = d.cln.fake.connections();
    const run = await d.run(executeArgs(id));
    expect(run.status).toBe(POLICY_VIOLATION);
    expect(errorOf(documentOf(run, 'actions-execute'))['code']).toBe(POLICY_VIOLATION);
    expect(d.cln.fake.connections()).toBe(connections);
    expect(count(d.database, 'executions')).toBe(0);
  }, 60_000);

  for (const network of ['bitcoin', 'testnet4']) {
    it(`CP-030/W2 a node reporting network ${network} at execution is refused with exit 5 and nothing is sent (INV-15)`, async () => {
      const d = await demo(open);
      const { id } = await planned(d);
      await approve(d, id);
      d.cln.state.network = network;
      const run = await d.run(executeArgs(id));
      expect(run.status).toBe(SAFETY_REFUSAL);
      expect(errorOf(documentOf(run, 'actions-execute'))).toMatchObject({ code: SAFETY_REFUSAL, step: 'identity' });
      expect(fundMoving(d)).toEqual([]);
      expect(rows(d.database, "SELECT id FROM executions WHERE status <> 'CANCELLED'")).toEqual([]);
      expect(rows(d.database, "SELECT state FROM nodes WHERE name = 'cln-m'")).toEqual([{ state: 'QUARANTINED' }]);
    }, 60_000);
  }
});

describe('actions status', () => {
  it('CP-032/B6 actions status on an unknown execution id exits 2', async () => {
    const d = await demo(open);
    const json = await d.run(['--json', 'actions', 'status', '01JC0000000000000000000000']);
    expect(json.status).toBe(INVALID_INPUT);
    expect(errorOf(documentOf(json, 'actions-status'))['code']).toBe(INVALID_INPUT);
    expect((await d.run(['actions', 'status'])).status).toBe(INVALID_INPUT);
  }, 60_000);
});

describe('credential values on the command line', () => {
  it('CP-026/W2 a credential-looking argument to any money-path command exits 2 before any node call and is never echoed', async () => {
    const d = await demo(open);
    const { id } = await planned(d);
    const rune = d.cln.rune;
    const macaroonHex = readFileSync(SENTINEL_MACAROON).toString('hex');
    const connections = d.cln.fake.connections();
    for (const secret of [rune, macaroonHex]) {
      const argvs = [
        ['liquidity', 'diagnose', '--node', secret],
        ['liquidity', 'plan', '--refresh', '--node', secret],
        ['liquidity', 'explain', secret],
        ['liquidity', 'approve', id, '--key', secret, '--max-fee-msat', '300000', '--max-cltv-delta', '144'],
        ['actions', 'execute', secret, '--require-regtest'],
        ['actions', 'status', secret],
        ['ledger', 'verify', secret],
        ['reconcile', '--node', secret],
        ['evidence', 'export', '--run-id', secret, '--out', `${d.dir}/bundle`],
        ['daemon', secret],
      ];
      for (const argv of argvs) {
        for (const json of [false, true]) {
          const run = await d.run(json ? ['--json', ...argv] : argv);
          expect(run.status, argv.join(' ')).toBe(INVALID_INPUT);
          expect(run.stdout + run.stderr).not.toContain(secret);
          expect(leakedForms(run.stdout + run.stderr, Buffer.from(secret, 'utf8'))).toEqual([]);
        }
      }
    }
    expect(d.cln.fake.connections()).toBe(connections);
    expect(count(d.database, 'approvals')).toBe(0);
  }, 120_000);
});
