/*
 * Interface: `reconcile` and `evidence export` through the built CLI (SPEC §10.3 items 10-11, §9.4, §14.2), and the
 * UNKNOWN path of `actions execute` / `actions status` that reconcile resolves (SPEC §8.4, §10.3 AE11, AS3).
 *
 * Invocation:
 *   fluxwarden [--json] reconcile [--node <name>] [--since <dur>] --config <path>
 *   fluxwarden [--json] evidence export --run-id <run-id> --out <dir> --config <path>
 *   <dur> is <int>(s|m|h|d); anything else -> exit 2. An unknown --node -> exit 2.
 *
 * reconcile (RC1-RC4): resolves every non-terminal execution from node evidence (never a payment call), compares the
 *   ledger with the node's accounting for the period (CLN: listsendpays, listinvoices, bkpr-listaccountevents,
 *   listpeerchannels) and writes a report with a run id `run_<ULID>`. --json: schemas/output/reconcile.json
 *   { run_id, since (unix ms), nodes: [ { name, result } ], executions: [ { execution_id, from, to } ] (each status change it
 *   made), differences: [ { node, execution_id, item, ledger_msat, node_msat, journal_id } ], steps: [ { step, result } ] }.
 *   Exit 8 if verification steps 1-3 fail; else 7 if an execution stays UNKNOWN/IN_FLIGHT; else 9 if any difference
 *   (each posted as a RECON_DIFFERENCE journal with a recon:difference line); else 0. With exit 7 or 9 the document carries
 *   both the report in `result` and the `error`.
 * evidence export (EV1-EV3): unknown run id -> 2; --out existing and not empty -> 2, left untouched; the bundle of SPEC
 *   §14.2 (manifest.json, topology-before.json, topology-after.json, proposals.json, execution-trace.ndjson,
 *   ledger-audit.json, reconciliation.json, chaos-results.json) plus checksums.sha256 in `sha256sum` format
 *   ("<64 hex>  <name>" per line, every other file once); leak-checked; --json: schemas/output/evidence-export.json
 *   { run_id, out, files: [ { name, sha256 } ] } listing the eight bundle files. Two exports of the same run are identical.
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { MUTATING, callsOf, methodsOf } from '../fakes/cln/rebalance-node.js';
import { leakedForms } from '../helpers/cp016-cli.js';
import {
  approve, count, demo as createDemo, documentOf, errorOf, INVALID_INPUT, list, OUTCOME_UNKNOWN, plan, prepareDemoFixtures, RECONCILIATION_ALERT, rec, resultOf, rows,
  sha256Hex, SUCCESS, type Demo, type DemoFixtures, type DemoOptions, type Doc,
} from '../helpers/cpw-cli.js';

const open: FakeServer[] = [];
let fixtures: DemoFixtures;
beforeAll(async () => { fixtures = await prepareDemoFixtures(); });
const demo = (servers: FakeServer[], options: DemoOptions = {}) => createDemo(servers, { ...options, fixtures });
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

const BUNDLE = ['chaos-results.json', 'execution-trace.ndjson', 'ledger-audit.json', 'manifest.json', 'proposals.json', 'reconciliation.json', 'topology-after.json', 'topology-before.json'];

async function rebalance(d: Demo): Promise<{ proposalId: string; executionId: string }> {
  const proposalId = String((await plan(d))['proposal_id']);
  await approve(d, proposalId);
  const run = await d.run(['--json', 'actions', 'execute', proposalId, '--require-regtest']);
  if (run.status !== SUCCESS) throw new Error(`actions execute exited ${String(run.status)}: ${run.stdout}${run.stderr}`);
  return { proposalId, executionId: String(resultOf(documentOf(run, 'actions-execute'))['execution_id']) };
}

async function reconcile(d: Demo, expected: number): Promise<{ doc: Doc; result: Doc }> {
  const run = await d.run(['--json', 'reconcile', '--node', 'cln-m', '--since', '1h']);
  expect(run.status, run.stdout + run.stderr).toBe(expected);
  const doc = documentOf(run, 'reconcile');
  return { doc, result: rec(doc['result']) };
}

describe('reconcile', () => {
  it('CP-038/B1 after the rebalance the ledger matches the node accounting: no difference, exit 0, no payment call', async () => {
    const d = await demo(open);
    await rebalance(d);
    const mutatingBefore = methodsOf(d.cln.fake).filter(method => MUTATING.includes(method)).length;
    const { result } = await reconcile(d, SUCCESS);
    expect(String(result['run_id'])).toMatch(/^run_[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(result['differences']).toEqual([]);
    expect(result['executions']).toEqual([]);
    expect(result['nodes']).toEqual([{ name: 'cln-m', result: 'compared' }]);
    expect(list(result['steps']).map(step => rec(step)['result'])).toEqual(['compared', 'compared', 'compared', 'compared']);
    expect(Number(result['since'])).toBeGreaterThan(Date.now() - 3_600_000 - 60_000);
    expect(Number(result['since'])).toBeLessThanOrEqual(Date.now() - 3_600_000 + 60_000);
    expect(rows(d.database, "SELECT id FROM ledger_journals WHERE event_type = 'RECON_DIFFERENCE'")).toEqual([]);
    // SPEC §9.4 sources were read; nothing that moves funds was called.
    const methods = methodsOf(d.cln.fake);
    for (const method of ['listsendpays', 'bkpr-listaccountevents', 'listpeerchannels']) expect(methods, method).toContain(method);
    expect(methods.filter(method => MUTATING.includes(method)).length).toBe(mutatingBefore);
  }, 120_000);

  it('CP-038/B2 an extra fee in the bookkeeper is a difference: recon:difference posting and exit 9', async () => {
    // Bookkeeper reports 202,102 msat; the ledger expensed the node-confirmed 202,101 (SPEC §9.4).
    const d = await demo(open, { fake: { bkprFeeMsat: 202_102n } });
    const { executionId } = await rebalance(d);
    const { doc, result } = await reconcile(d, RECONCILIATION_ALERT);
    expect(errorOf(doc)['code']).toBe(RECONCILIATION_ALERT);
    const differences = list(result['differences']).map(rec);
    expect(differences).toHaveLength(1);
    expect(differences[0]).toMatchObject({ node: 'cln-m', execution_id: executionId, ledger_msat: '202101', node_msat: '202102' });
    const journals = rows(d.database, "SELECT id FROM ledger_journals WHERE event_type = 'RECON_DIFFERENCE'");
    expect(journals).toEqual([{ id: differences[0]?.['journal_id'] }]);
    const lines = rows(d.database, 'SELECT account_code, debit_msat, credit_msat FROM ledger_lines WHERE journal_id = ?', String(journals[0]?.['id']));
    const recon = lines.filter(line => line['account_code'] === 'recon:difference');
    expect(recon).toHaveLength(1);
    expect(Number(recon[0]?.['debit_msat']) + Number(recon[0]?.['credit_msat'])).toBe(1);
    expect(lines.reduce((sum, line) => sum + Number(line['debit_msat']) - Number(line['credit_msat']), 0)).toBe(0);
  }, 120_000);

  it('CP-038/W1 a malformed --since or an unknown --node exits 2 before any node call', async () => {
    const d = await demo(open);
    const connections = d.cln.fake.connections();
    for (const args of [['--since', 'yesterday'], ['--since', '0'], ['--node', 'cln-x'], ['--since']]) {
      const run = await d.run(['--json', 'reconcile', ...args]);
      expect(run.status, args.join(' ')).toBe(INVALID_INPUT);
      expect(errorOf(documentOf(run, 'reconcile'))['code']).toBe(INVALID_INPUT);
    }
    expect(d.cln.fake.connections()).toBe(connections);
  }, 60_000);
});

describe('UNKNOWN and its resolution', () => {
  it('CP-032/B6 a lost sendpay answer exits 7 with the reconcile message; reconcile resolves it from node evidence without a second send', async () => {
    const d = await demo(open, { fake: { sendpay: 'lose-answer' } });
    d.rewrite({ attemptDeadline: '1s' });
    const proposalId = String((await plan(d))['proposal_id']);
    await approve(d, proposalId);
    const text = await d.run(['actions', 'execute', proposalId, '--require-regtest'], { timeoutMs: 5_000 });
    expect(text.status).toBe(OUTCOME_UNKNOWN);
    expect(text.stdout + text.stderr).toContain('outcome unknown — run `fluxwarden reconcile`; do not retry');
    const executions = rows(d.database, 'SELECT id, status FROM executions');
    expect(executions).toEqual([{ id: executions[0]?.['id'], status: 'UNKNOWN' }]);
    const executionId = String(executions[0]?.['id']);
    expect(rows(d.database, "SELECT event_type FROM ledger_journals WHERE execution_id = ? AND event_type IN ('REBALANCE_SETTLED', 'REBALANCE_REVERSED')", executionId)).toEqual([]);

    const status = await d.run(['--json', 'actions', 'status', executionId]);
    expect(status.status).toBe(OUTCOME_UNKNOWN);
    expect(resultOf(documentOf(status, 'actions-status'))['status']).toBe('UNKNOWN');
    const statusText = await d.run(['actions', 'status', executionId]);
    expect(statusText.status).toBe(OUTCOME_UNKNOWN);
    expect(statusText.stdout + statusText.stderr).toContain('outcome unknown — run `fluxwarden reconcile`; do not retry');

    // The node comes back: it settled the payment (preimage in listsendpays).
    d.cln.state.unreachable = false;
    const { result } = await reconcile(d, SUCCESS);
    expect(result['executions']).toEqual([{ execution_id: executionId, from: 'UNKNOWN', to: 'VERIFIED_SUCCESS' }]);
    const resolved = await d.run(['--json', 'actions', 'status', executionId]);
    expect(resolved.status).toBe(SUCCESS);
    expect(resultOf(documentOf(resolved, 'actions-status'))).toMatchObject({ status: 'VERIFIED_SUCCESS', actual_fee_msat: '202101' });
    expect(callsOf(d.cln.fake, 'sendpay')).toHaveLength(1);
    expect(callsOf(d.cln.fake, 'invoice')).toHaveLength(1);
    expect(rows(d.database, 'SELECT event_type FROM ledger_journals WHERE execution_id = ? ORDER BY event_type', executionId).map(row => row['event_type']))
      .toEqual(['REBALANCE_SENT', 'REBALANCE_SETTLED']);
  });
});

describe('evidence export', () => {
  async function exported(d: Demo): Promise<string> {
    await rebalance(d);
    const { result } = await reconcile(d, SUCCESS);
    return String(result['run_id']);
  }

  it('CP-039/B1 evidence export writes the SPEC §14.2 bundle whose checksums verify', async () => {
    const d = await demo(open);
    const runId = await exported(d);
    const out = join(d.dir, 'bundle');
    const run = await d.run(['--json', 'evidence', 'export', '--run-id', runId, '--out', out]);
    expect(run.status).toBe(SUCCESS);
    const result = resultOf(documentOf(run, 'evidence-export'));
    expect(result['run_id']).toBe(runId);
    expect(readdirSync(out).sort()).toEqual([...BUNDLE, 'checksums.sha256'].sort());
    const files = list(result['files']).map(rec);
    expect(files.map(file => file['name']).sort()).toEqual(BUNDLE);
    // checksums.sha256 in sha256sum format: one line per bundle file, each digest the file's SHA-256.
    const lines = readFileSync(join(out, 'checksums.sha256'), 'utf8').trimEnd().split('\n');
    expect(lines).toHaveLength(BUNDLE.length);
    const listed = new Map(lines.map(line => {
      const match = /^([0-9a-f]{64}) {2}(\S+)$/.exec(line);
      if (match === null) throw new Error(`not a sha256sum line: ${line}`);
      return [match[2] ?? '', match[1] ?? ''];
    }));
    expect([...listed.keys()].sort()).toEqual(BUNDLE);
    for (const name of BUNDLE) {
      const digest = sha256Hex(readFileSync(join(out, name)));
      expect(listed.get(name), name).toBe(digest);
      expect(files.find(file => file['name'] === name)?.['sha256'], name).toBe(digest);
    }
    const manifest = rec(JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8')));
    const text = JSON.stringify(manifest);
    for (const expected of [d.key.keyId, String(rows(d.database, 'SELECT policy_sha256 FROM policy_versions')[0]?.['policy_sha256']), d.cln.state.id]) {
      expect(text, expected).toContain(expected);
    }
    // One transition line per execution event (SPEC §14.2 execution-trace.ndjson).
    const trace = readFileSync(join(out, 'execution-trace.ndjson'), 'utf8').trimEnd().split('\n');
    expect(trace).toHaveLength(count(d.database, 'execution_events'));
    for (const line of trace) expect(() => JSON.parse(line) as unknown).not.toThrow();
  }, 120_000);

  it('CP-039/B3 no bundle file carries the node credential in any encoding', async () => {
    const d = await demo(open);
    const runId = await exported(d);
    const out = join(d.dir, 'bundle');
    expect((await d.run(['evidence', 'export', '--run-id', runId, '--out', out])).status).toBe(SUCCESS);
    const rune = Buffer.from(d.cln.rune, 'utf8');
    for (const name of readdirSync(out)) {
      const content = readFileSync(join(out, name), 'latin1');
      expect(leakedForms(content, rune), name).toEqual([]);
      expect(content, name).not.toContain(d.cln.rune);
    }
  }, 120_000);

  it('CP-039/B4 two exports of the same run are identical', async () => {
    const d = await demo(open);
    const runId = await exported(d);
    const first = join(d.dir, 'bundle-1');
    const second = join(d.dir, 'bundle-2');
    expect((await d.run(['evidence', 'export', '--run-id', runId, '--out', first])).status).toBe(SUCCESS);
    expect((await d.run(['evidence', 'export', '--run-id', runId, '--out', second])).status).toBe(SUCCESS);
    for (const name of [...BUNDLE, 'checksums.sha256']) {
      expect(readFileSync(join(second, name)).equals(readFileSync(join(first, name))), name).toBe(true);
    }
  }, 120_000);

  it('CP-039/B2 an existing non-empty --out or an unknown run id exits 2 and writes nothing', async () => {
    const d = await demo(open);
    const runId = await exported(d);
    const out = join(d.dir, 'taken');
    mkdirSync(out);
    writeFileSync(join(out, 'keep.txt'), 'operator file\n');
    const taken = await d.run(['--json', 'evidence', 'export', '--run-id', runId, '--out', out]);
    expect(taken.status).toBe(INVALID_INPUT);
    expect(errorOf(documentOf(taken, 'evidence-export'))['code']).toBe(INVALID_INPUT);
    expect(readdirSync(out)).toEqual(['keep.txt']);
    expect(readFileSync(join(out, 'keep.txt'), 'utf8')).toBe('operator file\n');
    const fresh = join(d.dir, 'fresh');
    const unknown = await d.run(['--json', 'evidence', 'export', '--run-id', 'run_01JC0000000000000000000000', '--out', fresh]);
    expect(unknown.status).toBe(INVALID_INPUT);
    expect(errorOf(documentOf(unknown, 'evidence-export'))['code']).toBe(INVALID_INPUT);
    expect(existsSync(fresh)).toBe(false);
    for (const runIdArg of ['../run_01JC0000000000000000000000', 'run_x/../../etc']) {
      const traversal = await d.run(['--json', 'evidence', 'export', '--run-id', runIdArg, '--out', fresh]);
      expect(traversal.status, runIdArg).toBe(INVALID_INPUT);
    }
    expect(existsSync(fresh)).toBe(false);
  }, 120_000);
});
