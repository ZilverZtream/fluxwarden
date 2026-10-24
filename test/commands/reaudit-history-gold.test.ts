// SPEC Commands RC2-RC4 / Evidence EV1-EV3: a short node/window report must
// remain usable with retained completed signed attempts. SECURITY section 4.1
// supplies the independent digest/signature encoding below. Product Policy
// requires complete incoming history for EWMA, or a conservative refusal.
import { createHash, createPrivateKey, randomBytes, sign } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';
import { afterEach, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { clnInvoice } from '../fakes/cln/responses.js';
import { MUTATING, methodsOf, S, T } from '../fakes/cln/rebalance-node.js';
import { approvalMessage, approve, demo, documentOf, jsonDocument, list, plan, rec, resultOf, rows, storedId, until, verifiesWith, type Demo } from '../helpers/cpw-cli.js';
import { spawnCli } from '../helpers/cp016-cli.js';
import { claimed, dbNow, loadClaim, loadPersistence, policyFor, seedBase, seedProposal } from '../helpers/cp028-executor.js';
import { prepareMoneySafetyAlertKey, registerMoneySafetyCredentials } from '../helpers/public-money-safety.js';

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });
const RECORD_BOUND = 16 * 1024 * 1024;

function proposalDigest(row: Record<string, SQLInputValue>, pubkey: string, policy: string): string {
  const fields = [String(row['id']), pubkey, S, T, String(row['principal_msat']),
    String(row['max_fee_msat']), String(row['max_fee_ppm']), '5000', String(row['max_cltv_delta']), policy, String(row['expires_at'])];
  const hash = createHash('sha256').update('FluxWarden-proposal-v1\0');
  for (const field of fields) {
    const bytes = Buffer.from(field), length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length); hash.update(length).update(bytes);
  }
  return hash.digest('hex');
}

function requiredRow(db: DatabaseSync, sql: string, ...args: SQLInputValue[]): Record<string, SQLInputValue> {
  const row = db.prepare(sql).get(...args);
  if (row === undefined) throw new Error('signed historical fixture prerequisite is missing');
  return row;
}

async function signedCancelledHistory(d: Demo, proposalId: string, smallControl = true): Promise<void> {
  const key = createPrivateKey(readFileSync(d.key.keyFile));
  const db = new DatabaseSync(d.database);
  try {
    const current = requiredRow(db, 'SELECT * FROM liquidity_proposals WHERE id = ?', storedId(proposalId));
    const approval = requiredRow(db, 'SELECT * FROM approvals WHERE proposal_id = ?', String(current['id']));
    const node = requiredRow(db, 'SELECT * FROM nodes WHERE id = ?', String(current['node_id']));
    const policy = String(requiredRow(db, 'SELECT policy_sha256 FROM policy_versions WHERE id = ?', String(current['policy_version_id']))['policy_sha256']);
    // Confirm the independent reference against the public CLI's existing
    // genuinely approved intent before creating any historical copies.
    expect(proposalDigest(current, String(node['expected_pubkey']), policy)).toBe(current['proposal_digest']);
    const otherNode = { ...node, id: '00000000000000000000190000', name: 'retained-other-node', expected_pubkey: `02${'39'.repeat(32)}` };
    const insert = (table: string, example: Record<string, SQLInputValue>) => {
      const columns = Object.keys(example);
      const statement = db.prepare(`INSERT INTO ${table} (${columns.join(',')}) VALUES (${columns.map(() => '?').join(',')})`);
      return (row: Record<string, SQLInputValue>): void => { statement.run(...columns.map(column => row[column] ?? null)); };
    };
    const insertNode = insert('nodes', node), insertP = insert('liquidity_proposals', current), insertA = insert('approvals', approval);
    db.exec('BEGIN');
    insertNode(otherNode);
    const channelIds = new Map<string, string>();
    for (const channel of db.prepare('SELECT * FROM channels WHERE node_id = ?').all(String(node['id']))) {
      const oldId = String(channel['id']), newId = `OLD${oldId.slice(3)}`;
      insert('channels', channel)({ ...channel, id: newId, node_id: otherNode.id });
      channelIds.set(oldId, newId);
    }
    // Nodes/channels are ordinary normalized identity fixtures, not another
    // configured network endpoint. Half the history belongs to this other node.
    const execution = db.prepare(`INSERT INTO executions
      (id,proposal_id,approval_id,worker_id,fence_epoch,status,error_code,created_at,updated_at)
      VALUES (?,?,?,'retained-worker',1,'CANCELLED','BUDGET_EXHAUSTED',?,?)`);
    const event = db.prepare(`INSERT INTO execution_events (execution_id,fence_epoch,from_status,to_status,evidence_json,at)
      VALUES (?,1,NULL,'CANCELLED','{}',?)`);
    const old = Date.now() - 172_800_000;
    for (let i = 0; i < 12_000; i++) {
      const id = (i + 1).toString(16).toUpperCase().padStart(26, '0');
      const aid = (i + 50_000).toString(16).toUpperCase().padStart(26, '0');
      const eid = (i + 100_000).toString(16).toUpperCase().padStart(26, '0');
      const other = i % 2 === 1;
      const historical: Record<string, SQLInputValue> = { ...current, id,
        node_id: other ? otherNode.id : current['node_id'] ?? null,
        source_channel_id: other ? channelIds.get(String(current['source_channel_id'])) ?? null : current['source_channel_id'] ?? null,
        target_channel_id: other ? channelIds.get(String(current['target_channel_id'])) ?? null : current['target_channel_id'] ?? null,
        created_at: old, expires_at: old + 900_000 };
      const digest = proposalDigest(historical, other ? otherNode.expected_pubkey : String(node['expected_pubkey']), policy);
      historical['proposal_digest'] = digest;
      const nonce = randomBytes(32);
      const message = approvalMessage({ digest, policySha256: policy, maxFeeMsat: BigInt(String(approval['max_fee_msat'])),
        maxCltvDelta: Number(approval['max_cltv_delta']), expiresAt: BigInt(old + 600_000), nonce, keyId: d.key.keyId });
      const signature = sign(null, message, key);
      // Every historical approval is authentic; unsigned oversized dummy rows
      // would test a different input than retained operator-approved attempts.
      if (!verifiesWith(d.key.publicKey, message, signature)) throw new Error('historical approval fixture failed independent verification');
      insertP(historical);
      insertA({ ...approval, id: aid, proposal_id: id, nonce: nonce.toString('hex'), signature: signature.toString('base64'),
        created_at: old, expires_at: old + 600_000 });
      execution.run(eid, id, aid, old, old); event.run(eid, old);
      if (i === 1 && smallControl) {
        db.exec('COMMIT');
        // Same authenticated mixed-node fixture at small scale proves the
        // prerequisite works; only retained history volume then changes.
        const control = await d.run(['--json', 'reconcile', '--node', 'cln-m', '--since', '1h'], { timeoutMs: 60_000 });
        expect(control.status, 'small signed historical fixture is a valid reconciliation input').toBe(0);
        documentOf(control, 'reconcile');
        db.exec('BEGIN');
      }
    }
    db.exec('COMMIT');
  } finally { db.close(); }
}

function historyFingerprint(database: string): string {
  const db = new DatabaseSync(database), hash = createHash('sha256');
  try {
    for (const table of ['liquidity_proposals', 'approvals', 'executions', 'execution_events', 'ledger_journals', 'ledger_lines']) {
      hash.update(table);
      for (const row of db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).iterate()) hash.update(JSON.stringify(row));
    }
    return hash.digest('hex');
  } finally { db.close(); }
}

function assertCurrentJournalLines(text: string, executionId: string): void {
  const audit = rec(JSON.parse(text) as unknown);
  const journals = list(audit['journals']).map(rec).filter(row => row['executionId'] === executionId);
  expect(journals).toHaveLength(2);
  const lines = (type: string): unknown[] => list(journals.find(row => row['eventType'] === type)?.['lines']);
  // SPEC section 9.3 worked postings: debit principal+202101 to clearing on
  // send; on settlement debit 100m to T and 202101 to fees, clearing to zero.
  expect(lines('REBALANCE_SENT')).toEqual([
    { sequenceNo: 1, account: 'clearing:inflight', debitMsat: '100202101', creditMsat: '0' },
    { sequenceNo: 2, account: 'channel:cln-m:102x1x0:local', debitMsat: '0', creditMsat: '100202101' },
  ]);
  expect(lines('REBALANCE_SETTLED')).toEqual([
    { sequenceNo: 1, account: 'channel:cln-m:105x1x0:local', debitMsat: '100000000', creditMsat: '0' },
    { sequenceNo: 2, account: 'expense:routing_fees', debitMsat: '202101', creditMsat: '0' },
    { sequenceNo: 3, account: 'clearing:inflight', debitMsat: '0', creditMsat: '100202101' },
  ]);
}

function assertHistoryScope(manifest: Record<string, unknown>): void {
  // Public SPEC Commands/Evidence contract: omitted history is disclosed in
  // the existing unavailable_evidence map. Check its meaning, not exact prose.
  const unavailable = rec(manifest['unavailable_evidence']);
  const proposals = unavailable['proposal_history'], ledger = unavailable['ledger_history'];
  expect(typeof proposals, 'proposal-history scope is an explicit manifest explanation').toBe('string');
  expect(typeof ledger, 'ledger-history scope is an explicit manifest explanation').toBe('string');
  for (const meaning of [/node/i, /window|period|since|until/i, /unresolved|pending|non.?terminal/i,
    /changed|recover|updated|transition/i, /reference|accounting|journal/i, /omit|exclud|retained|unrelated|outside/i]) {
    expect(proposals, 'proposal history describes selected scope, required execution closure and omitted history').toMatch(meaning);
  }
  for (const meaning of [/full|whole|complete|entire/i, /verif/i, /balance/i, /subset|scop|select|window/i,
    /cannot|not|doesn.t|alone|insufficient/i]) {
    expect(ledger, 'scoped exported journals are distinguished from whole-book verification and balances').toMatch(meaning);
  }
}

it('CP-038/REG-DEEP04 short-window reconciliation retains current signed execution evidence despite twelve thousand old cancelled attempts on two nodes', async () => {
  const d = await demo(open);
  registerMoneySafetyCredentials([d.cln.runeFile, d.key.keyFile]);
  await prepareMoneySafetyAlertKey(d.database);
  const proposalId = String((await plan(d))['proposal_id']);
  await approve(d, proposalId);
  const executed = await d.run(['--json', 'actions', 'execute', proposalId, '--require-regtest']);
  expect(executed.status, 'public signed execution prerequisite succeeds').toBe(0);
  const current = rows(d.database, 'SELECT id, approval_id, status FROM executions')[0];
  expect(current?.['status']).toBe('VERIFIED_SUCCESS');
  const currentId = String(current?.['id']);
  const journalIds = rows(d.database, 'SELECT id FROM ledger_journals WHERE execution_id = ?', currentId).map(row => String(row['id']));
  expect(journalIds).toHaveLength(2);
  await signedCancelledHistory(d, proposalId);
  expect(rows(d.database, 'SELECT count(*) AS n FROM executions')).toEqual([{ n: 12_001 }]);
  expect(rows(d.database, `SELECT n.name, count(*) AS n FROM executions e JOIN liquidity_proposals p ON p.id=e.proposal_id
    JOIN nodes n ON n.id=p.node_id WHERE e.status='CANCELLED' GROUP BY n.name ORDER BY n.name`))
    .toEqual([{ name: 'cln-m', n: 6000 }, { name: 'retained-other-node', n: 6000 }]);
  const before = historyFingerprint(d.database);
  for (let attempt = 0; attempt < 2; attempt++) {
    const run = await d.run(['--json', 'reconcile', '--node', 'cln-m', '--since', '1h'], { timeoutMs: 60_000 });
    expect(run.status, 'selected short-window reconciliation remains operational with signed history').toBe(0);
    const result = resultOf(documentOf(run, 'reconcile'));
    expect(result['differences']).toEqual([]);
    expect(result['nodes']).toEqual([{ name: 'cln-m', result: 'compared' }]);
    const runId = String(result['run_id']);
    const recorded = `${d.database}.${runId}.json`;
    expect(statSync(recorded).size, 'the original run-record bound remains sufficient').toBeLessThanOrEqual(RECORD_BOUND);
    const out = join(d.dir, `history-export-${String(attempt)}`);
    const exported = await d.run(['--json', 'evidence', 'export', '--run-id', runId, '--out', out], { timeoutMs: 60_000 });
    expect(exported.status).toBe(0);
    documentOf(exported, 'evidence-export');
    const proposals = readFileSync(join(out, 'proposals.json'), 'utf8');
    expect(proposals.includes(storedId(proposalId)), 'current proposal remains in recorded evidence').toBe(true);
    // SPEC section 14.2 explicitly includes approvals without private material
    // in proposals.json; a manifest key id alone does not close this reference.
    expect(proposals.includes(String(current?.['approval_id'])), 'current approval reference remains in recorded evidence').toBe(true);
    const manifest = rec(JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8')) as unknown);
    assertHistoryScope(manifest);
    expect(manifest['approval_key_ids']).toEqual([d.key.keyId]);
    expect(manifest['policy_sha256']).toBe(rows(d.database, 'SELECT policy_sha256 FROM policy_versions')[0]?.['policy_sha256']);
    const trace = readFileSync(join(out, 'execution-trace.ndjson'), 'utf8').trim().split('\n').map(line => rec(JSON.parse(line) as unknown));
    expect(trace.filter(row => row['execution_id'] === currentId)).toHaveLength(rows(d.database, 'SELECT id FROM execution_events WHERE execution_id = ?', currentId).length);
    const ledger = readFileSync(join(out, 'ledger-audit.json'), 'utf8');
    for (const id of journalIds) expect(ledger.includes(id), 'current journals remain in the report').toBe(true);
    assertCurrentJournalLines(ledger, currentId);
    const reconciliation = JSON.parse(readFileSync(join(out, 'reconciliation.json'), 'utf8')) as unknown;
    expect(JSON.stringify(reconciliation).includes('cln-m')).toBe(true);
    expect(readdirSync(out).reduce((sum, file) => sum + statSync(join(out, file)).size, 0)).toBeLessThan(RECORD_BOUND);
    const again = join(d.dir, `history-export-repeat-${String(attempt)}`);
    expect((await d.run(['--json', 'evidence', 'export', '--run-id', runId, '--out', again], { timeoutMs: 60_000 })).status).toBe(0);
    for (const file of readdirSync(out)) expect(readFileSync(join(again, file)).equals(readFileSync(join(out, file))), 'same-run exports are immutable').toBe(true);
  }
  expect(historyFingerprint(d.database), 'bounded evidence selection preserves all operator history').toBe(before);
  expect(d.cln.state.sent).toHaveLength(1);
}, 90_000);

it('CP-038/REG-DEEP04-UNSELECTED selected-node reconciliation never hides a housekeeping change to another node claim', async () => {
  const d = await demo(open, { withKey: false });
  registerMoneySafetyCredentials([d.cln.runeFile]);
  await prepareMoneySafetyAlertKey(d.database);
  await plan(d);
  const livePolicy = rows(d.database, 'SELECT id, policy_sha256 FROM policy_versions')[0];
  const persistence = await loadPersistence(), claim = await loadClaim();
  const other = { ...seedBase(persistence, d.database), // baseline lnd-r identity/channels
    policyVersionId: String(livePolicy?.['id']), policySha256: String(livePolicy?.['policy_sha256']) };
  const db = persistence.openDatabase(d.database, { readOnly: false });
  let executionId: string, proposalId: string, approvalId: string, expiresAt: number;
  try {
    const approval = seedProposal(other, { proposalTtlMs: 3000, approvalTtlMs: 3000 });
    const fixture = new DatabaseSync(d.database);
    try {
      // The claim-only helper's '{}' explanation is deliberately minimal.
      // Give the public recorder the planner's complete explanation shape;
      // this does not invent a payment, a hash, a transition or a journal.
      fixture.prepare(`UPDATE liquidity_proposals SET reason_json =
        (SELECT reason_json FROM liquidity_proposals WHERE node_id <> ? LIMIT 1)
        WHERE id = ?`).run(other.nodeId, approval.proposalId);
    } finally { fixture.close(); }
    const taken = claimed(claim.claimExecution(db, { approval, policy: policyFor(other),
      approvalKeyIds: [approval.keyId], workerId: 'unselected-expiring-worker', leaseMs: 1 }));
    executionId = taken.executionId; proposalId = approval.proposalId;
    approvalId = approval.approvalId; expiresAt = approval.expiresAt;
  } finally { db.close(); }
  const before = rows(d.database, 'SELECT * FROM executions WHERE id = ?', executionId);
  const reservationBefore = rows(d.database, 'SELECT * FROM budget_reservations WHERE execution_id = ?', executionId);
  expect(before[0]).toMatchObject({ status: 'CLAIMED', payment_hash: null, proposal_id: proposalId, approval_id: approvalId });
  expect(reservationBefore[0]).toMatchObject({ state: 'HELD', reserved_msat: 200000, consumed_msat: null });
  const approvalBefore = createHash('sha256').update(JSON.stringify(rows(d.database, 'SELECT * FROM approvals WHERE id = ?', approvalId))).digest('hex');
  const journalsBefore = rows(d.database, 'SELECT * FROM ledger_journals ORDER BY id');
  // A real claim and its one-ms lease expire by the actual SQLite clock. No
  // payment, hash or invented in-flight state is needed for this sweep case.
  await until(() => dbNow(d.database) > expiresAt, 10_000, 'the genuine claim approval to expire');
  const run = await d.run(['--json', 'reconcile', '--node', 'cln-m', '--since', '1h']);
  expect(run.status).toBe(0);
  const result = resultOf(documentOf(run, 'reconcile'));
  const after = rows(d.database, 'SELECT * FROM executions WHERE id = ?', executionId);
  const reservationAfter = rows(d.database, 'SELECT * FROM budget_reservations WHERE execution_id = ?', executionId);
  // RC2 limits payment recovery to selected nodes; section 6.5 also permits
  // expired-unsent housekeeping. Either isolation or honest changed-input
  // closure is acceptable. SPEC section 14.2 requires the actual transitions
  // and proposals, including a change discovered outside the selected window.
  if (JSON.stringify(after) === JSON.stringify(before)) {
    expect(reservationAfter).toEqual(reservationBefore);
  } else {
    expect(after[0]).toMatchObject({ status: 'CANCELLED', payment_hash: null,
      proposal_id: proposalId, approval_id: approvalId });
    expect(reservationAfter[0]).toMatchObject({ state: 'RELEASED', reserved_msat: 200000, consumed_msat: null });
    const record = rec(JSON.parse(readFileSync(`${d.database}.${String(result['run_id'])}.json`, 'utf8')) as unknown);
    const trace = list(record['executionTrace']).map(rec);
    expect(trace, 'every actual unselected-node change remains in the recorded execution trace')
      .toContainEqual(expect.objectContaining({ execution_id: executionId, from: 'CLAIMED', to: 'CANCELLED' }));
    const proposals = list(record['proposals']).map(rec);
    expect(proposals, 'the changed execution keeps its actual node and proposal input')
      .toContainEqual(expect.objectContaining({ proposal_id: `prop_${proposalId}`, node: 'lnd-r' }));
  }
  expect(createHash('sha256').update(JSON.stringify(rows(d.database, 'SELECT * FROM approvals WHERE id = ?', approvalId))).digest('hex'),
    'the changed execution retains its immutable public approval reference').toBe(approvalBefore);
  expect(rows(d.database, 'SELECT * FROM ledger_journals ORDER BY id'), 'hashless housekeeping creates no financial posting').toEqual(journalsBefore);
  expect(d.cln.state.sent).toEqual([]);
});

it('CP-038/REG-DEEP04-UNKNOWN historical volume preserves recovery of the current UNKNOWN attempt and its journal references without another send', async () => {
  const d = await demo(open, { fake: { sendpay: 'lose-answer' } });
  registerMoneySafetyCredentials([d.cln.runeFile, d.key.keyFile]);
  await prepareMoneySafetyAlertKey(d.database);
  d.rewrite({ attemptDeadline: '1s' });
  const proposalId = String((await plan(d))['proposal_id']);
  await approve(d, proposalId);
  const sent = await d.run(['--json', 'actions', 'execute', proposalId, '--require-regtest']);
  expect(sent.status, 'a real lost send reply leaves the baseline attempt unresolved').toBe(7);
  documentOf(sent, 'actions-execute');
  const current = rows(d.database, 'SELECT id, status, payment_hash FROM executions')[0];
  expect(current?.['status']).toBe('UNKNOWN');
  const currentId = String(current?.['id']);
  expect(rows(d.database, 'SELECT state FROM budget_reservations WHERE execution_id = ?', currentId)).toEqual([{ state: 'HELD' }]);
  // Preserve the real current unresolved attempt while constructing only old
  // completed copies. The first case separately proves the small control.
  await signedCancelledHistory(d, proposalId, false);
  d.cln.state.unreachable = false;
  const recovered = await d.run(['--json', 'reconcile', '--node', 'cln-m', '--since', '1h'], { timeoutMs: 60_000 });
  expect(recovered.status, 'retained old terminal history must not prevent a recorded recovery report').toBe(0);
  const result = resultOf(documentOf(recovered, 'reconcile'));
  expect(result['executions']).toEqual([{ execution_id: currentId, from: 'UNKNOWN', to: 'VERIFIED_SUCCESS' }]);
  expect(rows(d.database, 'SELECT status, payment_hash FROM executions WHERE id = ?', currentId))
    .toEqual([{ status: 'VERIFIED_SUCCESS', payment_hash: current?.['payment_hash'] }]);
  expect(rows(d.database, 'SELECT state, consumed_msat FROM budget_reservations WHERE execution_id = ?', currentId))
    .toEqual([{ state: 'CONSUMED', consumed_msat: 202101 }]);
  const journalIds = rows(d.database, 'SELECT id, event_type FROM ledger_journals WHERE execution_id = ? ORDER BY event_type', currentId);
  expect(journalIds.map(row => row['event_type'])).toEqual(['REBALANCE_SENT', 'REBALANCE_SETTLED']);
  const out = join(d.dir, 'recovered-history-export');
  expect((await d.run(['--json', 'evidence', 'export', '--run-id', String(result['run_id']), '--out', out], { timeoutMs: 60_000 })).status).toBe(0);
  assertHistoryScope(rec(JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8')) as unknown));
  const trace = readFileSync(join(out, 'execution-trace.ndjson'), 'utf8').trim().split('\n').map(line => rec(JSON.parse(line) as unknown));
  expect(trace).toContainEqual(expect.objectContaining({ execution_id: currentId, from: 'UNKNOWN', to: 'VERIFIED_SUCCESS' }));
  const ledger = readFileSync(join(out, 'ledger-audit.json'), 'utf8');
  for (const journal of journalIds) expect(ledger.includes(String(journal['id'])), 'recovery keeps every required execution journal').toBe(true);
  assertCurrentJournalLines(ledger, currentId);
  const beforeRepeat = historyFingerprint(d.database);
  const repeated = await d.run(['--json', 'reconcile', '--node', 'cln-m', '--since', '1h'], { timeoutMs: 60_000 });
  expect(repeated.status).toBe(0);
  expect(historyFingerprint(d.database), 'recovery does not duplicate events or journals on repetition').toBe(beforeRepeat);
  expect(rows(d.database, "SELECT count(*) AS n FROM executions WHERE status = 'CANCELLED'")).toEqual([{ n: 12_000 }]);
  expect(d.cln.state.sent).toHaveLength(1);
}, 90_000);

it('CP-040/REG-DEEP07 valid paged CLN invoice history completes or refuses structurally within a 128 MiB CLI heap', async () => {
  const d = await demo(open, { withKey: false });
  registerMoneySafetyCredentials([d.cln.runeFile]);
  writeFileSync(d.policy, readFileSync(d.policy, 'utf8').replace('  mode: targets', '  mode: ewma'));
  const respond = d.cln.fake.result;
  const starts: number[] = [], bodySizes: number[] = [];
  const description = 'ordinary-invoice-description-'.repeat(700);
  d.cln.fake.result = (context, behavior, value) => {
    if (context.request.url === '/v1/listinvoices') {
      const start = Number(context.params['start'] ?? 0);
      starts.push(start);
      // CLN v26.06.9 doc/schemas/listinvoices.json: native optional description,
      // created_index/start/limit pagination, and unpaid invoice status. Twelve
      // full 500-row pages are individually about 10.27 MB (<16 MiB), followed
      // by an empty final page. Unpaid invoices never establish EWMA samples.
      value = { invoices: start >= 6000 ? [] : Array.from({ length: 500 }, (_, i) => clnInvoice({
        created_index: start + i + 1, label: `history-${String(start + i + 1)}`,
        payment_hash: (start + i + 1).toString(16).padStart(64, '0'), status: 'unpaid', description,
      })) };
      bodySizes.push(Buffer.byteLength(JSON.stringify(value)));
    }
    respond(context, behavior, value);
  };
  const started = performance.now();
  const child = spawnCli(['--json', 'liquidity', 'plan', '--refresh', '--config', d.config], {
    nodeArgs: ['--max-old-space-size=128'], timeoutMs: 60_000,
  });
  expect(child.child.spawnargs[1], 'the actual product child carries the requested heap bound').toBe('--max-old-space-size=128');
  const run = await child.done;
  const safeOutcome = { pages: starts.length, maxBodyBytes: Math.max(...bodySizes), status: run.status, signal: run.signal };
  expect(starts.length).toBeGreaterThan(0);
  expect(starts.length).toBeLessThanOrEqual(13);
  expect(Math.max(...bodySizes)).toBeGreaterThan(10_000_000);
  expect(Math.max(...bodySizes)).toBeLessThan(RECORD_BOUND);
  expect(performance.now() - started).toBeLessThan(60_000);
  expect(/heap out of memory|Reached heap limit|Allocation failed|fatal process out of memory/i.test(run.stderr),
    `valid bounded history must not exhaust the child heap: ${JSON.stringify(safeOutcome)}`).toBe(false);
  expect(run.signal, 'bounded scanner exits through the structured CLI surface').toBeNull();
  expect([4, 5], 'unpaid or conservatively bounded history cannot authorize an EWMA plan').toContain(run.status);
  const doc = documentOf(run, 'liquidity-plan');
  expect(doc['ok']).toBe(false);
  expect(doc['result']).toBeNull();
  const error = rec(jsonDocument(run)['error']);
  expect(error['code']).toBe(run.status);
  expect(typeof error['step']).toBe('string');
  expect(error['step']).not.toBe('internal');
  expect(rows(d.database, 'SELECT id FROM liquidity_proposals')).toEqual([]);
  expect(methodsOf(d.cln.fake).filter(method => MUTATING.includes(method))).toEqual([]);
}, 60_000);
