// SPEC 10.1/10.2 and SECURITY INV-04/05: repeated graceful interrupts preserve
// established payment uncertainty7 and invariant breach8; before submission6 remains.
// Ordinary Node IPC delivers real registered CLI signal events synchronously.
// The preload observes signals/output only; it never changes a command result.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, beforeAll, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { FEE, PRINCIPAL, S, T } from '../fakes/cln/rebalance-node.js';
import { binPath, childEnv } from '../helpers/cli.js';
import { approve, demo, plan, rec, rows, prepareDemoFixtures, type Demo, type DemoFixtures, type Run } from '../helpers/cpw-cli.js';
import { testRoot } from '../helpers/env.js';
import { registerMoneySafetyCredentials } from '../helpers/public-money-safety.js';

const servers: FakeServer[] = [];
let fixtures: DemoFixtures;
beforeAll(async () => {
  fixtures = await prepareDemoFixtures();
  registerMoneySafetyCredentials([fixtures.key.keyFile]);
});
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });
type Signal = 'SIGINT' | 'SIGTERM';
interface Trace { events: Signal[]; realHandlers: Record<Signal, number>; reportCode?: number }

function signalPreload(tracePath: string, pair: readonly Signal[], reportCode?: 7 | 8): string {
  return [
    "import { writeFileSync } from 'node:fs';",
    `const path = ${JSON.stringify(tracePath)}, pair = ${JSON.stringify(pair)};`,
    'const trace = { events: [], realHandlers: {} };',
    'let delivered = false;',
    'const save = () => writeFileSync(path, JSON.stringify(trace));',
    'const deliver = () => {',
    '  if (delivered) return; delivered = true;',
    '  for (const signal of pair) {',
    '    trace.realHandlers[signal] = process.listenerCount(signal);',
    '    process.prependOnceListener(signal, () => { trace.events.push(signal); save(); });',
    '  }',
    '  save();',
    '  for (const signal of pair) process.emit(signal, signal);',
    '};',
    "process.on('message', message => { if (message === 'graceful-pair') deliver(); });",
    'process.channel?.unref();',
    ...(reportCode === undefined ? [] : [
      'let text = "";',
      'const write = process.stdout.write;',
      'process.stdout.write = function(chunk, ...args) {',
      '  const result = write.call(this, chunk, ...args);',
      '  text += String(chunk);',
      '  let doc; try { doc = JSON.parse(text); } catch { return result; }',
      `  if (doc.command === 'actions execute' && doc.error?.code === ${String(reportCode)}) { trace.reportCode = doc.error.code; deliver(); }`,
      '  return result;',
      '};',
    ]),
    '',
  ].join('\n');
}

function start(d: Demo, proposal: string, pair: readonly Signal[], reportCode?: 7 | 8) {
  const tracePath = join(d.dir, 'signal-events.json'), preload = join(d.dir, 'graceful-signals.mjs');
  writeFileSync(preload, signalPreload(tracePath, pair, reportCode));
  const child = spawn(process.execPath, ['--import', pathToFileURL(preload).href, binPath(), '--json', 'actions', 'execute',
    proposal, '--require-regtest', '--config', d.config], { cwd: d.dir, env: childEnv(),
    shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', (bytes: Buffer) => { stdout += bytes.toString('utf8'); });
  child.stderr.on('data', (bytes: Buffer) => { stderr += bytes.toString('utf8'); });
  const done = new Promise<Run>((resolve, reject) => {
    const deadline = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('graceful CLI did not finish within the existing 10s child bound')); }, 10_000);
    child.once('error', error => { clearTimeout(deadline); reject(error); });
    child.once('close', (status, signal) => { clearTimeout(deadline); resolve({ status, signal, stdout, stderr, exitedAt: Date.now() }); });
  });
  const trace = () => {
    expect(existsSync(tracePath), 'the real graceful signal delivery boundary was reached').toBe(true);
    const observed = JSON.parse(readFileSync(tracePath, 'utf8')) as Trace;
    expect(observed.events).toEqual(pair);
    for (const signal of pair) expect(observed.realHandlers[signal], `${signal} has the registered real CLI handler`).toBeGreaterThan(0);
    if (reportCode !== undefined) expect(observed.reportCode).toBe(reportCode);
  };
  return { done, trace, output: () => ({ stdout, stderr }), pair: () => { child.send('graceful-pair'); }, close: () => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  } };
}

async function prepared(loseAnswer = false) {
  const d = await demo(servers, { fixtures, ...(loseAnswer ? { fake: { sendpay: 'lose-answer' as const } } : {}) });
  registerMoneySafetyCredentials([d.key.keyFile, d.cln.runeFile]);
  d.rewrite({ attemptDeadline: '1s' });
  const proposal = String((await plan(d))['proposal_id']);
  await approve(d, proposal);
  const respond = d.cln.fake.result;
  d.cln.fake.result = (context, behaviour, value) => {
    if (behaviour === 'invoice') {
      for (const [kind, bytes] of [['preimage', Buffer.from(String(context.params['preimage']), 'hex')],
        ['payment-secret', Buffer.from(String(rec(value)['payment_secret']), 'hex')]] as const) {
        const id = createHash('sha256').update(bytes).digest('hex').slice(0, 16);
        writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `graceful-${kind}-${id}.bin`), bytes, { mode: 0o600 });
      }
    }
    respond(context, behaviour, value);
  };
  return { d, proposal };
}

function held(d: Demo, method: 'getinfo' | 'sendpay'): Promise<void> {
  let reached: (() => void) | undefined;
  const pending = new Promise<void>(resolve => { reached = resolve; });
  const respond = d.cln.fake.result;
  d.cln.fake.result = (context, behaviour, value) => {
    if (behaviour === method) { d.cln.fake.hold(context, behaviour); reached?.(); return; }
    respond(context, behaviour, value);
  };
  return pending;
}

function oneUnknown(d: Demo) {
  const execution = rows(d.database, 'SELECT id, status, payment_hash, actual_fee_msat FROM executions');
  expect(execution).toHaveLength(1);
  expect.soft(execution[0]).toMatchObject({ status: 'UNKNOWN', actual_fee_msat: null });
  const hash = String(execution[0]?.['payment_hash']);
  expect(hash).toMatch(/^[0-9a-f]{64}$/);
  expect(d.cln.state.sent).toEqual([hash]);
  expect(rows(d.database, 'SELECT state, consumed_msat FROM budget_reservations')).toEqual([{ state: 'HELD', consumed_msat: null }]);
  expect(d.cln.fake.calls.filter(call => call.method === 'sendpay')).toHaveLength(1);
  expect(d.cln.fake.calls.filter(call => ['delinvoice', 'pay', 'xpay'].includes(call.method))).toEqual([]);
  expect(rows(d.database, "SELECT event_type FROM ledger_journals WHERE event_type IN ('REBALANCE_SETTLED','REBALANCE_REVERSED')")).toEqual([]);
}

it('CP-001/REG-SIGNAL repeated graceful events during observed submission preserve UNKNOWN and exit 7', async () => {
  const { d, proposal } = await prepared(), pending = held(d, 'sendpay');
  const run = start(d, proposal, ['SIGINT', 'SIGTERM']);
  try {
    await Promise.race([pending, run.done.then(result => { throw new Error(`SETUP_ERROR: CLI exited ${String(result.status)} before native submission`); })]);
    expect(d.cln.fake.calls.filter(call => call.method === 'sendpay')).toHaveLength(1);
    expect(['SUBMITTING', 'IN_FLIGHT']).toContain(rows(d.database, 'SELECT status FROM executions')[0]?.['status']);
    run.pair();
    const result = await run.done;
    run.trace(); oneUnknown(d);
    expect(result.signal).toBeNull();
    expect(result.status).toBe(7);
  } finally { run.close(); }
});

it('CP-001/REG-SIGNAL repeated graceful events after the actual unresolved result preserve exit 7', async () => {
  const { d, proposal } = await prepared(true), run = start(d, proposal, ['SIGTERM', 'SIGINT'], 7);
  try {
    const result = await run.done;
    run.trace(); oneUnknown(d);
    expect(result.signal).toBeNull();
    expect(result.status).toBe(7);
  } finally { run.close(); }
});

it('CP-001/REG-SIGNAL repeated graceful events before submission retain exit 6 and zero payment work', async () => {
  const { d, proposal } = await prepared(), pending = held(d, 'getinfo'), run = start(d, proposal, ['SIGINT', 'SIGTERM']);
  try {
    await Promise.race([pending, run.done.then(result => { throw new Error(`SETUP_ERROR: CLI exited ${String(result.status)} before native read`); })]);
    run.pair();
    const result = await run.done;
    run.trace();
    expect(result.signal).toBeNull(); expect(result.status).toBe(6);
    expect(d.cln.fake.calls.filter(call => ['invoice', 'sendpay', 'delinvoice', 'pay', 'xpay'].includes(call.method))).toEqual([]);
    expect(rows(d.database, "SELECT id FROM executions WHERE status IN ('SUBMITTING','IN_FLIGHT','UNKNOWN','VERIFIED_SUCCESS')")).toEqual([]);
  } finally { run.close(); }
});

it('CP-001/REG-SIGNAL repeated graceful events after an actual paid fee breach retain exit 8', async () => {
  const { d, proposal } = await prepared(), actualFee = 300_001n;
  d.cln.state.bkprFeeMsat = actualFee;
  const respond = d.cln.fake.result;
  d.cln.fake.result = (context, behaviour, value) => {
    const answer = rec(value);
    if (behaviour === 'waitsendpay-complete') answer['amount_sent_msat'] = Number(PRINCIPAL + actualFee);
    if (behaviour === 'listsendpays') for (const payment of answer['payments'] as Record<string, unknown>[]) {
      if (payment['status'] === 'complete') payment['amount_sent_msat'] = Number(PRINCIPAL + actualFee);
    }
    if (behaviour === 'listpeerchannels' && d.cln.state.settledAt !== null) {
      for (const channel of answer['channels'] as Record<string, unknown>[]) if (channel['short_channel_id'] === S) {
        for (const key of ['to_us_msat', 'max_to_us_msat', 'spendable_msat']) channel[key] = Number(channel[key]) - Number(actualFee - FEE);
      }
    }
    respond(context, behaviour, answer);
  };
  const run = start(d, proposal, ['SIGTERM', 'SIGINT'], 8);
  try {
    const result = await run.done;
    run.trace();
    expect(result.signal).toBeNull(); expect(result.status).toBe(8);
    expect(rows(d.database, 'SELECT status, actual_fee_msat FROM executions')).toEqual([{ status: 'VERIFIED_SUCCESS', actual_fee_msat: 300001 }]);
    expect(d.cln.fake.calls.filter(call => call.method === 'sendpay')).toHaveLength(1);
    expect(d.cln.fake.calls.filter(call => ['delinvoice', 'pay', 'xpay'].includes(call.method))).toEqual([]);
  } finally { run.close(); }
});

it('CP-001/REG-SRC009 repeated graceful events during a pending observation retain an established paid breach8', async () => {
  const { d, proposal } = await prepared(), actualFee = 300_001n;
  d.cln.state.bkprFeeMsat = actualFee;
  let reached: (() => void) | undefined;
  const pending = new Promise<void>(resolve => { reached = resolve; });
  const respond = d.cln.fake.result;
  d.cln.fake.result = (context, behaviour, value) => {
    const answer = rec(value);
    if (behaviour === 'waitsendpay-complete') answer['amount_sent_msat'] = Number(PRINCIPAL + actualFee);
    if (behaviour === 'listsendpays') for (const payment of answer['payments'] as Record<string, unknown>[]) {
      if (payment['status'] === 'complete') payment['amount_sent_msat'] = Number(PRINCIPAL + actualFee);
    }
    if (behaviour === 'listpeerchannels' && d.cln.state.settledAt !== null) {
      // An ordinary current node observation remains pending after the native
      // paid receipt; no result, exit code or persisted outcome is substituted.
      d.cln.fake.hold(context, behaviour); reached?.(); return;
    }
    respond(context, behaviour, answer);
  };
  const run = start(d, proposal, ['SIGINT', 'SIGTERM']);
  try {
    await Promise.race([pending, run.done.then(result => { throw new Error(`SETUP_ERROR: CLI exited ${String(result.status)} before pending paid observation`); })]);
    const beforeExecution = rows(d.database, 'SELECT id, status, actual_fee_msat, payment_hash FROM executions');
    expect(beforeExecution, 'paid truth is durable before either graceful signal').toHaveLength(1);
    expect(beforeExecution[0]).toMatchObject({ status: 'VERIFIED_SUCCESS', actual_fee_msat: 300001 });
    expect(rows(d.database, 'SELECT max_fee_msat FROM approvals')).toEqual([{ max_fee_msat: 300000 }]);
    const id = String(beforeExecution[0]?.['id']);
    const alerts = readdirSync(join(d.dir, 'alerts')).filter(name => name.endsWith('.json'))
      .map(name => rec(JSON.parse(readFileSync(join(d.dir, 'alerts', name), 'utf8'))));
    expect(alerts.filter(alert => alert['kind'] === 'invariant-breach' && alert['subject'] === id),
      'independent durable breach evidence exists before either graceful signal').toHaveLength(1);
    registerMoneySafetyCredentials([join(dirname(d.database), 'outbox.key')]);
    const beforeJournals = rows(d.database, 'SELECT * FROM ledger_journals WHERE execution_id = ? ORDER BY id', id);
    const beforeLines = rows(d.database, `SELECT l.* FROM ledger_lines l JOIN ledger_journals j ON j.id=l.journal_id
      WHERE j.execution_id = ? ORDER BY l.journal_id, l.account_code`, id);
    expect(beforeJournals.map(row => row['event_type']).sort()).toEqual(['REBALANCE_SENT', 'REBALANCE_SETTLED']);
    const sent = beforeJournals.find(row => row['event_type'] === 'REBALANCE_SENT');
    const settled = beforeJournals.find(row => row['event_type'] === 'REBALANCE_SETTLED');
    const lines = (journal: Record<string, unknown> | undefined) => beforeLines.filter(line => line['journal_id'] === journal?.['id'])
      .map(line => [line['account_code'], line['debit_msat'], line['credit_msat']]);
    expect(lines(sent)).toEqual([[`channel:cln-m:${S}:local`, 0, Number(PRINCIPAL + FEE)], ['clearing:inflight', Number(PRINCIPAL + FEE), 0]]);
    expect(lines(settled)).toEqual([[`channel:cln-m:${T}:local`, 100000000, 0], ['clearing:inflight', 0, Number(PRINCIPAL + FEE)],
      ['expense:routing_fees', 300001, 0], ['recon:difference', 0, Number(actualFee - FEE)]]);
    expect(run.output().stdout, 'final JSON has not been emitted before the pending observation').toBe('');
    run.pair();
    const result = await run.done;
    run.trace();
    expect(rows(d.database, 'SELECT id, status, actual_fee_msat, payment_hash FROM executions')).toEqual(beforeExecution);
    expect(rows(d.database, 'SELECT * FROM ledger_journals WHERE execution_id = ? ORDER BY id', id)).toEqual(beforeJournals);
    expect(rows(d.database, `SELECT l.* FROM ledger_lines l JOIN ledger_journals j ON j.id=l.journal_id
      WHERE j.execution_id = ? ORDER BY l.journal_id, l.account_code`, id)).toEqual(beforeLines);
    expect(rows(d.database, 'SELECT state, consumed_msat FROM budget_reservations')).toEqual([{ state: 'CONSUMED', consumed_msat: 300001 }]);
    expect(d.cln.fake.calls.filter(call => call.method === 'invoice')).toHaveLength(1);
    expect(d.cln.fake.calls.filter(call => call.method === 'sendpay')).toHaveLength(1);
    expect(d.cln.fake.calls.filter(call => ['delinvoice', 'pay', 'xpay'].includes(call.method))).toEqual([]);
    expect(result.signal).toBeNull();
    expect(result.status).toBe(8);
  } finally { run.close(); }
});
