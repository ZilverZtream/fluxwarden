// Interface: existing executor/reconciler ports in test/helpers/cp030-execution.ts.
// SPEC §11.6 T-01..T-12; SECURITY INV-02..06,08,11,13,15..17.
import { afterAll, beforeAll, describe, expect, it, onTestFinished } from 'vitest';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import { failed, succeeded } from '../fakes/execution-node.js';
import { fakeChannel, circularRoute, FakePreflightNode } from '../fakes/preflight-node.js';
import { APPROVAL_KEYS, codeOf, execById, execByProposal, loadClaim, loadPersistence, loadPreflight, policyFor, scratchDb, seedBase, seedProposal, type ExecDatabase } from '../helpers/cp028-executor.js';
import { prepare } from '../helpers/cp030-dispatch.js';
import { exec, loadReconciler, rowOf } from '../helpers/cp030-execution.js';
import { cancelled, journalTypes, preflight, reconciliation, routeWorld } from '../helpers/chaos-matrix.js';
import { capturedSink, outputModule, secretForms, secretType, sentinels } from '../helpers/output.js';
import { loadLedger } from '../helpers/cp037-ledger.js';
import { childEnv, repoRoot } from '../helpers/cli.js';

for (const network of ['mainnet', 'testnet4', 'signet'] as const) {
  it(`CP-033/B1 T-01 configured ${network} is refused before claim or credentials`, async () => {
    const r = await preflight(`t01-${network}`, () => ({}), { network });
    expect(r.outcome).toEqual({ kind: 'REFUSED', executionId: null, exit: 5, step: 'network-lock' });
    expect(r.row).toBeUndefined(); expect(r.node.calls).toEqual([]);
  });
  it(`CP-033/B1 T-01 observed ${network} cancels before any mutating RPC`, async () => {
    cancelled(await preflight(`t01-node-${network}`, () => ({ network })), 'network-lock');
  });
}

it('CP-033/B1 T-02 snapshot older than 60 seconds cancels with zero mutating RPCs', async () => {
  cancelled(await preflight('t02', b => ({ channels: () => [fakeChannel(b.sourceKey, `02${'aa'.repeat(32)}`, { observedAt: Date.now() - 61_000 }), fakeChannel(b.targetKey, `02${'bb'.repeat(32)}`)] })), 'STALE_SNAPSHOT');
});

describe('absolute fee ceiling', () => {
  const prepareFixture = async () => {
    const p = await loadPersistence(), { prepareExecution } = await loadPreflight();
    const path = scratchDb('t03'), base = seedBase(p, path), approval = seedProposal(base), policy = policyFor(base);
    const node = new FakePreflightNode(base.sourceKey, base.targetKey, { route: () => circularRoute(base.sourceKey, base.targetKey, 200_001n, 80) });
    return { p, prepareExecution, path, base, approval, policy, node };
  };
  let fixture: Awaited<ReturnType<typeof prepareFixture>>;
  let database: ExecDatabase | undefined;
  let preparedAt: number, prepMs: number;
  const close = (): void => { const owned = database; database = undefined; owned?.close(); };
  beforeAll(async () => {
    preparedAt = performance.now();
    fixture = await prepareFixture();
    database = fixture.p.openDatabase(fixture.path, { readOnly: false });
    prepMs = performance.now() - preparedAt;
  }, 30_000);
  afterAll(close);
  it('CP-033/B1 T-03 a route over the absolute fee cap is refused', async () => {
    const started = performance.now();
    onTestFinished(close);
    if (database === undefined) throw new Error('fee ceiling fixture is not open');
    try {
      const w = routeWorld(); w.constraints.maxFeeMsat = 202_100n;
      expect(await w.validate()).toEqual({ ok: false, code: 'FEE_CEILING_EXCEEDED', check: 'V3' });
      const { prepareExecution, path, base, approval, policy, node } = fixture;
      const outcome = await prepareExecution({ db: database, adapter: node, workerId: 'matrix', leaseMs: 60_000 }, { approval, policy, approvalKeyIds: APPROVAL_KEYS });
      cancelled({ path, base, approval, node, outcome, row: execByProposal(path, approval.proposalId) }, 'FEE_CEILING_EXCEEDED');
    } finally {
      close();
      console.log(JSON.stringify({ case: 'route-fee-ceiling', prepMs, caseMs: performance.now() - started, totalMs: performance.now() - preparedAt }));
    }
  });
});

it('CP-033/B1 T-04 excessive CLTV cancels without invoice or send', async () => {
  cancelled(await preflight('t04', b => ({ route: () => circularRoute(b.sourceKey, b.targetKey, 150_000n, 101) })), 'CLTV_DELTA_UNSAFE');
});

it('CP-033/B1 T-05 a reset after write is UNKNOWN then resolved by hash with one send and one journal pair', async () => {
  const r = await prepare('t05', { script: () => ({ send: c => { c.onDispatched?.(); return Promise.reject(Object.assign(new Error('reset'), { phase: 'response' })); } }) });
  expect(await r.run()).toEqual({ executionId: r.executionId, exit: 7, step: 'OUTCOME_UNKNOWN' });
  expect(rowOf(r.path, r.executionId).status).toBe('UNKNOWN'); expect(r.node.count('sendOnRoute')).toBe(1);
  const { reconcile } = await loadReconciler();
  r.node.script.observe = () => Promise.resolve(succeeded(150_000n));
  exec(r.path, 'UPDATE executions SET lease_expires_at = 0 WHERE id = ?', r.executionId);
  const db = r.p.openDatabase(r.path, { readOnly: false });
  try {
    for (let pass = 0; pass < 2; pass += 1) await reconcile({ db, adapters: new Map([[r.base.nodeId, r.node]]), workerId: 'recovery', leaseMs: 60_000, notFoundWindowMs: 120_000, escalateAfterMs: 3_600_000, confirmIntervalMs: 0, alert: () => undefined }, { startup: true });
  } finally { db.close(); }
  expect(rowOf(r.path, r.executionId).status).toBe('VERIFIED_SUCCESS'); expect(r.node.count('sendOnRoute')).toBe(1);
  expect(journalTypes(r.path, r.executionId)).toEqual(['REBALANCE_SENT', 'REBALANCE_SETTLED']);
});

describe('claim and stale execution fence', () => {
  const prepareFixture = async () => {
    const p = await loadPersistence(), { claimExecution } = await loadClaim(), path = scratchDb('t06'), base = seedBase(p, path), approval = seedProposal(base), policy = policyFor(base);
    return { p, claimExecution, path, approval, policy, dispatch: await prepare('t06-fence') };
  };
  let fixture: Awaited<ReturnType<typeof prepareFixture>>;
  let claimDatabase: ExecDatabase | undefined, dispatchDatabase: ExecDatabase | undefined;
  let preparedAt: number, prepMs: number;
  const close = (): void => {
    const claim = claimDatabase, dispatch = dispatchDatabase;
    claimDatabase = undefined; dispatchDatabase = undefined;
    try { claim?.close(); } finally { dispatch?.close(); }
  };
  beforeAll(async () => {
    preparedAt = performance.now();
    fixture = await prepareFixture();
    claimDatabase = fixture.p.openDatabase(fixture.path, { readOnly: false });
    dispatchDatabase = fixture.dispatch.p.openDatabase(fixture.dispatch.path, { readOnly: false });
    prepMs = performance.now() - preparedAt;
  }, 30_000);
  afterAll(close);
  it('CP-033/B1 T-06 two workers claim once and the stale fence stops before every node call', async () => {
    const started = performance.now();
    onTestFinished(close);
    if (claimDatabase === undefined || dispatchDatabase === undefined) throw new Error('fence fixtures are not open');
    try {
      const { claimExecution, path, approval, policy, dispatch: r } = fixture;
      const db = claimDatabase;
      const one = claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'one', leaseMs: 60_000 });
      expect(one.ok).toBe(true); if (!one.ok) throw new Error('first claim refused');
      expect(claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'two', leaseMs: 60_000 })).toEqual({ ok: false, exit: 5, step: 'claimed-elsewhere', executionId: one.executionId });
      const epoch = db.executions.transition(one.executionId, one.fenceEpoch, 'CLAIMED', 'PREFLIGHT');
      expect(codeOf(() => db.executions.transition(one.executionId, one.fenceEpoch, 'CLAIMED', 'PREFLIGHT'))).toBe('LEASE_LOST');
      expect(execById(path, one.executionId).fence_epoch).toBe(epoch);
      db.close(); claimDatabase = undefined;
      expect(await r.run(r.node, dispatchDatabase, { fenceEpoch: r.input.fenceEpoch - 1n })).toEqual({ executionId: r.executionId, exit: 5, step: 'lease-lost' });
      expect(r.node.calls).toEqual([]);
    } finally {
      close();
      console.log(JSON.stringify({ case: 'claim-and-stale-fence', prepMs, caseMs: performance.now() - started, totalMs: performance.now() - preparedAt }));
    }
  });
});

it('CP-033/B1 T-07 death after claim leaves no send and reclaims with a higher fence', async () => {
  const p = await loadPersistence(), { claimExecution } = await loadClaim(), path = scratchDb('t07'), b = seedBase(p, path), approval = seedProposal(b), policy = policyFor(b);
  const db = p.openDatabase(path, { readOnly: false });
  try {
    const one = claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'dead', leaseMs: 60_000 });
    if (!one.ok) throw new Error('first claim refused');
    exec(path, 'UPDATE executions SET lease_expires_at = 0 WHERE id = ?', one.executionId);
    const two = claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'restart', leaseMs: 60_000 });
    expect(two).toEqual({ ok: true, executionId: one.executionId, fenceEpoch: one.fenceEpoch + 1n });
    expect(execById(path, one.executionId).payment_hash).toBeNull();
    expect(journalTypes(path, one.executionId)).toEqual([]);
    expect(codeOf(() => db.executions.transition(one.executionId, one.fenceEpoch, 'CLAIMED', 'PREFLIGHT'))).toBe('LEASE_LOST');
  } finally { db.close(); }
});

it('CP-033/B1 T-07 killing a paused executor after claim leaves zero mutating RPCs and permits fenced reclaim', async () => {
  const p = await loadPersistence(), path = scratchDb('t07-process'), b = seedBase(p, path), approval = seedProposal(b), policy = policyFor(b);
  const payload = JSON.stringify({ approval, policy, approvalKeyIds: APPROVAL_KEYS }, (_key, value: unknown) => typeof value === 'bigint' ? `bigint:${String(value)}` : value);
  const source = `const [databasePath,storeUrl,preflightUrl]=process.argv.slice(1);
const {openDatabase}=await import(storeUrl); const {prepareExecution}=await import(preflightUrl);
const input=JSON.parse(process.env.MATRIX_INPUT,(_k,v)=>typeof v==='string'&&v.startsWith('bigint:')?BigInt(v.slice(7)):v);
const log=name=>process.stdout.write(name+'\\n');setInterval(()=>{},1000);
const node={handshake:()=>{log('paused-handshake');return new Promise(()=>{});},
createInvoice:()=>{log('createInvoice');throw Error('unexpected');},sendOnRoute:()=>{log('sendOnRoute');throw Error('unexpected');},cancelUnpaidInvoice:()=>{log('cancelUnpaidInvoice');throw Error('unexpected');}};
void prepareExecution({db:openDatabase(databasePath,{readOnly:false}),adapter:node,workerId:'paused',leaseMs:60000},input);`;
  const child = spawn(process.execPath, ['--no-warnings', '--input-type=module', '-e', source, path,
    pathToFileURL(join(repoRoot, 'dist/persistence/index.js')).href, pathToFileURL(join(repoRoot, 'dist/executor/preflight.js')).href],
  { shell: false, windowsHide: true, env: { ...childEnv(), MATRIX_INPUT: payload }, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  try {
    await new Promise<void>((resolve, reject) => {
      child.stdout.on('data', (chunk: Buffer) => { output += chunk.toString(); if (output.includes('paused-handshake')) resolve(); });
      child.once('exit', () => { reject(new Error('worker died before claim')); }); child.once('error', reject);
    });
    const db = p.openDatabase(path, { readOnly: false });
    try {
      const { claimExecution } = await loadClaim();
      const before = (await import('../helpers/cp028-executor.js')).execByProposal(path, approval.proposalId);
      if (!before) throw new Error('claim not stored'); expect(before.status).toBe('PREFLIGHT');
      child.kill('SIGKILL'); await new Promise<void>(resolve => { child.once('exit', () => { resolve(); }); });
      exec(path, 'UPDATE executions SET lease_expires_at = 0 WHERE id = ?', before.id);
      expect(claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'restart', leaseMs: 60_000 })).toEqual({ ok: true, executionId: before.id, fenceEpoch: before.fence_epoch + 1n });
      expect(output.split('\n').filter(name => ['createInvoice', 'sendOnRoute', 'cancelUnpaidInvoice'].includes(name))).toEqual([]);
      expect(execById(path, before.id).payment_hash).toBeNull();
    } finally { db.close(); }
  } finally { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }
});

for (const sentinel of sentinels()) {
  it(`CP-033/B1 T-08 ${sentinel.kind} in node responses and errors is redacted in all output encodings`, async () => {
    const Secret = await secretType(), { createOutput } = await outputModule(), out = capturedSink(), err = capturedSink();
    const output = createOutput({ stdout: out.sink, stderr: err.sink, secrets: [new Secret(sentinel.bytes)] });
    for (const [, form] of secretForms(sentinel.bytes)) {
      await output.json({ nodeResponse: form }); await output.write(form, { stream: 'stderr' });
    }
    for (const [, form] of secretForms(sentinel.bytes)) { expect(out.text()).not.toContain(form); expect(err.text()).not.toContain(form); }
    expect(out.text()).toContain('redacted'); expect(err.text()).toContain('redacted');
  });
}

it('CP-033/B1 T-09 unbalanced posting rolls back every earlier journal in the transaction', async () => {
  const r = await prepare('t09'), m = await loadLedger(), db = m.openDatabase(r.path, { readOnly: false });
  const before = rowOf(r.path, r.executionId);
  try {
    expect(() => { db.transaction(tx => {
      m.post(tx, { eventType: 'OPENING', reference: m.channelLocalAccount('lnd-r', '112x1x0'), executionId: null, occurredAt: 1,
        lines: [{ account: m.channelLocalAccount('lnd-r', '112x1x0'), debitMsat: 1000n, creditMsat: 0n }, { account: m.EQUITY_OPENING_BALANCE, debitMsat: 0n, creditMsat: 1000n }] });
      m.post(tx, { eventType: 'OPENING', reference: m.channelLocalAccount('lnd-r', '112x1x0'), executionId: null, occurredAt: 1,
        lines: [{ account: m.channelLocalAccount('lnd-r', '112x1x0'), debitMsat: 1001n, creditMsat: 0n }, { account: m.EQUITY_OPENING_BALANCE, debitMsat: 0n, creditMsat: 1000n }] });
    }); }).toThrow(expect.objectContaining({ code: 'UNBALANCED' }));
    expect(db.ledger.journals()).toEqual([]); expect(rowOf(r.path, r.executionId)).toEqual(before);
  } finally { db.close(); }
});

it('CP-033/B1 T-10 a multipart candidate is refused before dispatch', async () => {
  const w = routeWorld(); w.route.parts = 2;
  expect(await w.validate()).toEqual({ ok: false, code: 'SINGLE_PATH_UNAVAILABLE', check: 'V6' });
});

describe('matching-preimage reconciliation', () => {
  const running = new Set<Promise<unknown>>();
  let accepting = true;
  let w: Awaited<ReturnType<typeof reconciliation>>;
  beforeAll(async () => {
    // The wire case separately injects SUCCEEDED/TIMEOUT. Its normalized evidence crosses this adapter port.
    const prepared = await reconciliation('t11', [succeeded(150_000n)], { invoice: 'SETTLED' });
    w = { ...prepared, run: async startup => {
      if (!accepting) throw new Error('reconciliation fixture has closed');
      const work = prepared.run(startup);
      running.add(work);
      try { return await work; }
      finally { running.delete(work); }
    } };
  });
  afterAll(async () => {
    accepting = false;
    await Promise.allSettled([...running]);
  });

  it('CP-033/B1 T-11 matching preimage evidence settles exactly once despite a reported failure reason', async () => {
    await w.run(); await w.run();
    expect(w.row().status).toBe('VERIFIED_SUCCESS'); expect(w.node.count('cancelUnpaidInvoice')).toBe(0);
    expect(journalTypes(w.path, w.executionId)).toEqual(['REBALANCE_SENT', 'REBALANCE_SETTLED']);
  });
});

it('CP-033/B1 T-12 a failed observation with an in-flight HTLC cannot terminate before later success', async () => {
  const w = await reconciliation('t12', [failed('temporary', 1), { kind: 'IN_FLIGHT' }, succeeded(150_000n)]);
  expect((await w.run()).exit).toBe(7); expect(w.row().status).toBe('UNKNOWN');
  expect((await w.run()).exit).toBe(7); expect(w.row().status).toBe('UNKNOWN');
  await w.run(); expect(w.row().status).toBe('VERIFIED_SUCCESS'); expect(w.node.count('cancelUnpaidInvoice')).toBe(0);
  expect(journalTypes(w.path, w.executionId)).toEqual(['REBALANCE_SENT', 'REBALANCE_SETTLED']);
});
