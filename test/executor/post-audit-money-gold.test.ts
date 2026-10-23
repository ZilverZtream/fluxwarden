// Independent desired-behavior oracles for AUDIT-01/02/04/09.
// Sources: docs/spec.md Policy and Approval/execution/recovery; SECURITY payment authority.
// Node scripts reuse the documented LND/CLN public ports and pinned schemas of the existing fakes.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { circularRoute, fakeChannel } from '../fakes/preflight-node.js';
import type { FakeServer } from '../fakes/https.js';
import { PAYMENT_SECRET, succeeded } from '../fakes/execution-node.js';
import { APPROVAL_KEYS, IN_PEER, NODE_PUBKEY, OUT_PEER, PRINCIPAL, loadClaim, raw, seedOtherNode, seedProposal, type ExecDatabase } from '../helpers/cp028-executor.js';
import { balances, prepare, REGTEST_HANDSHAKE, ROUTE_FEE, S_BEFORE, T_BEFORE } from '../helpers/cp030-dispatch.js';
import { loadReconciler, reservationState, rowOf, seedExecution, transitionsOf } from '../helpers/cp030-execution.js';
import { approve, demo, plan, rows } from '../helpers/cpw-cli.js';
import { loadSrc } from '../helpers/load-src.js';
import { loadLedger, type LedgerDatabase } from '../helpers/cp037-ledger.js';
import { registerMoneySafetyCredentials } from '../helpers/public-money-safety.js';

// The old approved snapshot has ample liquidity. Only the new dispatch snapshot changes.
// P=100000000, route fee=150000, reserve=50000000: the exact route floor is 150150000.
for (const [label, spendable, refused] of [
  ['lower-fresh-balance', 120_000_000n, true],
  ['one-msat-below', 150_149_999n, true],
  ['exact-floor', 150_150_000n, false],
] as const) {
  it(`POST-AUDIT/AUDIT-01/${label} rechecks source spendable at dispatch against the reserve`, async () => {
    const r = await prepare(`post-audit-reserve-${label}`, { script: ({ base }) => ({
      // Local balance deliberately remains high: reserve checks must use spendable liquidity.
      before: () => [fakeChannel(base.sourceKey, OUT_PEER, { spendableMsat: spendable, localBalanceMsat: S_BEFORE }),
        fakeChannel(base.targetKey, IN_PEER, { localBalanceMsat: T_BEFORE })],
      after: () => balances(base, S_BEFORE - PRINCIPAL - ROUTE_FEE, T_BEFORE + PRINCIPAL),
    }) });
    const core = await loadSrc<{ proveRegtest: (...args: unknown[]) => unknown;
      approveRoute: (...args: unknown[]) => { route?: typeof r.route; refusal?: string } }>('core/execution.ts');
    const approved = core.approveRoute(r.route, r.route, r.approval, r.input.policy,
      core.proveRegtest('regtest', REGTEST_HANDSHAKE),
      { nodePubkey: NODE_PUBKEY, implementation: 'lnd', channels: balances(r.base, S_BEFORE, T_BEFORE) });
    if (approved.route === undefined) throw new Error(`valid old snapshot refused: ${String(approved.refusal)}`);
    const outcome = await r.run(r.node, undefined, { route: approved.route });
    expect.soft(r.node.count('sendOnRoute')).toBe(refused ? 0 : 1);
    expect.soft(outcome.exit).toBe(refused ? 5 : 0);
    expect.soft(rowOf(r.path, r.executionId).status).toBe(refused ? 'CANCELLED' : 'VERIFIED_SUCCESS');
    expect.soft(reservationState(r.path, r.executionId).state).toBe(refused ? 'RELEASED' : 'CONSUMED');
    if (refused) expect(transitionsOf(r.path, r.executionId)).not.toContain('PREFLIGHT>SUBMITTING');
  });
}

for (const boundary of ['preflight', 'after-route-validation'] as const) {
it(`POST-AUDIT/AUDIT-09/${boundary} a signed CLI proposal preserves its configured source outbound target after balances fall`, async () => {
  const servers: FakeServer[] = [];
  try {
    const d = await demo(servers);
    registerMoneySafetyCredentials([d.key.keyFile, d.cln.runeFile]);
    // SPEC Policy: source floor = max(reserve 50000000, outbound target 1700000000).
    writeFileSync(d.policy, readFileSync(d.policy, 'utf8').replace('      min_inbound_msat: "400000000"',
      '      min_inbound_msat: "400000000"\n      min_outbound_msat: "1700000000"'));
    const proposal = String((await plan(d))['proposal_id']);
    await approve(d, proposal);
    const respond = d.cln.fake.result;
    let sourceReads = 0;
    let routeValidated = false;
    d.cln.fake.result = (context, behavior, value) => {
      // The temporary route layer is removed when the ordinary CLN route query
      // completes. Lowering balances only afterwards proves the final dispatch
      // read preserves the configured target too, beyond initial preflight.
      if (behavior === 'askrene-remove-layer') routeValidated = true;
      if (context.request.url === '/v1/listpeerchannels' && (boundary === 'preflight' || routeValidated)) {
        const result = value as { channels: Record<string, unknown>[] };
        for (const channel of result.channels) {
          if (channel['short_channel_id'] !== '102x1x0') continue;
          sourceReads += 1;
          channel['spendable_msat'] = Number(BigInt(String(channel['spendable_msat'])) - 70_000_000n);
        }
      }
      respond(context, behavior, value);
    };
    const result = await d.run(['--json', 'actions', 'execute', proposal, '--require-regtest']);
    expect(sourceReads).toBeGreaterThan(0);
    expect.soft(result.status).toBe(5);
    expect.soft(d.cln.state.sent).toEqual([]);
    expect.soft(rows(d.database, "SELECT id FROM executions WHERE status IN ('SUBMITTING','IN_FLIGHT','UNKNOWN','VERIFIED_SUCCESS')")).toEqual([]);
    expect.soft(rows(d.database, "SELECT execution_id FROM budget_reservations WHERE state = 'HELD'")).toEqual([]);
  } finally { await Promise.all(servers.map(server => server.close())); }
});
}

for (const samePair of [true, false]) {
  it(`POST-AUDIT/AUDIT-02/${samePair ? 'same-pair' : 'unrelated-pair'} checks the success cooldown at the submission boundary`, async () => {
    const r = await prepare(`post-audit-cooldown-${String(samePair)}`);
    // Deterministic interleaving: another execution commits its terminal success while
    // this worker awaits createInvoice, after preflight and before SUBMITTING.
    r.node.script.invoice = (_amount, preimage) => {
      const otherBase = samePair ? r.base : seedOtherNode(r.base);
      const other = seedExecution(otherBase, { status: 'IN_FLIGHT',
        paymentHash: createHash('sha256').update('independent-other-payment').digest('hex'),
        route: circularRoute(otherBase.sourceKey, otherBase.targetKey, ROUTE_FEE, 80), plannedFeeMsat: ROUTE_FEE });
      const db = r.p.openDatabase(r.path, { readOnly: false });
      try { db.executions.transition(other.executionId, 3n, 'IN_FLIGHT', 'VERIFIED_SUCCESS',
        { actualFeeMsat: ROUTE_FEE, settledChannelKey: samePair ? r.base.targetKey : null, deltaStatus: 'MATCH' }); }
      finally { db.close(); }
      return Promise.resolve({ paymentHash: createHash('sha256').update(preimage).digest('hex'), paymentSecret: PAYMENT_SECRET, finalCltvDelta: 18 });
    };
    const result = await r.run();
    expect.soft(r.node.count('sendOnRoute')).toBe(samePair ? 0 : 1);
    expect.soft(result.exit).toBe(samePair ? 5 : 0);
    expect.soft(rowOf(r.path, r.executionId).status).toBe(samePair ? 'CANCELLED' : 'VERIFIED_SUCCESS');
    expect.soft(reservationState(r.path, r.executionId).state).toBe(samePair ? 'RELEASED' : 'CONSUMED');
    if (samePair) {
      expect(r.node.count('cancelUnpaidInvoice')).toBe(1);
      expect(transitionsOf(r.path, r.executionId)).not.toContain('PREFLIGHT>SUBMITTING');
    }
  });
}

interface AccountingCommand {
  runReconcile: (input: { db: LedgerDatabase; window: { sinceMs: number; untilMs: number };
    executions: { id: string; node: string; paymentHash: string; status: 'VERIFIED_SUCCESS' }[];
    sources: { node: string; implementation: 'lnd'; api: { listPayments: () => Promise<{
      payments: { paymentHash: string; valueMsat: bigint; feeMsat: bigint; status: 'SUCCEEDED'; creationTimeNs: bigint; paymentIndex: bigint }[];
      lastIndexOffset: bigint }> } }[]; clock: { now(): number } }) => Promise<{ exitCode: number }>;
}

async function accountingScenario(prefix: string, existing?: Awaited<ReturnType<typeof prepare>>) {
  const r = existing ?? await prepare(prefix);
  if (existing === undefined) expect((await r.run()).exit).toBe(0);
  const ledger = await loadLedger();
  const db = ledger.openDatabase(r.path, { readOnly: false });
  const { runReconcile } = await loadSrc<AccountingCommand>('commands/reconcile.ts');
  const paymentHash = rowOf(r.path, r.executionId).payment_hash;
  if (paymentHash === null) throw new Error('successful fixture has no persisted hash');
  const now = Date.now();
  const reconcileFee = (feeMsat: bigint) => runReconcile({ db, window: { sinceMs: now - 60_000, untilMs: now + 60_000 },
    executions: [{ id: r.executionId, node: 'lnd-r', paymentHash, status: 'VERIFIED_SUCCESS' }],
    // LND ListPayments fee_msat/value_msat: lnrpc/lightning.proto Payment, as the existing accounting fake records.
    sources: [{ node: 'lnd-r', implementation: 'lnd', api: { listPayments: () => Promise.resolve({ payments: [{
      paymentHash, valueMsat: PRINCIPAL, feeMsat, status: 'SUCCEEDED', creationTimeNs: BigInt(now) * 1_000_000n,
      paymentIndex: 1n }], lastIndexOffset: 1n }) } }], clock: { now: () => now } });
  return { r, ledger, db, reconcileFee };
}

it('POST-AUDIT/AUDIT-04 corrected fees replace budget consumption once in either direction', async () => {
  const { r, ledger, db, reconcileFee } = await accountingScenario('post-audit-corrected-budget');
  try {
    for (const corrected of [175_000n, 125_000n]) {
      expect((await reconcileFee(corrected)).exitCode).toBe(9);
      expect.soft(db.ledger.balances().get('expense:routing_fees')).toBe(corrected);
      expect.soft(reservationState(r.path, r.executionId)).toEqual({ state: 'CONSUMED', consumed: corrected });
      const journals = db.ledger.journals();
      expect((await reconcileFee(corrected)).exitCode).toBe(0);
      expect(db.ledger.journals()).toEqual(journals);
      expect.soft(ledger.verifyLedger({ journals, balances: db.ledger.balances(), executions: db.ledger.executions() }).ok).toBe(true);
    }
    expect(rows(r.path, 'SELECT state FROM nodes')).toEqual([{ state: 'ONLINE' }]);
    expect(r.node.count('sendOnRoute')).toBe(1);
  } finally { db.close(); }
});

it('POST-AUDIT/AUDIT-04 a fee correction above the signed cap consumes the full fee, quarantines, and blocks a global-budget overspend', async () => {
  const { r, db, reconcileFee } = await accountingScenario('post-audit-corrected-cap');
  try {
    // Corrected spend 1900000 + next held fee 200000 > global budget 2000000.
    expect.soft((await reconcileFee(1_900_000n)).exitCode).toBe(8);
    expect.soft(db.ledger.balances().get('expense:routing_fees')).toBe(1_900_000n);
    expect.soft(reservationState(r.path, r.executionId)).toEqual({ state: 'CONSUMED', consumed: 1_900_000n });
    expect.soft(rows(r.path, 'SELECT state FROM nodes WHERE id = ?', r.base.nodeId)).toEqual([{ state: 'QUARANTINED' }]);
    expect(rowOf(r.path, r.executionId).status).toBe('VERIFIED_SUCCESS');
    const other = seedOtherNode(r.base);
    const { claimExecution } = await loadClaim();
    const claimDb = r.p.openDatabase(r.path, { readOnly: false });
    try {
      const next = claimExecution(claimDb, { approval: seedProposal(other), policy: r.input.policy,
        approvalKeyIds: APPROVAL_KEYS, workerId: 'after-correction', leaseMs: 60_000 });
      expect.soft(next).toMatchObject({ ok: false, exit: 5, step: 'BUDGET_EXHAUSTED' });
    } finally { claimDb.close(); }
    const journals = db.ledger.journals();
    await reconcileFee(1_900_000n);
    expect(db.ledger.journals()).toEqual(journals);
    expect.soft(rows(r.path, 'SELECT state FROM nodes WHERE id = ?', r.base.nodeId)).toEqual([{ state: 'QUARANTINED' }]);
  } finally { db.close(); }
});

it('POST-AUDIT/AUDIT-04 a refused budget correction rolls back its journal and node-state changes atomically', async () => {
  const { r, db, reconcileFee } = await accountingScenario('post-audit-correction-atomicity');
  const before = db.ledger.journals();
  const fail = raw(r.path);
  try {
    fail.exec(`CREATE TRIGGER audit_reject_budget_correction BEFORE UPDATE OF consumed_msat ON budget_reservations
      WHEN NEW.consumed_msat <> OLD.consumed_msat BEGIN SELECT RAISE(ABORT, 'injected budget write failure'); END`);
  } finally { fail.close(); }
  try {
    // Either a reported invariant refusal or a propagated storage error is acceptable;
    // successful reconciliation with a split accounting/budget commit is not.
    const outcome = await reconcileFee(1_900_000n).then(result => result.exitCode, () => 8);
    expect.soft(outcome).toBe(8);
    expect.soft(db.ledger.journals()).toEqual(before);
    expect.soft(db.ledger.balances().get('expense:routing_fees')).toBe(ROUTE_FEE);
    expect.soft(reservationState(r.path, r.executionId)).toEqual({ state: 'CONSUMED', consumed: ROUTE_FEE });
    expect.soft(rows(r.path, 'SELECT state FROM nodes')).toEqual([{ state: 'ONLINE' }]);
  } finally { db.close(); }
});

for (const initialFee of ['reported', 'unavailable'] as const) {
  it(`POST-AUDIT/AUDIT-04+06/${initialFee} pending paid recovery preserves an accepted fee correction and the original settlement`, async () => {
    // SPEC: balance-read failure does not undo paid truth; corrections are
    // append-only journals, and repeated evidence must never charge fees twice.
    const r = await prepare(`post-audit-correction-recovery-${initialFee}`, {
      script: () => ({ after: () => { throw new Error('temporary balance read failure'); },
        ...(initialFee === 'unavailable' ? {
          send: context => { context.onDispatched?.(); return Promise.resolve({ kind: 'IN_FLIGHT' as const }); },
          observe: () => Promise.resolve({ kind: 'IN_FLIGHT' as const }),
          // Receiver proof establishes paid truth while the payer's fee is unavailable.
          invoiceState: () => Promise.resolve('SETTLED' as const),
        } : {}),
      }),
    });
    const { reconcile } = await loadReconciler();
    const recover = async () => {
      const db = r.p.openDatabase(r.path, { readOnly: false });
      try { return await reconcile({ db, adapters: new Map([[r.base.nodeId, r.node]]), workerId: 'corrected-fee-recovery',
        leaseMs: 60_000, notFoundWindowMs: 120_000, escalateAfterMs: 3_600_000, confirmIntervalMs: 1_000,
        deltaToleranceMsat: 1_000n, alert: () => undefined }, { startup: true }); }
      finally { db.close(); }
    };
    expect((await r.run()).exit).toBe(initialFee === 'reported' ? 9 : 7);
    if (initialFee === 'unavailable') await recover();
    expect(rowOf(r.path, r.executionId)).toMatchObject({ status: 'VERIFIED_SUCCESS', delta_status: 'PENDING',
      actual_fee_msat: initialFee === 'reported' ? ROUTE_FEE : null });
    const originalSettlement = rows(r.path, "SELECT * FROM ledger_journals WHERE execution_id = ? AND event_type = 'REBALANCE_SETTLED'", r.executionId);
    expect(originalSettlement).toHaveLength(1);
    const { db, ledger, reconcileFee } = await accountingScenario('unused-existing-paid-fixture', r);
    try {
      const corrected = 175_000n; // Within signed absolute 200000 and policy 2500ppm limits.
      expect((await reconcileFee(corrected)).exitCode).toBe(9);
      expect(db.ledger.balances().get('expense:routing_fees')).toBe(corrected);
      expect(reservationState(r.path, r.executionId)).toEqual({ state: 'CONSUMED', consumed: corrected });
      const correctedJournals = db.ledger.journals();
      // Later ordinary payer evidence now agrees with accounting; fresh balances
      // independently prove source delta=-(100000000+175000), target delta=100000000.
      r.node.script.observe = () => Promise.resolve(succeeded(corrected, 1, true, r.base.targetKey));
      r.node.script.after = () => balances(r.base, S_BEFORE - PRINCIPAL - corrected, T_BEFORE + PRINCIPAL);
      const recovered = await recover();
      // A fee different from the planned route may still report fee-mismatch (9).
      expect.soft([0, 9]).toContain(recovered.exit);
      expect.soft(rowOf(r.path, r.executionId)).toMatchObject({ status: 'VERIFIED_SUCCESS', delta_status: 'MATCH' });
      // Receiver-only success may still need a principal-attribution correction;
      // it must not repeat an already accepted fee correction.
      if (initialFee === 'reported') expect.soft(db.ledger.journals()).toEqual(correctedJournals);
      expect.soft(db.ledger.balances().get('expense:routing_fees')).toBe(corrected);
      expect.soft(reservationState(r.path, r.executionId)).toEqual({ state: 'CONSUMED', consumed: corrected });
      expect.soft(rows(r.path, "SELECT * FROM ledger_journals WHERE execution_id = ? AND event_type = 'REBALANCE_SETTLED'", r.executionId)).toEqual(originalSettlement);
      expect.soft(ledger.runLedgerVerify(db).exitCode).toBe(0);
      const afterRecovery = db.ledger.journals();
      await recover();
      await reconcileFee(corrected);
      expect.soft(db.ledger.journals()).toEqual(afterRecovery);
      expect.soft(reservationState(r.path, r.executionId)).toEqual({ state: 'CONSUMED', consumed: corrected });
      expect(r.node.count('sendOnRoute')).toBe(1);
      expect(r.node.count('createInvoice')).toBe(1);
    } finally { db.close(); }
  });
}

it('POST-AUDIT/AUDIT-04+06/concurrent-original-fee accounting rereads committed recovery before charging the same fee', async () => {
  // SPEC append-only corrections and idempotent posting apply across connections:
  // a response read while the original fee was absent cannot charge it again
  // after another worker has already committed that exact original fee.
  const fee = 175_000n; // Less than the independently seeded signed cap 200000.
  const r = await prepare('post-audit-concurrent-original-fee', { script: () => ({
    after: () => { throw new Error('temporary balance read failure'); },
    send: context => { context.onDispatched?.(); return Promise.resolve({ kind: 'IN_FLIGHT' as const }); },
    observe: () => Promise.resolve({ kind: 'IN_FLIGHT' as const }),
    invoiceState: () => Promise.resolve('SETTLED' as const),
  }) });
  expect((await r.run()).exit).toBe(7);
  const { reconcile } = await loadReconciler();
  const setup = r.p.openDatabase(r.path, { readOnly: false });
  try {
    await reconcile({ db: setup, adapters: new Map([[r.base.nodeId, r.node]]), workerId: 'unknown-original-fee',
      leaseMs: 60_000, notFoundWindowMs: 120_000, escalateAfterMs: 3_600_000, confirmIntervalMs: 1_000,
      alert: () => undefined }, { startup: true });
  } finally { setup.close(); }
  expect(rowOf(r.path, r.executionId)).toMatchObject({ status: 'VERIFIED_SUCCESS', actual_fee_msat: null });
  const hash = rowOf(r.path, r.executionId).payment_hash;
  if (hash === null) throw new Error('paid fixture requires a persisted payment hash');
  const ledger = await loadLedger();
  const db = ledger.openDatabase(r.path, { readOnly: false });
  const { runReconcile } = await loadSrc<AccountingCommand>('commands/reconcile.ts');
  let release!: () => void;
  let reached!: () => void;
  const responseHeld = new Promise<void>(resolve => { release = resolve; });
  const requestReached = new Promise<void>(resolve => { reached = resolve; });
  const now = Date.now();
  let holdResponse = true;
  const accounting = () => runReconcile({ db, window: { sinceMs: now - 60_000, untilMs: now + 60_000 },
    executions: [{ id: r.executionId, node: 'lnd-r', paymentHash: hash, status: 'VERIFIED_SUCCESS' }],
    sources: [{ node: 'lnd-r', implementation: 'lnd', api: { listPayments: async () => {
      if (holdResponse) { reached(); await responseHeld; }
      return { payments: [{ paymentHash: hash, valueMsat: PRINCIPAL, feeMsat: fee, status: 'SUCCEEDED' as const,
        creationTimeNs: BigInt(now) * 1_000_000n, paymentIndex: 1n }], lastIndexOffset: 1n };
    } } }], clock: { now: () => now } });
  const pending = accounting();
  try {
    await requestReached;
    // This is a separate real SQLite connection, committing while the first
    // command awaits its ordinary LND ListPayments response. No sleeps or mocks.
    const recovery = r.p.openDatabase(r.path, { readOnly: false }) as ExecDatabase & {
      executions: { view(id: string): { fenceEpoch: bigint } | null;
        recoverSettlement(id: string, epoch: bigint, channel: string, actualFeeMsat: bigint): bigint };
    };
    try {
      const view = recovery.executions.view(r.executionId);
      if (view === null) throw new Error('paid execution disappeared before recovery');
      recovery.executions.recoverSettlement(r.executionId, view.fenceEpoch, r.base.targetKey, fee);
    } finally { recovery.close(); }
    expect(db.ledger.balances().get('expense:routing_fees')).toBe(fee);
    expect(reservationState(r.path, r.executionId)).toEqual({ state: 'CONSUMED', consumed: fee });
    const recoveredJournals = db.ledger.journals();
    release();
    const result = await pending;
    holdResponse = false;
    expect.soft([0, 9]).toContain(result.exitCode);
    expect.soft(db.ledger.balances().get('expense:routing_fees')).toBe(fee);
    expect.soft(reservationState(r.path, r.executionId)).toEqual({ state: 'CONSUMED', consumed: fee });
    expect.soft(rows(r.path, 'SELECT state FROM nodes WHERE id = ?', r.base.nodeId)).toEqual([{ state: 'ONLINE' }]);
    expect.soft(db.ledger.journals()).toEqual(recoveredJournals);
    expect.soft(ledger.runLedgerVerify(db).exitCode).toBe(0);
    await accounting();
    expect.soft(db.ledger.journals()).toEqual(recoveredJournals);
    expect.soft(db.ledger.balances().get('expense:routing_fees')).toBe(fee);
    expect.soft(reservationState(r.path, r.executionId)).toEqual({ state: 'CONSUMED', consumed: fee });
    expect(r.node.count('sendOnRoute')).toBe(1);
  } finally {
    release();
    await pending.catch(() => undefined);
    db.close();
  }
});
