// SPEC Policy / Approval, execution and recovery; SECURITY payment authority:
// the global budget includes corrected actual fees and every unresolved held fee.
import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { PAYMENT_SECRET, ScriptedExecutionNode } from '../fakes/execution-node.js';
import { circularRoute, fakeChannel, FakePreflightNode } from '../fakes/preflight-node.js';
import { APPROVAL_KEYS, dbNow, loadPreflight, PRINCIPAL, reservationsOf, seedOtherNode, seedProposal } from '../helpers/cp028-executor.js';
import { prepare, PREIMAGE, ROUTE_FEE, S_BEFORE, T_BEFORE, TOLERANCE } from '../helpers/cp030-dispatch.js';
import { labelOf, loadDispatch, reservationState, rowOf, sha256, transitionsOf } from '../helpers/cp030-execution.js';
import { loadLedger, type LedgerDatabase } from '../helpers/cp037-ledger.js';
import { rows } from '../helpers/cpw-cli.js';
import { loadSrc } from '../helpers/load-src.js';
import { sentinelRoot } from '../helpers/output.js';

interface AccountingCommand {
  runReconcile: (input: { db: LedgerDatabase; window: { sinceMs: number; untilMs: number };
    executions: { id: string; node: string; paymentHash: string; status: 'VERIFIED_SUCCESS' }[];
    sources: { node: string; implementation: 'lnd'; api: { listPayments(): Promise<{
      payments: { paymentHash: string; valueMsat: bigint; feeMsat: bigint; status: 'SUCCEEDED'; creationTimeNs: bigint; paymentIndex: bigint }[];
      lastIndexOffset: bigint }> } }[]; clock: { now(): number } }) => Promise<{ exitCode: number }>;
}

function barrier() {
  let resolve: () => void = () => undefined;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

it('POST-AUDIT/AUDIT-04+GLOBAL-BUDGET a held operation rechecks corrected fees across nodes before sending', async () => {
  const a = await prepare('post-audit-global-budget-admission');
  const preimageB = randomBytes(32);
  writeFileSync(join(sentinelRoot(), 'budget-admission-preimage-a.bin'), PREIMAGE, { mode: 0o600 });
  writeFileSync(join(sentinelRoot(), 'budget-admission-preimage-b.bin'), preimageB, { mode: 0o600 });
  writeFileSync(join(sentinelRoot(), 'budget-admission-payment-secret.bin'), Buffer.from(PAYMENT_SECRET, 'hex'), { mode: 0o600 });
  expect((await a.run()).exit).toBe(0);
  expect(reservationState(a.path, a.executionId)).toEqual({ state: 'CONSUMED', consumed: 150_000n });
  expect(a.input.policy.budget.msat).toBe(2_000_000n);

  const b = seedOtherNode(a.base);
  expect(b.nodeId).not.toBe(a.base.nodeId);
  const config = rows(a.path, 'SELECT name, expected_pubkey FROM nodes WHERE id = ?', b.nodeId)[0];
  const source = rows(a.path, 'SELECT peer_pubkey FROM channels WHERE id = ?', b.sourceChannelId)[0];
  const target = rows(a.path, 'SELECT peer_pubkey FROM channels WHERE id = ?', b.targetChannelId)[0];
  if (config === undefined || source === undefined || target === undefined) throw new Error('missing second configured fake node');
  const ownPubkey = String(config['expected_pubkey']);
  const outPeer = String(source['peer_pubkey']);
  const inPeer = String(target['peer_pubkey']);
  const route = { ...circularRoute(b.sourceKey, b.targetKey, ROUTE_FEE, 80), outPeer, inPeer };
  const nodeOut = [outPeer, inPeer, ownPubkey];
  const routeB = { ...route, hops: route.hops.map((hop, index) => ({ ...hop, nodeOut: nodeOut[index] ?? ownPubkey })) };
  const channels = (sourceMsat: bigint, targetMsat: bigint) => {
    // Same clock as the production controller's listChannels stamping and the
    // executor's freshness boundary. This fixture varies fees, not clock skew.
    const observedAt = dbNow(a.path);
    return [
      fakeChannel(b.sourceKey, outPeer, { nodeId: String(config['name']), localBalanceMsat: sourceMsat, observedAt }),
      fakeChannel(b.targetKey, inPeer, { nodeId: String(config['name']), localBalanceMsat: targetMsat, observedAt }),
    ];
  };
  const approval = seedProposal(b);
  const preflight = new FakePreflightNode(b.sourceKey, b.targetKey, {
    pubkey: ownPubkey, version: '26.06.9', channels: () => channels(S_BEFORE, T_BEFORE), route: () => routeB,
  });
  const executionDb = a.p.openDatabase(a.path, { readOnly: false });
  const ledger = await loadLedger();
  const accountingDb = ledger.openDatabase(a.path, { readOnly: false });
  const invoiceEntered = barrier();
  const finishInvoice = barrier();
  let pending: Promise<unknown> | undefined;
  try {
    // B claims through ordinary preflight while A still consumes only 150000.
    const ready = await (await loadPreflight()).prepareExecution({ db: executionDb, adapter: preflight,
      workerId: 'worker-b', leaseMs: 60_000 }, { approval, policy: a.input.policy, approvalKeyIds: APPROVAL_KEYS });
    expect(ready.kind).toBe('READY');
    if (ready.kind !== 'READY') throw new Error(`second-node preflight refused: ${ready.step}`);
    expect(reservationsOf(a.path, ready.executionId)).toMatchObject([{ state: 'HELD', reserved_msat: 200_000n }]);
    let heldAtInvoiceClosure: string | undefined;
    // Existing fake ports model AddInvoice/invoice and CancelInvoice/delinvoice;
    // protocol source citations are in test/fakes/execution-node.ts. No network.
    const node = new ScriptedExecutionNode({
      settledChannelKey: b.targetKey,
      before: () => channels(S_BEFORE, T_BEFORE),
      after: () => channels(S_BEFORE - PRINCIPAL - ROUTE_FEE, T_BEFORE + PRINCIPAL),
      invoice: async (_amount, preimage) => {
        invoiceEntered.resolve();
        await finishInvoice.promise;
        return { paymentHash: sha256(preimage), paymentSecret: PAYMENT_SECRET, finalCltvDelta: 18 };
      },
      cancel: () => {
        heldAtInvoiceClosure = reservationState(a.path, ready.executionId).state;
        return Promise.resolve('CANCELED');
      },
    });
    const dispatch = (await loadDispatch()).dispatchExecution({ db: executionDb, adapter: node,
      workerId: 'worker-b', leaseMs: 60_000, randomBytes: size => size === 32 ? Uint8Array.from(preimageB) : randomBytes(size),
      stopSignal: new AbortController().signal, attemptDeadlineMs: 5_000, invoiceExpirySeconds: 3_600,
      deltaToleranceMsat: TOLERANCE, alert: () => undefined },
    { executionId: ready.executionId, fenceEpoch: ready.fenceEpoch, route: ready.route, approval, policy: a.input.policy });
    pending = dispatch;
    await Promise.race([invoiceEntered.promise, dispatch.then(() => { throw new Error('B finished before invoice preparation'); })]);
    expect(node.count('sendOnRoute')).toBe(0);
    expect(rowOf(a.path, ready.executionId).status).toBe('PREFLIGHT');
    expect(reservationState(a.path, ready.executionId)).toEqual({ state: 'HELD', consumed: null });

    const paymentHash = rowOf(a.path, a.executionId).payment_hash;
    if (paymentHash === null) throw new Error('successful A has no persisted hash');
    const now = Date.now();
    const originalJournals = accountingDb.ledger.journals();
    const { runReconcile } = await loadSrc<AccountingCommand>('commands/reconcile.ts');
    // LND ListPayments fee_msat/value_msat (lnrpc/lightning.proto Payment),
    // exactly the authoritative accounting port used by the existing money gold tests.
    const correctA = () => runReconcile({ db: accountingDb, window: { sinceMs: now - 60_000, untilMs: now + 60_000 },
      executions: [{ id: a.executionId, node: 'lnd-r', paymentHash, status: 'VERIFIED_SUCCESS' }],
      sources: [{ node: 'lnd-r', implementation: 'lnd', api: { listPayments: () => Promise.resolve({ payments: [{
        paymentHash, valueMsat: PRINCIPAL, feeMsat: 1_900_000n, status: 'SUCCEEDED', creationTimeNs: BigInt(now) * 1_000_000n,
        paymentIndex: 1n }], lastIndexOffset: 1n }) } }], clock: { now: () => now } });
    expect((await correctA()).exitCode).toBe(8);
    expect(reservationState(a.path, a.executionId)).toEqual({ state: 'CONSUMED', consumed: 1_900_000n });
    expect(accountingDb.ledger.balances().get('expense:routing_fees')).toBe(1_900_000n);
    expect(rows(a.path, 'SELECT state FROM nodes WHERE id = ?', b.nodeId)).toEqual([{ state: 'ONLINE' }]);
    expect(rows(a.path, `SELECT SUM(CASE WHEN state = 'CONSUMED' THEN consumed_msat ELSE reserved_msat END) AS total
      FROM budget_reservations WHERE state IN ('CONSUMED', 'HELD')`)).toEqual([{ total: 2_100_000 }]);
    const correctedJournals = accountingDb.ledger.journals();
    expect(correctedJournals.filter(journal => originalJournals.some(original => original.id === journal.id))).toEqual(originalJournals);

    finishInvoice.resolve();
    const outcome = await dispatch;
    // 1900000 consumed + B's 200000 held > 2000000 global policy budget.
    // Definite unpaid invoice closure precedes release of B's unsent reservation.
    expect.soft(node.count('sendOnRoute')).toBe(0);
    expect.soft(outcome).toMatchObject({ exit: 5, step: 'BUDGET_EXHAUSTED' });
    expect.soft(node.named('cancelUnpaidInvoice').map(call => call.args)).toEqual([[sha256(preimageB), labelOf(ready.executionId)]]);
    expect.soft(heldAtInvoiceClosure).toBe('HELD');
    expect.soft(rowOf(a.path, ready.executionId)).toMatchObject({ status: 'CANCELLED', error_code: 'BUDGET_EXHAUSTED', submitted_at: null });
    expect.soft(transitionsOf(a.path, ready.executionId)).not.toContain('PREFLIGHT>SUBMITTING');
    expect.soft(reservationState(a.path, ready.executionId)).toEqual({ state: 'RELEASED', consumed: null });
    expect.soft(rows(a.path, 'SELECT state FROM nodes WHERE id = ?', b.nodeId)).toEqual([{ state: 'ONLINE' }]);
    expect.soft(rowOf(a.path, a.executionId).status).toBe('VERIFIED_SUCCESS');
    expect.soft(reservationState(a.path, a.executionId)).toEqual({ state: 'CONSUMED', consumed: 1_900_000n });
    expect.soft(accountingDb.ledger.journals()).toEqual(correctedJournals);
    expect.soft(accountingDb.ledger.balances().get('expense:routing_fees')).toBe(1_900_000n);
    expect.soft(ledger.verifyLedger({ journals: accountingDb.ledger.journals(), balances: accountingDb.ledger.balances(),
      executions: accountingDb.ledger.executions() }).ok).toBe(true);
    await correctA();
    expect.soft(accountingDb.ledger.journals()).toEqual(correctedJournals);
    expect.soft(a.node.count('sendOnRoute')).toBe(1);
  } finally {
    finishInvoice.resolve();
    await pending?.catch(() => undefined);
    accountingDb.close();
    executionDb.close();
  }
});
