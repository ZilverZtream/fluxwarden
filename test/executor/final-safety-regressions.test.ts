// Independent reference gold: ARCHITECTURE §3 step9; SPEC §6.4, §8.3 P6,
// §8.7 step4, §9.2–9.3; SECURITY §4.3 clocks. These cases use only owned
// synthetic databases and the existing public execution/adapter interfaces.
import { expect, it, vi } from 'vitest';
import { PAYMENT_SECRET, succeeded } from '../fakes/execution-node.js';
import { circularRoute, fakeChannel } from '../fakes/preflight-node.js';
import { sendpay } from '../fakes/cln/responses.js';
import { loadErrors, type ClnRest } from '../helpers/adapter-interfaces.js';
import { dbNow, IN_PEER, PRINCIPAL, raw } from '../helpers/cp028-executor.js';
import { balances, prepare, ROUTE_FEE, S_BEFORE, T_BEFORE } from '../helpers/cp030-dispatch.js';
import { exec, loadClnExecute, rowOf, seedExecution, sha256 } from '../helpers/cp030-execution.js';

for (const operation of ['renewLease', 'submit'] as const) {
  it(`CP-028/B5 an expired database lease cannot authorize ${operation} with an unchanged fence`, async () => {
    const r = await prepare(`expired-${operation}`);
    exec(r.path, 'UPDATE executions SET lease_expires_at = ?, payment_hash = ? WHERE id = ?', dbNow(r.path) - 1_000, sha256(new Uint8Array(32)), r.executionId);
    const db = r.p.openDatabase(r.path, { readOnly: false });
    const before = rowOf(r.path, r.executionId);
    try {
      const invoke = () => operation === 'renewLease'
        ? db.executions.renewLease(r.executionId, 3n, 60_000)
        : db.executions.submit(r.executionId, 3n, 1, 60_000);
      expect(invoke).toThrow(expect.objectContaining({ code: 'LEASE_LOST' }));
      expect(rowOf(r.path, r.executionId)).toEqual(before);
    } finally { db.close(); }
  });
}

it('CP-028/B3 a late UNKNOWN terminal observation remains writable after database lease expiry', async () => {
  const r = await prepare('late-terminal');
  const terminal = seedExecution(r.base, { status: 'UNKNOWN', leaseInMs: -1_000, paymentHash: sha256(new Uint8Array(32)), route: r.route, plannedFeeMsat: ROUTE_FEE });
  const db = r.p.openDatabase(r.path, { readOnly: false });
  try {
    // SPEC §8.4 resolves UNKNOWN by evidence; this write cannot authorize a send.
    expect(db.executions.transition(terminal.executionId, 3n, 'UNKNOWN', 'VERIFIED_FAILURE')).toBe(4n);
    expect(rowOf(r.path, terminal.executionId).status).toBe('VERIFIED_FAILURE');
    expect(r.node.calls).toEqual([]);
  } finally { db.close(); }
});

it('CP-030/B7 a worker paused past its lease during invoice creation makes no payment send without a takeover', async () => {
  const r = await prepare('expired-during-invoice', {
    script: ({ path, executionId }) => ({ invoice: (_amount, preimage) => {
      // Deterministic ordinary await boundary: only the database deadline ages;
      // the worker and fence stay unchanged and no competing claim occurs.
      exec(path, 'UPDATE executions SET lease_expires_at = ? WHERE id = ?', dbNow(path) - 1_000, executionId);
      return Promise.resolve({ paymentHash: sha256(preimage), paymentSecret: PAYMENT_SECRET, finalCltvDelta: 18 });
    } }),
  });
  const outcome = await r.run();
  expect(r.node.count('sendOnRoute')).toBe(0);
  expect(outcome).toMatchObject({ exit: 5, step: 'lease-lost' });
  expect(rowOf(r.path, r.executionId).status).toBe('PREFLIGHT');
});

it('CP-037/B2 non-strict forwarding credits the observed incoming channel with exact worked-example principal and fee', async () => {
  const incoming = '369435907129344';
  const fee = 202_101n;
  const r = await prepare('observed-incoming', {
    approval: approval => ({ ...approval, approvedMaxFeeMsat: 300_000n }),
    route: base => circularRoute(base.sourceKey, base.targetKey, fee, 80),
    script: ({ base }) => ({
      before: () => [...balances(base, S_BEFORE, T_BEFORE), fakeChannel(incoming, IN_PEER, { localBalanceMsat: 200_000_000n })],
      after: () => [...balances(base, S_BEFORE - PRINCIPAL - fee, T_BEFORE), fakeChannel(incoming, IN_PEER, { localBalanceMsat: 300_000_000n })],
      send: context => { context.onDispatched?.(); return Promise.resolve({ ...succeeded(fee), settledChannelKey: incoming }); },
    }),
  });
  await r.run();
  const db = raw(r.path);
  try {
    const lines = db.prepare(`SELECT l.account_code AS account, l.debit_msat AS debit, l.credit_msat AS credit
      FROM ledger_lines l JOIN ledger_journals j ON j.id = l.journal_id
      WHERE j.execution_id = ? AND j.event_type = 'REBALANCE_SETTLED' ORDER BY l.sequence_no`).all(r.executionId);
    expect(lines).toEqual([
      { account: `channel:lnd-r:${incoming}:local`, debit: 100_000_000n, credit: 0n },
      { account: 'expense:routing_fees', debit: 202_101n, credit: 0n },
      { account: 'clearing:inflight', debit: 0n, credit: 100_202_101n },
    ]);
  } finally { db.close(); }
});

it('CP-037/B2 an unknown incoming channel cannot fabricate a credit to the planned target', async () => {
  const r = await prepare('unknown-incoming', {
    script: ({ base }) => ({ settledChannelKey: null, after: () => balances(base, S_BEFORE - PRINCIPAL - ROUTE_FEE, T_BEFORE) }),
  });
  await r.run();
  const db = raw(r.path);
  try {
    const fabricated = db.prepare(`SELECT l.debit_msat AS debit FROM ledger_lines l JOIN ledger_journals j ON j.id = l.journal_id
      WHERE j.execution_id = ? AND j.event_type = 'REBALANCE_SETTLED' AND l.account_code = ?`).all(r.executionId, `channel:lnd-r:${r.base.targetKey}:local`);
    expect(fabricated).toEqual([]);
    const clearing = db.prepare("SELECT balance_decimal AS balance FROM account_balances WHERE account_code = 'clearing:inflight'").get();
    // D76: actual paid principal without a receiver identity is a terminal
    // unassigned asset; required settlement accounting no longer leaves fees
    // and principal pending together. The planned target still receives nothing.
    expect(clearing).toEqual({ balance: '0' });
    const unassigned = db.prepare("SELECT balance_decimal AS balance FROM account_balances WHERE account_code = 'clearing:unassigned'").get();
    expect(unassigned).toEqual({ balance: '100000000' });
  } finally { db.close(); }
});

it('CP-031/B3 a backward wall-clock step does not extend bounded waitsendpay observation or start another send', async () => {
  const { ClnExecutionAdapter } = await loadClnExecute();
  const { ClnError } = await loadErrors();
  const own = '03' + 'd4'.repeat(32);
  const peerA = '02' + 'aa'.repeat(32);
  const peerB = '02' + 'bb'.repeat(32);
  const hash = sha256(new Uint8Array(32));
  let wall = 1_800_000_000_000;
  let waits = 0;
  let sends = 0;
  const rest: ClnRest = { call: async method => {
    if (method === 'sendpay') { sends += 1; return sendpay({ status: 'pending', payment_hash: hash, amount_msat: 100000000, amount_sent_msat: 100202101 }); }
    if (method === 'waitsendpay') {
      waits += 1;
      await new Promise<void>(resolve => setTimeout(resolve, 30));
      wall -= 60_000;
      if (waits > 8) throw new Error('synthetic bounded transport closure');
      // The normal ClnRest error exposes numeric200 and HTTP500; see the pinned
      // waitsendpay-timeout response used by test/node-cln/cp031-cln-execute.
      throw Object.assign(new ClnError('Timed out while waiting'), { code: 200, httpStatus: 500 });
    }
    throw new Error(`Unexpected public RPC ${method}`);
  } };
  const clock = vi.spyOn(Date, 'now').mockImplementation(() => wall);
  try {
    const cln = new ClnExecutionAdapter(rest, { ownId: own, waitChunkSeconds: 1, attemptDeadlineMs: 100 });
    const observation = await cln.sendOnRoute({
      sourceChannelKey: '103x1x0', targetChannelKey: '107x2x0', outPeer: peerA, inPeer: peerB, principalMsat: 100_000_000n,
      hops: [
        { channelKey: '103x1x0', nodeOut: peerA, amountOutMsat: 100_202_101n, expiry: 944 },
        { channelKey: '105x1x1', nodeOut: peerB, amountOutMsat: 100_101_000n, expiry: 864 },
        { channelKey: '107x2x0', nodeOut: own, amountOutMsat: 100_000_000n, expiry: 830 },
      ], totalFeeMsat: 202_101n, feePpmCeil: 2_022n, totalTimelockDelta: 132, parts: 1,
    }, hash, PAYMENT_SECRET);
    expect(observation.kind).toBe('AMBIGUOUS');
    expect(sends).toBe(1);
    // UNKNOWN must also bound background work: observe after the outer deadline,
    // while the same wall-clock rollback remains in effect. The finite fake
    // closes at nine chunks so a defective implementation cannot hang the suite.
    await new Promise<void>(resolve => setTimeout(resolve, 220));
    expect(waits).toBeGreaterThanOrEqual(1);
    // At most four 30ms bounded chunks fit a 100ms monotonic deadline.
    expect(waits).toBeLessThanOrEqual(4);
  } finally { clock.mockRestore(); }
});
