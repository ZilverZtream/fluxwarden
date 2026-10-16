/*
Interface: test/helpers/cp030-execution.ts (dispatchExecution, ExecutionAdapter, DispatchOutcome, Alert), on top of
test/helpers/cp028-executor.ts (persistence, fenced transitions, budget reservations).

Rules under test: SPEC §8.2 (transitions and their side effects), §8.3 P5-P7, §8.7 (result checks, delta verification),
§5.3 L1/L7-L9, §6.4 (lease re-assertion before the mutating RPC; zero affected rows stops the worker), §6.6 (reservation
HELD / CONSUMED / RELEASED), §10.1 (interrupts: exit 6 before any mutating RPC), §10.3 AE9-AE13 (exit codes);
SECURITY INV-03 (a higher actual fee raises INVARIANT_BREACH), INV-05 (hash persisted before any payment bytes),
INV-17 (one HTLC), INV-18 (fenced writes), INV-19 (never sent again).
*/
// The seeded fake receiver is channel246290604752896 (seedBase); these receipts declare its independently simulated incoming settlement.
import { afterAll, beforeAll, describe, expect, it, onTestFinished } from 'vitest';
import { failed, never, PAYMENT_SECRET, ScriptedExecutionNode, succeeded } from '../fakes/execution-node.js';
import { APPROVED_MAX_FEE, PRINCIPAL, sleep, type ExecDatabase } from '../helpers/cp028-executor.js';
import { databaseText, exec, labelOf, reservationState, rowOf, sha256, transitionsOf } from '../helpers/cp030-execution.js';
import { balances, HASH, prepare, PREIMAGE, ROUTE_FEE, S_BEFORE, settled, T_BEFORE, TOLERANCE } from '../helpers/cp030-dispatch.js';

it('CP-030/B1 FluxWarden generates the preimage and persists its hash before the invoice and before the one send', async () => {
  const seen: Record<string, ReturnType<typeof rowOf>> = {};
  const r = await prepare('order', {
    script: ({ path, executionId }) => ({
      invoice: (_amount, preimage) => { seen['invoice'] = rowOf(path, executionId); return Promise.resolve({ paymentHash: sha256(preimage), paymentSecret: PAYMENT_SECRET, finalCltvDelta: 18 }); },
      send: async context => {
        seen['send'] = rowOf(path, executionId);
        context.onDispatched?.();
        await sleep(30);
        seen['dispatched'] = rowOf(path, executionId);
        return succeeded(context.route.totalFeeMsat, 1, true, '246290604752896');
      },
    }),
  });
  const outcome = await r.run();
  expect(outcome).toEqual({ executionId: r.executionId, exit: 0, step: null });
  // INV-05 / SPEC §5.3 L1: the hash is stored while the row is still PREFLIGHT, before AddInvoice / invoice.
  expect(seen['invoice']?.status).toBe('PREFLIGHT');
  expect(seen['invoice']?.payment_hash).toBe(HASH);
  // SPEC §5.3 L7: SUBMITTING, with the route and submitted_at, before the payment RPC.
  expect(seen['send']?.status).toBe('SUBMITTING');
  expect(seen['send']?.payment_hash).toBe(HASH);
  expect(seen['send']?.route_json).not.toBeNull();
  expect(seen['send']?.submitted_at).not.toBeNull();
  // SPEC §5.3 L8: IN_FLIGHT as soon as the request is written.
  expect(seen['dispatched']?.status).toBe('IN_FLIGHT');
  const invoice = r.node.named('createInvoice');
  expect(invoice).toHaveLength(1);
  expect(invoice[0]?.args.slice(0, 3)).toEqual([PRINCIPAL, PREIMAGE, labelOf(r.executionId)]);
  const send = r.node.named('sendOnRoute');
  expect(send).toHaveLength(1);
  expect(send[0]?.args).toEqual([r.route, HASH, PAYMENT_SECRET]);
  expect(r.node.names().indexOf('createInvoice')).toBeLessThan(r.node.names().indexOf('sendOnRoute'));
});

it('CP-030/B1 the preimage is never written to the database', async () => {
  const r = await prepare('nopreimage');
  expect((await r.run()).exit).toBe(0);
  const text = databaseText(r.path);
  expect(text).toContain(HASH);
  expect(text.toLowerCase()).not.toContain(PREIMAGE.toString('hex'));
  expect(text).not.toContain(PREIMAGE.toString('base64'));
});

for (const variant of ['rejected', 'foreign-hash'] as const) {
  it(`CP-030/B1 an invoice answer that is ${variant} cancels the execution and sends nothing`, async () => {
    const r = await prepare(`inv-${variant}`, {
      script: () => ({
        invoice: () => variant === 'rejected'
          ? Promise.reject(new Error('invoice creation answer lost'))
          : Promise.resolve({ paymentHash: 'ee'.repeat(32), paymentSecret: PAYMENT_SECRET, finalCltvDelta: 18 }),
      }),
    });
    const outcome = await r.run();
    expect(outcome.exit).toBe(5);
    expect(r.node.count('sendOnRoute')).toBe(0);
    expect(rowOf(r.path, r.executionId).status).toBe('CANCELLED');
    expect(reservationState(r.path, r.executionId).state).toBe('RELEASED');
  });
}

for (const kind of ['SUCCEEDED', 'FAILED', 'IN_FLIGHT', 'NOT_FOUND', 'AMBIGUOUS', 'rejection'] as const) {
  it(`CP-030/B3 exactly one send whatever the answer (${kind})`, async () => {
    const r = await prepare(`one-${kind}`, {
      script: () => ({
        send: context => {
          context.onDispatched?.();
          switch (kind) {
            case 'SUCCEEDED': return Promise.resolve(succeeded(ROUTE_FEE, 1, true, '246290604752896'));
            case 'FAILED': return Promise.resolve(failed('FAILURE_REASON_NO_ROUTE'));
            case 'IN_FLIGHT': return Promise.resolve({ kind: 'IN_FLIGHT' });
            case 'NOT_FOUND': return Promise.resolve({ kind: 'NOT_FOUND' });
            case 'AMBIGUOUS': return Promise.resolve({ kind: 'AMBIGUOUS', cause: 'connection reset after the request was written' });
            case 'rejection': return Promise.reject(new Error('socket hang up'));
          }
        },
        observe: () => Promise.resolve({ kind: 'IN_FLIGHT' }),
      }),
    });
    await r.run();
    expect(r.node.count('sendOnRoute')).toBe(1);
    expect(r.node.count('createInvoice')).toBe(1);
  });
}

it('CP-030/B3 a stop request before dispatch cancels without any invoice or send (exit 6)', async () => {
  const stop = new AbortController();
  stop.abort();
  const r = await prepare('stop-early', { signal: stop.signal });
  const outcome = await r.run();
  expect(outcome).toEqual({ executionId: r.executionId, exit: 6, step: 'INTERRUPTED' });
  expect(r.node.fundMovingCalls()).toEqual([]);
  const row = rowOf(r.path, r.executionId);
  expect(row.status).toBe('CANCELLED');
  expect(row.error_code).toBe('INTERRUPTED');
  expect(reservationState(r.path, r.executionId).state).toBe('RELEASED');
});

it('CP-030/B3 a stop request while the invoice is created prevents the send and cancels the invoice (exit 6)', async () => {
  const stop = new AbortController();
  const r = await prepare('stop-invoice', {
    signal: stop.signal,
    script: () => ({
      invoice: (_amount, preimage) => { stop.abort(); return Promise.resolve({ paymentHash: sha256(preimage), paymentSecret: PAYMENT_SECRET, finalCltvDelta: 18 }); },
    }),
  });
  const outcome = await r.run();
  expect(outcome).toEqual({ executionId: r.executionId, exit: 6, step: 'INTERRUPTED' });
  expect(r.node.count('sendOnRoute')).toBe(0);
  expect(r.node.named('cancelUnpaidInvoice').map(call => call.args)).toEqual([[HASH, labelOf(r.executionId)]]);
  const row = rowOf(r.path, r.executionId);
  expect(row.status).toBe('CANCELLED');
  expect(row.payment_hash).toBe(HASH);
  expect(reservationState(r.path, r.executionId).state).toBe('RELEASED');
});

it('CP-030/B4 one HTLC with the route fee within the cap is VERIFIED_SUCCESS: fee recorded, reservation consumed, exit 0', async () => {
  const r = await prepare('success');
  const outcome = await r.run();
  expect(outcome).toEqual({ executionId: r.executionId, exit: 0, step: null });
  const row = rowOf(r.path, r.executionId);
  expect(row.status).toBe('VERIFIED_SUCCESS');
  expect(row.actual_fee_msat).toBe(ROUTE_FEE);
  expect(row.delta_status).toBe('MATCH');
  expect(reservationState(r.path, r.executionId)).toEqual({ state: 'CONSUMED', consumed: ROUTE_FEE });
  expect(transitionsOf(r.path, r.executionId)).toEqual(['PREFLIGHT>SUBMITTING', 'SUBMITTING>IN_FLIGHT', 'IN_FLIGHT>VERIFIED_SUCCESS']);
  expect(r.alerts).toEqual([]);
  expect(r.node.count('cancelUnpaidInvoice')).toBe(0);
});

it('CP-030/B4 two settled HTLCs raise INVARIANT_BREACH (SINGLE_PATH_UNAVAILABLE) and exit 8; the settled payment stays a success', async () => {
  const r = await prepare('two-htlcs', { script: () => ({ send: c => { c.onDispatched?.(); return Promise.resolve(succeeded(ROUTE_FEE, 2)); } }) });
  const outcome = await r.run();
  expect(outcome.exit).toBe(8);
  expect(r.alerts).toEqual([{ kind: 'INVARIANT_BREACH', executionId: r.executionId, code: 'SINGLE_PATH_UNAVAILABLE' }]);
  // SPEC §8.2: VERIFIED_FAILURE needs a FAILED payment; money that moved is never booked as a failure.
  expect(rowOf(r.path, r.executionId).status).toBe('VERIFIED_SUCCESS');
});

it('CP-030/B4 an actual fee one msat above the approved cap raises INVARIANT_BREACH (FEE_ABOVE_CAP), exit 8, the fee consumed as reported', async () => {
  const fee = APPROVED_MAX_FEE + 1n;
  const r = await prepare('fee-cap', {
    script: ({ base }) => ({ after: settled(base, fee), send: c => { c.onDispatched?.(); return Promise.resolve(succeeded(fee)); } }),
  });
  const outcome = await r.run();
  expect(outcome.exit).toBe(8);
  expect(r.alerts).toEqual([{ kind: 'INVARIANT_BREACH', executionId: r.executionId, code: 'FEE_ABOVE_CAP' }]);
  const row = rowOf(r.path, r.executionId);
  expect(row.status).toBe('VERIFIED_SUCCESS');
  expect(row.actual_fee_msat).toBe(fee);
  // SPEC §6.6: a fee above the reservation is recorded, never refused after the fact.
  expect(reservationState(r.path, r.executionId)).toEqual({ state: 'CONSUMED', consumed: fee });
});

it('CP-030/B4 an actual fee equal to the cap but different from the route fee is a fee-mismatch (exit 9), not a breach', async () => {
  const fee = APPROVED_MAX_FEE;
  const r = await prepare('fee-mismatch', {
    script: ({ base }) => ({ after: settled(base, fee), send: c => { c.onDispatched?.(); return Promise.resolve(succeeded(fee, 1, true, '246290604752896')); } }),
  });
  const outcome = await r.run();
  expect(outcome.exit).toBe(9);
  expect(r.alerts).toEqual([{ kind: 'fee-mismatch', executionId: r.executionId, code: 'FEE_MISMATCH' }]);
  expect(rowOf(r.path, r.executionId).status).toBe('VERIFIED_SUCCESS');
});

it('CP-030/B4 a success whose preimage does not hash to the payment hash stays unresolved with INVARIANT_BREACH, exit 8', async () => {
  const r = await prepare('preimage', { script: () => ({ send: c => { c.onDispatched?.(); return Promise.resolve(succeeded(ROUTE_FEE, 1, false)); } }) });
  const outcome = await r.run();
  expect(outcome.exit).toBe(8);
  expect(r.alerts).toEqual([{ kind: 'INVARIANT_BREACH', executionId: r.executionId, code: 'PREIMAGE_MISMATCH' }]);
  expect(rowOf(r.path, r.executionId).status).toBe('UNKNOWN');
  expect(reservationState(r.path, r.executionId).state).toBe('HELD');
  expect(r.node.count('cancelUnpaidInvoice')).toBe(0);
});

describe('terminal failure dispatch fixture', () => {
  let r: Awaited<ReturnType<typeof prepare>>;
  let database: ExecDatabase | undefined;
  let statusAtCancel: string;
  let preparedAt: number, prepMs: number;
  const close = (): void => { const owned = database; database = undefined; owned?.close(); };
  beforeAll(async () => {
    preparedAt = performance.now(); statusAtCancel = '';
    r = await prepare('failure', {
      script: ({ path, executionId }) => ({
        send: c => { c.onDispatched?.(); return Promise.resolve(failed('FAILURE_REASON_INCORRECT_PAYMENT_DETAILS')); },
        cancel: () => { statusAtCancel = rowOf(path, executionId).status; return Promise.resolve('CANCELED'); },
      }),
    });
    database = r.p.openDatabase(r.path, { readOnly: false });
    prepMs = performance.now() - preparedAt;
  }, 30_000);
  afterAll(close);
  it('CP-030/B5 a terminal failure cancels the invoice first, then VERIFIED_FAILURE with the node reason, reservation released, exit 5', async () => {
    const started = performance.now();
    onTestFinished(close);
    if (database === undefined) throw new Error('terminal failure fixture is not open');
    try {
      const outcome = await r.run(r.node, database);
      expect(outcome).toEqual({ executionId: r.executionId, exit: 5, step: 'FAILURE_REASON_INCORRECT_PAYMENT_DETAILS' });
      expect(r.node.named('cancelUnpaidInvoice').map(call => call.args)).toEqual([[HASH, labelOf(r.executionId)]]);
      expect(statusAtCancel).toBe('IN_FLIGHT');
      const row = rowOf(r.path, r.executionId);
      expect(row.status).toBe('VERIFIED_FAILURE');
      expect(row.error_code).toBe('FAILURE_REASON_INCORRECT_PAYMENT_DETAILS');
      expect(row.actual_fee_msat).toBeNull();
      expect(reservationState(r.path, r.executionId).state).toBe('RELEASED');
      expect(transitionsOf(r.path, r.executionId).at(-1)).toBe('IN_FLIGHT>VERIFIED_FAILURE');
    } finally {
      close();
      console.log(JSON.stringify({ case: 'terminal-failure', prepMs, caseMs: performance.now() - started, totalMs: performance.now() - preparedAt }));
    }
  });
});

describe('failed payment still in flight fixture', () => {
  let r: Awaited<ReturnType<typeof prepare>>;
  let database: ExecDatabase | undefined;
  let preparedAt: number, prepMs: number;
  const close = (): void => { const owned = database; database = undefined; owned?.close(); };
  beforeAll(async () => {
    preparedAt = performance.now();
    r = await prepare('failed-inflight', { script: () => ({ send: c => { c.onDispatched?.(); return Promise.resolve(failed('FAILURE_REASON_TIMEOUT', 1)); } }) });
    database = r.p.openDatabase(r.path, { readOnly: false });
    prepMs = performance.now() - preparedAt;
  }, 30_000);
  afterAll(close);
  it('CP-030/B5 FAILED with an HTLC still in flight is not a failure: UNKNOWN, no invoice cancel, exit 7', async () => {
    const started = performance.now();
    onTestFinished(close);
    if (database === undefined) throw new Error('in-flight failure fixture is not open');
    try {
      const outcome = await r.run(r.node, database);
      expect(outcome).toEqual({ executionId: r.executionId, exit: 7, step: 'OUTCOME_UNKNOWN' });
      expect(rowOf(r.path, r.executionId).status).toBe('UNKNOWN');
      expect(r.node.count('cancelUnpaidInvoice')).toBe(0);
      expect(reservationState(r.path, r.executionId).state).toBe('HELD');
    } finally {
      close();
      console.log(JSON.stringify({ case: 'failed-inflight', prepMs, caseMs: performance.now() - started, totalMs: performance.now() - preparedAt }));
    }
  });
});

describe('paid invoice cancellation fixture', () => {
  let r: Awaited<ReturnType<typeof prepare>>;
  let database: ExecDatabase | undefined;
  let preparedAt: number, prepMs: number;
  const close = (): void => { const owned = database; database = undefined; owned?.close(); };
  beforeAll(async () => {
    preparedAt = performance.now();
    r = await prepare('already-paid', {
      script: () => ({
        send: c => { c.onDispatched?.(); return Promise.resolve(failed('FAILURE_REASON_TIMEOUT')); },
        cancel: () => Promise.resolve('ALREADY_PAID'),
        observe: () => Promise.resolve(succeeded(ROUTE_FEE, 1, true, '246290604752896')),
      }),
    });
    database = r.p.openDatabase(r.path, { readOnly: false });
    prepMs = performance.now() - preparedAt;
  }, 30_000);
  afterAll(close);
  it('CP-030/B5 a failure whose invoice turns out paid at cancel time is resolved as a success', async () => {
    const started = performance.now();
    onTestFinished(close);
    if (database === undefined) throw new Error('paid invoice cancellation fixture is not open');
    try {
      const outcome = await r.run(r.node, database);
      expect(outcome.exit).toBe(0);
      expect(rowOf(r.path, r.executionId).status).toBe('VERIFIED_SUCCESS');
      expect(r.node.count('sendOnRoute')).toBe(1);
    } finally {
      close();
      console.log(JSON.stringify({ case: 'already-paid', prepMs, caseMs: performance.now() - started, totalMs: performance.now() - preparedAt }));
    }
  });
});

for (const [name, sourceAfter, targetAfter, status, exit] of [
  ['exactly the tolerance away', S_BEFORE - PRINCIPAL - ROUTE_FEE + TOLERANCE, T_BEFORE + PRINCIPAL, 'MATCH', 0],
  ['one msat beyond the tolerance', S_BEFORE - PRINCIPAL - ROUTE_FEE + TOLERANCE + 1n, T_BEFORE + PRINCIPAL, 'MISMATCH', 9],
  ['credited to no target balance', S_BEFORE - PRINCIPAL - ROUTE_FEE, T_BEFORE, 'MISMATCH', 9],
] as const) {
  describe(`channel delta ${name} fixture`, () => {
    let r: Awaited<ReturnType<typeof prepare>>;
    let database: ExecDatabase | undefined;
    let preparedAt: number, prepMs: number;
    const close = (): void => { const owned = database; database = undefined; owned?.close(); };
    beforeAll(async () => {
      preparedAt = performance.now();
      r = await prepare(`delta-${status}-${String(exit)}-${String(name.length)}`, { script: ({ base }) => ({ after: () => balances(base, sourceAfter, targetAfter) }) });
      database = r.p.openDatabase(r.path, { readOnly: false });
      prepMs = performance.now() - preparedAt;
    }, 30_000);
    afterAll(close);
    it(`CP-030/B6 channel deltas ${name} give delta_status ${status} (exit ${String(exit)}); the execution stays VERIFIED_SUCCESS`, async () => {
      const started = performance.now();
      onTestFinished(close);
      if (database === undefined) throw new Error('channel delta fixture is not open');
      try {
        const outcome = await r.run(r.node, database);
        expect(outcome.exit).toBe(exit);
        const row = rowOf(r.path, r.executionId);
        expect(row.status).toBe('VERIFIED_SUCCESS');
        expect(row.delta_status).toBe(status);
        expect(r.alerts).toEqual(status === 'MATCH' ? [] : [{ kind: 'delta-mismatch', executionId: r.executionId, code: 'DELTA_MISMATCH' }]);
        expect(r.node.count('listChannels')).toBe(2);
      } finally {
        close();
        console.log(JSON.stringify({ case: `delta-${name}`, prepMs, caseMs: performance.now() - started, totalMs: performance.now() - preparedAt }));
      }
    });
  });
}

it('CP-030/B7 dispatching the same execution again is refused by the fence: lease-lost, no invoice and no send', async () => {
  const r = await prepare('again');
  expect((await r.run()).exit).toBe(0);
  const before = rowOf(r.path, r.executionId);
  const second = new ScriptedExecutionNode({ before: () => balances(r.base, S_BEFORE, T_BEFORE) });
  const outcome = await r.run(second);
  expect(outcome).toEqual({ executionId: r.executionId, exit: 5, step: 'lease-lost' });
  // INV-18: a worker without the lease makes no node call at all, reads included.
  expect(second.calls).toEqual([]);
  expect(rowOf(r.path, r.executionId)).toEqual(before);
});

it('CP-030/B7 two concurrent dispatches of one execution send exactly once', async () => {
  const r = await prepare('concurrent');
  const other = new ScriptedExecutionNode({ settledChannelKey: r.base.targetKey, before: () => balances(r.base, S_BEFORE, T_BEFORE), after: settled(r.base, ROUTE_FEE) });
  const outcomes = await Promise.all([r.run(r.node), r.run(other)]);
  expect(r.node.count('sendOnRoute') + other.count('sendOnRoute')).toBe(1);
  expect(r.node.count('createInvoice') + other.count('createInvoice')).toBe(1);
  expect(outcomes.map(o => o.exit).sort()).toEqual([0, 5]);
  expect(outcomes.find(o => o.exit === 5)?.step).toBe('lease-lost');
});

it('CP-030/B7 a lease taken over while the invoice is created stops the worker before the send (lease-lost, exit 5)', async () => {
  const r = await prepare('takeover', {
    script: ({ path, executionId }) => ({
      invoice: (_amount, preimage) => {
        exec(path, "UPDATE executions SET fence_epoch = fence_epoch + 1, worker_id = 'worker-b' WHERE id = ?", executionId);
        return Promise.resolve({ paymentHash: sha256(preimage), paymentSecret: PAYMENT_SECRET, finalCltvDelta: 18 });
      },
    }),
  });
  const outcome = await r.run();
  expect(outcome).toEqual({ executionId: r.executionId, exit: 5, step: 'lease-lost' });
  expect(r.node.count('sendOnRoute')).toBe(0);
  const row = rowOf(r.path, r.executionId);
  expect(row.status).toBe('PREFLIGHT');
  expect(row.worker_id).toBe('worker-b');
});

it('CP-030/B3 a route whose final CLTV delta is one block short of the invoice minimum is never sent (CLTV_DELTA_UNSAFE)', async () => {
  // The default route reaches us at height 518 for a build height of 500: a final delta of 18 (SPEC §5.3 L3: the route
  // is validated against the invoice's final delta in any case; ARCHITECTURE §3 check 8).
  const r = await prepare('final-cltv', {
    script: () => ({ invoice: (_amount, preimage) => Promise.resolve({ paymentHash: sha256(preimage), paymentSecret: PAYMENT_SECRET, finalCltvDelta: 19 }) }),
  });
  const outcome = await r.run();
  expect(outcome).toEqual({ executionId: r.executionId, exit: 5, step: 'CLTV_DELTA_UNSAFE' });
  expect(r.node.count('sendOnRoute')).toBe(0);
  expect(r.node.named('cancelUnpaidInvoice').map(call => call.args)).toEqual([[HASH, labelOf(r.executionId)]]);
  expect(rowOf(r.path, r.executionId).status).toBe('CANCELLED');
  expect(reservationState(r.path, r.executionId).state).toBe('RELEASED');
});

it('CP-030/B4 a SUCCEEDED record without any settled HTLC is not a single-path success: INVARIANT_BREACH, exit 8', async () => {
  const r = await prepare('zero-htlcs', { script: () => ({ send: c => { c.onDispatched?.(); return Promise.resolve(succeeded(ROUTE_FEE, 0)); } }) });
  const outcome = await r.run();
  expect(outcome.exit).toBe(8);
  expect(r.alerts).toEqual([{ kind: 'INVARIANT_BREACH', executionId: r.executionId, code: 'SINGLE_PATH_UNAVAILABLE' }]);
});

it('CP-030/B5 a FAILED answer without a write report still passes IN_FLIGHT before VERIFIED_FAILURE (the node had the payment)', async () => {
  const r = await prepare('failed-no-dispatch', { script: () => ({ send: () => Promise.resolve(failed('FAILURE_REASON_NO_ROUTE')) }) });
  const outcome = await r.run();
  expect(outcome.exit).toBe(5);
  // SPEC §8.2: VERIFIED_FAILURE is reached from IN_FLIGHT (the REBALANCE_SENT point), never straight from SUBMITTING by a worker.
  expect(transitionsOf(r.path, r.executionId)).toEqual(['PREFLIGHT>SUBMITTING', 'SUBMITTING>IN_FLIGHT', 'IN_FLIGHT>VERIFIED_FAILURE']);
});

for (const [name, cancel] of [
  ['answers NOT_FOUND', () => Promise.resolve('NOT_FOUND' as const)],
  ['fails', () => Promise.reject(new Error('delinvoice answer lost'))],
] as const) {
  describe(`invoice cancel ${name}`, () => {
    let r: Awaited<ReturnType<typeof prepare>>;
    let database: ExecDatabase | undefined;
    let preparedAt: number, prepMs: number;
    const close = (): void => { const owned = database; database = undefined; owned?.close(); };
    beforeAll(async () => {
      preparedAt = performance.now();
      r = await prepare(`cancel-${String(name.length)}`, {
        script: () => ({ send: c => { c.onDispatched?.(); return Promise.resolve(failed('FAILURE_REASON_NO_ROUTE')); }, cancel }),
      });
      database = r.p.openDatabase(r.path, { readOnly: false });
      prepMs = performance.now() - preparedAt;
    }, 30_000);
    afterAll(close);
    it(`CP-030/B5 a failure whose invoice cancel ${name} is not closed: UNKNOWN, exit 7, reservation held`, async () => {
      const started = performance.now();
      onTestFinished(close);
      if (database === undefined) throw new Error('invoice cancellation fixture is not open');
      try {
        const outcome = await r.run(r.node, database);
        expect(outcome).toEqual({ executionId: r.executionId, exit: 7, step: 'OUTCOME_UNKNOWN' });
        expect(rowOf(r.path, r.executionId).status).toBe('UNKNOWN');
        expect(reservationState(r.path, r.executionId).state).toBe('HELD');
      } finally {
        close();
        console.log(JSON.stringify({ case: `invoice-cancel-${name}`, prepMs, caseMs: performance.now() - started, totalMs: performance.now() - preparedAt }));
      }
    });
  });
}

it('CP-030/B7 a re-claimed PREFLIGHT row that already holds a payment hash never gets a second hash and is not left in PREFLIGHT', async () => {
  const stored = 'ab'.repeat(32);
  const r = await prepare('reclaimed-hash');
  // The first worker persisted its hash (and created its invoice), died, and the row was re-claimed (SPEC §8.3 crash point after P5).
  exec(r.path, "UPDATE executions SET payment_hash = ?, fence_epoch = 5, worker_id = 'worker-a' WHERE id = ?", stored, r.executionId);
  const outcome = await r.run(r.node, undefined, { fenceEpoch: 5n });
  const row = rowOf(r.path, r.executionId);
  expect(row.payment_hash).toBe(stored);
  expect(r.node.count('createInvoice')).toBe(0);
  expect(row.status).not.toBe('PREFLIGHT');
  const sends = r.node.named('sendOnRoute');
  if (sends.length === 0) {
    // Closed: the stored invoice is cancelled and nothing was sent (INV-05).
    expect(outcome).toEqual({ executionId: r.executionId, exit: 5, step: expect.any(String) as string });
    expect(r.node.named('cancelUnpaidInvoice').map(call => call.args)).toEqual([[stored, labelOf(r.executionId)]]);
    expect(row.status).toBe('CANCELLED');
    expect(reservationState(r.path, r.executionId).state).toBe('RELEASED');
  } else {
    // Reused: one send under the stored hash.
    expect(sends).toHaveLength(1);
    expect(sends[0]?.args[1]).toBe(stored);
  }
});

it('CP-030/B7 a lease taken over while a failing invoice call is pending: the worker stops without closing that invoice (no node call after the lease is lost)', async () => {
  const r = await prepare('takeover-invoice-fails', {
    script: ({ path, executionId }) => ({
      invoice: () => {
        exec(path, "UPDATE executions SET fence_epoch = fence_epoch + 1, worker_id = 'worker-b' WHERE id = ?", executionId);
        return Promise.reject(new Error('invoice creation answer lost'));
      },
    }),
  });
  const outcome = await r.run();
  // INV-18 / SPEC §6.4: zero affected rows means the lease is lost; the worker makes no further node call, the holder decides.
  expect(outcome).toEqual({ executionId: r.executionId, exit: 5, step: 'lease-lost' });
  expect(r.node.names()).toEqual(['listChannels', 'createInvoice']);
  expect(rowOf(r.path, r.executionId).worker_id).toBe('worker-b');
});

it('CP-032/B1 a lease lost while the invoice cancel after a FAILED answer is pending: an "already paid" answer leads to no further node call', async () => {
  const r = await prepare('lease-cancel-paid', {
    script: ({ path, executionId }) => ({
      send: c => { c.onDispatched?.(); return Promise.resolve(failed('FAILURE_REASON_TIMEOUT')); },
      cancel: () => {
        exec(path, "UPDATE executions SET status = 'UNKNOWN', fence_epoch = fence_epoch + 1, worker_id = 'reconciler' WHERE id = ?", executionId);
        return Promise.resolve('ALREADY_PAID');
      },
      observe: () => Promise.resolve(succeeded(ROUTE_FEE, 1, true, '246290604752896')),
    }),
  });
  const outcome = await r.run();
  // INV-18: after the lease is lost the worker stops; the reconciler, now holding the row, reads the payment.
  expect(outcome).toEqual({ executionId: r.executionId, exit: 7, step: 'lease-lost' });
  expect(r.node.count('observePayment')).toBe(0);
  expect(rowOf(r.path, r.executionId).worker_id).toBe('reconciler');
});

it('CP-030/B7 a re-claimed PREFLIGHT row whose stored invoice is already paid follows the success path, never CANCELLED and never re-sent', async () => {
  const stored = 'ab'.repeat(32);
  const r = await prepare('reclaimed-paid', {
    script: () => ({ cancel: () => Promise.resolve('ALREADY_PAID'), send: () => never(), observe: () => Promise.resolve(succeeded(ROUTE_FEE, 1, true, '246290604752896')) }),
  });
  exec(r.path, "UPDATE executions SET payment_hash = ?, fence_epoch = 5, worker_id = 'worker-a' WHERE id = ?", stored, r.executionId);
  await r.run(r.node, undefined, { fenceEpoch: 5n });
  // SPEC §8.2: our settled invoice is evidence that the money moved under this hash; INV-19: nothing is sent again.
  const row = rowOf(r.path, r.executionId);
  expect(row.status).toBe('VERIFIED_SUCCESS');
  expect(row.payment_hash).toBe(stored);
  expect(row.actual_fee_msat).toBe(ROUTE_FEE);
  expect(r.node.count('sendOnRoute')).toBe(0);
  expect(r.node.count('createInvoice')).toBe(0);
});
