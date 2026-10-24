// D29 before-edit oracle clarification, 2026-10-24. Desired outcomes derive from
// SPEC 8.3/8.4/8.7, INV-04/08/14 and the pinned native protocols, not the audit's
// intentionally inverted DEEP witnesses. All transports are synthetic regtest.
import { afterEach, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { S, T } from '../fakes/cln/rebalance-node.js';
import { b64, invoice, payment } from '../fakes/lnd/responses.js';
import { demo, plan, approve, rows, rec } from '../helpers/cpw-cli.js';
import { prepare } from '../helpers/cp030-dispatch.js';
import { fakeChannel } from '../fakes/preflight-node.js';
import { IN_PEER, OUT_PEER } from '../helpers/cp028-executor.js';
import { exec, loadLndExecute, loadReconciler, reservationState, rowOf, type ExecutionAdapter } from '../helpers/cp030-execution.js';
import { prepareMoneySafetyAlertKey, registerMoneySafetyCredentials } from '../helpers/public-money-safety.js';

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

async function approvedDemo() {
  // startRebalanceCln declares its rune before writing; generateKey authorizes
  // the exact output before spawning keys generate (existing capture adapters).
  const d = await demo(open);
  registerMoneySafetyCredentials([d.cln.runeFile, d.key.keyFile]);
  await prepareMoneySafetyAlertKey(d.database);
  const proposal = await plan(d);
  const id = String(proposal['proposal_id']);
  await approve(d, id);
  return { d, id };
}

it('CP-030/DEEP-01 newest target receivable zero refuses signed CLI dispatch before invoice creation or send', async () => {
  const { d, id } = await approvedDemo();
  const respond = d.cln.fake.result;
  let routeFinished = false, newestSeen = false;
  d.cln.fake.result = (context, behavior, value) => {
    if (context.request.url === '/v1/askrene-remove-layer') routeFinished = true;
    if (routeFinished && context.request.url === '/v1/listpeerchannels') {
      const body = rec(value);
      value = { ...body, channels: (body['channels'] as Record<string, unknown>[]).map(channel => {
        if (channel['short_channel_id'] !== T) return channel;
        newestSeen = true;
        // CLN v26.06.9 listpeerchannels.json: receivable_msat is node-reported.
        return { ...channel, receivable_msat: 0 };
      }) };
    }
    respond(context, behavior, value);
  };
  const run = await d.run(['--json', 'actions', 'execute', id, '--require-regtest']);
  expect(newestSeen, 'fault is reached only after route assessment').toBe(true);
  expect.soft(run.status).toBe(5);
  expect.soft(d.cln.fake.calls.filter(call => call.method === 'invoice').length).toBe(0);
  expect.soft(d.cln.state.sent).toHaveLength(0);
  expect.soft(rows(d.database, 'SELECT status FROM executions')).toEqual([{ status: 'CANCELLED' }]);
});

for (const [endpoint, channelKey, change] of [
  ['source disconnected', S, { peer_connected: false }],
  ['target disconnected', T, { peer_connected: false }],
  ['source closing', S, { state: 'CHANNELD_SHUTTING_DOWN' }],
  ['target closing', T, { state: 'CHANNELD_SHUTTING_DOWN' }],
] as const) {
  it(`CP-030/DEEP-01 newest ${endpoint} refuses signed CLI dispatch before invoice creation or send`, async () => {
    const { d, id } = await approvedDemo();
    const respond = d.cln.fake.result;
    let routeFinished = false, newestSeen = false;
    d.cln.fake.result = (context, behavior, value) => {
      if (context.request.url === '/v1/askrene-remove-layer') routeFinished = true;
      if (routeFinished && context.request.url === '/v1/listpeerchannels') {
        const body = rec(value);
        // Native listpeerchannels.json peer_connected and state are distinct:
        // disconnecting a normal channel and cooperative shutdown both exclude it.
        value = { ...body, channels: (body['channels'] as Record<string, unknown>[]).map(channel => {
          if (channel['short_channel_id'] !== channelKey) return channel;
          newestSeen = true;
          return { ...channel, ...change };
        }) };
      }
      respond(context, behavior, value);
    };
    const run = await d.run(['--json', 'actions', 'execute', id, '--require-regtest']);
    expect(newestSeen).toBe(true);
    expect.soft(run.status).toBe(5);
    expect.soft(d.cln.fake.calls.filter(call => call.method === 'invoice').length).toBe(0);
    expect.soft(d.cln.state.sent).toHaveLength(0);
    expect.soft(rows(d.database, 'SELECT status FROM executions')).toEqual([{ status: 'CANCELLED' }]);
  });
}

it('CP-030/DEEP-01 latest source reserve floor remains enforced alongside receiver admission', async () => {
  // INV-14: 120m - (100m principal + 150k fee) is below the 50m floor.
  const r = await prepare('reaudit-source-floor', { script: ({ base }) => ({ before: () => [
    fakeChannel(base.sourceKey, OUT_PEER, { spendableMsat: 120_000_000n }),
    fakeChannel(base.targetKey, IN_PEER),
  ] }) });
  expect(await r.run()).toMatchObject({ exit: 5, step: 'RESERVE_FLOOR' });
  expect(r.node.count('createInvoice')).toBe(0);
  expect(r.node.count('sendOnRoute')).toBe(0);
  expect(rowOf(r.path, r.executionId).status).toBe('CANCELLED');
  expect(reservationState(r.path, r.executionId).state).toBe('RELEASED');
});

it('CP-024/DEEP-02 lost successful layer creation and failed immediate removal retain durable ownership for fresh CLI recovery', async () => {
  const { d, id } = await approvedDemo();
  // Another assessment's layer is native state, with no acquisition by this DB.
  const foreign = 'fluxwarden-independent-assessment';
  d.cln.state.layers.layers.set(foreign, { disabledNodes: [], channelUpdates: [] });
  const respond = d.cln.fake.result;
  let owned: string | undefined;
  d.cln.fake.result = (context, behavior, value) => {
    if (context.request.url === '/v1/askrene-create-layer' && owned === undefined) {
      // askrene.c json_create_layer mutates before returning its RPC result.
      // RFC9112 9.6: lose the result after native acquisition, then lose cleanup.
      owned = String(context.params['layer']);
      d.cln.state.unreachable = true;
      d.cln.fake.reset(context, 'connection-reset');
      return;
    }
    respond(context, behavior, value);
  };
  const run = await d.run(['--json', 'actions', 'execute', id, '--require-regtest']);
  if (owned === undefined) throw new Error('synthetic native layer-create fault was not reached');
  const acquired = owned;
  expect(run.status).not.toBe(0);
  expect(d.cln.state.layers.layers.has(acquired)).toBe(true);
  expect(d.cln.state.sent).toHaveLength(0);
  expect(d.cln.state.invoices.size).toBe(0);
  expect.soft(rows(d.database, 'SELECT * FROM routing_layers').some(row => Object.values(row).includes(acquired)),
    'unacknowledged acquisition remains durably discoverable after CLI exit').toBe(true);
  const ownedRemovals = () => d.cln.fake.calls.filter(call => call.method === 'askrene-remove-layer' && call.params['layer'] === acquired).length;
  const beforeRecoveryRemovals = ownedRemovals();
  d.cln.state.unreachable = false;
  const recovered = await d.run(['--json', 'reconcile', '--node', 'cln-m', '--since', '1h']);
  expect.soft(recovered.status).toBe(0);
  expect.soft(d.cln.state.layers.layers.has(acquired), 'fresh process removes exactly the acquired layer').toBe(false);
  expect.soft(ownedRemovals(), 'one healthy cleanup attempt resolves the pending owned acquisition').toBe(beforeRecoveryRemovals + 1);
  expect(d.cln.state.layers.layers.has(foreign)).toBe(true);
  const removed = d.cln.fake.calls.filter(call => call.method === 'askrene-remove-layer').map(call => call.params['layer']);
  expect(removed).not.toContain(foreign);
  await d.run(['--json', 'reconcile', '--node', 'cln-m', '--since', '1h']);
  expect.soft(ownedRemovals(), 'repeated recovery does not remove an already discharged acquisition').toBe(beforeRecoveryRemovals + 1);
  expect(d.cln.state.sent).toHaveLength(0);
});

it('CP-031/DEEP-03-06 failed terminal incoming HTLC never credits its channel in signed CLI or later recovery', async () => {
  const { d, id } = await approvedDemo();
  const respond = d.cln.fake.result;
  d.cln.fake.result = (context, behavior, value) => {
    if (d.cln.state.sent.length > 0 && context.request.url === '/v1/listpeerchannels') {
      const body = rec(value);
      // The actual credited channel closed; its history is no longer retained.
      value = { ...body, channels: (body['channels'] as Record<string, unknown>[]).filter(channel => channel['short_channel_id'] !== T) };
    }
    if (d.cln.state.sent.length > 0 && context.request.url === '/v1/listhtlcs') {
      const body = rec(value);
      value = { ...body, htlcs: (body['htlcs'] as Record<string, unknown>[]).map(htlc => ({ ...htlc, short_channel_id: S })) };
    }
    respond(context, behavior, value);
  };
  // CLN v26.06.9 lightningd/peer_htlcs.c remove_htlc_in/update_in_htlc/
  // peer_sending_revocation: SENT_REMOVE_ACK_REVOCATION occurs for failed AND
  // fulfilled HTLCs. listhtlcs.json exposes no success discriminator/preimage.
  // The paid invoice proves receipt somewhere, not that this failed HTLC paid.
  const run = await d.run(['--json', 'actions', 'execute', id, '--require-regtest']);
  // Reading the failed-history fixture is optional: independently conclusive
  // native credit may be consulted first. The journal outcome is mandatory.
  expect(run.status).toBe(9);
  expect(d.cln.state.sent).toHaveLength(1);
  const settledLines = () => rows(d.database, `SELECT l.account_code,l.debit_msat,l.credit_msat FROM ledger_lines l
    JOIN ledger_journals j ON j.id=l.journal_id WHERE j.event_type='REBALANCE_SETTLED' ORDER BY l.account_code`);
  const original = settledLines();
  expect.soft(original).toEqual([
    { account_code: 'clearing:inflight', debit_msat: 0, credit_msat: 100_202_101 },
    { account_code: 'clearing:unassigned', debit_msat: 100_000_000, credit_msat: 0 },
    { account_code: 'expense:routing_fees', debit_msat: 202_101, credit_msat: 0 },
  ]);
  expect.soft(rows(d.database, 'SELECT status FROM executions')).toEqual([{ status: 'VERIFIED_SUCCESS' }]);
  await d.run(['--json', 'reconcile', '--node', 'cln-m', '--since', '1h']);
  expect.soft(settledLines(), 'original journal stays append-only').toEqual(original);
  expect.soft(rows(d.database, `SELECT account_code,SUM(debit_msat-credit_msat) AS balance FROM ledger_lines
    WHERE account_code='clearing:unassigned' GROUP BY account_code`)).toEqual([{ account_code: 'clearing:unassigned', balance: 100_000_000 }]);
  expect.soft(rows(d.database, `SELECT l.account_code FROM ledger_lines l JOIN ledger_journals j ON j.id=l.journal_id
    WHERE j.event_type='REBALANCE_SETTLED' AND l.account_code=? AND l.debit_msat>0`, `channel:cln-m:${S}:local`)).toEqual([]);
  expect(d.cln.state.sent).toHaveLength(1);
});

it('CP-030/DEEP-05 stalled nonempty LND history remains ambiguous and HELD until adequate terminal payer evidence', async () => {
  const r = await prepare('reaudit-lnd-stalled', { script: () => ({ send: context => {
    context.onDispatched?.(); return Promise.resolve({ kind: 'IN_FLIGHT' });
  } }) });
  expect((await r.run()).exit).toBe(7);
  const hash = rowOf(r.path, r.executionId).payment_hash;
  if (hash === null) throw new Error('synthetic IN_FLIGHT execution has no hash');
  exec(r.path, 'UPDATE executions SET submitted_at=submitted_at-180000 WHERE id=?', r.executionId);
  const { LndExecutionAdapter } = await loadLndExecute();
  let terminal = false;
  const reads: string[] = [];
  const adapter = new LndExecutionAdapter({
    call: async (method, path) => {
      await Promise.resolve();
      reads.push(`${method} ${path}`);
      if (path.startsWith('/v1/payments?')) return terminal
        ? { payments: [payment({ payment_hash: hash, payment_index: '2', status: 'FAILED', failure_reason: 'FAILURE_REASON_NO_ROUTE' })], first_index_offset: '2', last_index_offset: '2' }
        // LND v0.21.4-beta lightning.proto ListPaymentsResponse L4100-4114:
        // last_index_offset must permit forward seeking. A repeated nonempty
        // page is an incomplete transport/protocol observation, not absence.
        : { payments: [payment({ payment_hash: 'ab'.repeat(32), payment_index: '1' })], first_index_offset: '1', last_index_offset: '0' };
      if (path === '/v2/invoices/cancel') return {};
      if (path === `/v1/invoice/${hash}`) return invoice({ r_hash: b64(hash), state: 'CANCELED' });
      throw new Error('unexpected synthetic LND endpoint');
    },
    stream: () => Promise.reject(new Error('sweep uses paginated read-only history')),
  }, { trackDeadlineMs: 1_000 });
  expect.soft(await adapter.observePayment(hash, 'sweep')).toMatchObject({ kind: 'AMBIGUOUS' });
  const { reconcile } = await loadReconciler();
  const db = r.p.openDatabase(r.path, { readOnly: false });
  try {
    // The older loadLndExecute helper types only its payment-facing methods;
    // recovery consumes the complete public execution-adapter port.
    const recover = () => reconcile({ db, adapters: new Map([[r.base.nodeId, adapter as ExecutionAdapter]]), workerId: 'reaudit-stalled',
      leaseMs: 60_000, notFoundWindowMs: 120_000, escalateAfterMs: 3_600_000, confirmIntervalMs: 1_000,
      alert: () => undefined }, { startup: true });
    expect.soft((await recover()).exit).toBe(7);
    expect.soft(rowOf(r.path, r.executionId)).toMatchObject({ status: 'UNKNOWN', error_code: null });
    expect.soft(reservationState(r.path, r.executionId)).toEqual({ state: 'HELD', consumed: null });
    terminal = true;
    const readsBeforeTerminal = reads.length;
    expect.soft((await recover()).exit).toBe(0);
    expect.soft(rowOf(r.path, r.executionId)).toMatchObject({ status: 'VERIFIED_FAILURE', error_code: 'FAILURE_REASON_NO_ROUTE' });
    expect.soft(reservationState(r.path, r.executionId).state).toBe('RELEASED');
    expect.soft(reads.length, 'eventual failure is decided by newly adequate evidence').toBeGreaterThan(readsBeforeTerminal);
    expect(reads.some(read => read.includes('/v1/payments?'))).toBe(true);
    expect(reads.every(read => !read.includes('/v2/router/route/send') && !read.endsWith('/v1/invoices'))).toBe(true);
  } finally { db.close(); }
});
