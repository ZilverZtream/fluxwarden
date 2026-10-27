// ARC-044-002 / SPEC8.4 / INV-13: a stale recovery worker must stop on
// fencing loss without aborting unrelated lapsed work. All state changes
// below use real public SQLite transitions; approval and lease expiry are real.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, expect, it } from 'vitest';
import type { Database } from '../../src/persistence/index.js';
import type { ExecutionPolicy, VerifiedApproval } from '../../src/core/execution.js';
import type { FakeServer } from '../fakes/https.js';
import { methodsOf } from '../fakes/cln/rebalance-node.js';
import { demo, plan, rec, type Demo } from '../helpers/cpw-cli.js';
import { repoRoot } from '../helpers/cli.js';
import { reservationState } from '../helpers/cp030-execution.js';
import { publishSentinel, sentinelRoot } from '../helpers/output.js';
import { registerMoneySafetyCredentials } from '../helpers/public-money-safety.js';

const servers: FakeServer[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });
const built = async <T>(path: string): Promise<T> => await import(pathToFileURL(join(repoRoot, 'dist', path)).href) as T;

function barrier() {
  let enter!: () => void, release!: () => void;
  const entered = new Promise<void>(resolve => { enter = resolve; });
  const released = new Promise<void>(resolve => { release = resolve; });
  return { entered, release, wait: async () => { enter(); await released; } };
}

async function untilDatabaseTime(db: Database, timestamp: number): Promise<void> {
  const deadline = performance.now() + 20_000;
  while (db.now() <= timestamp) {
    if (performance.now() >= deadline) throw new Error('PREMISE_INVALID: public database clock did not reach the recorded expiry');
    await new Promise(resolve => setTimeout(resolve, Math.min(25, Math.max(1, timestamp - db.now() + 1))));
  }
}

async function approved(d: Demo, db: Database) {
  const proposalId = String((await plan(d))['proposal_id']);
  const run = await d.run(['--json', 'liquidity', 'approve', proposalId, '--key', d.key.keyFile,
    '--max-fee-msat', '300000', '--max-cltv-delta', '144', '--expires-in', '10s']);
  expect(run.status).toBe(0);
  const stored = db.proposals.find(proposalId.slice('prop_'.length));
  if (stored === null || stored.sourceChannelKey === null || stored.targetChannelKey === null) throw new Error('valid public proposal fixture unavailable');
  const context = { keys: [{ keyId: d.key.keyId, publicKey: d.key.publicKey }], now: db.now(),
    proposal: { id: stored.id, nodePubkey: stored.nodePubkey, sourceChannelKey: stored.sourceChannelKey,
      targetChannelKey: stored.targetChannelKey, principalMsat: stored.principalMsat, maxFeeMsat: stored.maxFeeMsat,
      maxFeePpm: stored.maxFeePpm, exemptFeeMsat: 5_000n, maxCltvDelta: stored.maxCltvDelta,
      policySha256: stored.policySha256, expiresAt: stored.expiresAt },
    policy: { sha256: stored.policySha256, maxFeeMsat: 300_000n, maxCltvDelta: 144,
      approvalMaxTtlSeconds: 900, maxSnapshotAgeSeconds: 60 } };
  const verifier = await built<{ verifiedStoredApproval(context: unknown, store: unknown): VerifiedApproval }>('approval/verify.js');
  const approval = verifier.verifiedStoredApproval(context, db.commandData.approvals);
  const policy: ExecutionPolicy = { sha256: stored.policySha256, network: 'regtest', maxFeeMsat: 300_000n,
    maxFeePpm: 2_500n, exemptFeeMsat: 5_000n, maxCltvDelta: 144, minChannelReserveMsat: 50_000_000n,
    budget: { msat: 2_000_000n, periodMs: 86_400_000 }, cooldownAfterFailureMs: 3_600_000,
    cooldownAfterSuccessMs: 1_800_000, maxInFlight: 1, maxSnapshotAgeMs: 60_000 };
  return { approval, policy, nodeId: stored.nodeId };
}

for (const branch of ['SETTLED', 'ALREADY_PAID'] as const) {
  it(`CP-044/ARC-044-002 preflight recovery loses its fence before ${branch} attribution and continues other lapsed work`, async () => {
    const d = await demo(servers);
    registerMoneySafetyCredentials([d.key.keyFile, d.cln.runeFile]);
    const p = await built<typeof import('../../src/persistence/index.js')>('persistence/index.js');
    const recovery = await built<typeof import('../../src/executor/preflight.js')>('executor/preflight.js');
    const claims = await built<typeof import('../../src/executor/claim.js')>('executor/claim.js');
    const { loadConfig } = await built<typeof import('../../src/config/config.js')>('config/config.js');
    const { resolveConnection } = await built<typeof import('../../src/cli/connect.js')>('cli/connect.js');
    const { handshake } = await built<typeof import('../../src/commands/handshake.js')>('commands/handshake.js');
    const { controller } = await built<typeof import('../../src/commands/workflow.js')>('commands/workflow.js');
    const a = p.openDatabase(d.database, { readOnly: false }), b = p.openDatabase(d.database, { readOnly: false });
    const gate = barrier();
    let pass: Promise<unknown> | undefined;
    try {
      const first = await approved(d, a), config = loadConfig(d.config), node = config.nodes[0];
      if (node === undefined) throw new Error('public configured node unavailable');
      const session = await handshake(a, node, resolveConnection(node, {}, {}));
      const payment = await controller(node, config, session, a);
      const ready = await recovery.prepareExecution({ db: a, adapter: payment.adapter, workerId: 'original-worker', leaseMs: 10_000 },
        { approval: first.approval, policy: first.policy, approvalKeyIds: [d.key.keyId] });
      expect(ready.kind).toBe('READY');
      if (ready.kind !== 'READY') throw new Error('valid public preflight fixture refused');
      const preimage = randomBytes(32), hash = createHash('sha256').update(preimage).digest('hex');
      publishSentinel(sentinelRoot(), `arc044-preimage-${randomUUID()}.bin`, preimage);
      a.executions.transition(ready.executionId, ready.fenceEpoch, 'PREFLIGHT', 'PREFLIGHT', { paymentHash: hash, leaseMs: 1_000 });
      const invoice = await payment.adapter.createInvoice(100_000_000n, preimage, `fluxwarden-${ready.executionId}`, 300);
      expect(invoice.paymentHash).toBe(hash);
      const second = await approved(d, a);
      const unrelated = claims.claimExecution(a, { approval: second.approval, policy: second.policy,
        approvalKeyIds: [d.key.keyId], workerId: 'unrelated-worker', leaseMs: 1_000 });
      expect(unrelated.ok).toBe(true);
      if (!unrelated.ok) throw new Error('valid unrelated public claim fixture refused');
      // The original public recovery contract selects lapsed authority. These
      // signatures were verified while valid; their actual expiries now pass.
      await untilDatabaseTime(a, Math.max(first.approval.expiresAt, second.approval.expiresAt));
      const candidates = a.executions.lapsedClaims();
      expect(candidates).toContain(ready.executionId);
      expect(candidates).toContain(unrelated.executionId);
      expect(candidates.indexOf(ready.executionId)).toBeLessThan(candidates.indexOf(unrelated.executionId));
      const originalMethods = methodsOf(d.cln.fake);
      const paidRecord = d.cln.state.invoices.get(hash);
      if (paidRecord === undefined) throw new Error('actual public invoice fixture missing');
      const adapter = {
        invoiceState: async (asked: string) => {
          if (branch === 'SETTLED' && asked === hash) await gate.wait();
          return await payment.adapter.invoiceState(asked);
        },
        cancelUnpaidInvoice: async (asked: string, label: string) => {
          if (branch === 'ALREADY_PAID' && asked === hash) await gate.wait();
          return await payment.adapter.cancelUnpaidInvoice(asked, label);
        },
      };
      pass = recovery.recoverPreflight({ db: a, adapters: new Map([[first.nodeId, adapter]]), workerId: 'stale-recovery', leaseMs: 1_000 });
      const finished = pass.then(report => ({ report }), (error: unknown) => ({ error }));
      await Promise.race([gate.entered, finished.then(() => { throw new Error('PREMISE_INVALID: recovery finished before its ordinary node await'); })]);
      const held = a.executions.view(ready.executionId);
      if (held?.leaseExpiresAt === null || held === null) throw new Error('public recovery lease unavailable');
      await untilDatabaseTime(b, held.leaseExpiresAt);
      const winner = b.executions.takeOver(ready.executionId, 'winning-recovery', 60_000);
      if (winner === null) throw new Error('PREMISE_INVALID: real expired-lease takeover refused');
      paidRecord.status = 'paid';
      b.executions.recordPaidIntent(ready.executionId, winner.fenceEpoch, hash);
      const winnerView = b.executions.view(ready.executionId), winnerEvents = b.executions.events(ready.executionId);
      const winnerReservation = reservationState(d.database, ready.executionId);
      const journals = b.ledger.journals();
      expect(winnerView?.status).toBe('UNKNOWN');
      expect((await d.run(['--json', 'ledger', 'verify'])).status).toBe(0);
      gate.release();
      const outcome = await finished;
      const failure = 'error' in outcome ? outcome.error : null;
      const code = typeof failure === 'object' && failure !== null && 'code' in failure ? failure.code : failure === null ? null : 'unexpected-error';
      expect.soft(code).toBeNull();
      expect.soft(a.executions.view(unrelated.executionId)?.status).toBe('CANCELLED');
      expect.soft(a.executions.view(ready.executionId)).toEqual(winnerView);
      expect.soft(a.executions.events(ready.executionId)).toEqual(winnerEvents);
      expect.soft(reservationState(d.database, ready.executionId)).toEqual(winnerReservation);
      expect.soft(reservationState(d.database, unrelated.executionId).state).toBe('RELEASED');
      expect.soft(a.ledger.journals()).toEqual(journals);
      expect.soft(d.cln.state.sent).toEqual([]);
      expect(methodsOf(d.cln.fake).filter(method => method === 'invoice')).toHaveLength(originalMethods.filter(method => method === 'invoice').length);
      expect(rec(JSON.parse((await d.run(['--json', 'ledger', 'verify'])).stdout))['error']).toBeNull();
    } finally { gate.release(); await pass?.catch(() => undefined); a.close(); b.close(); }
  });
}
