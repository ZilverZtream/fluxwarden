// Oracle: 2026-10-26 audit F02: finite safe-integer age, 0 <= age <= maxAge,
// checked after awaited work at both execution boundaries (SECURITY INV-06).
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { expect, it } from 'vitest';
import { FakePreflightNode, circularRoute, fakeChannel } from '../fakes/preflight-node.js';
import { ScriptedExecutionNode } from '../fakes/execution-node.js';
import { APPROVAL_KEYS, IN_PEER, NODE_PUBKEY, OUT_PEER, dbNow, loadPersistence, loadPreflight,
  policyFor, scratchDb, seedBase, seedProposal } from '../helpers/cp028-executor.js';
import { loadDispatch, loadExecutionCore, reservationState, rowOf, seedExecution } from '../helpers/cp030-execution.js';
import { publishSentinel, sentinelRoot } from '../helpers/output.js';

for (const side of ['source', 'target'] as const) {
  for (const offset of [1_000, Number.NaN, Number.POSITIVE_INFINITY, 0.5, -0.5]) {
    it(`CP-044/F02 preflight rejects ${side} observation with invalid age (${String(offset)})`, async () => {
      const p = await loadPersistence(), path = scratchDb('cp044-age');
      const base = seedBase(p, path), approval = seedProposal(base);
      const db = p.openDatabase(path, { readOnly: false });
      const now = dbNow(path);
      // Public injected database clock: no sleeps or dependence on scheduler timing.
      const clockDb = { ...db, now: () => now };
      const node = new FakePreflightNode(base.sourceKey, base.targetKey, { channels: () => [
        fakeChannel(base.sourceKey, OUT_PEER, { observedAt: now + (side === 'source' ? offset : 0) }),
        fakeChannel(base.targetKey, IN_PEER, { observedAt: now + (side === 'target' ? offset : 0) }),
      ] });
      try {
        const { prepareExecution } = await loadPreflight();
        const result = await prepareExecution({ db: clockDb, adapter: node, workerId: 'clock', leaseMs: 60_000 },
          { approval, policy: policyFor(base), approvalKeyIds: APPROVAL_KEYS });
        expect.soft(result).toMatchObject({ kind: 'CANCELLED', exit: 5, step: 'STALE_SNAPSHOT' });
        expect.soft(node.calls).not.toContain('findCircularRoute');
        expect(node.mutatingCalls()).toEqual([]);
      } finally { db.close(); }
    });
  }
}

for (const age of [0, 60_000]) {
  it(`CP-044/F02 preflight permits the inclusive valid age boundary ${String(age)}ms`, async () => {
    const p = await loadPersistence(), path = scratchDb('cp044-age-boundary');
    const base = seedBase(p, path), approval = seedProposal(base), db = p.openDatabase(path, { readOnly: false });
    const now = dbNow(path);
    const clockDb = { ...db, now: () => now };
    const node = new FakePreflightNode(base.sourceKey, base.targetKey, { channels: () => [
      fakeChannel(base.sourceKey, OUT_PEER, { observedAt: now - age }),
      fakeChannel(base.targetKey, IN_PEER, { observedAt: now - age }),
    ] });
    try {
      const { prepareExecution } = await loadPreflight();
      const result = await prepareExecution({ db: clockDb, adapter: node, workerId: 'clock', leaseMs: 60_000 },
        { approval, policy: policyFor(base), approvalKeyIds: APPROVAL_KEYS });
      expect(result.kind).toBe('READY');
      expect(node.mutatingCalls()).toEqual([]);
    } finally { db.close(); }
  });
}

it('CP-044/F02 preflight rechecks negative age after route discovery awaits', async () => {
  const p = await loadPersistence(), path = scratchDb('cp044-age-route');
  const base = seedBase(p, path), approval = seedProposal(base), db = p.openDatabase(path, { readOnly: false });
  let now = dbNow(path);
  const clockDb = { ...db, now: () => now };
  const observedAt = now;
  const node = new FakePreflightNode(base.sourceKey, base.targetKey, {
    channels: () => [fakeChannel(base.sourceKey, OUT_PEER, { observedAt }), fakeChannel(base.targetKey, IN_PEER, { observedAt })],
    during: { findCircularRoute: () => { now -= 1_000; } },
  });
  try {
    const { prepareExecution } = await loadPreflight();
    const result = await prepareExecution({ db: clockDb, adapter: node, workerId: 'clock', leaseMs: 60_000 },
      { approval, policy: policyFor(base), approvalKeyIds: APPROVAL_KEYS });
    expect(result).toMatchObject({ kind: 'CANCELLED', exit: 5, step: 'STALE_SNAPSHOT' });
    expect(node.mutatingCalls()).toEqual([]);
  } finally { db.close(); }
});

for (const stage of ['baseline', 'invoice-await'] as const) {
  for (const offset of stage === 'baseline' ? [1_000, Number.NaN, Number.POSITIVE_INFINITY, 0.5, -0.5, 0, -60_000, -60_001] : [1_000]) {
    const valid = stage === 'baseline' && (offset === 0 || offset === -60_000);
    it(`CP-044/F02 dispatch ${valid ? 'permits inclusive valid' : 'rejects invalid'} age (${String(-offset)}) at ${stage}`, async () => {
      const p = await loadPersistence(), path = scratchDb('cp044-dispatch-age');
      const base = seedBase(p, path), route = circularRoute(base.sourceKey, base.targetKey, 150_000n, 80);
      const seeded = seedExecution(base, { status: 'PREFLIGHT', route, plannedFeeMsat: 150_000n });
      const policy = policyFor(base), db = p.openDatabase(path, { readOnly: false });
      let now = dbNow(path);
      const clockDb = { ...db, now: () => now };
      const observedAt = now + (stage === 'baseline' ? offset : 0);
      const preimage = randomBytes(32), paymentSecret = randomBytes(32);
      publishSentinel(sentinelRoot(), `cp044-preimage-${randomUUID()}.bin`, preimage);
      publishSentinel(sentinelRoot(), `cp044-payment-secret-${randomUUID()}.bin`, paymentSecret);
      const node = new ScriptedExecutionNode({
        before: () => [fakeChannel(base.sourceKey, OUT_PEER, { observedAt }), fakeChannel(base.targetKey, IN_PEER, { observedAt })],
        invoice: (_amount, bytes) => {
          if (stage === 'invoice-await') now -= offset;
          return Promise.resolve({ paymentHash: createHash('sha256').update(bytes).digest('hex'),
            paymentSecret: paymentSecret.toString('hex'), finalCltvDelta: 18 });
        },
        send: () => Promise.resolve({ kind: 'IN_FLIGHT' }),
      });
      const { approveRoute, proveRegtest } = await loadExecutionCore();
      const proof = proveRegtest('regtest', { pubkey: NODE_PUBKEY, network: 'regtest', synced: true, version: '0.21.4-beta' });
      if (proof === null) throw new Error('fixture regtest proof refused');
      const approved = approveRoute(route, route, seeded.approval, policy, proof);
      if (!('route' in approved)) throw new Error('fixture route refused');
      try {
        const { dispatchExecution } = await loadDispatch();
        const result = await dispatchExecution({ db: clockDb, adapter: node,
          workerId: 'clock', leaseMs: 60_000, randomBytes: () => preimage,
          stopSignal: new AbortController().signal, attemptDeadlineMs: 5_000, invoiceExpirySeconds: 300,
          deltaToleranceMsat: 0n, alert: () => undefined },
        { executionId: seeded.executionId, fenceEpoch: 3n, route: approved.route, approval: seeded.approval, policy });
        expect.soft(result).toMatchObject(valid ? { exit: 7, step: 'OUTCOME_UNKNOWN' } : { exit: 5, step: 'STALE_SNAPSHOT' });
        expect.soft(node.count('sendOnRoute')).toBe(valid ? 1 : 0);
        expect.soft(node.count('createInvoice')).toBe(valid || stage === 'invoice-await' ? 1 : 0);
        expect.soft(rowOf(path, seeded.executionId).status).toBe(valid ? 'UNKNOWN' : 'CANCELLED');
        expect(reservationState(path, seeded.executionId).state).toBe(valid ? 'HELD' : 'RELEASED');
      } finally { db.close(); }
    });
  }
}
