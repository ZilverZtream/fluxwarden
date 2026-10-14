/*
Interface: test/helpers/cp028-executor.ts (claimExecution, Database.executions.transition / submit / renewLease, prepareExecution).

Rules under test: SPEC §6.4 (claims and fenced writes), §6.5 (lease expiry), §6.2 (lease times from the database clock),
SECURITY INV-13 and INV-18.
*/
import { afterEach, expect, it, vi } from 'vitest';
import { FakePreflightNode } from '../fakes/preflight-node.js';
import {
  APPROVAL_KEYS, claimed, codeOf, dbNow, eventsOf, execById, execByProposal, force, loadClaim, loadPersistence, loadPreflight, policyFor, reservationsOf,
  preflightWithHash, racingTransition, raw, scalar, scratchDb, seedBase, seedProposal, seedSecondApproval, sleep,
  type Base, type ExecutionStatus, type VerifiedApproval,
} from '../helpers/cp028-executor.js';

const LEASE = 60_000;

async function setup(prefix: string) {
  const p = await loadPersistence();
  const { claimExecution } = await loadClaim();
  const path = scratchDb(prefix);
  const base = seedBase(p, path);
  const db = p.openDatabase(path, { readOnly: false });
  const policy = policyFor(base);
  return { p, path, base, db, policy, claimExecution };
}

afterEach(() => { vi.useRealTimers(); });

it('CP-028/B1 a first claim inserts CLAIMED with fence epoch 1, the worker and a database-clock lease, and returns that epoch', async () => {
  const { path, base, db, policy, claimExecution } = await setup('first');
  try {
    const approval = seedProposal(base);
    const before = dbNow(path);
    const outcome = claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-a', leaseMs: LEASE });
    const after = dbNow(path);
    const { executionId } = claimed(outcome);
    expect(outcome).toEqual({ ok: true, executionId, fenceEpoch: 1n });
    const row = execById(path, executionId);
    expect(row.status).toBe('CLAIMED');
    expect(row.fence_epoch).toBe(1n);
    expect(row.worker_id).toBe('worker-a');
    const lease = Number(row.lease_expires_at);
    expect(lease).toBeGreaterThanOrEqual(before + LEASE - 1);
    expect(lease).toBeLessThanOrEqual(after + LEASE + 1);
    expect(eventsOf(path, executionId).map(e => e.to_status)).toEqual(['CLAIMED']);
  } finally { db.close(); }
});

it('CP-028/B1 a claim while another worker holds a live lease is refused as claimed-elsewhere and changes nothing', async () => {
  const { path, base, db, policy, claimExecution } = await setup('live');
  try {
    const approval = seedProposal(base);
    const { executionId } = claimed(claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-a', leaseMs: LEASE }));
    const before = execById(path, executionId);
    const second = claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-b', leaseMs: LEASE });
    // SPEC §10.3 AE4: lost race or already claimed -> exit 5, step claimed-elsewhere, with the execution id.
    expect(second).toEqual({ ok: false, exit: 5, step: 'claimed-elsewhere', executionId });
    expect(execById(path, executionId)).toEqual(before);
    expect(reservationsOf(path, executionId)).toHaveLength(1);
    expect(eventsOf(path, executionId)).toHaveLength(1);
  } finally { db.close(); }
});

it('CP-028/B3 a write with a stale epoch affects zero rows: LEASE_LOST, no event, no reservation change', async () => {
  const { path, base, db, policy, claimExecution } = await setup('stale');
  try {
    const approval = seedProposal(base);
    const a = claimed(claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-a', leaseMs: LEASE }));
    force(path, a.executionId, { leaseAgoMs: 1_000 });
    const b = claimed(claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-b', leaseMs: LEASE }));
    expect(b.fenceEpoch).toBe(2n);
    const row = execById(path, a.executionId);
    const events = eventsOf(path, a.executionId);
    const reservations = reservationsOf(path, a.executionId);

    expect(codeOf(() => db.executions.transition(a.executionId, a.fenceEpoch, 'CLAIMED', 'PREFLIGHT'))).toBe('LEASE_LOST');
    expect(codeOf(() => db.executions.transition(a.executionId, a.fenceEpoch, 'CLAIMED', 'CANCELLED', { errorCode: 'STALE_SNAPSHOT' }))).toBe('LEASE_LOST');
    expect(codeOf(() => db.executions.renewLease(a.executionId, a.fenceEpoch, LEASE))).toBe('LEASE_LOST');
    expect(execById(path, a.executionId)).toEqual(row);
    expect(eventsOf(path, a.executionId)).toEqual(events);
    expect(reservationsOf(path, a.executionId)).toEqual(reservations);

    // The holder's epoch writes, and the status condition is part of the fence.
    expect(db.executions.transition(b.executionId, b.fenceEpoch, 'CLAIMED', 'PREFLIGHT')).toBe(3n);
    expect(execById(path, a.executionId)).toMatchObject({ status: 'PREFLIGHT', fence_epoch: 3n, worker_id: 'worker-b' });
    expect(codeOf(() => db.executions.transition(b.executionId, 3n, 'CLAIMED', 'CANCELLED'))).toBe('LEASE_LOST');
    expect(execById(path, a.executionId)).toMatchObject({ status: 'PREFLIGHT', fence_epoch: 3n });
  } finally { db.close(); }
});

it('CP-028/B3 the holder re-asserts its lease: the epoch increments and the lease moves on the database clock', async () => {
  const { path, base, db, policy, claimExecution } = await setup('renew');
  try {
    const approval = seedProposal(base);
    const a = claimed(claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-a', leaseMs: 1_000 }));
    const before = dbNow(path);
    expect(db.executions.renewLease(a.executionId, a.fenceEpoch, 120_000)).toBe(2n);
    const after = dbNow(path);
    const row = execById(path, a.executionId);
    expect(row.fence_epoch).toBe(2n);
    expect(row.status).toBe('CLAIMED');
    expect(Number(row.lease_expires_at)).toBeGreaterThanOrEqual(before + 120_000 - 1);
    expect(Number(row.lease_expires_at)).toBeLessThanOrEqual(after + 120_000 + 1);
  } finally { db.close(); }
});

for (const variant of ['a failing check', 'a passing preflight'] as const) {
  it(`CP-028/B3 a worker whose lease is taken over during preflight stops at its next write (${variant}): lease-lost, nothing written over the new holder, no mutating call`, async () => {
    const { p, path, base, db, policy, claimExecution } = await setup('takeover');
    const other = p.openDatabase(path, { readOnly: false, busyTimeoutMs: 2_000 });
    try {
      const approval = seedProposal(base);
      const { prepareExecution } = await loadPreflight();
      let takenEpoch = 0n;
      const fake = new FakePreflightNode(base.sourceKey, base.targetKey, {
        ...(variant === 'a failing check' ? { network: 'signet' as const } : {}),
        during: {
          handshake: () => {
            const row = execByProposalId(path, approval.proposalId);
            force(path, row, { leaseAgoMs: 1_000 });
            takenEpoch = claimed(claimExecution(other, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-b', leaseMs: LEASE })).fenceEpoch;
          },
        },
      });
      const outcome = await prepareExecution({ db, adapter: fake, workerId: 'worker-a', leaseMs: LEASE }, { approval, policy, approvalKeyIds: APPROVAL_KEYS });
      const id = execByProposalId(path, approval.proposalId);
      expect(outcome).toEqual({ kind: 'REFUSED', executionId: id, exit: 5, step: 'lease-lost' });
      const row = execById(path, id);
      expect(row.worker_id).toBe('worker-b');
      expect(row.fence_epoch).toBe(takenEpoch);
      expect(['CLAIMED', 'PREFLIGHT']).toContain(row.status);
      expect(row.error_code).toBeNull();
      expect(row.route_json).toBeNull();
      expect(row.planned_fee_msat).toBeNull();
      expect(reservationsOf(path, id).map(r => r.state)).toEqual(['HELD']);
      expect(fake.mutatingCalls()).toEqual([]);
      if (variant === 'a failing check') expect(fake.calls).toEqual(['handshake']);
    } finally { other.close(); db.close(); }
  });
}

function execByProposalId(path: string, proposalId: string): string {
  const row = execByProposal(path, proposalId);
  if (row === undefined) throw new Error('no execution row');
  return row.id;
}

it('CP-028/B4 an expired lease is re-claimable from CLAIMED and from PREFLIGHT; the epoch increments and the reservation is kept', async () => {
  const { path, base, db, policy, claimExecution } = await setup('reclaim');
  try {
    for (const status of ['CLAIMED', 'PREFLIGHT'] as const) {
      const approval = seedProposal(base);
      const a = claimed(claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-a', leaseMs: LEASE }));
      let epoch = a.fenceEpoch;
      if (status === 'PREFLIGHT') epoch = db.executions.transition(a.executionId, epoch, 'CLAIMED', 'PREFLIGHT');
      force(path, a.executionId, { leaseAgoMs: 1_000 });
      const reserved = reservationsOf(path, a.executionId);
      const before = dbNow(path);
      const b = claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-b', leaseMs: LEASE });
      expect(b, status).toEqual({ ok: true, executionId: a.executionId, fenceEpoch: epoch + 1n });
      const row = execById(path, a.executionId);
      expect(row.fence_epoch, status).toBe(epoch + 1n);
      expect(row.worker_id, status).toBe('worker-b');
      expect(Number(row.lease_expires_at), status).toBeGreaterThanOrEqual(before + LEASE - 1);
      expect(reservationsOf(path, a.executionId), status).toEqual(reserved);
    }
  } finally { db.close(); }
});

it('CP-028/B4 SUBMITTING, IN_FLIGHT, UNKNOWN and terminal executions are never re-claimed, even with a long-expired lease', async () => {
  const { path, base, db, claimExecution } = await setup('noreclaim');
  // Every row here shares one channel pair and node; cooldowns and the in-flight limit are lifted so only the re-claim rule decides.
  const policy = policyFor(base, { cooldownAfterFailureMs: 0, cooldownAfterSuccessMs: 0, maxInFlight: 100 });
  try {
    const statuses: ExecutionStatus[] = ['SUBMITTING', 'IN_FLIGHT', 'UNKNOWN', 'VERIFIED_SUCCESS', 'VERIFIED_FAILURE', 'CANCELLED'];
    for (const status of statuses) {
      const approval = seedProposal(base);
      const a = claimed(claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-a', leaseMs: LEASE }));
      force(path, a.executionId, { status, leaseAgoMs: 600_000 });
      const row = execById(path, a.executionId);
      const b = claimExecution(db, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-b', leaseMs: LEASE });
      expect(b, status).toEqual({ ok: false, exit: 5, step: 'claimed-elsewhere', executionId: a.executionId });
      expect(execById(path, a.executionId), status).toEqual(row);
      expect(reservationsOf(path, a.executionId), status).toHaveLength(1);
    }
  } finally { db.close(); }
});

it('CP-028/B5 lease length and expiry are computed on the database clock; stepping the worker clock changes nothing', async () => {
  const { path, base, db, policy, claimExecution } = await setup('clock');
  try {
    const realNow = Date.now();
    vi.useFakeTimers({ toFake: ['Date'] });

    // Worker clock one hour fast: the stored lease is still database time + lease.
    vi.setSystemTime(realNow + 3_600_000);
    const first = seedProposal(base);
    const before = dbNow(path);
    const a = claimed(claimExecution(db, { approval: first, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-a', leaseMs: LEASE }));
    const after = dbNow(path);
    const lease = Number(execById(path, a.executionId).lease_expires_at);
    expect(lease).toBeGreaterThanOrEqual(before + LEASE - 1);
    expect(lease).toBeLessThanOrEqual(after + LEASE + 1);

    // A second worker whose clock is two hours fast still sees a live lease.
    vi.setSystemTime(realNow + 7_200_000);
    expect(claimExecution(db, { approval: first, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-b', leaseMs: LEASE }))
      .toEqual({ ok: false, exit: 5, step: 'claimed-elsewhere', executionId: a.executionId });

    // Worker clock one hour slow: a 300 ms lease expires after 300 ms of database time and can then be re-claimed.
    vi.setSystemTime(realNow - 3_600_000);
    const second = seedProposal(base);
    const beforeShort = dbNow(path);
    const c = claimed(claimExecution(db, { approval: second, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-a', leaseMs: 300 }));
    const shortLease = Number(execById(path, c.executionId).lease_expires_at);
    expect(shortLease).toBeGreaterThanOrEqual(beforeShort + 299);
    expect(shortLease).toBeLessThanOrEqual(dbNow(path) + 301);
    await new Promise<void>(resolve => { setTimeout(resolve, 700); });
    expect(claimExecution(db, { approval: second, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-b', leaseMs: LEASE }))
      .toEqual({ ok: true, executionId: c.executionId, fenceEpoch: 2n });
  } finally { db.close(); }
});

for (const variant of ['a failing check', 'a passing preflight'] as const) {
  it(`CP-028/B3 a fenced write that loses the lease after the worker's last read (${variant}) ends lease-lost and writes nothing over the new holder`, async () => {
    const { p, path, base, db, policy, claimExecution } = await setup('write-race');
    const other = p.openDatabase(path, { readOnly: false, busyTimeoutMs: 2_000 });
    try {
      const approval = seedProposal(base);
      const { prepareExecution } = await loadPreflight();
      let takenEpoch = 0n;
      // Another process takes the lease between the worker's last read and its next fenced write.
      const racing = racingTransition(db, () => {
        force(path, execByProposalId(path, approval.proposalId), { leaseAgoMs: 1_000 });
        takenEpoch = claimed(claimExecution(other, { approval, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-b', leaseMs: LEASE })).fenceEpoch;
      });
      const fake = new FakePreflightNode(base.sourceKey, base.targetKey, {
        ...(variant === 'a failing check' ? { synced: false } : {}),
        during: { [variant === 'a failing check' ? 'handshake' : 'findCircularRoute']: () => { racing.arm(); } },
      });
      const outcome = await prepareExecution({ db: racing.db, adapter: fake, workerId: 'worker-a', leaseMs: LEASE }, { approval, policy, approvalKeyIds: APPROVAL_KEYS });
      const id = execByProposalId(path, approval.proposalId);
      expect(outcome).toEqual({ kind: 'REFUSED', executionId: id, exit: 5, step: 'lease-lost' });
      const row = execById(path, id);
      expect(takenEpoch).not.toBe(0n);
      expect(row.worker_id).toBe('worker-b');
      expect(row.fence_epoch).toBe(takenEpoch);
      expect(row.status).not.toBe('CANCELLED');
      expect(row.error_code).toBeNull();
      expect(row.route_json).toBeNull();
      expect(reservationsOf(path, id).map(r => r.state)).toEqual(['HELD']);
      expect(fake.mutatingCalls()).toEqual([]);
    } finally { other.close(); db.close(); }
  });
}

it('CP-028/B3 a fenced write carrying leaseMs renews the lease on the database clock', async () => {
  const { path, base, db, policy, claimExecution } = await setup('renew-write');
  try {
    const a = claimed(claimExecution(db, { approval: seedProposal(base), policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-a', leaseMs: 1_000 }));
    const before = dbNow(path);
    expect(db.executions.transition(a.executionId, a.fenceEpoch, 'CLAIMED', 'PREFLIGHT', { leaseMs: 90_000 })).toBe(a.fenceEpoch + 1n);
    const after = dbNow(path);
    const lease = Number(execById(path, a.executionId).lease_expires_at);
    expect(lease).toBeGreaterThanOrEqual(before + 90_000 - 1);
    expect(lease).toBeLessThanOrEqual(after + 90_000 + 1);
  } finally { db.close(); }
});

it('CP-028/B3 preflight renews the lease with its fenced writes: after a slow node the lease runs from the last write', async () => {
  const { path, base, db, policy } = await setup('renew-preflight');
  try {
    const approval = seedProposal(base);
    const { prepareExecution } = await loadPreflight();
    const fake = new FakePreflightNode(base.sourceKey, base.targetKey, { during: { findCircularRoute: () => sleep(500) } });
    const before = dbNow(path);
    const outcome = await prepareExecution({ db, adapter: fake, workerId: 'worker-a', leaseMs: LEASE }, { approval, policy, approvalKeyIds: APPROVAL_KEYS });
    expect(outcome.kind).toBe('READY');
    expect(Number(execByProposal(path, approval.proposalId)?.lease_expires_at)).toBeGreaterThanOrEqual(before + 500 + LEASE - 1);
  } finally { db.close(); }
});

it('CP-028/B3 submit with a stale epoch throws LEASE_LOST and writes nothing', async () => {
  const { path, base, db, policy } = await setup('submit-stale');
  try {
    const claim = await loadClaim();
    const x = preflightWithHash(db, claim, base, policy);
    force(path, x.executionId, { leaseAgoMs: 1_000 });
    claimed(claim.claimExecution(db, { approval: approvalOf(path, x.executionId, base), policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-b', leaseMs: LEASE }));
    const row = execById(path, x.executionId);
    expect(codeOf(() => db.executions.submit(x.executionId, x.fenceEpoch, 1, LEASE))).toBe('LEASE_LOST');
    expect(execById(path, x.executionId)).toEqual(row);
    expect(reservationsOf(path, x.executionId).map(r => r.state)).toEqual(['HELD']);
  } finally { db.close(); }
});

it('CP-028/B3 submit refuses an execution whose payment hash is not persisted, and writes nothing (SPEC §8.2)', async () => {
  const { path, base, db, policy, claimExecution } = await setup('submit-nohash');
  try {
    const c = claimed(claimExecution(db, { approval: seedProposal(base), policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-a', leaseMs: LEASE }));
    const epoch = db.executions.transition(c.executionId, c.fenceEpoch, 'CLAIMED', 'PREFLIGHT');
    const row = execById(path, c.executionId);
    expect(codeOf(() => db.executions.submit(c.executionId, epoch, 1, LEASE))).toBe('INVALID_TRANSITION');
    expect(execById(path, c.executionId)).toEqual(row);
    expect(scalar(path, 'SELECT count(*) AS v FROM executions WHERE submitted_at IS NOT NULL')).toBe(0n);
  } finally { db.close(); }
});

it('CP-028/B3 an admitted submit writes SUBMITTING with submitted_at and a fresh lease on the database clock', async () => {
  const { path, base, db, policy } = await setup('submit-ok');
  try {
    const x = preflightWithHash(db, await loadClaim(), base, policy);
    force(path, x.executionId, { leaseAgoMs: -5_000 });
    const before = dbNow(path);
    expect(db.executions.submit(x.executionId, x.fenceEpoch, 1, 90_000)).toEqual({ status: 'SUBMITTING', fenceEpoch: x.fenceEpoch + 1n });
    const after = dbNow(path);
    const row = execById(path, x.executionId);
    expect(row.status).toBe('SUBMITTING');
    expect(row.fence_epoch).toBe(x.fenceEpoch + 1n);
    const submittedAt = Number(scalar(path, 'SELECT submitted_at AS v FROM executions WHERE id = ?', x.executionId));
    expect(submittedAt).toBeGreaterThanOrEqual(before);
    expect(submittedAt).toBeLessThanOrEqual(after);
    expect(Number(row.lease_expires_at)).toBeGreaterThanOrEqual(before + 90_000 - 1);
    expect(Number(row.lease_expires_at)).toBeLessThanOrEqual(after + 90_000 + 1);
    expect(reservationsOf(path, x.executionId).map(r => r.state)).toEqual(['HELD']);
  } finally { db.close(); }
});

it('CP-028/B4 an expired claim is re-claimed only under its own approval: a second approval of the same proposal gets claimed-elsewhere', async () => {
  const { path, base, db, policy, claimExecution } = await setup('second-approval');
  try {
    const first = seedProposal(base);
    const a = claimed(claimExecution(db, { approval: first, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-a', leaseMs: LEASE }));
    force(path, a.executionId, { leaseAgoMs: 1_000 });
    const second = seedSecondApproval(base, first);
    const row = execById(path, a.executionId);
    expect(claimExecution(db, { approval: second, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-b', leaseMs: LEASE }))
      .toEqual({ ok: false, exit: 5, step: 'claimed-elsewhere', executionId: a.executionId });
    expect(execById(path, a.executionId)).toEqual(row);
    expect(scalar(path, 'SELECT count(*) AS v FROM executions WHERE approval_id = ?', second.approvalId)).toBe(0n);
    // Under its own approval the same expired claim is taken over.
    expect(claimExecution(db, { approval: first, policy, approvalKeyIds: APPROVAL_KEYS, workerId: 'worker-c', leaseMs: LEASE }))
      .toEqual({ ok: true, executionId: a.executionId, fenceEpoch: a.fenceEpoch + 1n });
  } finally { db.close(); }
});

/** The stored approval behind an execution, as the verifier would hand it over again. */
function approvalOf(path: string, executionId: string, base: Base): VerifiedApproval {
  const conn = raw(path);
  try {
    const row = conn.prepare(`SELECT a.id, a.proposal_id, a.key_id, a.nonce, a.expires_at, a.max_fee_msat, a.max_cltv_delta, p.proposal_digest
      FROM executions e JOIN approvals a ON a.id = e.approval_id JOIN liquidity_proposals p ON p.id = e.proposal_id WHERE e.id = ?`).get(executionId) as
      { id: string; proposal_id: string; key_id: string; nonce: string; expires_at: bigint; max_fee_msat: bigint; max_cltv_delta: bigint; proposal_digest: string };
    return {
      approvalId: row.id, proposalId: row.proposal_id, keyId: row.key_id, nonce: row.nonce, proposalDigest: row.proposal_digest,
      policySha256: base.policySha256, approvedMaxFeeMsat: row.max_fee_msat, approvedMaxCltvDelta: Number(row.max_cltv_delta), expiresAt: Number(row.expires_at),
    };
  } finally { conn.close(); }
}
