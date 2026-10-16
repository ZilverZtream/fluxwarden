// Interface: stored cooldown/reservation admission through the built planner CLI.
import { readFileSync, writeFileSync } from 'node:fs';
import { afterEach, beforeAll, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { methodsOf } from '../fakes/cln/rebalance-node.js';
import { approve, demo, plan, prepareDemoFixtures, rows, type DemoFixtures } from '../helpers/cpw-cli.js';
import { loadClaim, loadPersistence, type ExecutionPolicy, type VerifiedApproval } from '../helpers/cp028-executor.js';

const servers: FakeServer[] = [];
let fixtures: DemoFixtures;
beforeAll(async () => { fixtures = await prepareDemoFixtures(); });
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });

it('CP-025/B3 REG-PLAN006 planning reads a stored success cooldown and retains its explicit refusal', async () => {
  const d = await demo(servers, { fixtures });
  const initial = await plan(d);
  expect(initial['action']).toBe('CIRCULAR_REBALANCE');
  const proposal = String(initial['proposal_id']);
  await approve(d, proposal);
  const paid = await d.run(['--json', 'actions', 'execute', proposal, '--require-regtest']);
  expect(paid.status, paid.stdout + paid.stderr).toBe(0);
  const sendCount = methodsOf(d.cln.fake).filter(method => method === 'sendpay').length;
  const next = await plan(d);
  expect(next['action']).toBe('NO_ACTION');
  expect(next['candidates']).toEqual(expect.arrayContaining([expect.objectContaining({ code: 'COOLDOWN_ACTIVE' })]));
  expect(methodsOf(d.cln.fake).filter(method => method === 'sendpay')).toHaveLength(sendCount);
});

it('CP-025/B3 REG-PLAN006 planning counts a stored held claim reservation before any payment is in flight', async () => {
  const d = await demo(servers, { fixtures });
  writeFileSync(d.policy, readFileSync(d.policy, 'utf8').replace('msat: "2000000"', 'msat: "500000"'));
  const initial = await plan(d);
  expect(initial['action']).toBe('CIRCULAR_REBALANCE');
  await approve(d, String(initial['proposal_id']));
  const stored = rows(d.database, 'SELECT * FROM approvals')[0];
  if (stored === undefined) throw new Error('approved fixture has no approval row');
  const approval: VerifiedApproval = { approvalId: String(stored['id']), proposalId: String(stored['proposal_id']), keyId: String(stored['key_id']),
    nonce: String(stored['nonce']), proposalDigest: String(initial['digest']), policySha256: String(initial['policy_sha256']),
    approvedMaxFeeMsat: BigInt(String(stored['max_fee_msat'])), approvedMaxCltvDelta: Number(stored['max_cltv_delta']), expiresAt: Number(stored['expires_at']) };
  const policy: ExecutionPolicy = { sha256: approval.policySha256, network: 'regtest', maxFeeMsat: 300_000n, maxFeePpm: 2_500n, exemptFeeMsat: 5_000n,
    maxCltvDelta: 144, minChannelReserveMsat: 50_000_000n, budget: { msat: 500_000n, periodMs: 86_400_000 },
    cooldownAfterFailureMs: 3_600_000, cooldownAfterSuccessMs: 1_800_000, maxInFlight: 1, maxSnapshotAgeMs: 60_000 };
  const p = await loadPersistence();
  const db = p.openDatabase(d.database, { readOnly: false });
  try {
    const { claimExecution } = await loadClaim();
    expect(claimExecution(db, { approval, policy, approvalKeyIds: [d.key.keyId], workerId: 'pending-worker', leaseMs: 60_000 }).ok).toBe(true);
  } finally { db.close(); }
  expect(rows(d.database, 'SELECT status FROM executions')).toEqual([{ status: 'CLAIMED' }]);
  expect(rows(d.database, 'SELECT state, reserved_msat FROM budget_reservations')).toEqual([{ state: 'HELD', reserved_msat: 300000 }]);
  const next = await plan(d);
  expect(next['action']).toBe('NO_ACTION');
  expect(next['candidates']).toEqual(expect.arrayContaining([expect.objectContaining({ code: 'BUDGET_EXHAUSTED' })]));
  expect(methodsOf(d.cln.fake).filter(method => method === 'sendpay')).toEqual([]);
});
