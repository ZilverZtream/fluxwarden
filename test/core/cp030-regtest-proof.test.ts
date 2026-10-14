/*
Interface: test/helpers/cp030-execution.ts (src/core/execution.ts proveRegtest, approveRoute; dispatchExecution's
network-lock refusal of a route that approveRoute did not return).

Rules under test: SECURITY INV-15 (money moves only when both the configured and the node-reported network are exactly
`regtest`; the dispatch path takes a RegtestProof that only the network check constructs; every other string is refused,
including mainnet, testnet, testnet4, signet, simnet, bitcoin, liquid, liquid-regtest and the empty string).
*/
import { expect, it } from 'vitest';
import { never } from '../fakes/execution-node.js';
import { circularRoute } from '../fakes/preflight-node.js';
import { APPROVED_MAX_CLTV, APPROVED_MAX_FEE, PRINCIPAL, type ExecutionPolicy, type VerifiedApproval } from '../helpers/cp028-executor.js';
import { loadExecutionCore, rowOf } from '../helpers/cp030-execution.js';
import { prepare, REGTEST_HANDSHAKE } from '../helpers/cp030-dispatch.js';

const observed = (network: string) => ({ ...REGTEST_HANDSHAKE, network });

const OTHERS = ['mainnet', 'testnet', 'testnet4', 'signet', 'simnet', 'bitcoin', 'liquid', 'liquid-regtest', 'Regtest', 'regtest ', ''];

it('CP-030/B3 proveRegtest gives a proof only when the configured and the reported network are both exactly regtest', async () => {
  const { proveRegtest } = await loadExecutionCore();
  expect(proveRegtest('regtest', observed('regtest'))).not.toBeNull();
  for (const other of OTHERS) {
    expect(proveRegtest(other, observed('regtest')), `configured ${JSON.stringify(other)}`).toBeNull();
    expect(proveRegtest('regtest', observed(other)), `reported ${JSON.stringify(other)}`).toBeNull();
  }
});

const route = circularRoute('123145302376448', '246290604752896', 150_000n, 80);
const terms = { sourceChannelKey: route.sourceChannelKey, targetChannelKey: route.targetChannelKey, principalMsat: PRINCIPAL };
const approval: VerifiedApproval = {
  approvalId: '01JEXECAPPROVAL0000000000A', proposalId: '01JEXECPROPOSAL0000000000A', keyId: 'k1', nonce: 'ab'.repeat(32),
  proposalDigest: 'cd'.repeat(32), policySha256: 'ef'.repeat(32), approvedMaxFeeMsat: APPROVED_MAX_FEE, approvedMaxCltvDelta: APPROVED_MAX_CLTV,
  expiresAt: Date.now() + 600_000,
};
const policy: ExecutionPolicy = {
  sha256: 'ef'.repeat(32), network: 'regtest', maxFeeMsat: 300_000n, maxFeePpm: 2_500n, exemptFeeMsat: 5_000n, maxCltvDelta: 144,
  minChannelReserveMsat: 50_000_000n, budget: { msat: 2_000_000n, periodMs: 86_400_000 }, cooldownAfterFailureMs: 0, cooldownAfterSuccessMs: 0,
  maxInFlight: 1, maxSnapshotAgeMs: 60_000,
};

it('CP-030/B3 approveRoute refuses a value shaped like a proof that proveRegtest did not make (network-lock)', async () => {
  const { approveRoute, proveRegtest } = await loadExecutionCore();
  expect(approveRoute(route, terms, approval, policy, Object.freeze({ network: 'regtest' as const }))).toEqual({ refusal: 'network-lock' });
  const proof = proveRegtest('regtest', observed('regtest'));
  if (proof === null) throw new Error('no proof for regtest/regtest');
  const approved = approveRoute(route, terms, approval, policy, proof);
  expect('route' in approved ? approved.route : approved).toEqual(route);
});

it('CP-030/B3 dispatch refuses a route that approveRoute did not return: network-lock, no node call, nothing written', async () => {
  const r = await prepare('unapproved', { script: () => ({ send: () => never() }) });
  const before = rowOf(r.path, r.executionId);
  const outcome = await r.run(r.node, undefined, { route: { ...r.route } });
  expect(outcome).toEqual({ executionId: r.executionId, exit: 5, step: 'network-lock' });
  expect(r.node.calls).toEqual([]);
  expect(rowOf(r.path, r.executionId)).toEqual(before);
});
