// SPEC 5.5 V10 / 8.3 P4: retain and enforce known forwarding fees and
// HTLC bounds. SPEC 8.7 / 9.2 and SECURITY INV-07/08: native incoming attribution is
// the channel whose balance and settlement journal must be checked.
import { expect, it } from 'vitest';
import { succeeded } from '../fakes/execution-node.js';
import { circularRoute, FakePreflightNode, fakeChannel } from '../fakes/preflight-node.js';
import {
  APPROVAL_KEYS, dbNow, execByProposal, IN_PEER, loadPersistence, loadPreflight, OUT_PEER, policyFor, PRINCIPAL, raw,
  scratchDb, seedBase, seedProposal,
} from '../helpers/cp028-executor.js';
import { balances, prepare, ROUTE_FEE, S_BEFORE, T_BEFORE } from '../helpers/cp030-dispatch.js';
import { rowOf } from '../helpers/cp030-execution.js';

for (const condition of ['valid', 'wrong-fee', 'below-minimum', 'above-maximum'] as const) {
  it(`CP-029/REG-CORE001 preflight enforces known forwarding policies: ${condition}`, async () => {
    const p = await loadPersistence();
    const { prepareExecution } = await loadPreflight();
    const path = scratchDb(`external-known-policy-${condition}`);
    const base = seedBase(p, path);
    const approval = seedProposal(base);
    const route = circularRoute(base.sourceKey, base.targetKey, ROUTE_FEE, 80);
    // The independent hop-policy vocabulary and forwarding arithmetic are
    // recorded in test/helpers/route-interfaces.ts and cp022/cp024 route tests.
    // Each forwarding node charges exactly 75,000 msat in this route.
    const known = { ...route, hops: route.hops.map((hop, index) => ({ ...hop, policy: index === 0 ? null : {
      baseFeeMsat: condition === 'wrong-fee' && index === 2 ? 75_001n : 75_000n,
      feePpm: 0n, cltvExpiryDelta: index === 1 ? 28 : 34,
      minHtlcMsat: condition === 'below-minimum' && index === 2 ? PRINCIPAL + 1n : 1n,
      maxHtlcMsat: condition === 'above-maximum' && index === 2 ? PRINCIPAL - 1n : 1_000_000_000n,
    } })) };
    const node = new FakePreflightNode(base.sourceKey, base.targetKey, {
      route: () => known,
      // Match workflow.ts's database-clock observation authority; these cases
      // vary forwarding policy, not snapshot clock skew (CP044/F02 covers skew).
      channels: () => {
        const observedAt = dbNow(path);
        return [fakeChannel(base.sourceKey, OUT_PEER, { observedAt }), fakeChannel(base.targetKey, IN_PEER, { observedAt })];
      },
    });
    const db = p.openDatabase(path, { readOnly: false });
    try {
      const outcome = await prepareExecution({ db, adapter: node, workerId: 'worker-a', leaseMs: 60_000 },
        { approval, policy: policyFor(base), approvalKeyIds: APPROVAL_KEYS });
      expect(node.mutatingCalls()).toEqual([]);
      expect(node.routeRequests).toHaveLength(1);
      if (condition === 'valid') expect(outcome.kind).toBe('READY');
      else {
        expect(outcome).toMatchObject({ kind: 'CANCELLED', exit: 5, step: 'NO_FEASIBLE_ROUTE' });
        expect(execByProposal(path, approval.proposalId)?.payment_hash).toBeNull();
      }
    } finally { db.close(); }
  });
}

const INCOMING = '369435907129344';
const INCOMING_BEFORE = 200_000_000n;
for (const condition of ['actual-credit', 'actual-missing-baseline', 'planned-only-credit'] as const) {
  it(`CP-030/REG-EXEC002 incoming channel delta uses native receipt: ${condition}`, async () => {
    const r = await prepare(`external-incoming-${condition}`, {
      script: ({ base }) => ({
        before: () => [
          ...balances(base, S_BEFORE, T_BEFORE),
          ...(condition === 'actual-missing-baseline' ? [] : [fakeChannel(INCOMING, IN_PEER, { localBalanceMsat: INCOMING_BEFORE })]),
        ],
        after: () => [
          ...balances(base, S_BEFORE - PRINCIPAL - ROUTE_FEE, T_BEFORE + (condition === 'actual-credit' ? 0n : PRINCIPAL)),
          fakeChannel(INCOMING, IN_PEER, { localBalanceMsat: INCOMING_BEFORE + (condition === 'planned-only-credit' ? 0n : PRINCIPAL) }),
        ],
        send: context => { context.onDispatched?.(); return Promise.resolve(succeeded(ROUTE_FEE, 1, true, INCOMING)); },
      }),
    });
    const outcome = await r.run();
    const expected = condition === 'actual-credit' ? 'MATCH' : condition === 'actual-missing-baseline' ? 'PENDING' : 'MISMATCH';
    expect(rowOf(r.path, r.executionId)).toMatchObject({ status: 'VERIFIED_SUCCESS', delta_status: expected });
    if (condition === 'actual-credit') expect(outcome.exit).toBe(0);
    if (condition === 'planned-only-credit') expect(outcome.exit).toBe(9);
    const db = raw(r.path);
    try {
      const credits = db.prepare(`SELECT l.account_code AS account, l.debit_msat AS debit
        FROM ledger_lines l JOIN ledger_journals j ON j.id = l.journal_id
        WHERE j.execution_id = ? AND j.event_type = 'REBALANCE_SETTLED' AND l.account_code LIKE 'channel:%'`).all(r.executionId);
      expect(credits).toEqual([{ account: `channel:lnd-r:${INCOMING}:local`, debit: PRINCIPAL }]);
    } finally { db.close(); }
    expect(r.node.count('sendOnRoute')).toBe(1);
  });
}
