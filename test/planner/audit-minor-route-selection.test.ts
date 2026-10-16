// Interface: liquidityPlan's existing read-only route finder and persistence input ports.
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { channel, fixedClock, NODE, NODE_ID, policy } from '../helpers/cp020-planner.js';
import { loadPersistence, scratch } from '../helpers/cp015-persistence.js';
import { loadSrc } from '../helpers/load-src.js';
import type { CandidateRoute, RouteConstraints } from '../helpers/route-interfaces.js';

interface PlanModule { readonly liquidityPlan: (input: Record<string, unknown>) => Promise<{ exitCode: number; json: string }> }
const SELF = `03${'d4'.repeat(32)}`;
const S1 = '110x1x0';
const S2 = '111x1x0';
const T = '120x1x0';

function route(c: RouteConstraints, fee: bigint): CandidateRoute {
  const lastFee = fee / 2n;
  const forwarder = (baseFeeMsat: bigint) => ({ baseFeeMsat, feePpm: 0n, cltvExpiryDelta: 20, minHtlcMsat: 1n, maxHtlcMsat: null });
  return { hops: [
    { scid: c.sourceScid, nodeIdOut: c.outPeer, amountOutMsat: c.principalMsat + fee, cltvOut: c.blockHeight + 58, policy: null },
    { scid: '190x1x0', nodeIdOut: c.inPeer, amountOutMsat: c.principalMsat + lastFee, cltvOut: c.blockHeight + 38, policy: forwarder(fee - lastFee) },
    { scid: c.targetScid, nodeIdOut: c.selfPubkey, amountOutMsat: c.principalMsat, cltvOut: c.blockHeight + 18, policy: forwarder(lastFee) },
  ], parts: 1, totalAmountMsat: c.principalMsat + fee, totalFeeMsat: fee, totalTimeLock: c.blockHeight + 58, builtAtHeight: c.blockHeight };
}

async function setup(secondSource: boolean) {
  const p = await loadPersistence();
  const db = p.openDatabase(join(scratch('route-selection'), 'state.db'), { readOnly: false });
  db.nodes.insert({ id: NODE_ID, name: NODE, implementation: 'cln', expectedNetwork: 'regtest', expectedPubkey: SELF });
  const channels = [
    channel(S1, { capacity: 500_000_000n, spendable: 400_000_000n, receivable: 30_000_000n, blockHeight: 812 }),
    ...(secondSource ? [channel(S2, { capacity: 500_000_000n, spendable: 400_000_000n, receivable: 30_000_000n, blockHeight: 812 })] : []),
    channel(T, { capacity: 500_000_000n, spendable: 70_000_000n, receivable: 330_000_000n, blockHeight: 812 }),
  ].map((entry, index) => ({ ...entry, fundingOutpoint: `${String(index + 1).padStart(64, '0')}:0` }));
  for (const item of channels) { const id = db.channels.upsert(item); db.snapshots.record(id, item); }
  const pol = policy({ [NODE]: { [S1]: { min_inbound_msat: 130_000_000n }, ...(secondSource ? { [S2]: { min_inbound_msat: 129_900_000n } } : {}) } });
  const input = { db, node: { id: NODE_ID, name: NODE, pubkey: SELF, implementation: 'cln' }, channels, policy: pol,
    policySha256: 'a7'.repeat(32), policyCanonicalJson: '{"version":3}', blockHeight: 812, finalCltvDelta: 18,
    cooldowns: [], reservations: [], clock: fixedClock() };
  return { db, input };
}

it('CP-025/B3 REG-PLAN004 sends the tighter request cap and truthfully identifies a returned ppm-only violation (INV-03)', async () => {
  const s = await setup(false);
  const requests: RouteConstraints[] = [];
  try {
    const { liquidityPlan } = await loadSrc<PlanModule>('commands/liquidity-plan.ts');
    const outcome = await liquidityPlan({ ...s.input, routes: { buildCircularRoute: (c: RouteConstraints) => { requests.push(c); return Promise.resolve(route(c, 250_001n)); } } });
    expect(requests).toHaveLength(1);
    expect(requests[0]?.maxFeeMsat).toBe(250_000n);
    expect(outcome.exitCode).toBe(0);
    const result = (JSON.parse(outcome.json) as { result: Record<string, unknown> }).result;
    expect(result['action']).toBe('NO_ACTION');
    expect(result['candidates']).toEqual([expect.objectContaining({ source_channel: S1, target_channel: T, code: 'PPM_CEILING_EXCEEDED' })]);
  } finally { s.db.close(); }
});

it('CP-025/B3 REG-PLAN008 score uses principal minus fee with a fixed integer weight of one', async () => {
  const s = await setup(true);
  try {
    const { liquidityPlan } = await loadSrc<PlanModule>('commands/liquidity-plan.ts');
    const outcome = await liquidityPlan({ ...s.input, routes: { buildCircularRoute: (c: RouteConstraints) => Promise.resolve(route(c, c.sourceScid === S1 ? 250_000n : 10_000n)) } });
    expect(outcome.exitCode).toBe(0);
    const result = (JSON.parse(outcome.json) as { result: Record<string, unknown> }).result;
    // 99,900,000 - 10,000 = 99,890,000 beats 100,000,000 - 250,000 = 99,750,000.
    expect(result).toMatchObject({ action: 'CIRCULAR_REBALANCE', source_channel: S2, target_channel: T, principal_msat: '99900000' });
    expect(result['candidates']).toEqual(expect.arrayContaining([
      expect.objectContaining({ source_channel: S1, code: null, chosen: false }),
      expect.objectContaining({ source_channel: S2, code: null, chosen: true }),
    ]));
  } finally { s.db.close(); }
});
