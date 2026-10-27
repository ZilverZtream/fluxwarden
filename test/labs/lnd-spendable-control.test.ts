import { expect, it } from 'vitest';
import { firstHopSetup, observedLndSpendable } from '../../labs/scenarios/chaos/lnd-spendable.mjs';

const channel = { active: true, initiator: true, commitment_type: 'ANCHORS', pending_htlcs: [],
  local_balance: '200000', local_constraints: { chan_reserve_sat: '50000' }, fee_per_kw: '2500', commit_weight: '1124' };
it('T-18 independent native oracle counts twice-rate HTLC buffer and anchors without product normalization', () => {
  // (200000 - 50000 - floor(2*2500*(1124+172)/1000) - 660) sat.
  expect(observedLndSpendable(channel).spendableMsat).toBe(142860000n);
});
it('T-18 independent oracle refuses unsupported native shapes rather than inventing availability', () => {
  for (const override of [{ initiator: false }, { commitment_type: 'UNKNOWN_COMMITMENT_TYPE' },
    { local_constraints: {} }, { local_balance: Number.MAX_SAFE_INTEGER + 1 }, { pending_htlcs: [{}] }]) expect(() => observedLndSpendable({ ...channel, ...override })).toThrow('GAP');
});
it('T-18 finite setup admits measured fee-buffer margins and rejects cap or reverse-capacity growth before payment', () => {
  expect(firstHopSetup(55000000n, 300000n, 10000000n, 80000000n).topUp).toBe(60300000n);
  expect(() => firstHopSetup(1000000n, 300000n, 10000000n, 1000000000n)).toThrow('GAP');
  expect(() => firstHopSetup(210000000n, 300000n, 10000000n, 1000000000n)).toThrow('GAP');
  expect(() => firstHopSetup(55000000n, 300000n, 10000000n, 60000000n)).toThrow('GAP');
});
