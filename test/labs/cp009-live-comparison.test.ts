import { expect, it } from 'vitest';
import { same } from '../helpers/recording.js';

it('CP-009/B2 route comparison permits a different last-hop node identity between lab instances', () => {
  const recorded = { last_hop_pubkey: 'recorded-node', amt_msat: '100000000', use_mission_control: true, fee_limit: { fixed_msat: '10000000' } };
  expect(same(recorded, { ...recorded, last_hop_pubkey: 'fresh-owned-node' })).toBeNull();
  expect(same(recorded, { ...recorded, last_hop_pubkey: 123 })).not.toBeNull();
});

it.each([
  { amt_msat: '100000001' }, { use_mission_control: false }, { fee_limit: { fixed_msat: '10000001' } },
])('CP-009/B2 route comparison rejects changed nonvolatile money or flags %j', change => {
  const recorded = { last_hop_pubkey: 'recorded-node', amt_msat: '100000000', use_mission_control: true, fee_limit: { fixed_msat: '10000000' } };
  expect(same(recorded, { ...recorded, ...change })).not.toBeNull();
});
