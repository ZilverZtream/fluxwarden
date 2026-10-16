// Interface: normalizeClnChannel on native pending objects. Pinned CLN v26.06.9 peer_control.c:2769-2779 emits both forms.
import { expect, it } from 'vitest';
import { loadCore } from '../helpers/cp004-reference.js';

interface Normalizer {
  readonly normalizeClnChannel: (raw: unknown, context: { nodeId: string; observedAt: number; blockHeight: number }) => {
    channelKey: string; state: string; nodeState: string; spendableMsat: bigint; receivableMsat: bigint;
  };
}

it('CP-014/B3 REG-CLN018 simultaneous single-funded and dual-funded pending objects for one peer retain distinct keys', async () => {
  const { normalizeClnChannel } = await loadCore<Normalizer>('normalize');
  const peer = `02${'ab'.repeat(32)}`;
  const common = { peer_id: peer, peer_connected: true, opener: 'local', features: ['option_static_remotekey'], to_us_msat: 100_000_000, total_msat: 100_000_000 };
  // Native serializers: lightningd/opening_control.c:29-72 and lightningd/dual_open_control.c:100-160 at v26.06.9.
  const inputs = [{ ...common, state: 'OPENINGD', owner: 'lightning_openingd' },
    { ...common, state: 'DUALOPEND_OPEN_INIT', owner: 'lightning_dualopend', lost_state: false, status: [] }];
  const context = { nodeId: '01JC0000000000000000000000', observedAt: 1_800_000_000_000, blockHeight: 812 };
  const channels = inputs.map(input => normalizeClnChannel(input, context));
  expect(channels.map(channel => channel.nodeState)).toEqual(['OPENINGD', 'DUALOPEND_OPEN_INIT']);
  expect(channels.map(channel => [channel.state, channel.spendableMsat, channel.receivableMsat])).toEqual([
    ['PENDING', 0n, 0n], ['PENDING', 0n, 0n],
  ]);
  expect(new Set(channels.map(channel => channel.channelKey)).size).toBe(2);
  expect(inputs.map(input => normalizeClnChannel(input, context).channelKey)).toEqual(channels.map(channel => channel.channelKey));
});
