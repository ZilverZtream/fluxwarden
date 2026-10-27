/*
Reference check against the pinned regtest lab: snapshots stored from live captures (capture layout under
$FLUXWARDEN_LAB_CAPTURE_DIR as in test/lab/cp014-reference.test.ts) read back the node's own figures at the same height.
Interfaces: src/core/normalize.ts and src/persistence/index.ts as in the unit tests.
*/
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { loadCore } from '../helpers/cp004-reference.js';
import { loadPersistence, scratch, type SnapshotInput } from '../helpers/cp015-persistence.js';
import { currentPlannerCapture } from '../helpers/live-profile.js';

interface Ctx { nodeId: string; observedAt: number; blockHeight: number }
interface Normalize {
  normalizeLndChannel(raw: unknown, ctx: Ctx): SnapshotInput;
  normalizeClnChannel(raw: unknown, ctx: Ctx): SnapshotInput;
}

function capture(name: string): Record<string, unknown> {
  const dir = currentPlannerCapture();
  return JSON.parse(readFileSync(join(dir, name), 'utf8')) as Record<string, unknown>;
}

const NODES = [
  { id: '01JZ8Q5W3K6Y2N4R7T9V1X3Z5E', name: 'lnd-r', implementation: 'lnd', dir: 'lnd-r', list: 'listchannels.json', key: 'identity_pubkey', height: 'block_height' },
  { id: '01JZ8Q5W3K6Y2N4R7T9V1X3Z5F', name: 'cln-m', implementation: 'cln', dir: 'cln-m', list: 'listpeerchannels.json', key: 'id', height: 'blockheight' },
] as const;

// The live captures are a validation input. The lab config selects this file only when a validation plan is
// supplied (decision D53); without the capture directory every case then fails closed.
it('CP-015/R1 db-state snapshots of LND-R and CLN-M match the live channel figures at the same height', async () => {
  const normalize = await loadCore<Normalize>('normalize');
  const p = await loadPersistence();
  const db = p.openDatabase(join(scratch('lab'), 'fluxwarden.db'), { readOnly: false });
  try {
    for (const node of NODES) {
      const info = capture(`${node.dir}/getinfo.json`);
      const height = Number(info[node.height]);
      db.nodes.insert({ id: node.id, name: node.name, implementation: node.implementation, expectedNetwork: 'regtest', expectedPubkey: String(info[node.key]) });
      const channels = capture(`${node.dir}/${node.list}`)['channels'] as unknown[];
      expect(channels.length).toBeGreaterThan(0);
      for (const raw of channels) {
        const ctx = { nodeId: node.id, observedAt: Date.now(), blockHeight: height };
        const n = node.implementation === 'lnd' ? normalize.normalizeLndChannel(raw, ctx) : normalize.normalizeClnChannel(raw, ctx);
        const channelId = db.channels.upsert(n);
        db.snapshots.record(channelId, n);
        const row = db.snapshots.latest(channelId);
        expect(row?.blockHeight).toBe(height);
        expect(row?.localMsat).toBe(n.localBalanceMsat);
        expect(row?.spendableMsat).toBe(n.spendableMsat);
        expect(row?.receivableMsat).toBe(n.receivableMsat);
        expect(row?.confidence).toBe(node.implementation === 'lnd' ? 'DERIVED_ESTIMATE' : 'NODE_REPORTED');
      }
    }
  } finally { db.close(); }
});
