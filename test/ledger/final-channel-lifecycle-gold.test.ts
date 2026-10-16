// SPEC §9.2: one opening from the first snapshot of each physical channel.
// CP015 public lifecycle contract: one immutable channel row from pending to
// active on the same funding outpoint. ARCHITECTURE normalization preserves
// positive local balances on pending/closing/uncommitted channel identities.
import { expect, it } from 'vitest';
import { channel, NODE_ID, type SnapshotInput } from '../helpers/cp015-persistence.js';
import { balanceOf, loadLedger, raw, scratchDb, seededLedger } from '../helpers/cp037-ledger.js';
import type { LedgerDatabase } from '../helpers/cp037-ledger.js';

// Public persistence interface signature (db.ts interface snapshots.storeAll),
// inspected with explicit root authorization; no implementation body consulted.
type SnapshotDatabase = LedgerDatabase & { readonly snapshots: LedgerDatabase['snapshots'] & {
  storeAll(channels: readonly SnapshotInput[]): string[];
} };

for (const [name, identity, fundingOutpoint, nodeState] of [
  ['LND funding outpoint', `${'c3'.repeat(32)}:0`, `${'c3'.repeat(32)}:0`, 'pending_open'],
  ['CLN uncommitted peer', `uncommitted:02${'ab'.repeat(32)}`, '', 'OPENINGD'],
] as const) {
  it(`CP-037/B1 a positive first snapshot under a ${name} identity is retained with a balanced opening`, async () => {
    const m = await loadLedger();
    const db = seededLedger(m, scratchDb('external-pending-opening'), []) as SnapshotDatabase;
    const snapshot = channel({ nodeId: NODE_ID, channelKey: identity, scid: null, fundingOutpoint,
      state: 'PENDING', nodeState, localBalanceMsat: 600_000_000n, observedAt: 1_000 });
    try {
      let stored: string[] = [];
      expect(() => { stored = db.snapshots.storeAll([snapshot]); }).not.toThrow();
      expect(stored).toHaveLength(1);
      const channelId = stored[0] ?? '';
      expect(db.snapshots.latest(channelId)?.localMsat).toBe(600_000_000n);
      const openings = db.ledger.journals().filter(j => j.eventType === 'OPENING');
      expect(openings).toHaveLength(1);
      expect(openings[0]?.lines.map(l => [l.debitMsat, l.creditMsat])).toEqual([[600_000_000n, 0n], [0n, 600_000_000n]]);
      expect(m.runLedgerVerify(db).exitCode).toBe(0);
    } finally { db.close(); }
  });
}

it('CP-037/B1 a committed pending channel becoming active on the same physical funding outpoint keeps one opening and original equity', async () => {
  const m = await loadLedger();
  const path = scratchDb('external-channel-lifecycle');
  const db = seededLedger(m, path, []) as SnapshotDatabase;
  const pendingKey = 'e1'.repeat(32);
  const activeKey = '109x1x1';
  const fundingOutpoint = `${'c3'.repeat(32)}:0`;
  const pending: SnapshotInput = channel({ channelKey: pendingKey, scid: null, fundingOutpoint,
    state: 'PENDING', nodeState: 'CHANNELD_AWAITING_LOCKIN', localBalanceMsat: 600_000_000n, observedAt: 1_000 });
  const active: SnapshotInput = channel({ channelKey: activeKey, scid: activeKey, fundingOutpoint,
    state: 'ACTIVE', nodeState: 'CHANNELD_NORMAL', localBalanceMsat: 550_000_000n, observedAt: 2_000 });
  try {
    const firstId = db.snapshots.storeAll([pending])[0];
    if (firstId === undefined) throw new Error('first snapshot missing');
    // CP015's reference contract stamps snapshots using the database clock,
    // not the normalized fixture's observedAt. Independently read that persisted
    // first capture time before renaming to prove opening provenance survives.
    const receipt = raw(path);
    let firstSnapshotTime: number;
    try {
      const captured = receipt.prepare('SELECT observed_at AS at FROM channel_snapshots WHERE channel_id = ? ORDER BY observed_at LIMIT 1').get(firstId) as { at: bigint };
      firstSnapshotTime = Number(captured.at);
    } finally { receipt.close(); }
    const before = db.ledger.journals().filter(j => j.eventType === 'OPENING');
    expect(before[0]?.occurredAt).toBe(firstSnapshotTime);
    const activeId = db.snapshots.storeAll([active])[0];
    expect(activeId).toBe(firstId);
    const after = db.ledger.journals().filter(j => j.eventType === 'OPENING');
    expect(after).toHaveLength(1);
    expect(after[0]?.id).toBe(before[0]?.id);
    expect(after[0]?.occurredAt).toBe(firstSnapshotTime);
    expect(balanceOf(db, 'equity:opening_balance')).toBe(-600_000_000n);
    const channelAssets = [...db.ledger.balances()].filter(([account]) => account.startsWith('channel:')).reduce((sum, [, value]) => sum + (value ?? 0n), 0n);
    expect(channelAssets).toBe(600_000_000n);
    // INV-08/09: append-only rekey corrections must also move the original asset;
    // preserving total equity alone cannot leave funds stranded on an old key.
    expect(balanceOf(db, m.channelLocalAccount('cln-m', pendingKey))).toBe(0n);
    expect(balanceOf(db, m.channelLocalAccount('cln-m', activeKey))).toBe(600_000_000n);
    expect(m.runLedgerVerify(db).exitCode).toBe(0);
  } finally { db.close(); }
});
