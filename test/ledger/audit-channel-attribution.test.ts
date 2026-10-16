// Interface: normalizeClnChannel and snapshots.storeAll over native listpeerchannels objects.
// SPEC §9.2, INV-07/08/09: preserve physical attribution, original openings and atomic snapshot storage.
import { expect, it } from 'vitest';
import { loadCore } from '../helpers/cp004-reference.js';
import { loadPersistence, NODE_ID, type SnapshotInput } from '../helpers/cp015-persistence.js';
import { loadLedger, raw, scratchDb, seededLedger, type LedgerDatabase, type LedgerModules } from '../helpers/cp037-ledger.js';

interface Normalizer {
  readonly normalizeClnChannel: (raw: unknown, context: { nodeId: string; observedAt: number; blockHeight: number }) => SnapshotInput;
}
type SnapshotDatabase = LedgerDatabase & { readonly snapshots: LedgerDatabase['snapshots'] & {
  readonly storeAll: (channels: readonly SnapshotInput[]) => string[];
} };

const PEER = `02${'ab'.repeat(32)}`;
const SCID = '812x2x0';
const OUTPOINT = `${'c3'.repeat(32)}:0`;
const SINGLE_MSAT = 100_000_000n;
const DUAL_MSAT = 300_000_000n;
const context = { nodeId: NODE_ID, observedAt: 1_800_000_000_000, blockHeight: 812 };
const common = { peer_id: PEER, peer_connected: true, opener: 'local',
  channel_type: { bits: [12, 22], names: ['static_remotekey/even', 'anchors/even'] },
  features: ['option_static_remotekey', 'option_anchors'] };

// CLN v26.06.9 opening_control.c:31-75 and dual_open_control.c:107-167 omit committed identities here.
function opening(): Record<string, unknown> {
  return { ...common, state: 'OPENINGD', owner: 'lightning_openingd', status: ['Funding channel'],
    to_us_msat: Number(SINGLE_MSAT), total_msat: Number(SINGLE_MSAT) };
}
function dualOpening(): Record<string, unknown> {
  return { ...common, state: 'DUALOPEND_OPEN_INIT', owner: 'lightning_dualopend', lost_state: false, status: [],
    to_us_msat: Number(DUAL_MSAT), total_msat: Number(DUAL_MSAT) };
}
function committed(): Record<string, unknown> {
  return { ...common, state: 'CHANNELD_NORMAL', owner: 'channeld', channel_id: 'd1'.repeat(32),
    short_channel_id: SCID, funding_txid: 'c3'.repeat(32), funding_outnum: 0,
    to_us_msat: Number(DUAL_MSAT), total_msat: Number(DUAL_MSAT),
    our_reserve_msat: 0, their_reserve_msat: 0, spendable_msat: Number(DUAL_MSAT), receivable_msat: 0, htlcs: [] };
}

function capture(db: SnapshotDatabase, path: string) {
  const reader = raw(path);
  try {
    return {
      channels: reader.prepare('SELECT * FROM channels ORDER BY id').all(),
      snapshots: reader.prepare('SELECT * FROM channel_snapshots ORDER BY channel_id, observed_at').all(),
      journals: db.ledger.journals(),
      balances: [...db.ledger.balances()].sort(([a], [b]) => a.localeCompare(b)),
    };
  } finally { reader.close(); }
}

function checkAssets(m: LedgerModules, db: SnapshotDatabase, expected: readonly (readonly [string, bigint])[], soft = false) {
  const assert = soft ? expect.soft : expect;
  const actual = [...db.ledger.balances()].filter(([account, amount]) => account.startsWith('channel:') && amount !== 0n)
    .sort(([a], [b]) => a.localeCompare(b));
  assert(actual).toEqual([...expected].sort(([a], [b]) => a.localeCompare(b)));
  assert(db.ledger.balances().get(m.EQUITY_OPENING_BALANCE)).toBe(-expected.reduce((sum, [, amount]) => sum + amount, 0n));
  assert(m.runLedgerVerify(db).exitCode).toBe(0);
}

it('CP-015/B5 REG-SRC006 two unlinked pending observations retain distinct physical assets or refuse atomically in either update order', async () => {
  const m = await loadLedger();
  const p = await loadPersistence();
  const { normalizeClnChannel } = await loadCore<Normalizer>('normalize');
  const outcomes: string[] = [];
  for (const activeFirst of [false, true]) {
    const path = scratchDb('channel-attribution');
    const db = seededLedger(m, path, []) as SnapshotDatabase;
    try {
      const first = [opening(), dualOpening()].map(value => normalizeClnChannel(value, context));
      expect(first.map(channel => [channel.nodeState, channel.localBalanceMsat, channel.fundingOutpoint || ''])).toEqual([
        ['OPENINGD', SINGLE_MSAT, ''], ['DUALOPEND_OPEN_INIT', DUAL_MSAT, ''],
      ]);
      expect(new Set(first.map(channel => channel.channelKey)).size).toBe(2);
      const firstIds = db.snapshots.storeAll(first);
      expect(firstIds).toHaveLength(2);
      expect(new Set(firstIds).size).toBe(2);
      const original = capture(db, path);
      const openings = original.journals.filter(journal => journal.eventType === 'OPENING');
      expect(openings).toHaveLength(2);
      checkAssets(m, db, first.map(channel => [m.channelLocalAccount('cln-m', channel.channelKey), channel.localBalanceMsat] as const));
      const next = (activeFirst ? [committed(), opening()] : [opening(), committed()])
        .map(value => normalizeClnChannel(value, { ...context, observedAt: context.observedAt + 1_000 }));
      expect(next.map(channel => channel.localBalanceMsat)).toEqual(activeFirst ? [DUAL_MSAT, SINGLE_MSAT] : [SINGLE_MSAT, DUAL_MSAT]);
      const single = next.find(channel => channel.nodeState === 'OPENINGD');
      const active = next.find(channel => channel.nodeState === 'CHANNELD_NORMAL');
      if (single === undefined || active === undefined) throw new Error('native channel normalization lost an observation');
      expect(single.channelKey).toBe(first[0]?.channelKey);
      expect(active).toMatchObject({ scid: SCID, fundingOutpoint: OUTPOINT, state: 'ACTIVE' });

      const dispositions: string[] = [];
      for (let pass = 0; pass < 2; pass += 1) {
        const before = capture(db, path);
        let ids: string[];
        try { ids = db.snapshots.storeAll(next); }
        catch (error) {
          // An explicit identity refusal is safe only if the entire persisted observation remains unchanged.
          expect(error).toBeInstanceOf(p.PersistenceError);
          expect(String((error as { code?: unknown }).code)).toMatch(/^[A-Z][A-Z_]+$/);
          expect((error as Error).message).toMatch(/channel|identity|ambig|uncommitted|link|pending|collision/i);
          expect(capture(db, path)).toEqual(before);
          console.info(JSON.stringify({ case: 'REG-SRC006', order: activeFirst ? 'active-first' : 'pending-first', pass,
            disposition: 'refused', errorCode: (error as { code: string }).code }));
          dispositions.push('refused');
          continue;
        }
        expect.soft(ids).toEqual(activeFirst ? [firstIds[1], firstIds[0]] : firstIds);
        const after = capture(db, path);
        expect.soft(after.channels).toHaveLength(2);
        expect.soft(after.channels.find(row => row['id'] === firstIds[0])).toMatchObject({ channel_key: single.channelKey, lifecycle_state: 'PENDING' });
        expect.soft(after.channels.find(row => row['id'] === firstIds[1])).toMatchObject({ channel_key: active.channelKey, funding_outpoint: OUTPOINT, lifecycle_state: 'ACTIVE' });
        expect.soft(after.snapshots).toEqual(expect.arrayContaining(original.snapshots));
        expect.soft(db.snapshots.latest(firstIds[0] ?? '')?.localMsat).toBe(SINGLE_MSAT);
        expect.soft(db.snapshots.latest(firstIds[1] ?? '')?.localMsat).toBe(DUAL_MSAT);
        expect.soft(after.journals.filter(journal => journal.eventType === 'OPENING')).toEqual(openings);
        expect.soft(after.journals).toEqual(expect.arrayContaining(original.journals));
        checkAssets(m, db, [[m.channelLocalAccount('cln-m', single.channelKey), SINGLE_MSAT], [m.channelLocalAccount('cln-m', active.channelKey), DUAL_MSAT]], true);
        if (pass === 1) {
          expect.soft(after.journals).toEqual(before.journals);
          expect.soft(after.balances).toEqual(before.balances);
        }
        console.info(JSON.stringify({ case: 'REG-SRC006', order: activeFirst ? 'active-first' : 'pending-first', pass,
          disposition: 'admitted', distinctReturnedIds: new Set(ids).size, channelRows: after.channels.length }));
        dispositions.push('admitted');
      }
      expect.soft(dispositions).toHaveLength(2);
      expect.soft(dispositions[1]).toBe(dispositions[0]);
      outcomes.push(dispositions[0] ?? 'missing');
    } finally { db.close(); }
  }
  expect.soft(outcomes).toHaveLength(2);
  expect.soft(outcomes[1]).toBe(outcomes[0]);
});

it('CP-015/B5 REG-SRC006 a native shared funding outpoint preserves its channel row opening and assets across activation and replay', async () => {
  const m = await loadLedger();
  const { normalizeClnChannel } = await loadCore<Normalizer>('normalize');
  const path = scratchDb('channel-attribution-linked');
  const db = seededLedger(m, path, []) as SnapshotDatabase;
  try {
    const pending: Record<string, unknown> = { ...committed(), state: 'CHANNELD_AWAITING_LOCKIN' };
    delete pending['short_channel_id'];
    const first = normalizeClnChannel(pending, context);
    const active = normalizeClnChannel(committed(), { ...context, observedAt: context.observedAt + 1_000 });
    expect(first.fundingOutpoint).toBe(OUTPOINT);
    expect(active.fundingOutpoint).toBe(OUTPOINT);
    const ids = db.snapshots.storeAll([first]);
    expect(ids).toHaveLength(1);
    const before = capture(db, path);
    expect(before.journals.filter(journal => journal.eventType === 'OPENING')).toHaveLength(1);
    expect(db.snapshots.storeAll([active])).toEqual(ids);
    const updated = capture(db, path);
    expect(updated.channels).toHaveLength(1);
    expect(updated.journals.filter(journal => journal.eventType === 'OPENING')).toEqual(before.journals.filter(journal => journal.eventType === 'OPENING'));
    expect(updated.snapshots).toEqual(expect.arrayContaining(before.snapshots));
    expect(db.snapshots.latest(ids[0] ?? '')?.localMsat).toBe(DUAL_MSAT);
    checkAssets(m, db, [[m.channelLocalAccount('cln-m', active.channelKey), DUAL_MSAT]]);
    expect(db.snapshots.storeAll([active])).toEqual(ids);
    const repeated = capture(db, path);
    expect(repeated.journals).toEqual(updated.journals);
    expect(repeated.balances).toEqual(updated.balances);
    console.info(JSON.stringify({ case: 'REG-SRC006-linked', observations: 3, channelRows: repeated.channels.length,
      openingJournals: repeated.journals.filter(journal => journal.eventType === 'OPENING').length }));
  } finally { db.close(); }
});
