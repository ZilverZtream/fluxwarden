/*
Interface: src/planner/diagnose.ts (pure; imports only src/core and src/planner; time from the injected clock).

  import type { ChannelState, Confidence, NormalizedChannel } from '../core/normalize.js';

  // Policy values as the policy loader hands them over. Field names as in the policy file (SPEC §7.1);
  // amounts in msat as bigint, durations in milliseconds.
  export interface ChannelTarget { readonly min_inbound_msat?: bigint; readonly min_outbound_msat?: bigint }
  export interface PlanningPolicy {
    readonly fees: { readonly max_fee_msat: bigint; readonly max_fee_ppm: bigint; readonly exempt_fee_msat: bigint };
    readonly routing: { readonly max_cltv_delta: number };
    readonly amounts: { readonly min_channel_reserve_msat: bigint; readonly max_principal_msat: bigint; readonly min_principal_msat: bigint };
    readonly budget: { readonly msat: bigint; readonly period: number };
    readonly cooldown_after_failure: number;
    readonly cooldown_after_success: number;
    readonly max_in_flight: number;
    readonly max_snapshot_age: number;
    readonly demand: { readonly mode: 'targets' | 'ewma'; readonly horizon: number };
    readonly targets: Readonly<Record<string, Readonly<Record<string, ChannelTarget>>>>;  // node name → channel key → target
    readonly exclude_channels: readonly string[];
  }
  export interface Clock { now(): number }            // database clock, unix ms

  export interface DiagnoseInput {
    readonly nodeName: string;                         // key into policy.targets
    readonly channels: readonly NormalizedChannel[];   // latest snapshot per channel; observedAt = the snapshot's observed_at
    readonly policy: PlanningPolicy;
    readonly horizonMs: number | null;                 // --horizon; null → policy.demand.horizon
    readonly clock: Clock;
  }
  export interface ChannelDiagnosis {
    readonly channelKey: string;
    readonly state: ChannelState;                      // copied from the snapshot; deficits are computed for every state
    readonly capacityMsat: bigint;
    readonly spendableMsat: bigint;
    readonly receivableMsat: bigint;
    readonly confidence: Confidence;                   // copied from the snapshot (INV-07)
    readonly caveat: string | null;                    // copied from the snapshot
    readonly observedAt: number;
    readonly snapshotAgeMs: number;                    // clock.now() − observedAt
    readonly blockHeight: number;
    readonly inboundTargetMsat: bigint | null;         // targets[node][channel].min_inbound_msat, null when absent
    readonly inboundDeficitMsat: bigint;               // max(0, R_in − receivable), R_in = target or 0
    readonly inboundSurplusMsat: bigint;               // max(0, receivable − R_in)
    readonly outboundTargetMsat: bigint | null;        // min_outbound_msat, null when absent
    readonly outboundDeficitMsat: bigint;              // max(0, R_out − spendable), R_out = target or 0
    readonly outboundSurplusMsat: bigint;              // max(0, spendable − R_out)
  }
  export type Diagnosis =
    | { readonly status: 'OK'; readonly nodeName: string; readonly demandSource: 'TARGETS'; readonly horizonMs: number;
        readonly evaluatedAt: number;                  // clock.now()
        readonly channels: readonly ChannelDiagnosis[];
        readonly starved: readonly string[];           // keys with inboundDeficitMsat > 0 (planning sources, SPEC §7.4)
        readonly donors: readonly string[] }           // keys with inboundSurplusMsat > 0 (planning targets)
    | { readonly status: 'STALE_SNAPSHOT'; readonly nodeName: string;
        readonly stale: readonly { readonly channelKey: string; readonly ageMs: number | null }[] }  // no figures
    | { readonly status: 'INSUFFICIENT_HISTORY'; readonly nodeName: string };
  export function diagnose(input: DiagnoseInput): Diagnosis;

  Rules:
  - Two snapshots with the same channel key are an invariant breach: diagnose throws (an Error), before anything else.
  - A channel snapshot is stale when clock.now() − observedAt > policy.max_snapshot_age (age exactly equal is fresh),
    or when observedAt lies after clock.now() (negative age: freshness cannot be shown, INV-06).
    A channel named in targets[nodeName] without any snapshot is stale with ageMs null: a missing snapshot is never
    read as a met target. Any stale channel makes the whole diagnosis STALE_SNAPSHOT, listing every stale channel
    with its age. Checked after the duplicate check and before the targets check.
  - No target entry with a min_inbound_msat or min_outbound_msat for nodeName (demand.mode targets; EWMA comes later)
    → INSUFFICIENT_HISTORY. Targets of other nodes do not count. Outbound-only targets are targets.
  - channels, starved, donors and stale are sorted by channel key ascending (JavaScript string comparison).
  - The horizon does not change target-based figures; it is only recorded.

Interface: src/commands/liquidity-diagnose.ts (no I/O; the CLI writes `json` to stdout and exits with `exitCode`).

  export function liquidityDiagnose(input: DiagnoseInput): { readonly exitCode: number; readonly json: string };

  `json` is exactly one JSON document plus "\n", valid against schemas/output/liquidity-diagnose.json:
    {"schema":1,"command":"liquidity diagnose","ok":…,"warnings":[],"result":…,"error":…}
  OK diagnosis → exit 0, result:
    { action: 'DEFICIT' when any channel has an inbound or outbound deficit, else 'NO_ACTION',
      reason: null for DEFICIT, 'BALANCED_OR_INSUFFICIENT_SURPLUS' for NO_ACTION,
      node, demand_source: 'TARGETS', horizon_seconds, evaluated_at,
      channels: [{ channel, capacity_msat, spendable_msat, receivable_msat, confidence, caveat, observed_at,
                   snapshot_age_ms, block_height, inbound_target_msat, inbound_deficit_msat, inbound_surplus_msat,
                   outbound_target_msat, outbound_deficit_msat, outbound_surplus_msat }],
      starved, donors }                                      (msat as decimal strings, SPEC §4.3)
  INSUFFICIENT_HISTORY → exit 0, result { action: 'NO_ACTION', reason: 'INSUFFICIENT_HISTORY', demand_source: null,
                          channels: [], starved: [], donors: [], plus node, horizon_seconds, evaluated_at }
  Channel rows also carry `state` (the snapshot's ChannelState) after `channel`.
  STALE_SNAPSHOT → exit 5 (SAFETY_REFUSAL), ok false, result null, error { code: 5, step: 'STALE_SNAPSHOT', message }.
  diagnose throws (duplicate snapshots) → exit 8 (INVARIANT_BREACH), ok false, result null, error.code 8; the function
  itself never throws.
*/
import Ajv2020 from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import { readJson } from '../helpers/cli.js';
import {
  CLN_CAVEAT, HOUR, NODE, NOW, SECOND, channel, commandModule, diagnoseModule, fixedClock, ok, policy,
  type ChannelDiagnosis, type DiagnoseInput, type NormalizedChannel, type PlanningPolicy,
} from '../helpers/cp020-planner.js';

const SAFETY_REFUSAL = 5;
const INVARIANT_BREACH = 8;
const OBSERVED = NOW - 5 * SECOND;

/** SPEC §7.1 targets for cln-m, with an outbound target added on 103x1x0. */
const TARGETS: PlanningPolicy['targets'] = {
  [NODE]: {
    '103x1x0': { min_inbound_msat: 150_000_000n, min_outbound_msat: 400_000_000n },
    '105x1x0': { min_inbound_msat: 50_000_000n },
    '109x1x0': { min_inbound_msat: 70_000_000n },
    '111x1x0': { min_inbound_msat: 25_000_000n },
  },
};

/** Recorded snapshots, deliberately not in key order. 105x1x0 comes from LND (derived figures), the rest from CLN. */
function b1Channels(): NormalizedChannel[] {
  return [
    channel('111x1x0', { capacity: 60_000_000n, spendable: 35_000_001n, receivable: 24_999_999n }),
    channel('107x2x1', { capacity: 200_000_000n, spendable: 90_000_000n, receivable: 100_000_000n }),
    channel('105x1x0', { capacity: 500_000_000n, spendable: 100_000_000n, receivable: 380_000_000n, confidence: 'DERIVED_ESTIMATE' }),
    channel('109x1x0', { capacity: 150_000_000n, spendable: 80_000_000n, receivable: 70_000_000n }),
    channel('103x1x0', { capacity: 1_000_000_000n, spendable: 600_000_000n, receivable: 30_000_000n }),
  ];
}

function input(channels: readonly NormalizedChannel[], overrides: Partial<DiagnoseInput> = {}): DiagnoseInput {
  return { nodeName: NODE, channels, policy: policy(TARGETS), horizonMs: null, clock: fixedClock(), ...overrides };
}

function row(key: string, fields: Omit<ChannelDiagnosis, 'channelKey' | 'state' | 'observedAt' | 'snapshotAgeMs' | 'blockHeight' | 'caveat'> & { caveat?: string | null }): ChannelDiagnosis {
  return { channelKey: key, state: 'ACTIVE', observedAt: OBSERVED, snapshotAgeMs: 5 * SECOND, blockHeight: 431, caveat: CLN_CAVEAT, ...fields };
}

/**
 * Hand-computed from SPEC §7.3: inbound deficit = max(0, R_in − receivable), surplus = max(0, receivable − R_in),
 * outbound likewise against spendable; R = 0 where the channel has no target.
 */
const B1_EXPECTED: ChannelDiagnosis[] = [
  // 150,000,000 − 30,000,000 = 120,000,000 inbound deficit; 600,000,000 − 400,000,000 = 200,000,000 outbound surplus.
  row('103x1x0', { capacityMsat: 1_000_000_000n, spendableMsat: 600_000_000n, receivableMsat: 30_000_000n, confidence: 'NODE_REPORTED',
    inboundTargetMsat: 150_000_000n, inboundDeficitMsat: 120_000_000n, inboundSurplusMsat: 0n,
    outboundTargetMsat: 400_000_000n, outboundDeficitMsat: 0n, outboundSurplusMsat: 200_000_000n }),
  // 380,000,000 − 50,000,000 = 330,000,000 inbound surplus; no outbound target → surplus = spendable 100,000,000.
  row('105x1x0', { capacityMsat: 500_000_000n, spendableMsat: 100_000_000n, receivableMsat: 380_000_000n, confidence: 'DERIVED_ESTIMATE', caveat: null,
    inboundTargetMsat: 50_000_000n, inboundDeficitMsat: 0n, inboundSurplusMsat: 330_000_000n,
    outboundTargetMsat: null, outboundDeficitMsat: 0n, outboundSurplusMsat: 100_000_000n }),
  // No target: R_in = R_out = 0 → surpluses are the full receivable 100,000,000 and spendable 90,000,000.
  row('107x2x1', { capacityMsat: 200_000_000n, spendableMsat: 90_000_000n, receivableMsat: 100_000_000n, confidence: 'NODE_REPORTED',
    inboundTargetMsat: null, inboundDeficitMsat: 0n, inboundSurplusMsat: 100_000_000n,
    outboundTargetMsat: null, outboundDeficitMsat: 0n, outboundSurplusMsat: 90_000_000n }),
  // Exactly at target: 70,000,000 − 70,000,000 = 0 both ways → neither starved nor donor.
  row('109x1x0', { capacityMsat: 150_000_000n, spendableMsat: 80_000_000n, receivableMsat: 70_000_000n, confidence: 'NODE_REPORTED',
    inboundTargetMsat: 70_000_000n, inboundDeficitMsat: 0n, inboundSurplusMsat: 0n,
    outboundTargetMsat: null, outboundDeficitMsat: 0n, outboundSurplusMsat: 80_000_000n }),
  // One msat under target: 25,000,000 − 24,999,999 = 1 → starved.
  row('111x1x0', { capacityMsat: 60_000_000n, spendableMsat: 35_000_001n, receivableMsat: 24_999_999n, confidence: 'NODE_REPORTED',
    inboundTargetMsat: 25_000_000n, inboundDeficitMsat: 1n, inboundSurplusMsat: 0n,
    outboundTargetMsat: null, outboundDeficitMsat: 0n, outboundSurplusMsat: 35_000_001n }),
];

const validator = (): ((doc: unknown) => boolean) => {
  const ajv = new Ajv2020.default({ strict: true, allErrors: true });
  return ajv.compile(readJson('schemas/output/liquidity-diagnose.json') as object);
};

function parse(json: string): Record<string, unknown> {
  expect(json.endsWith('\n'), 'one document followed by a newline').toBe(true);
  expect(json.slice(0, -1).includes('\n'), 'exactly one line').toBe(false);
  return JSON.parse(json) as Record<string, unknown>;
}

describe('diagnosis from operator targets', () => {
  it('CP-020/B1 deficits and surpluses per channel are exact msat from the targets', async () => {
    const { diagnose } = await diagnoseModule();
    expect(diagnose(input(b1Channels()))).toEqual({
      status: 'OK',
      nodeName: NODE,
      demandSource: 'TARGETS',
      horizonMs: 6 * HOUR,
      evaluatedAt: NOW,
      channels: B1_EXPECTED,
      starved: ['103x1x0', '111x1x0'],
      donors: ['105x1x0', '107x2x1'],
    });
  });

  it('CP-020/B1 the horizon is recorded and does not change target-based figures', async () => {
    const { diagnose } = await diagnoseModule();
    const twoHours = ok(diagnose(input(b1Channels(), { horizonMs: 2 * HOUR })));
    expect(twoHours.horizonMs).toBe(7_200_000);
    expect(twoHours.channels).toEqual(B1_EXPECTED);
  });

  it('CP-020/B1 a target above capacity and a zero-capacity channel give the unclamped formula values', async () => {
    const { diagnose } = await diagnoseModule();
    const targets = { [NODE]: { '201x1x0': { min_inbound_msat: 250_000_000n }, '202x1x0': { min_inbound_msat: 1_000n } } };
    const result = ok(diagnose(input([
      channel('203x1x0', { capacity: 0n, spendable: 0n, receivable: 0n }),
      channel('202x1x0', { capacity: 0n, spendable: 0n, receivable: 0n }),
      channel('201x1x0', { capacity: 100_000_000n, spendable: 60_000_000n, receivable: 40_000_000n }),
    ], { policy: policy(targets) })));
    const byKey = new Map(result.channels.map(c => [c.channelKey, c]));
    // 250,000,000 − 40,000,000 = 210,000,000: SPEC §7.3 has no capacity clamp; the planner bounds the principal.
    expect(byKey.get('201x1x0')?.inboundDeficitMsat).toBe(210_000_000n);
    // Zero capacity, target 1,000: 1,000 − 0 = 1,000 deficit.
    expect(byKey.get('202x1x0')?.inboundDeficitMsat).toBe(1_000n);
    expect(byKey.get('202x1x0')?.inboundSurplusMsat).toBe(0n);
    // Zero capacity, no target: 0 − 0 = 0 surplus, so it is not a donor.
    expect(byKey.get('203x1x0')?.inboundSurplusMsat).toBe(0n);
    expect(byKey.get('203x1x0')?.outboundSurplusMsat).toBe(0n);
    expect(result.starved).toEqual(['201x1x0', '202x1x0']);
    expect(result.donors).toEqual([]);
  });
});

describe('snapshot freshness (INV-06)', () => {
  it('CP-020/B2 a snapshot 60,001 ms old refuses with STALE_SNAPSHOT and no figures; exactly 60,000 ms is fresh', async () => {
    const { diagnose } = await diagnoseModule();
    const channels = b1Channels().map(c => c.channelKey === '107x2x1' ? { ...c, observedAt: NOW - 60_001 } : c);
    expect(diagnose(input(channels))).toEqual({ status: 'STALE_SNAPSHOT', nodeName: NODE, stale: [{ channelKey: '107x2x1', ageMs: 60_001 }] });
    const boundary = b1Channels().map(c => c.channelKey === '107x2x1' ? { ...c, observedAt: NOW - 60_000 } : c);
    const fresh = ok(diagnose(input(boundary)));
    expect(fresh.channels.find(c => c.channelKey === '107x2x1')?.snapshotAgeMs).toBe(60_000);
  });

  it('CP-020/B2 the bound is the policy max_snapshot_age and every stale channel is listed in key order', async () => {
    const { diagnose } = await diagnoseModule();
    // max_snapshot_age 30 s: 30,001 ms is stale, 30,000 ms is not.
    const channels = b1Channels().map(c =>
      c.channelKey === '111x1x0' ? { ...c, observedAt: NOW - 30_001 }
        : c.channelKey === '103x1x0' ? { ...c, observedAt: NOW - 45_000 }
          : c.channelKey === '105x1x0' ? { ...c, observedAt: NOW - 30_000 } : c);
    const result = diagnose(input(channels, { policy: policy(TARGETS, { max_snapshot_age: 30 * SECOND }) }));
    expect(result).toEqual({ status: 'STALE_SNAPSHOT', nodeName: NODE, stale: [{ channelKey: '103x1x0', ageMs: 45_000 }, { channelKey: '111x1x0', ageMs: 30_001 }] });
  });

  it('CP-020/B2 the command exits 5 with step STALE_SNAPSHOT and prints no balance figures', async () => {
    const { liquidityDiagnose } = await commandModule();
    const channels = b1Channels().map(c => c.channelKey === '103x1x0' ? { ...c, observedAt: NOW - 61 * SECOND } : c);
    const outcome = liquidityDiagnose(input(channels));
    expect(outcome.exitCode).toBe(SAFETY_REFUSAL);
    const doc = parse(outcome.json);
    expect(doc['ok']).toBe(false);
    expect(doc['result']).toBeNull();
    expect(doc['error']).toMatchObject({ code: SAFETY_REFUSAL, step: 'STALE_SNAPSHOT' });
    for (const figure of ['120000000', '330000000', '600000000', '380000000']) expect(outcome.json.includes(figure), `figure ${figure} absent`).toBe(false);
    expect(validator()(doc)).toBe(true);
  });
});

describe('demand source', () => {
  it('CP-020/B3 no targets, or targets only for another node, gives INSUFFICIENT_HISTORY', async () => {
    const { diagnose } = await diagnoseModule();
    expect(diagnose(input(b1Channels(), { policy: policy({}) }))).toEqual({ status: 'INSUFFICIENT_HISTORY', nodeName: NODE });
    const otherNode = policy({ 'lnd-r': { '103x1x0': { min_inbound_msat: 100_000_000n } } });
    expect(diagnose(input(b1Channels(), { policy: otherNode }))).toEqual({ status: 'INSUFFICIENT_HISTORY', nodeName: NODE });
  });

  it('CP-020/B3 the command reports INSUFFICIENT_HISTORY as NO_ACTION with exit 0 and no demand source', async () => {
    const { liquidityDiagnose } = await commandModule();
    const outcome = liquidityDiagnose(input(b1Channels(), { policy: policy({}) }));
    expect(outcome.exitCode).toBe(0);
    const doc = parse(outcome.json);
    expect(doc).toEqual({
      schema: 1, command: 'liquidity diagnose', ok: true, warnings: [], error: null,
      result: { action: 'NO_ACTION', reason: 'INSUFFICIENT_HISTORY', node: NODE, demand_source: null, horizon_seconds: 21_600, evaluated_at: NOW, channels: [], starved: [], donors: [] },
    });
    expect(validator()(doc)).toBe(true);
  });
});

function jsonRow(c: ChannelDiagnosis): Record<string, unknown> {
  const text = (v: bigint | null): string | null => v === null ? null : v.toString();
  return {
    channel: c.channelKey, state: c.state, capacity_msat: text(c.capacityMsat), spendable_msat: text(c.spendableMsat), receivable_msat: text(c.receivableMsat),
    confidence: c.confidence, caveat: c.caveat, observed_at: c.observedAt, snapshot_age_ms: c.snapshotAgeMs, block_height: c.blockHeight,
    inbound_target_msat: text(c.inboundTargetMsat), inbound_deficit_msat: text(c.inboundDeficitMsat), inbound_surplus_msat: text(c.inboundSurplusMsat),
    outbound_target_msat: text(c.outboundTargetMsat), outbound_deficit_msat: text(c.outboundDeficitMsat), outbound_surplus_msat: text(c.outboundSurplusMsat),
  };
}

describe('command output', () => {
  it('CP-020/B4 --json carries the exact figures as msat strings, sorted by channel key, valid against the schema', async () => {
    const { liquidityDiagnose } = await commandModule();
    const outcome = liquidityDiagnose(input(b1Channels(), { horizonMs: 2 * HOUR }));
    expect(outcome.exitCode).toBe(0);
    const doc = parse(outcome.json);
    expect(doc).toEqual({
      schema: 1, command: 'liquidity diagnose', ok: true, warnings: [], error: null,
      result: {
        action: 'DEFICIT', reason: null, node: NODE, demand_source: 'TARGETS', horizon_seconds: 7_200, evaluated_at: NOW,
        channels: B1_EXPECTED.map(jsonRow), starved: ['103x1x0', '111x1x0'], donors: ['105x1x0', '107x2x1'],
      },
    });
    expect(validator()(doc)).toBe(true);
  });

  it('CP-020/B4 the same snapshots in any order give byte-identical output', async () => {
    const { liquidityDiagnose } = await commandModule();
    const forward = b1Channels();
    const first = liquidityDiagnose(input(forward)).json;
    expect(liquidityDiagnose(input(forward)).json).toBe(first);
    expect(liquidityDiagnose(input([...forward].reverse())).json).toBe(first);
    expect(liquidityDiagnose(input([forward[2], forward[4], forward[0], forward[3], forward[1]].filter(c => c !== undefined))).json).toBe(first);
  });

  it('CP-020/B4 a node at or above every target is NO_ACTION with exit 0', async () => {
    const { liquidityDiagnose } = await commandModule();
    const targets = { [NODE]: { '105x1x0': { min_inbound_msat: 50_000_000n }, '109x1x0': { min_inbound_msat: 70_000_000n } } };
    const outcome = liquidityDiagnose(input(b1Channels().filter(c => c.channelKey === '105x1x0' || c.channelKey === '109x1x0'), { policy: policy(targets) }));
    expect(outcome.exitCode).toBe(0);
    const doc = parse(outcome.json);
    expect(doc['result']).toMatchObject({ action: 'NO_ACTION', reason: 'BALANCED_OR_INSUFFICIENT_SURPLUS', demand_source: 'TARGETS', starved: [], donors: ['105x1x0'] });
    expect(validator()(doc)).toBe(true);
  });

  it('CP-020/B4 the schema rejects documents without a confidence tag, with numeric amounts, or with an unknown tag', async () => {
    const { liquidityDiagnose } = await commandModule();
    const validate = validator();
    const good = parse(liquidityDiagnose(input(b1Channels())).json);
    expect(validate(good)).toBe(true);
    const mutate = (change: (first: Record<string, unknown>) => void): unknown => {
      const copy = structuredClone(good);
      const channels = (copy['result'] as { channels: Record<string, unknown>[] }).channels;
      const first = channels[0];
      if (!first) throw new Error('no channel row');
      change(first);
      return copy;
    };
    expect(validate(mutate(first => { delete first['confidence']; }))).toBe(false);
    expect(validate(mutate(first => { first['inbound_deficit_msat'] = 120_000_000; }))).toBe(false);
    expect(validate(mutate(first => { first['confidence'] = 'GUESSED'; }))).toBe(false);
    expect(validate({ ...good, ok: false })).toBe(false);
  });
});

describe('provenance (INV-07)', () => {
  it('CP-020/B5 each diagnosed channel carries its snapshot confidence tag and caveat into the diagnosis and the output', async () => {
    const { diagnose } = await diagnoseModule();
    const { liquidityDiagnose } = await commandModule();
    const result = ok(diagnose(input(b1Channels())));
    const tags = result.channels.map(c => [c.channelKey, c.confidence, c.caveat]);
    expect(tags).toEqual([
      ['103x1x0', 'NODE_REPORTED', CLN_CAVEAT],
      ['105x1x0', 'DERIVED_ESTIMATE', null],
      ['107x2x1', 'NODE_REPORTED', CLN_CAVEAT],
      ['109x1x0', 'NODE_REPORTED', CLN_CAVEAT],
      ['111x1x0', 'NODE_REPORTED', CLN_CAVEAT],
    ]);
    // Flipping the tags on the input flips them on the output: the tag is copied, not inferred.
    const flipped = b1Channels().map(c => ({ ...c, confidence: c.confidence === 'NODE_REPORTED' ? 'DERIVED_ESTIMATE' as const : 'NODE_REPORTED' as const }));
    const doc = parse(liquidityDiagnose(input(flipped)).json);
    const rows = (doc['result'] as { channels: { channel: string; confidence: string }[] }).channels;
    expect(rows.map(r => [r.channel, r.confidence])).toEqual([
      ['103x1x0', 'DERIVED_ESTIMATE'],
      ['105x1x0', 'NODE_REPORTED'],
      ['107x2x1', 'DERIVED_ESTIMATE'],
      ['109x1x0', 'DERIVED_ESTIMATE'],
      ['111x1x0', 'DERIVED_ESTIMATE'],
    ]);
  });
});

describe('incomplete or contradictory snapshots', () => {
  it('CP-020/B2 a snapshot dated after the database clock is refused as STALE_SNAPSHOT', async () => {
    const { diagnose } = await diagnoseModule();
    // Age NOW − (NOW + 1) = −1 ms: freshness cannot be shown (INV-06).
    const channels = b1Channels().map(c => c.channelKey === '107x2x1' ? { ...c, observedAt: NOW + 1 } : c);
    expect(diagnose(input(channels))).toEqual({ status: 'STALE_SNAPSHOT', nodeName: NODE, stale: [{ channelKey: '107x2x1', ageMs: -1 }] });
  });

  it('CP-020/B2 a targeted channel without a snapshot is listed as stale, never read as a met target', async () => {
    const { diagnose } = await diagnoseModule();
    const { liquidityDiagnose } = await commandModule();
    const targets = policy({ [NODE]: { ...TARGETS[NODE], '199x9x9': { min_inbound_msat: 10_000_000n } } });
    expect(diagnose(input(b1Channels(), { policy: targets }))).toEqual({ status: 'STALE_SNAPSHOT', nodeName: NODE, stale: [{ channelKey: '199x9x9', ageMs: null }] });
    const outcome = liquidityDiagnose(input(b1Channels(), { policy: targets }));
    expect(outcome.exitCode).toBe(SAFETY_REFUSAL);
    const doc = parse(outcome.json);
    expect(doc['error']).toMatchObject({ code: SAFETY_REFUSAL, step: 'STALE_SNAPSHOT' });
    expect(validator()(doc)).toBe(true);
  });

  it('CP-020/B2 a node with targets and no snapshots lists every targeted channel as stale; without targets it is INSUFFICIENT_HISTORY', async () => {
    const { diagnose } = await diagnoseModule();
    expect(diagnose(input([]))).toEqual({
      status: 'STALE_SNAPSHOT', nodeName: NODE,
      stale: ['103x1x0', '105x1x0', '109x1x0', '111x1x0'].map(channelKey => ({ channelKey, ageMs: null })),
    });
    expect(diagnose(input([], { policy: policy({}) }))).toEqual({ status: 'INSUFFICIENT_HISTORY', nodeName: NODE });
  });

  it('CP-020/B4 two snapshots for one channel are an invariant breach: diagnose throws, the command exits 8 in its envelope', async () => {
    const { diagnose } = await diagnoseModule();
    const { liquidityDiagnose } = await commandModule();
    const channels = [...b1Channels(), channel('105x1x0', { capacity: 500_000_000n, spendable: 90_000_000n, receivable: 390_000_000n })];
    expect(() => diagnose(input(channels))).toThrow();
    let outcome: { exitCode: number; json: string } | undefined;
    expect(() => { outcome = liquidityDiagnose(input(channels)); }).not.toThrow();
    if (!outcome) throw new Error('no outcome');
    expect(outcome.exitCode).toBe(INVARIANT_BREACH);
    const doc = parse(outcome.json);
    expect(doc['ok']).toBe(false);
    expect(doc['result']).toBeNull();
    expect(doc['error']).toMatchObject({ code: INVARIANT_BREACH });
    expect(validator()(doc)).toBe(true);
  });
});

describe('outbound targets', () => {
  it('CP-020/B1 outbound-only targets are targets: the outbound deficit is exact and the command reports DEFICIT', async () => {
    const { diagnose } = await diagnoseModule();
    const { liquidityDiagnose } = await commandModule();
    const outboundOnly = policy({ [NODE]: { '107x2x1': { min_outbound_msat: 150_000_000n } } });
    const result = ok(diagnose(input(b1Channels(), { policy: outboundOnly })));
    const target = result.channels.find(c => c.channelKey === '107x2x1');
    // 150,000,000 − spendable 90,000,000 = 60,000,000 outbound deficit; no inbound target → inbound surplus = receivable 100,000,000.
    expect(target).toMatchObject({ outboundTargetMsat: 150_000_000n, outboundDeficitMsat: 60_000_000n, outboundSurplusMsat: 0n, inboundTargetMsat: null, inboundDeficitMsat: 0n, inboundSurplusMsat: 100_000_000n });
    expect(result.starved).toEqual([]);
    const outcome = liquidityDiagnose(input(b1Channels(), { policy: outboundOnly }));
    expect(outcome.exitCode).toBe(0);
    const doc = parse(outcome.json);
    expect(doc['result']).toMatchObject({ action: 'DEFICIT', reason: null, demand_source: 'TARGETS', starved: [] });
    expect(validator()(doc)).toBe(true);
  });
});

describe('stale list order and duplicate keys', () => {
  it('CP-020/B4 an aged snapshot and a missing targeted channel are listed together in channel-key order', async () => {
    const { diagnose } = await diagnoseModule();
    // '100x0x0' is targeted last in the policy but sorts first; '107x2x1' is 61,000 ms old (> 60,000).
    const targets = policy({ [NODE]: { ...TARGETS[NODE], '100x0x0': { min_inbound_msat: 10_000_000n } } });
    const channels = b1Channels().map(c => c.channelKey === '107x2x1' ? { ...c, observedAt: NOW - 61 * SECOND } : c);
    expect(diagnose(input(channels, { policy: targets }))).toEqual({
      status: 'STALE_SNAPSHOT', nodeName: NODE,
      stale: [{ channelKey: '100x0x0', ageMs: null }, { channelKey: '107x2x1', ageMs: 61_000 }],
    });
  });

  it('CP-020/B4 a duplicate snapshot of the lowest channel key is refused like any other', async () => {
    const { diagnose } = await diagnoseModule();
    const { liquidityDiagnose } = await commandModule();
    const channels = [channel('103x1x0', { capacity: 1_000_000_000n, spendable: 590_000_000n, receivable: 40_000_000n }), ...b1Channels()];
    expect(() => diagnose(input(channels))).toThrow();
    const outcome = liquidityDiagnose(input(channels));
    expect(outcome.exitCode).toBe(INVARIANT_BREACH);
    expect(parse(outcome.json)['error']).toMatchObject({ code: INVARIANT_BREACH });
  });
});
