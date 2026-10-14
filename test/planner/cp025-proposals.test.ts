/*
Interface: proposals, digest and explain.

src/planner/proposal.ts (pure apart from node:crypto)
  export interface DigestFields {
    readonly proposalId: string;          // the stored 26-character ULID, without the `prop_` output prefix
    readonly nodePubkey: string;          // 66 lowercase hex
    readonly sourceChannelKey: string; readonly targetChannelKey: string;
    readonly principalMsat: bigint; readonly maxFeeMsat: bigint; readonly maxFeePpm: bigint; readonly exemptFeeMsat: bigint;
    readonly maxCltvDelta: number;
    readonly policySha256: string;        // 64 lowercase hex, digested as that text
    readonly expiresAt: number;           // unix ms, digested as its decimal text
  }
  export function proposalDigest(fields: DigestFields): string;   // 64 lowercase hex
  SHA-256 over "FluxWarden-proposal-v1" || 0x00, then each field in the order above as a 4-byte
  big-endian length and its UTF-8 bytes; numbers as decimal strings (SPEC §7.6, SECURITY §4.1).

src/planner/diagnose.ts PlanningPolicy gains `proposal_ttl: number` (milliseconds, SPEC §7.1).

src/commands/liquidity-plan.ts
  export interface RouteFinder { buildCircularRoute(c: RouteConstraints): Promise<CandidateRoute | NoRoute> }   // read-only view
  export interface LiquidityPlanInput {
    readonly db: Database;                // src/persistence openDatabase(..., { readOnly: false }); node and channel rows exist
    readonly node: { readonly id: string; readonly name: string; readonly pubkey: string; readonly implementation: 'lnd' | 'cln' };
    readonly channels: readonly NormalizedChannel[];   // latest snapshot per channel
    readonly policy: PlanningPolicy; readonly policySha256: string; readonly policyCanonicalJson: string;
    readonly blockHeight: number; readonly finalCltvDelta: number;
    readonly cooldowns: readonly CooldownEvent[]; readonly reservations: readonly BudgetReservation[];
    readonly routes: RouteFinder; readonly clock: Clock;
  }
  export function liquidityPlan(input: LiquidityPlanInput): Promise<{ exitCode: number; json: string; text: string }>;
  Steps: diagnose and plan (§7.4); every candidate pair, in plan order, is assessed with
    RouteConstraints { selfPubkey: node.pubkey, implementation, sourceScid/targetScid: the channels' scids,
    outPeer/inPeer: their peers, principalMsat, maxFeeMsat: min(max_fee_msat, max(exempt_fee_msat,
    floor(max_fee_ppm × P / 10^6))) (the ppm cap derived into the absolute limit sent, SECURITY §4.2),
    maxCltvDelta: routing.max_cltv_delta, finalCltvDelta, blockHeight }, then core validateRoute with the
    snapshot channels and the policy caps. The best valid route (§7.4 score) becomes the proposal.
  Storage, one transaction: a policy_versions row when policySha256 is new; one liquidity_proposals row
    (action_type, channel row ids, principal, the policy caps max_fee_msat / max_fee_ppm / max_cltv_delta,
    route_json, demand_source, proposal_digest, status PROPOSED, reason_json = the explanation tree
    { demand_source, inputs, candidates, ... } with node text stored unescaped,
    created_at = clock.now(), expires_at = created_at + proposal_ttl). No candidate → a NO_ACTION row.
  Output: exit 0; `json` is one --json document (schemas/output/liquidity-plan.json) whose result is the
    proposal document below; `text` is the human rendering of the same document.

src/commands/liquidity-explain.ts
  export function liquidityExplain(input: { readonly db: Database; readonly proposalId: string; readonly clock: Clock }):
    { exitCode: number; json: string; text: string };
  Read-only, no node calls. `proposalId` is `prop_<ULID>`; anything else or an unknown id → exit 2 with an
  error document (schemas/output/liquidity-explain.json). Otherwise exit 0 with the stored proposal document.
  A PROPOSED proposal whose expires_at ≤ clock.now() is shown with status EXPIRED.

Proposal document (result of both commands):
  { proposal_id: 'prop_<ULID>', node, action, status, demand_source, source_channel, target_channel, principal_msat,
    caps: { max_fee_msat, max_fee_ppm, exempt_fee_msat, max_cltv_delta },
    route: null | { hops: [{ channel, node_out, amount_msat, cltv }], fee_msat, fee_ppm, cltv_delta, padding },
    policy_sha256, digest, created_at, expires_at,
    inputs: [{ channel, confidence, caveat, snapshot_age_ms, spendable_msat, receivable_msat }],   // channel key order
    candidates: [{ source_channel, target_channel, principal_msat, code, detail, chosen }],       // source, then target key order
    approvals: [] }
  `code` is null for a valid route; `detail` carries the node's no-route text (display only) or null;
  `principal_msat` is null for a pair refused before route discovery. Text output escapes control and
  bidirectional characters as the output module does (\xNN, \uNNNN).
*/
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';
import { CLN_CAVEAT, MINUTE, NODE, NODE_ID, NOW, channel, fixedClock, policy, type Clock, type NormalizedChannel } from '../helpers/cp020-planner.js';
import { loadPersistence, raw, scratch } from '../helpers/cp015-persistence.js';
import type { CandidateRoute, NoRoute, RouteConstraints } from '../helpers/route-interfaces.js';

interface DigestFields {
  proposalId: string; nodePubkey: string; sourceChannelKey: string; targetChannelKey: string;
  principalMsat: bigint; maxFeeMsat: bigint; maxFeePpm: bigint; exemptFeeMsat: bigint; maxCltvDelta: number;
  policySha256: string; expiresAt: number;
}
interface ProposalModule { proposalDigest: (fields: DigestFields) => string }
interface Outcome { exitCode: number; json: string; text: string }
interface PlanModule { liquidityPlan: (input: Record<string, unknown>) => Promise<Outcome> }
interface ExplainModule { liquidityExplain: (input: { db: unknown; proposalId: string; clock: Clock }) => Outcome }

const load = async <T>(relative: string): Promise<T> => await import(pathToFileURL(join(repoRoot, relative)).href) as T;
const proposalModule = (): Promise<ProposalModule> => load('src/planner/proposal.ts');
const planModule = (): Promise<PlanModule> => load('src/commands/liquidity-plan.ts');
const explainModule = (): Promise<ExplainModule> => load('src/commands/liquidity-explain.ts');

/** SPEC §7.6 written out independently: domain prefix, NUL, then (4-byte BE length, UTF-8 bytes) per field. */
function referenceDigest(f: DigestFields): string {
  const parts = [
    f.proposalId, f.nodePubkey, f.sourceChannelKey, f.targetChannelKey, f.principalMsat.toString(), f.maxFeeMsat.toString(),
    f.maxFeePpm.toString(), f.exemptFeeMsat.toString(), String(f.maxCltvDelta), f.policySha256, String(f.expiresAt),
  ];
  const hash = createHash('sha256').update(Buffer.from('FluxWarden-proposal-v1', 'utf8')).update(Buffer.from([0]));
  for (const part of parts) {
    const bytes = Buffer.from(part, 'utf8');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length).update(bytes);
  }
  return hash.digest('hex');
}

const NODE_PUBKEY = `03${'d4'.repeat(32)}`;
const POLICY_SHA = 'a7'.repeat(32);
const BASE: DigestFields = {
  proposalId: '01JC5Z0000000000000000000A', nodePubkey: NODE_PUBKEY, sourceChannelKey: '102x1x0', targetChannelKey: '105x1x0',
  principalMsat: 100_000_000n, maxFeeMsat: 300_000n, maxFeePpm: 2_500n, exemptFeeMsat: 5_000n, maxCltvDelta: 144,
  policySha256: POLICY_SHA, expiresAt: NOW + 15 * MINUTE,
};

describe('digest', () => {
  it('CP-025/B1 the digest is SHA-256 over the approved fields with the domain prefix and length framing', async () => {
    const { proposalDigest } = await proposalModule();
    expect(proposalDigest(BASE)).toMatch(/^[0-9a-f]{64}$/);
    expect(proposalDigest(BASE)).toBe(referenceDigest(BASE));
  });

  it('CP-025/B1 changing any one digested field changes the digest', async () => {
    const { proposalDigest } = await proposalModule();
    const tampered: DigestFields[] = [
      { ...BASE, proposalId: '01JC5Z0000000000000000000B' },
      { ...BASE, nodePubkey: `02${'d4'.repeat(32)}` },
      { ...BASE, sourceChannelKey: '102x1x1' },
      { ...BASE, targetChannelKey: '104x1x0' },
      { ...BASE, principalMsat: 100_000_001n },
      { ...BASE, maxFeeMsat: 300_001n },
      { ...BASE, maxFeePpm: 2_501n },
      { ...BASE, exemptFeeMsat: 5_001n },
      { ...BASE, maxCltvDelta: 145 },
      { ...BASE, policySha256: 'a7'.repeat(31) + 'a8' },
      { ...BASE, expiresAt: BASE.expiresAt + 1 },
    ];
    const digests = tampered.map(fields => proposalDigest(fields));
    expect(new Set([proposalDigest(BASE), ...digests]).size).toBe(12);
    tampered.forEach((fields, index) => { expect(digests[index]).toBe(referenceDigest(fields)); });
  });

  it('CP-025/B1 length framing separates fields: moving a character across a boundary changes the digest', async () => {
    const { proposalDigest } = await proposalModule();
    const a = proposalDigest({ ...BASE, sourceChannelKey: '102x1x0', targetChannelKey: '1105x1x0' });
    const b = proposalDigest({ ...BASE, sourceChannelKey: '102x1x01', targetChannelKey: '105x1x0' });
    expect(a).not.toBe(b);
  });
});

// ---- liquidity plan / explain over a real database and a scripted read-only route finder ----

const SOURCE = '102x1x0';
const RESERVE_BOUND = '101x1x0';
const NO_PATH = '103x1x0';
const EXPENSIVE = '104x1x0';
const TARGET = '105x1x0';
const MIDDLE_SCID = '190x1x0';
const HEIGHT = 812;
const P = 100_000_000n;
const HOSTILE = 'no path \u001b[31m\u202eevil';

const peerOf = (key: string): string => channel(key, { capacity: 1n, spendable: 0n, receivable: 0n }).peerPubkey;

function channels(): NormalizedChannel[] {
  const spec = (spendable: bigint, receivable: bigint) => ({ capacity: 500_000_000n, spendable, receivable, blockHeight: HEIGHT });
  return [
    channel(RESERVE_BOUND, spec(60_000_000n, 10_000_000n)), // deficit 140,000,000; 60,000,000 − 300,000 − 50,000,000 < 10,000,000
    channel(SOURCE, spec(400_000_000n, 40_000_000n)), // deficit 110,000,000
    channel(NO_PATH, spec(100_000_000n, 300_000_000n)),
    channel(EXPENSIVE, spec(100_000_000n, 300_000_000n)),
    channel(TARGET, spec(20_000_000n, 400_000_000n)), // surplus 350,000,000 over its 50,000,000 target
  ];
}

const TARGETS = { [NODE]: { [RESERVE_BOUND]: { min_inbound_msat: 150_000_000n }, [SOURCE]: { min_inbound_msat: 150_000_000n }, [TARGET]: { min_inbound_msat: 50_000_000n } } };

/** SPEC §5.4 C6 worked example for c: (S → out-peer, P + 202,101, Δ132), (middle → in-peer, P + 101,000, Δ52), (T → us, P, Δ18). */
function specRoute(c: RouteConstraints): CandidateRoute {
  const forwarder = (cltvExpiryDelta: number) => ({ baseFeeMsat: 1000n, feePpm: 1000n, cltvExpiryDelta, minHtlcMsat: 1n, maxHtlcMsat: null });
  return {
    hops: [
      { scid: c.sourceScid, nodeIdOut: c.outPeer, amountOutMsat: 100_202_101n, cltvOut: c.blockHeight + 132, policy: null },
      { scid: MIDDLE_SCID, nodeIdOut: c.inPeer, amountOutMsat: 100_101_000n, cltvOut: c.blockHeight + 52, policy: forwarder(80) },
      { scid: c.targetScid, nodeIdOut: c.selfPubkey, amountOutMsat: 100_000_000n, cltvOut: c.blockHeight + 18, policy: forwarder(34) },
    ],
    parts: 1, totalAmountMsat: 100_202_101n, totalFeeMsat: 202_101n, totalTimeLock: c.blockHeight + 132, builtAtHeight: c.blockHeight,
  };
}

/** A structurally sound route whose fee, 400,000 msat, is over every cap (V3). */
function expensiveRoute(c: RouteConstraints): CandidateRoute {
  const forwarder = { baseFeeMsat: 200_000n, feePpm: 0n, cltvExpiryDelta: 20, minHtlcMsat: 1n, maxHtlcMsat: null };
  return {
    hops: [
      { scid: c.sourceScid, nodeIdOut: c.outPeer, amountOutMsat: 100_400_000n, cltvOut: c.blockHeight + 58, policy: null },
      { scid: MIDDLE_SCID, nodeIdOut: c.inPeer, amountOutMsat: 100_200_000n, cltvOut: c.blockHeight + 38, policy: forwarder },
      { scid: c.targetScid, nodeIdOut: c.selfPubkey, amountOutMsat: 100_000_000n, cltvOut: c.blockHeight + 18, policy: forwarder },
    ],
    parts: 1, totalAmountMsat: 100_400_000n, totalFeeMsat: 400_000n, totalTimeLock: c.blockHeight + 58, builtAtHeight: c.blockHeight,
  };
}

function finder(seen: RouteConstraints[], all: 'scripted' | 'none' = 'scripted') {
  return {
    buildCircularRoute: (c: RouteConstraints): Promise<CandidateRoute | NoRoute> => {
      seen.push(c);
      if (all === 'none' || c.targetScid === NO_PATH) return Promise.resolve({ kind: 'no-route', code: 'NO_FEASIBLE_ROUTE', reason: HOSTILE });
      if (c.targetScid === EXPENSIVE) return Promise.resolve(expensiveRoute(c));
      return Promise.resolve(specRoute(c));
    },
  };
}

interface Seeded { path: string; db: { close(): void }; channelIds: Record<string, string> }

async function seeded(): Promise<Seeded> {
  const p = await loadPersistence();
  const path = join(scratch('cp025'), 'fluxwarden.db');
  const db = p.openDatabase(path, { readOnly: false });
  db.nodes.insert({ id: NODE_ID, name: NODE, implementation: 'cln', expectedNetwork: 'regtest', expectedPubkey: NODE_PUBKEY });
  const channelIds: Record<string, string> = {};
  for (const item of channels()) {
    const id = db.channels.upsert(item);
    db.snapshots.record(id, item);
    channelIds[item.channelKey] = id;
  }
  return { path, db, channelIds };
}

function planInput(s: Seeded, seen: RouteConstraints[], over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    db: s.db, node: { id: NODE_ID, name: NODE, pubkey: NODE_PUBKEY, implementation: 'cln' },
    channels: channels(), policy: policy(TARGETS), policySha256: POLICY_SHA, policyCanonicalJson: '{"version":3}',
    blockHeight: HEIGHT, finalCltvDelta: 18, cooldowns: [], reservations: [], routes: finder(seen), clock: fixedClock(), ...over,
  };
}

const parse = (json: string): Record<string, unknown> => JSON.parse(json) as Record<string, unknown>;
const result = (json: string): Record<string, unknown> => parse(json)['result'] as Record<string, unknown>;

function validator(name: 'liquidity-plan' | 'liquidity-explain') {
  const ajv = new Ajv2020.default({ strict: true, allErrors: true });
  return ajv.compile(JSON.parse(readFileSync(join(repoRoot, 'schemas', 'output', `${name}.json`), 'utf8')) as object);
}

function rows(path: string, sql: string): Record<string, unknown>[] {
  const db = raw(path);
  try { return db.prepare(sql).all(); } finally { db.close(); }
}

const CHOSEN_ROUTE = {
  hops: [
    { channel: SOURCE, node_out: peerOf(SOURCE), amount_msat: '100202101', cltv: HEIGHT + 132 },
    { channel: MIDDLE_SCID, node_out: peerOf(TARGET), amount_msat: '100101000', cltv: HEIGHT + 52 },
    { channel: TARGET, node_out: NODE_PUBKEY, amount_msat: '100000000', cltv: HEIGHT + 18 },
  ],
  // F = 202,101; ppm = ceil(2,021.01) = 2,022; Δ = 132; CLN routes carry padding 1 (SPEC §4.4, §4.5; Decision D52).
  fee_msat: '202101', fee_ppm: 2022, cltv_delta: 132, padding: 1,
};

describe('liquidity plan', () => {
  it('CP-025/B1 plan stores one CIRCULAR_REBALANCE proposal whose digest is recomputable from the stored fields', async () => {
    const { liquidityPlan } = await planModule();
    const s = await seeded();
    try {
      const outcome = await liquidityPlan(planInput(s, []));
      expect(outcome.exitCode).toBe(0);
      const doc = result(outcome.json);
      const stored = rows(s.path, 'SELECT * FROM liquidity_proposals');
      expect(stored).toHaveLength(1);
      const row = stored[0] ?? {};
      expect(doc['proposal_id']).toBe(`prop_${String(row['id'])}`);
      expect(row).toMatchObject({
        action_type: 'CIRCULAR_REBALANCE', source_channel_id: s.channelIds[SOURCE], target_channel_id: s.channelIds[TARGET],
        principal_msat: P, max_fee_msat: 300_000n, max_fee_ppm: 2_500n, max_cltv_delta: 144n, demand_source: 'TARGETS',
        status: 'PROPOSED', created_at: BigInt(NOW), expires_at: BigInt(NOW + 15 * MINUTE),
      });
      const expected = referenceDigest({ ...BASE, proposalId: String(row['id']), expiresAt: NOW + 15 * MINUTE });
      expect(row['proposal_digest']).toBe(expected);
      expect(doc['digest']).toBe(expected);
      const versions = rows(s.path, 'SELECT policy_sha256 FROM policy_versions');
      expect(versions).toEqual([{ policy_sha256: POLICY_SHA }]);
      expect(row['policy_version_id']).toBe(rows(s.path, 'SELECT id FROM policy_versions')[0]?.['id']);
    } finally { s.db.close(); }
  });

  it('CP-025/B1 two plans on equal terms store two proposals with distinct digests and one policy version', async () => {
    const { liquidityPlan } = await planModule();
    const s = await seeded();
    try {
      await liquidityPlan(planInput(s, []));
      await liquidityPlan(planInput(s, []));
      const stored = rows(s.path, 'SELECT id, proposal_digest FROM liquidity_proposals');
      expect(stored).toHaveLength(2);
      expect(new Set(stored.map(row => row['proposal_digest'])).size).toBe(2);
      expect(new Set(stored.map(row => row['id'])).size).toBe(2);
      expect(rows(s.path, 'SELECT count(*) AS n FROM policy_versions')).toEqual([{ n: 1n }]);
    } finally { s.db.close(); }
  });

  it('CP-025/B1 a tampered stored field no longer matches the stored digest', async () => {
    const { liquidityPlan } = await planModule();
    const { proposalDigest } = await proposalModule();
    const s = await seeded();
    try {
      await liquidityPlan(planInput(s, []));
      const row = rows(s.path, 'SELECT id, principal_msat, proposal_digest FROM liquidity_proposals')[0] ?? {};
      const fields = { ...BASE, proposalId: String(row['id']), expiresAt: NOW + 15 * MINUTE };
      expect(proposalDigest({ ...fields, principalMsat: row['principal_msat'] as bigint })).toBe(row['proposal_digest']);
      expect(proposalDigest({ ...fields, principalMsat: (row['principal_msat'] as bigint) + 1n })).not.toBe(row['proposal_digest']);
    } finally { s.db.close(); }
  });

  it('CP-025/B3 each pair is assessed with the ppm cap folded into the absolute fee limit, then validated', async () => {
    const { liquidityPlan } = await planModule();
    const s = await seeded();
    const seen: RouteConstraints[] = [];
    try {
      await liquidityPlan(planInput(s, seen));
      // Pairs from RESERVE_BOUND are refused before route discovery; SOURCE pairs with every donor are assessed.
      expect(seen.map(c => c.targetScid).sort()).toEqual([NO_PATH, EXPENSIVE, TARGET].sort());
      expect(seen.find(c => c.targetScid === TARGET)).toEqual({
        selfPubkey: NODE_PUBKEY, implementation: 'cln', sourceScid: SOURCE, targetScid: TARGET, outPeer: peerOf(SOURCE), inPeer: peerOf(TARGET),
        // min(300,000, max(5,000, floor(2,500 × 100,000,000 / 10^6) = 250,000))
        principalMsat: P, maxFeeMsat: 250_000n, maxCltvDelta: 144, finalCltvDelta: 18, blockHeight: HEIGHT,
      });
    } finally { s.db.close(); }
  });

  it('CP-025/B3 the explanation tree lists inputs with confidence, every candidate with its code, the route, fees and CLTV', async () => {
    const { liquidityPlan } = await planModule();
    const s = await seeded();
    try {
      const doc = result((await liquidityPlan(planInput(s, []))).json);
      expect(doc).toMatchObject({
        node: NODE, action: 'CIRCULAR_REBALANCE', status: 'PROPOSED', demand_source: 'TARGETS',
        source_channel: SOURCE, target_channel: TARGET, principal_msat: '100000000',
        caps: { max_fee_msat: '300000', max_fee_ppm: 2500, exempt_fee_msat: '5000', max_cltv_delta: 144 },
        policy_sha256: POLICY_SHA, created_at: NOW, expires_at: NOW + 15 * MINUTE, approvals: [],
      });
      expect(doc['route']).toEqual(CHOSEN_ROUTE);
      expect(doc['candidates']).toEqual([
        { source_channel: RESERVE_BOUND, target_channel: NO_PATH, principal_msat: null, code: 'RESERVE_FLOOR', detail: null, chosen: false },
        { source_channel: RESERVE_BOUND, target_channel: EXPENSIVE, principal_msat: null, code: 'RESERVE_FLOOR', detail: null, chosen: false },
        { source_channel: RESERVE_BOUND, target_channel: TARGET, principal_msat: null, code: 'RESERVE_FLOOR', detail: null, chosen: false },
        { source_channel: SOURCE, target_channel: NO_PATH, principal_msat: '100000000', code: 'NO_FEASIBLE_ROUTE', detail: HOSTILE, chosen: false },
        { source_channel: SOURCE, target_channel: EXPENSIVE, principal_msat: '100000000', code: 'FEE_CEILING_EXCEEDED', detail: null, chosen: false },
        { source_channel: SOURCE, target_channel: TARGET, principal_msat: '100000000', code: null, detail: null, chosen: true },
      ].map(candidate => ({ ...candidate, detail: candidate.detail === null ? null : expect.stringContaining('evil') as unknown })));
      const inputs = doc['inputs'] as Record<string, unknown>[];
      expect(inputs.map(item => item['channel'])).toEqual([RESERVE_BOUND, SOURCE, NO_PATH, EXPENSIVE, TARGET]);
      for (const item of inputs) expect(item).toMatchObject({ confidence: 'NODE_REPORTED', caveat: CLN_CAVEAT, snapshot_age_ms: 5000 });
      expect(inputs.find(item => item['channel'] === SOURCE)).toMatchObject({ spendable_msat: '400000000', receivable_msat: '40000000' });
      // The stored explanation tree is the same document.
      const stored = rows(s.path, 'SELECT reason_json, route_json FROM liquidity_proposals')[0] ?? {};
      const tree = JSON.parse(String(stored['reason_json'])) as { candidates: Record<string, unknown>[]; inputs: unknown; demand_source: unknown };
      expect(tree.demand_source).toBe('TARGETS');
      expect(tree.inputs).toEqual(inputs);
      const brief = (list: Record<string, unknown>[]) => list.map(item => [item['source_channel'], item['target_channel'], item['code'], item['chosen']]);
      expect(brief(tree.candidates)).toEqual(brief(doc['candidates'] as Record<string, unknown>[]));
    } finally { s.db.close(); }
  });

  it('CP-025/B3 with no surviving route the plan stores NO_ACTION with every refusal and exits 0', async () => {
    const { liquidityPlan } = await planModule();
    const s = await seeded();
    try {
      const outcome = await liquidityPlan(planInput(s, [], { routes: finder([], 'none') }));
      expect(outcome.exitCode).toBe(0);
      const doc = result(outcome.json);
      expect(doc).toMatchObject({ action: 'NO_ACTION', source_channel: null, target_channel: null, principal_msat: null, route: null });
      expect((doc['candidates'] as Record<string, unknown>[]).map(item => item['code'])).toEqual([
        'RESERVE_FLOOR', 'RESERVE_FLOOR', 'RESERVE_FLOOR', 'NO_FEASIBLE_ROUTE', 'NO_FEASIBLE_ROUTE', 'NO_FEASIBLE_ROUTE',
      ]);
      expect(rows(s.path, 'SELECT action_type, source_channel_id, principal_msat FROM liquidity_proposals')).toEqual([
        { action_type: 'NO_ACTION', source_channel_id: null, principal_msat: null },
      ]);
      expect(validator('liquidity-plan')(parse(outcome.json))).toBe(true);
    } finally { s.db.close(); }
  });

  it('CP-025/B5 plan --json is one document valid against the schema; numeric msat or a short digest is rejected', async () => {
    const { liquidityPlan } = await planModule();
    const s = await seeded();
    try {
      const outcome = await liquidityPlan(planInput(s, []));
      expect(outcome.json.endsWith('\n')).toBe(true);
      expect(outcome.json.trimEnd().split('\n')).toHaveLength(1);
      const doc = parse(outcome.json);
      expect(doc).toMatchObject({ schema: 1, command: 'liquidity plan', ok: true, warnings: [], error: null });
      const validate = validator('liquidity-plan');
      expect(validate(doc), JSON.stringify(validate.errors)).toBe(true);
      const body = doc['result'] as Record<string, unknown>;
      expect(validate({ ...doc, result: { ...body, principal_msat: 100000000 } })).toBe(false);
      expect(validate({ ...doc, result: { ...body, digest: 'ab'.repeat(16) } })).toBe(false);
      expect(validate({ ...doc, result: { ...body, status: 'EXECUTED' } })).toBe(false);
      expect(validate({ ...doc, result: { ...body, route: null } })).toBe(false);
    } finally { s.db.close(); }
  });
});

describe('liquidity explain', () => {
  async function planned(): Promise<{ s: Seeded; id: string }> {
    const { liquidityPlan } = await planModule();
    const s = await seeded();
    const doc = result((await liquidityPlan(planInput(s, []))).json);
    return { s, id: String(doc['proposal_id']) };
  }

  it('CP-025/B2 expiry is created_at + proposal_ttl; at expires_at the proposal is listed as EXPIRED', async () => {
    const { liquidityExplain } = await explainModule();
    const { s, id } = await planned();
    try {
      const expires = NOW + 15 * MINUTE;
      const before = result(liquidityExplain({ db: s.db, proposalId: id, clock: fixedClock(expires - 1) }).json);
      expect(before).toMatchObject({ status: 'PROPOSED', expires_at: expires });
      const at = liquidityExplain({ db: s.db, proposalId: id, clock: fixedClock(expires) });
      expect(at.exitCode).toBe(0);
      expect(result(at.json)).toMatchObject({ status: 'EXPIRED', expires_at: expires });
    } finally { s.db.close(); }
  });

  it('CP-025/B2 another proposal_ttl gives another expiry', async () => {
    const { liquidityPlan } = await planModule();
    const s = await seeded();
    try {
      const doc = result((await liquidityPlan(planInput(s, [], { policy: { ...policy(TARGETS), proposal_ttl: 7 * MINUTE } }))).json);
      expect(doc['expires_at']).toBe(NOW + 7 * MINUTE);
      expect(rows(s.path, 'SELECT expires_at FROM liquidity_proposals')).toEqual([{ expires_at: BigInt(NOW + 7 * MINUTE) }]);
    } finally { s.db.close(); }
  });

  it('CP-025/B3 explain renders the stored explanation tree with the route, fee checks, confidence and demand source', async () => {
    const { liquidityExplain } = await explainModule();
    const { s, id } = await planned();
    try {
      const outcome = liquidityExplain({ db: s.db, proposalId: id, clock: fixedClock(NOW + MINUTE) });
      expect(outcome.exitCode).toBe(0);
      const doc = result(outcome.json);
      expect(doc).toMatchObject({ proposal_id: id, action: 'CIRCULAR_REBALANCE', status: 'PROPOSED', demand_source: 'TARGETS', route: CHOSEN_ROUTE });
      expect((doc['candidates'] as unknown[]).length).toBe(6);
      for (const needle of [id, String(doc['digest']), POLICY_SHA, 'TARGETS', 'NODE_REPORTED', 'RESERVE_FLOOR', 'NO_FEASIBLE_ROUTE', 'FEE_CEILING_EXCEEDED', '202101', '2022', '100202101', '132']) {
        expect(outcome.text, needle).toContain(needle);
      }
      expect(outcome.text).toContain('An estimate of the total we could send through channel');
    } finally { s.db.close(); }
  });

  it('CP-025/B4 explain on an unknown or malformed id exits 2 with an error document', async () => {
    const { liquidityExplain } = await explainModule();
    const { s } = await planned();
    try {
      const validate = validator('liquidity-explain');
      for (const proposalId of ['prop_01JC5Z0000000000000000000Z', '01JC5Z0000000000000000000Z', '../etc/passwd', '']) {
        const outcome = liquidityExplain({ db: s.db, proposalId, clock: fixedClock() });
        expect(outcome.exitCode, proposalId).toBe(2);
        const doc = parse(outcome.json);
        expect(doc).toMatchObject({ schema: 1, command: 'liquidity explain', ok: false, result: null, error: { code: 2 } });
        expect(validate(doc), JSON.stringify(validate.errors)).toBe(true);
      }
    } finally { s.db.close(); }
  });

  it('CP-025/B4 node-supplied text is rendered escaped in text and JSON', async () => {
    const { liquidityExplain } = await explainModule();
    const { s, id } = await planned();
    try {
      const outcome = liquidityExplain({ db: s.db, proposalId: id, clock: fixedClock() });
      expect(outcome.text.includes('\u001b') || outcome.text.includes('\u202e')).toBe(false);
      expect(outcome.text).toContain('\\x1b[31m');
      expect(outcome.text).toContain('\\u202e');
      expect(outcome.json.includes('\u001b') || outcome.json.includes('\u202e')).toBe(false);
      const detail = (result(outcome.json)['candidates'] as Record<string, unknown>[]).find(item => item['code'] === 'NO_FEASIBLE_ROUTE')?.['detail'];
      expect(detail).toBe('no path \\x1b[31m\\u202eevil');
    } finally { s.db.close(); }
  });

  it('CP-025/B5 explain --json is valid against its schema and equals the document plan printed', async () => {
    const { liquidityPlan } = await planModule();
    const { liquidityExplain } = await explainModule();
    const s = await seeded();
    try {
      const plannedDoc = result((await liquidityPlan(planInput(s, []))).json);
      const outcome = liquidityExplain({ db: s.db, proposalId: String(plannedDoc['proposal_id']), clock: fixedClock() });
      const doc = parse(outcome.json);
      const validate = validator('liquidity-explain');
      expect(validate(doc), JSON.stringify(validate.errors)).toBe(true);
      expect(doc).toMatchObject({ schema: 1, command: 'liquidity explain', ok: true, warnings: [], error: null });
      expect(doc['result']).toEqual(plannedDoc);
    } finally { s.db.close(); }
  });
});
