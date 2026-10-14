// CLN route assessment, read-only. The interface is written down in test/helpers/route-interfaces.ts.
// Upstream facts (Core Lightning v26.06.9): getroutes parameters and path items, doc/schemas/getroutes.json
// #L19-L233 (required source, destination, amount_msat, layers, maxfee_msat, final_cltv; optional maxdelay
// and maxparts); errors 205 no route and 206 too expensive, #L234-L240 and common/jsonrpc_errors.h#L40-L41;
// askrene layer commands, doc/schemas/askrene-*.json and plugins/askrene/askrene.c; xpay and pay settle a
// payment to our own invoice without hops (SPEC §5.4, plugins/xpay/xpay.c "Self-pay? Shortcut all this").
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { loadCapabilities, loadClnRest, loadErrors, rejection, type ClnRest } from '../helpers/adapter-interfaces.js';
import { repoRoot } from '../helpers/cli.js';
import {
  isCandidate, loadClnRoutes, loadRoute, POLICY,
  type CandidateRoute, type NoRoute, type RouteChannel, type RouteConstraints,
} from '../helpers/route-interfaces.js';
import { certificatePath, type FakeServer } from '../fakes/https.js';
import { askrene, type LayerState } from '../fakes/cln/askrene.js';
import { askreneTotalDelay } from '../fakes/cln/askrene-total-delay.js';
import { startFakeCln, type ClnHandler, type FakeCln } from '../fakes/cln/fake-cln.js';
import { channelDirection, CLN_PUBKEY, getroutesAnswer, pathHop, peerChannel } from '../fakes/cln/responses.js';

const scratch = mkdtempSync(join(tmpdir(), 'fw-cp024-'));
const rune = randomBytes(48).toString('base64url');
const runePath = join(scratch, 'test.rune');
writeFileSync(runePath, `${rune}\n`);

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

const SELF = CLN_PUBKEY; // CLN-M
const OUT = `02${'71'.repeat(32)}`; // LND-R, the out-peer over channel 2
const IN = `02${'72'.repeat(32)}`; // CLN-R, the in-peer over channel 5
const MID = `03${'73'.repeat(32)}`;
const S = '102x1x0';
const CH3 = '103x1x0';
const T = '105x1x0';
const EXCLUDED = '104x1x0';
const X = '106x1x0';
const Y = '107x1x0';
const HEIGHT = 812;
const P = 100_000_000n;
const LAYER = 'fluxwarden-01JC0000000000000000000001';

const constraints = (over: Partial<RouteConstraints> = {}): RouteConstraints => ({
  selfPubkey: SELF, implementation: 'cln', sourceScid: S, targetScid: T, outPeer: OUT, inPeer: IN,
  principalMsat: P, maxFeeMsat: 250_000n, maxCltvDelta: 144, finalCltvDelta: 18, blockHeight: HEIGHT, ...over,
});

interface Scenario {
  /** The in-peer's policy for forwarding to us over T (listpeerchannels updates.remote). */
  inPolicy: { base: number; ppm: number; delta: number };
  directions: Record<string, unknown>[];
  answer: Record<string, unknown>;
}

/*
 * SPEC §4.4 / §5.4 C6 worked example: both forwarders base 1,000 msat and 1,000 ppm; CLTV deltas 80 (LND-R on
 * channel 3) and 34 (CLN-R on channel 5); final 18. Backwards from P: CLN-R charges 1,000 + 100,000 = 101,000,
 * LND-R charges 1,000 + 100,101 = 101,101 → (ch2 → LND-R, 100,202,101, Δ132), (ch3 → CLN-R, 100,101,000, Δ52),
 * (ch5 → CLN-M, 100,000,000, Δ18). askrene's own amount_in and cltv_in below are wrong on purpose.
 */
const SPEC_EXAMPLE: Scenario = {
  inPolicy: { base: 1000, ppm: 1000, delta: 34 },
  directions: [
    channelDirection({ scid: CH3, source: OUT, destination: IN, base: 1000, ppm: 1000, delay: 80 }),
    channelDirection({ scid: CH3, source: IN, destination: OUT, base: 5, ppm: 5, delay: 6 }),
  ],
  answer: getroutesAnswer([{ amount: 100_101_000, finalCltv: 52, path: [
    pathHop({ scidDir: `${CH3}/1`, nodeIn: OUT, nodeOut: IN, amountIn: 100_201_000, amountOut: 100_101_000, cltvIn: 130, cltvOut: 52 }),
  ] }]),
};

const SPEC_ROUTE: CandidateRoute = {
  hops: [
    { scid: S, nodeIdOut: OUT, amountOutMsat: 100_202_101n, cltvOut: HEIGHT + 132, policy: null },
    { scid: CH3, nodeIdOut: IN, amountOutMsat: 100_101_000n, cltvOut: HEIGHT + 52, policy: { baseFeeMsat: 1000n, feePpm: 1000n, cltvExpiryDelta: 80, minHtlcMsat: 1n, maxHtlcMsat: 4_950_000_000n } },
    { scid: T, nodeIdOut: SELF, amountOutMsat: 100_000_000n, cltvOut: HEIGHT + 18, policy: { baseFeeMsat: 1000n, feePpm: 1000n, cltvExpiryDelta: 34, minHtlcMsat: 1n, maxHtlcMsat: 4_950_000_000n } },
  ],
  parts: 1, totalAmountMsat: 100_202_101n, totalFeeMsat: 202_101n, totalTimeLock: HEIGHT + 132, builtAtHeight: HEIGHT,
};

/*
 * Two forwarders inside the path, hand-computed backwards from P:
 *   IN on T (updates.remote): base 0, ppm 100, delta 20 → IN receives 100,010,000 (fee 10,000), expiry 812 + 18 + 20 = 850
 *   MID on Y: base 500, ppm 1000, delta 30              → MID receives 100,110,510 (fee 500 + 100,010), expiry 880
 *   OUT on X: base 1000, ppm 500, delta 40              → OUT receives 100,161,565 (fee 1000 + 50,055), expiry 920
 */
const TWO_HOPS: Scenario = {
  inPolicy: { base: 0, ppm: 100, delta: 20 },
  directions: [
    channelDirection({ scid: X, source: OUT, destination: MID, base: 1000, ppm: 500, delay: 40, min: 1000 }),
    channelDirection({ scid: X, source: MID, destination: OUT, base: 9, ppm: 9, delay: 9 }),
    channelDirection({ scid: Y, source: MID, destination: IN, base: 500, ppm: 1000, delay: 30, max: 3_000_000_000 }),
    channelDirection({ scid: Y, source: IN, destination: MID, base: 8, ppm: 8, delay: 8 }),
  ],
  answer: getroutesAnswer([{ amount: 100_010_000, finalCltv: 38, path: [
    pathHop({ scidDir: `${X}/0`, nodeIn: OUT, nodeOut: MID, amountIn: 100_161_565, amountOut: 100_110_510, cltvIn: 108, cltvOut: 68 }),
    pathHop({ scidDir: `${Y}/1`, nodeIn: MID, nodeOut: IN, amountIn: 100_110_510, amountOut: 100_010_000, cltvIn: 68, cltvOut: 38 }),
  ] }]),
};

const TWO_HOPS_ROUTE: CandidateRoute = {
  hops: [
    { scid: S, nodeIdOut: OUT, amountOutMsat: 100_161_565n, cltvOut: 920, policy: null },
    { scid: X, nodeIdOut: MID, amountOutMsat: 100_110_510n, cltvOut: 880, policy: { baseFeeMsat: 1000n, feePpm: 500n, cltvExpiryDelta: 40, minHtlcMsat: 1000n, maxHtlcMsat: 4_950_000_000n } },
    { scid: Y, nodeIdOut: IN, amountOutMsat: 100_010_000n, cltvOut: 850, policy: { baseFeeMsat: 500n, feePpm: 1000n, cltvExpiryDelta: 30, minHtlcMsat: 1n, maxHtlcMsat: 3_000_000_000n } },
    { scid: T, nodeIdOut: SELF, amountOutMsat: 100_000_000n, cltvOut: 830, policy: { baseFeeMsat: 0n, feePpm: 100n, cltvExpiryDelta: 20, minHtlcMsat: 1n, maxHtlcMsat: 4_950_000_000n } },
  ],
  parts: 1, totalAmountMsat: 100_161_565n, totalFeeMsat: 161_565n, totalTimeLock: 920, builtAtHeight: HEIGHT,
};

const PAYMENT_COMMANDS = ['xpay', 'pay', 'sendpay', 'renepay', 'keysend', 'injectpaymentonion', 'sendonion'];

function peerChannels(scenario: Scenario): Record<string, unknown>[] {
  // Our own fee fields and updates.local differ from the in-peer's policy, so reading them shows.
  const updates = (remote: { base: number; ppm: number; delta: number }) => ({
    local: { htlc_minimum_msat: 0, htlc_maximum_msat: 4950000000, cltv_expiry_delta: 6, fee_base_msat: 7, fee_proportional_millionths: 7 },
    remote: { htlc_minimum_msat: 1, htlc_maximum_msat: 4950000000, cltv_expiry_delta: remote.delta, fee_base_msat: remote.base, fee_proportional_millionths: remote.ppm },
  });
  return [
    peerChannel({ peer_id: OUT, short_channel_id: S, channel_id: '21'.repeat(32), fee_base_msat: 7, fee_proportional_millionths: 7, spendable_msat: 400000000, updates: updates({ base: 3, ppm: 3, delta: 3 }) }),
    peerChannel({ peer_id: IN, short_channel_id: T, channel_id: '25'.repeat(32), fee_base_msat: 7, fee_proportional_millionths: 7, receivable_msat: 400000000, updates: updates(scenario.inPolicy) }),
  ];
}

interface Harness { fake: FakeCln; state: LayerState }

async function harness(scenario: Scenario, getroutes?: ClnHandler, overrides: Partial<Record<string, ClnHandler>> = {}, state?: LayerState): Promise<Harness> {
  const layers = askrene(state, overrides);
  const payments = Object.fromEntries(PAYMENT_COMMANDS.map(name => [name, ((context, cln) => { cln.rpcError(context, 'rpc-error', -1, 'not expected'); }) satisfies ClnHandler]));
  const fake = await startFakeCln({
    rune,
    methods: {
      ...layers.methods,
      ...payments,
      listpeerchannels: (context, cln) => { cln.result(context, 'listpeerchannels', { channels: peerChannels(scenario) }); },
      listchannels: (context, cln) => {
        const scid = context.params['short_channel_id'];
        cln.result(context, 'listchannels', { channels: scenario.directions.filter(entry => scid === undefined || entry['short_channel_id'] === scid) });
      },
      getroutes: getroutes ?? ((context, cln) => { cln.result(context, 'getroutes', scenario.answer); }),
      ...overrides,
    },
  });
  open.push(fake);
  return { fake, state: layers.state };
}

async function rest(fake: FakeCln): Promise<ClnRest> {
  const { openClnRest } = await loadClnRest();
  return openClnRest({ host: fake.host, port: fake.port, tlsCertPath: certificatePath('node'), runePath, timeoutMs: 5000 });
}

async function assess(
  h: Harness, c: RouteConstraints = constraints(), excludeScids: readonly string[] = [],
  options?: { profile?: 'v26.06' | 'v26.04' }, client?: ClnRest,
): Promise<CandidateRoute | NoRoute> {
  const { ClnRouteApi } = await loadClnRoutes();
  return new ClnRouteApi(client ?? await rest(h.fake), options).buildCircularRoute(c, { layer: LAYER, excludeScids });
}

const routing = (fake: FakeCln) => fake.calls.filter(call => call.method.startsWith('askrene-') || call.method === 'getroutes');

/** msat parameters may be a JSON integer, a decimal string or "<n>msat" (doc/schemas getroutes.json type msat). */
function msat(value: unknown): bigint {
  if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value);
  if (typeof value === 'string' && /^(?:0|[1-9][0-9]*)(?:msat)?$/.test(value)) return BigInt(value.replace(/msat$/, ''));
  throw new Error(`not an msat parameter: ${JSON.stringify(value)}`);
}

function expectLayerGone(h: Harness): void {
  expect(h.state.layers.size, 'no layer is left behind').toBe(0);
  const methods = routing(h.fake).map(call => call.method);
  expect(methods.filter(method => method === 'askrene-remove-layer')).toHaveLength(1);
  expect(methods.at(-1)).toBe('askrene-remove-layer');
  expect(routing(h.fake).at(-1)?.params).toEqual({ layer: LAYER });
}

it('CP-024/B1 a fresh layer disables our node and both directions of each excluded channel before getroutes', async () => {
  const h = await harness(SPEC_EXAMPLE);
  await assess(h, constraints(), [EXCLUDED]);
  const calls = routing(h.fake);
  expect(calls.map(call => call.method)).toEqual([
    'askrene-create-layer', 'askrene-disable-node', 'askrene-update-channel', 'askrene-update-channel', 'getroutes', 'askrene-remove-layer',
  ]);
  expect(calls[0]?.params['layer']).toBe(LAYER);
  expect(calls[0]?.params['persistent'] ?? false).toBe(false);
  expect(calls[1]?.params).toEqual({ layer: LAYER, node: SELF });
  expect([calls[2]?.params, calls[3]?.params].sort((a, b) => String(a?.['short_channel_id_dir']).localeCompare(String(b?.['short_channel_id_dir'])))).toEqual([
    { layer: LAYER, short_channel_id_dir: `${EXCLUDED}/0`, enabled: false },
    { layer: LAYER, short_channel_id_dir: `${EXCLUDED}/1`, enabled: false },
  ]);
});

it('CP-024/B1 getroutes runs between the peers with the in-hop folded into amount, fee cap and delays, maxparts 1', async () => {
  const h = await harness(SPEC_EXAMPLE);
  await assess(h);
  const calls = routing(h.fake);
  expect(calls.map(call => call.method)).toEqual(['askrene-create-layer', 'askrene-disable-node', 'getroutes', 'askrene-remove-layer']);
  const params = calls[2]?.params ?? {};
  expect(Object.keys(params).sort()).toEqual(['amount_msat', 'destination', 'final_cltv', 'layers', 'maxdelay', 'maxfee_msat', 'maxparts', 'source']);
  expect(params['source']).toBe(OUT);
  expect(params['destination']).toBe(IN);
  // C4/D57: P + CLN-R's fee 101,000; cap 250,000 − 101,000; final 34 + 18.
  // Pinned mcf.c:1409 includes final_cltv in maxdelay; reserve only D52's one-block send padding.
  expect(msat(params['amount_msat'])).toBe(100_101_000n);
  expect(msat(params['maxfee_msat'])).toBe(149_000n);
  expect(params['final_cltv']).toBe(52);
  expect(params['maxdelay']).toBe(143);
  expect(params['maxparts']).toBe(1);
  expect(params['layers']).toEqual(['xpay', LAYER]);
});

it('CP-024/B1 getroutes figures follow the in-peer policy of another target channel', async () => {
  const h = await harness(TWO_HOPS);
  await assess(h, constraints({ maxFeeMsat: 200_000n, maxCltvDelta: 120 }));
  const params = routing(h.fake).find(call => call.method === 'getroutes')?.params ?? {};
  expect(msat(params['amount_msat'])).toBe(100_010_000n);
  expect(msat(params['maxfee_msat'])).toBe(190_000n);
  expect(params['final_cltv']).toBe(38);
  // 120 − 1; final 38 = in-hop delta 20 + final 18 is already included by askrene.
  expect(params['maxdelay']).toBe(119);
});

// D57 reference model and D52 dispatch bound: final 18 + inbound 34 = 52; askrene's middle
// forwarding delta is added once. No fee, principal, policy or CLTV cap is widened.
const delayScenario = (delay: number): Scenario => ({
  ...SPEC_EXAMPLE,
  directions: [channelDirection({ scid: CH3, source: OUT, destination: IN, base: 1000, ppm: 1000, delay })],
});
const delayChannels: RouteChannel[] = [
  { channelKey: S, scid: S, peerPubkey: OUT, state: 'ACTIVE', spendableMsat: 400_000_000n, receivableMsat: 10_000_000n },
  { channelKey: T, scid: T, peerPubkey: IN, state: 'ACTIVE', spendableMsat: 20_000_000n, receivableMsat: 400_000_000n },
];

it.each([{ middle: 80, total: 132 }, { middle: 91, total: 143 }])(
  'CP-024/D57_TOTAL_DELAY pinned askrene accepts final plus middle $total and core retains padding 1',
  async ({ middle, total }) => {
    const scenario = delayScenario(middle);
    const h = await harness(scenario, askreneTotalDelay(middle, scenario.answer));
    const c = constraints({ maxFeeMsat: 300_000n });
    const candidate = await assess(h, c);
    expect(isCandidate(candidate), 'pinned node includes the final 52 in its maxdelay bound').toBe(true);
    if (!isCandidate(candidate)) throw new Error('expected reference-feasible route');
    expect(candidate.totalTimeLock).toBe(HEIGHT + total);
    expect(candidate.hops.map(hop => hop.cltvOut)).toEqual([HEIGHT + total, HEIGHT + 52, HEIGHT + 18]);
    expect(candidate.totalFeeMsat).toBe(202_101n);
    const { validateRoute } = await loadRoute();
    expect(validateRoute(candidate, c, delayChannels, POLICY)).toMatchObject({
      ok: true, feeMsat: 202_101n, feePpm: 2_022n, cltvDelta: total, padding: 1,
    });
    const request = h.fake.calls.find(call => call.method === 'getroutes')?.params ?? {};
    expect(request['maxdelay']).toBe(143);
    expect(request['final_cltv']).toBe(52);
    expect(request['maxparts']).toBe(1);
    expect(msat(request['amount_msat'])).toBe(100_101_000n);
    expect(msat(request['maxfee_msat'])).toBe(199_000n);
    expect(h.fake.calls.some(call => PAYMENT_COMMANDS.includes(call.method))).toBe(false);
    expectLayerGone(h);
  },
);

it('CP-024/D57_OVERBOUND pinned askrene rejects 144 and full assembled route guard rejects an untrusted answer', async () => {
  const scenario = delayScenario(92); // final 52 + middle 92 = 144, plus send padding 1 = 145 > 144.
  const h = await harness(scenario, askreneTotalDelay(92, scenario.answer));
  const c = constraints({ maxFeeMsat: 300_000n });
  expect(await assess(h, c)).toMatchObject({ kind: 'no-route', reason: 'Could not find route without excessive delays' });
  expectLayerGone(h);
  expect(h.fake.calls.some(call => PAYMENT_COMMANDS.includes(call.method))).toBe(false);

  // A faulty transport returning a path above the node request bound cannot bypass INV-16.
  // Recompute using the actual adapter's public assembly, then run the actual public core validator.
  const untrusted = await harness(scenario);
  const candidate = await assess(untrusted, c);
  if (!isCandidate(candidate)) throw new Error('expected candidate from untrusted answer');
  expect(candidate.totalTimeLock).toBe(HEIGHT + 144);
  const { validateRoute } = await loadRoute();
  expect(validateRoute(candidate, c, delayChannels, POLICY)).toMatchObject({ ok: false, code: 'CLTV_DELTA_UNSAFE', check: 'V5' });
  expectLayerGone(untrusted);
  expect(untrusted.fake.calls.some(call => PAYMENT_COMMANDS.includes(call.method))).toBe(false);
});

it('CP-024/B2 the v26.06 hop fields are read; an answer with only the deprecated names is refused as unsupported', async () => {
  const { CapabilityUnsupported } = await loadCapabilities();
  const legacy = getroutesAnswer([{ amount: 100_101_000, finalCltv: 52, path: [
    pathHop({ scidDir: `${CH3}/1`, nodeIn: OUT, nodeOut: IN, amountIn: 100_202_101, amountOut: 100_101_000, cltvIn: 132, cltvOut: 52 }, 'legacy-only'),
  ] }]);
  const fresh = getroutesAnswer([{ amount: 100_101_000, finalCltv: 52, path: [
    pathHop({ scidDir: `${CH3}/1`, nodeIn: OUT, nodeOut: IN, amountIn: 100_202_101, amountOut: 100_101_000, cltvIn: 132, cltvOut: 52 }, 'new-only'),
  ] }]);
  const ok = await harness({ ...SPEC_EXAMPLE, answer: fresh });
  expect(await assess(ok)).toEqual(SPEC_ROUTE);
  const old = await harness(SPEC_EXAMPLE, (context, cln) => { cln.result(context, 'getroutes-legacy', legacy); });
  expect(await rejection(assess(old))).toBeInstanceOf(CapabilityUnsupported);
  expectLayerGone(old);
});

it('CP-024/B2 with the v26.04 profile declared the deprecated names are read as hop starts and give the same route', async () => {
  const legacy = getroutesAnswer([{ amount: 100_010_000, finalCltv: 38, path: [
    pathHop({ scidDir: `${X}/0`, nodeIn: OUT, nodeOut: MID, amountIn: 100_161_565, amountOut: 100_110_510, cltvIn: 108, cltvOut: 68 }, 'legacy-only'),
    pathHop({ scidDir: `${Y}/1`, nodeIn: MID, nodeOut: IN, amountIn: 100_110_510, amountOut: 100_010_000, cltvIn: 68, cltvOut: 38 }, 'legacy-only'),
  ] }]);
  const h = await harness(TWO_HOPS, (context, cln) => { cln.result(context, 'getroutes-legacy', legacy); });
  expect(await assess(h, constraints(), [], { profile: 'v26.04' })).toEqual(TWO_HOPS_ROUTE);
});

it('CP-024/B3 the SPEC worked example assembles out-hop, path and in-hop with amounts and CLTVs recomputed backwards', async () => {
  const h = await harness(SPEC_EXAMPLE);
  expect(await assess(h)).toEqual(SPEC_ROUTE);
});

it('CP-024/B3 two forwarders in the path: each hop carries its sending node\'s policy and the recomputed figures', async () => {
  const h = await harness(TWO_HOPS);
  expect(await assess(h)).toEqual(TWO_HOPS_ROUTE);
});

it('CP-024/B3 the assembled route passes the core validator: F 202,101, ppm 2,022, Δ 132, CLN padding 1', async () => {
  const { validateRoute } = await loadRoute();
  const h = await harness(SPEC_EXAMPLE);
  const candidate = await assess(h);
  if (!isCandidate(candidate)) throw new Error('expected a route');
  const channels: RouteChannel[] = [
    { channelKey: S, scid: S, peerPubkey: OUT, state: 'ACTIVE', spendableMsat: 400_000_000n, receivableMsat: 10_000_000n },
    { channelKey: T, scid: T, peerPubkey: IN, state: 'ACTIVE', spendableMsat: 20_000_000n, receivableMsat: 400_000_000n },
  ];
  expect(validateRoute(candidate, constraints(), channels, POLICY)).toMatchObject({ ok: true, feeMsat: 202_101n, feePpm: 2_022n, cltvDelta: 132, padding: 1 });
});

it('CP-024/B4 the layer is removed after a route, after a refusal and after an exception at every later step', async () => {
  const success = await harness(SPEC_EXAMPLE);
  expect(isCandidate(await assess(success))).toBe(true);
  expectLayerGone(success);

  const refused = await harness(SPEC_EXAMPLE, (context, cln) => { cln.rpcError(context, 'getroutes-no-route', 205, 'Could not find route without excessive cost'); });
  expect(await assess(refused)).toMatchObject({ kind: 'no-route' });
  expectLayerGone(refused);

  const malformed = await harness(SPEC_EXAMPLE, (context, cln) => { cln.raw(context, 'malformed', 201, '{"routes": [ truncated'); });
  await rejection(assess(malformed));
  expectLayerGone(malformed);

  const disableFails = await harness(SPEC_EXAMPLE, undefined, {
    'askrene-disable-node': (context, cln) => { cln.rpcError(context, 'rpc-error', -32602, 'node: should be a node id'); },
  });
  await rejection(assess(disableFails));
  expectLayerGone(disableFails);
  expect(disableFails.fake.calls.some(call => call.method === 'getroutes')).toBe(false);

  const updateFails = await harness(SPEC_EXAMPLE, undefined, {
    'askrene-update-channel': (context, cln) => { cln.rpcError(context, 'rpc-error', -32602, 'short_channel_id_dir: should be a short_channel_id_dir'); },
  });
  await rejection(assess(updateFails, constraints(), [EXCLUDED]));
  expectLayerGone(updateFails);
});

it('CP-024/B4 a layer name already in use is never removed and no route is sought under it', async () => {
  const state: LayerState = { layers: new Map([[LAYER, { disabledNodes: [], channelUpdates: [] }]]) };
  const h = await harness(SPEC_EXAMPLE, undefined, {}, state);
  await rejection(assess(h));
  expect(h.state.layers.has(LAYER)).toBe(true);
  expect(h.fake.calls.map(call => call.method).filter(method => method !== 'listpeerchannels' && method !== 'listchannels')).toEqual(['askrene-create-layer']);
});

it('CP-024/B5 xpay, pay and sendpay are never invoked: runtime spy over success, refusal and failure', async () => {
  const allowed = new Set(['askrene-create-layer', 'askrene-disable-node', 'askrene-update-channel', 'askrene-remove-layer', 'getroutes', 'listpeerchannels', 'listchannels', 'getinfo']);
  const answers: (ClnHandler | undefined)[] = [
    undefined,
    (context, cln) => { cln.rpcError(context, 'getroutes-too-expensive', 206, 'Could not find route without excessive cost'); },
    (context, cln) => { cln.raw(context, 'malformed', 201, 'not json'); },
  ];
  for (const answer of answers) {
    const h = await harness(SPEC_EXAMPLE, answer);
    const real = await rest(h.fake);
    const methods: string[] = [];
    const spy: ClnRest = { call: (method, params) => { methods.push(method); return real.call(method, params); } };
    await assess(h, constraints(), [EXCLUDED], undefined, spy).catch(() => undefined);
    expect(methods.length).toBeGreaterThan(0);
    for (const method of methods) expect(allowed.has(method), method).toBe(true);
    expect(h.fake.calls.filter(call => PAYMENT_COMMANDS.includes(call.method))).toEqual([]);
  }
});

it('CP-024/B5 the route module and its imports name no payment command (import graph)', () => {
  const seen = new Map<string, string>();
  const visit = (file: string): void => {
    if (seen.has(file)) return;
    const text = readFileSync(file, 'utf8');
    seen.set(file, text);
    for (const match of text.matchAll(/(?:from\s+|import\s*\(\s*|import\s+)['"](\.{1,2}\/[^'"]+)['"]/g)) visit(resolve(dirname(file), (match[1] ?? '').replace(/\.js$/, '.ts')));
  };
  visit(join(repoRoot, 'src', 'node-cln', 'routes.ts'));
  expect(seen.size).toBeGreaterThan(0);
  for (const [file, text] of seen) {
    // 'xpay' is a layer name in getroutes, so pay and xpay are refused only as the method of a call.
    expect(text, file).not.toMatch(/\.call\(\s*['"`](?:x?pay)['"`]/);
    expect(text, file).not.toMatch(/['"`](?:sendpay|renepay|keysend|injectpaymentonion|sendonion)['"`]/);
  }
});

it('CP-024/B6 getroutes 205 is NO_FEASIBLE_ROUTE, 206 is FEE_CEILING_EXCEEDED, two routes are SINGLE_PATH_UNAVAILABLE', async () => {
  const twoRoutes = getroutesAnswer([
    { amount: 50_050_500, finalCltv: 52, path: [pathHop({ scidDir: `${CH3}/1`, nodeIn: OUT, nodeOut: IN, amountIn: 50_101_550, amountOut: 50_050_500, cltvIn: 132, cltvOut: 52 })] },
    { amount: 50_050_500, finalCltv: 52, path: [pathHop({ scidDir: `${X}/0`, nodeIn: OUT, nodeOut: IN, amountIn: 50_101_550, amountOut: 50_050_500, cltvIn: 132, cltvOut: 52 })] },
  ]);
  const cases: [ClnHandler, string][] = [
    [(context, cln) => { cln.rpcError(context, 'getroutes-no-route', 205, 'Could not find route'); }, 'NO_FEASIBLE_ROUTE'],
    [(context, cln) => { cln.rpcError(context, 'getroutes-too-expensive', 206, 'Could not find route without excessive cost'); }, 'FEE_CEILING_EXCEEDED'],
    [(context, cln) => { cln.result(context, 'getroutes', twoRoutes); }, 'SINGLE_PATH_UNAVAILABLE'],
  ];
  for (const [answer, code] of cases) {
    const h = await harness(SPEC_EXAMPLE, answer);
    expect(await assess(h), code).toMatchObject({ kind: 'no-route', code });
    expectLayerGone(h);
  }
  const errors = await loadErrors();
  const other = await harness(SPEC_EXAMPLE, (context, cln) => { cln.rpcError(context, 'rpc-error', -1, 'Catchall nonspecific error'); });
  expect(await rejection(assess(other))).toBeInstanceOf(errors.ClnError);
  expectLayerGone(other);
});
