// LND route assessment, read-only. The interface is written down in test/helpers/route-interfaces.ts.
// Upstream facts (lnd v0.21.4-beta): QueryRoutesRequest fields, lnrpc/lightning.proto#L3086-L3213;
// REST binding POST /v1/graph/routes/{pub_key}/{amt} with body "*", lnrpc/lightning.yaml#L105-L109;
// the path amt overrides the body and is in sat, so the msat amount travels as amt_msat with amt 0
// (lnrpc/lightning.pb.gw.go#L1742-L1750, lnrpc/marshall_utils.go#L58-L61); cltv_limit includes the
// final delta and QueryRoutes adds no padding (router_backend.go#L388-L411, lightning.proto#L3106-L3116).
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { loadErrors, loadLndRest, rejection, type LndRest } from '../helpers/adapter-interfaces.js';
import { repoRoot } from '../helpers/cli.js';
import {
  isCandidate, loadLndRoutes, loadRoute, POLICY,
  type CandidateRoute, type NoRoute, type RouteChannel, type RouteConstraints,
} from '../helpers/route-interfaces.js';
import { certificatePath, type FakeServer } from '../fakes/https.js';
import { queryRoutesRequest, startFakeLnd, type FakeLnd, type LndContext, type LndRoute } from '../fakes/lnd/fake-lnd.js';
import { b64, channelEdge, LND_PUBKEY, PEER_A, PEER_B, route, routeHop, routingPolicy } from '../fakes/lnd/responses.js';

const scratch = mkdtempSync(join(tmpdir(), 'fw-cp023-'));
const macaroon = randomBytes(96);
const macaroonHex = macaroon.toString('hex');
const macaroonPath = join(scratch, 'test.macaroon');
writeFileSync(macaroonPath, macaroon);

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

const SELF = LND_PUBKEY;
const A = PEER_A; // out-peer, 03b2...
const B = PEER_B; // in-peer, 02c3...
const C = `02${'0d'.repeat(32)}`; // middle node; sorts before A and B, so node1 on X and Y
const S = '812x1x0';
const X = '813x2x1';
const Y = '814x3x0';
const T = '815x1x1';
const S2 = '816x4x0';
// chan_id = block << 40 | tx << 16 | output (BOLT 7 short_channel_id), computed by hand:
const CHAN: Readonly<Record<string, string>> = {
  [S]: '892803441819648', [X]: '893902953512961', [Y]: '895002465206272', [T]: '896101976702977', [S2]: '897201488527360',
};
const HEIGHT = 900;
const P = 100_000_000n;

const constraints = (over: Partial<RouteConstraints> = {}): RouteConstraints => ({
  selfPubkey: SELF, implementation: 'lnd', sourceScid: S, targetScid: T, outPeer: A, inPeer: B,
  principalMsat: P, maxFeeMsat: 240_000n, maxCltvDelta: 144, finalCltvDelta: 18, blockHeight: HEIGHT, ...over,
});

/*
 * The route LND answers, hand-computed backwards from P with these policies (fee = base + floor(a × ppm / 10^6)):
 *   A on X: base 1000, ppm 500, delta 40;  C on Y: base 500, ppm 1000, delta 30;  B on T: base 0, ppm 100, delta 20.
 *   B forwards P = 100,000,000: fee 10,000          → B receives 100,010,000, expiry in 900 + 18 + 20 = 938
 *   C forwards 100,010,000: fee 500 + 100,010       → C receives 100,110,510, expiry in 938 + 30 = 968
 *   A forwards 100,110,510: fee 1000 + 50,055       → A receives 100,161,565, expiry in 968 + 40 = 1008
 * LND's hop k carries what node k forwards (amt_to_forward_msat, fee_msat, expiry); total_time_lock is
 * the first HTLC's expiry (lightning.proto#L3256-L3336, #L3372-L3425).
 */
function lndRoute(sat?: 'zero' | 'skewed'): Record<string, unknown> {
  const satFields = (forward: string, fee: string): Pick<Parameters<typeof routeHop>[0], 'sat'> =>
    sat === 'zero' ? { sat: { amtToForward: '0', fee: '0' } } : sat === 'skewed' ? { sat: { amtToForward: forward, fee } } : {};
  return route(1008, 100_161_565n, 161_565n, [
    routeHop({ chanId: CHAN[S] ?? '', pubKey: A, forwardMsat: 100_110_510n, feeMsat: 51_055n, expiry: 968, ...satFields('100111', '52') }),
    routeHop({ chanId: CHAN[X] ?? '', pubKey: C, forwardMsat: 100_010_000n, feeMsat: 100_510n, expiry: 938, ...satFields('100011', '101') }),
    routeHop({ chanId: CHAN[Y] ?? '', pubKey: B, forwardMsat: 100_000_000n, feeMsat: 10_000n, expiry: 918, ...satFields('100001', '11') }),
    routeHop({ chanId: CHAN[T] ?? '', pubKey: SELF, forwardMsat: 100_000_000n, feeMsat: 0n, expiry: 918, ...satFields('100001', '1') }),
  ]);
}

// Each edge also carries the other direction's policy with different values, so reading the wrong side shows.
const EDGES: Readonly<Record<string, Record<string, unknown>>> = {
  [CHAN[X] ?? '']: channelEdge(CHAN[X] ?? '', A, C, {
    [A]: routingPolicy({ timeLockDelta: 40, baseMsat: 1000, rateMilliMsat: 500, minHtlcMsat: '1000', maxHtlcMsat: '4950000000' }),
    [C]: routingPolicy({ timeLockDelta: 144, baseMsat: 9999, rateMilliMsat: 9999 }),
  }),
  [CHAN[Y] ?? '']: channelEdge(CHAN[Y] ?? '', C, B, {
    [C]: routingPolicy({ timeLockDelta: 30, baseMsat: 500, rateMilliMsat: 1000, minHtlcMsat: '2000', maxHtlcMsat: '3000000000' }),
    [B]: routingPolicy({ timeLockDelta: 99, baseMsat: 7777, rateMilliMsat: 7777 }),
  }),
  // Only reached by the hostile route that repeats S.
  [CHAN[S] ?? '']: channelEdge(CHAN[S] ?? '', SELF, A, {
    [SELF]: routingPolicy({ timeLockDelta: 10, baseMsat: 0, rateMilliMsat: 0 }),
    [A]: routingPolicy({ timeLockDelta: 10, baseMsat: 0, rateMilliMsat: 0 }),
  }),
  [CHAN[T] ?? '']: channelEdge(CHAN[T] ?? '', B, SELF, {
    [B]: routingPolicy({ timeLockDelta: 20, baseMsat: 0, rateMilliMsat: 100, minHtlcMsat: '1', maxHtlcMsat: '990000000' }),
    [SELF]: routingPolicy({ timeLockDelta: 50, baseMsat: 3333, rateMilliMsat: 3333 }),
  }),
};

const EXPECTED: CandidateRoute = {
  hops: [
    { scid: S, nodeIdOut: A, amountOutMsat: 100_161_565n, cltvOut: 1008, policy: null },
    { scid: X, nodeIdOut: C, amountOutMsat: 100_110_510n, cltvOut: 968, policy: { baseFeeMsat: 1000n, feePpm: 500n, cltvExpiryDelta: 40, minHtlcMsat: 1000n, maxHtlcMsat: 4_950_000_000n } },
    { scid: Y, nodeIdOut: B, amountOutMsat: 100_010_000n, cltvOut: 938, policy: { baseFeeMsat: 500n, feePpm: 1000n, cltvExpiryDelta: 30, minHtlcMsat: 2000n, maxHtlcMsat: 3_000_000_000n } },
    { scid: T, nodeIdOut: SELF, amountOutMsat: 100_000_000n, cltvOut: 918, policy: { baseFeeMsat: 0n, feePpm: 100n, cltvExpiryDelta: 20, minHtlcMsat: 1n, maxHtlcMsat: 990_000_000n } },
  ],
  parts: 1, totalAmountMsat: 100_161_565n, totalFeeMsat: 161_565n, totalTimeLock: 1008, builtAtHeight: HEIGHT,
};

type RouteAnswer = (context: LndContext, lnd: FakeLnd, body: Record<string, unknown>) => void;

const edgeRoute: LndRoute = (context, lnd) => {
  const edge = EDGES[context.params['chan_id'] ?? ''];
  if (edge === undefined) { lnd.grpcError(context, 'grpc-error', 2, 'edge not found'); return; }
  lnd.answer(context, 'getchaninfo', edge);
};

async function fakeLnd(answer: RouteAnswer): Promise<FakeLnd> {
  const fake = await startFakeLnd({
    macaroonHex,
    routes: {
      'POST /v1/graph/routes/{pub_key}/{amt}': (context, lnd) => {
        const body = queryRoutesRequest(context, lnd);
        if (body !== null) answer(context, lnd, body);
      },
      'GET /v1/graph/edge/{chan_id}': edgeRoute,
    },
  });
  open.push(fake);
  return fake;
}

const answerRoute = (value: Record<string, unknown>): RouteAnswer => (context, lnd) => { lnd.answer(context, 'queryroutes', { routes: [value], success_prob: 0.82 }); };

async function rest(fake: FakeLnd): Promise<LndRest> {
  const { openLndRest } = await loadLndRest();
  return openLndRest({ host: fake.host, port: fake.port, tlsCertPath: certificatePath('node'), macaroonPath, timeoutMs: 5000 });
}

async function assess(fake: FakeLnd, c: RouteConstraints = constraints(), client?: LndRest): Promise<CandidateRoute | NoRoute> {
  const { LndRouteApi } = await loadLndRoutes();
  return new LndRouteApi(client ?? await rest(fake)).buildCircularRoute(c);
}

const routeRequests = (fake: FakeLnd) => fake.requests.filter(request => request.url.startsWith('/v1/graph/routes/'));

it('CP-023/B1 QueryRoutes is one POST to /v1/graph/routes/{self}/0 with exactly the pinned body fields', async () => {
  const fake = await fakeLnd(answerRoute(lndRoute()));
  await assess(fake);
  const sent = routeRequests(fake);
  expect(sent).toHaveLength(1);
  expect(sent[0]?.method).toBe('POST');
  expect(sent[0]?.url).toBe(`/v1/graph/routes/${SELF}/0`);
  const body = JSON.parse(sent[0]?.body ?? '{}') as Record<string, unknown>;
  expect(Object.keys(body).sort()).toEqual([
    'amt_msat', 'cltv_limit', 'fee_limit', 'final_cltv_delta', 'ignored_pairs', 'last_hop_pubkey', 'outgoing_chan_ids', 'use_mission_control',
  ]);
  expect(body).not.toHaveProperty('outgoing_chan_id');
  expect(body['amt_msat']).toBe('100000000');
  expect(body['final_cltv_delta']).toBe(18);
  expect(body['fee_limit']).toEqual({ fixed_msat: '240000' });
  expect(body['outgoing_chan_ids']).toEqual([CHAN[S]]);
  // bytes fields over REST are standard base64 (lightning.proto#L3215-L3227 NodePair; #L3177 last_hop_pubkey)
  expect(body['last_hop_pubkey']).toBe(b64(B));
  // cltv_limit counts the final delta; 3 blocks are kept back for LND's send padding (SPEC §5.3 L3, §4.5)
  expect(body['cltv_limit']).toBe(141);
  const pairs = (body['ignored_pairs'] as { from: string; to: string }[]).map(pair => `${pair.from}>${pair.to}`).sort();
  expect(pairs).toEqual([`${b64(A)}>${b64(SELF)}`, `${b64(SELF)}>${b64(B)}`].sort());
  expect(body['use_mission_control']).toBe(true);
});

it('CP-023/B1 the body follows the constraints: another source, cap and CLTV bound', async () => {
  const fake = await fakeLnd((context, lnd) => { lnd.grpcError(context, 'queryroutes-no-path', 2, 'unable to find a path to destination'); });
  await assess(fake, constraints({ sourceScid: S2, maxFeeMsat: 5_000n, maxCltvDelta: 100, finalCltvDelta: 40, principalMsat: 25_000_123n }));
  const body = JSON.parse(routeRequests(fake)[0]?.body ?? '{}') as Record<string, unknown>;
  expect(body['outgoing_chan_ids']).toEqual([CHAN[S2]]);
  expect(body['fee_limit']).toEqual({ fixed_msat: '5000' });
  expect(body['cltv_limit']).toBe(97);
  expect(body['final_cltv_delta']).toBe(40);
  expect(body['amt_msat']).toBe('25000123');
});

it('CP-023/B2 the single route becomes hop-end amounts and expiries with each sending node\'s policy', async () => {
  const fake = await fakeLnd(answerRoute(lndRoute()));
  expect(await assess(fake)).toEqual(EXPECTED);
  const edges = fake.requests.filter(request => request.url.startsWith('/v1/graph/edge/')).map(request => `${request.method} ${request.url}`).sort();
  expect(edges).toEqual([CHAN[X], CHAN[Y], CHAN[T]].map(id => `GET /v1/graph/edge/${id ?? ''}`).sort());
});

it('CP-023/B2 only the _msat hop fields are read: zeroed or disagreeing sat fields change nothing', async () => {
  for (const variant of ['zero', 'skewed'] as const) {
    const fake = await fakeLnd(answerRoute(lndRoute(variant)));
    expect(await assess(fake), variant).toEqual(EXPECTED);
  }
});

it('CP-023/B2 an answer with other than exactly one route is a protocol error', async () => {
  const errors = await loadErrors();
  for (const routes of [[], [lndRoute(), lndRoute()]]) {
    const fake = await fakeLnd((context, lnd) => { lnd.answer(context, 'queryroutes', { routes, success_prob: 0.5 }); });
    expect(await rejection(assess(fake)), `${String(routes.length)} routes`).toBeInstanceOf(errors.ProtocolError);
  }
});

it('CP-023/B3 LND\'s no-path answer is NO_FEASIBLE_ROUTE', async () => {
  const fake = await fakeLnd((context, lnd) => { lnd.grpcError(context, 'queryroutes-no-path', 2, 'unable to find a path to destination'); });
  const result = await assess(fake);
  expect(result).toMatchObject({ kind: 'no-route', code: 'NO_FEASIBLE_ROUTE' });
});

it('CP-023/B3 a fee limit below the only route surfaces as no path and is NO_FEASIBLE_ROUTE, not a fee refusal', async () => {
  // pathfind.go#L823-L825: an edge whose total fee exceeds FeeLimit is skipped, so the search ends with errNoPathFound.
  const answer: RouteAnswer = (context, lnd, body) => {
    const limit = BigInt((body['fee_limit'] as { fixed_msat?: string } | undefined)?.fixed_msat ?? '0');
    if (limit < 161_565n) lnd.grpcError(context, 'queryroutes-no-path', 2, 'unable to find a path to destination');
    else answerRoute(lndRoute())(context, lnd, body);
  };
  const fake = await fakeLnd(answer);
  expect(await assess(fake, constraints({ maxFeeMsat: 161_564n }))).toMatchObject({ kind: 'no-route', code: 'NO_FEASIBLE_ROUTE' });
  expect(await assess(fake, constraints({ maxFeeMsat: 161_565n }))).toEqual(EXPECTED);
});

it('CP-023/B3 other LND errors are not turned into a refusal', async () => {
  const errors = await loadErrors();
  const fake = await fakeLnd((context, lnd) => { lnd.grpcError(context, 'grpc-error', 2, 'total time lock of 2017 exceeds max allowed 2016'); });
  const error = await rejection(assess(fake));
  expect(error).toBeInstanceOf(errors.LndError);
  expect((error as InstanceType<typeof errors.LndError>).grpcCode).toBe(2);
});

const CHANNELS: RouteChannel[] = [
  { channelKey: CHAN[S] ?? '', scid: S, peerPubkey: A, state: 'ACTIVE', spendableMsat: 400_000_000n, receivableMsat: 10_000_000n },
  { channelKey: CHAN[T] ?? '', scid: T, peerPubkey: B, state: 'ACTIVE', spendableMsat: 20_000_000n, receivableMsat: 400_000_000n },
];

it('CP-023/B4 the normalized route passes the core validator with the recomputed fee, ppm and CLTV delta', async () => {
  const { validateRoute } = await loadRoute();
  const fake = await fakeLnd(answerRoute(lndRoute()));
  const candidate = await assess(fake);
  if (!isCandidate(candidate)) throw new Error('expected a route');
  // F = 100,161,565 − P = 161,565; ppm = ceil(1,615.65) = 1,616; Δ = 1008 − 900 = 108, padding 3.
  expect(validateRoute(candidate, constraints(), CHANNELS, POLICY)).toMatchObject({ ok: true, feeMsat: 161_565n, feePpm: 1_616n, cltvDelta: 108, padding: 3 });
});

it('CP-023/B4 a route repeating the out channel or ending at the out peer is refused by the core validator', async () => {
  const { validateRoute } = await loadRoute();
  const hostile = (hops: Record<string, unknown>[]): RouteAnswer => answerRoute(route(1008, 100_161_565n, 161_565n, hops));
  const repeat = hostile([
    routeHop({ chanId: CHAN[S] ?? '', pubKey: A, forwardMsat: 100_110_510n, feeMsat: 51_055n, expiry: 968 }),
    routeHop({ chanId: CHAN[X] ?? '', pubKey: C, forwardMsat: 100_010_000n, feeMsat: 100_510n, expiry: 938 }),
    routeHop({ chanId: CHAN[S] ?? '', pubKey: B, forwardMsat: 100_000_000n, feeMsat: 10_000n, expiry: 918 }),
    routeHop({ chanId: CHAN[T] ?? '', pubKey: SELF, forwardMsat: 100_000_000n, feeMsat: 0n, expiry: 918 }),
  ]);
  const viaOutPeer = hostile([
    routeHop({ chanId: CHAN[S] ?? '', pubKey: A, forwardMsat: 100_110_510n, feeMsat: 51_055n, expiry: 968 }),
    routeHop({ chanId: CHAN[X] ?? '', pubKey: C, forwardMsat: 100_010_000n, feeMsat: 100_510n, expiry: 938 }),
    routeHop({ chanId: CHAN[Y] ?? '', pubKey: A, forwardMsat: 100_000_000n, feeMsat: 10_000n, expiry: 918 }),
    routeHop({ chanId: CHAN[T] ?? '', pubKey: SELF, forwardMsat: 100_000_000n, feeMsat: 0n, expiry: 918 }),
  ]);
  for (const [answer, code, check] of [[repeat, 'REPEATED_CHANNEL', 'V2'], [viaOutPeer, 'NO_FEASIBLE_ROUTE', 'V1']] as const) {
    const fake = await fakeLnd(answer);
    const candidate = await assess(fake);
    if (!isCandidate(candidate)) throw new Error('the adapter must hand the route to the validator, not drop it');
    expect(candidate.hops.map(hop => hop.scid)).toEqual(code === 'REPEATED_CHANNEL' ? [S, X, S, T] : [S, X, Y, T]);
    expect(validateRoute(candidate, constraints(), CHANNELS, POLICY)).toEqual({ ok: false, code, check });
  }
});

/** Every relative module reachable from `entry` by static or dynamic import. */
function moduleGraph(entry: string): Map<string, string> {
  const seen = new Map<string, string>();
  const visit = (file: string): void => {
    if (seen.has(file)) return;
    const text = readFileSync(file, 'utf8');
    seen.set(file, text);
    for (const match of text.matchAll(/(?:from\s+|import\s*\(\s*|import\s+)['"](\.{1,2}\/[^'"]+)['"]/g)) {
      visit(resolve(dirname(file), (match[1] ?? '').replace(/\.js$/, '.ts')));
    }
  };
  visit(entry);
  return seen;
}

it('CP-023/B5 no send endpoint is reachable from the route module (import graph)', () => {
  const graph = moduleGraph(join(repoRoot, 'src', 'node-lnd', 'routes.ts'));
  expect(graph.size).toBeGreaterThan(0);
  for (const [file, text] of graph) {
    expect(text, file).not.toMatch(/\/v2\/router\/(?:route\/send|send)\b/);
  }
});

it('CP-023/B5 a full assessment makes read calls only (runtime spy on the transport and the node)', async () => {
  const fake = await fakeLnd(answerRoute(lndRoute()));
  const real = await rest(fake);
  const calls: string[] = [];
  const spy: LndRest = {
    call: (method, path, body) => { calls.push(`${method} ${path}`); return real.call(method, path, body); },
    stream: (method, path, body, onMessage, signal) => { calls.push(`STREAM ${method} ${path}`); return real.stream(method, path, body, onMessage, signal); },
  };
  expect(isCandidate(await assess(fake, constraints(), spy))).toBe(true);
  expect(calls.length).toBe(4);
  for (const call of calls) expect(call).toMatch(/^(?:POST \/v1\/graph\/routes\/[0-9a-f]{66}\/0|GET \/v1\/graph\/edge\/\d+)$/);
  expect(fake.requests.some(request => request.url.startsWith('/v2/'))).toBe(false);
});
