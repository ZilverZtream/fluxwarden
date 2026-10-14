/*
 * Interface: the snapshot collector of `fluxwarden daemon --collect` (SPEC.md §10.4 DM1, DM2, DM4 collector, DM6).
 *
 * CLI: fluxwarden daemon --collect --config <path>
 *   G1-G4, then G5 for every configured node (an unreachable node is marked OFFLINE and retried), then collection
 *   cycles until a signal. The first SIGINT or SIGTERM lets the current cycle finish (its snapshots are stored) and
 *   exits 0 without starting another cycle; a second signal exits at once with 6 (INTERRUPTED).
 *   Configuration as the read-only commands, plus `collect_interval: <int>(s|m|h|d)` (design default 15s).
 *
 * src/daemon/collector.ts
 *   export interface CollectorTimers {
 *     monotonic(): number;                                  // ms, never steps (production: performance.now())
 *     wall(): number;                                       // ms since the epoch, may step (production: Date.now());
 *                                                           // never used for cadence, backoff or timeouts
 *     sleep(ms: number, signal: AbortSignal): Promise<void>; // waits `ms` of monotonic time; resolves early, never
 *                                                           // rejects, when `signal` aborts
 *   }
 *   export interface CollectorNodeReport {
 *     name: string;
 *     state: 'ONLINE' | 'OFFLINE' | 'QUARANTINED' | 'NOT_SYNCED';
 *     channels: number;     // snapshots stored for the node in this cycle
 *     payments: number;     // payment entries read in this cycle
 *     incomplete: boolean;  // the payment listing stopped at its page bound with more entries remaining
 *   }
 *   export interface CollectorCycle { cycle: number; startedAt: number; nodes: CollectorNodeReport[] }  // 1-based,
 *                                                           // monotonic ms, nodes by name
 *   export interface CollectorOptions {
 *     configPath: string;
 *     timers: CollectorTimers;
 *     signal: AbortSignal;               // abort: finish the current cycle, then resolve
 *     output: RenderOutput;              // src/output createOutput(); warnings are text lines on stderr
 *     onCycle?: (cycle: CollectorCycle) => void;
 *   }
 *   export interface CollectorResult { cycles: number; exitCode: number }
 *   export function runCollector(options: CollectorOptions): Promise<CollectorResult>;
 *
 * Cycle k (k = 1, 2, ...) starts at monotonic t0 + (k - 1) * interval: the cadence is fixed-rate on the monotonic
 * clock, whatever the wall clock does and however long a cycle's node calls take (when shorter than the interval).
 * The first cycle starts at once. Per node and cycle: the identity call (GetInfo / getinfo, SPEC §5.2 H2-H4),
 * then, only when the node is synced to chain (ARCHITECTURE.md §3 step 1), its channel listing, stored as one
 * snapshot per channel. A channel listing over 10,000 entries is a protocol error: nothing of it is stored.
 * Payments (LND ListPayments include_incomplete=true, max_payments=500, paged by index_offset; CLN listsendpays) are
 * read from where the previous cycle stopped, at most 200 pages per cycle; when the bound stops the listing with
 * entries remaining the cycle reports `incomplete` and the next cycle continues from there (SECURITY.md §5 bounds).
 * A read that fails (transport, TLS, authentication, protocol) marks the node OFFLINE; it is retried with a backoff
 * of 1 s rising to at most 15 s on the monotonic clock, never sooner than 1 s after a failure. Warnings, one line
 * each on stderr naming the node, only on a state change: `node-offline` (into OFFLINE), `node-online` (OFFLINE
 * back to ONLINE), `node-not-synced` (into NOT_SYNCED). The collector issues no mutating call (INV-02).
 */
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { pathToFileURL } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import type { LndContext, LndRoute } from '../fakes/lnd/fake-lnd.js';
import { certificatePath } from '../fakes/https.js';
import { channel as lndChannel, getInfo, LND_PUBKEY, payment, PEER_B } from '../fakes/lnd/responses.js';
import { CLN_PUBKEY, peerChannel } from '../fakes/cln/responses.js';
import { repoRoot } from '../helpers/cli.js';
import { capturedSink, outputModule } from '../helpers/output.js';
import {
  clnNode, createDatabase, lndNode, MISSION_CONTROL, NO_PENDING, scratch, snapshotCount, spawnCli, writeConfig, type NodeEntry, type Run,
} from '../helpers/cp016-cli.js';

interface CollectorTimers { monotonic(): number; wall(): number; sleep(ms: number, signal: AbortSignal): Promise<void> }
interface CollectorNodeReport { name: string; state: string; channels: number; payments: number; incomplete: boolean }
interface CollectorCycle { cycle: number; startedAt: number; nodes: CollectorNodeReport[] }
interface CollectorModule {
  runCollector: (options: {
    configPath: string; timers: CollectorTimers; signal: AbortSignal; output: unknown; onCycle?: (cycle: CollectorCycle) => void;
  }) => Promise<{ cycles: number; exitCode: number }>;
}

async function collector(): Promise<CollectorModule> {
  return await import(pathToFileURL(join(repoRoot, 'dist/daemon/collector.js')).href) as CollectorModule;
}

/** Virtual monotonic time: only sleeps and the fake nodes' handlers advance it. */
class VirtualTimers implements CollectorTimers {
  now = 0;
  wallBase = 1_760_000_000_000;
  readonly sleeps: number[] = [];
  readonly controller = new AbortController();
  stopWhen: () => boolean = () => false;
  monotonic = (): number => this.now;
  wall = (): number => this.wallBase + this.now;
  sleep = (ms: number, signal: AbortSignal): Promise<void> => {
    this.sleeps.push(ms);
    if (!signal.aborted && ms > 0) this.now += ms;
    if (this.stopWhen()) this.controller.abort();
    return new Promise(resolve => setImmediate(resolve));
  };
}

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

const lndEntry = (name: string, url: string, credential: string): NodeEntry =>
  ({ name, implementation: 'lnd', url, tlsCert: certificatePath('node'), credential, expectedPubkey: LND_PUBKEY });
const clnEntry = (name: string, url: string, credential: string): NodeEntry =>
  ({ name, implementation: 'cln', url, tlsCert: certificatePath('node'), credential, expectedPubkey: CLN_PUBKEY });

const SECOND_CHANNEL = lndChannel({ chan_id: '892946470614859777', channel_point: `${'cd'.repeat(32)}:0`, remote_pubkey: PEER_B });

async function run(configPath: string, timers: VirtualTimers, onCycle?: (cycle: CollectorCycle) => void): Promise<{ result: { cycles: number; exitCode: number }; stderr: () => string }> {
  const [{ runCollector }, { createOutput }] = await Promise.all([collector(), outputModule()]);
  const stderr = capturedSink();
  const output = createOutput({ stdout: capturedSink().sink, stderr: stderr.sink, secrets: [] });
  const result = await runCollector({ configPath, timers, signal: timers.controller.signal, output, ...(onCycle === undefined ? {} : { onCycle }) });
  return { result, stderr: () => stderr.text() };
}

const linesWith = (text: string, code: string, node: string): number =>
  text.split('\n').filter(line => line.includes(code) && line.includes(node)).length;

describe('CP-017 cadence', () => {
  it('CP-017/B1 cycles start one interval apart on the monotonic clock whatever the wall clock and the node latency', async () => {
    const dir = scratch('cp017-b1');
    const timers = new VirtualTimers();
    const arrivals: number[] = [];
    const lnd = await lndNode(dir, open, {
      channels: [lndChannel()],
      routes: {
        'GET /v1/channels': (ctx, f) => {
          arrivals.push(timers.now);
          // A slow node: each listing takes 2.5 s of monotonic time. The wall clock steps back an hour, then forward two.
          timers.now += 2500;
          if (arrivals.length === 2) timers.wallBase -= 3_600_000;
          if (arrivals.length === 4) timers.wallBase += 7_200_000;
          f.answer(ctx, 'listchannels', { channels: [lndChannel()] });
        },
      },
    });
    const database = join(dir, 'fw.db');
    await createDatabase(database);
    const config = writeConfig(dir, { database, collectInterval: '10s', nodes: [lndEntry('lnd-a', lnd.url, lnd.macaroon)] });
    timers.stopWhen = () => arrivals.length >= 6;
    const { result } = await run(config, timers);
    expect(result).toEqual({ cycles: 6, exitCode: 0 });
    expect(arrivals.slice(1).map((at, index) => at - (arrivals[index] ?? 0))).toEqual([10000, 10000, 10000, 10000, 10000]);
    expect(snapshotCount(database, 'lnd-a')).toBe(6);
  }, 60_000);
});

describe('CP-017 bounded lists', () => {
  const many = (count: number): Record<string, unknown>[] => Array.from({ length: count }, (_, index) =>
    lndChannel({ chan_id: String(892945371103232001n + BigInt(index)), channel_point: `${index.toString(16).padStart(64, '0')}:0` }));

  it('CP-017/B2 a listing of 10,000 channels is stored whole and one of 10,001 is refused without storing any of it', async () => {
    const dir = scratch('cp017-b2');
    let listing = many(10_001);
    const lnd = await lndNode(dir, open, { routes: { 'GET /v1/channels': (ctx, f) => { f.answer(ctx, 'listchannels', { channels: listing }); } } });
    const cln = await clnNode(dir, open, { channels: [peerChannel()] });
    const database = join(dir, 'fw.db');
    await createDatabase(database);
    const config = writeConfig(dir, { database, collectInterval: '10s', nodes: [lndEntry('lnd-big', lnd.url, lnd.macaroon), clnEntry('cln-a', cln.url, cln.runeFile)] });
    const cycles: CollectorCycle[] = [];
    const over = new VirtualTimers();
    over.stopWhen = () => cycles.length >= 1;
    const first = await run(config, over, cycle => cycles.push(cycle));
    expect(first.result).toEqual({ cycles: 1, exitCode: 0 });
    // SECURITY.md §5: more than 10,000 channels per listing is a protocol error, never a truncated list.
    expect(snapshotCount(database, 'lnd-big')).toBe(0);
    expect(snapshotCount(database, 'cln-a')).toBe(1);
    expect(cycles[0]?.nodes.map(node => [node.name, node.state, node.channels])).toEqual([['cln-a', 'ONLINE', 1], ['lnd-big', 'OFFLINE', 0]]);
    listing = many(10_000);
    cycles.length = 0;
    const exact = new VirtualTimers();
    exact.stopWhen = () => cycles.length >= 1;
    expect((await run(config, exact, cycle => cycles.push(cycle))).result).toEqual({ cycles: 1, exitCode: 0 });
    expect(snapshotCount(database, 'lnd-big')).toBe(10_000);
    expect(cycles[0]?.nodes.find(node => node.name === 'lnd-big')).toMatchObject({ state: 'ONLINE', channels: 10_000 });
  }, 180_000);

  it('CP-017/B2 the payment listing stops after 200 pages of 500, reports incomplete and resumes there next cycle', async () => {
    const dir = scratch('cp017-b2');
    const TOTAL = 100_500;
    const queries: URLSearchParams[] = [];
    const lnd = await lndNode(dir, open, {
      routes: {
        'GET /v1/payments': (ctx, f) => {
          queries.push(ctx.query);
          // ListPayments: entries with index > index_offset, oldest first, at most max_payments (lightning.proto#L4400-L4472).
          const offset = Number(ctx.query.get('index_offset') ?? '0');
          const limit = Number(ctx.query.get('max_payments') ?? '0');
          const count = Math.max(0, Math.min(limit, TOTAL - offset));
          const payments = Array.from({ length: count }, (_, index) => payment({ payment_index: String(offset + index + 1), status: 'SUCCEEDED' }));
          f.answer(ctx, 'listpayments', {
            payments, first_index_offset: count === 0 ? '0' : String(offset + 1), last_index_offset: count === 0 ? '0' : String(offset + count), total_num_payments: '0',
          });
        },
      },
    });
    const database = join(dir, 'fw.db');
    await createDatabase(database);
    const config = writeConfig(dir, { database, collectInterval: '10s', nodes: [lndEntry('lnd-a', lnd.url, lnd.macaroon)] });
    const cycles: CollectorCycle[] = [];
    const timers = new VirtualTimers();
    timers.stopWhen = () => cycles.length >= 2;
    const firstCycleQueries: URLSearchParams[] = [];
    const { result } = await run(config, timers, cycle => { cycles.push(cycle); if (cycle.cycle === 1) firstCycleQueries.push(...queries); });
    expect(result).toEqual({ cycles: 2, exitCode: 0 });
    expect(firstCycleQueries).toHaveLength(200);
    expect(firstCycleQueries.map(query => query.get('max_payments'))).toEqual(Array.from({ length: 200 }, () => '500'));
    expect(firstCycleQueries.every(query => query.get('include_incomplete') === 'true')).toBe(true);
    expect(firstCycleQueries.map(query => query.get('index_offset'))).toEqual(Array.from({ length: 200 }, (_, page) => String(page * 500)));
    expect(cycles[0]?.nodes[0]).toMatchObject({ name: 'lnd-a', payments: 100_000, incomplete: true });
    const second = queries.slice(200);
    expect(second[0]?.get('index_offset')).toBe('100000');
    expect(cycles[1]?.nodes[0]).toMatchObject({ name: 'lnd-a', payments: 500, incomplete: false });
  }, 120_000);
});

describe('CP-017 signals', () => {
  async function heldDaemon(dir: string): Promise<{ config: string; database: string; held: Promise<() => void>; listings: () => number }> {
    let release: (answer: () => void) => void = () => undefined;
    const held = new Promise<() => void>(resolve => { release = resolve; });
    let count = 0;
    const lnd = await lndNode(dir, open, {
      routes: {
        'GET /v1/channels': (ctx: LndContext, f) => {
          count += 1;
          const answer = (): void => { f.answer(ctx, 'listchannels', { channels: [lndChannel(), SECOND_CHANNEL] }); };
          if (count === 1) { f.hold(ctx, 'listchannels'); release(answer); } else answer();
        },
      },
    });
    const database = join(dir, 'fw.db');
    await createDatabase(database);
    const config = writeConfig(dir, { database, collectInterval: '1s', nodes: [lndEntry('lnd-a', lnd.url, lnd.macaroon)] });
    return { config, database, held, listings: () => count };
  }

  /** The held listing, or a failure as soon as the daemon exits without reaching it. */
  async function heldOrExited<T>(held: Promise<T>, done: Promise<Run>): Promise<T> {
    return Promise.race([held, done.then(exit => { throw new Error(`daemon exited with ${String(exit.status)} before listing channels: ${exit.stderr.slice(0, 300)}`); })]);
  }

  for (const sig of ['SIGINT', 'SIGTERM'] as const) {
    it(`CP-017/B3 ${sig} lets the current cycle finish, starts no other and exits 0`, async () => {
      const dir = scratch('cp017-b3');
      const daemon = await heldDaemon(dir);
      const spawned = spawnCli(['daemon', '--collect', '--config', daemon.config], { signals: true, timeoutMs: 20_000 });
      const answer = await heldOrExited(daemon.held, spawned.done);
      spawned.signal(sig);
      await new Promise(resolve => setTimeout(resolve, 500));
      answer();
      const done = await spawned.done;
      expect(done.status).toBe(0);
      // The interrupted cycle's two channels are stored; no later cycle listed channels.
      expect(snapshotCount(daemon.database, 'lnd-a')).toBe(2);
      expect(daemon.listings()).toBe(1);
    }, 60_000);
  }

  it('CP-017/B3 a second signal exits at once with 6 and stores nothing of the unfinished cycle', async () => {
    const dir = scratch('cp017-b3');
    const daemon = await heldDaemon(dir);
    const spawned = spawnCli(['daemon', '--collect', '--config', daemon.config], { signals: true, timeoutMs: 20_000 });
    await heldOrExited(daemon.held, spawned.done);
    spawned.signal('SIGINT');
    await new Promise(resolve => setTimeout(resolve, 300));
    const second = Date.now();
    spawned.signal('SIGTERM');
    const done = await spawned.done;
    expect(done.status).toBe(6);
    expect(done.exitedAt - second).toBeLessThan(3000);
    expect(snapshotCount(daemon.database, 'lnd-a')).toBe(0);
  }, 60_000);
});

describe('CP-017 read-only', () => {
  /** Read endpoints (ARCHITECTURE.md §4.3 read methods; SECURITY.md §3.1 read permissions). Anything else is a write. */
  const LND_READS = new Set(['GET /v1/getinfo', 'GET /v1/channels', 'GET /v1/channels/pending', 'GET /v1/payments', 'GET /v2/router/mccfg', 'POST /v1/switch']);
  const CLN_READS = new Set(['getinfo', 'listpeerchannels', 'listsendpays', 'listpays', 'listinvoices', 'bkpr-listaccountevents', 'askrene-listlayers', 'listchannels', 'listnodes', 'listfunds', 'listforwards']);

  it('CP-017/B4 one hundred cycles over LND and CLN issue no write call and store every snapshot', async () => {
    const dir = scratch('cp017-b4');
    const lnd = await lndNode(dir, open, { channels: [lndChannel(), SECOND_CHANNEL] });
    const cln = await clnNode(dir, open, { channels: [peerChannel()] });
    const database = join(dir, 'fw.db');
    await createDatabase(database);
    const config = writeConfig(dir, { database, collectInterval: '10s', nodes: [lndEntry('lnd-a', lnd.url, lnd.macaroon), clnEntry('cln-a', cln.url, cln.runeFile)] });
    let cycles = 0;
    const timers = new VirtualTimers();
    timers.stopWhen = () => cycles >= 100;
    const { result } = await run(config, timers, () => { cycles += 1; });
    expect(result).toEqual({ cycles: 100, exitCode: 0 });
    const lndCalls = lnd.fake.requests.map(request => `${request.method} ${request.url.split('?')[0] ?? ''}`);
    const clnCalls = cln.fake.requests.map(request => request.url.replace(/^\/v1\//, '').split('?')[0] ?? '');
    expect(lndCalls.filter(call => !LND_READS.has(call))).toEqual([]);
    expect(clnCalls.filter(call => !CLN_READS.has(call))).toEqual([]);
    expect(lndCalls.filter(call => call === 'GET /v1/channels')).toHaveLength(100);
    expect(clnCalls.filter(call => call === 'listpeerchannels')).toHaveLength(100);
    expect(snapshotCount(database, 'lnd-a')).toBe(200);
    expect(snapshotCount(database, 'cln-a')).toBe(100);
  }, 180_000);
});

describe('CP-017 unavailable nodes', () => {
  it('CP-017/B5 an unreachable node is retried with bounded backoff and warned about once per state change', async () => {
    const dir = scratch('cp017-b5');
    const timers = new VirtualTimers();
    const down = (): boolean => timers.now < 40_000 || (timers.now >= 80_000 && timers.now < 120_000);
    const arrivals: { at: number; failed: boolean; url: string }[] = [];
    const flaky = (route: LndRoute): LndRoute => (ctx, f) => {
      const failed = down();
      arrivals.push({ at: timers.now, failed, url: ctx.request.url });
      // The connection is cut before any answer: a transport failure (ARCHITECTURE.md §10.6 answer modes).
      if (failed) ctx.response.socket?.destroy();
      else route(ctx, f);
    };
    const lnd = await lndNode(dir, open, {
      routes: {
        'GET /v1/getinfo': flaky((ctx, f) => { f.answer(ctx, 'getinfo', getInfo()); }),
        'GET /v2/router/mccfg': flaky((ctx, f) => { f.answer(ctx, 'router-mccfg', MISSION_CONTROL); }),
        'GET /v1/channels': flaky((ctx, f) => { f.answer(ctx, 'listchannels', { channels: [lndChannel()] }); }),
        'GET /v1/channels/pending': flaky((ctx, f) => { f.answer(ctx, 'pendingchannels', NO_PENDING); }),
        'GET /v1/payments': flaky((ctx, f) => { f.answer(ctx, 'listpayments', { payments: [], first_index_offset: '0', last_index_offset: '0', total_num_payments: '0' }); }),
      },
    });
    const database = join(dir, 'fw.db');
    await createDatabase(database);
    const config = writeConfig(dir, { database, collectInterval: '10s', nodes: [lndEntry('lnd-a', lnd.url, lnd.macaroon)] });
    timers.stopWhen = () => timers.now >= 160_000;
    const { result, stderr } = await run(config, timers);
    expect(result.exitCode).toBe(0);
    expect(linesWith(stderr(), 'node-offline', 'lnd-a')).toBe(2);
    expect(linesWith(stderr(), 'node-online', 'lnd-a')).toBe(2);
    // SECURITY.md §5: reads back off from 1 s to 15 s; never a retry storm, never abandoned.
    const gaps = arrivals.flatMap((arrival, index) => {
      const next = arrivals[index + 1];
      return arrival.failed && next !== undefined ? [next.at - arrival.at] : [];
    });
    expect(gaps.length).toBeGreaterThan(0);
    expect(gaps.filter(gap => gap < 1000 || gap > 15_000)).toEqual([]);
    const listed = (from: number, to: number): boolean => arrivals.some(arrival => !arrival.failed && arrival.url === '/v1/channels' && arrival.at >= from && arrival.at <= to);
    expect(listed(40_000, 55_000)).toBe(true);
    expect(listed(120_000, 135_000)).toBe(true);
  }, 120_000);

  it('CP-017/B5 no snapshot is taken while the node reports it is not synced to chain', async () => {
    const dir = scratch('cp017-b5');
    const timers = new VirtualTimers();
    // A node catching up reports synced_to_chain false at an old height (lnd#6171); later it is synced at 812.
    const info = (): Record<string, unknown> => timers.now < 25_000 ? { ...getInfo({ synced: false }), block_height: 700 } : getInfo();
    const lnd = await lndNode(dir, open, { channels: [lndChannel()], routes: { 'GET /v1/getinfo': (ctx, f) => { f.answer(ctx, 'getinfo', info()); } } });
    const database = join(dir, 'fw.db');
    await createDatabase(database);
    const config = writeConfig(dir, { database, collectInterval: '10s', nodes: [lndEntry('lnd-a', lnd.url, lnd.macaroon)] });
    timers.stopWhen = () => timers.now >= 60_000;
    const { result, stderr } = await run(config, timers);
    expect(result.exitCode).toBe(0);
    const db = new DatabaseSync(database, { readOnly: true });
    try {
      const heights = db.prepare('SELECT block_height AS h, count(*) AS n FROM channel_snapshots GROUP BY block_height ORDER BY block_height').all()
        .map(row => [Number(row['h']), Number(row['n'])]);
      expect(heights.map(([height]) => height)).toEqual([812]);
      expect(heights[0]?.[1]).toBeGreaterThan(0);
    } finally {
      db.close();
    }
    expect(linesWith(stderr(), 'node-not-synced', 'lnd-a')).toBe(1);
  }, 60_000);
});
