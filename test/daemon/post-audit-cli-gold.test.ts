// AUDIT-05 is a coverage witness, not a defect. These cases exercise real CLI
// wiring against native-shaped regtest RPC replies and observable cleanup.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { MUTATING, methodsOf } from '../fakes/cln/rebalance-node.js';
import { spawnCli, type Run } from '../helpers/cp016-cli.js';
import { count, demo, rows, until } from '../helpers/cpw-cli.js';
import { prepareMoneySafetyAlertKey, registerMoneySafetyCredentials } from '../helpers/public-money-safety.js';

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

function barrier() {
  let resolve: (() => void) | undefined;
  const reached = new Promise<void>(done => { resolve = done; });
  return { reached, arrive: () => { resolve?.(); } };
}

async function reachedOrExited(reached: Promise<void>, done: Promise<Run>): Promise<void> {
  await Promise.race([reached, done.then(run => { throw new Error(`daemon exited (${String(run.status)}) before the RPC barrier`); })]);
}

it('CP-041/AUDIT-05 CLI contains a failed planning pass cleans its layer and reaches the next collection', async () => {
  const d = await demo(open, { withKey: false, collectInterval: '1s' });
  registerMoneySafetyCredentials([d.cln.runeFile]);
  await prepareMoneySafetyAlertKey(d.database);
  const original = d.cln.fake.result;
  const nextCollection = barrier();
  let failed = false;
  let release: (() => void) | undefined;
  d.cln.fake.result = (context, behavior, value) => {
    if (context.request.url === '/v1/getroutes' && !failed) {
      failed = true;
      // A malformed upstream response is an adapter failure, not a request
      // for the daemon to terminate (SECURITY bounded untrusted node input).
      original(context, behavior, { routes: 'not-an-array' });
      return;
    }
    if (context.request.url === '/v1/listpeerchannels' && failed && release === undefined) {
      let released = false;
      release = () => { if (!released) { released = true; original(context, behavior, value); } };
      nextCollection.arrive();
      return;
    }
    original(context, behavior, value);
  };
  const spawned = spawnCli(['daemon', '--config', d.config], { signals: true });
  let run: Run | undefined;
  try {
    await reachedOrExited(nextCollection.reached, spawned.done);
    expect(d.cln.state.layers.layers.size, 'failed planner releases its temporary askrene layer before the next pass').toBe(0);
    expect(rows(d.database, "SELECT id FROM liquidity_proposals WHERE action_type = 'CIRCULAR_REBALANCE'")).toEqual([]);
    release?.();
    await until(() => count(d.database, 'liquidity_proposals') > 0, 10_000, 'a successful later planning pass');
  } finally {
    release?.();
    spawned.signal('SIGTERM');
    run = await spawned.done;
  }
  expect(run.status).toBe(0);
  expect(/propos|plan|route/i.test(`${run.stdout}${run.stderr}`), 'failed planning step is reported').toBe(true);
  expect(d.cln.state.layers.layers.size).toBe(0);
  expect(count(d.database, 'executions')).toBe(0);
  expect(methodsOf(d.cln.fake).filter(method => MUTATING.includes(method))).toEqual([]);
  expect(rows(d.database, 'PRAGMA integrity_check')).toEqual([{ integrity_check: 'ok' }]);
});

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  it(`CP-041/AUDIT-05 CLI ${signal} during route discovery releases the layer and starts no later pass`, async () => {
    const d = await demo(open, { withKey: false, collectInterval: '1s' });
    registerMoneySafetyCredentials([d.cln.runeFile]);
    await prepareMoneySafetyAlertKey(d.database);
    const original = d.cln.fake.result;
    const held = barrier();
    let release: (() => void) | undefined;
    let collections = 0;
    d.cln.fake.result = (context, behavior, value) => {
      if (context.request.url === '/v1/listpeerchannels') collections += 1;
      if (context.request.url === '/v1/getroutes' && release === undefined) {
        let released = false;
        release = () => { if (!released) { released = true; original(context, behavior, value); } };
        held.arrive();
        return;
      }
      original(context, behavior, value);
    };
    // Observe completion of the real signal event's listeners in the child.
    // The preload only records the OS/IPC boundary; it does not mock shutdown.
    const observed = join(d.dir, 'signal-observed.txt');
    const preload = join(d.dir, 'observe-signal.mjs');
    writeFileSync(preload, `import {writeFileSync} from 'node:fs';\nprocess.on('${signal}', () => setImmediate(() => writeFileSync(${JSON.stringify(observed)}, 'observed')));\n`);
    const spawned = spawnCli(['daemon', '--config', d.config], {
      signals: true, nodeArgs: ['--import', pathToFileURL(preload).href],
    });
    let run: Run | undefined;
    let atSignal: number;
    try {
      await reachedOrExited(held.reached, spawned.done);
      expect(d.cln.state.layers.layers.size, 'the request owns a real temporary routing layer').toBe(1);
      atSignal = collections;
      spawned.signal(signal);
      await until(() => existsSync(observed), 5_000, 'the child signal event');
      expect(readFileSync(observed, 'utf8')).toBe('observed');
      release?.();
      run = await spawned.done;
    } finally {
      release?.();
      if (run === undefined) { spawned.signal('SIGTERM'); await spawned.done; }
    }
    expect(run.status).toBe(0);
    expect(collections, 'aborted loop starts no later collection').toBe(atSignal);
    expect(d.cln.state.layers.layers.size, 'shutdown removes the held route discovery layer').toBe(0);
    expect(count(d.database, 'executions')).toBe(0);
    expect(methodsOf(d.cln.fake).filter(method => MUTATING.includes(method))).toEqual([]);
    expect(rows(d.database, 'PRAGMA integrity_check')).toEqual([{ integrity_check: 'ok' }]);
  });
}
