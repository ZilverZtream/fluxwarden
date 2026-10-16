/*
Interface: as in test/persistence/cp015-persistence.test.ts. Child processes load the built module dist/persistence/index.js
(`npm run build` first; `npm test` builds through pretest).

Rule under test (SPEC §6.1, ARCHITECTURE §7.1): a write that meets a lock held by another process waits at most the
configured busy timeout (`openDatabase(path, { readOnly: false, busyTimeoutMs })`) and then fails with
PersistenceError code 'BUSY', writing nothing; concurrent writers in separate processes lose no rows; processes racing to
create a missing database each open it (or fail with a PersistenceError), never with a raw file-system error.
*/
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync, linkSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it, onTestFinished } from 'vitest';
import { childEnv, repoRoot } from '../helpers/cli.js';
import { channel, codeOf, count, fileHash, listing, loadPersistence, raw, scratch, seeded } from '../helpers/cp015-persistence.js';

const built = join(repoRoot, 'dist', 'persistence', 'index.js');

// Holds a write lock with node:sqlite directly until told to release it.
const LOCKER = `
import { DatabaseSync } from 'node:sqlite';
const db = new DatabaseSync(process.argv[1]);
db.exec('BEGIN IMMEDIATE');
process.stdout.write('locked\\n');
process.stdin.once('data', () => { db.exec('COMMIT'); db.close(); process.exit(0); });
`;

// Records snapshots through the product module, one transaction each, with block heights from..from+n-1.
const WRITER = `
import { createInterface } from 'node:readline';
const [modulePath, dbPath, channelId, from, n] = process.argv.slice(1);
const { openDatabase } = await import(modulePath);
const db = openDatabase(dbPath, { readOnly: false });
const base = JSON.parse(process.env.FW_CHANNEL, (k, v) => typeof v === 'string' && /^bigint:/.test(v) ? BigInt(v.slice(7)) : v);
const commands = createInterface({ input: process.stdin });
let written = 0;
try {
  process.stdout.write('ready:1\\n');
  for await (const command of commands) {
    if (command !== 'go' || written >= Number(n)) throw new Error('invalid writer command');
    db.snapshots.record(channelId, { ...base, blockHeight: Number(from) + written });
    written += 1;
    process.stdout.write('written:' + written + '\\n');
    if (written === Number(n)) break;
    process.stdout.write('ready:' + (written + 1) + '\\n');
  }
  if (written !== Number(n)) throw new Error('incomplete writer input');
  process.stdout.write('done\\n');
} catch (error) {
  process.stdout.write('failed:' + (error && error.code === 'BUSY' ? 'BUSY' : 'ERROR') + '\\n');
  process.exitCode = 1;
} finally {
  commands.close();
  process.stdin.destroy();
  db.close();
}
`;

function run(code: string, args: string[], env: NodeJS.ProcessEnv = {}): ChildProcessWithoutNullStreams {
  return spawn(process.execPath, ['--no-warnings', '--input-type=module', '-e', code, ...args], {
    env: { ...childEnv(), ...env }, shell: false, windowsHide: true, stdio: 'pipe',
  });
}

function waitFor(child: ChildProcessWithoutNullStreams, text: string): Promise<void> {
  return new Promise((resolve, reject) => {
    let out = '';
    let err = '';
    child.stdout.on('data', (chunk: Buffer) => { out += chunk.toString(); if (out.includes(text)) resolve(); });
    child.stderr.on('data', (chunk: Buffer) => { err += chunk.toString(); });
    child.once('exit', status => { if (!out.includes(text)) reject(new Error(`child exited ${String(status)} before "${text}": ${err}`)); });
  });
}

function exited(child: ChildProcessWithoutNullStreams): Promise<number | null> {
  return new Promise(resolve => {
    if (child.exitCode !== null) resolve(child.exitCode);
    else child.once('exit', status => { resolve(status); });
  });
}

it('CP-015/B6 a write blocked by another process fails as BUSY within the bounded timeout and writes nothing', async () => {
  const p = await loadPersistence();
  const path = join(scratch('busy'), 'fluxwarden.db');
  const channelId = seeded(p, path);
  const db = p.openDatabase(path, { readOnly: false, busyTimeoutMs: 300 });
  const locker = run(LOCKER, [path]);
  try {
    await waitFor(locker, 'locked');
    const started = performance.now();
    const code = codeOf(() => { db.snapshots.record(channelId, channel()); });
    const elapsed = performance.now() - started;
    expect(code).toBe('BUSY');
    expect(elapsed).toBeGreaterThanOrEqual(250);
    expect(elapsed).toBeLessThan(3_000);
    locker.stdin.write('release\n');
    expect(await exited(locker)).toBe(0);
    expect(count(path, 'channel_snapshots')).toBe(0n);
    db.snapshots.record(channelId, channel());
    expect(count(path, 'channel_snapshots')).toBe(1n);
  } finally {
    db.close();
    if (locker.exitCode === null) locker.kill();
  }
});

it('CP-015/B6 two processes writing snapshots at once lose no rows', async () => {
  const started = performance.now();
  expect(existsSync(built), 'built persistence module').toBe(true);
  const p = await loadPersistence();
  const path = join(scratch('race'), 'fluxwarden.db');
  const channelId = seeded(p, path);
  const encoded = JSON.stringify(channel(), (_k, v: unknown) => typeof v === 'bigint' ? `bigint:${v.toString()}` : v);
  const moduleUrl = pathToFileURL(built).href;
  const children = [
    run(WRITER, [moduleUrl, path, channelId, '1', '50'], { FW_CHANNEL: encoded }),
    run(WRITER, [moduleUrl, path, channelId, '1001', '50'], { FW_CHANNEL: encoded }),
  ];
  const lifecycle = { accepting: true };
  const observers = children.map(child => {
    let buffered = '', failure: Error | undefined;
    const seen = new Set<string>();
    const waiting = new Map<string, { resolve(): void; reject(error: Error): void }>();
    const fail = (error: Error): void => {
      failure ??= error;
      for (const pending of waiting.values()) pending.reject(failure);
      waiting.clear();
    };
    child.stdout.on('data', (chunk: Buffer) => {
      buffered += chunk.toString();
      for (let end = buffered.indexOf('\n'); end >= 0; end = buffered.indexOf('\n')) {
        const message = buffered.slice(0, end); buffered = buffered.slice(end + 1);
        if (!/^(?:ready|written):(?:[1-9]|[1-4][0-9]|50)$|^done$/.test(message) || seen.has(message)) {
          fail(new Error(message === 'failed:BUSY' ? 'snapshot writer reported BUSY' : 'snapshot writer protocol failed'));
          continue;
        }
        seen.add(message); waiting.get(message)?.resolve(); waiting.delete(message);
      }
    });
    child.on('error', () => { fail(new Error('snapshot writer process failed')); });
    child.stdin.on('error', () => { fail(new Error('snapshot writer input failed')); });
    // Drain diagnostics without echoing child data into a failed assertion.
    child.stderr.resume();
    const closed = new Promise<number | null>(resolve => {
      child.once('close', status => {
        if (status !== 0 || !seen.has('done')) fail(new Error('snapshot writer closed before successful completion'));
        resolve(status);
      });
    });
    const wait = (message: string): Promise<void> => {
      const result = new Promise<void>((resolve, reject) => {
        if (failure) reject(failure);
        else if (seen.has(message)) resolve();
        else waiting.set(message, { resolve, reject });
      });
      void result.catch(() => undefined);
      return result;
    };
    return { wait, closed };
  });
  let cleanup: Promise<void> | undefined;
  const stop = (): Promise<void> => cleanup ??= (async () => {
    lifecycle.accepting = false;
    for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await Promise.all(observers.map(observer => observer.closed));
  })();
  onTestFinished(stop);
  let fixtureMs: number, roundsMs: number;
  try {
    // Bounded busy handling does not promise starvation freedom across 50 consecutive commits.
    // Both writers compete once per round; neither can monopolize the next 49 transactions.
    await Promise.all(observers.map(observer => observer.wait('ready:1')));
    const ready = performance.now();
    fixtureMs = ready - started;
    for (let round = 1; round <= 50; round += 1) {
      await Promise.all(observers.map(observer => observer.wait(`ready:${String(round)}`)));
      if (!lifecycle.accepting) throw new Error('snapshot writer fixture has closed');
      expect(children.every(child => child.exitCode === null && child.signalCode === null), 'both writers are live before each paired release').toBe(true);
      const acknowledged = Promise.all(observers.map(observer => observer.wait(`written:${String(round)}`)));
      void acknowledged.catch(() => undefined);
      for (const child of children) child.stdin.write('go\n');
      await acknowledged;
    }
    const done = Promise.all(observers.map(observer => observer.wait('done')));
    await Promise.all([done, ...observers.map(observer => observer.closed)]);
    expect(await Promise.all(observers.map(observer => observer.closed))).toEqual([0, 0]);
    roundsMs = performance.now() - ready;
  } finally { await stop(); }
  const check = raw(path);
  try {
    const heights = (check.prepare('SELECT block_height AS h FROM channel_snapshots ORDER BY block_height').all() as { h: bigint }[]).map(r => Number(r.h));
    const expected = [...Array.from({ length: 50 }, (_, i) => 1 + i), ...Array.from({ length: 50 }, (_, i) => 1001 + i)];
    expect(heights).toEqual(expected);
  } finally { check.close(); }
  console.log(JSON.stringify({ case: 'snapshot-writers', fixtureMs, roundsMs, totalMs: performance.now() - started, writers: children.length, rounds: 50, activeChildren: children.filter(child => child.exitCode === null && child.signalCode === null).length }));
}, 60_000);

// Loads the module, says "ready", waits for "go" on stdin so that all openers start together, then opens a database
// that does not exist yet and reports "=ok" or "=<error name>:<code>".
const OPENER = `
const [modulePath, dbPath] = process.argv.slice(1);
const { openDatabase } = await import(modulePath);
process.stdout.write('ready');
process.stdin.once('data', () => {
  let result;
  try { openDatabase(dbPath, { readOnly: false, busyTimeoutMs: 10000 }).close(); result = 'ok'; }
  catch (error) { result = String(error && error.name) + ':' + String(error && error.code); }
  process.stdout.write('=' + result);
  process.exit(0);
});
`;

it('CP-015/B6 processes racing to create the same database each open it or get a PersistenceError, never a raw file error', async () => {
  expect(existsSync(built), 'built persistence module').toBe(true);
  const moduleUrl = pathToFileURL(built).href;
  const outcomes: string[] = [];
  const owned = new Set<ChildProcessWithoutNullStreams>();
  const trace = join(process.env['FLUXWARDEN_TEST_TMP'] ?? scratch('race-trace'), 'create-race-pids.json');
  const started = performance.now();
  const lifecycle: { stopped: boolean } = { stopped: false };
  const isStopped = (): boolean => lifecycle.stopped;
  let peakChildren = 0;
  function receipt(phase: string, round: number): void {
    const pids = [...owned].flatMap(child => child.pid === undefined ? [] : [child.pid]);
    writeFileSync(trace, JSON.stringify({ pids }));
    console.info(JSON.stringify({ case: 'CP-015/B6-create-race', phase, round, elapsedMs: performance.now() - started,
      activeChildren: owned.size, peakChildren }));
  }
  onTestFinished(async () => {
    lifecycle.stopped = true;
    const live = [...owned].filter(child => child.exitCode === null && child.signalCode === null);
    const exits = live.map(exited);
    for (const child of live) {
      if (process.platform === 'win32' && child.pid !== undefined) {
        spawnSync('C:/Windows/System32/taskkill.exe', ['/PID', String(child.pid), '/T', '/F'],
          { shell: false, windowsHide: true, stdio: 'ignore' });
      } else child.kill();
    }
    await Promise.all(exits);
    receipt('finished', -1);
  });
  async function runRound(round: number): Promise<string[]> {
    const path = join(scratch('first-open'), 'state', 'fluxwarden.db');
    const children = Array.from({ length: 8 }, () => run(OPENER, [moduleUrl, path]));
    for (const child of children) {
      owned.add(child);
      child.once('exit', () => { owned.delete(child); });
    }
    peakChildren = Math.max(peakChildren, owned.size);
    receipt('round-start', round);
    const results = children.map(child => new Promise<string>(resolve => {
      let out = '';
      child.stdout.on('data', (chunk: Buffer) => { out += chunk.toString(); });
      child.once('exit', () => { resolve(out.slice(out.indexOf('=') + 1)); });
    }));
    await Promise.all(children.map(child => waitFor(child, 'ready')));
    if (isStopped()) return [];
    receipt('round-ready', round);
    for (const child of children) child.stdin.write('go');
    const outs = await Promise.all(results);
    if (isStopped()) return [];
    expect(outs.filter(out => out === 'ok').length, `round ${String(round)}: ${outs.join(', ')}`).toBeGreaterThan(0);
    receipt('round-end', round);
    return outs;
  }
  // Distinct database paths keep the rounds independent; at most two sets of eight openers are active.
  for (let round = 0; round < 12; round += 2) {
    const rounds = await Promise.all([runRound(round), runRound(round + 1)]);
    if (isStopped()) return;
    outcomes.push(...rounds.flat());
  }
  // A losing O_EXCL create must not surface as Error:EEXIST; it is an existing database (or a coded refusal).
  expect(outcomes.filter(out => !/^(?:ok|PersistenceError:[A-Z_]+)$/.test(out))).toEqual([]);
}, 120_000);

// Records one snapshot through the product module and exits without closing: the -wal file keeps the commit, as after
// a crash of the writer.
const CRASHING_WRITER = `
const [modulePath, dbPath, channelId] = process.argv.slice(1);
const { openDatabase } = await import(modulePath);
const base = JSON.parse(process.env.FW_CHANNEL, (k, v) => typeof v === 'string' && /^bigint:/.test(v) ? BigInt(v.slice(7)) : v);
const db = openDatabase(dbPath, { readOnly: false });
db.snapshots.record(channelId, { ...base, blockHeight: 4242 });
process.exit(0);
`;

// Holds a read transaction on a rollback-journal database for 400 ms, then releases it.
const BRIEF_READER = `
import { DatabaseSync } from 'node:sqlite';
const db = new DatabaseSync(process.argv[1]);
db.exec('BEGIN');
db.prepare('SELECT count(*) FROM nodes').get();
process.stdout.write('locked\\n');
setTimeout(() => { db.exec('COMMIT'); db.close(); process.exit(0); }, 400);
`;

async function crashAfterWrite(p: Awaited<ReturnType<typeof loadPersistence>>, path: string): Promise<string> {
  const channelId = seeded(p, path);
  const encoded = JSON.stringify(channel(), (_k, v: unknown) => typeof v === 'bigint' ? `bigint:${v.toString()}` : v);
  const child = run(CRASHING_WRITER, [pathToFileURL(built).href, path, channelId], { FW_CHANNEL: encoded });
  expect(await exited(child)).toBe(0);
  expect(existsSync(`${path}-wal`), 'the writer left its -wal behind').toBe(true);
  return channelId;
}

it('CP-015/B2 a read-only open sees commits a crashed writer left in the -wal file', async () => {
  expect(existsSync(built), 'built persistence module').toBe(true);
  const p = await loadPersistence();
  const path = join(scratch('crash-wal'), 'fluxwarden.db');
  const channelId = await crashAfterWrite(p, path);
  const reader = p.openDatabase(path, { readOnly: true });
  try {
    expect(reader.snapshots.latest(channelId)?.blockHeight).toBe(4242);
  } finally { reader.close(); }
}, 60_000);

it('CP-015/B2 read-only open refuses a committed crash WAL without SHM and creates or migrates nothing', async () => {
  expect(existsSync(built), 'built persistence module').toBe(true);
  const p = await loadPersistence();
  const dir = scratch('crash-wal-no-shm');
  const path = join(dir, 'fluxwarden.db');
  const channelId = await crashAfterWrite(p, path);
  const shm = `${path}-shm`;
  expect(existsSync(shm), 'the crashed writer left its owned SHM').toBe(true);
  unlinkSync(shm);
  const before = listing(dir);
  expect(before).toEqual(['fluxwarden.db', 'fluxwarden.db-wal']);
  const bytes = [fileHash(path), fileHash(`${path}-wal`)];
  const unchanged = (): void => {
    expect.soft(listing(dir)).toEqual(before);
    // Unchanged DB and committed WAL bytes also prove no schema migration or checkpoint occurred.
    expect.soft([fileHash(path), fileHash(`${path}-wal`)]).toEqual(bytes);
  };
  // Read-only opening must refuse this WAL rather than create its missing SHM.
  let reader: ReturnType<typeof p.openDatabase> | undefined;
  const code = codeOf(() => {
    try {
      reader = p.openDatabase(path, { readOnly: true });
      reader.snapshots.latest(channelId);
    } finally {
      unchanged(); // While any unexpectedly accepted handle is still open, or immediately on refusal.
      reader?.close();
    }
  });
  expect.soft(code).toBe('UNSAFE_PATH');
  unchanged();
}, 60_000);

it('CP-015/B7 a hard-linked -wal file is refused in both modes', async () => {
  expect(existsSync(built), 'built persistence module').toBe(true);
  const p = await loadPersistence();
  const path = join(scratch('linked-wal'), 'fluxwarden.db');
  await crashAfterWrite(p, path);
  linkSync(`${path}-wal`, join(scratch('linked-wal-alias'), 'copy-wal'));
  expect(codeOf(() => { p.openDatabase(path, { readOnly: true }).close(); })).toBe('UNSAFE_PATH');
  expect(codeOf(() => { p.openDatabase(path, { readOnly: false }).close(); })).toBe('UNSAFE_PATH');
}, 60_000);

it('CP-015/B6 the WAL switch waits for a lock that is released within the busy timeout', async () => {
  const p = await loadPersistence();
  const path = join(scratch('wal-retry'), 'fluxwarden.db');
  seeded(p, path);
  const edit = raw(path);
  try { edit.prepare('PRAGMA journal_mode = DELETE').get(); } finally { edit.close(); }
  const holder = run(BRIEF_READER, [path]);
  try {
    await waitFor(holder, 'locked');
    const started = performance.now();
    const db = p.openDatabase(path, { readOnly: false, busyTimeoutMs: 5_000 });
    try {
      expect(db.pragmas().journalMode).toBe('wal');
    } finally { db.close(); }
    expect(performance.now() - started).toBeLessThan(5_000);
  } finally {
    if (holder.exitCode === null) holder.kill();
  }
  expect(await exited(holder)).toBe(0);
}, 60_000);
