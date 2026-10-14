/*
Interface: src/daemon/loop.ts, src/daemon/alerts.ts (alert files written through the src/output effect writer).

  src/daemon/alerts.ts — alert files (SPEC §10.4 DM5, §2.4)
    export type AlertKind = 'stuck-in-flight' | 'fee-mismatch' | 'delta-mismatch' | 'budget-overrun' | 'recon-difference'
      | 'invariant-breach' | 'node-quarantined';
    export interface AlertInput { kind: AlertKind; subject: string; state: string; detail?: Readonly<Record<string, string>> }
      // subject: the execution id or node name; state: the condition the alert reports (e.g. the execution status)
    export interface AlertWriter { raise(alert: AlertInput): 'written' | 'duplicate' | 'rate-limited' }
    export function createAlertWriter(options: {
      dir: string; key: Uint8Array;                    // HMAC key (outbox.key, 32 bytes)
      monotonic: { now(): number }; clock: { now(): number };   // rate limit on the monotonic clock; raisedAt from clock
      maxPerWindow: number; windowMs: number; secrets: readonly Secret[];
    }): AlertWriter;
    Each written alert is one payment-lab effect file (macwarden PL src/outbox/effects.ts): `<dir>/<name>.json`, a
    JSON object of string or number fields plus `hmacSha256` = hex HMAC-SHA256(key, JSON.stringify of the fields
    as [name, value] pairs sorted by name). Fields:
      kind, idempotencyKey = `${kind}:${subject}:${state}`, subject, state, raisedAt (clock.now()),
      suppressed (number of rate-limited raises since the previous written alert),
      `detail.<name>` for each detail entry, each value cut to its first 1024 characters.
    Every field value passes through the output redactor (registered secrets and pattern classes). Written files are
    created exclusively (no temporary file is left in dir) and are at most 64 KiB.
    - duplicate: a valid file for the same idempotencyKey already exists in dir (including one written by an earlier
      writer instance): nothing is written and the rate budget is not used. A new state for a subject is a new alert.
      Distinct (kind, subject, state) triples never share a file, even when subject or state contain ':' or are longer
      than the 1024-character cut.
    - a file at the alert's path that does not verify under the key (edited, foreign key, not JSON, over 64 KiB, or the
      file of another alert) makes raise() throw; it is never taken as a duplicate and never overwritten.
    - a cut never ends inside a UTF-16 surrogate pair (the pair is dropped whole).
    - rate-limited: maxPerWindow files were already written within the last windowMs: nothing is written, the raise
      counts into the next written alert's `suppressed`, and a later raise may write it. The window holds across
      writer instances (a daemon restart): alert files already in dir whose raisedAt is within windowMs of
      clock.now() count against it.

  src/daemon/loop.ts — the observe → diagnose → propose loop (SPEC §10.4 DM4, DM6; INV-01, INV-02)
    export type CollectOutcome = { kind: 'ok' } | { kind: 'offline'; reason: string };  // collector: one snapshot transaction per node
    export type ProposeOutcome = { kind: 'proposed'; proposalId: string } | { kind: 'no-action' };  // planner: diagnose, plan, store
    export interface ReconcilePass { alerts: readonly AlertInput[] }                       // reconciler: §8.4 pass and alert conditions
    export interface DaemonDeps {
      nodes: readonly string[]; cycleMs: number;
      monotonic: { now(): number };
      sleep(ms: number, signal: AbortSignal): Promise<void>;   // resolves after ms or once signal aborts; never rejects
      collector: { collect(node: string): Promise<CollectOutcome> };
      planner: { propose(node: string): Promise<ProposeOutcome> };
      reconciler: { reconcile(): Promise<ReconcilePass> };
      alerts: { raise(alert: AlertInput): 'written' | 'duplicate' | 'rate-limited' };
      executor: { execute(proposalId: string): Promise<unknown> };   // linked into the binary; the daemon never calls it
      releaseLeases(): Promise<void>;                               // DM6: fenced release of the leases it holds
      log: { error(step: 'collect' | 'propose' | 'reconcile' | 'alert', message: string): void };
        // every rejected step and every raise() that throws is reported once, as it happens (SPEC §10.4 DM5)
    }
    export function runDaemon(deps: DaemonDeps, signal: AbortSignal): Promise<{ exitCode: 0 }>;
    - Cycle k is due at start + k × cycleMs (start = monotonic.now() at entry; cycle 0 runs at once). A cycle: for each
      node in order, collect; when it answers 'ok', propose for that node (an 'offline' answer or a rejection skips the
      node's propose and never stops the loop). Then reconcile once and pass each of its alerts to alerts.raise.
      A rejected propose or reconcile is skipped likewise.
    - Between cycles the loop awaits exactly one sleep at a time, until the next due time strictly after now: cycles
      missed while the host was suspended are not replayed (one cycle, then the normal cadence).
    - The signal is checked before every step. A step in progress is awaited, never abandoned; after the abort no new
      step starts; then releaseLeases() runs once and the promise resolves { exitCode: 0 }.
    export function bindShutdownSignals(target: { on(event: string, listener: () => void): unknown;
      off(event: string, listener: () => void): unknown }, controller: AbortController): () => void;
      // SIGINT and SIGTERM abort the controller; the returned function removes both listeners.
*/
import { createHmac, randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadSource } from '../helpers/adapter-interfaces.js';
import { repoRoot } from '../helpers/cli.js';
import { sentinels } from '../helpers/output.js';

type AlertKind = 'stuck-in-flight' | 'fee-mismatch' | 'delta-mismatch' | 'budget-overrun' | 'recon-difference' | 'invariant-breach' | 'node-quarantined';
interface AlertInput { kind: AlertKind; subject: string; state: string; detail?: Record<string, string> }
type RaiseResult = 'written' | 'duplicate' | 'rate-limited';
interface AlertWriter { raise(alert: AlertInput): RaiseResult }
interface SecretValue { toString(): string }
interface AlertsModule {
  createAlertWriter: (options: {
    dir: string; key: Uint8Array; monotonic: { now(): number }; clock: { now(): number };
    maxPerWindow: number; windowMs: number; secrets: readonly SecretValue[];
  }) => AlertWriter;
}
type CollectOutcome = { kind: 'ok' } | { kind: 'offline'; reason: string };
type ProposeOutcome = { kind: 'proposed'; proposalId: string } | { kind: 'no-action' };
interface DaemonDeps {
  nodes: readonly string[]; cycleMs: number; monotonic: { now(): number };
  sleep(ms: number, signal: AbortSignal): Promise<void>;
  collector: { collect(node: string): Promise<CollectOutcome> };
  planner: { propose(node: string): Promise<ProposeOutcome> };
  reconciler: { reconcile(): Promise<{ alerts: readonly AlertInput[] }> };
  alerts: { raise(alert: AlertInput): RaiseResult };
  executor: { execute(proposalId: string): Promise<unknown> };
  releaseLeases(): Promise<void>;
  log: { error(step: string, message: string): void };
}
interface LoopModule {
  runDaemon: (deps: DaemonDeps, signal: AbortSignal) => Promise<{ exitCode: number }>;
  bindShutdownSignals: (target: { on(event: string, listener: () => void): unknown; off(event: string, listener: () => void): unknown }, controller: AbortController) => () => void;
}
interface Scanner { findLeaks(options: { sentinels: string; root: string; paths: string[] }): { path: string; encoding: string } | null }

const CYCLE = 15_000;   // SPEC §10.4 DM4: collect_interval and reconciler interval, design default 15 s
const loop = (): Promise<LoopModule> => loadSource<LoopModule>('daemon/loop.ts');
const alertsModule = (): Promise<AlertsModule> => loadSource<AlertsModule>('daemon/alerts.ts');

function scratch(prefix: string): string {
  return mkdtempSync(join(process.env['FLUXWARDEN_TEST_TMP'] ?? tmpdir(), `fw-cp041-${prefix}-`));
}

/** Virtual monotonic time: each sleep advances the clock by its duration (plus `jumps[n]` on the n-th sleep) and aborts at stopAt. */
function virtualTime(stopAt: number, controller: AbortController, jumps: ReadonlyMap<number, number> = new Map()) {
  let now = 0;
  const sleeps: number[] = [];
  return {
    sleeps,
    monotonic: { now: () => now },
    sleep: (ms: number): Promise<void> => {
      sleeps.push(ms);
      now += Math.max(0, ms) + (jumps.get(sleeps.length) ?? 0);
      if (now >= stopAt || sleeps.length > 100_000) controller.abort();
      return Promise.resolve();
    },
  };
}

interface Recorder { log: string[]; executed: string[]; released: number }

function deps(time: { monotonic: { now(): number }; sleep: (ms: number) => Promise<void> }, recorder: Recorder, overrides: Partial<DaemonDeps> = {}): DaemonDeps {
  const at = (): string => String(time.monotonic.now());
  let proposal = 0;
  return {
    nodes: ['cln-m', 'lnd-r'], cycleMs: CYCLE, monotonic: time.monotonic, sleep: time.sleep,
    collector: { collect: node => { recorder.log.push(`collect:${node}@${at()}`); return Promise.resolve({ kind: 'ok' }); } },
    planner: {
      propose: node => {
        recorder.log.push(`propose:${node}@${at()}`);
        proposal += 1;
        return Promise.resolve({ kind: 'proposed', proposalId: `prop_${String(proposal)}` });
      },
    },
    reconciler: { reconcile: () => { recorder.log.push(`reconcile@${at()}`); return Promise.resolve({ alerts: [] }); } },
    alerts: { raise: () => 'written' },
    executor: { execute: id => { recorder.executed.push(id); return Promise.resolve(); } },
    releaseLeases: () => { recorder.released += 1; recorder.log.push(`release@${at()}`); return Promise.resolve(); },
    log: { error: () => undefined },
    ...overrides,
  };
}

const recorder = (): Recorder => ({ log: [], executed: [], released: 0 });
const count = (log: readonly string[], prefix: string): number => log.filter(entry => entry.startsWith(prefix)).length;

/** The fields and HMAC of a payment-lab effect file (macwarden PL src/outbox/effects.ts sign/readEffect). */
function readAlert(path: string, key: Buffer): { fields: Record<string, unknown>; valid: boolean } {
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
  const { hmacSha256, ...fields } = parsed;
  const canonical = JSON.stringify(Object.keys(fields).sort().map(name => [name, fields[name] ?? null]));
  const expected = createHmac('sha256', key).update(canonical).digest('hex');
  return { fields, valid: hmacSha256 === expected };
}

function alertFiles(dir: string): string[] {
  return readdirSync(dir).sort();
}

describe('daemon loop', () => {
  it('CP-041/B1 every cycle collects then proposes per node and reconciles, on the 15 s cadence, and never calls the executor', async () => {
    const controller = new AbortController();
    const time = virtualTime(60_000, controller);
    const r = recorder();
    const { runDaemon } = await loop();
    const result = await runDaemon(deps(time, r), controller.signal);
    expect(result).toEqual({ exitCode: 0 });
    const expected = [0, 15_000, 30_000, 45_000].flatMap(t => [
      `collect:cln-m@${String(t)}`, `propose:cln-m@${String(t)}`, `collect:lnd-r@${String(t)}`, `propose:lnd-r@${String(t)}`, `reconcile@${String(t)}`,
    ]);
    expect(r.log).toEqual([...expected, 'release@60000']);
    expect(r.executed).toEqual([]);
    expect(r.released).toBe(1);
  });

  it('CP-041/B1 a node whose snapshot failed is not proposed for, and an approved proposal is still never executed', async () => {
    const controller = new AbortController();
    const time = virtualTime(30_000, controller);
    const r = recorder();
    const { runDaemon } = await loop();
    const result = await runDaemon(deps(time, r, {
      collector: { collect: node => { r.log.push(`collect:${node}`); return Promise.resolve(node === 'lnd-r' ? { kind: 'offline', reason: 'unreachable' } : { kind: 'ok' }); } },
      planner: { propose: node => { r.log.push(`propose:${node}`); return Promise.resolve({ kind: 'proposed', proposalId: 'prop_approved' }); } },
      reconciler: { reconcile: () => { r.log.push('reconcile'); return Promise.resolve({ alerts: [] }); } },
    }), controller.signal);
    expect(result.exitCode).toBe(0);
    expect(r.log.filter(entry => !entry.startsWith('release'))).toEqual([
      'collect:cln-m', 'propose:cln-m', 'collect:lnd-r', 'reconcile', 'collect:cln-m', 'propose:cln-m', 'collect:lnd-r', 'reconcile',
    ]);
    expect(r.executed).toEqual([]);
  });

  it('CP-041/B2 a condition reported on every reconciler pass is one alert file per state; a state change is a new file', async () => {
    const dir = scratch('b2-loop');
    const key = randomBytes(32);
    const controller = new AbortController();
    const time = virtualTime(60_000, controller);
    const { createAlertWriter } = await alertsModule();
    const writer = createAlertWriter({ dir, key, monotonic: time.monotonic, clock: { now: () => 1_760_000_000_000 }, maxPerWindow: 10, windowMs: 60_000, secrets: [] });
    let pass = 0;
    const r = recorder();
    const { runDaemon } = await loop();
    await runDaemon(deps(time, r, {
      alerts: writer,
      reconciler: {
        reconcile: () => {
          pass += 1;
          const state = pass <= 2 ? 'UNKNOWN' : 'IN_FLIGHT';
          return Promise.resolve({ alerts: [{ kind: 'stuck-in-flight', subject: 'exec_01K7ZQ8M3V6W9X2Y4Z5A7B8C9F', state, detail: { age_ms: '3600000' } }] });
        },
      },
    }), controller.signal);
    expect(pass).toBe(4);
    const files = alertFiles(dir);
    expect(files).toHaveLength(2);
    const states = files.map(name => readAlert(join(dir, name), key)).map(alert => [alert.valid, alert.fields['state']]).sort();
    expect(states).toEqual([[true, 'IN_FLIGHT'], [true, 'UNKNOWN']]);
  });

  it('CP-041/B2 an alert file carries exactly the specified fields under a valid HMAC, and is not written twice, even by a new writer', async () => {
    const dir = scratch('b2-file');
    const key = randomBytes(32);
    const { createAlertWriter } = await alertsModule();
    const options = { dir, key, monotonic: { now: () => 0 }, clock: { now: () => 1_760_000_000_000 }, maxPerWindow: 10, windowMs: 60_000, secrets: [] };
    const alert: AlertInput = { kind: 'stuck-in-flight', subject: 'exec_1', state: 'UNKNOWN', detail: { age_ms: '3600000' } };
    const writer = createAlertWriter(options);
    expect(writer.raise(alert)).toBe('written');
    expect(writer.raise(alert)).toBe('duplicate');
    expect(createAlertWriter(options).raise(alert)).toBe('duplicate');
    const files = alertFiles(dir);
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/^[^.].*\.json$/);
    const read = readAlert(join(dir, files[0] ?? ''), key);
    expect(read.valid).toBe(true);
    expect(read.fields).toEqual({
      kind: 'stuck-in-flight', idempotencyKey: 'stuck-in-flight:exec_1:UNKNOWN', subject: 'exec_1', state: 'UNKNOWN',
      raisedAt: 1_760_000_000_000, suppressed: 0, 'detail.age_ms': '3600000',
    });
    expect(readAlert(join(dir, files[0] ?? ''), randomBytes(32)).valid).toBe(false);
  });

  it('CP-041/B2 a flood of distinct alerts writes at most maxPerWindow files per window and reports the suppressed count in the next file', async () => {
    const dir = scratch('b2-flood');
    const key = randomBytes(32);
    let now = 0;
    const { createAlertWriter } = await alertsModule();
    const writer = createAlertWriter({ dir, key, monotonic: { now: () => now }, clock: { now: () => 1_760_000_000_000 + now }, maxPerWindow: 3, windowMs: 60_000, secrets: [] });
    const flood = Array.from({ length: 50 }, (_, i): AlertInput => ({ kind: 'recon-difference', subject: `exec_${String(i)}`, state: 'fee' }));
    const alertAt = (i: number): AlertInput => flood[i] ?? { kind: 'recon-difference', subject: 'missing', state: 'fee' };
    const results = flood.map(alert => writer.raise(alert));
    expect(results.filter(result => result === 'written')).toHaveLength(3);
    expect(results.filter(result => result === 'rate-limited')).toHaveLength(47);
    expect(writer.raise(alertAt(0))).toBe('duplicate');
    expect(alertFiles(dir)).toHaveLength(3);
    now = 59_999;
    expect(writer.raise(alertAt(10))).toBe('rate-limited');
    now = 60_000;
    expect(writer.raise(alertAt(10))).toBe('written');
    const files = alertFiles(dir);
    expect(files).toHaveLength(4);
    const latest = files.map(name => readAlert(join(dir, name), key).fields).find(fields => fields['subject'] === 'exec_10');
    expect(latest?.['suppressed']).toBe(48);
    // The count restarts after it was reported.
    expect(writer.raise(alertAt(11))).toBe('written');
    const next = alertFiles(dir).map(name => readAlert(join(dir, name), key).fields).find(fields => fields['subject'] === 'exec_11');
    expect(next?.['suppressed']).toBe(0);
  });

  it('CP-041/B2 alert output is bounded and redacted: a huge detail is cut and a registered secret never reaches the file', async () => {
    const dir = scratch('b2-bounded');
    const Secret = (await loadSource<{ Secret: new (bytes: Uint8Array) => SecretValue }>('core/secret.ts')).Secret;
    const macaroon = sentinels().find(row => row.kind === 'macaroon')?.bytes ?? Buffer.alloc(0);
    const key = randomBytes(32);
    const { createAlertWriter } = await alertsModule();
    const writer = createAlertWriter({ dir, key, monotonic: { now: () => 0 }, clock: { now: () => 1 }, maxPerWindow: 10, windowMs: 60_000, secrets: [new Secret(macaroon)] });
    expect(writer.raise({ kind: 'invariant-breach', subject: 'exec_2', state: 'preimage-mismatch', detail: { message: 'x'.repeat(100_000) } })).toBe('written');
    expect(writer.raise({ kind: 'node-quarantined', subject: 'lnd-r', state: 'QUARANTINED', detail: { error: `macaroon ${macaroon.toString('hex')} refused` } })).toBe('written');
    const files = alertFiles(dir);
    expect(files).toHaveLength(2);
    for (const name of files) expect(statSync(join(dir, name)).size).toBeLessThanOrEqual(65_536);
    const breach = files.map(name => readAlert(join(dir, name), key).fields).find(fields => fields['kind'] === 'invariant-breach');
    expect(breach?.['detail.message']).toBe('x'.repeat(1024));
    const scanner = await import(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href) as Scanner;
    expect(scanner.findLeaks({ sentinels: join(repoRoot, 'test/sentinels.json'), root: repoRoot, paths: [dir] })).toBeNull();
    for (const name of files) expect(readFileSync(join(dir, name), 'utf8')).not.toContain(key.toString('hex'));
  });

  it('CP-041/B3 a shutdown during a snapshot waits for that step to finish, starts nothing else, releases leases once and exits 0', async () => {
    const controller = new AbortController();
    const time = virtualTime(Number.MAX_SAFE_INTEGER, controller);
    const r = recorder();
    let finish: (outcome: CollectOutcome) => void = () => undefined;
    const pending = new Promise<CollectOutcome>(resolve => { finish = resolve; });
    const state = { collecting: false };
    const { runDaemon } = await loop();
    let settled = false;
    const run = runDaemon(deps(time, r, {
      collector: { collect: node => { r.log.push(`collect:${node}`); state.collecting = true; return pending; } },
    }), controller.signal).then(result => { settled = true; return result; });
    for (let i = 0; i < 20 && !state.collecting; i++) await new Promise(resolve => setImmediate(resolve));
    expect(state.collecting).toBe(true);
    controller.abort();
    for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve));
    expect(settled).toBe(false);
    expect(r.released).toBe(0);
    finish({ kind: 'ok' });
    expect(await run).toEqual({ exitCode: 0 });
    expect(r.log).toEqual(['collect:cln-m', 'release@0']);
    expect(r.released).toBe(1);
  });

  it('CP-041/B3 SIGINT and SIGTERM abort the daemon and the listeners are removed afterwards', async () => {
    const { bindShutdownSignals } = await loop();
    for (const signal of ['SIGINT', 'SIGTERM']) {
      const target = new EventEmitter();
      const controller = new AbortController();
      const unbind = bindShutdownSignals(target, controller);
      expect(target.listenerCount('SIGINT')).toBe(1);
      expect(target.listenerCount('SIGTERM')).toBe(1);
      expect(controller.signal.aborted).toBe(false);
      target.emit(signal);
      expect(controller.signal.aborted, signal).toBe(true);
      unbind();
      expect(target.listenerCount('SIGINT') + target.listenerCount('SIGTERM')).toBe(0);
    }
  });

  it('CP-041/B4 a node that refuses connections for an hour is retried at most once per cycle while the other node keeps its cadence', async () => {
    const controller = new AbortController();
    const time = virtualTime(3_600_000, controller);
    const r = recorder();
    const { runDaemon } = await loop();
    const result = await runDaemon(deps(time, r, {
      collector: {
        collect: node => {
          r.log.push(`collect:${node}`);
          return node === 'lnd-r' ? Promise.reject(new Error('connect ECONNREFUSED 127.0.0.1:8080')) : Promise.resolve({ kind: 'ok' });
        },
      },
      planner: { propose: node => { r.log.push(`propose:${node}`); return Promise.resolve({ kind: 'no-action' }); } },
      reconciler: { reconcile: () => { r.log.push('reconcile'); return Promise.resolve({ alerts: [] }); } },
    }), controller.signal);
    expect(result.exitCode).toBe(0);
    // 3,600,000 ms / 15,000 ms = 240 cycles (t = 0 … 3,585,000).
    expect(count(r.log, 'collect:cln-m')).toBe(240);
    expect(count(r.log, 'propose:cln-m')).toBe(240);
    expect(count(r.log, 'reconcile')).toBe(240);
    const attempts = count(r.log, 'collect:lnd-r');
    expect(attempts).toBeGreaterThanOrEqual(2);
    expect(attempts).toBeLessThanOrEqual(240);
    expect(count(r.log, 'propose:lnd-r')).toBe(0);
    expect(r.executed).toEqual([]);
  });

  it('CP-041/B4 a monotonic jump of an hour (suspended host) runs one cycle, not a burst of missed ones', async () => {
    const controller = new AbortController();
    const time = virtualTime(3_660_000, controller, new Map([[1, 3_600_000]]));
    const r = recorder();
    const { runDaemon } = await loop();
    await runDaemon(deps(time, r), controller.signal);
    // Cycles at 0, then 3,615,000 (after the jump), 3,630,000 and 3,645,000.
    expect(r.log.filter(entry => entry.startsWith('collect:cln-m'))).toEqual([
      'collect:cln-m@0', 'collect:cln-m@3615000', 'collect:cln-m@3630000', 'collect:cln-m@3645000',
    ]);
  });
});

describe('alert files: integrity, identity and restarts', () => {
  const base = { monotonic: { now: () => 0 }, clock: { now: () => 1_760_000_000_000 }, maxPerWindow: 10, windowMs: 60_000, secrets: [] };
  const ALERT: AlertInput = { kind: 'recon-difference', subject: 'exec_7', state: 'fee' };

  /** The single file name the writer uses for `alert`, learnt from a scratch directory. */
  async function fileNameFor(alert: AlertInput, key: Buffer): Promise<string> {
    const dir = scratch('name');
    const { createAlertWriter } = await alertsModule();
    createAlertWriter({ ...base, dir, key }).raise(alert);
    const [name] = alertFiles(dir);
    if (name === undefined) throw new Error('no alert file');
    return name;
  }

  /** An effect file signed as macwarden PL src/outbox/effects.ts sign() does. */
  function signed(fields: Record<string, string | number>, key: Buffer): string {
    const canonical = JSON.stringify(Object.keys(fields).sort().map(name => [name, fields[name] ?? null]));
    return JSON.stringify({ ...fields, hmacSha256: createHmac('sha256', key).update(canonical).digest('hex') });
  }

  it('CP-041/B2 an alert file edited after it was written fails its HMAC: raise throws instead of reporting a duplicate', async () => {
    const dir = scratch('tampered');
    const key = randomBytes(32);
    const { createAlertWriter } = await alertsModule();
    const writer = createAlertWriter({ ...base, dir, key });
    expect(writer.raise(ALERT)).toBe('written');
    const [name] = alertFiles(dir);
    const path = join(dir, name ?? '');
    const doc = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
    doc['raisedAt'] = 1;
    writeFileSync(path, JSON.stringify(doc));
    expect(() => writer.raise(ALERT)).toThrow();
    expect(() => createAlertWriter({ ...base, dir, key }).raise(ALERT)).toThrow();
    expect(alertFiles(dir)).toEqual([name]);
  });

  it('CP-041/B2 a correctly signed file over 64 KiB at the alert path is not accepted as the alert', async () => {
    const key = randomBytes(32);
    const name = await fileNameFor(ALERT, key);
    const dir = scratch('oversized');
    const fields = { kind: ALERT.kind, idempotencyKey: `${ALERT.kind}:${ALERT.subject}:${ALERT.state}`, subject: ALERT.subject, state: ALERT.state, raisedAt: 1, suppressed: 0, 'detail.pad': 'x'.repeat(70_000) };
    writeFileSync(join(dir, name), signed(fields, key));
    expect(statSync(join(dir, name)).size).toBeGreaterThan(65_536);
    const { createAlertWriter } = await alertsModule();
    expect(() => createAlertWriter({ ...base, dir, key }).raise(ALERT)).toThrow();
  });

  it('CP-041/B2 a cut detail never ends inside a surrogate pair', async () => {
    const dir = scratch('surrogate');
    const key = randomBytes(32);
    const { createAlertWriter } = await alertsModule();
    expect(createAlertWriter({ ...base, dir, key }).raise({ ...ALERT, detail: { message: `${'x'.repeat(1023)}\u{1F600}tail` } })).toBe('written');
    const [name] = alertFiles(dir);
    expect(readAlert(join(dir, name ?? ''), key).fields['detail.message']).toBe('x'.repeat(1023));
  });

  it('CP-041/B2 alerts that differ only in where a colon falls between subject and state are two files', async () => {
    const dir = scratch('separator');
    const key = randomBytes(32);
    const { createAlertWriter } = await alertsModule();
    const writer = createAlertWriter({ ...base, dir, key });
    expect(writer.raise({ kind: 'stuck-in-flight', subject: 'a:b', state: 'c' })).toBe('written');
    expect(writer.raise({ kind: 'stuck-in-flight', subject: 'a', state: 'b:c' })).toBe('written');
    const files = alertFiles(dir);
    expect(files).toHaveLength(2);
    expect(files.map(file => readAlert(join(dir, file), key)).map(alert => [alert.valid, alert.fields['subject'], alert.fields['state']]).sort())
      .toEqual([[true, 'a', 'b:c'], [true, 'a:b', 'c']]);
  });

  it('CP-041/B2 the rate limit holds across a writer restart within the window and frees up after it', async () => {
    const dir = scratch('restart');
    const key = randomBytes(32);
    let wall = 1_760_000_000_000;
    const { createAlertWriter } = await alertsModule();
    const options = { ...base, dir, key, clock: { now: () => wall }, maxPerWindow: 3 };
    const first = createAlertWriter(options);
    for (let i = 0; i < 3; i++) expect(first.raise({ ...ALERT, subject: `exec_${String(i)}` })).toBe('written');
    let written = 0;
    for (let restart = 0; restart < 4; restart++) {
      const writer = createAlertWriter(options);
      if (writer.raise({ ...ALERT, subject: `restart_${String(restart)}` }) === 'written') written += 1;
    }
    expect(written).toBe(0);
    expect(alertFiles(dir)).toHaveLength(3);
    wall += 60_000;
    expect(createAlertWriter({ ...options, monotonic: { now: () => 60_000 } }).raise({ ...ALERT, subject: 'later' })).toBe('written');
  });

  it('CP-041/B2 an alert the writer cannot write is reported by the daemon on every pass, not swallowed', async () => {
    const key = randomBytes(32);
    const alert: AlertInput = { kind: 'invariant-breach', subject: 'ledger', state: 'step-3' };
    const name = await fileNameFor(alert, key);
    const dir = scratch('planted');
    writeFileSync(join(dir, name), '{}');
    const { createAlertWriter } = await alertsModule();
    const writer = createAlertWriter({ ...base, dir, key });
    const controller = new AbortController();
    const time = virtualTime(30_000, controller);
    const errors: string[] = [];
    const { runDaemon } = await loop();
    const result = await runDaemon(deps(time, recorder(), {
      nodes: [], alerts: writer,
      reconciler: { reconcile: () => Promise.resolve({ alerts: [alert] }) },
      log: { error: step => { errors.push(step); } },
    }), controller.signal);
    expect(result.exitCode).toBe(0);
    expect(errors).toEqual(['alert', 'alert']);
    expect(readFileSync(join(dir, name), 'utf8')).toBe('{}');
  });
});
