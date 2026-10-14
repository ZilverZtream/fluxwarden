import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { gzipSync } from 'node:zlib';
import { expect, it } from 'vitest';
import { childEnv, repoRoot } from '../helpers/cli.js';
import { testRoot } from '../helpers/env.js';

// SECURITY INV-11/D50: documented synchronous findLeaks must complete and cover compressed
// retained bytes, including when its caller is ordinary Node module-eval code. Independent
// public reproduction: review/rereview-ci-route/scanner-worker-probe.{mjs,json}, candidate7019165.
// The tiny fixture has a 3s child watchdog; vitest.lab.config.ts stays at its existing180s.
const WATCHDOG = 3000;
type Hit = { path: string; encoding: string } | null;
type Event = { event: string; hit?: Hit; name?: string };

function fixture(compressed: boolean, leaked: boolean) {
  const temporary = testRoot('FLUXWARDEN_TEST_TMP'), registration = testRoot('FLUXWARDEN_SENTINEL_DIR');
  const root = mkdtempSync(join(temporary, 'scanner-startup-'));
  const sentinelDir = mkdtempSync(join(registration, 'scanner-startup-'));
  const secret = randomBytes(32);
  writeFileSync(join(sentinelDir, 'synthetic.bin'), secret, { mode: 0o600 });
  const sentinels = join(root, 'registry.json'); writeFileSync(sentinels, '[]');
  const scratch = join(root, 'scratch'), evidence = join(root, 'retained'); mkdirSync(scratch); mkdirSync(evidence);
  const artifact = join(evidence, compressed ? 'tiny.gz' : 'tiny.log');
  if (leaked) appendFileSync(join(temporary, 'declared-out.txt'), `${artifact}\n`);
  const bytes = Buffer.from(leaked ? `ordinary retained prefix ${secret.toString('hex')} suffix\n` : 'ordinary retained clean output\n');
  writeFileSync(artifact, compressed ? gzipSync(bytes) : bytes, { mode: 0o600 });
  const options = { root, sentinelDir, sentinels, testTmp: scratch, evidenceDir: evidence, paths: [artifact] };
  const config = join(root, 'configuration.json');
  writeFileSync(config, JSON.stringify({ module: join(repoRoot, 'scripts/leak-check.mjs'), options }));
  const cleanup = () => {
    for (const [parent, owned] of [[temporary, root], [registration, sentinelDir]]) {
      const local = relative(resolve(parent ?? ''), resolve(owned ?? ''));
      if (!local || local.startsWith('..') || isAbsolute(local)) throw new Error('startup fixture cleanup escaped its owner');
      rmSync(owned ?? '', { recursive: true, force: true });
    }
  };
  return { root, scratch, evidence, sentinelDir, sentinels, artifact, config, secret, cleanup };
}

function run(f: ReturnType<typeof fixture>, args: string[], api = false) {
  const result = spawnSync(process.execPath, ['--max-old-space-size=128', ...args], {
    cwd: f.root, env: { ...childEnv(), FLUXWARDEN_TEST_TMP: f.scratch, FLUXWARDEN_SENTINEL_DIR: f.sentinelDir,
      FLUXWARDEN_EVIDENCE_DIR: f.evidence }, encoding: 'utf8', windowsHide: true, timeout: WATCHDOG, maxBuffer: 16 * 1024,
  });
  const diagnostic = Buffer.from(`${result.stdout}\n${result.stderr}`);
  expect([f.secret, Buffer.from(f.secret.toString('hex')), Buffer.from(f.secret.toString('base64'))]
    .every(form => !diagnostic.includes(form)), 'only process/result metadata leaves the child').toBe(true);
  if (api) expect(JSON.parse(result.stdout.trim().split(/\r?\n/)[0] ?? 'null')).toEqual({ event: 'ready' });
  expect(result.error === undefined, 'tiny public scan completes within the startup watchdog').toBe(true);
  expect(result.signal, 'public scan does not crash').toBeNull();
  return result;
}

const modes = ['file-api', 'eval-module-api'] as const;
const apiCases = modes.flatMap(mode => [false, true].flatMap(compressed => [false, true].map(leaked => ({ mode, compressed, leaked }))));
it.each(apiCases)('CP-002/B8 $mode completes tiny compressed=$compressed leaked=$leaked with exact public result', ({ mode, compressed, leaked }) => {
  const f = fixture(compressed, leaked);
  try {
    const helper = join(repoRoot, 'test/helpers/scanner-startup-child.mjs');
    const args = mode === 'file-api' ? [helper, f.config] : ['--input-type=module', '-e', readFileSync(helper, 'utf8'), f.config];
    const result = run(f, args, true);
    expect(result.status).toBe(0);
    expect(result.stderr.length).toBe(0);
    const events = result.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line) as Event);
    expect(events.map(event => event.event)).toEqual(['ready', 'result']);
    const hit = events[1]?.hit;
    if (!leaked) expect(hit).toBeNull();
    else {
      expect(hit !== null && hit !== undefined, 'compressed/plain bytes remain covered').toBe(true);
      expect(typeof hit?.encoding === 'string' && hit.encoding.length > 0).toBe(true);
      expect(hit?.path === f.artifact || hit?.path.startsWith(`${f.artifact}:`) === true, 'hit belongs to the supplied artifact/member').toBe(true);
      expect(Object.keys(hit ?? {}).sort()).toEqual(['encoding', 'path']);
    }
  } finally { f.cleanup(); }
});

it.each([false, true])('CP-002/B8 scanner CLI completes tiny gzip leaked=%s with exact exit status', leaked => {
  const f = fixture(true, leaked);
  try {
    const result = run(f, [join(repoRoot, 'scripts/leak-check.mjs'), '--sentinels', f.sentinels, '--sentinel-dir', f.sentinelDir, f.artifact]);
    expect(result.status).toBe(leaked ? 1 : 0);
  } finally { f.cleanup(); }
});

it('CP-002/reference-worker-startup Node module-eval inherits input-type and exposes a bounded worker startup error', () => {
  const f = fixture(false, false);
  try {
    const worker = join(f.root, 'independent-worker.mjs');
    writeFileSync(worker, "import {parentPort} from 'node:worker_threads'; parentPort.postMessage('ready');\n");
    // Node's public Worker API, separate from the scanner: default execArgv inheritance and
    // file-entry input-type refusal. No scanner Worker inspection, substitution or hook.
    // https://nodejs.org/docs/latest-v24.x/api/worker_threads.html#new-workerfilename-options
    const code = "import {Worker} from 'node:worker_threads'; import {writeSync} from 'node:fs'; const w=new Worker(process.argv.at(-1)); w.once('error',e=>writeSync(1,JSON.stringify({code:e.code})+'\\n'));";
    const result = run(f, ['--input-type=module', '-e', code, worker]);
    expect(result.status).toBe(0);
    expect(result.stderr.length).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({ code: 'ERR_INPUT_TYPE_NOT_ALLOWED' });
  } finally { f.cleanup(); }
});
