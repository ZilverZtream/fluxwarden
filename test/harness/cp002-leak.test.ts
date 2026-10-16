import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { asRecord, childEnv, repoRoot, runNpmScript } from '../helpers/cli.js';
import '../helpers/env.js';

type Hit = { path: string; encoding: string } | null;
interface Scanner {
  findLeaks(options: { sentinels: string; sentinelDir?: string; root: string; paths?: string[]; commandOutput?: string; testTmp?: string; evidenceDir?: string }): Hit;
  sentinelRedactor(options: { sentinels: string; sentinelDir?: string; root?: string }): (text: string) => string;
}
interface Scratch {
  realDirectory(path: string, io?: { platform: string; lstat: (path: string) => Promise<{ isDirectory(): boolean; isSymbolicLink(): boolean }>; realpath: (path: string) => Promise<string> }): Promise<unknown>;
  createPrivateDirectory(parent: string, prefix: string): Promise<string>;
  assertPrivateDirectory(path: string): Promise<void>;
}

function owner(): { root: string; sentinels: string; sentinelDir: string } {
  const base = process.env['FLUXWARDEN_TEST_TMP'];
  const sources = process.env['FLUXWARDEN_SENTINEL_DIR'];
  if (!base || !sources) throw new Error('test temporary and sentinel directories are required');
  const root = mkdtempSync(join(base, 'scanner-'));
  const sentinelDir = mkdtempSync(join(sources, 'scanner-'));
  const sentinels = join(root, 'sentinels.json');
  writeFileSync(sentinels, '[]');
  return { root, sentinels, sentinelDir };
}

function removePlantedFiles(root: string, names: readonly string[]): void {
  const base = process.env['FLUXWARDEN_TEST_TMP'];
  if (!base) throw new Error('test temporary directory required for cleanup');
  const owned = resolve(root);
  const local = relative(resolve(base), owned);
  if (!local || local === '..' || local.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) || isAbsolute(local)) throw new Error('artifact cleanup root is outside owned temporary directory');
  for (const name of names) {
    const file = resolve(owned, name);
    const within = relative(owned, file);
    if (!within || within === '..' || within.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) || isAbsolute(within)) throw new Error('artifact cleanup path is outside owned root');
    rmSync(file, { force: true });
  }
}

function base32(bytes: Buffer): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, accumulator = 0, out = '';
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte; bits += 8;
    while (bits >= 5) { bits -= 5; out += alphabet.charAt((accumulator >>> bits) & 31); }
  }
  if (bits > 0) out += alphabet.charAt((accumulator << (5 - bits)) & 31);
  return out;
}

// Byte/encoding recognition and macaroon equivalents follow the pinned generic scanner.
// Expected hits are independently constructed; credential bytes never enter assertion diagnostics.
function forms(bytes: Buffer): [string, Buffer][] {
  const hex = bytes.toString('hex'), b64 = bytes.toString('base64');
  const latin = bytes.toString('latin1');
  const utf16 = Buffer.from(latin, 'utf16le');
  const percent = [...bytes].map(byte => `%${byte.toString(16).padStart(2, '0')}`).join('');
  const text: [string, string][] = [
    ['utf8', bytes.toString('utf8')], ['latin1', latin],
    ['hex-lower', hex], ['hex-upper', hex.toUpperCase()],
    ['base64-padded', b64], ['base64-unpadded', b64.replace(/=+$/, '')],
    ['base64url-padded', b64.replace(/\+/g, '-').replace(/\//g, '_')],
    ['base64url-unpadded', bytes.toString('base64url')],
    ['base64-case-folded', b64.replace(/=+$/, '').toLowerCase()],
    ['base64url-case-folded', bytes.toString('base64url').toLowerCase()],
    ['base32', base32(bytes)], ['base32-lower', base32(bytes).toLowerCase()],
    ['percent', percent], ['escaped', [...bytes].map(byte => `\\x${byte.toString(16).padStart(2, '0')}`).join('')],
    ['decimal', `[${[...bytes].join(',')}]`],
    ['separated-hex', hex.match(/../g)?.join(':') ?? ''],
    ['wrapped-base64', b64.match(/.{1,8}/g)?.join('\n') ?? ''],
    ['nested-base64', Buffer.from(hex).toString('base64')],
    ['nested-hex', Buffer.from(b64).toString('hex')],
  ];
  return [['raw', bytes], ['utf16le', utf16], ['utf16be', Buffer.from(utf16).swap16()],
    ...text.map(([name, value]): [string, Buffer] => [name, Buffer.from(value)])];
}

const candidateKinds = ['preimage', 'macaroon', 'rune', 'tls-key', 'ed25519-key', 'outbox-key', 'macaroon-without-version', 'macaroon-signature'] as const;

it.each(candidateKinds)('CP-002/B8 %s retained encodings are detected in output and artifacts with safe diagnostics', async candidateKind => {
  const scanner = await import(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href) as Scanner;
  const o = owner();
  const signature = randomBytes(32);
  const macaroon = Buffer.concat([Buffer.from([2, 1, 4]), randomBytes(16), Buffer.from([0, 6, 32]), signature]);
  const kinds: [string, Buffer][] = [
    ['preimage', randomBytes(32)], ['macaroon', macaroon], ['rune', Buffer.from(randomBytes(32).toString('base64url'))],
    ['tls-key', Buffer.from(`-----BEGIN PRIVATE KEY-----\n${randomBytes(48).toString('base64')}\n-----END PRIVATE KEY-----`)],
    ['ed25519-key', randomBytes(64)], ['outbox-key', randomBytes(32)],
  ];
  expect(kinds.map(([kind]) => kind)).toEqual(['preimage', 'macaroon', 'rune', 'tls-key', 'ed25519-key', 'outbox-key']);
  for (const [kind, source] of kinds) writeFileSync(join(o.sentinelDir, `${kind}.bin`), source);
  const candidates = [...kinds, ['macaroon-without-version', macaroon.subarray(1)] as [string, Buffer], ['macaroon-signature', signature] as [string, Buffer]];
  expect(candidates.map(([kind]) => kind)).toEqual(candidateKinds);
  const candidate = candidates.find(([kind]) => kind === candidateKind);
  if (!candidate) throw new Error(`missing candidate kind: ${candidateKind}`);
  const [kind, bytes] = candidate;
  const locations = ['temporary.log', 'state.sqlite', 'retained/evidence.log'];
  mkdirSync(join(o.root, 'retained'));
  try {
    for (const [encoding, value] of forms(bytes)) {
      for (const location of locations) {
        const target = join(o.root, location);
        if (location.endsWith('.sqlite')) {
          rmSync(target, { force: true });
          const database = new DatabaseSync(target);
          try {
            database.exec('CREATE TABLE artifacts (payload BLOB NOT NULL)');
            database.prepare('INSERT INTO artifacts VALUES (?)').run(value);
          } finally { database.close(); }
        } else writeFileSync(target, Buffer.concat([Buffer.from('header\n'), value, Buffer.from('\nfooter')]));
        const hit = scanner.findLeaks({ ...o, paths: [target], testTmp: o.root, evidenceDir: join(o.root, 'retained') });
        expect.soft(hit !== null, `${kind}/${encoding}/${location}: detected`).toBe(true);
        expect.soft(hit?.path === target, `${kind}/${encoding}/${location}: location`).toBe(true);
        expect.soft(typeof hit?.encoding === 'string' && hit.encoding.length > 0, `${kind}/${encoding}: encoding named`).toBe(true);
        const diagnostic = JSON.stringify(hit);
        expect.soft(!diagnostic.includes(bytes.toString('hex')) && !diagnostic.includes(bytes.toString('base64')), `${kind}/${encoding}: safe`).toBe(true);
      }
      // Captured text preserves valid UTF-8; binary forms are scanned as original file bytes.
      if (Buffer.from(value.toString('utf8')).equals(value)) {
        const output = scanner.findLeaks({ ...o, commandOutput: value.toString('utf8') });
        expect.soft(output !== null, `${kind}/${encoding}: captured output detected`).toBe(true);
      }
    }
  } finally {
    removePlantedFiles(o.root, [...locations, 'state.sqlite-wal', 'state.sqlite-shm', 'state.sqlite-journal']);
  }
});

it('CP-002/B8 short binary values and distinct shared-prefix sentinels are detected and redacted without rejecting incomplete prefixes', async () => {
  const scanner = await import(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href) as Scanner;
  const scratch = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as Scratch;
  const base = process.env['FLUXWARDEN_TEST_TMP'];
  const sources = process.env['FLUXWARDEN_SENTINEL_DIR'];
  if (!base || !sources) throw new Error('test temporary and sentinel directories are required');
  const root = await scratch.createPrivateDirectory(base, 'small-values-');
  const sentinelDir = await scratch.createPrivateDirectory(sources, 'small-values-');
  const sentinels = join(root, 'sentinels.json');
  writeFileSync(sentinels, '[]');
  const prefix = Buffer.from('!!!!!!!!');
  // Every nonempty registered value is covered, including byte-length boundaries.
  // Complete values are secret; an incomplete common prefix is ordinary data.
  const population: [string, Buffer][] = [
    ['one-byte', Buffer.from([249])],
    ['two-byte', Buffer.from([250, 251])],
    ['three-byte', Buffer.from([252, 253, 254])],
    ['shared-first', Buffer.concat([prefix, Buffer.alloc(24, '#')])],
    ['shared-second', Buffer.concat([prefix, Buffer.alloc(24, '$')])],
  ];
  const sourceFiles = population.map(([label]) => join(sentinelDir, `${label}.bin`));
  const target = join(root, 'payload.bin');
  const options = { root, sentinels, sentinelDir };
  const variants = population.map(([label, bytes]) => ({ label, variants: forms(bytes) }));
  const clean = Buffer.concat([prefix, Buffer.from('????')]);
  try {
    for (const [label, bytes] of population) writeFileSync(join(sentinelDir, `${label}.bin`), bytes);
    // This independent collision check validates the control against every retained form.
    expect(variants.every(source => source.variants.every(([, value]) => !clean.includes(value))), 'clean fixture contains no full registered encoding').toBe(true);
    writeFileSync(target, clean);
    expect(scanner.findLeaks({ ...options, paths: [target] }) === null, 'incomplete shared prefix is clean in a file').toBe(true);
    expect(scanner.findLeaks({ ...options, commandOutput: clean.toString('utf8') }) === null, 'incomplete shared prefix is clean in output').toBe(true);
    const redact = scanner.sentinelRedactor(options);
    expect(redact(clean.toString('utf8')) === clean.toString('utf8'), 'clean output is preserved').toBe(true);
    const placements: [string, Buffer, Buffer][] = [
      ['start', Buffer.alloc(0), clean],
      ['interior', clean, clean],
      ['end', clean, Buffer.alloc(0)],
    ];
    for (const { label, variants: encodings } of variants) {
      for (const [encoding, value] of encodings) {
        for (const [placement, before, after] of placements) {
          const payload = Buffer.concat([before, value, after]);
          writeFileSync(target, payload);
          const hit = scanner.findLeaks({ ...options, paths: [target] });
          expect.soft(hit !== null, `${label}/${encoding}/${placement}: file detected`).toBe(true);
          // The selected file identifies the planted leak; its diagnostic path must
          // also redact any full registered encoding that occurs in the path itself.
          const diagnosticPath = hit?.path;
          expect.soft(typeof diagnosticPath === 'string' && diagnosticPath.length > 0, `${label}/${encoding}/${placement}: diagnostic path present`).toBe(true);
          expect.soft(typeof diagnosticPath === 'string' && variants.every(source => source.variants.every(([, registered]) => !Buffer.from(diagnosticPath).includes(registered))), `${label}/${encoding}/${placement}: diagnostic path contains no full registered encoding`).toBe(true);
          if (Buffer.from(payload.toString('utf8')).equals(payload)) {
            const text = payload.toString('utf8');
            expect.soft(scanner.findLeaks({ ...options, commandOutput: text }) !== null, `${label}/${encoding}/${placement}: output detected`).toBe(true);
            const redacted = Buffer.from(redact(text));
            expect.soft(!redacted.includes(value), `${label}/${encoding}/${placement}: full value redacted`).toBe(true);
          }
        }
      }
    }
  } finally {
    removePlantedFiles(root, ['payload.bin']);
    // These are this case's own files in its separately allocated private directory.
    for (const file of sourceFiles) rmSync(file, { force: true });
  }
});

type BusyClock = 'normal' | 'frozen' | 'backward' | 'forward';
type BusyCode = 'EBUSY' | 'EPERM' | 'EACCES';

async function runtimeBusyChild(clock: BusyClock, code: BusyCode, controls = false) {
  const o = owner();
  const source = join(o.sentinelDir, 'runtime.bin');
  writeFileSync(source, randomBytes(32));
  // Faults affect ordinary Node IO and the wall clock only in this separate process.
  // The scanner still receives real nonempty registration through its public API.
  const script = `
    import fs from 'node:fs';
    import { syncBuiltinESMExports } from 'node:module';
    import { performance } from 'node:perf_hooks';
    const options = ${JSON.stringify(o)};
    let source = ${JSON.stringify(source)};
    const value = fs.readFileSync(source).toString('hex');
    const clean = 'ordinary application output';
    const scanner = await import(${JSON.stringify(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href)});
    const originalStat = fs.statSync, originalRead = fs.readFileSync, originalNow = Date.now;
    let busyCalls = 0, active = false, recoveryAt = Infinity, failureCode = ${JSON.stringify(code)};
    let clockMode = ${JSON.stringify(clock)}, wallCalls = 0;
    let busyOperation = clockMode === 'frozen' || clockMode === 'forward' ? 'read' : 'stat';
    const failures = [];
    const checkBusy = path => {
      if (active && String(path) === source && performance.now() < recoveryAt) {
        busyCalls++;
        const error = new Error('controlled runtime busy');
        error.code = failureCode;
        failures.push(error);
        throw error;
      }
    };
    fs.statSync = (path, ...args) => { if (busyOperation === 'stat') checkBusy(path); return originalStat(path, ...args); };
    fs.readFileSync = (path, ...args) => { if (busyOperation === 'read') checkBusy(path); return originalRead(path, ...args); };
    syncBuiltinESMExports();
    Date.now = () => {
      wallCalls++;
      if (clockMode === 'frozen') return 1791800000000;
      if (clockMode === 'backward') return 1791800000000 - wallCalls * 60000;
      if (clockMode === 'forward') return 1791800000000 + wallCalls * 60000;
      return originalNow();
    };
    const observe = api => {
      const start = performance.now();
      try {
        const detected = api === 'findLeaks'
          ? scanner.findLeaks({ ...options, commandOutput: value }) !== null
          : !scanner.sentinelRedactor(options)(value).includes(value);
        const cleanPreserved = api === 'findLeaks'
          ? scanner.findLeaks({ ...options, commandOutput: clean }) === null
          : scanner.sentinelRedactor(options)(clean) === clean;
        return { failed: false, detected, cleanPreserved, elapsedMs: performance.now() - start, busyCalls };
      } catch (error) {
        return { failed: true, code: error.code, originalFailure: failures.includes(error),
          elapsedMs: performance.now() - start, busyCalls };
      }
    };
    fs.writeSync(1, JSON.stringify({ event: 'started' }) + '\\n');
    let observations;
    if (${String(controls)}) {
      observations = ['findLeaks', 'sentinelRedactor'].map(api => ({ api, kind: 'initial', ...observe(api) }));
      for (const [mode, code, api] of [
        ['frozen', 'EBUSY', 'findLeaks'],
        ['backward', 'EPERM', 'sentinelRedactor'],
        ['forward', 'EACCES', 'findLeaks'],
      ]) {
        // Each recovery uses a fresh registered path, so a successful earlier
        // read cannot satisfy the next operation from already-read bytes.
        const freshSource = source + '.next';
        fs.renameSync(source, freshSource); source = freshSource;
        clockMode = mode; wallCalls = 0; failureCode = code; busyCalls = 0;
        busyOperation = mode === 'backward' ? 'read' : 'stat';
        active = true; recoveryAt = performance.now() + 750;
        observations.push({ api, kind: 'recovery', clock: mode, ...observe(api) });
        active = false;
      }
    } else {
      active = true;
      observations = [observe(clockMode === 'frozen' || clockMode === 'forward' ? 'sentinelRedactor' : 'findLeaks')];
    }
    fs.writeSync(1, JSON.stringify({ event: 'finished', observations }) + '\\n');
  `;
  try {
    return await new Promise<{ status: number | null; signal: NodeJS.Signals | null; timedOut: boolean; cleanupVerified: boolean; elapsedMs: number; stdout: string; stderr: string }>((resolveResult, reject) => {
      const start = performance.now();
      const child = spawn(process.execPath, ['--input-type=module', '--eval', script], {
        cwd: o.root, env: childEnv(), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
      });
      let stdout = '', stderr = '', timedOut = false;
      child.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString('utf8'); });
      child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8'); });
      // This safety watchdog is independent of the synchronous child scanner.
      // Its firing is an assertion failure, never evidence of bounded rejection.
      const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, 6500);
      child.on('error', error => { clearTimeout(timer); reject(error); });
      child.on('close', (status, signal) => {
        clearTimeout(timer);
        let cleanupVerified = false;
        if (child.pid !== undefined) {
          try { process.kill(child.pid, 0); }
          catch (error) { cleanupVerified = (error as NodeJS.ErrnoException).code === 'ESRCH'; }
        }
        const result = { status, signal, timedOut, cleanupVerified, elapsedMs: performance.now() - start, stdout, stderr };
        writeFileSync(join(o.root, 'busy-observation.json'), JSON.stringify({ clock, code, controls, ...result }));
        resolveResult(result);
      });
    });
  } finally {
    // The parent removes only its own registration, after child disappearance.
    for (let suffix = 0; suffix <= 3; suffix++) rmSync(source + '.next'.repeat(suffix), { force: true });
  }
}

function finishedBusyObservations(result: Awaited<ReturnType<typeof runtimeBusyChild>>): Record<string, unknown>[] {
  const safeObservation = JSON.stringify(result);
  console.info(`runtime busy observation: ${safeObservation}`);
  expect(result.cleanupVerified, safeObservation).toBe(true);
  expect(result.timedOut, safeObservation).toBe(false);
  expect(result.status, safeObservation).toBe(0);
  expect(result.stderr, 'child diagnostics are empty').toBe('');
  const lines = result.stdout.trim().split(/\r?\n/);
  expect(lines.length, safeObservation).toBe(2);
  const finished = asRecord(JSON.parse(lines[1] ?? 'null') as unknown, 'finished busy observation');
  expect(finished['event']).toBe('finished');
  const observations = finished['observations'];
  if (!Array.isArray(observations)) throw new Error('busy observations are absent');
  return observations.map((observation: unknown) => asRecord(observation, 'busy observation'));
}

it('CP-002/B9 runtime sentinel initial reads and recovering busy files preserve detection through wall-clock changes', async () => {
  const observations = finishedBusyObservations(await runtimeBusyChild('normal', 'EBUSY', true));
  expect(observations.length).toBe(5);
  for (const observation of observations) {
    expect(observation['failed'], JSON.stringify(observation)).toBe(false);
    expect(observation['detected']).toBe(true);
    expect(observation['cleanPreserved']).toBe(true);
    if (observation['kind'] === 'initial') {
      expect(observation['busyCalls']).toBe(0);
      expect(observation['elapsedMs']).toBeLessThan(1000);
    } else {
      expect(observation['busyCalls']).toBeGreaterThan(0);
      expect(observation['elapsedMs']).toBeGreaterThanOrEqual(750);
      expect(observation['elapsedMs']).toBeLessThan(2500);
    }
  }
});

const permanentBusyCases: { title: string; clock: BusyClock; code: BusyCode }[] = [
  { title: 'CP-002/B9 runtime sentinel permanent EBUSY rejects after the five-second budget under a normal wall clock', clock: 'normal', code: 'EBUSY' },
  { title: 'CP-002/B9 runtime sentinel permanent EPERM rejects after the five-second budget under a frozen wall clock', clock: 'frozen', code: 'EPERM' },
  { title: 'CP-002/B9 runtime sentinel permanent EACCES rejects after the five-second budget under a backward wall clock', clock: 'backward', code: 'EACCES' },
  { title: 'CP-002/B9 runtime sentinel permanent EBUSY rejects after the five-second budget under a forward wall clock', clock: 'forward', code: 'EBUSY' },
];
for (const busyCase of permanentBusyCases) {
  it(busyCase.title, async () => {
    const observations = finishedBusyObservations(await runtimeBusyChild(busyCase.clock, busyCase.code));
    expect(observations.length).toBe(1);
    const observation = observations[0];
    expect(observation?.['failed']).toBe(true);
    expect(observation?.['code']).toBe(busyCase.code);
    expect(observation?.['originalFailure']).toBe(true);
    expect(observation?.['busyCalls']).toBeGreaterThan(1);
    // The normative retry budget is 5000 ms. The upper observation allowance
    // permits scheduler overhead, while rejecting an extended or early deadline.
    expect(observation?.['elapsedMs']).toBeGreaterThanOrEqual(5000);
    expect(observation?.['elapsedMs']).toBeLessThan(6000);
  });
}

it('CP-002/B9 exact declared outputs alone are excluded while recordings and missing or empty sentinel sets fail closed', async () => {
  const scanner = await import(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href) as Scanner;
  const o = owner();
  const bytes = randomBytes(32);
  writeFileSync(join(o.sentinelDir, 'registered.bin'), bytes);
  const out = join(o.root, 'credential.out');
  const negativeLocations = ['labs/fixtures/recordings', 'test/vectors', 'test/scan-fixtures'];
  try {
  writeFileSync(out, bytes);
  writeFileSync(join(o.root, 'declared-out.txt'), `${out}\n`);
  expect(scanner.findLeaks({ ...o, paths: [out], testTmp: o.root })).toBeNull();
  for (const location of negativeLocations) {
    const recording = join(o.root, location, 'unexpected.bin');
    mkdirSync(join(o.root, location), { recursive: true });
    writeFileSync(recording, bytes);
    expect(scanner.findLeaks({ ...o, paths: [recording], testTmp: o.root }) !== null, location).toBe(true);
  }
  const clean = join(o.root, 'clean.txt');
  writeFileSync(clean, 'ordinary application output');
  expect(scanner.findLeaks({ ...o, paths: [clean], testTmp: o.root })).toBeNull();
  const empty = owner();
  for (const sentinelDir of [empty.sentinelDir, join(empty.root, 'missing')]) {
    const result = spawnSync(process.execPath, [join(repoRoot, 'scripts/leak-check.mjs'), '--sentinels', empty.sentinels, '--sentinel-dir', sentinelDir, clean], { encoding: 'utf8', windowsHide: true, timeout: 10000 });
    expect(result.status).toBe(1);
  }
  writeFileSync(join(empty.sentinelDir, 'empty.bin'), '');
  expect(() => scanner.findLeaks({ ...empty, paths: [clean] })).toThrow();
  writeFileSync(join(o.root, 'declared-out.txt'), `${out}*\n`);
  expect(scanner.findLeaks({ ...o, paths: [out], testTmp: o.root }) !== null).toBe(true);
  } finally {
    removePlantedFiles(o.root, ['credential.out', ...negativeLocations.map(location => `${location}/unexpected.bin`)]);
  }
});

it('CP-002/B8 scratch roots are owner-only and linked parents are refused through injected platform IO', async () => {
  const scratch = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as Scratch;
  const o = owner();
  const directory = await scratch.createPrivateDirectory(o.root, 'private-');
  await expect(scratch.assertPrivateDirectory(directory)).resolves.toBeUndefined();
  await expect(scratch.createPrivateDirectory(o.root, '../escape')).rejects.toThrow();
  await expect(scratch.realDirectory('/tmp/linked/child', {
    platform: 'linux', lstat: () => Promise.resolve({ isDirectory: () => true, isSymbolicLink: () => false }),
    realpath: () => Promise.resolve('/outside/child'),
  })).rejects.toThrow();
  await expect(scratch.realDirectory('C:\\linked\\child', {
    platform: 'win32', lstat: path => Promise.resolve({ isDirectory: () => true, isSymbolicLink: () => path === 'C:\\linked' }),
    realpath: () => Promise.resolve('C:\\outside\\child'),
  })).rejects.toThrow();
});

// Preserve the genuinely empty fixture without substituting live tests. Lab keeps
// its empty-suite success; chaos must fail explicitly when its required matrix is absent.
it('CP-002/B15 empty lab succeeds, empty chaos fails explicitly, and unavailable capabilities keep their exact refusal', async () => {
  const base = process.env['FLUXWARDEN_TEST_TMP'];
  const npmCli = process.env['npm_execpath'];
  if (!base || !npmCli || !/npm-cli\.js$/.test(npmCli)) throw new Error('private temporary root and npm CLI are required');
  const scratch = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as Scratch;
  const fixture = await scratch.createPrivateDirectory(base, 'empty-suites-');
  // Copy actual metadata and generic entry/configuration files, never a reference test.
  for (const file of ['package.json', 'package-lock.json', 'vitest.config.ts', 'vitest.lab.config.ts', 'vitest.chaos.config.ts']) {
    copyFileSync(join(repoRoot, file), join(fixture, file));
  }
  mkdirSync(join(fixture, 'scripts'));
  for (const file of ['private-scratch.mjs', 'no-pending.mjs', 'leak-check.mjs', 'later.mjs']) {
    copyFileSync(join(repoRoot, 'scripts', file), join(fixture, 'scripts', file));
  }
  const dependencies = join(fixture, 'node_modules');
  symlinkSync(realpathSync(join(repoRoot, 'node_modules')), dependencies, process.platform === 'win32' ? 'junction' : 'dir');
  try {
    for (const script of ['test:lab', 'test:chaos']) {
      const result = spawnSync(process.execPath, [npmCli, 'run', '--silent', script], {
        cwd: fixture, env: childEnv(), encoding: 'utf8', windowsHide: true, timeout: 10000,
      });
      expect(result.error, script).toBeUndefined();
      expect(result.status, script).toBe(script === 'test:chaos' ? 1 : 0);
      const output = `${result.stdout}\n${result.stderr}`;
      expect(output, script).toMatch(/No test files found/i);
      if (script === 'test:chaos') {
        expect(output, 'chaos fails for empty selection, not an unrelated exit-1 error').toMatch(/No test files found, exiting with code 1/i);
        expect(output, 'the clean empty-selection control is not a leak failure').not.toMatch(/leak-check failed/i);
      }
    }
  } finally {
    // Unlink only the owned fixture junction: keep immutable installed dependencies intact,
    // and leave every fixture file available for the normal artifact scan without exclusions.
    unlinkSync(dependencies);
  }
  for (const script of ['test:full']) {
    const result = runNpmScript(script);
    expect(result.status, script).toBe(1);
    expect(result.stdout, script).toBe('');
    expect(result.stderr.replace(/\r\n/g, '\n'), script).toBe('fluxwarden: this capability is not yet available\n');
  }
  // The lab command runs the whole-product leak scans, which take tens of seconds.
}, 180_000);
