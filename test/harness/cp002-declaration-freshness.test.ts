// Sources: CP-002/B8 registered bytes and clean controls; CP-002/B9 exact
// declared-out.txt exclusions, wildcard rejection and missing/empty registration.
// These cases change ordinary owned files sequentially through the public API.
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { appendFileSync, rmSync, rmdirSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { childEnv, repoRoot } from '../helpers/cli.js';
import { testRoot } from '../helpers/env.js';

interface Options {
  root: string;
  sentinels: string;
  sentinelDir: string;
  testTmp: string;
  evidenceDir: string;
  paths: string[];
  commandOutput?: string;
}
interface Scanner {
  findLeaks(options: Options): { path: string; encoding: string } | null;
  sentinelRedactor(options: Options): (text: string) => string;
}
interface Scratch { createPrivateDirectory(parent: string, prefix: string): Promise<string> }

async function fixture() {
  const scanner = await import(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href) as Scanner;
  const scratch = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as Scratch;
  const root = await scratch.createPrivateDirectory(testRoot('FLUXWARDEN_TEST_TMP'), 'fresh-declarations-');
  const sentinelDir = await scratch.createPrivateDirectory(testRoot('FLUXWARDEN_SENTINEL_DIR'), 'fresh-declarations-');
  // As in CP-003/leak, declared scratch artifacts and retained evidence have
  // distinct roots: an exclusion must not ask to suppress evidence scanning.
  const evidenceDir = await scratch.createPrivateDirectory(testRoot('FLUXWARDEN_EVIDENCE_DIR'), 'fresh-declarations-');
  const sentinels = join(root, 'registry.json');
  const declaration = join(root, 'declared-out.txt');
  const source = join(sentinelDir, 'runtime.bin');
  const first = join(root, 'payload-a.log'), second = join(root, 'payload-b.log');
  const clean = join(root, 'ordinary.log');
  writeFileSync(sentinels, '[]', { mode: 0o600 });
  writeFileSync(clean, 'ordinary application output ~!?', { mode: 0o600 });
  // Exact outer declarations protect concurrent whole-run scans. The scanner
  // below uses its own root and therefore sees only its own declaration file.
  appendFileSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'declared-out.txt'), `${first}\n${second}\n`);
  const options: Options = { root, sentinels, sentinelDir, testTmp: root, evidenceDir, paths: [] };
  return {
    scanner, options, declaration, source, first, second, clean,
    scan(path: string) { return scanner.findLeaks({ ...options, paths: [path] }); },
    cleanup() {
      for (const path of [first, second, clean, declaration, sentinels, source]) rmSync(path, { force: true });
      rmdirSync(root);
      rmdirSync(sentinelDir);
      rmdirSync(evidenceDir);
    },
  };
}

function replaceWithSameMetadata(path: string, bytes: string | Buffer): void {
  const before = statSync(path);
  expect(Buffer.byteLength(bytes) === before.size, 'sequential replacement has the same byte length').toBe(true);
  writeFileSync(path, bytes);
  utimesSync(path, before.atime, before.mtime);
  const after = statSync(path);
  expect(after.size === before.size && after.mtimeMs === before.mtimeMs, 'replacement preserves size and modification time').toBe(true);
}

function stableMtime(path: string): void {
  // Integral seconds make the saved timestamp portable across filesystem precision.
  utimesSync(path, 1700000000, 1700000000);
}

it('CP-002/B9 repeated scans use current exact declarations after equal-size edits and removal', async () => {
  const f = await fixture();
  const bytes = randomBytes(32);
  try {
    writeFileSync(f.source, bytes, { mode: 0o600 });
    writeFileSync(f.first, bytes, { mode: 0o600 });
    writeFileSync(f.second, bytes, { mode: 0o600 });
    writeFileSync(f.declaration, `${f.first}\n`, { mode: 0o600 });
    stableMtime(f.declaration);
    const check = (declared: string, undeclared: string, stage: string) => {
      for (let repeat = 0; repeat < 2; repeat++) {
        expect(f.scan(declared) === null, `${stage}: current exact declaration excludes its artifact`).toBe(true);
        expect(f.scan(undeclared) !== null, `${stage}: other artifact remains detectable`).toBe(true);
        expect(f.scan(f.clean) === null, `${stage}: clean control remains clean`).toBe(true);
      }
    };
    check(f.first, f.second, 'initial');
    replaceWithSameMetadata(f.declaration, `${f.second}\n`);
    check(f.second, f.first, 'changed');
    replaceWithSameMetadata(f.declaration, `${f.first}\n`);
    check(f.first, f.second, 'restored');
    for (const stage of ['removed', 'empty', 'wildcard']) {
      if (stage === 'removed') rmSync(f.declaration);
      else writeFileSync(f.declaration, stage === 'empty' ? '' : `${f.first}*\n`, { mode: 0o600 });
      expect(f.scan(f.first) !== null, `${stage}: earlier exclusion no longer authorizes the first artifact`).toBe(true);
      expect(f.scan(f.second) !== null, `${stage}: second artifact remains detectable`).toBe(true);
      expect(f.scan(f.clean) === null, `${stage}: clean control remains clean`).toBe(true);
    }
  } finally { f.cleanup(); }
});

it('CP-002/B8 sequential registered-byte changes refresh detection and redaction with size and mtime preserved', async () => {
  const f = await fixture();
  const initial = randomBytes(32), changed = randomBytes(32);
  const ordinary = 'ordinary application output ~!?';
  try {
    writeFileSync(f.source, initial, { mode: 0o600 });
    stableMtime(f.source);
    const check = (current: Buffer, previous: Buffer, stage: string) => {
      writeFileSync(f.first, current.toString('hex'), { mode: 0o600 });
      writeFileSync(f.second, previous.toString('hex'), { mode: 0o600 });
      for (let repeat = 0; repeat < 2; repeat++) {
        expect(f.scan(f.first) !== null, `${stage}: current registration is detected in its artifact`).toBe(true);
        expect(f.scan(f.second) === null, `${stage}: other bytes are not registered`).toBe(true);
        expect(f.scan(f.clean) === null, `${stage}: clean artifact remains clean`).toBe(true);
        const currentText = current.toString('hex'), previousText = previous.toString('hex');
        expect(f.scanner.findLeaks({ ...f.options, commandOutput: currentText }) !== null, `${stage}: current output is detected`).toBe(true);
        const redact = f.scanner.sentinelRedactor(f.options);
        expect(!redact(currentText).includes(currentText), `${stage}: current output is redacted`).toBe(true);
        expect(redact(previousText) === previousText, `${stage}: unregistered output is preserved`).toBe(true);
        expect(redact(ordinary) === ordinary, `${stage}: ordinary output is preserved`).toBe(true);
      }
    };
    check(initial, changed, 'initial');
    replaceWithSameMetadata(f.source, changed);
    check(changed, initial, 'changed');
    replaceWithSameMetadata(f.source, initial);
    check(initial, changed, 'restored');
    for (const stage of ['empty', 'removed']) {
      if (stage === 'empty') writeFileSync(f.source, '');
      else rmSync(f.source);
      expect(() => f.scan(f.clean), `${stage}: scanning refuses an empty registration population`).toThrow();
    }
  } finally { f.cleanup(); }
});

it('CP-002/B9 unreadable runtime registration fails closed after earlier successful public scans', async () => {
  const f = await fixture();
  try {
    writeFileSync(f.source, randomBytes(32), { mode: 0o600 });
    // Process-local faults affect ordinary Node filesystem reads only. They do
    // not inspect scanner internals, count calls, or depend on elapsed time.
    const script = `
      import fs from 'node:fs';
      import { syncBuiltinESMExports } from 'node:module';
      const source = ${JSON.stringify(f.source)};
      const options = ${JSON.stringify(f.options)};
      const value = fs.readFileSync(source).toString('hex');
      const scanner = await import(${JSON.stringify(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href)});
      const initialDetection = scanner.findLeaks({ ...options, commandOutput: value }) !== null;
      const initialRedaction = !scanner.sentinelRedactor(options)(value).includes(value);
      const originalRead = fs.readFileSync, originalOpen = fs.openSync;
      const fault = () => { const error = new Error('synthetic registration read failure'); error.code = 'EIO'; throw error; };
      fs.readFileSync = (path, ...args) => String(path) === source ? fault() : originalRead(path, ...args);
      fs.openSync = (path, ...args) => String(path) === source ? fault() : originalOpen(path, ...args);
      syncBuiltinESMExports();
      const refuses = action => { try { action(); return false; } catch { return true; } };
      const scanRefused = refuses(() => scanner.findLeaks({ ...options, commandOutput: 'ordinary application output' }));
      const redactorRefused = refuses(() => scanner.sentinelRedactor(options));
      process.stdout.write(JSON.stringify({ initialDetection, initialRedaction, scanRefused, redactorRefused }));
    `;
    const result = spawnSync(process.execPath, ['--input-type=module', '--eval', script], {
      cwd: f.options.root, env: childEnv(), encoding: 'utf8', windowsHide: true, timeout: 15000,
    });
    expect(result.error === undefined, 'isolated unreadable-registration observation completes').toBe(true);
    expect(result.status === 0 && result.signal === null, 'isolated observation exits normally').toBe(true);
    expect(result.stderr.length === 0, 'isolated observation has no diagnostics').toBe(true);
    // Only booleans cross the process boundary; registered values never appear
    // in assertion diagnostics, snapshots or process output.
    expect(JSON.parse(result.stdout) as unknown).toEqual({
      initialDetection: true, initialRedaction: true, scanRefused: true, redactorRefused: true,
    });
  } finally { f.cleanup(); }
});
