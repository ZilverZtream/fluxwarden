// SECURITY INV-11 / docs/security-model.md: complete credentials are detected
// in original artifacts and captured output; redaction preserves ordinary bytes.
// CP-002/B8 supplies raw/UTF-8 recognition and incomplete-prefix clean controls.
// CP-002/B9 supplies empty-registration refusal and unreadable-input refusal.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, readFileSync, rmSync, rmdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { childEnv, repoRoot } from '../helpers/cli.js';
import { declareFixturePaths } from '../helpers/capture-fixture.js';
import { testRoot } from '../helpers/env.js';

interface Options { root: string; sentinels: string; sentinelDir: string; testTmp: string; evidenceDir: string; paths: string[]; commandOutput?: string }
interface Scanner {
  findLeaks(options: Options): { path: string; encoding: string } | null;
  sentinelRedactor(options: Options): (text: string) => string;
}
interface Scratch { createPrivateDirectory(parent: string, prefix: string): Promise<string> }
const boundaries = [4096, 65536, 262144];
const fingerprint = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');

function record(row: Record<string, unknown>): void {
  const file = process.env['FLUXWARDEN_SCANNER_GOLD_METADATA'];
  if (file) appendFileSync(file, `${JSON.stringify({ role: 'test-engineer', ...row })}\n`, { mode: 0o600 });
}

function publicResult<T>(operation: 'file scan' | 'captured output scan' | 'redactor construction' | 'redaction', action: () => T): T {
  try { return action(); }
  catch {
    // Scanner errors can embed registered bytes in messages or stacks. Preserve
    // failure with a fixed category and a new stack, without forwarding either.
    throw new Error(`scanner ${operation} failed (unexpected exception)`);
  }
}

async function fixture(label: string) {
  const scanner = await import(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href) as Scanner;
  const scratch = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as Scratch;
  const root = await scratch.createPrivateDirectory(testRoot('FLUXWARDEN_TEST_TMP'), 'byte-boundary-');
  const sentinelDir = await scratch.createPrivateDirectory(root, 'sources-');
  const evidenceDir = await scratch.createPrivateDirectory(testRoot('FLUXWARDEN_EVIDENCE_DIR'), 'byte-boundary-');
  const sentinels = join(root, 'registry.json'), target = join(root, 'payload.bin');
  const sources: string[] = [];
  writeFileSync(sentinels, '[]', { mode: 0o600 });
  const declaration = join(testRoot('FLUXWARDEN_TEST_TMP'), 'declared-out.txt');
  appendFileSync(declaration, `${target}\n`, { mode: 0o600 });
  const declaredBytes = readFileSync(declaration);
  record({ event: 'fixture', label, root, sentinelDir, evidenceDir, declaration, declarationBytes: declaredBytes.length, declarationSha256: fingerprint(declaredBytes), declarationContent: declaredBytes.toString('utf8') });
  const options: Options = { root, sentinels, sentinelDir, testTmp: root, evidenceDir, paths: [] };
  return {
    scanner, options, target,
    register(bytes: Buffer, name = 'source.bin') {
      const file = join(sentinelDir, name);
      if (!sources.includes(file)) {
        sources.push(file);
        declareFixturePaths([file]);
      }
      writeFileSync(file, bytes, { mode: 0o600 });
      record({ event: 'registration', label, path: file, bytes: bytes.length, sha256: fingerprint(bytes) });
      return file;
    },
    file(bytes: Buffer, found: boolean, message: string, boundary?: number) {
      if (boundary === undefined) writeFileSync(target, bytes, { mode: 0o600 });
      else {
        writeFileSync(target, bytes.subarray(0, boundary), { mode: 0o600 });
        appendFileSync(target, bytes.subarray(boundary));
      }
      expect(publicResult('file scan', () => scanner.findLeaks({ ...options, paths: [target] })) !== null, message).toBe(found);
    },
    text(text: string, source: Buffer, found: boolean, message: string) {
      // The expected original bytes come from Node's documented UTF-8 conversion,
      // independently of any scanner text segmentation or string representation.
      expect(Buffer.from(text, 'utf8').includes(source), `${message}: byte oracle`).toBe(found);
      expect(publicResult('captured output scan', () => scanner.findLeaks({ ...options, commandOutput: text })) !== null, `${message}: detection`).toBe(found);
      const redact = publicResult('redactor construction', () => scanner.sentinelRedactor(options));
      const redacted = publicResult('redaction', () => Buffer.from(redact(text), 'utf8'));
      if (found) expect(!redacted.includes(source), `${message}: no complete credential remains`).toBe(true);
      else expect(redacted.equals(Buffer.from(text, 'utf8')), `${message}: ordinary bytes preserved`).toBe(true);
    },
    cleanup() {
      for (const file of [target, sentinels, ...sources]) rmSync(file, { force: true });
      for (const directory of [sentinelDir, root, evidenceDir]) rmdirSync(directory);
      record({ event: 'closed', label, roots: [root, sentinelDir, evidenceDir], allRemoved: [root, sentinelDir, evidenceDir].every(directory => !existsSync(directory)) });
    },
  };
}

it('CP-002/B8 short raw registrations remain detectable at large file boundaries without accepting incomplete encodings', async () => {
  const f = await fixture('short-raw');
  try {
    for (const length of [1, 2, 5]) {
      const source = Buffer.from(Array.from({ length }, (_, index) => 249 - index));
      f.register(source);
      for (const boundary of boundaries) {
        const prefix = source.toString('hex').slice(0, -1);
        const clean = Buffer.from(`${'.'.repeat(boundary - prefix.length)}${prefix}~`);
        f.file(clean, false, `length-${String(length)}/boundary-${String(boundary)}: incomplete hex is clean`);
        const split = length === 1 ? 0 : Math.floor(length / 2);
        const planted = Buffer.concat([Buffer.alloc(boundary - split, '.'), source, Buffer.from('~')]);
        f.file(planted, true, `length-${String(length)}/boundary-${String(boundary)}: complete raw bytes detected`, boundary);
      }
    }
  } finally { f.cleanup(); }
});

it('CP-002/B8 mixed UTF8 credentials cross byte boundaries inside two three and four byte characters', async () => {
  const f = await fixture('utf8-bytes');
  const text = 'A\u00e9\u6f22\u{1f600}Z', source = Buffer.from(text, 'utf8');
  try {
    f.register(source);
    for (const boundary of boundaries) {
      const control = `${'.'.repeat(boundary)}${text.slice(0, -1)}~`;
      f.text(control, source, false, `boundary-${String(boundary)}: incomplete Unicode prefix`);
      f.file(Buffer.from(control, 'utf8'), false, `boundary-${String(boundary)}: incomplete file prefix`);
      // Relative byte offsets 2/4/7 are strictly inside the 2/3/4-byte characters.
      for (const inside of [2, 4, 7]) {
        const value = `${'.'.repeat(boundary - inside)}${text}~`;
        const label = `boundary-${String(boundary)}/inside-${String(inside)}`;
        f.text(value, source, true, `${label}: original captured Unicode`);
        f.file(Buffer.from(value, 'utf8'), true, `${label}: original UTF8 file`, boundary);
      }
    }
  } finally { f.cleanup(); }
});

it('CP-002/B8 captured surrogate pairs and lone surrogates retain their exact UTF8 credential bytes across string boundaries', async () => {
  const f = await fixture('utf16-output');
  const pair = Buffer.from('A\u{1f600}Z', 'utf8'), replacement = Buffer.from('A\ufffdZ', 'utf8');
  try {
    f.register(pair, 'pair.bin'); f.register(replacement, 'replacement.bin');
    const variants: [string, string, Buffer][] = [
      ['pair', 'A\ud83d\ude00Z', pair],
      ['unpaired-high', 'A\ud800Z', replacement],
      ['unpaired-low', 'A\udc00Z', replacement],
    ];
    for (const boundary of boundaries) {
      for (const [label, value, source] of variants) {
        // The surrogate code unit is immediately before the boundary. For the
        // valid pair, its second code unit is immediately after the boundary.
        const before = '.'.repeat(boundary - 2);
        f.text(`${before}${value}~`, source, true, `${label}/boundary-${String(boundary)}: complete encoded bytes`);
        f.text(`${before}${value.slice(0, -1)}~`, source, false, `${label}/boundary-${String(boundary)}: incomplete encoded bytes`);
      }
    }
  } finally { f.cleanup(); }
});

it('CP-002/B8 a literal longer than 256 KiB remains complete across file boundaries and repeated captured occurrences', async () => {
  const f = await fixture('long-literal');
  const text = `!${'w'.repeat(262144)}?`, source = Buffer.from(text, 'utf8');
  try {
    f.register(source);
    const clean = `.${text.slice(0, -1)}~.`;
    f.text(clean, source, false, 'long near-complete literal is ordinary output');
    f.file(Buffer.from(clean, 'utf8'), false, 'long near-complete literal is an ordinary file');
    f.text(`.${text}.${text}.`, source, true, 'every complete long occurrence is detected and redacted');
    const bytes = Buffer.concat([Buffer.alloc(4095, '.'), source, Buffer.from('~')]);
    f.file(bytes, true, 'complete long raw credential crosses independent file writes', 65536);
  } finally { f.cleanup(); }
});

it('CP-002/B9 empty and unreadable registration refuses clean large captured output after a positive control', async () => {
  const f = await fixture('registration-refusal');
  try {
    const source = Buffer.from('A\u00e9\u6f22\u{1f600}Z', 'utf8');
    const sourcePath = f.register(source);
    f.text(source.toString('utf8'), source, true, 'nonempty readable registration works');
    const script = `
      import fs from 'node:fs';
      import { syncBuiltinESMExports } from 'node:module';
      const sourcePath = ${JSON.stringify(sourcePath)}, options = ${JSON.stringify(f.options)};
      const scanner = await import(${JSON.stringify(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href)});
      const originalRead = fs.readFileSync, originalOpen = fs.openSync;
      const fault = () => { const error = new Error('synthetic registration unavailable'); error.code = 'EIO'; throw error; };
      fs.readFileSync = (path, ...args) => String(path) === sourcePath ? fault() : originalRead(path, ...args);
      fs.openSync = (path, ...args) => String(path) === sourcePath ? fault() : originalOpen(path, ...args);
      syncBuiltinESMExports();
      const refuses = action => { try { action(); return false; } catch { return true; } };
      const text = '.'.repeat(262144);
      process.stdout.write(JSON.stringify({ scanRefused: refuses(() => scanner.findLeaks({ ...options, commandOutput: text })), redactorRefused: refuses(() => scanner.sentinelRedactor(options)) }));
    `;
    const result = spawnSync(process.execPath, ['--input-type=module', '--eval', script], { cwd: f.options.root, env: childEnv(), encoding: 'utf8', windowsHide: true, timeout: 10000 });
    expect(result.error === undefined && result.status === 0 && result.signal === null, 'isolated ordinary IO failure observation completes').toBe(true);
    expect(result.stderr.length === 0, 'isolated observation contains no diagnostics').toBe(true);
    expect(JSON.parse(result.stdout) as unknown).toEqual({ scanRefused: true, redactorRefused: true });
    f.register(Buffer.alloc(0));
    expect(() => f.scanner.findLeaks({ ...f.options, commandOutput: '.'.repeat(262144) }), 'empty independent registration refuses').toThrow();
  } finally { f.cleanup(); }
});
