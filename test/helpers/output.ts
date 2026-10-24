import { appendFileSync, linkSync, lstatSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { pathToFileURL } from 'node:url';
import { repoRoot } from './cli.js';
import { testRoot } from './env.js';
import { declareFixturePaths } from './capture-fixture.js';

export interface SecretValue { toString(): string; toJSON(): string }
export interface Output {
  redact(text: string): string;
  write(text: string, options?: { stream?: 'stdout' | 'stderr'; exitCode?: number }): Promise<void>;
  json(value: unknown, options?: { exitCode?: number }): Promise<void>;
  /** Completes finite output: resolves pending partial values independently
   * per stream, preserves ordinary bytes, and waits for transport backpressure.
   * write() acknowledges bounded acceptance without waiting for finalization. */
  finalize(): Promise<void>;
}
export interface OutputModule {
  createOutput: (options: { stdout: Writable; stderr: Writable; secrets: readonly SecretValue[] }) => Output;
}

export async function secretType(): Promise<new (bytes: Uint8Array) => SecretValue> {
  const module = await import(pathToFileURL(join(repoRoot, 'dist/core/secret.js')).href) as { Secret: new (bytes: Uint8Array) => SecretValue };
  return module.Secret;
}

export async function outputModule(): Promise<OutputModule> {
  return await import(pathToFileURL(join(repoRoot, 'dist/output/index.js')).href) as OutputModule;
}

export function sentinels(): { kind: string; file: string; bytes: Buffer }[] {
  const value: unknown = JSON.parse(readFileSync(join(repoRoot, 'test/sentinels.json'), 'utf8'));
  if (!Array.isArray(value) || value.length !== 5) throw new Error('five disposable sentinel files are required');
  const rows = value as unknown[];
  return rows.map(entry => {
    if (typeof entry !== 'string' || !/^test\/sentinels\/[a-z0-9-]+\.(bin|pem|txt)$/.test(entry)) throw new Error('invalid sentinel path');
    const file = join(repoRoot, entry);
    return { kind: entry.split('/').at(-1)?.split('.')[0] ?? '', file, bytes: readFileSync(file) };
  });
}

export function sentinelRoot(): string {
  return testRoot('FLUXWARDEN_SENTINEL_DIR');
}

export function registerSentinels(directory = sentinelRoot()): void {
  for (const row of sentinels()) publishSentinel(directory, `product-${row.kind}.bin`, row.bytes);
}

/** Publish complete immutable input bytes without exposing an empty destination
 * or truncating another worker's source. Node fs.linkSync is exclusive at the
 * destination (Node 24.21 fs documentation); EEXIST requires exact validation.
 * Stages stay in owned scratch until command cleanup: unlinking a winning
 * hard-link stage earlier would change the registered inode's native ctime. */
export function publishSentinel(directory: string, name: string, bytes: Buffer): void {
  if (!/^[a-z0-9-]+\.bin$/.test(name) || bytes.length === 0) throw new Error('invalid immutable sentinel input');
  const destination = join(directory, name);
  const hasCode = (error: unknown, code: string): boolean => typeof error === 'object' && error !== null && 'code' in error && error.code === code;
  const existingMatches = (): boolean => {
    let before;
    try { before = lstatSync(destination, { bigint: true }); }
    catch (error) { if (hasCode(error, 'ENOENT')) return false; throw error; }
    if (!before.isFile() || before.isSymbolicLink()) throw new Error('immutable sentinel is not a regular file');
    const actual = readFileSync(destination), after = lstatSync(destination, { bigint: true });
    if (!actual.equals(bytes) || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new Error('immutable sentinel input changed');
    return true;
  };
  if (existingMatches()) return;
  const stage = join(mkdtempSync(join(scratchRoot(), 'sentinel-input-')), 'source.bin');
  declareFixturePaths([stage, destination]);
  writeFileSync(stage, bytes, { flag: 'wx', mode: 0o600 });
  try { linkSync(stage, destination); }
  catch (error) { if (!hasCode(error, 'EEXIST')) throw error; }
  if (!existingMatches()) throw new Error('immutable sentinel publication is absent');
}

export function scratchRoot(): string {
  return testRoot('FLUXWARDEN_TEST_TMP');
}

/**
 * Declares deliberately planted leak artifacts by exact path in the shared declared-output
 * list, so a concurrent whole-scratch scan does not report them. Call before writing them.
 */
export function declareDeliberateOutputs(paths: readonly string[], root = scratchRoot()): void {
  appendFileSync(join(root, 'declared-out.txt'), paths.map(path => `${path}\n`).join(''));
}

export function secretForms(bytes: Buffer): [string, string][] {
  const base64 = bytes.toString('base64');
  return [
    ['raw-utf8', bytes.toString('utf8')], ['raw-latin1', bytes.toString('latin1')],
    ['hex-lower', bytes.toString('hex')], ['hex-upper', bytes.toString('hex').toUpperCase()],
    ['base64', base64], ['base64-unpadded', base64.replace(/=+$/, '')],
    ['base64url', bytes.toString('base64url')], ['base64url-padded', base64.replace(/\+/g, '-').replace(/\//g, '_')],
    ['percent-lower', [...bytes].map(byte => `%${byte.toString(16).padStart(2, '0')}`).join('')],
    ['percent-upper', [...bytes].map(byte => `%${byte.toString(16).padStart(2, '0').toUpperCase()}`).join('')],
  ];
}

export function marker(text: string): boolean {
  return /^(?:\[redacted\]|\[redacted fp:[0-9a-f]{16}\])$/.test(text);
}

export function discardSink(): Writable {
  return new Writable({ write(_chunk, _encoding, callback) { callback(); } });
}

export function capturedSink(): { sink: Writable; text(): string } {
  const chunks: Buffer[] = [];
  return { sink: new Writable({ write(chunk: Buffer, _encoding, callback) { chunks.push(Buffer.from(chunk)); callback(); } }), text: () => Buffer.concat(chunks).toString('utf8') };
}

export function registryIsNonempty(directory: string): boolean {
  return readdirSync(directory, { withFileTypes: true }).some(entry => {
    const path = join(directory, entry.name);
    // Suites register sentinels in private subdirectories of the shared root.
    // Follow regular directories only; links cannot supply sentinel evidence.
    return entry.isDirectory() ? registryIsNonempty(path) : entry.isFile() && readFileSync(path).byteLength > 0;
  });
}
