import { appendFileSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { pathToFileURL } from 'node:url';
import { repoRoot } from './cli.js';
import { testRoot } from './env.js';

export interface SecretValue { toString(): string; toJSON(): string }
export interface Output {
  redact(text: string): string;
  write(text: string, options?: { stream?: 'stdout' | 'stderr'; exitCode?: number }): Promise<void>;
  json(value: unknown, options?: { exitCode?: number }): Promise<void>;
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
  for (const row of sentinels()) writeFileSync(join(directory, `product-${row.kind}.bin`), row.bytes, { mode: 0o600 });
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
  return readdirSync(directory).some(file => readFileSync(join(directory, file)).byteLength > 0);
}
