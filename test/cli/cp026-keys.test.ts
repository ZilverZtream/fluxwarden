/*
Interface:
  `fluxwarden keys generate --out <file> [--json]` (SPEC §10.3 command 13). Writes the operator's
  Ed25519 private key as a PKCS#8 PEM file, owner-only (mode 0600 on POSIX; on Windows a protected
  DACL whose allow entries grant only the current user SID, none inherited,
  SECURITY.md §5), and
  prints the public key and key_id for `approval_keys`. With --json: result
  { public_key: <base64 of the raw 32-byte public key>, key_id: <32 lowercase hex> }. Exit 0.
  An existing --out file → exit 2 and the file is left untouched; a parent directory of --out that is
  a symbolic link or junction → exit 2 and nothing is written.
*/
import { createHash, createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { unlinkFixture } from '../helpers/fixture-links.js';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { asRecord, binPath, childEnv, runCli, scratchDir, singleJsonDocument } from '../helpers/cli.js';
import { assertStrictWindowsOwnerOnly, readWindowsSecurity } from '../helpers/windows-security.js';

function rawPublicKey(key: KeyObject): Buffer {
  const jwk = key.export({ format: 'jwk' });
  if (typeof jwk.x !== 'string') throw new Error('not an Ed25519 public key');
  return Buffer.from(jwk.x, 'base64url');
}

/**
 * Owner-only as SECURITY.md §5 states it: mode 0600 on POSIX; on Windows a protected DACL whose
 * allow entries name only the current user, none inherited. Read from the effective security
 * descriptor (SDDL), not from how the file was created.
 */
function expectOwnerOnly(path: string): void {
  if (process.platform !== 'win32') {
    expect(statSync(path).mode & 0o777).toBe(0o600);
    return;
  }
  assertStrictWindowsOwnerOnly(readWindowsSecurity(path), 'file');
}

it('CP-026/B1 keys generate writes an owner-only PKCS#8 Ed25519 key and prints its public key and key_id', async () => {
  const dir = scratchDir('keys');
  const out = join(dir, 'operator.key');
  const run = await runCli(['keys', 'generate', '--out', out, '--json']);
  expect(run.status).toBe(0);
  const doc = singleJsonDocument(run.stdout);
  expect(doc['ok']).toBe(true);
  const result = asRecord(doc['result'], 'result');
  const pem = readFileSync(out, 'utf8');
  expect(pem.startsWith('-----BEGIN PRIVATE KEY-----')).toBe(true);
  const privateKey = createPrivateKey(pem);
  expect(privateKey.asymmetricKeyType).toBe('ed25519');
  const raw = rawPublicKey(createPublicKey(privateKey));
  expect(result['public_key']).toBe(raw.toString('base64'));
  expect(result['key_id']).toBe(createHash('sha256').update(raw).digest().subarray(0, 16).toString('hex'));
  expectOwnerOnly(out);
  // Nothing staged next to the key survives a successful write.
  expect(readdirSync(dir)).toStrictEqual(['operator.key']);
  const jwk = privateKey.export({ format: 'jwk' });
  if (typeof jwk.d !== 'string') throw new Error('no private scalar');
  const seed = Buffer.from(jwk.d, 'base64url');
  const body = pem.split(/\r?\n/).filter(line => line !== '' && !line.startsWith('-----')).join('');
  for (const form of [body, seed.toString('hex'), seed.toString('base64'), jwk.d]) {
    expect(run.stdout.includes(form) || run.stderr.includes(form)).toBe(false);
  }
});

it('CP-026/B1 keys generate refuses an existing file and leaves it unchanged', async () => {
  const dir = scratchDir('keys');
  const occupied = join(dir, 'occupied.key');
  writeFileSync(occupied, 'keep me\n');
  const refused = await runCli(['keys', 'generate', '--out', occupied, '--json']);
  expect(refused.status).toBe(2);
  expect(readFileSync(occupied, 'utf8')).toBe('keep me\n');

  const out = join(dir, 'operator.key');
  expect((await runCli(['keys', 'generate', '--out', out])).status).toBe(0);
  const first = readFileSync(out);
  expect((await runCli(['keys', 'generate', '--out', out])).status).toBe(2);
  expect(readFileSync(out).equals(first)).toBe(true);
});

// SECURITY.md §5: every write path and its parents are checked; symbolic links, junctions and
// reparse points are refused.
it('CP-026/B1 keys generate refuses an output path whose parent directory is a link or junction', async () => {
  const dir = scratchDir('keys');
  const real = join(dir, 'real');
  mkdirSync(join(real, 'nested'), { recursive: true });
  const linked = join(dir, 'linked');
  symlinkSync(real, linked, 'junction');
  try {
    for (const out of [join(linked, 'operator.key'), join(linked, 'nested', 'operator.key')]) {
      const run = await runCli(['keys', 'generate', '--out', out, '--json']);
      expect(run.status, out).toBe(2);
    }
    expect(readdirSync(real).sort()).toStrictEqual(['nested']);
    expect(readdirSync(join(real, 'nested'))).toStrictEqual([]);
  } finally { unlinkFixture(linked); }
});

// The system tools are taken from C:\Windows\System32, never from SystemRoot or windir, which the
// caller's environment controls.
/** The environment without any spelling of windir (Windows treats names case-insensitively). */
function withoutWindir(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.entries(env).filter(([name]) => !/^windir$/i.test(name)));
}

// Node itself cannot start with SystemRoot pointing elsewhere, so this run moves windir only; the
// SystemRoot case is covered in-process by test/platform/cp026-owner-only-env.test.ts.
if (process.platform === 'win32') it('CP-026/B1 keys generate ignores windir pointing elsewhere', () => {
  const dir = scratchDir('keys');
  const decoy = join(dir, 'decoy');
  mkdirSync(join(decoy, 'System32'), { recursive: true });
  const out = join(dir, 'operator.key');
  const run = spawnSync(process.execPath, [binPath(), 'keys', 'generate', '--out', out, '--json'], {
    cwd: dir, encoding: 'utf8', windowsHide: true, timeout: 30_000,
    env: { ...withoutWindir(childEnv()), windir: decoy },
  });
  expect(run.status, run.stderr).toBe(0);
  expectOwnerOnly(out);
  expect(readdirSync(join(decoy, 'System32'))).toStrictEqual([]);
});

if (process.platform === 'win32') it('CP-026/B1 keys generate refuses Win32 namespace paths with exit 2', async () => {
  const dir = scratchDir('keys');
  for (const out of [`\\\\?\\${join(dir, 'operator.key')}`, `\\\\.\\${join(dir, 'operator.key')}`]) {
    const run = await runCli(['keys', 'generate', '--out', out, '--json']);
    expect(run.status, out).toBe(2);
  }
  expect(readdirSync(dir)).toStrictEqual([]);
});

// Win32 strips a trailing dot or space and maps reserved device names, so such a path names another
// file than the one created (SECURITY.md §5: write paths are checked before use).
if (process.platform === 'win32') it('CP-026/B1 keys generate refuses trailing dots or spaces and device names with exit 2', async () => {
  const dir = scratchDir('keys');
  writeFileSync(join(dir, 'exist.txt'), 'keep\n');
  for (const name of ['exist.txt.', 'exist.txt ', 'operator.key.', 'NUL', 'CON.pem', 'aux.key', 'com1.key', 'LPT9', 'PRN.txt', 'nul.key', 'LPT1.key', 'COM1.pem', 'LPT\u00b9.key', 'COM\u00b9.key', 'com\u00b2', 'lpt\u00b3.pem']) {
    const run = await runCli(['keys', 'generate', '--out', join(dir, name), '--json']);
    expect(run.status, name).toBe(2);
  }
  expect(readdirSync(dir)).toStrictEqual(['exist.txt']);
  expect(readFileSync(join(dir, 'exist.txt'), 'utf8')).toBe('keep\n');
});
