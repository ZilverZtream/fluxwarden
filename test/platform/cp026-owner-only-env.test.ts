// The owner-only writer runs icacls.exe and whoami.exe from C:\Windows\System32 and never resolves
// them through SystemRoot or windir, which the caller's environment controls. The variables are
// moved before the module is first loaded in this file and restored afterwards.
import { mkdirSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, expect, it } from 'vitest';
import { scratchDir } from '../helpers/cli.js';
import { loadSrc } from '../helpers/load-src.js';
import { assertStrictWindowsOwnerOnly, readWindowsSecurity } from '../helpers/windows-security.js';

interface PrivateFileModule { writeOwnerOnlyFile: (path: string, bytes: Uint8Array) => unknown }

const saved = { SystemRoot: process.env['SystemRoot'], windir: process.env['windir'] };
afterAll(() => {
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) Reflect.deleteProperty(process.env, name);
    else process.env[name] = value;
  }
});

/** The process environment with the original SystemRoot and windir (names are case-insensitive on Windows). */
function realEnvironment(): NodeJS.ProcessEnv {
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^(?:systemroot|windir)$/i.test(name)));
  return { ...env, ...saved };
}

if (process.platform === 'win32') it('CP-026/B1 the owner-only writer ignores SystemRoot and windir pointing elsewhere', async () => {
  const dir = scratchDir('owner-env');
  const decoy = join(dir, 'decoy');
  mkdirSync(join(decoy, 'System32'), { recursive: true });
  process.env['SystemRoot'] = decoy;
  process.env['windir'] = decoy;
  const { writeOwnerOnlyFile } = await loadSrc<PrivateFileModule>('output/private-file.ts');
  const out = join(dir, 'secret.bin');
  expect(writeOwnerOnlyFile(out, Buffer.from('owner only\n'))).toBe('written');
  assertStrictWindowsOwnerOnly(readWindowsSecurity(out, realEnvironment()), 'file');
  expect(readdirSync(join(decoy, 'System32'))).toStrictEqual([]);
  expect(readdirSync(dir).sort()).toStrictEqual(['decoy', 'secret.bin']);
});

if (process.platform !== 'win32') it('CP-026/B1 POSIX owner-only writes preserve mode and owner with SystemRoot and windir pointing elsewhere', async () => {
  const dir = scratchDir('owner-env');
  const decoy = join(dir, 'decoy');
  mkdirSync(join(decoy, 'System32'), { recursive: true });
  process.env['SystemRoot'] = decoy;
  process.env['windir'] = decoy;
  const { writeOwnerOnlyFile } = await loadSrc<PrivateFileModule>('output/private-file.ts');
  const path = join(dir, 'secret.bin');
  const bytes = Buffer.from('owner only\n');
  expect(writeOwnerOnlyFile(path, bytes)).toBe('written');
  expect(readFileSync(path)).toEqual(bytes);
  expect(statSync(path).mode & 0o777).toBe(0o600);
  if (!process.getuid) throw new Error('POSIX user identity is unavailable');
  expect(statSync(path).uid).toBe(process.getuid());
  expect(readdirSync(join(decoy, 'System32'))).toEqual([]);
  expect(readdirSync(dir).sort()).toEqual(['decoy', 'secret.bin']);
});
