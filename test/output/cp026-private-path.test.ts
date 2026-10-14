/*
Interface (src/output/private-file.ts):
  export function writeOwnerOnlyFile(path: string, bytes: Uint8Array): 'written' | 'exists' | 'failed' | 'invalid-path';
    On Windows a path component that Win32 would resolve to something else is 'invalid-path' and
    nothing is created: a trailing dot or space, or a reserved device name (CON, PRN, AUX, NUL,
    CONIN$, CONOUT$, COM0-9, LPT0-9, including the superscript digits ¹ ² ³), with or without an
    extension.
*/
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { scratchDir } from '../helpers/cli.js';
import { loadSrc } from '../helpers/load-src.js';

interface PrivateFileModule { writeOwnerOnlyFile: (path: string, bytes: Uint8Array) => string }

if (process.platform === 'win32') it('CP-026/B1 the owner-only writer refuses Win32 device names, superscript digits included', async () => {
  const { writeOwnerOnlyFile } = await loadSrc<PrivateFileModule>('output/private-file.ts');
  const dir = scratchDir('device-names');
  for (const name of ['LPT¹', 'LPT¹.key', 'lpt².pem', 'LPT³', 'COM¹.key', 'com²', 'COM³.txt',
    'LPT1.key', 'COM1.pem', 'NUL', 'nul.key', 'CON.pem', 'AUX.txt', 'PRN.key', 'CONIN$', 'conout$.log']) {
    expect(writeOwnerOnlyFile(join(dir, name), Buffer.from('x')), name).toBe('invalid-path');
  }
  expect(readdirSync(dir)).toStrictEqual([]);
  // Ordinary names around the reserved ones are written.
  for (const name of ['LPT10.key', 'COM.key', 'console.key', 'lpt¹x.key']) {
    expect(writeOwnerOnlyFile(join(dir, name), Buffer.from('x')), name).toBe('written');
  }
});

if (process.platform !== 'win32') it('CP-026/B1 the owner-only writer creates an ordinary POSIX file with mode 0600 and the current owner', async () => {
  const { writeOwnerOnlyFile } = await loadSrc<PrivateFileModule>('output/private-file.ts');
  const dir = scratchDir('private-path');
  const path = join(dir, 'operator.key');
  const bytes = Buffer.from('owner only\n');
  expect(writeOwnerOnlyFile(path, bytes)).toBe('written');
  expect(readFileSync(path)).toEqual(bytes);
  expect(statSync(path).mode & 0o777).toBe(0o600);
  if (!process.getuid) throw new Error('POSIX user identity is unavailable');
  expect(statSync(path).uid).toBe(process.getuid());
  expect(readdirSync(dir)).toEqual(['operator.key']);
});
