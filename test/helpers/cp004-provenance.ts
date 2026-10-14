import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { expect } from 'vitest';
import { asRecord, readJson, readText, repoRoot } from './cli.js';

export const upstream = {
  name: 'macwarden', url: 'https://github.com/ZilverZtream/macwarden', commit: '25bbfa4', license: 'MIT',
  copyright: 'Copyright (c) 2026 macwarden contributors',
  licenseSha256: 'a0230b4c00986df0e67e146e974e6b05d6ad4ff52821fdfec540f5f1f33bb714',
};

export function sourceHashes(): Record<string, { path: string; sha256: string }> {
  return readJson('test/fixtures/cp004-source-hashes.json') as Record<string, { path: string; sha256: string }>;
}

export function hash(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export function verifyProvenance(): void {
  const manifest = asRecord(readJson('docs/source-provenance.json'), 'source provenance');
  expect(manifest['schema']).toBe(1);
  expect(manifest['upstream']).toEqual(upstream);
  const files = manifest['files'];
  expect(Array.isArray(files)).toBe(true);
  if (!Array.isArray(files)) throw new Error('source provenance must list reused files');
  const entries = files.map((entry: unknown) => asRecord(entry, 'reused file'));
  expect(new Set(entries.map(entry => entry['path'])).size).toBe(entries.length);
  expect(new Set(entries.map(entry => entry['upstreamPath'])).size).toBe(entries.length);
  const notice = readText('NOTICE-SOURCE-REUSE.md');
  const normalize = (value: string): string => value.replace(/\s+/g, ' ').trim();
  expect(normalize(notice)).toContain(normalize(readText('test/fixtures/cp004-license.txt')));
  for (const value of Object.values(upstream)) expect(notice).toContain(value);
  for (const [source, expected] of Object.entries(sourceHashes())) {
    const matching = entries.filter(entry => entry['upstreamPath'] === source);
    expect(matching, source).toHaveLength(1);
    expect(matching[0]?.['path']).toBe(expected.path);
    expect(matching[0]?.['upstreamSha256']).toBe(expected.sha256);
  }
  for (const entry of entries) {
    const path = entry['path'];
    if (typeof path !== 'string') throw new Error('reused file must name its product path');
    const local = relative(repoRoot, resolve(repoRoot, path));
    expect(!isAbsolute(path) && local !== '..' && !local.startsWith('../') && !local.startsWith('..\\'), 'reused file is inside the product').toBe(true);
    const actual = hash(readFileSync(join(repoRoot, path)));
    expect(entry['importedSha256'], path).toBe(actual);
    expect(entry['upstreamSha256']).toMatch(/^[0-9a-f]{64}$/);
    expect(['copied', 'adapted', 'design-only']).toContain(entry['disposition']);
    expect(typeof entry['changes']).toBe('string');
    if (entry['disposition'] === 'copied' && entry['changes'] === 'none') expect(actual, path).toBe(entry['upstreamSha256']);
    const rows = notice.split(/\r?\n/).filter(row => row.startsWith('|') && row.includes(`\`${path}\``));
    expect(rows, path).toHaveLength(1);
    for (const field of ['upstreamPath', 'upstreamSha256', 'disposition', 'changes']) {
      expect(rows[0], `${path} ${field}`).toContain(entry[field]);
    }
  }
}
