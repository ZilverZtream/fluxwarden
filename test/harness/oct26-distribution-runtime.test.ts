// Independent October 26 audit F08/F09/F10 and owner decision D29.
// Advisory patch floors are quoted in the audit; patch releases remain compatible,
// but every direct tool remains an exact pin and the lock must agree with it.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { expect, it } from 'vitest';
import { asRecord, childEnv, readJson, readText, repoRoot } from '../helpers/cli.js';
import { testRoot } from '../helpers/env.js';
import { parseYaml } from '../helpers/yaml.js';

function version(value: unknown): [number, number, number] {
  expect(value, 'toolchain versions must remain exact stable pins').toMatch(/^\d+\.\d+\.\d+$/);
  const [major = 0, minor = 0, patch = 0] = String(value).split('.').map(Number);
  return [major, minor, patch];
}

it('CP-044/F08 exact direct pins and every locked Vite launch-editor and fast-uri copy meet compatible advisory patch floors', () => {
  const manifest = asRecord(readJson('package.json'), 'package');
  const direct = asRecord(manifest['devDependencies'], 'direct toolchain');
  const packages = asRecord(asRecord(readJson('package-lock.json'), 'lock')['packages'], 'locked packages');
  expect(asRecord(packages[''], 'lock root')['devDependencies']).toEqual(direct);
  for (const [name, pin] of Object.entries(direct)) {
    version(pin);
    expect(asRecord(packages[`node_modules/${name}`], 'locked direct package')['version'], name).toBe(pin);
  }
  // launch-editor 2.14.2: parent independently verified the primary advisory
  // on October 26 alongside the audit's Vite and fast-uri patch floors.
  for (const [name, major, minor, patch] of [['vite', 8, 3, 3], ['launch-editor', 2, 14, 2], ['fast-uri', 3, 1, 9]] as const) {
    const copies = Object.entries(packages).filter(([path]) => path.endsWith(`/node_modules/${name}`) || path === `node_modules/${name}`);
    // launch-editor is checked if installed; its absence is safe and does not
    // require adding a dependency merely to satisfy the advisory oracle.
    if (name !== 'launch-editor') expect(copies.length, `${name} must have a locked audited dependency`).toBeGreaterThan(0);
    for (const [path, row] of copies) {
      const [actualMajor, actualMinor, actualPatch] = version(asRecord(row, path)['version']);
      expect(actualMajor, `${path}: retain the reviewed compatible major`).toBe(major);
      expect.soft(actualMinor > minor || actualMinor === minor && actualPatch >= patch,
        `${path}: October 26 primary advisory patch floor`).toBe(true);
    }
  }
  for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'bundledDependencies']) {
    expect(Object.keys(manifest[field] ?? {}), 'D29 zero runtime dependencies').toEqual([]);
  }
});

function tarMembers(bytes: Buffer): Map<string, Buffer> {
  const tar = gunzipSync(bytes), entries = new Map<string, Buffer>();
  for (let offset = 0; offset + 512 <= tar.length;) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) break;
    const text = (start: number, end: number): string => header.subarray(start, end).toString('utf8').replace(/\0.*$/s, '');
    const prefix = text(345, 500), name = `${prefix ? `${prefix}/` : ''}${text(0, 100)}`;
    const size = parseInt(text(124, 136).trim(), 8);
    expect(Number.isSafeInteger(size) && size >= 0 && offset + 512 + size <= tar.length).toBe(true);
    expect(entries.has(name), 'duplicate tar member').toBe(false);
    entries.set(name, tar.subarray(offset + 512, offset + 512 + size));
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return entries;
}

it('CP-044/F09 the actual compressed npm package preserves the complete upstream attribution and permission notice', () => {
  const output = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'oct26-notice-'));
  const npm = process.env['npm_execpath'] ?? join(dirname(process.execPath), process.platform === 'win32'
    ? 'node_modules/npm/bin/npm-cli.js' : '../lib/node_modules/npm/bin/npm-cli.js');
  const result = spawnSync(process.execPath, [npm, 'pack', '--offline', '--json', '--pack-destination', output], {
    cwd: repoRoot, env: childEnv(), encoding: 'utf8', windowsHide: true, timeout: 120_000,
  });
  expect(result.error, 'actual pack must complete before artifact assertions').toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
  const packed = JSON.parse(result.stdout) as { filename: string }[];
  expect(packed).toHaveLength(1);
  const first = packed[0];
  if (!first) throw new Error('actual npm pack produced no artifact');
  const filename = first.filename;
  expect(filename).toMatch(/^fluxwarden-[0-9.]+\.tgz$/);
  const members = tarMembers(readFileSync(join(output, filename)));
  const notice = members.get('package/NOTICE-SOURCE-REUSE.md');
  expect(notice, 'F09 requires the notice inside the actual tarball').toBeDefined();
  expect(notice?.equals(readFileSync(join(repoRoot, 'NOTICE-SOURCE-REUSE.md'))),
    'retain upstream attribution and permission text without truncation or replacement').toBe(true);
}, 150_000);

it('CP-044/F10 Linux and Windows validate minimum and moving Node 26 while retaining the supported 22 and 24 targets', () => {
  const workflow = asRecord(parseYaml(readText('.github/workflows/ci.yml')), 'CI');
  const jobs = asRecord(workflow['jobs'], 'jobs');
  const rows: Record<string, unknown>[] = [];
  for (const job of Object.values(jobs)) {
    const strategy = asRecord(job, 'job')['strategy'];
    if (!strategy) continue;
    const matrix = asRecord(asRecord(strategy, 'strategy')['matrix'], 'matrix');
    let combinations: Record<string, unknown>[] = [{}];
    for (const [key, values] of Object.entries(matrix)) {
      if (key === 'include' || key === 'exclude') continue;
      expect(Array.isArray(values), 'static auditable matrix axis').toBe(true);
      combinations = combinations.flatMap(row => (values as unknown[]).map(value => ({ ...row, [key]: value })));
    }
    const excluded = (matrix['exclude'] ?? []) as Record<string, unknown>[];
    rows.push(...combinations.filter(row => !excluded.some(exclusion => Object.entries(exclusion).every(([key, value]) => row[key] === value))));
    rows.push(...(matrix['include'] ?? []) as Record<string, unknown>[]);
  }
  for (const os of ['ubuntu-latest', 'windows-latest']) {
    for (const node of ['22.23.2', '22.x', '24.18.1', '24.x', '26.5.1', '26.x']) {
      expect(rows.some(row => row['os'] === os && row['node'] === node), `${os}, Node ${node}: audit F10 / D29`).toBe(true);
    }
  }
});
