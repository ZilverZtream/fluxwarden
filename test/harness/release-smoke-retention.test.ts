import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { beforeAll, expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';
import { testRoot } from '../helpers/env.js';

// CP-044 / RATCHET sections 6 and 13: nested validation commands are part of
// the original invocation evidence, including a command whose result is rejected.
// This dependency-free fixture executes a real offline npm install and its real
// installed CLI. The oracle records bytes produced by those fixture children;
// oracle/source/package files are never credited as retained execution evidence.
const npm = process.env.npm_execpath?.endsWith('npm-cli.js') ? process.env.npm_execpath
  : join(dirname(process.execPath), process.platform === 'win32'
    ? 'node_modules/npm/bin/npm-cli.js' : '../lib/node_modules/npm/bin/npm-cli.js');
let fixture: string;
let tarball: string;
let bridge: string;

beforeAll(() => {
  fixture = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'smoke-retention-'));
  const source = join(fixture, 'source');
  mkdirSync(join(source, 'dist/cli'), { recursive: true });
  mkdirSync(join(source, 'dist/evidence'));
  writeFileSync(join(source, 'package.json'), JSON.stringify({ name: 'fluxwarden', version: '9.8.7',
    type: 'module', bin: { fluxwarden: 'dist/cli/bin.js' }, files: ['dist', 'README.md', 'LICENSE', 'SECURITY.md', 'CHANGELOG.md', 'NOTICE-SOURCE-REUSE.md'] }));
  for (const name of ['README.md', 'LICENSE', 'SECURITY.md', 'CHANGELOG.md']) writeFileSync(join(source, name), 'Synthetic offline smoke fixture.\n');
  // Audit F09: a valid smoke fixture must carry the actual upstream reuse notice.
  writeFileSync(join(source, 'NOTICE-SOURCE-REUSE.md'), readFileSync(join(repoRoot, 'NOTICE-SOURCE-REUSE.md')));
  writeFileSync(join(source, 'dist/evidence/build-info.json'), JSON.stringify({ gitCommit: 'a'.repeat(40) }));
  writeFileSync(join(source, 'dist/cli/bin.js'), `#!/usr/bin/env node
import { appendFileSync } from 'node:fs';
const args = process.argv.slice(2);
let status = 0;
let stdout;
if (args[0] === '--version') stdout = Buffer.from('9.8.7\\n');
else if (args[0] === '--help') {
  stdout = Buffer.concat([Buffer.from('doctor café help\\n'), Buffer.from([255, 128, 10])]);
  if (process.env.FW_RETENTION_FAILURE === 'yes') status = 7;
} else {
  status = 2;
  stdout = Buffer.from(JSON.stringify({ schema: 1, ok: false, result: null,
    error: { code: 2 }, command: args.slice(0, args[0] === 'liquidity' ? 2 : 1).join(' ') }) + '\\n');
}
const stderr = Buffer.concat([Buffer.from('fixture café ' + args.join(' ') + '\\n'), Buffer.from([254, 129, 10])]);
appendFileSync(process.env.FW_RETENTION_ORACLE, JSON.stringify({ stdout: stdout.toString('base64'),
  stderr: stderr.toString('base64'), status }) + '\\n');
process.stdout.write(stdout);
process.stderr.write(stderr);
process.exitCode = status;
`);
  const packed = spawnSync(process.execPath, [npm, 'pack', '--offline', '--ignore-scripts', '--json', '--pack-destination', fixture],
    { cwd: source, env: { ...process.env, NODE_OPTIONS: '', NODE_DEBUG: '' }, windowsHide: true, timeout: 10_000 });
  expect(packed.error).toBeUndefined();
  expect(packed.status).toBe(0);
  tarball = join(fixture, 'fluxwarden-9.8.7.tgz');
  bridge = join(fixture, 'npm-bridge.mjs');
  // A transparent fixture executable adds distinctive raw output around the real
  // installer streams. It returns the actual install result, never a fake result.
  writeFileSync(bridge, `import { spawnSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';
const result = spawnSync(process.execPath, [${JSON.stringify(npm)}, ...process.argv.slice(2)],
  { env: process.env, windowsHide: true, timeout: 10000 });
if (result.error) throw result.error;
const stdout = Buffer.concat([Buffer.from('offline café install\\n'), Buffer.from([253, 130, 10]), result.stdout]);
const stderr = Buffer.concat([Buffer.from('offline café diagnostic\\n'), Buffer.from([252, 131, 10]), result.stderr]);
appendFileSync(process.env.FW_RETENTION_ORACLE, JSON.stringify({ stdout: stdout.toString('base64'),
  stderr: stderr.toString('base64'), status: result.status }) + '\\n');
process.stdout.write(stdout); process.stderr.write(stderr); process.exitCode = result.status;
`);
});

interface CommandOutput { stdout: string; stderr: string; status: number }

function retainedFiles(directory: string): Buffer[] {
  const result: Buffer[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) result.push(...retainedFiles(path));
    else if (entry.isFile()) result.push(readFileSync(path));
  }
  return result;
}

// Accept safe structured exit records in either captured streams or retained
// files. Their location and additional safe fields are deliberately unspecified.
function statuses(buffers: Buffer[]): number[] {
  const result: number[] = [];
  const visit = (value: unknown): void => {
    if (!value || typeof value !== 'object') return;
    if (Array.isArray(value)) { value.forEach(visit); return; }
    const object = value as Record<string, unknown>;
    const status = object.status ?? object.exitCode;
    if (typeof status === 'number' && (object.signal === null || object.signal === undefined)
      && (object.error === null || object.error === undefined)) result.push(status);
    for (const child of Object.values(object)) visit(child);
  };
  for (const buffer of buffers) {
    const text = buffer.toString('utf8');
    try { visit(JSON.parse(text)); continue; } catch { /* Also accept JSONL mixed with raw output. */ }
    for (const line of text.split(/\r?\n/)) {
      try { visit(JSON.parse(line)); } catch { /* Raw child output is not a status record. */ }
    }
  }
  return result;
}

for (const failure of [false, true]) {
  it(`CP-044/release-smoke-retention-${failure ? 'failure' : 'success'} retains complete nested command bytes and statuses after cleanup`, async () => {
    const scenario = mkdtempSync(join(fixture, failure ? 'failure-' : 'success-'));
    const oracle = join(scenario, 'oracle.jsonl');
    const roots = ['temp', 'tmp', 'scratch', 'sources', 'evidence'].map(name => join(scenario, name));
    roots.forEach(path => { mkdirSync(path, { mode: 0o700 }); });
    const scratch = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as {
      assertPrivateDirectories: (paths: string[]) => Promise<void>;
    };
    await scratch.assertPrivateDirectories(roots);
    // Windows Vitest workers can inherit an uppercase alias. Node's child env
    // normalization would choose it before the owned lowercase bridge override.
    const env = { ...process.env };
    for (const key of Object.keys(env)) if (key.toLowerCase() === 'npm_execpath') Reflect.deleteProperty(env, key);
    const result = spawnSync(process.execPath, [join(repoRoot, 'scripts/release-smoke.mjs'), tarball], {
      cwd: repoRoot, windowsHide: true, timeout: 10_000,
      env: { ...env, NODE_OPTIONS: '', NODE_DEBUG: '', npm_execpath: bridge,
        TEMP: roots[0], TMP: roots[1], FLUXWARDEN_TEST_TMP: roots[2],
        FLUXWARDEN_SENTINEL_DIR: roots[3], FLUXWARDEN_EVIDENCE_DIR: roots[4],
        FW_RETENTION_ORACLE: oracle, FW_RETENTION_FAILURE: failure ? 'yes' : 'no' },
    });
    // Preserve the exact public invocation result, outside the evidence census.
    writeFileSync(join(scenario, 'outer.stdout'), result.stdout);
    writeFileSync(join(scenario, 'outer.stderr'), result.stderr);
    writeFileSync(join(scenario, 'outer-result.json'), JSON.stringify({ status: result.status,
      signal: result.signal, error: result.error?.name ?? null }));
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(failure ? 1 : 0);
    const expected = readFileSync(oracle, 'utf8').trim().split('\n').map(line => JSON.parse(line) as CommandOutput);
    expect(expected.map(output => output.status)).toEqual(failure ? [0, 0, 7] : [0, 0, 0, 2, 2, 2, 2]);
    const files = roots.flatMap(retainedFiles);
    const retained = [result.stdout, result.stderr, ...files];
    const observations = expected.map(output => ({
      stdout: retained.some(bytes => bytes.includes(Buffer.from(output.stdout, 'base64'))),
      stderr: retained.some(bytes => bytes.includes(Buffer.from(output.stderr, 'base64'))),
    }));
    const exits = statuses(retained);
    const classified = expected.map(output => {
      const index = exits.indexOf(output.status);
      if (index < 0) return false;
      exits.splice(index, 1);
      return true;
    });
    writeFileSync(join(scenario, 'retention-result.json'), JSON.stringify({ observations, classified }));
    // Boolean-only diagnostics prevent raw fixture streams appearing in reports.
    expect.soft(observations.every(output => output.stdout && output.stderr), 'all original nested streams survive validation and cleanup byte-for-byte').toBe(true);
    expect.soft(classified.every(Boolean), 'each original nested command has a retained safe execution status').toBe(true);
  });
}
