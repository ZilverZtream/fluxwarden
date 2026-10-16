// CP-036/B5: a successful dispatch must have real, credential-free evidence to upload.
// Selection and artifact production are independent obligations. A bounded owned
// reporter fixture proves truthful failure evidence, never real chaos coverage.
import { spawnSync } from 'node:child_process';
import { copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { asRecord, childEnv, readText, repoRoot } from '../helpers/cli.js';
import { testRoot } from '../helpers/env.js';
import { parseYaml } from '../helpers/yaml.js';

function files(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? files(path) : entry.isFile() ? [path] : [];
  });
}

it('CP-033/034 without a live plan the chaos command selects its existing fake-node matrix and excludes live references', () => {
  const output = join(mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'chaos-selection-')), 'files.json');
  const env = childEnv();
  Reflect.deleteProperty(env, 'FLUXWARDEN_LAB_PLAN');
  Reflect.deleteProperty(env, 'FLUXWARDEN_CHAOS_REFERENCE_PLAN');
  const result = spawnSync(process.execPath, [join(repoRoot, 'node_modules/vitest/vitest.mjs'), 'list',
    '--config', 'vitest.chaos.config.ts', '--filesOnly', `--json=${output}`], {
    cwd: repoRoot, env, encoding: 'utf8', windowsHide: true, timeout: 10_000,
  });
  expect(result.error, result.stderr).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
  const selected: unknown = JSON.parse(readFileSync(output, 'utf8'));
  if (!Array.isArray(selected)) throw new Error('chaos file inventory must be a list');
  const paths = selected.map(value => relative(repoRoot, String(asRecord(value, 'selected file')['file'])).replace(/\\/g, '/'));
  for (const file of ['test/chaos/t01-t12.test.ts', 'test/chaos/t13-t25.test.ts', 'test/chaos/matrix-wire.test.ts']) {
    expect(paths, `the no-plan chaos command must run existing CP-033/034 assertions in ${file}`).toContain(file);
  }
  expect(paths.filter(path => path.endsWith('.live.test.ts')), 'live references require their explicit inputs').toEqual([]);
}, 15_000);

it('CP-033/034 selecting live references retains the ordinary fake-node matrix as additional coverage', () => {
  const scratch = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'chaos-live-selection-'));
  const output = join(scratch, 'files.json');
  // Listing does not import or run test files. These nonexistent markers are only
  // selection inputs and establish no owner, readiness, live outcome or coverage.
  const env = { ...childEnv(), FLUXWARDEN_LAB_PLAN: join(scratch, 'selection-only-owner.json'),
    FLUXWARDEN_CHAOS_REFERENCE_PLAN: join(scratch, 'selection-only-reference.json') };
  const result = spawnSync(process.execPath, [join(repoRoot, 'node_modules/vitest/vitest.mjs'), 'list',
    '--config', 'vitest.chaos.config.ts', '--filesOnly', `--json=${output}`], {
    cwd: repoRoot, env, encoding: 'utf8', windowsHide: true, timeout: 10_000,
  });
  expect(result.error, result.stderr).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
  const selected: unknown = JSON.parse(readFileSync(output, 'utf8'));
  if (!Array.isArray(selected)) throw new Error('chaos file inventory must be a list');
  const paths = selected.map(value => relative(repoRoot, String(asRecord(value, 'selected file')['file'])).replace(/\\/g, '/'));
  for (const file of ['test/chaos/t01-t12.test.ts', 'test/chaos/t13-t25.test.ts', 'test/chaos/matrix-wire.test.ts',
    'test/chaos/cp033-owned-reference.live.test.ts', 'test/chaos/cp034-balance-reference.live.test.ts', 'test/chaos/cp034-chain-reference.live.test.ts']) {
    expect(paths, `live selection must preserve ${file}`).toContain(file);
  }
}, 15_000);

it('CP-036/B5 the actual chaos workflow command records real assertion outcomes in its scanned upload directory', () => {
  const workflow = asRecord(parseYaml(readText('.github/workflows/ci.yml')), 'workflow');
  const chaos = asRecord(asRecord(workflow['jobs'], 'jobs')['chaos'], 'chaos');
  const stepsValue = chaos['steps'];
  if (!Array.isArray(stepsValue)) throw new Error('chaos steps required');
  const steps = stepsValue.map(step => asRecord(step, 'step'));
  const run = steps.findIndex(step => typeof step['run'] === 'string' && /\bnpm run test:chaos\b/.test(step['run']));
  const scan = steps.findIndex(step => typeof step['run'] === 'string' && /scripts\/leak-check\.mjs/.test(step['run']));
  const upload = steps.findIndex(step => typeof step['uses'] === 'string' && step['uses'].startsWith('actions/upload-artifact@'));
  expect(run, 'actual chaos command exists').toBeGreaterThanOrEqual(0);
  expect(scan, 'evidence is scanned after generation').toBeGreaterThan(run);
  expect(upload, 'only scanned evidence is uploaded').toBeGreaterThan(scan);
  const uploadOptions = asRecord(steps[upload]?.['with'], 'upload options');
  expect(uploadOptions['if-no-files-found'], 'missing evidence must remain an error').toBe('error');

  const scratch = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'chaos-workflow-evidence-'));
  const evidence = join(scratch, 'chaos-evidence');
  const sentinels = join(scratch, 'chaos-sentinels');
  const tests = join(scratch, 'chaos-tests');
  for (const directory of [evidence, sentinels, tests]) mkdirSync(directory, { mode: 0o700 });
  const fixture = join(scratch, 'reporter-fixture');
  mkdirSync(join(fixture, 'test/chaos'), { recursive: true });
  for (const file of ['package.json', 'vitest.config.ts', 'vitest.chaos.config.ts']) copyFileSync(join(repoRoot, file), join(fixture, file));
  cpSync(join(repoRoot, 'scripts'), join(fixture, 'scripts'), { recursive: true });
  // A deliberate failure control verifies that evidence reflects executed assertions.
  // This fixture is not substituted for the real matrix or used as coverage evidence.
  writeFileSync(join(fixture, 'test/chaos/reporter-control.live.test.ts'), `import { expect, it } from 'vitest';
it('reporter passing control', () => { expect(2 + 2).toBe(4); });
it('reporter failing control', () => { expect('observed result').toBe('required result'); });
`);
  const dependencies = join(fixture, 'node_modules');
  symlinkSync(realpathSync(join(repoRoot, 'node_modules')), dependencies, process.platform === 'win32' ? 'junction' : 'dir');
  const expand = (value: string): string => value
    .replace(/\$\{\{\s*runner\.temp\s*\}\}|\$\{RUNNER_TEMP\}|\$RUNNER_TEMP/g, scratch)
    .replace(/\$\{FLUXWARDEN_EVIDENCE_DIR\}|\$FLUXWARDEN_EVIDENCE_DIR/g, evidence);
  const uploaded = resolve(expand(String(uploadOptions['path'])));
  const inside = relative(scratch, uploaded);
  expect(inside && !inside.startsWith('..') && !isAbsolute(inside), 'upload stays in this run scratch').toBeTruthy();
  expect(expand(String(steps[scan]?.['run'])).replace(/\\/g, '/'), 'scanner covers uploaded directory').toContain(uploaded.replace(/\\/g, '/'));

  const command = expand(String(steps[run]?.['run'])).trim();
  // Interpret simple argv only; do not execute workflow text through a shell.
  const argv = (command.match(/"[^"]*"|'[^']*'|[^\s]+/g) ?? []).map(arg => arg.replace(/^(["'])(.*)\1$/, '$2'));
  expect(argv.slice(0, 3)).toEqual(['npm', 'run', 'test:chaos']);
  expect(argv.some(arg => /[;&|`\r\n]/.test(arg)), 'chaos command uses simple arguments').toBe(false);
  const npmCli = process.env['npm_execpath'] ?? (process.platform === 'win32'
    ? join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js')
    : join(dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js'));
  const env = { ...childEnv(), RUNNER_TEMP: scratch, FLUXWARDEN_TEST_TMP: tests, FLUXWARDEN_SENTINEL_DIR: sentinels,
    FLUXWARDEN_EVIDENCE_DIR: evidence, FLUXWARDEN_LAB_PLAN: join(fixture, 'selection-only-marker.json') };
  Reflect.deleteProperty(env, 'FLUXWARDEN_CHAOS_REFERENCE_PLAN');
  const result = (() => {
    try {
      return spawnSync(process.execPath, [npmCli, ...argv.slice(1)], {
        cwd: fixture, env, encoding: 'utf8', windowsHide: true, timeout: 15_000,
      });
    } finally { unlinkSync(dependencies); }
  })();
  expect(result.error, result.stderr).toBeUndefined();
  const reports = existsSync(uploaded) ? files(uploaded).filter(path => path.endsWith('.json')) : [];
  expect(reports.length, 'the actual chaos command must create a JSON test report before scan/upload; mkdir alone leaves no uploadable evidence').toBeGreaterThan(0);
  const report = asRecord(JSON.parse(readFileSync(reports[0] ?? '', 'utf8')) as unknown, 'chaos test report');
  expect(result.status, 'a reported assertion failure must remain a failing command').toBe(1);
  expect(report['success']).toBe(false);
  expect(report['numTotalTests']).toBe(2);
  expect(report['numPassedTests']).toBe(1);
  expect(report['numFailedTests']).toBe(1);
  expect(report['numPendingTests']).toBe(0);
  const results = report['testResults'];
  if (!Array.isArray(results)) throw new Error('actual test results required');
  expect(results).toHaveLength(1);
  const assertions = asRecord(results[0], 'test file')['assertionResults'];
  if (!Array.isArray(assertions)) throw new Error('actual assertion results required');
  expect(assertions.map(value => asRecord(value, 'assertion')['status']).sort()).toEqual(['failed', 'passed']);
}, 20_000);
