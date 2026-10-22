// CP-036/B5: a successful dispatch must have real, credential-free evidence to upload.
// Selection and artifact production are independent obligations. A bounded owned
// reporter fixture proves truthful failure evidence, never real chaos coverage.
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { asRecord, childEnv, readText, repoRoot } from '../helpers/cli.js';
import { testRoot } from '../helpers/env.js';
import { declareFixtureCapture, declareFixturePaths, ownedCaptureToolArgs } from '../helpers/capture-fixture.js';
import { parseYaml } from '../helpers/yaml.js';

function files(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? files(path) : entry.isFile() ? [path] : [];
  });
}

function copyPhysicalToolInputs(source: string, destination: string): void {
  const root = realpathSync.native(source);
  const inputs: { source: string; destination: string; directory: boolean }[] = [];
  const validate = (path: string, output: string, ancestors: ReadonlySet<string>): void => {
    const info = lstatSync(path), target = realpathSync.native(path), within = relative(root, target);
    if (isAbsolute(within) || within === '..' || within.startsWith(`..${sep}`)) {
      throw new Error('fixture tool input resolves outside the original dependency root');
    }
    if (info.isSymbolicLink() && ['.vite', '.vite-temp'].some(name => within === name || within.startsWith(`${name}${sep}`))) {
      throw new Error('generated cache cannot supply fixture tool input through a link');
    }
    const physical = info.isSymbolicLink() ? statSync(path) : info;
    if (physical.isDirectory()) {
      if (ancestors.has(target)) throw new Error('fixture tool input contains a directory link cycle');
      inputs.push({ source: target, destination: output, directory: true });
      const next = new Set(ancestors).add(target);
      for (const name of readdirSync(target)) validate(join(target, name), join(output, name), next);
    } else if (physical.isFile()) inputs.push({ source: target, destination: output, directory: false });
    else throw new Error('fixture tool input must resolve to a regular file or directory');
  };
  const validatePhysical = (path: string): void => {
    const info = lstatSync(path);
    if (info.isSymbolicLink() || (!info.isDirectory() && !info.isFile())) {
      throw new Error('fixture tool copy must contain only physical regular files and directories');
    }
    if (info.isDirectory()) for (const name of readdirSync(path)) validatePhysical(join(path, name));
  };
  // Validate the complete pinned graph before copying only its canonical inputs.
  // Explicit file/directory writes leave no links for the outer Closing scan.
  validate(root, destination, new Set());
  if (existsSync(destination)) validatePhysical(destination);
  for (const input of inputs) {
    if (input.directory) mkdirSync(input.destination, { recursive: true });
    else copyFileSync(input.source, input.destination);
  }
  validatePhysical(destination);
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
  const install = steps.findIndex(step => typeof step['run'] === 'string' && /^node scripts\/ci-install\.mjs --root "\$PWD"$/.test(step['run'].trim()));
  const scan = steps.findIndex(step => typeof step['run'] === 'string' && /scripts\/leak-check\.mjs/.test(step['run']));
  const verify = steps.findIndex(step => typeof step['run'] === 'string' && /scripts\/ci-capture\.mjs verify\b/.test(step['run']));
  const uploads = steps.map((step, index) => ({ step, index })).filter(({ step }) => typeof step['uses'] === 'string' &&
    step['uses'].startsWith('actions/upload-artifact@') && asRecord(step['with'], 'upload options')['name'] === 'chaos-evidence');
  expect(uploads, 'one original evidence-directory upload remains separate from the safe receipt').toHaveLength(1);
  const upload = uploads[0]?.index ?? -1;
  expect(run, 'actual chaos command exists').toBeGreaterThanOrEqual(0);
  expect(install, 'trusted frozen-lock setup precedes candidate validation').toBeGreaterThanOrEqual(0);
  expect(run).toBeGreaterThan(install);
  expect(steps[run]?.['if'], 'original installer failure still enters evidence capture').toBe('always()');
  expect(verify, 'complete invocation verification follows generation').toBeGreaterThan(run);
  expect(scan, 'evidence scan belongs to the same complete captured command').toBe(run);
  expect(upload, 'upload follows complete invocation verification').toBeGreaterThan(verify);
  expect(upload, 'only scanned evidence is uploaded').toBeGreaterThan(scan);
  expect(steps[verify]?.['if'], 'capture is finalized on command failure').toBe('always()');
  expect(String(steps[upload]?.['if'])).toContain("steps.capture-verify.outcome == 'success'");
  const receiptUploads = steps.filter(step => typeof step['uses'] === 'string' && step['uses'].startsWith('actions/upload-artifact@') &&
    String(asRecord(step['with'], 'upload options')['path']).trim().endsWith('/receipt.json'));
  expect(receiptUploads, 'a separate safe receipt accompanies the single evidence-directory upload').toHaveLength(1);
  expect(steps.filter(step => typeof step['uses'] === 'string' && step['uses'].startsWith('actions/upload-artifact@'))).toHaveLength(2);
  const uploadOptions = asRecord(steps[upload]?.['with'], 'upload options');
  expect(uploadOptions['if-no-files-found'], 'missing evidence must remain an error').toBe('error');

  const scratch = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'ce-'));
  const evidence = join(scratch, 'chaos-evidence');
  const sentinels = join(scratch, 'chaos-sentinels');
  const tests = join(scratch, 'chaos-tests');
  const capture = join(scratch, 'chaos-capture'), temp = join(scratch, 'temp'), tmp = join(scratch, 'tmp');
  for (const directory of [evidence, sentinels, tests, capture, temp, tmp]) mkdirSync(directory, { mode: 0o700 });
  const fixture = join(scratch, 'r');
  mkdirSync(join(fixture, 'test/chaos'), { recursive: true });
  for (const file of ['package.json', '.gitignore', 'vitest.config.ts', 'vitest.chaos.config.ts']) copyFileSync(join(repoRoot, file), join(fixture, file));
  const support = [...readdirSync(join(repoRoot, 'scripts')).filter(name => /^ci-.*\.mjs$/.test(name)),
    'leak-check.mjs', 'private-scratch.mjs', 'no-pending.mjs'];
  mkdirSync(join(fixture, 'scripts'));
  for (const name of support) copyFileSync(join(repoRoot, 'scripts', name), join(fixture, 'scripts', name));
  expect(createHash('sha256').update(readFileSync(join(fixture, 'scripts/leak-check.mjs'))).digest('hex'), 'the executed scanner is copied without modification')
    .toBe(createHash('sha256').update(readFileSync(join(repoRoot, 'scripts/leak-check.mjs'))).digest('hex'));
  mkdirSync(join(fixture, 'test/sentinels'));
  // This control proves reporter outcomes rather than five-kind coverage. Its
  // independent disposable INPUT and retained copies are declared before write.
  const controlSource = join(fixture, 'test/sentinels/reporter-control.bin'), controlBytes = randomBytes(32);
  declareFixturePaths([controlSource]);
  declareFixtureCapture(capture, [controlBytes], []);
  writeFileSync(controlSource, controlBytes, { mode: 0o600 });
  writeFileSync(join(fixture, 'test/sentinels.json'), JSON.stringify(['test/sentinels/reporter-control.bin']));
  // A deliberate failure control verifies that evidence reflects executed assertions.
  // This fixture is not substituted for the real matrix or used as coverage evidence.
  writeFileSync(join(fixture, 'test/chaos/reporter-control.live.test.ts'), `import { expect, it } from 'vitest';
it('reporter passing control', () => { expect(2 + 2).toBe(4); });
it('reporter failing control', () => { expect('observed result').toBe('required result'); });
`);
  const dependencies = join(fixture, 'node_modules');
  // Real trusted setup installs the dependency-free owned package offline. The
  // stale canary proves setup precedes build. Pinned test-tool inputs are copied
  // into this owned checkout before capture authenticates its original read-set.
  const pkg = asRecord(JSON.parse(readFileSync(join(fixture, 'package.json'), 'utf8')) as unknown, 'fixture package');
  asRecord(pkg['scripts'], 'fixture scripts')['build'] = 'node build-control.mjs';
  pkg['devDependencies'] = {};
  writeFileSync(join(fixture, 'package.json'), JSON.stringify(pkg));
  writeFileSync(join(fixture, 'package-lock.json'), JSON.stringify({ name: pkg['name'], version: pkg['version'], lockfileVersion: 3,
    packages: { '': { name: pkg['name'], version: pkg['version'] } } }));
  writeFileSync(join(fixture, 'build-control.mjs'), `import { existsSync, lstatSync } from 'node:fs'; import { join, resolve } from 'node:path';
const modules = resolve('node_modules');
if (modules !== join(process.cwd(), 'node_modules') || existsSync(join(modules, 'install-canary'))) throw new Error('offline install did not finish before build');
if (!lstatSync(modules).isDirectory() || lstatSync(modules).isSymbolicLink()) throw new Error('original owned regular dependencies required');
`);
  const observer = join(fixture, 'observe-processes.mjs'), trace = join(tests, 'processes.jsonl');
  // Observe actual external command starts/exits without substituting a command,
  // report, scanner, return value or filesystem result.
  writeFileSync(observer, `import cp from 'node:child_process'; import { appendFileSync } from 'node:fs'; import { syncBuiltinESMExports } from 'node:module';
const original = cp.spawn, trace = ${JSON.stringify(trace)};
cp.spawn = function(command, args, options) {
 appendFileSync(trace, JSON.stringify({ event: 'start', command, args }) + '\\n');
 const child = original.call(this, command, args, options);
 child.once('close', code => appendFileSync(trace, JSON.stringify({ event: 'close', command, args, code }) + '\\n'));
 return child;
}; syncBuiltinESMExports();
`);
  const expand = (value: string): string => value
    .replace(/\$\{\{\s*runner\.temp\s*\}\}|\$\{RUNNER_TEMP\}|\$RUNNER_TEMP/g, scratch)
    .replace(/\$\{\{\s*env\.FLUXWARDEN_EVIDENCE_DIR\s*\}\}|\$\{FLUXWARDEN_EVIDENCE_DIR\}|\$FLUXWARDEN_EVIDENCE_DIR/g, evidence)
    .replace(/\$\{FLUXWARDEN_SENTINEL_DIR\}|\$FLUXWARDEN_SENTINEL_DIR/g, sentinels)
    .replace(/\$\{FLUXWARDEN_CI_CAPTURE_DIR\}|\$FLUXWARDEN_CI_CAPTURE_DIR/g, capture)
    .replace(/\$PWD/g, fixture);
  const uploaded = resolve(expand(String(uploadOptions['path'])));
  const inside = relative(scratch, uploaded);
  expect(inside && !inside.startsWith('..') && !isAbsolute(inside), 'upload stays in this run scratch').toBeTruthy();
  expect(expand(String(steps[scan]?.['run'])).replace(/\\/g, '/'), 'scanner covers uploaded directory').toContain(uploaded.replace(/\\/g, '/'));

  const command = expand(String(steps[run]?.['run'])).trim();
  // Interpret simple argv only; do not execute workflow text through a shell.
  const argv = (command.match(/"[^"]*"|'[^']*'|[^\s]+/g) ?? []).map(arg => arg.replace(/^(["'])(.*)\1$/, '$2'));
  expect(argv.slice(0, 2)).toEqual(['node', 'scripts/ci-capture.mjs']);
  const separator = argv.indexOf('--');
  expect(argv.slice(2, separator), 'the wrapper is bound to this fixture identity and private capture').toEqual(['--root', fixture, '--capture-dir', capture]);
  expect(argv.slice(separator + 1, separator + 10), 'the captured job checks the original trusted installer result before validation')
    .toEqual(['node', 'scripts/ci-job.mjs', '--commands-only', '--', 'node', 'scripts/ci-install.mjs', 'verify', '--root', fixture]);
  const buildIndex = argv.indexOf('--next'), testIndex = argv.indexOf('--next', buildIndex + 1), finalIndex = argv.indexOf('--finally');
  expect(argv.slice(buildIndex + 1, testIndex), 'build follows original installation verification').toEqual(['npm', 'run', 'build']);
  expect(argv.slice(testIndex + 1, testIndex + 4), 'the same selected chaos command follows build').toEqual(['npm', 'run', 'test:chaos']);
  expect(argv.slice(finalIndex), 'the unchanged scanner is an explicit final stage with original source/evidence arguments').toEqual([
    '--finally', 'node', 'scripts/leak-check.mjs', '--sentinels', 'test/sentinels.json', '--sentinel-dir', sentinels, evidence,
  ]);
  expect(argv.some(arg => /[;&|`\r\n]/.test(arg)), 'chaos command uses simple arguments').toBe(false);
  const env = { ...childEnv(), npm_config_offline: 'true', RUNNER_TEMP: scratch,
    TEMP: temp, TMP: tmp, FLUXWARDEN_TEST_TMP: tests, FLUXWARDEN_SENTINEL_DIR: sentinels,
    FLUXWARDEN_CI_CAPTURE_DIR: capture, FLUXWARDEN_EVIDENCE_DIR: evidence, FLUXWARDEN_LAB_PLAN: join(fixture, 'selection-only-marker.json') };
  Reflect.deleteProperty(env, 'FLUXWARDEN_CHAOS_REFERENCE_PLAN');
  // Capture requires an actual immutable candidate identity. This bounded
  // synthetic checkout contains only owned reporter controls and public tools.
  const manifest = ['.gitignore', 'package.json', 'package-lock.json', 'build-control.mjs', 'observe-processes.mjs', 'vitest.config.ts', 'vitest.chaos.config.ts',
    'test/chaos/reporter-control.live.test.ts', 'test/sentinels.json', 'test/sentinels/reporter-control.bin', ...support.map(name => `scripts/${name}`)];
  for (const args of [['init', '--quiet'], ['config', 'core.longpaths', 'true'], ['add', '--', ...manifest], ['-c', 'user.name=CI reporter fixture',
    '-c', 'user.email=fixture@invalid', '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'owned reporter fixture']]) {
    const initialized = spawnSync('git', [...args], { cwd: fixture, env, encoding: 'utf8', windowsHide: true, timeout: 10_000 });
    expect(initialized.status, 'owned reporter fixture has real Git identity').toBe(0);
  }
  mkdirSync(dependencies);
  writeFileSync(join(dependencies, 'install-canary'), 'owned stale install canary');
  const installed = spawnSync(process.execPath, [...ownedCaptureToolArgs([join(fixture, 'scripts/ci-install.mjs'), '--root', fixture])], {
    cwd: fixture, env, encoding: 'utf8', windowsHide: true, timeout: 10_000,
  });
  expect(installed.error).toBeUndefined();
  expect(installed.status, 'real trusted offline npm setup succeeds before validation').toBe(0);
  const installerStatus = asRecord(JSON.parse(readFileSync(join(evidence, 'npm-install.json'), 'utf8')) as unknown, 'original installer status');
  expect(installerStatus['status'] ?? installerStatus['exitCode'], 'installer metadata independently records successful setup').toBe(0);
  expect(installerStatus['complete']).toBe(true);
  expect(existsSync(join(dependencies, 'install-canary')), 'real npm ci removes the stale install input').toBe(false);
  // Declare the original pinned source and lock identity before copying bytes.
  // This is an owned copy, with no post-start junction or blanket exemption.
  writeFileSync(join(tests, 'dependency-input.json'), JSON.stringify({ source: join(repoRoot, 'node_modules'),
    lockSha256: createHash('sha256').update(readFileSync(join(repoRoot, 'package-lock.json'))).digest('hex') }));
  copyPhysicalToolInputs(join(repoRoot, 'node_modules'), dependencies);
  const observedArgv = [...argv];
  observedArgv.splice(separator + 2, 0, '--import', pathToFileURL(observer).href);
  const result = spawnSync(process.execPath, [...ownedCaptureToolArgs(observedArgv.slice(1))], {
    cwd: fixture, env, encoding: 'utf8', windowsHide: true, timeout: 60_000,
  });
  expect(result.error, result.stderr).toBeUndefined();
  const reports = existsSync(uploaded) ? files(uploaded).filter(path => path.endsWith('.json')) : [];
  expect(reports.length, 'the actual chaos command must create a JSON test report before scan/upload; mkdir alone leaves no uploadable evidence').toBeGreaterThan(0);
  const outputIndex = argv.findIndex(arg => /^--outputFile(?:\.json)?(?:=|$)/.test(arg));
  const outputArgument = argv[outputIndex] ?? '';
  const output = outputArgument.includes('=') ? outputArgument.slice(outputArgument.indexOf('=') + 1) : argv[outputIndex + 1];
  expect(output, 'the actual chaos command names its own reporter output').toBeTruthy();
  const reportPath = resolve(fixture, output ?? '');
  expect(reports, 'the actual reporter output belongs to the scanned upload directory').toContain(reportPath);
  const report = asRecord(JSON.parse(readFileSync(reportPath, 'utf8')) as unknown, 'chaos test report');
  expect(result.status, 'a reported assertion failure must remain a failing command').toBe(1);
  const observations = readFileSync(trace, 'utf8').trim().split('\n').map(line => asRecord(JSON.parse(line) as unknown, 'executed command'));
  const chaosFailure = observations.findIndex(row => row['event'] === 'close' && Array.isArray(row['args']) && row['args'].includes('test:chaos') && row['code'] === 1);
  const scannerStart = observations.findIndex(row => row['event'] === 'start' && Array.isArray(row['args']) && row['args'].includes('scripts/leak-check.mjs'));
  expect(chaosFailure, 'the actual selected chaos command failed').toBeGreaterThanOrEqual(0);
  expect(scannerStart, 'the unchanged scanner actually starts after that failure').toBeGreaterThan(chaosFailure);
  expect(observations.some(row => row['event'] === 'close' && Array.isArray(row['args']) && row['args'].includes('scripts/leak-check.mjs') && row['code'] === 0),
    'the actual unchanged scanner finishes successfully on original failure evidence').toBe(true);
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
}, 75_000);
