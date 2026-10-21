// SECURITY INV-11; RATCHET 6/13; CP-044 original runtime-source lifetime.
// This checks the actual owned Vitest entry and worker, not a direct Node child
// or any recorder implementation detail. All source bytes are synthetic/private.
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { asRecord, childEnv, repoRoot } from '../helpers/cli.js';
import { declareFixtureCapture, declareFixturePaths, ownedCaptureToolArgs } from '../helpers/capture-fixture.js';
import { testRoot } from '../helpers/env.js';

const hash = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');
function retainedBytes(directory: string): Buffer[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? retainedBytes(path) : entry.isFile() ? [readFileSync(path)] : [];
  });
}

it('CP-044/CI-WORKER actual owned Vitest worker retains replaced original runtime source and detects its earlier stdout', async () => {
  const parent = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'worker-lifetime-'));
  const root = join(parent, 'checkout'), capture = join(parent, 'capture');
  const roots = ['temp', 'tmp', 'scratch', 'sources', 'evidence'].map(name => join(parent, name));
  for (const directory of [root, capture, ...roots]) mkdirSync(directory, { mode: 0o700 });
  const permissions = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as {
    assertPrivateDirectories: (paths: string[]) => Promise<void>;
  };
  await permissions.assertPrivateDirectories(roots);
  const first = randomBytes(32), replacement = randomBytes(32), staticControl = randomBytes(32);
  const runtime = join(roots[3] ?? '', 'runtime-worker.bin');
  const stdout = join(capture, 'stdout.log');
  declareFixtureCapture(capture, [first, replacement, staticControl], []);
  // Exact intentional output and its retained copy are known before any write.
  // No grant is made for the inner invocation: stdout remains inner EGRESS.
  declareFixturePaths([stdout]);
  mkdirSync(join(root, 'test'));
  const staticSource = join(root, 'test/control.bin');
  declareFixturePaths([staticSource]);
  writeFileSync(staticSource, staticControl, { mode: 0o600 });
  writeFileSync(join(root, 'test/sentinels.json'), '["test/control.bin"]');
  // Match the public npm test:harness entry's inherited project boundary: CLI
  // options must reach this selected project's real worker, not only root config.
  writeFileSync(join(root, 'vitest.config.mjs'), `export default { test: {
    allowOnly: false, passWithNoTests: false, maxWorkers: 1,
    projects: [
      { extends: true, test: { name: 'product', include: ['test/product/*.test.mjs'] } },
      { extends: true, test: { name: 'harness-docs', include: ['test/worker.test.mjs'], maxWorkers: 1, fileParallelism: false } }
    ] } };\n`);
  const vitest = pathToFileURL(join(repoRoot, 'node_modules/vitest/dist/index.js')).href;
  writeFileSync(join(root, 'test/worker.test.mjs'), `import { expect, it } from ${JSON.stringify(vitest)};
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
it('actual worker source lifetime control', () => {
 const source = join(process.env.FLUXWARDEN_SENTINEL_DIR, 'runtime-worker.bin');
 expect(Boolean(process.env.FLUXWARDEN_CI_CAPTURE)).toBe(true);
 expect(existsSync(source)).toBe(false);
 const first = Buffer.from(process.env.FW_WORKER_FIRST, 'base64');
 const replacement = Buffer.from(process.env.FW_WORKER_REPLACEMENT, 'base64');
 writeFileSync(source, first, { mode: 0o600 });
 process.stdout.write(first.toString('hex') + '\\n');
 writeFileSync(source, replacement, { mode: 0o600 });
 writeFileSync(join(process.env.FLUXWARDEN_TEST_TMP, 'worker-presence.json'), JSON.stringify({
   capturePresent: Boolean(process.env.FLUXWARDEN_CI_CAPTURE), workerReached: true,
   importFlagPresent: process.execArgv.some(arg => arg.includes('ci-capture-preload.mjs'))
 }));
});\n`);
  const env: NodeJS.ProcessEnv = { ...childEnv(), TEMP: roots[0], TMP: roots[1], FLUXWARDEN_TEST_TMP: roots[2],
    FLUXWARDEN_SENTINEL_DIR: roots[3], FLUXWARDEN_EVIDENCE_DIR: roots[4],
    FW_WORKER_FIRST: first.toString('base64'), FW_WORKER_REPLACEMENT: replacement.toString('base64') };
  for (const args of [['init', '--quiet'], ['add', '--', 'test/sentinels.json', 'test/control.bin', 'test/worker.test.mjs', 'vitest.config.mjs'],
    ['-c', 'user.name=Worker fixture', '-c', 'user.email=fixture@invalid', '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'owned worker fixture']]) {
    const result = spawnSync('git', [...args], { cwd: root, env, encoding: 'utf8', windowsHide: true, timeout: 10_000 });
    expect(result.status, 'minimal worker fixture has real Git identity').toBe(0);
  }
  const reportPath = join(roots[4] ?? '', 'worker-tests.json');
  const args = [join(repoRoot, 'scripts/ci-capture.mjs'), '--root', root, '--capture-dir', capture, '--', process.execPath,
    join(repoRoot, 'scripts/ci-test-driver.mjs'), 'run', '--config', join(root, 'vitest.config.mjs'), '--root', root,
    '--project', 'harness-docs', '--reporter=default', '--reporter=json', `--outputFile.json=${reportPath}`];
  const result = spawnSync(process.execPath, [...ownedCaptureToolArgs(args)], {
    cwd: root, env, windowsHide: true, timeout: 10_000,
  });
  writeFileSync(join(parent, 'wrapper.stdout'), result.stdout);
  writeFileSync(join(parent, 'wrapper.stderr'), result.stderr);
  writeFileSync(join(parent, 'invocation.json'), JSON.stringify({ args, roots, root, capture,
    status: result.status, signal: result.signal, error: result.error?.name ?? null }));
  expect(result.error).toBeUndefined();
  expect(existsSync(reportPath), 'actual owned driver executes the worker test').toBe(true);
  const report = asRecord(JSON.parse(readFileSync(reportPath, 'utf8')) as unknown, 'worker test report');
  expect({ passed: report['numPassedTests'], failed: report['numFailedTests'], pending: report['numPendingTests'] })
    .toEqual({ passed: 1, failed: 0, pending: 0 });
  expect(readFileSync(runtime).equals(replacement), 'runtime source was actually replaced before worker completion').toBe(true);
  const receipt = asRecord(JSON.parse(readFileSync(join(capture, 'receipt.json'), 'utf8')) as unknown, 'capture receipt');
  const sources = receipt['sources'];
  if (!Array.isArray(sources)) throw new Error('complete source membership is required');
  const members = sources.map(value => asRecord(value, 'source'));
  const observations = {
    originalMember: members.some(row => row['purpose'] === 'INPUT' && row['sha256'] === hash(first)),
    replacementMember: members.some(row => row['purpose'] === 'INPUT' && row['sha256'] === hash(replacement)),
    originalBytesRetained: retainedBytes(capture).some(bytes => bytes.equals(first)),
    originalStdoutRetained: readFileSync(stdout).includes(first.toString('hex')),
  };
  writeFileSync(join(parent, 'lifetime-result.json'), JSON.stringify({ observations, result: receipt['result'] }));
  expect(observations.originalStdoutRetained, 'original worker disclosure survives privately').toBe(true);
  expect.soft(observations.originalMember, 'Closing retains the first registered worker source lifetime').toBe(true);
  expect.soft(observations.replacementMember, 'Closing retains the replacement lifetime too').toBe(true);
  expect.soft(observations.originalBytesRetained, 'first source bytes remain available after replacement').toBe(true);
  expect.soft({ rejected: result.status !== null && result.status !== 0, result: receipt['result'] },
    'the actual owned worker cannot erase source recognition by replacing it before Closing')
    .toMatchObject({ rejected: true, result: { leakFree: false } });
});
