// Private evidence run, not a replacement for CI or an acceptance gate.
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { appendFile, copyFile, readFile, readdir, writeFile } from 'node:fs/promises';
import { join, win32 } from 'node:path';
import { createPrivateDirectory, assertPrivateDirectories, realDirectory } from '../../scripts/private-scratch.mjs';

if (process.platform !== 'win32' || !['v22.23.2', 'v24.18.1'].includes(process.version)) throw new Error('the pinned Windows diagnostic runtime is required');
if (process.env.FLUXWARDEN_NATIVE_DIAGNOSTIC_CASE !== 'original-create-race') throw new Error('unknown private diagnostic case');
const bindings = [
  ['src/platform/owner-only.ts', '636ad29d0a7eb0d64b88923a026614da7b73d2f29932dd618f998427fa143287'],
  ['src/persistence/owner-files.ts', '181993cf9791feebc97563d1790ac6197224ee6ae8966b7493dccdd0ee5ddd91'],
  ['src/persistence/paths.ts', '7fa4dbac3bf820591642d943764916e26ba8b771795f289ddcdcadd30fe5801c'],
  ['test/persistence/cp015-concurrency.test.ts', '1a6b6f67825801ebeb1b3b6b9788b594801df3b52479498e366a4ae91968725b'],
];
for (const [file, expected] of bindings) {
  if (createHash('sha256').update(await readFile(file)).digest('hex') !== expected) throw new Error('the frozen native source or original race changed');
}
const systemRoot = process.env.SystemRoot;
if (!systemRoot || !/^[A-Za-z]:\\Windows$/i.test(systemRoot)) throw new Error('the original Windows system drive policy is required');
await realDirectory(systemRoot);
const drive = win32.parse(systemRoot).root;
await realDirectory(drive);
const owned = await createPrivateDirectory(drive, 'fluxwarden-ci-');
const env = { ...process.env };
for (const [name, prefix] of [['FLUXWARDEN_TEST_TMP', 'ci-tests-'], ['FLUXWARDEN_SENTINEL_DIR', 'ci-sentinels-'], ['FLUXWARDEN_EVIDENCE_DIR', 'ci-evidence-'],
  ['FLUXWARDEN_NATIVE_TRACE_DIR', 'native-traces-'], ['FLUXWARDEN_NATIVE_ARTIFACTS', 'native-artifacts-']]) {
  env[name] = await createPrivateDirectory(owned, prefix);
}
await assertPrivateDirectories([owned, ...['FLUXWARDEN_TEST_TMP', 'FLUXWARDEN_SENTINEL_DIR', 'FLUXWARDEN_EVIDENCE_DIR', 'FLUXWARDEN_NATIVE_TRACE_DIR', 'FLUXWARDEN_NATIVE_ARTIFACTS'].map(name => env[name])]);
if (process.env.GITHUB_ENV) await appendFile(process.env.GITHUB_ENV, ['FLUXWARDEN_SENTINEL_DIR', 'FLUXWARDEN_NATIVE_ARTIFACTS'].map(name => `${name}=${env[name]}\n`).join(''));
const report = join(env.FLUXWARDEN_NATIVE_ARTIFACTS, 'vitest-original-race.json');
const args = ['./node_modules/vitest/vitest.mjs', 'run', '--project', 'product', '--config=scripts/private-native-diagnostic/native-diagnostic.config.mjs',
  '--maxWorkers=1', '--fileParallelism=false', 'test/persistence/cp015-concurrency.test.ts', '-t',
  'CP-015/B6 processes racing to create the same database each open it or get a PersistenceError, never a raw file error',
  '--reporter=default', '--reporter=json', `--outputFile.json=${report}`];
const child = spawn(process.execPath, args, { env, shell: false, windowsHide: true, stdio: 'inherit' });
const status = await new Promise((resolveStatus, reject) => { child.once('error', reject); child.once('exit', code => resolveStatus(code ?? 1)); });
const allowedKeys = new Set(['operation', 'processId', 'childProcessId', 'sequence', 'phase', 'wallMs', 'failed', 'exitCode', 'startupCpuMs', 'finalCpuMs', 'scriptWallMs']);
const operations = new Set(['node-child', 'whoami', 'icacls', 'readSecurityDescriptors', 'createOwnerOnlyDirectory', 'createOwnerOnlyEmptyFile', 'other-system-tool']);
const phases = new Set(['child-start', 'child-end', 'native-start', 'native-end']);
let rows = 0, cpuRows = 0, nativeStarts = 0, nativeEnds = 0, childStarts = 0, childEnds = 0;
for (const file of await readdir(env.FLUXWARDEN_NATIVE_TRACE_DIR)) {
  if (!/^(?:node-\d+\.jsonl|cpu-\d+-\d+\.json)$/.test(file)) throw new Error('unexpected private diagnostic receipt');
  const records = (await readFile(join(env.FLUXWARDEN_NATIVE_TRACE_DIR, file), 'utf8')).trim().split(/\r?\n/).map(line => JSON.parse(line));
  for (const row of records) {
    if (!row || typeof row !== 'object' || !operations.has(row.operation) || Object.keys(row).some(key => !allowedKeys.has(key))
      || Object.entries(row).some(([key, value]) => key === 'operation' ? !operations.has(value) : key === 'phase' ? !phases.has(value) : typeof value !== 'number' || !Number.isFinite(value))) {
      throw new Error('private diagnostic data exceeded numeric metadata');
    }
    rows += 1;
    if ('startupCpuMs' in row) cpuRows += 1;
    if (row.phase === 'native-start') nativeStarts += 1;
    if (row.phase === 'native-end') nativeEnds += 1;
    if (row.phase === 'child-start') childStarts += 1;
    if (row.phase === 'child-end') childEnds += 1;
  }
  await copyFile(join(env.FLUXWARDEN_NATIVE_TRACE_DIR, file), join(env.FLUXWARDEN_NATIVE_ARTIFACTS, file));
}
const head = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8', shell: false, windowsHide: true });
if (head.status !== 0 || !/^[0-9a-f]{40}\s*$/.test(head.stdout)) throw new Error('the diagnostic source binding could not be read');
await writeFile(join(env.FLUXWARDEN_NATIVE_ARTIFACTS, 'binding.json'), JSON.stringify({ evidenceOnly: true, source: head.stdout.trim(), node: process.version,
  bindings: bindings.map(([file, sha256]) => ({ file, sha256 })), originalRoundsPlanned: 12, originalOpenersPlanned: 96, originalCaseCapMs: 120000,
  vitestExitCode: status, rows, cpuRows, nativeStarts, nativeEnds, childStarts, childEnds }, null, 2) + '\n');
process.stdout.write(JSON.stringify({ evidenceOnly: true, vitestExitCode: status, rows, cpuRows, nativeStarts, nativeEnds, childStarts, childEnds }) + '\n');
// Preserve the actual product test result, including a timeout or other failure.
process.exitCode = status;
