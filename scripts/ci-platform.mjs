// Single successful job step, preserving the original independent argv and caps.
import { spawn } from 'node:child_process';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { nodes } from './release-inventory.mjs';
export const nativeFiles = [
  'test/labs/cp006-cp008-owner-lifecycle.test.ts', 'test/persistence/cp015-concurrency.test.ts',
  'test/chaos/t01-t12.test.ts', 'test/cli/cp038-reconcile-evidence.test.ts', 'test/commands/cp043-driver.test.ts',
  'test/executor/cp029-preflight.test.ts', 'test/output/cp003-output.test.ts',
  'test/persistence/cp015-command-data-readonly.test.ts', 'test/persistence/cp015-persistence.test.ts',
  'test/daemon/cp041-daemon.test.ts', 'test/ledger/cp037-ledger.test.ts', 'test/commands/cp043-t05-repository.test.ts',
];
export function platformCommands({ os, node, shard }, environment) {
  if (!nodes.includes(node) || !['ubuntu-latest', 'windows-latest'].includes(os)) throw new Error('platform dispatch: unsupported target');
  const windows = os === 'windows-latest', harness = /^harness-[1-8]$/.test(shard), core = /^core-[1-3]$/.test(shard);
  if (!(windows ? harness || core || /^native-[12]$/.test(shard) : /^(product|harness)-[12]$/.test(shard))) throw new Error('platform dispatch: unsupported shard');
  if (!environment.FLUXWARDEN_EVIDENCE_DIR || !environment.TEMP) throw new Error('platform dispatch: private roots required');
  const suite = harness ? 'harness' : 'product', report = join(environment.FLUXWARDEN_EVIDENCE_DIR, `vitest-${suite}.json`);
  const commands = [['node', 'scripts/ci-install.mjs', 'verify', '--root', process.cwd()], ['npm', 'run', 'lint'], ['npm', 'run', 'build'], ['node', 'scripts/ci-database-check.mjs']];
  if (windows && core) commands.push(['node', 'scripts/ci-windows-core.mjs']);
  commands.push([...harness ? ['npm', 'run', 'test:harness', '--'] : ['npm', 'test', '--'],
    ...(windows && core ? [`--config=${join(environment.TEMP, 'vitest-windows-core.config.mjs')}`] : []),
    `--maxWorkers=${windows || harness ? '1' : '2'}`, ...windows || harness ? ['--fileParallelism=false'] : [],
    ...windows && !core && !harness ? nativeFiles : [],
    `--shard=${shard.split('-').at(-1)}/${windows ? harness ? '8' : core ? '3' : '2' : '2'}`,
    '--reporter=default', '--reporter=json', `--outputFile.json=${report}`]);
  if (harness) commands.push(['node', 'scripts/no-pending.mjs', report]);
  return { suite, commands };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 6 || args[0] !== '--os' || args[2] !== '--node' || args[4] !== '--shard') throw new Error('platform dispatch: arguments required');
    const target = { os: args[1], node: args[3], shard: args[5] }, { suite, commands } = platformCommands(target, process.env);
    const env = { ...process.env, FLUXWARDEN_CI_CORE_CONFIG: join(process.env.TEMP, 'vitest-windows-core.config.mjs') };
    const invocation = ['scripts/ci-capture.mjs', '--root', process.cwd(), '--capture-dir', env.FLUXWARDEN_CI_CAPTURE_DIR,
      '--', 'node', 'scripts/ci-job.mjs', ...suite === 'harness' ? ['--commands-only'] : [], '--', ...commands.flatMap((command, i) => [...i ? ['--next'] : [], ...command])];
    const child = spawn(process.execPath, invocation, { env, stdio: 'inherit', windowsHide: true });
    process.exitCode = await new Promise(resolveExit => { child.once('error', () => resolveExit(1)); child.once('close', code => resolveExit(code ?? 1)); });
  } catch { process.stderr.write('platform dispatch: failed\n'); process.exitCode = 1; }
}
