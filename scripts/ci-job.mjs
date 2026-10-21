// One matrix invocation includes the original npm lifecycle, optional harness,
// and no-pending check, so all writes finish before its one final custody seal.
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';

async function run(command, args) {
  const ownedNodeStage = command === 'npm' || command === 'node';
  if (command === 'npm') {
    const npm = [join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js'), resolve(dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js')].find(existsSync);
    if (!npm) throw new Error('CI npm unavailable');
    args = [npm, ...args];
    command = process.execPath;
  } else if (command === 'node') command = process.execPath;
  if (ownedNodeStage && process.env.FLUXWARDEN_CI_CAPTURE) args = ['--import', new URL('./ci-capture-preload.mjs', import.meta.url).href, ...args];
  const child = spawn(command, args, { stdio: 'inherit', env: process.env, windowsHide: true });
  return await new Promise(resolveExit => {
    child.once('error', () => resolveExit(1));
    child.once('close', code => resolveExit(code ?? 1));
  });
}
try {
  const args = process.argv.slice(2);
  const harness = args[0] === '--harness';
  if (harness) args.shift();
  const reports = args[0] !== '--commands-only';
  if (!reports) args.shift();
  if (args.shift() !== '--' || !args.length) throw new Error('CI command required');
  const commands = [{ args: [], always: false }];
  for (const arg of args) {
    if (arg === '--next' || arg === '--finally') commands.push({ args: [], always: arg === '--finally' });
    else commands.at(-1).args.push(arg);
  }
  let result = 0;
  for (const command of commands) {
    if (!command.args.length) throw new Error('CI stage required');
    if (result !== 0 && !command.always) continue;
    const stage = await run(command.args[0], command.args.slice(1));
    if (result === 0) result = stage;
  }
  if (result === 0 && harness) result = await run('npm', ['run', 'test:harness', '--', '--maxWorkers=1', '--fileParallelism=false', '--reporter=default', '--reporter=json', '--outputFile.json=' + join(process.env.FLUXWARDEN_EVIDENCE_DIR, 'vitest-harness.json')]);
  if (result === 0 && reports) result = await run('node', ['scripts/no-pending.mjs', join(process.env.FLUXWARDEN_EVIDENCE_DIR, 'vitest-product.json'), ...(harness ? [join(process.env.FLUXWARDEN_EVIDENCE_DIR, 'vitest-harness.json')] : [])]);
  process.exitCode = result;
} catch { process.stderr.write('CI command failed\n'); process.exitCode = 1; }
