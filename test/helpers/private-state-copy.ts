import { spawn } from 'node:child_process';
import { binPath } from './cli.js';
import { cliEnv, scratch, type Run } from './cp016-cli.js';

export interface StateCopyIntent {
  kind: 'state-outbox-copy'; path: string; sourcePath: string; command: string; args: readonly string[];
  env: NodeJS.ProcessEnv;
}

/** Prospective typed OUTPUT intent only. Never declares a copy as fixture INPUT.
 * The ordinary product child gets exactly the args/env that were authorized. */
export async function runPrivateStateCopy(input: {
  operation: 'backup' | 'restore'; bundle: string; config: string; path: string; sourcePath: string;
}): Promise<Run> {
  const args = [binPath(), '--json', 'state', input.operation, input.operation === 'backup' ? '--out' : '--from', input.bundle, '--config', input.config];
  const env = cliEnv(), cwd = scratch('state-copy-cwd');
  if (process.env['FLUXWARDEN_CI_CAPTURE']) {
    const { authorizeSecretOutput } = await import(new URL('../../scripts/ci-secret-output.mjs', import.meta.url).href) as {
      authorizeSecretOutput: (intent: StateCopyIntent) => Promise<void>;
    };
    await authorizeSecretOutput({ kind: 'state-outbox-copy', path: input.path, sourcePath: input.sourcePath,
      command: process.execPath, args, env });
  }
  return await new Promise<Run>((done, reject) => {
    const child = spawn(process.execPath, args, { cwd, env, windowsHide: true, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', (bytes: Buffer) => { stdout += bytes.toString('utf8'); });
    child.stderr.on('data', (bytes: Buffer) => { stderr += bytes.toString('utf8'); });
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('state copy did not exit within 20000 ms')); }, 20000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (status, signal) => { clearTimeout(timer); done({ status, signal, stdout, stderr, exitedAt: Date.now() }); });
  });
}
