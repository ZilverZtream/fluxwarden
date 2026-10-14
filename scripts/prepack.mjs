import { lstatSync, readdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const output = join(root, 'dist');
try {
  const info = lstatSync(output);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('unsafe build output');
  // Reject links before removing build output, including links below its root.
  const inspect = directory => {
    for (const name of readdirSync(directory)) {
      const path = join(directory, name);
      const entry = lstatSync(path);
      if (entry.isSymbolicLink()) throw new Error('linked build output');
      if (entry.isDirectory()) inspect(path);
    }
  };
  inspect(output);
  rmSync(output, { recursive: true });
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}
const result = spawnSync(process.execPath, [join(root, 'node_modules/typescript/bin/tsc'), '-p', join(root, 'tsconfig.json')],
  { cwd: root, stdio: 'inherit', windowsHide: true, timeout: 120_000 });
if (result.error) throw result.error;
if (result.status === 0) await import('./build-info.mjs');
process.exitCode = result.status ?? 1;
