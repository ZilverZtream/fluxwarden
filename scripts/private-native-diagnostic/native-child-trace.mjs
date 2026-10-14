// Append an explicit preload to original direct Node children; preserve ready/go and every argument.
import childProcess from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { syncBuiltinESMExports } from 'node:module';
import { performance } from 'node:perf_hooks';

const installed = Symbol.for('fluxwarden.private.native-child-trace');
if (!childProcess.spawn[installed]) {
  const original = childProcess.spawn;
  const preload = new URL('./native-process-trace.mjs', import.meta.url).href;
  childProcess.spawn = function (file, args, options) {
    const directory = options?.env === undefined ? process.env.FLUXWARDEN_NATIVE_TRACE_DIR : options.env.FLUXWARDEN_NATIVE_TRACE_DIR;
    if (typeof file !== 'string' || file.toLowerCase() !== process.execPath.toLowerCase() || !Array.isArray(args) || !directory) {
      return original.apply(this, arguments);
    }
    const began = performance.now();
    const child = original.call(this, file, ['--import', preload, ...args], options);
    function record(row) {
      try { appendFileSync(join(directory, `node-${process.pid}.jsonl`), JSON.stringify({ operation: 'node-child',
        processId: process.pid, childProcessId: child.pid ?? 0, ...row }) + '\n'); } catch { /* Do not change original child handling. */ }
    }
    record({ phase: 'child-start' });
    child.once('exit', code => record({ phase: 'child-end', wallMs: performance.now() - began, exitCode: code ?? -1 }));
    return child;
  };
  Object.defineProperty(childProcess.spawn, installed, { value: true });
  syncBuiltinESMExports();
}
