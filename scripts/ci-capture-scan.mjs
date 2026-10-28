import fs from 'node:fs';
import { availableParallelism } from 'node:os';
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { findLeaks } from './leak-check.mjs';

if (!isMainThread && workerData?.captureScan === true) {
  let complete = false, hit = false;
  try { hit = Boolean(findLeaks(workerData.options)); complete = true; }
  catch { /* The parent rejects every incomplete recognition result. */ }
  parentPort.postMessage({ complete, hit, count: workerData.options.paths.length });
}

export async function hasCaptureLeaks(options) {
  const paths = options.paths ?? [];
  if (paths.length < 256) return Boolean(findLeaks(options));
  const entries = paths.map(path => ({ path, info: fs.lstatSync(path) }));
  if (entries.some(({ info }) => !info.isFile() || info.isSymbolicLink())) return Boolean(findLeaks(options));
  const count = Math.min(4, availableParallelism(), paths.length);
  if (count < 2) return Boolean(findLeaks(options));
  const partitions = Array.from({ length: count }, () => ({ paths: [], bytes: 0 }));
  for (const { path, info } of entries.sort((a, b) => b.info.size - a.info.size)) {
    const partition = partitions.reduce((left, right) => left.bytes <= right.bytes ? left : right);
    partition.paths.push(path);
    partition.bytes += Math.max(4096, info.size);
  }
  const assigned = partitions.flatMap(partition => partition.paths), expected = new Set(paths);
  if (expected.size !== paths.length || assigned.length !== paths.length ||
    new Set(assigned).size !== paths.length || assigned.some(path => !expected.has(path))) throw new Error('capture scan partition failed');
  const threads = [], pending = [];
  try {
    for (const partition of partitions) {
      // Node.js/node doc/api/worker_threads.md: each bounded worker runs the
      // unchanged recognizer against the entire source population. Files remain
      // independent streams, with their original names and declaration context.
      const thread = new Worker(new URL(import.meta.url), { execArgv: [],
        resourceLimits: { maxOldGenerationSizeMb: 512 },
        workerData: { captureScan: true, options: { ...options, paths: partition.paths } } });
      threads.push(thread);
      pending.push(new Promise(resolve => {
        let result, messages = 0, failed = false;
        thread.on('message', message => { result = message; messages++; });
        thread.once('error', () => { failed = true; });
        thread.once('exit', code => resolve({ valid: !failed && code === 0 && messages === 1 && result?.complete === true &&
          typeof result.hit === 'boolean' && result.count === partition.paths.length, hit: result?.hit === true }));
      }));
    }
    const results = await Promise.all(pending);
    if (results.length !== count || results.some(result => !result.valid)) throw new Error('capture scan incomplete');
    return results.some(result => result.hit);
  } finally {
    await Promise.all(threads.map(thread => thread.terminate()));
  }
}