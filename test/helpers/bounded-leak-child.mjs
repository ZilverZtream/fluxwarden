import { readFileSync, writeSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';

// Only the documented public scanner boundary is imported. Fixture construction,
// expectations and the independent process watchdog belong to the parent test.
const configuration = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const scanner = await import(pathToFileURL(configuration.module).href);
writeSync(1, JSON.stringify({ event: 'ready', heapUsed: process.memoryUsage().heapUsed }) + '\n');
const started = performance.now();
const results = [];
for (const task of configuration.tasks) {
  try {
    results.push({ label: task.label, hit: scanner.findLeaks({ ...configuration.options, paths: task.paths }) });
  } catch (error) {
    // Exception messages may contain credentials; retain only their category.
    results.push({ label: task.label, failed: true, errorName: error?.name, errorCode: error?.code });
  }
}
writeSync(1, JSON.stringify({ event: 'finished', results, elapsedMs: performance.now() - started, memory: process.memoryUsage() }) + '\n');
