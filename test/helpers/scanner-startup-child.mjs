import { readFileSync, writeSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

// File entry and module-eval both use the documented public findLeaks API.
const configuration = JSON.parse(readFileSync(process.argv.at(-1), 'utf8'));
const scanner = await import(pathToFileURL(configuration.module).href);
writeSync(1, JSON.stringify({ event: 'ready' }) + '\n');
try {
  const hit = scanner.findLeaks(configuration.options);
  writeSync(1, JSON.stringify({ event: 'result', hit }) + '\n');
} catch (error) {
  // Exception strings and node bodies are not diagnostics.
  writeSync(1, JSON.stringify({ event: 'refused', name: error?.name }) + '\n');
}
