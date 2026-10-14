export interface BoundaryCase { name: string; path: string; source: string; boundary: string; allowed: boolean }

// Expected placements come from the public architecture's module boundary table.
export const boundaryCases: BoundaryCase[] = [];
const areas = ['core', 'node-lnd', 'node-cln', 'persistence', 'policy', 'planner', 'executor', 'reconciler', 'ledger', 'approval', 'output', 'cli', 'daemon'];
const nonAdapters = areas.filter(area => !['node-lnd', 'node-cln'].includes(area));
function placements(name: string, source: string, boundary: string, forbidden: string[], allowed: string[]): void {
  for (const [locations, permitted] of [[forbidden, false], [allowed, true]] as const) {
    for (const location of locations) boundaryCases.push({ name, source, boundary, allowed: permitted, path: `src/${location}/boundary-probe.ts` });
  }
}
for (const area of areas.filter(area => area !== 'core')) placements('core dependency', `export { value } from '../${area}/value.js';`, 'pure core', ['core'], ['cli']);
placements('core builtin', "export { readFile } from 'node:fs';", 'pure core', ['core'], ['output']);
placements('core cryptography', "export { createHash } from 'node:crypto';", 'pure core', [], ['core']);
for (const module of ['http', 'https', 'http2', 'net', 'tls', 'dgram']) {
  placements(`network ${module}`, `import * as transport from 'node:${module}'; export { transport };`, 'network', nonAdapters, ['node-lnd', 'node-cln']);
}
for (const source of ['export const request = fetch;', 'export const Socket = WebSocket;']) {
  placements('network global', source, 'network', nonAdapters, ['node-lnd', 'node-cln']);
}
placements('sqlite', "export { DatabaseSync } from 'node:sqlite';", 'SQL', areas.filter(area => area !== 'persistence'), ['persistence']);
placements('SQL text', "export const statement = 'SELECT balance FROM accounts WHERE id = ?';", 'SQL', areas.filter(area => area !== 'persistence'), ['persistence']);
for (const source of ['export const stream = process.stdout;', 'export const stream = process.stderr;', 'export const log = console.log;']) {
  placements('output stream', source, 'output', areas.filter(area => area !== 'output'), ['output']);
}
placements('child processes', "export { spawn } from 'node:child_process';", 'child process', areas, []);
const childProcess = "export { spawnSync } from 'node:child_process';";
boundaryCases.push({ name: 'owner-only file helper', path: 'src/platform/owner-only.ts', source: childProcess, boundary: 'child process', allowed: true });
for (const path of ['src/platform/other.ts', 'src/platform/owner-only-extra.ts', 'src/platform/nested/owner-only.ts', 'src/approval/sign.ts', 'src/output/owner-only.ts']) {
  boundaryCases.push({ name: 'child processes outside the owner-only helper', path, source: childProcess, boundary: 'child process', allowed: false });
}
for (const adapter of ['node-lnd', 'node-cln']) {
  placements('adapter construction', `export { adapter } from '../${adapter}/adapter.js';`, 'adapter dependency', ['executor', 'reconciler'], ['cli', 'daemon']);
}
for (const module of ['persistence', 'executor', 'reconciler', 'ledger', 'policy']) {
  placements('adapter dependency', `export { value } from '../${module}/value.js';`, 'adapter dependency', ['node-lnd', 'node-cln'], ['cli']);
}
placements('adapter core port', "export type { Port } from '../core/ports.js';", 'adapter dependency', [], ['node-lnd', 'node-cln']);
for (const source of ['export const now = Date.now();', 'export const now = new Date();', 'export const random = Math.random();']) {
  placements('injected time and randomness', source, 'injected clock', ['planner', 'policy', 'ledger', 'approval'], ['daemon']);
}
placements('explicit date', 'export const date = new Date(0);', 'injected clock', [], ['planner', 'policy', 'ledger', 'approval']);
for (const module of ['node:fs', 'node:fs/promises']) {
  const argumentsText = module.endsWith('/promises') ? "'evidence.txt', 'evidence'" : "'evidence.txt', 'evidence', () => {}";
  placements('file write', `import * as files from '${module}'; export function write() { return files.writeFile(${argumentsText}); }`, 'file write', areas.filter(area => !['persistence', 'output'].includes(area)), ['persistence', 'output']);
}
placements('file append', "import { appendFileSync } from 'node:fs'; export function record(): void { appendFileSync('evidence.txt', 'evidence'); }", 'file write', areas.filter(area => !['persistence', 'output'].includes(area)), ['persistence', 'output']);
placements('core process', 'export const environment = process.env;', 'pure core', ['core'], ['cli']);
for (const module of ['dgram', 'https']) {
  placements(`dynamic network ${module}`, `export const transport = import('node:${module}');`, 'network', nonAdapters, ['node-lnd', 'node-cln']);
}
// process.getBuiltinModule returns a builtin by name, so it is held to the import boundaries.
placements('builtin lookup child process', "export const processes = process.getBuiltinModule('node:child_process');", 'child process', areas, []);
placements('builtin lookup network', "export const transport = process.getBuiltinModule('node:https');", 'network', nonAdapters, []);
placements('builtin lookup sqlite', "export const database = process.getBuiltinModule('node:sqlite');", 'SQL', areas.filter(area => area !== 'persistence'), []);
// Code loading primitives: vm, worker source evaluation and process internals load or run
// code that no static import shows.
placements('vm loader', "import * as vm from 'node:vm'; export const run = (code: string): unknown => vm.runInThisContext(code);", 'module loading', areas, []);
for (const option of ['true', 'enabled']) {
  placements(`worker eval ${option}`, `import { Worker } from 'node:worker_threads'; export function start(code: string, enabled: boolean): Worker { void enabled; return new Worker(code, { eval: ${option} }); }`, 'module loading', areas, []);
}
placements('process binding', "export const natives: unknown = process.binding('natives');", 'module loading', areas, []);
placements('process dlopen', 'export function load(target: { exports: unknown }, file: string): void { process.dlopen(target, file); }', 'module loading', areas, []);
for (const module of ['_http_client', '_tls_wrap']) {
  placements(`internal network ${module}`, `import * as transport from 'node:${module}'; export { transport };`, 'network', nonAdapters, []);
}
placements('SQL insert or replace', "export const statement = 'INSERT OR REPLACE INTO channels (id) VALUES (?)';", 'SQL', areas.filter(area => area !== 'persistence'), ['persistence']);
placements('SQL replace', "export const statement = 'REPLACE INTO channels (id) VALUES (?)';", 'SQL', areas.filter(area => area !== 'persistence'), ['persistence']);
placements('SQL concatenation', "export const statement = 'INSERT ' + 'INTO channels (id) VALUES (?)';", 'SQL', areas.filter(area => area !== 'persistence'), ['persistence']);
placements('file write alias', "import { writeFileSync as save } from 'node:fs'; export function write() { save('evidence.txt', 'evidence'); }", 'file write', ['executor'], ['output']);
placements('file read', "import { readFileSync } from 'node:fs'; export const read = readFileSync;", 'file write', [], ['policy']);
placements('injected request', 'export function request(fetch: () => string) { return fetch(); }', 'network', [], ['planner']);
placements('ordinary property', 'export const fields = { fetch: true, stdout: true };', 'network', [], ['planner']);

export const bypassCases: BoundaryCase[] = [
  ...['core', 'node-lnd', 'output'].map(location => ({ name: 'computed import', path: `src/${location}/boundary-probe.ts`, source: "export async function load(name: string) { return import(name); }", boundary: 'literal import', allowed: false })),
  { name: 'concatenated import', path: 'src/planner/boundary-probe.ts', source: "export const load = import('node:' + 'https');", boundary: 'literal import', allowed: false },
  { name: 'require', path: 'src/planner/boundary-probe.ts', source: "export const network = require('node:https');", boundary: 'module loading', allowed: false },
  { name: 'computed builtin lookup', path: 'src/planner/boundary-probe.ts', source: 'export function load(name: string): unknown { return process.getBuiltinModule(name); }', boundary: 'literal import', allowed: false },
  { name: 'eval', path: 'src/planner/boundary-probe.ts', source: "export const value: unknown = eval('1');", boundary: 'module loading', allowed: false },
  { name: 'data module import', path: 'src/planner/boundary-probe.ts', source: "export const loaded: unknown = import('data:text/javascript,export default 1');", boundary: 'module loading', allowed: false },
  { name: 'data URL worker', path: 'src/cli/boundary-probe.ts', source: "import { Worker } from 'node:worker_threads'; export const worker = new Worker(new URL('data:text/javascript,1'));", boundary: 'module loading', allowed: false },
  { name: 'worker options spread', path: 'src/cli/boundary-probe.ts', source: "import { Worker } from 'node:worker_threads'; const options = {}; export const worker = new Worker('worker.js', { ...options });", boundary: 'module loading', allowed: false },
  { name: 'Function constructor', path: 'src/planner/boundary-probe.ts', source: "export const evaluate = new Function('return 1');", boundary: 'module loading', allowed: false },
  { name: 'Function call', path: 'src/planner/boundary-probe.ts', source: "export const evaluate = Function('return 1');", boundary: 'module loading', allowed: false },
  { name: 'createRequire', path: 'src/planner/boundary-probe.ts', source: "import * as module from 'node:module'; export const load = module.createRequire(import.meta.url);", boundary: 'module loading', allowed: false },
  { name: 'fetch property', path: 'src/planner/boundary-probe.ts', source: 'export const request = globalThis.fetch;', boundary: 'network', allowed: false },
  { name: 'fetch lookup', path: 'src/planner/boundary-probe.ts', source: "export const request = globalThis['fetch'];", boundary: 'network', allowed: false },
  { name: 'stream lookup', path: 'src/cli/boundary-probe.ts', source: "export const stream = process['stdout'];", boundary: 'output', allowed: false },
  { name: 'reexport network', path: 'src/core/boundary-probe.ts', source: "export * from 'node:https';", boundary: 'network', allowed: false },
  { name: 'literal dynamic adapter import', path: 'src/node-lnd/boundary-probe.ts', source: "export const load = import('node:https');", boundary: 'network', allowed: true },
  { name: 'literal dynamic core import', path: 'src/core/boundary-probe.ts', source: "export const load = import('node:crypto');", boundary: 'pure core', allowed: true },
];

export const toolingCases: BoundaryCase[] = [];
for (const directory of ['scripts', 'labs/docker', 'test/helpers']) {
  for (const shell of [false, true]) toolingCases.push({ name: `spawn ${shell ? 'with shell' : 'without shell'}`, path: `${directory}/boundary-probe.mjs`, source: `import { spawn } from 'node:child_process'; export const child = spawn('node', ['--version'], { shell: ${String(shell)} });`, boundary: 'shell', allowed: !shell });
}
toolingCases.push({ name: 'test HTTPS server', path: 'test/helpers/boundary-probe.mjs', source: "export { createServer } from 'node:https';", boundary: 'network', allowed: true });
