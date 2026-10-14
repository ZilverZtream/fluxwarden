import { mkdtempSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { repoRoot } from './cli.js';
import { observedLab } from './cp006-observed.js';

export interface Owner {
  version: 1;
  id: string;
  project: string;
  runtimeRoot: string;
  tmpRoot: string;
  sentinelRoot: string;
  evidenceRoot: string;
  ports: { lndRest: number; clnRest: number; toxiproxy: number };
  resources: { cpus: number; memoryBytes: number; pids: number };
}
export interface Result { exitCode: number; stdout: string; stderr: string }
export interface CommandOptions { cwd: string; env: NodeJS.ProcessEnv; timeoutMs: number; signal?: AbortSignal }
export type Run = (argv: readonly string[], options: CommandOptions) => Promise<Result>;
export interface LabOptions {
  owner: Owner;
  run: Run;
  clock: () => number;
  delay: (ms: number, signal?: AbortSignal) => Promise<void>;
  permissions: { create: (parent: string, prefix: string) => Promise<string>; assert: (directory: string) => Promise<void> };
  signal?: AbortSignal;
}
export interface Lab { up(): Promise<unknown>; down(): Promise<unknown> }
interface Module { createLab(options: LabOptions): Lab }
interface Permissions {
  createPrivateDirectory: (parent: string, prefix: string) => Promise<string>;
  assertPrivateDirectory: (directory: string) => Promise<void>;
}

export async function loadLab(): Promise<Module> {
  return await import(pathToFileURL(join(repoRoot, 'labs/docker/lab.mjs')).href) as Module;
}

export function owner(index = 0): Promise<Owner> {
  const base = process.env['FLUXWARDEN_TEST_TMP'];
  if (!base) throw new Error('private test temporary root is required');
  const root = mkdtempSync(join(base, 'owner-'));
  const paths = ['runtime', 'tmp', 'sentinels', 'evidence'].map(name => join(root, name));
  for (const path of paths) mkdirSync(path, { mode: 0o700 });
  return Promise.resolve({
    version: 1, id: root.split(/[\\/]/).at(-1) ?? 'owner', project: `fluxwarden-lab-${root.split(/[\\/]/).at(-1)?.toLowerCase() ?? 'owner'}`,
    runtimeRoot: paths[0] ?? '', tmpRoot: paths[1] ?? '', sentinelRoot: paths[2] ?? '', evidenceRoot: paths[3] ?? '',
    ports: { lndRest: 25100 + index * 10, clnRest: 25101 + index * 10, toxiproxy: 25102 + index * 10 },
    resources: { cpus: 1, memoryBytes: 1073741824, pids: 128 },
  });
}

export async function options(selected: Owner, run: Run): Promise<LabOptions> {
  const permission = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as Permissions;
  let time = 0;
  // Keep the public default functions intact so their native owner-root inspection can batch.
  return { owner: selected, run, clock: () => time, delay: ms => { time += ms; return Promise.resolve(); }, permissions: { create: permission.createPrivateDirectory, assert: permission.assertPrivateDirectory } };
}

/** Inventory and process failures only; these scripted controls make no claim about node facts. */
export function control(mode: 'existing' | 'up-failure' | 'cleanup-failure'): { run: Run; calls: string[][] } {
  const calls: string[][] = [];
  let started = false;
  const run: Run = argv => {
    const args = [...argv]; calls.push(args);
    if (args.includes('info')) return Promise.resolve({ exitCode: 0, stdout: '{"NCPU":24,"MemTotal":33511964672}', stderr: '' });
    if (args.includes('ps')) return Promise.resolve({ exitCode: 0, stdout: mode === 'existing' ? 'owned-existing-container\n' : '', stderr: '' });
    if (args.includes('up')) { started = true; return Promise.resolve({ exitCode: 23, stdout: '', stderr: 'synthetic startup failure' }); }
    if (args.includes('down')) return Promise.resolve({ exitCode: mode === 'cleanup-failure' && started ? 29 : 0, stdout: '', stderr: '' });
    if (args.includes('volume') || args.includes('network')) return Promise.resolve({ exitCode: 0, stdout: '', stderr: '' });
    return Promise.resolve({ exitCode: 99, stdout: '', stderr: 'unexpected control command' });
  };
  return { run, calls };
}

/** Hostile identity answers test refusal, not real-node compatibility. Identity JSON fields:
 * ZilverZtream/macwarden@25bbfa4 test/fixture/fixture.mjs (getInfo and identity guard),
 * test/fixture/cln-fixture.mjs (status and up); accepted releases are SPEC 11.1. */
export function identityControl(selected: Owner, target: string, field: 'network' | 'version', forbidden: unknown): { run: Run; calls: string[][] } {
  const calls: string[][] = [];
  const fake = observedLab(selected, field === 'network' ? { network: { node: target, value: forbidden } } : { version: { node: target, value: forbidden } });
  const run: Run = (argv, command) => { calls.push([...argv]); return fake.run(argv, command); };
  return { run, calls };
}
