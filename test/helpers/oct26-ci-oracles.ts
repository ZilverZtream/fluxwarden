// Owner D29 graph/dispatcher oracle update. Workflow files and the public
// command-plan API are observable interfaces; source code shape is irrelevant.
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect } from 'vitest';
import { asRecord, childEnv, readText, repoRoot, scratchDir } from './cli.js';
import { parseYaml } from './yaml.js';
import { independentInventory, type PlatformJob } from './oct26-release-gate.js';

export const NODE_TARGETS = ['22.23.2', '22.x', '24.18.1', '24.x', '26.5.1', '26.x'];
export const NATIVE_FILES = [
  'test/labs/cp006-cp008-owner-lifecycle.test.ts', 'test/persistence/cp015-concurrency.test.ts',
  'test/chaos/t01-t12.test.ts', 'test/cli/cp038-reconcile-evidence.test.ts', 'test/commands/cp043-driver.test.ts',
  'test/executor/cp029-preflight.test.ts', 'test/output/cp003-output.test.ts', 'test/persistence/cp015-command-data-readonly.test.ts',
  'test/persistence/cp015-persistence.test.ts', 'test/daemon/cp041-daemon.test.ts', 'test/ledger/cp037-ledger.test.ts',
  'test/commands/cp043-t05-repository.test.ts',
];
const stepsOf = (job: Record<string, unknown>): Record<string, unknown>[] => {
  if (!Array.isArray(job['steps'])) throw new Error('workflow job must expose steps');
  return job['steps'].map(step => asRecord(step, 'step'));
};
function artifactStep(job: Record<string, unknown>, action: string, artifact: string): boolean {
  return stepsOf(job).some(step => String(step['uses'] ?? '').startsWith(`actions/${action}@`)
    && asRecord(step['with'], 'artifact action')['name'] === artifact);
}

export function proveCiGraph(): void {
  const workflow = asRecord(parseYaml(readText('.github/workflows/ci.yml')), 'workflow');
  const on = asRecord(workflow['on'], 'on');
  expect(Object.keys(on).sort()).toEqual(['pull_request', 'workflow_dispatch']);
  const permissions = asRecord(workflow['permissions'], 'workflow permissions');
  expect(permissions['contents']).toBe('read');
  for (const [key, value] of Object.entries(permissions)) { expect(['contents', 'actions']).toContain(key); expect(value).toBe('read'); }
  const jobs = asRecord(workflow['jobs'], 'jobs');
  const entries = Object.entries(jobs).map(([id, value]) => ({ id, job: asRecord(value, id) }));
  const platform = entries.find(({ job }) => {
    if (!job['strategy']) return false;
    const matrix = asRecord(asRecord(job['strategy'], 'strategy')['matrix'], 'matrix');
    return ['os', 'node', 'shard'].every(key => key in matrix);
  });
  if (!platform) throw new Error('platform matrix job required');
  expect(platform.job['timeout-minutes']).toBe('30');
  const strategy = asRecord(platform.job['strategy'], 'strategy'); expect(strategy['fail-fast']).toBe(false);
  const matrix = asRecord(strategy['matrix'], 'matrix');
  let combos: Record<string, string>[] = [{}];
  for (const [key, values] of Object.entries(matrix)) {
    if (key === 'include' || key === 'exclude') continue;
    if (!Array.isArray(values)) throw new Error('matrix axis must be a list');
    combos = combos.flatMap(row => values.map(value => ({ ...row, [key]: String(value) })));
  }
  for (const value of (matrix['exclude'] ?? []) as unknown[]) {
    const excluded = asRecord(value, 'exclude'); combos = combos.filter(row => !Object.entries(excluded).every(([key, item]) => row[key] === String(item)));
  }
  const baseKeys = Object.keys(matrix).filter(key => !['include', 'exclude'].includes(key));
  for (const value of (matrix['include'] ?? []) as unknown[]) {
    const included = Object.fromEntries(Object.entries(asRecord(value, 'include')).map(([key, item]) => [key, String(item)]));
    const matching = combos.filter(row => baseKeys.every(key => included[key] === undefined || included[key] === row[key]));
    if (matching.length && Object.keys(included).some(key => !baseKeys.includes(key))) matching.forEach(row => Object.assign(row, included));
    else if (!matching.length || baseKeys.every(key => included[key] !== undefined)) combos.push(included);
  }
  const expected = independentInventory().platformJobs.map(row => row.key).sort();
  const substitute = (value: unknown, row: Record<string, string>): string => String(value).replace(/\$\{\{\s*matrix\.([\w-]+)\s*\}\}/g, (_, key: string) => row[key] ?? '<missing>');
  expect(combos.map(row => `platform/${row['os'] ?? ''}/${row['node'] ?? ''}/${row['shard'] ?? ''}`).sort()).toEqual(expected);
  expect(combos.map(row => substitute(platform.job['name'], row)).sort(), 'official job names bind each exact required target').toEqual(expected);
  expect(platform.job['runs-on']).toBe('${{ matrix.os }}');
  const dispatchers = stepsOf(platform.job).filter(step => /\bnode scripts\/ci-platform\.mjs\b/.test(String(step['run'] ?? '')));
  expect(dispatchers, 'one dispatcher avoids successful jobs with skipped suite steps').toHaveLength(1);
  const dispatcher = dispatchers[0];
  if (!dispatcher) throw new Error('platform dispatcher absent');
  expect(dispatcher['if'] ?? 'always()').toBe('always()');
  expect(dispatcher['continue-on-error'] ?? false).toBe(false);
  for (const row of combos) {
    const command = substitute(dispatcher['run'], row);
    for (const flag of ['os', 'node', 'shard']) expect(command).toMatch(new RegExp(`--${flag} ["']?${row[flag] ?? '<missing>'}["']?(?:\\s|$)`));
  }
  for (const { job } of entries) {
    expect(job['continue-on-error'] ?? false).toBe(false);
    for (const [key, value] of Object.entries(asRecord(job['permissions'] ?? { contents: 'read' }, 'permissions'))) {
      expect(['contents', 'actions']).toContain(key); expect(value).toBe('read');
    }
    for (const step of stepsOf(job)) {
      const uses = step['uses'];
      if (typeof uses !== 'string') continue;
      expect(uses).toMatch(/^[^@\s]+@[0-9a-f]{40}$/);
      if (uses.startsWith('actions/checkout@')) {
        expect(uses).toBe('actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd');
        expect(asRecord(step['with'], 'checkout')['persist-credentials']).toBe(false);
      }
      if (uses.startsWith('actions/setup-node@')) {
        expect(uses).toBe('actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444');
        if (job === platform.job) expect(asRecord(step['with'], 'setup')['node-version']).toBe('${{ matrix.node }}');
      }
    }
  }
  const producers = ['live/lab', 'live/chaos', 'release/demo', 'release/leak-scan', 'release/installed-smoke', 'release/publisher']
    .map(name => {
      const match = entries.find(({ id, job }) => (job['name'] ?? id) === name);
      expect(match, `required producer ${name}`).toBeDefined();
      if (!match) throw new Error('required producer absent'); return match;
    });
  const packages = entries.filter(({ job }) => artifactStep(job, 'upload-artifact', 'fluxwarden-final-package'));
  const aggregates = entries.filter(({ job }) => artifactStep(job, 'upload-artifact', 'fluxwarden-release-evidence'));
  expect(packages, 'one actual final tarball producer').toHaveLength(1);
  expect(aggregates, 'one actual authenticated evidence aggregate').toHaveLength(1);
  const packageJob = packages[0], aggregate = aggregates[0];
  if (!packageJob || !aggregate) throw new Error('package and evidence graph required');
  const reaches = (from: string, target: string, seen = new Set<string>()): boolean => {
    if (from === target) return true;
    if (seen.has(from)) return false; seen.add(from);
    const job = asRecord(jobs[from], 'dependency job');
    const needs = job['needs'] === undefined ? [] : Array.isArray(job['needs']) ? job['needs'] : [job['needs']];
    return needs.some(value => reaches(String(value), target, new Set(seen)));
  };
  expect(Object.keys(asRecord(packageJob.job['outputs'], 'package outputs')).some(key => /sha256/i.test(key)), 'package producer exports actual tarball identity').toBe(true);
  for (const producer of [platform, ...producers]) {
    expect(reaches(producer.id, packageJob.id), `${producer.id} consumes the same package producer`).toBe(true);
    expect(artifactStep(producer.job, 'download-artifact', 'fluxwarden-final-package'), `${producer.id} downloads the actual package`).toBe(true);
    expect(reaches(aggregate.id, producer.id), `aggregate waits for ${producer.id}`).toBe(true);
  }
  expect(stepsOf(aggregate.job).some(step => String(step['uses'] ?? '').startsWith('actions/download-artifact@')), 'aggregate consumes real producer artifacts').toBe(true);
  for (const producer of producers.filter(({ job }) => /^live\//.test(String(job['name'])))) {
    expect(producer.job['timeout-minutes']).toBe('60'); expect(producer.job['runs-on']).toBe('ubuntu-latest');
    expect(String(producer.job['if'])).toMatch(/github\.event_name\s*==\s*'workflow_dispatch'/);
  }
}

interface CommandPlan { suite: string; commands: string[][] }
export async function platformPlan(target: Pick<PlatformJob, 'os' | 'node' | 'shard'>, env: NodeJS.ProcessEnv): Promise<CommandPlan> {
  const api = await import(pathToFileURL(join(repoRoot, 'scripts/ci-platform.mjs')).href) as {
    platformCommands(target: Pick<PlatformJob, 'os' | 'node' | 'shard'>, environment: NodeJS.ProcessEnv): CommandPlan;
  };
  return api.platformCommands(target, env);
}

export async function provePlatformPlans(): Promise<void> {
  const env: NodeJS.ProcessEnv = { ...childEnv(), FLUXWARDEN_CI_CORE_CONFIG: join(process.env['TEMP'] ?? '', 'vitest-windows-core.config.mjs') };
  for (const target of independentInventory().platformJobs) {
    const plan = await platformPlan(target, env), windows = target.os === 'windows-latest', harness = target.suite === 'harness';
    expect(plan.suite).toBe(target.suite);
    const core = target.shard.startsWith('core-'), native = target.shard.startsWith('native-');
    const index = target.shard.split('-')[1] ?? '<missing>', shards = harness || core ? '8' : '2';
    const report = join(env['FLUXWARDEN_EVIDENCE_DIR'] ?? '', `vitest-${target.suite}.json`);
    const suite = ['npm', ...(harness ? ['run', 'test:harness'] : ['test']), '--',
      ...(core ? [`--config=${env['FLUXWARDEN_CI_CORE_CONFIG'] ?? '<missing>'}`] : []),
      `--maxWorkers=${windows || harness ? '1' : '2'}`, ...(windows || harness ? ['--fileParallelism=false'] : []),
      ...(native ? NATIVE_FILES : []), `--shard=${index}/${shards}`, '--reporter=default', '--reporter=json', `--outputFile.json=${report}`];
    const prepared = [['node', 'scripts/ci-install.mjs', 'verify', '--root', repoRoot], ['npm', 'run', 'lint'], ['npm', 'run', 'build'], ['node', 'scripts/ci-database-check.mjs'],
      ...(core ? [['node', 'scripts/ci-windows-core.mjs']] : []), suite];
    const pending = ['node', 'scripts/no-pending.mjs', report];
    if (harness || plan.commands.length === prepared.length + 1) prepared.push(pending);
    expect(plan.commands, `${target.key}: exact original stage argv and limits`).toEqual(prepared);
  }
}

export async function proveDispatcherExit(): Promise<void> {
  const root = scratchDir('dispatcher-transport'), preload = join(root, 'transport.mjs'), trace = join(root, 'trace.jsonl');
  const captureRoot = join(root, 'capture'); mkdirSync(captureRoot);
  const plan = await platformPlan({ os: 'ubuntu-latest', node: '24.x', shard: 'product-1' }, childEnv());
  writeFileSync(preload, `import cp from 'node:child_process'; import {appendFileSync} from 'node:fs'; import {EventEmitter} from 'node:events'; import {syncBuiltinESMExports} from 'node:module';
const record=(command,args)=>{appendFileSync(process.env.CONTROL_TRACE,JSON.stringify({command,args})+'\\n'); const index=args.findIndex(arg=>/(?:^|[/\\\\])ci-capture\\.mjs$/.test(arg)); return index>=0&&args[index+1]==='verify'?0:Number(process.env.CONTROL_EXIT);};
cp.spawnSync=(command,args)=>({status:record(command,args),signal:null,stdout:Buffer.alloc(0),stderr:Buffer.alloc(0)});
cp.spawn=(command,args)=>{const code=record(command,args),child=new EventEmitter(); child.stdout=new EventEmitter(); child.stderr=new EventEmitter(); queueMicrotask(()=>{child.emit('exit',code,null);child.emit('close',code,null);});return child;};syncBuiltinESMExports();`);
  for (const code of [0, 7]) {
    writeFileSync(trace, '');
    const result = spawnSync(process.execPath, ['--import', pathToFileURL(preload).href, join(repoRoot, 'scripts/ci-platform.mjs'), '--os', 'ubuntu-latest', '--node', '24.x', '--shard', 'product-1'], {
      cwd: repoRoot, env: { ...childEnv(), FLUXWARDEN_CI_CAPTURE_DIR: captureRoot, CONTROL_TRACE: trace, CONTROL_EXIT: String(code) }, windowsHide: true, timeout: 30_000,
    });
    expect(result.error).toBeUndefined(); expect(result.signal).toBeNull(); expect(result.status, 'actual dispatcher propagates original capture outcome').toBe(code);
    const calls = readFileSync(trace, 'utf8').trim().split('\n').map(line => asRecord(JSON.parse(line), 'transport call'));
    const capture = calls.find(call => {
      const args = call['args'];
      if (!Array.isArray(args)) return false;
      const index = args.findIndex(arg => /(?:^|[/\\])ci-capture\.mjs$/.test(String(arg)));
      return index >= 0 && args[index + 1] !== 'verify';
    });
    expect(capture, 'actual CLI executes through the unchanged finite capture boundary').toBeDefined();
    const args = capture?.['args'];
    expect(args).toEqual(expect.arrayContaining(['--capture-dir', captureRoot, '--', 'node', 'scripts/ci-job.mjs']));
    if (Array.isArray(args) && args.includes('--commands-only')) expect(args, 'explicit no-pending replaces the runner automatic check').toContain('scripts/no-pending.mjs');
    if (!Array.isArray(args) || !args.every(arg => typeof arg === 'string')) throw new Error('capture argv must be literal strings');
    const jobIndex = args.findIndex(arg => /(?:^|[/\\])ci-job\.mjs$/.test(arg));
    const start = args.indexOf('--', jobIndex + 1);
    expect(start, 'finite runner starts with its command delimiter').toBeGreaterThan(jobIndex);
    const actual: string[][] = [[]];
    for (const arg of args.slice(start + 1)) {
      if (arg === '--next') actual.push([]);
      else actual.at(-1)?.push(arg);
    }
    expect(actual, 'actual captured CLI schedules the complete public plan unchanged').toEqual(plan.commands);
  }
}
