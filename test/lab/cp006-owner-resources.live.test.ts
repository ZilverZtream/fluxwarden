import { spawn } from 'node:child_process';
import { existsSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { afterEach, expect, it } from 'vitest';
import { asRecord, repoRoot } from '../helpers/cli.js';
import { allServices, dockerText, LabInvalidError, rows } from '../helpers/cp006-oracle.js';
import type { Result, Run } from '../helpers/cp006-lab.js';
import { loadLab, options } from '../helpers/cp006-lab.js';
import type { LiveOwner, Scenario } from '../helpers/cp006-lifecycle-plan.js';
import { lifecyclePlan } from '../helpers/cp006-lifecycle-plan.js';

const generalBudgetMs = 180000;
let evidenceCase = '';
function retain(selected: LiveOwner, name: string, value: string): void { writeFileSync(join(selected.owner.evidenceRoot, `cp006-r5-${evidenceCase}-${name}.txt`), value, { mode: 0o600 }); }
let observationOwner: LiveOwner | undefined;
let observationNumber = 0;
const activeWorkers = new Map<number, string>();
let peakWorkers = 0;
const pendingOperations = new Set<{ cancel(): void; completed: Promise<unknown> }>();
interface CaseOwner { selected: LiveOwner[]; projects: string[]; before: ReturnType<typeof unrelated>; positive: boolean }
let currentCase: CaseOwner | undefined;
function completedOutcomes(results: PromiseSettledResult<unknown>[]): void {
  for (const result of results) if (result.status === 'rejected') {
    if (result.reason instanceof Error) throw result.reason;
    throw new LabInvalidError('owned lifecycle rejected without a classified error');
  }
}
function observedDocker(args: string[]): string {
  const raw = dockerText(args);
  if (observationOwner) retain(observationOwner, `original-docker-${String(++observationNumber)}`, JSON.stringify({ argv: args }) + '\n' + raw);
  return raw;
}
function inventory(project: string): { containers: string[]; volumes: string[] } {
  return { containers: observedDocker(['ps', '-aq', '--filter', `label=com.docker.compose.project=${project}`]).split(/\s+/).filter(Boolean), volumes: observedDocker(['volume', 'ls', '-q', '--filter', `label=com.docker.compose.project=${project}`]).split(/\s+/).filter(Boolean) };
}
function unrelated(projects: string[]): { containers: string[]; volumes: string[] } {
  const owned = (line: string) => projects.some(project => new RegExp(`(?:^|[,\\s])com\\.docker\\.compose\\.project=${project}(?:$|[,\\s])`).test(line));
  return { containers: observedDocker(['ps', '-a', '--no-trunc', '--format', '{{.ID}} {{.Names}} {{.State}} {{.Labels}}']).split('\n').filter(line => line && !owned(line)).sort(), volumes: observedDocker(['volume', 'ls', '--format', '{{.Name}} {{.Labels}}']).split('\n').filter(line => line && !owned(line)).sort() };
}
function allocation(selected: LiveOwner): { cpus: number; memory: number; pids: number } {
  const ids = inventory(selected.owner.project).containers; expect(ids).toHaveLength(7);
  const raw = observedDocker(['inspect', ...ids]); retain(selected, 'ready-inspect', raw);
  const inspected = rows(JSON.parse(raw) as unknown, 'actual live inspect');
  let cpus = 0, memory = 0, pids = 0; const ports: number[] = [], services: unknown[] = [];
  for (const container of inspected) {
    const labels = asRecord(asRecord(container['Config'], 'live config')['Labels'], 'live labels');
    expect(labels['com.docker.compose.project']).toBe(selected.owner.project); services.push(labels['com.docker.compose.service']);
    expect(asRecord(container['State'], 'live state')['Running']).toBe(true);
    const limits = asRecord(container['HostConfig'], 'actual live limits');
    for (const field of ['NanoCpus', 'Memory', 'PidsLimit']) expect(limits[field]).toBeGreaterThan(0);
    cpus += Number(limits['NanoCpus']) / 1000000000; memory += Number(limits['Memory']); pids += Number(limits['PidsLimit']);
    for (const bindings of Object.values(asRecord(asRecord(container['NetworkSettings'], 'live networking')['Ports'], 'live ports'))) {
      if (bindings === null) continue;
      for (const binding of rows(bindings, 'published live ports')) { expect(binding['HostIp']).toBe('127.0.0.1'); ports.push(Number(binding['HostPort'])); }
    }
  }
  expect(services.sort()).toEqual([...allServices].sort()); expect(ports.sort((a, b) => a - b)).toEqual(Object.values(selected.owner.ports).sort((a, b) => a - b));
  expect(cpus).toBeLessThanOrEqual(selected.owner.resources.cpus); expect(memory).toBeLessThanOrEqual(selected.owner.resources.memoryBytes); expect(pids).toBeLessThanOrEqual(selected.owner.resources.pids);
  return { cpus, memory, pids };
}
function processExists(pid: number): boolean { try { process.kill(pid, 0); return true; } catch { return false; } }

async function command(selected: LiveOwner, operation: 'up' | 'down', sample?: Scenario, timeoutMs = generalBudgetMs): Promise<{ exit: number | null; pid: number; output: string }> {
  const child = spawn(process.execPath, [join(repoRoot, 'labs/docker/lab.mjs'), operation, '--owner', selected.declaration], { cwd: repoRoot, shell: false, windowsHide: true, env: { ...process.env, VITEST_MAX_THREADS: '99', VITEST_MAX_WORKERS: '99' }, stdio: ['ignore', 'pipe', 'pipe'] });
  if (!child.pid) throw new LabInvalidError('public owner CLI did not start');
  const pid = child.pid, chunks: Buffer[] = []; child.stdout.on('data', (chunk: Buffer) => chunks.push(chunk)); child.stderr.on('data', (chunk: Buffer) => chunks.push(chunk));
  activeWorkers.set(pid, selected.owner.project);
  const liveWorkers = [...activeWorkers].filter(([worker]) => processExists(worker));
  peakWorkers = Math.max(peakWorkers, liveWorkers.length);
  retain(selected, `${operation}-${sample?.outcome ?? 'success'}-active-workers`, JSON.stringify(liveWorkers.map(([pid, project]) => ({ pid, project, observedRunning: processExists(pid) }))));
  expect(liveWorkers.length).toBeLessThanOrEqual(2); expect(new Set(liveWorkers.map(([, project]) => project)).size, 'one actual CLI worker per owner').toBe(liveWorkers.length);
  const completed = new Promise<number | null>((done, reject) => { child.once('error', reject); child.once('close', done); });
  const pending = { cancel: () => { child.kill('SIGTERM'); }, completed }; pendingOperations.add(pending);
  void completed.then(() => pendingOperations.delete(pending), () => pendingOperations.delete(pending));
  const state = { exited: false }; void completed.then(() => { state.exited = true; }, () => { state.exited = true; });
  let timedOut = false;
  const timer = setTimeout(() => { if (!state.exited) { timedOut = true; child.kill('SIGKILL'); } }, Math.min(timeoutMs, generalBudgetMs));
  try {
    if (sample) {
      const deadline = Date.now() + 60000;
      while (!state.exited && inventory(selected.owner.project).containers.length === 0 && Date.now() < deadline) await delay(100);
      expect(state.exited, 'fault follows acquired startup').toBe(false);
      const owned = inventory(selected.owner.project).containers; expect(owned.length).toBeGreaterThan(0);
      retain(selected, `${sample.outcome}-before-inspect`, observedDocker(['inspect', ...owned]));
      if (sample.outcome !== 'SIGINT' && sample.outcome !== 'SIGTERM') throw new LabInvalidError('public CLI scenario requires an actual POSIX signal');
      if (process.platform === 'win32') throw new LabInvalidError('actual graceful POSIX signal evidence requires a supported live host');
      expect(child.kill(sample.outcome)).toBe(true);
      retain(selected, `${sample.outcome}-trigger`, JSON.stringify({ source: 'actual OS signal', pid, signal: sample.outcome, ownedContainers: owned }));
    }
    const exit = await completed, output = Buffer.concat(chunks).toString('utf8'), outcome = sample?.outcome ?? 'success';
    retain(selected, `${operation}-${outcome}-output`, output); retain(selected, `${operation}-${outcome}-process`, JSON.stringify({ pid, exit, timedOut, existsAfterExit: processExists(pid) }));
    expect(timedOut, 'guard termination cannot substitute for the requested lifecycle outcome').toBe(false);
    expect(processExists(pid), 'actual CLI worker disappeared').toBe(false); return { exit, pid, output };
  } finally { clearTimeout(timer); if (!state.exited) child.kill('SIGTERM'); activeWorkers.delete(pid); }
}
function cleaned(selected: LiveOwner, name: string): void {
  const after = inventory(selected.owner.project); retain(selected, `${name}-after-inventory`, JSON.stringify(after)); expect(after.containers).toEqual([]); expect(after.volumes).toEqual([]);
  expect(!existsSync(selected.owner.tmpRoot) || readdirSync(selected.owner.tmpRoot).length === 0, 'temporary secret state removed').toBe(true); expect(readdirSync(selected.owner.evidenceRoot).length).toBeGreaterThan(0);
}

// This dispatcher always executes Docker, including teardown. Only the explicit
// hostile input at the ordinary getinfo boundary is synthetic and labelled as such.
function realRun(selected: LiveOwner, name: string): Run {
  let sequence = 0;
  return (argv, configured) => new Promise((done, reject) => {
    const child = spawn('docker', [...argv], { cwd: configured.cwd, env: configured.env, signal: configured.signal, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout: Buffer[] = [], stderr: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk)); child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    const bound = Math.min(configured.timeoutMs, generalBudgetMs);
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, bound);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (exitCode, signal) => {
      clearTimeout(timer);
      const result = { exitCode: exitCode ?? 1, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') };
      retain(selected, `${name}-child-${String(++sequence)}`, JSON.stringify({ source: 'actual Docker child', argv, pid: child.pid, exitCode, signal, timedOut, timeoutMs: bound }) + '\n' + result.stdout + '\n' + result.stderr);
      if (timedOut) reject(new LabInvalidError('real Docker child exceeded documented general guard')); else done(result);
    });
  });
}

async function injectedLifecycle(selected: LiveOwner, sample: Scenario): Promise<void> {
  const dispatch = realRun(selected, sample.outcome), controller = new AbortController();
  let triggered = false, cleanup = false, offset = 0, rejected = false;
  const setupMutations: string[][] = [];
  const run: Run = async (argv, configured) => {
    if (argv.includes('down')) {
      expect(triggered, 'cleanup follows the classified stimulus').toBe(true);
      expect(argv).toContain(selected.owner.project); expect(argv).toContain('--volumes'); expect(argv).toContain('--remove-orphans');
      // The clock remains monotonic after the setup deadline advance. Cleanup
      // must supply its own positive bounded budget from this new time origin.
      expect(configured.timeoutMs).toBeGreaterThan(0); expect(configured.timeoutMs).toBeLessThanOrEqual(600000);
      const result = await dispatch(argv, configured); cleanup = result.exitCode === 0; return result;
    }
    if (triggered && ['generatetoaddress', 'sendtoaddress', 'openchannel', 'fundchannel'].some(method => argv.includes(method))) setupMutations.push([...argv]);
    const exec = argv.indexOf('exec');
    if (!triggered && exec >= 0 && argv.slice(exec + 1).includes('lnd-p') && argv.includes('getinfo')) {
      const acquired = inventory(selected.owner.project);
      expect(acquired.containers).toHaveLength(7); expect(acquired.volumes.length).toBeGreaterThan(0);
      retain(selected, `${sample.outcome}-before-inspect`, observedDocker(['inspect', ...acquired.containers]));
      expect(allocation(selected).cpus).toBeGreaterThan(0);
      triggered = true;
      retain(selected, `${sample.outcome}-worker-before`, JSON.stringify({ source: 'actual API caller process', pid: process.pid, observedRunning: processExists(process.pid), project: selected.owner.project }));
      if (sample.outcome === 'child-failure') {
        const stop = await dispatch(['compose', '--project-name', selected.owner.project, '-f', join(repoRoot, 'labs/docker/docker-compose.yml'), 'stop', 'lnd-p'], configured);
        expect(stop.exitCode).toBe(0);
        const failed = await dispatch(argv, configured);
        expect(failed.exitCode, 'actual owned Docker exec fails after its service stops').not.toBe(0);
        retain(selected, `${sample.outcome}-trigger`, JSON.stringify({ source: 'actual owned Docker child', argv, exitCode: failed.exitCode, acquired }));
        return failed;
      }
      if (sample.outcome === 'exception') {
        retain(selected, `${sample.outcome}-trigger`, JSON.stringify({ source: 'synthetic injected transport exception', acquired }));
        throw new Error('injected lifecycle transport exception');
      }
      const actual = await dispatch(argv, configured); expect(actual.exitCode).toBe(0);
      if (sample.outcome === 'INVALID') {
        const info = asRecord(JSON.parse(actual.stdout) as unknown, 'original actual node identity');
        const chains = rows(info['chains'], 'original actual network');
        expect(chains).toHaveLength(1); expect(chains[0]?.['network']).toBe('regtest');
        const injected: Result = { ...actual, stdout: JSON.stringify({ ...info, chains: chains.map(chain => ({ ...chain, network: 'mainnet' })) }) };
        retain(selected, `${sample.outcome}-trigger`, JSON.stringify({ source: 'synthetic injected node answer; not an actual node fact', service: 'lnd-p', actualNetwork: 'regtest', injectedNetwork: 'mainnet', childExitCode: actual.exitCode, acquired }));
        return injected;
      }
      if (sample.outcome === 'timeout') {
        // Exceed the unchanged maximum general setup deadline through the public
        // clock boundary, without delaying or extending any real child guard.
        offset = 600001;
        retain(selected, `${sample.outcome}-trigger`, JSON.stringify({ source: 'synthetic injected monotonic deadline', advanceMs: offset, childExitCode: actual.exitCode, acquired }));
        return actual;
      }
      throw new LabInvalidError('unsupported injected scenario');
    }
    return dispatch(argv, configured);
  };
  const configured = await options(selected.owner, run);
  configured.clock = () => performance.now() + offset;
  configured.delay = (ms, signal) => delay(ms, undefined, signal === undefined ? {} : { signal });
  configured.signal = controller.signal;
  const lab = (await loadLab()).createLab(configured);
  const completed = lab.up().then(() => { throw new Error('failure stimulus incorrectly allowed successful readiness'); }, () => { rejected = true; });
  const pending = { cancel: () => { controller.abort(); }, completed }; pendingOperations.add(pending);
  void completed.then(() => pendingOperations.delete(pending), () => pendingOperations.delete(pending));
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      completed,
      new Promise<never>((_done, reject) => { timer = setTimeout(() => { controller.abort(); reject(new LabInvalidError('injected lifecycle exceeded documented general guard')); }, generalBudgetMs); }),
    ]);
    expect(triggered, 'a do-nothing lifecycle never reaches the actual acquired-resource boundary').toBe(true);
    expect(rejected, 'public lifecycle rejects the classified failure').toBe(true);
    expect(cleanup, 'successful actual Docker cleanup was dispatched by the lifecycle').toBe(true);
    expect(setupMutations, 'no money-moving setup after the failure trigger').toEqual([]);
    cleaned(selected, sample.outcome);
    retain(selected, `${sample.outcome}-outcome`, JSON.stringify({ triggered, rejected, realCleanupSucceeded: cleanup, setupMutations: setupMutations.length, callerPid: process.pid, callerStillRunning: processExists(process.pid) }));
  } finally { if (timer !== undefined) clearTimeout(timer); }
}

async function freshCase(name: string, positive = false): Promise<CaseOwner> {
  const selected = lifecyclePlan(); // No Docker or process launch without this complete independent plan.
  if (process.platform === 'win32') throw new LabInvalidError('complete actual SIGINT/SIGTERM reference requires a supported POSIX live host');
  for (const item of selected) { const permissions = (await options(item.owner, () => Promise.resolve({ exitCode: 0, stdout: '', stderr: '' }))).permissions; for (const root of [item.owner.runtimeRoot, item.owner.tmpRoot, item.owner.sentinelRoot, item.owner.evidenceRoot]) await permissions.assert(root); }
  evidenceCase = name;
  observationOwner = selected[0]; observationNumber = 0; activeWorkers.clear(); peakWorkers = 0;
  const projects = selected.map(value => value.owner.project), before = unrelated(projects);
  for (const item of selected) expect(inventory(item.owner.project), 'fresh owner projects').toEqual({ containers: [], volumes: [] });
  const active = { selected, projects, before, positive }; currentCase = active; return active;
}

// A case can consume its documented deadline. Its independently documented hook
// budget still bounds cancellation and actual owner-only cleanup after failure.
afterEach(async () => {
  const active = currentCase;
  try {
    if (!active) return; // Refused/unacquired owners never reach teardown.
    const deadline = performance.now() + generalBudgetMs;
    const pending = [...pendingOperations]; for (const operation of pending) operation.cancel();
    await Promise.allSettled(pending.map(operation => operation.completed));
    const outcomes = await Promise.allSettled(active.selected.map(async item => {
      const owned = inventory(item.owner.project);
      if (active.positive || owned.containers.length || owned.volumes.length) {
        const remaining = Math.floor(deadline - performance.now());
        expect(remaining, 'actual teardown retains a positive independently bounded hook budget').toBeGreaterThan(0);
        expect((await command(item, 'down', undefined, remaining)).exit, 'actual public CLI down succeeds').toBe(0);
      }
      cleaned(item, 'hook');
    }));
    completedOutcomes(outcomes);
    expect(unrelated(active.projects)).toEqual(active.before);
  } finally { currentCase = undefined; observationOwner = undefined; evidenceCase = ''; }
}, 180000);

async function failureCase(outcome: Scenario['outcome']): Promise<void> {
  const active = await freshCase(outcome);
  const results = await Promise.allSettled(active.selected.map(async item => {
    const sample = item.scenarios.find(value => value.outcome === outcome);
    if (!sample) throw new LabInvalidError('independent plan is missing the selected distinct outcome');
    if (outcome === 'SIGINT' || outcome === 'SIGTERM') { expect((await command(item, 'up', sample)).exit).toBe(1); cleaned(item, outcome); }
    else await injectedLifecycle(item, sample);
  }));
  // Emergency hook teardown cannot turn failed stimulus or lifecycle cleanup into PASS.
  completedOutcomes(results);
  expect(unrelated(active.projects)).toEqual(active.before);
}

it('CP-006/R5 two independent live owners simultaneously reach public CLI readiness with bounded allocations actual workers and successful down', async () => {
  const active = await freshCase('positive', true);
  const outcomes = await Promise.allSettled(active.selected.map(item => command(item, 'up')));
  completedOutcomes(outcomes);
  const result = outcomes.flatMap(value => value.status === 'fulfilled' ? [value.value] : []);
  expect(result.map(value => value.exit)).toEqual([0, 0]); expect(new Set(result.map(value => value.pid)).size).toBe(2);
  expect(peakWorkers, 'two live CLI owner workers actually overlapped despite inherited requests').toBe(2);
  const resources = active.selected.map(allocation); expect(resources.reduce((sum, value) => sum + value.cpus, 0)).toBeLessThanOrEqual(8); expect(resources.reduce((sum, value) => sum + value.memory, 0)).toBeLessThanOrEqual(8589934592); expect(resources.reduce((sum, value) => sum + value.pids, 0)).toBeLessThanOrEqual(2048);
  expect(unrelated(active.projects)).toEqual(active.before);
}, 180000);

it('CP-006/R5-child both live owners reject an actual owned child failure and perform real cleanup', async () => { await failureCase('child-failure'); }, 180000);
it('CP-006/R5-invalid both live owners reject explicitly injected INVALID network answers and perform real cleanup', async () => { await failureCase('INVALID'); }, 180000);
it('CP-006/R5-deadline both live owners reject an injected monotonic deadline and perform real cleanup before any watchdog', async () => { await failureCase('timeout'); }, 180000);
it('CP-006/R5-exception both live owners reject an injected transport exception and perform real cleanup', async () => { await failureCase('exception'); }, 180000);
it('CP-006/R5-sigint both live owners receive actual public CLI SIGINT and perform real cleanup', async () => { await failureCase('SIGINT'); }, 180000);
it('CP-006/R5-sigterm both live owners receive actual public CLI SIGTERM and perform real cleanup', async () => { await failureCase('SIGTERM'); }, 180000);
