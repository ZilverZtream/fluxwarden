import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fork } from 'node:child_process';
import { join } from 'node:path';
import ts from 'typescript';
import { expect, it } from 'vitest';
import { asRecord, repoRoot } from '../helpers/cli.js';
import { ownedCaptureToolArgs } from '../helpers/capture-fixture.js';
import { loadLab, options, owner } from '../helpers/cp006-lab.js';
import type { Owner } from '../helpers/cp006-lab.js';
import { nodes, observedLab, topology } from '../helpers/cp006-observed.js';
import type { Observation, ScriptOptions } from '../helpers/cp006-observed.js';

async function allocated(index = 0): Promise<Owner> {
  const selected = await owner(index);
  selected.resources = { cpus: 4, memoryBytes: 4294967296, pids: 1024 };
  return selected;
}

async function setup(script: ScriptOptions = {}, index = 0) {
  const selected = await allocated(index), fake = observedLab(selected, script);
  const configured = await options(selected, fake.run);
  configured.clock = fake.clock; configured.delay = fake.delay;
  if (script.abort) configured.signal = script.abort.controller.signal;
  const lab = (await loadLab()).createLab(configured);
  return { selected, fake, lab };
}

const mutating = ['generatetoaddress', 'sendtoaddress', 'connect', 'openchannel', 'fundchannel', 'updatechanpolicy', 'setchannel'];
const matchesStage = (row: Observation, stage: string): boolean => row.method === stage || (stage === 'getmempoolinfo' && row.method === 'getrawmempool') || (stage === 'describegraph' && row.method === 'getchaninfo');
function cleanup(observations: Observation[], project: string): void {
  const downs = observations.filter(row => row.method === 'down');
  expect(downs.length, 'acquired owner teardown attempted').toBeGreaterThan(0);
  for (const down of downs) {
    expect(down.argv).toContain(project);
    expect(down.argv).toContain('--volumes');
    expect(down.argv).toContain('--remove-orphans');
    expect(down.command.signal?.aborted === true, 'cleanup cancellation is independent').toBe(false);
    expect(Number.isFinite(down.command.timeoutMs) && down.command.timeoutMs > 0, 'cleanup has finite deadline').toBe(true);
  }
}

it('CP-006/B4 delayed observed states release each setup stage only after every node is ready', async () => {
  const { selected, fake, lab } = await setup({ delayed: true });
  await lab.up();
  const rows = fake.observations;
  const indexes = (methods: string[]) => rows.flatMap((row, index) => methods.includes(row.method) ? [index] : []);
  const mines = indexes(['generatetoaddress']);
  expect(mines).toHaveLength(3);
  expect(mines.map(index => { const args = rows[index]?.argv ?? []; return args[args.indexOf('generatetoaddress') + 1]; })).toEqual(['101', '6', '6']);
  const funds = indexes(['sendtoaddress']), connects = indexes(['connect']), opens = indexes(['openchannel', 'fundchannel']), policies = indexes(['updatechanpolicy', 'setchannel']);
  expect(funds).toHaveLength(5); expect(opens).toHaveLength(5);
  expect(Math.min(...funds)).toBeGreaterThan(mines[0] ?? Infinity);
  expect(Math.max(...funds)).toBeLessThan(mines[1] ?? -1);
  expect(Math.min(...connects)).toBeGreaterThan(mines[1] ?? Infinity);
  expect(Math.max(...connects)).toBeLessThan(Math.min(...opens));
  expect(Math.max(...opens)).toBeLessThan(mines[2] ?? -1);
  expect(Math.min(...policies)).toBeGreaterThan(mines[2] ?? Infinity);
  expect([...new Set(policies.map(index => rows[index]?.node))].sort(), 'outgoing policies configured on every endpoint node').toEqual([...nodes].sort());
  const between = (start: number, end: number, methods: string[], node?: string) => rows.slice(start + 1, end).filter(row => methods.includes(row.method) && (!node || row.node === node));
  const waited = (answers: Observation[]) => {
    expect(answers.some(row => !row.ready), 'a genuinely unready answer was observed').toBe(true);
    expect(answers.some(row => row.ready), 'a later state released the wait').toBe(true);
    expect(answers.at(-1)?.ready).toBe(true);
  };
  for (const node of nodes) {
    waited(between(mines[0] ?? -1, Math.min(...funds), ['getinfo'], node));
    waited(between(mines[1] ?? -1, Math.min(...connects), ['walletbalance', 'listfunds'], node));
    waited(between(Math.max(...connects), Math.min(...opens), ['listpeers'], node));
    waited(between(mines[2] ?? -1, Math.min(...policies), ['listchannels', 'listpeerchannels'], node));
    waited(between(Math.max(...policies), rows.length, ['describegraph', 'getchaninfo', 'listchannels'], node));
  }
  waited(between(Math.max(...opens), mines[2] ?? -1, ['getmempoolinfo', 'getrawmempool']));
  for (const node of nodes.filter(node => node.startsWith('cln-'))) waited(between(Math.max(...policies), rows.length, ['askrene-listlayers'], node));
  expect(fake.delays.length, 'conditional retries actually delay').toBeGreaterThan(0);
  expect(fake.delays.every(ms => Number.isFinite(ms) && ms > 0)).toBe(true);
  for (const [index, channel] of topology.channels.entries()) {
    const opening = rows[opens[index] ?? -1];
    expect(opening?.node).toBe(channel.from);
    expect(opening?.argv.some(arg => arg.includes(fake.pubkeys[channel.to] ?? 'unmatchable'))).toBe(true);
    expect(opening?.argv.join(' ')).toContain('5000000');
    expect(opening?.argv.join(' ')).toContain((BigInt(channel.push_msat) / 1000n).toString());
  }
  for (const row of rows) { expect(row.command.cwd.length).toBeGreaterThan(0); expect(Number.isFinite(row.command.timeoutMs) && row.command.timeoutMs > 0).toBe(true); }
  await lab.down(); cleanup(fake.observations, selected.project);
  expect(fake.maxMutating(), 'owner setup and teardown mutations are serial').toBe(1);
});

for (const phase of ['chain', 'balance', 'peers', 'mempool', 'active', 'graph', 'layers'] as const) {
  it(`CP-006/B4 ${phase} never-ready exit-zero state reaches a bounded deadline and cleans its owner`, async () => {
    const { selected, fake, lab } = await setup({ never: phase });
    await expect(lab.up()).rejects.toThrow();
    expect(fake.observations.some(row => !row.ready), 'deadline follows observed unready state').toBe(true);
    expect(fake.delays.length).toBeGreaterThan(0);
    expect(fake.delays.length, 'no unbounded polling').toBeLessThan(10000);
    cleanup(fake.observations, selected.project);
  }, 60_000);
}

const stages = ['up', 'getinfo', 'generatetoaddress', 'sendtoaddress', 'walletbalance', 'listfunds', 'connect', 'listpeers', 'openchannel', 'fundchannel', 'getmempoolinfo', 'listpeerchannels', 'updatechanpolicy', 'setchannel', 'describegraph', 'askrene-listlayers'];
for (const stage of stages) {
  it(`CP-006/B5 child failure at ${stage} propagates and removes only newly owned resources`, async () => {
    const { selected, fake, lab } = await setup({ fail: stage });
    const safe = join(selected.evidenceRoot, 'independent-safe-observation.txt'); writeFileSync(safe, 'safe evidence retained');
    await expect(lab.up()).rejects.toThrow();
    const failed = fake.observations.findIndex(row => matchesStage(row, stage));
    expect(failed, 'failure control was actually reached').toBeGreaterThanOrEqual(0);
    expect(fake.observations.slice(failed + 1).some(row => mutating.includes(row.method)), 'no mutation after failed child').toBe(false);
    cleanup(fake.observations, selected.project);
    expect(existsSync(safe) && readFileSync(safe, 'utf8') === 'safe evidence retained', 'safe evidence survives failure').toBe(true);
  });
}

for (const mechanism of ['exception', 'malformed', 'abort', 'timeout'] as const) {
  for (const stage of mechanism === 'malformed' ? ['getinfo', 'listfunds', 'listpeerchannels', 'describegraph', 'askrene-listlayers'] : stages) {
    it(`CP-006/B5 ${mechanism} at ${stage} cannot accept readiness and retains usable cleanup`, async () => {
      const script: ScriptOptions = mechanism === 'abort' ? { abort: { method: stage, controller: new AbortController() } } : { [mechanism]: stage };
      const { selected, fake, lab } = await setup(script);
      await expect(lab.up()).rejects.toThrow();
      expect(fake.observations.some(row => matchesStage(row, stage)), 'control reached its intended stage').toBe(true);
      cleanup(fake.observations, selected.project);
    });
  }
}

for (const budget of ['cpu', 'memory', 'pids'] as const) {
  it(`CP-006/B8 excessive owner ${budget} budget refuses before Docker`, async () => {
    const selected = await allocated(), fake = observedLab(selected);
    if (budget === 'cpu') selected.resources.cpus = 4.01;
    if (budget === 'memory') selected.resources.memoryBytes = 4294967297;
    if (budget === 'pids') selected.resources.pids = 1025;
    const module = await loadLab();
    await expect(async () => { const lab = module.createLab(await options(selected, fake.run)); await lab.up(); }).rejects.toThrow();
    expect(fake.observations).toHaveLength(0);
  });
}

it('CP-006/B8 two real owner workers overlap at a deterministic barrier with disjoint bounded allocations', async () => {
  await loadLab(); // Missing public behavior is fail-first before launching fixture workers.
  const selected = [await allocated(0), await allocated(1)];
  const roots = selected.flatMap(selected => [selected.runtimeRoot, selected.tmpRoot, selected.sentinelRoot, selected.evidenceRoot]);
  expect(new Set(roots).size).toBe(8);
  expect(new Set(selected.map(owner => owner.project)).size).toBe(2);
  expect(new Set(selected.flatMap(owner => Object.values(owner.ports))).size).toBe(6);
  const temporary = process.env['FLUXWARDEN_TEST_TMP']; if (!temporary) throw new Error('private fixture root required');
  const compiled = join(temporary, 'cp006-observed-worker.mjs');
  const source = readFileSync(join(repoRoot, 'test/helpers/cp006-observed.ts'), 'utf8').replace("import { asRecord, readJson, repoRoot } from './cli.js';", `const repoRoot = ${JSON.stringify(repoRoot)}; const asRecord = (value, label) => { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(label); return value; }; const readJson = path => JSON.parse(readFileSync(repoRoot + '/' + path, 'utf8'));`);
  writeFileSync(compiled, ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText, { mode: 0o600 });
  const workers = selected.map(owner => {
    const declaration = join(owner.tmpRoot, 'worker-owner.json'); writeFileSync(declaration, JSON.stringify(owner), { mode: 0o600 });
    return fork(join(repoRoot, 'test/fixtures/cp006-owner-worker.mjs'), [declaration, compiled, join(repoRoot, 'labs/docker/lab.mjs'), join(repoRoot, 'scripts/private-scratch.mjs')], { cwd: repoRoot, execPath: process.execPath, execArgv: ownedCaptureToolArgs([]), env: { ...process.env, VITEST_MAX_THREADS: '99', VITEST_MAX_WORKERS: '99' }, silent: true });
  });
  const acquired: Record<string, unknown>[] = [], completed: Record<string, unknown>[] = [];
  const timer = setTimeout(() => { for (const worker of workers) worker.kill(); }, 110000);
  try {
    const exits = await Promise.all(workers.map(worker => new Promise<number | null>((done, reject) => {
      worker.once('error', reject); worker.once('exit', done);
      worker.on('message', message => {
        const value = asRecord(message, 'worker public result');
        if (value['kind'] === 'acquired') { acquired.push(value); if (acquired.length === 2) for (const child of workers) child.send('release'); }
        if (value['kind'] === 'completed') completed.push(value);
      });
    })));
    expect(exits).toEqual([0, 0]); expect(acquired).toHaveLength(2); expect(completed).toHaveLength(2);
    expect(new Set(acquired.map(worker => worker['pid'])).size, 'two distinct actual processes').toBe(2);
    expect(acquired.map(worker => worker['project']).sort()).toEqual(selected.map(owner => owner.project).sort());
    for (const worker of completed) {
      expect(worker['maxMutating'], 'inherited requests cannot increase owner mutating concurrency').toBe(1);
      const calls = worker['calls']; if (!Array.isArray(calls)) throw new Error('actual worker calls required');
      expect(calls.every(call => asRecord(call, 'worker command')['ownerScoped'] === true)).toBe(true);
      expect(calls.some(call => asRecord(call, 'worker command')['method'] === 'down')).toBe(true);
    }
    expect(selected.reduce((sum, owner) => sum + owner.resources.cpus, 0)).toBe(8);
    expect(selected.reduce((sum, owner) => sum + owner.resources.memoryBytes, 0)).toBe(8589934592);
    expect(selected.reduce((sum, owner) => sum + owner.resources.pids, 0)).toBe(2048);
  } finally { clearTimeout(timer); for (const worker of workers) if (worker.exitCode === null) worker.kill(); }
}, 120000);
