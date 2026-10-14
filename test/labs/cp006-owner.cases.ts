import { expect, it } from 'vitest';
import { control, loadLab, options, owner } from '../helpers/cp006-lab.js';

it('CP-006/B1 existing owner containers refuse acquisition without any setup or teardown mutation', async () => {
  const selected = await owner(), fake = control('existing');
  const lab = (await loadLab()).createLab(await options(selected, fake.run));
  await expect(lab.up()).rejects.toThrow();
  expect(fake.calls.some(args => args.includes('ps')), 'refusal actually observes inventory').toBe(true);
  expect(fake.calls.some(args => args.includes('up') || args.includes('down') || args.includes('exec')), 'pre-existing resources untouched').toBe(false);
  for (const args of fake.calls) expect(args.join(' ')).toContain(selected.project);
});

it('CP-006/B5 startup child failure removes newly owned resources using owner-scoped volume teardown', async () => {
  const selected = await owner(), fake = control('up-failure');
  const lab = (await loadLab()).createLab(await options(selected, fake.run));
  await expect(lab.up()).rejects.toThrow();
  const up = fake.calls.findIndex(args => args.includes('up'));
  const down = fake.calls.findIndex(args => args.includes('down'));
  expect(up, 'attempted startup').toBeGreaterThanOrEqual(0);
  expect(down, 'failure cleanup after startup').toBeGreaterThan(up);
  const cleanup = fake.calls[down] ?? [];
  expect(cleanup).toContain('--volumes');
  expect(cleanup).toContain('--remove-orphans');
  expect(cleanup).toContain(selected.project);
  expect(fake.calls.some(args => args.includes('exec')), 'failed startup cannot fund or mine').toBe(false);
});

it('CP-006/B5 cleanup child failure propagates and cannot become successful teardown', async () => {
  const selected = await owner(), calls: string[][] = [];
  const run = (args: readonly string[]) => {
    calls.push([...args]);
    return Promise.resolve({ exitCode: args.includes('down') ? 29 : 0, stdout: '', stderr: '' });
  };
  const lab = (await loadLab()).createLab(await options(selected, run));
  await expect(lab.down()).rejects.toThrow();
  expect(calls.some(args => args.includes('down')), 'teardown actually attempted').toBe(true);
});

it('CP-006/B5 startup transport exception still removes newly owned resources', async () => {
  const selected = await owner(), calls: string[][] = [];
  const run = (args: readonly string[]) => {
    calls.push([...args]);
    if (args.includes('up')) return Promise.reject(new Error('synthetic startup transport exception'));
    return Promise.resolve({ exitCode: 0, stdout: '', stderr: '' });
  };
  const lab = (await loadLab()).createLab(await options(selected, run));
  await expect(lab.up()).rejects.toThrow();
  expect(calls.some(args => args.includes('up')), 'exception occurs during acquired startup').toBe(true);
  expect(calls.some(args => args.includes('down') && args.includes(selected.project)), 'transport exception cleaned owner').toBe(true);
});

it('CP-006/B5 cancellation after acquired startup retains a usable cleanup deadline', async () => {
  const selected = await owner(), calls: string[][] = [], controller = new AbortController();
  let cleanupCompleted = false;
  const run = (args: readonly string[], command: { signal?: AbortSignal }) => {
    calls.push([...args]);
    if (args.includes('up')) controller.abort();
    if (args.includes('down') && command.signal?.aborted) return Promise.reject(new Error('cleanup inherited cancelled startup'));
    if (args.includes('down')) cleanupCompleted = true;
    return Promise.resolve({ exitCode: 0, stdout: '', stderr: '' });
  };
  const configured = await options(selected, run); configured.signal = controller.signal;
  const lab = (await loadLab()).createLab(configured);
  await expect(lab.up()).rejects.toThrow();
  expect(calls.some(args => args.includes('up')), 'cancellation follows acquired startup').toBe(true);
  expect(calls.some(args => args.includes('down')), 'cancelled startup cleans owner').toBe(true);
  expect(cleanupCompleted, 'cleanup actually succeeds with independent cancellation context').toBe(true);
  expect(calls.some(args => ['generatetoaddress', 'sendtoaddress', 'openchannel', 'fundchannel'].some(method => args.includes(method))), 'cancellation stops money-moving setup').toBe(false);
});

it('CP-006/B7 broad owner permissions refuse acceptance before Docker ownership is acquired', async () => {
  const selected = await owner(), fake = control('up-failure');
  const module = await loadLab(), configured = await options(selected, fake.run);
  configured.permissions.assert = () => Promise.reject(new Error('owner permissions are broad'));
  await expect(async () => { const lab = module.createLab(configured); await lab.up(); }).rejects.toThrow();
  expect(fake.calls, 'unsafe owner root never reaches Docker').toHaveLength(0);
});

it('CP-006/B8 overlapping owner roots refuse before Docker can touch either owner', async () => {
  const selected = await owner(); selected.sentinelRoot = selected.tmpRoot;
  const fake = control('up-failure');
  const module = await loadLab();
  await expect(async () => { const lab = module.createLab(await options(selected, fake.run)); await lab.up(); }).rejects.toThrow();
  expect(fake.calls).toHaveLength(0);
});

it('CP-006/B8 duplicate loopback allocations and unbounded resource declarations refuse before Docker', async () => {
  const module = await loadLab();
  for (const kind of ['port', 'cpu', 'memory', 'pids'] as const) {
    const selected = await owner(), fake = control('up-failure');
    if (kind === 'port') selected.ports.clnRest = selected.ports.lndRest;
    if (kind === 'cpu') selected.resources.cpus = Infinity;
    if (kind === 'memory') selected.resources.memoryBytes = 0;
    if (kind === 'pids') selected.resources.pids = 0;
    await expect(async () => { const lab = module.createLab(await options(selected, fake.run)); await lab.up(); }).rejects.toThrow();
    expect(fake.calls, `${kind} refused before inventory or startup`).toHaveLength(0);
  }
});
