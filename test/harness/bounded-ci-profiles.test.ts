// CP-044 D29/D30 bounded-CI-profile reference, 2026-10-27. The exact 168
// targets are a reference choice, independent of the candidate's target list.
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { childEnv, repoRoot } from '../helpers/cli.js';
import { platformPlan } from '../helpers/oct26-ci-oracles.js';
import { changeReport, independentInventory, releaseFixture, verifyFixture,
  type Inventory, type PlatformJob, type PlatformRow, type TestReport } from '../helpers/oct26-release-gate.js';

const RUNTIMES = ['22.23.2', '22.x', '24.18.1', '24.x', '26.5.1', '26.x'];
function expectedTargets(): PlatformJob[] {
  return ['ubuntu-latest', 'windows-latest'].flatMap(os => RUNTIMES.flatMap(node => {
    const groups: [string, number][] = os === 'ubuntu-latest' ? [['product', 2], ['harness', 8]] : [['core', 8], ['harness', 8], ['native', 2]];
    return groups.flatMap(([kind, count]) => Array.from({ length: count }, (_, index) => {
      const shard = `${kind}-${String(index + 1)}`;
      return { os, node, shard, suite: kind === 'harness' ? 'harness' as const : 'product' as const, key: `platform/${os}/${node}/${shard}` };
    }));
  }));
}
const ordered = (jobs: PlatformJob[]): PlatformJob[] => [...jobs].sort((a, b) => a.key.localeCompare(b.key));
async function inventoryApi(): Promise<{
  platformJobs: () => PlatformJob[];
  deriveInventory: (sourceCommit: string, suites: string[]) => Promise<Omit<Inventory, 'casesByTarget'>>;
}> {
  return import(pathToFileURL(join(repoRoot, 'scripts/release-inventory.mjs')).href) as ReturnType<typeof inventoryApi>;
}

it('CP-044/PROFILE-SET public inventory and independent fixture require all 168 exact OS runtime and partition targets', async () => {
  const expected = expectedTargets(), api = await inventoryApi();
  expect(expected).toHaveLength(168); expect(new Set(expected.map(row => row.key)).size).toBe(168);
  expect(api.platformJobs(), 'D29/D30 explicit platform count').toHaveLength(168);
  expect(ordered(api.platformJobs())).toEqual(ordered(expected));
  expect(ordered(independentInventory().platformJobs)).toEqual(ordered(expected));
});

it('CP-044/PROFILE-INVALID dispatcher refuses targets outside the exact two eight and native partition ranges', async () => {
  for (const target of [
    { os: 'ubuntu-latest', node: '24.x', shard: 'harness-0' }, { os: 'ubuntu-latest', node: '24.x', shard: 'harness-9' },
    { os: 'ubuntu-latest', node: '24.x', shard: 'product-3' }, { os: 'ubuntu-latest', node: '24.x', shard: 'core-1' },
    { os: 'windows-latest', node: '24.x', shard: 'core-0' }, { os: 'windows-latest', node: '24.x', shard: 'core-9' },
    { os: 'windows-latest', node: '24.x', shard: 'harness-9' }, { os: 'windows-latest', node: '24.x', shard: 'native-3' },
    { os: 'windows-latest', node: '24.x', shard: 'product-1' }, { os: 'ubuntu-latest', node: '24.x', shard: 'native-1' },
    { os: 'macos-latest', node: '24.x', shard: 'harness-1' }, { os: 'windows-latest', node: '20.x', shard: 'core-1' },
  ]) await expect(platformPlan(target, childEnv()), JSON.stringify(target)).rejects.toThrow();
});

it('CP-044/PROFILE-DERIVE clean-source public derivation preserves every original collected product case and exact target set', async () => {
  // Dynamic Vitest collection imports real source declarations, without running
  // bodies/hooks. Freeze the TE commit before this clean-source API is invoked.
  const identity = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: repoRoot, env: childEnv(), encoding: 'utf8', windowsHide: true, timeout: 10_000 });
  expect(identity.status).toBe(0);
  const derived = await (await inventoryApi()).deriveInventory(identity.stdout.trim(), ['product']);
  const product = derived.cases['product']; if (!product) throw new Error('actual product source collection absent');
  const ids = product.map(row => `${row.file}\n${row.name}`);
  expect(product.length).toBeGreaterThan(0); expect(new Set(ids).size, 'source case IDs occur exactly once').toBe(ids.length);
  // The original independent collection records platform-conditional declarations.
  // Compare the exact original eligible set on this host; later additions cannot
  // mask a missing original or make a Windows-only original eligible on Linux.
  const original = independentInventory(), os = process.platform === 'win32' ? 'windows-latest' : 'ubuntu-latest';
  const frozen = original.casesByTarget[`${os}/24.x`];
  if (!frozen) throw new Error('independent original source collection absent');
  const originalIds = new Set(Object.values(original.casesByTarget).flatMap(target => target.product.map(row => `${row.file}\n${row.name}`)));
  expect(ids.filter(id => originalIds.has(id)).sort(), 'exact independently recorded original platform eligibility').toEqual(
    frozen.product.map(row => `${row.file}\n${row.name}`).sort());
  expect(derived.platformJobs).toHaveLength(168);
  expect(ordered(derived.platformJobs)).toEqual(ordered(expectedTargets()));
});

function firstRow(rows: PlatformRow[]): PlatformRow {
  const row = rows[0]; if (!row) throw new Error('fixture needs a platform row'); return row;
}
function firstTest(report: TestReport) {
  const test = report.testResults[0]?.assertionResults[0]; if (!test) throw new Error('fixture needs a source assertion'); return test;
}

it('CP-044/PROFILE-FINAL final verifier accepts complete 168-profile control and refuses missing duplicate empty skipped or pending coverage', async () => {
  const positive = releaseFixture(); expect(positive.bundle.platform).toHaveLength(168);
  expect(await verifyFixture(positive), 'new targets must first establish actual accepted complete evidence').toBe(0);
  const mutations = [
    (f: ReturnType<typeof releaseFixture>) => { f.bundle.platform.pop(); },
    (f: ReturnType<typeof releaseFixture>) => { f.bundle.platform.splice(1, 1, { ...firstRow(f.bundle.platform) }); },
    (f: ReturnType<typeof releaseFixture>) => { f.bundle.platform = f.bundle.platform.filter(row => row.node !== '26.x'); },
    (f: ReturnType<typeof releaseFixture>) => { const row = firstRow(f.bundle.platform); const job = f.jobs.find(item => item.id === row.jobId); if (!job) throw new Error('bound official job absent'); job.conclusion = 'skipped'; },
    (f: ReturnType<typeof releaseFixture>) => { changeReport(f, firstRow(f.bundle.platform), report => { report.testResults = []; report.numTotalTests = 0; report.numPassedTests = 0; }); },
    (f: ReturnType<typeof releaseFixture>) => { changeReport(f, firstRow(f.bundle.platform), report => { firstTest(report).status = 'pending'; report.numPassedTests -= 1; report.numPendingTests += 1; }); },
    (f: ReturnType<typeof releaseFixture>) => { changeReport(f, firstRow(f.bundle.platform), report => {
      const file = report.testResults[0]; if (!file) throw new Error('source report file absent'); file.assertionResults.push({ ...firstTest(report) }); report.numTotalTests += 1; report.numPassedTests += 1;
    }); },
    (f: ReturnType<typeof releaseFixture>) => { changeReport(f, firstRow(f.bundle.platform), report => { firstTest(report).fullName = 'uncollected substituted source case'; }); },
  ];
  for (const mutate of mutations) { const f = releaseFixture(); mutate(f); expect(await verifyFixture(f), 'authentic report/receipt hashes cannot repair incomplete or duplicated scope').toBe(1); }
});
