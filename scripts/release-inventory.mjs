// Vitest's public list command dynamically collects cases without running bodies
// or hooks (vitest-dev/vitest packages/vitest/src/node/cli/list.ts).
import { execFile } from 'node:child_process';
import { readFile, writeFile, rm } from 'node:fs/promises';
import { promisify } from 'node:util';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { tmpdir } from 'node:os';
import { createPrivateDirectory } from './private-scratch.mjs';
const execute = promisify(execFile);
const root = dirname(dirname(fileURLToPath(import.meta.url)));
export const nodes = ['22.23.2', '22.x', '24.18.1', '24.x', '26.5.1', '26.x'];
export const requiredLiveRows = ['T-01', 'T-03', 'T-05', 'T-06', 'T-07', 'T-16', 'T-18', 'T-25'];
// vitest-dev/vitest packages/vitest/src/node/reporters/json.ts preserves
// ancestorTitles/title and space-joins fullName. Its CLI list display uses
// getNames(test).slice(1).join(' > '); literal separators remain title bytes.
export function reportedCaseName(assertion) {
  const safe = value => typeof value === 'string' && [...value].every(character => character.charCodeAt(0) >= 32 && character.charCodeAt(0) !== 127);
  if (!assertion || typeof assertion !== 'object' || Array.isArray(assertion) || !Array.isArray(assertion.ancestorTitles) ||
    !assertion.ancestorTitles.every(safe) || !safe(assertion.title) || !safe(assertion.fullName)) throw new Error('release inventory: original reporter structure required');
  const fullName = assertion.title ? [...assertion.ancestorTitles, assertion.title].join(' ') : assertion.ancestorTitles.join(' ');
  if (assertion.fullName !== fullName) throw new Error('release inventory: original fullName disagrees with reporter structure');
  const displayName = [...assertion.ancestorTitles.filter(title => title !== ''), assertion.title].join(' > ');
  if (!displayName) throw new Error('release inventory: nonempty reported case required');
  return displayName;
}
export function platformJobs() {
  const rows = [];
  for (const os of ['ubuntu-latest', 'windows-latest']) {
    const harness = Array.from({ length: 8 }, (_, i) => `harness-${i + 1}`);
    const shards = os === 'ubuntu-latest' ? ['product-1', 'product-2', ...harness] :
      [...Array.from({ length: 8 }, (_, i) => `core-${i + 1}`), ...harness, 'native-1', 'native-2'];
    for (const node of nodes) for (const shard of shards) rows.push({ os, node, shard, suite: shard.startsWith('harness-') ? 'harness' : 'product', key: `platform/${os}/${node}/${shard}` });
  }
  return rows;
}
export async function deriveInventory(sourceCommit, suites = ['product', 'harness', 'lab', 'chaos']) {
  const options = { cwd: root, windowsHide: true, timeout: 60_000, maxBuffer: 32 * 1024 * 1024 };
  const current = (await execute('git', ['rev-parse', 'HEAD'], options)).stdout.trim();
  const dirty = (await execute('git', ['status', '--porcelain', '--untracked-files=normal'], options)).stdout;
  if (current !== sourceCommit || dirty.trim()) throw new Error('release inventory: clean exact source required');
  const scratch = await createPrivateDirectory(process.env.TEMP ?? tmpdir(), 'release-inventory-');
  try {
    const cases = {};
    for (const suite of suites) {
      const output = join(scratch, `${suite}.json`), args = ['scripts/ci-test-driver.mjs', 'list', '--staticParse=false', '--maxWorkers=1', '--fileParallelism=false'];
      if (suite === 'product' || suite === 'harness') args.push('--project', suite === 'harness' ? 'harness-docs' : suite);
      else {
        const wrapper = join(scratch, `${suite}.config.mjs`), base = pathToFileURL(join(root, `vitest.${suite}.config.ts`)).href;
        await writeFile(wrapper, `import base from ${JSON.stringify(base)}; export default {...base,test:{...base.test,exclude:[]}};\n`, { mode: 0o600, flag: 'wx' });
        args.push('--config', wrapper);
      }
      args.push(`--json=${output}`);
      const env = { ...process.env }; delete env.FLUXWARDEN_REQUIRE_LIVE;
      await execute(process.execPath, args, { ...options, env });
      const collected = JSON.parse(await readFile(output, 'utf8'));
      if (!Array.isArray(collected) || collected.length === 0) throw new Error('release inventory: nonempty dynamic collection required');
      cases[suite] = collected.map(row => ({ file: relative(root, row.file).replaceAll('\\', '/'), name: row.name }));
    }
    return { platformJobs: platformJobs(), cases, requiredLiveRows: [...requiredLiveRows] };
  } finally { await rm(scratch, { recursive: true, force: true }); }
}
