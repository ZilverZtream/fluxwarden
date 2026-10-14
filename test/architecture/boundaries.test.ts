import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';
import { boundaryCases, bypassCases } from './cases.js';
import { checkBoundaries, checkBoundarySources } from './check.js';
import { lintBoundary, repositoryLint, technicalMessage } from './lint.js';

it('CP-005/B1 independent parser reports forbidden placements and preserves permitted module operations', () => {
  for (const example of boundaryCases) {
    const found = checkBoundaries(example.path, example.source);
    if (example.allowed) expect.soft(found, `${example.name} in ${example.path}`).toEqual([]);
    else expect.soft(found.some(hit => hit.boundary === example.boundary), `${example.name} in ${example.path}: ${example.boundary}`).toBe(true);
  }
});

it('CP-005/B1 ESLint reports forbidden placements and preserves permitted module operations', async () => {
  for (const example of boundaryCases) {
    const result = await lintBoundary(example);
    const name = `${example.name} in ${example.path}`;
    expect.soft(result.fatal, `${name}: valid syntax`).toBe(0);
    expect.soft(result.ignored, `${name}: selected`).toBe(false);
    if (example.allowed) expect.soft(result.messages, name).toEqual([]);
    else {
      expect.soft(result.messages.length, name).toBeGreaterThan(0);
      expect.soft(result.messages.some(message => technicalMessage.test(message)), `${name}: technical diagnostic`).toBe(true);
    }
  }
});

it('CP-005/B4 independent parser rejects computed loading and indirect forbidden APIs while allowing literal adapter imports', () => {
  for (const example of bypassCases) {
    const found = checkBoundaries(example.path, example.source);
    if (example.allowed) expect.soft(found, example.name).toEqual([]);
    else expect.soft(found.some(hit => hit.boundary === example.boundary), example.name).toBe(true);
  }
});

it('CP-005/B4 ESLint rejects computed loading and indirect forbidden APIs while allowing literal adapter imports', async () => {
  for (const example of bypassCases) {
    const result = await lintBoundary(example);
    expect.soft(result.fatal, `${example.name}: valid syntax`).toBe(0);
    expect.soft(result.ignored, `${example.name}: selected`).toBe(false);
    if (example.allowed) expect.soft(result.messages, example.name).toEqual([]);
    else expect.soft(result.messages.some(message => technicalMessage.test(message)), example.name).toBe(true);
  }
});

function sourceFiles(directory: string): string[] {
  return readdirSync(directory).flatMap(name => {
    const file = join(directory, name);
    const info = lstatSync(file);
    if (info.isSymbolicLink()) throw new Error('source inventory refuses symbolic links');
    return info.isDirectory() ? sourceFiles(file) : /\.(?:[cm]?[jt]s|[jt]sx)$/.test(name) ? [file] : [];
  });
}

it('CP-005/B1 batched parser keeps global API checks independent of declarations in other source files', () => {
  const sources = [
    { path: 'src/planner/local.ts', source: 'declare const fetch: () => void; fetch(); declare const console: { log: () => void }; console.log();' },
    { path: 'src/planner/global.ts', source: 'fetch();\nconsole.log();' },
    { path: 'src/node-lnd/global.ts', source: 'fetch();' },
  ];
  const verdicts = checkBoundarySources(sources);
  expect([...verdicts.keys()]).toEqual(sources.map(({ path }) => path));
  expect(verdicts.get('src/planner/local.ts')).toEqual([]);
  expect(verdicts.get('src/planner/global.ts')).toEqual([{ boundary: 'network', line: 1 }, { boundary: 'output', line: 2 }]);
  expect(verdicts.get('src/node-lnd/global.ts')).toEqual([]);
  for (const { path, source } of sources) expect(verdicts.get(path), path).toEqual(checkBoundaries(path, source));
});

const files = sourceFiles(join(repoRoot, 'src'));
const sources = files.map(file => ({ path: relative(repoRoot, file).replace(/\\/g, '/'), source: readFileSync(file, 'utf8') }));

it('CP-005/B1 every repository source file passes the independent parser', () => {
  expect(files.length, 'nonempty independent source inventory').toBeGreaterThan(0);
  const verdicts = checkBoundarySources(sources);
  expect([...verdicts.keys()].sort(), 'every source has an independent verdict').toEqual(sources.map(({ path }) => path).sort());
  for (const { path } of sources) expect.soft(verdicts.get(path), path).toEqual([]);
});

// Each module receives the full typed lint configuration using the same project service.
// Smaller batches release lint results promptly and avoid retaining all reports at once.
const areas = [...new Set(sources.map(({ path }) => path.split('/')[1] ?? ''))];
it.each(areas)('CP-005/B1 every repository source file in %s passes ESLint', async area => {
  const selected = files.filter((_, index) => sources[index]?.path.split('/')[1] === area);
  expect(selected.length, 'nonempty module inventory').toBeGreaterThan(0);
  const reports = await repositoryLint.lintFiles(selected);
  expect(reports.map(report => report.filePath).sort(), 'every source has a verdict').toEqual([...selected].sort());
  for (const report of reports) {
    expect.soft(report.fatalErrorCount, report.filePath).toBe(0);
    expect.soft(report.messages.filter(message => message.severity === 2), report.filePath).toEqual([]);
    expect.soft(report.messages.some(message => /ignored|no matching configuration/i.test(message.message)), report.filePath).toBe(false);
  }
});
