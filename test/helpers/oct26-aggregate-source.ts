// Independently collectable synthetic source, not an inventory override. Dev
// tools are ordinary copied files; no node_modules symlink enters the namespace.
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { expect } from 'vitest';
import { asRecord, repoRoot } from './cli.js';
import { REQUIRED_ROWS, type SealFixture } from './oct26-seal-fixture.js';
import { type SourceCase } from './oct26-release-gate.js';

const LAB_CASES: SourceCase[] = [{ file: 'test/lab/aggregate.live.test.ts', name: 'CP-044/AGGREGATE synthetic lab source contract input' }];
const CHAOS_CASES: SourceCase[] = REQUIRED_ROWS.map(id => ({ file: 'test/chaos/contract.live.test.ts', name: `CP-044/SEAL synthetic ${id} contract input` }));
interface Package { name: string; version: string; dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string> }

function copyDevTools(source: string): Record<string, string> {
  const modules = join(repoRoot, 'node_modules'), copied = new Set<string>(), versions: Record<string, string> = {};
  const findPackage = (name: string, start: string): string | undefined => {
    for (let cursor = start; cursor === repoRoot || cursor.startsWith(`${repoRoot}${sep}`); cursor = dirname(cursor)) {
      const candidate = join(cursor, 'node_modules', name);
      if (existsSync(join(candidate, 'package.json'))) return candidate;
    }
    return undefined;
  };
  const copy = (path: string): void => {
    if (copied.has(path)) return;
    copied.add(path);
    const suffix = relative(modules, path);
    if (suffix.startsWith('..')) throw new Error('fixture dev tool must come from the installed repository tools');
    const manifest = JSON.parse(readFileSync(join(path, 'package.json'), 'utf8')) as Package;
    const destination = join(source, 'node_modules', suffix);
    mkdirSync(dirname(destination), { recursive: true });
    cpSync(path, destination, { recursive: true, dereference: true,
      filter: entry => { const part = relative(path, entry); return part !== 'node_modules' && !part.startsWith(`node_modules${sep}`); } });
    versions[suffix.replaceAll('\\', '/')] = manifest.version;
    for (const name of Object.keys({ ...manifest.dependencies, ...manifest.optionalDependencies, ...manifest.peerDependencies })) {
      const dependency = findPackage(name, path);
      if (dependency) copy(dependency);
      else if (manifest.dependencies?.[name] && !manifest.optionalDependencies?.[name]) throw new Error(`installed fixture tool dependency missing: ${name}`);
    }
  };
  for (const name of ['vitest', 'vite']) {
    const path = findPackage(name, repoRoot);
    if (!path) throw new Error(`installed fixture dev tool missing: ${name}`);
    copy(path);
  }
  return versions;
}

export function prepareAggregateSource(source: string, nestedIdentity = false): void {
  const versions = copyDevTools(source);
  const manifest = asRecord(JSON.parse(readFileSync(join(source, 'package.json'), 'utf8')), 'synthetic package');
  const devDependencies = { vitest: versions['vitest'], vite: versions['vite'] };
  manifest['devDependencies'] = devDependencies;
  writeFileSync(join(source, 'package.json'), JSON.stringify(manifest));
  const lock = asRecord(JSON.parse(readFileSync(join(source, 'package-lock.json'), 'utf8')), 'synthetic lock');
  const packages = asRecord(lock['packages'], 'lock packages');
  asRecord(packages[''], 'root package')['devDependencies'] = devDependencies;
  const installed = asRecord(asRecord(JSON.parse(readFileSync(join(repoRoot, 'package-lock.json'), 'utf8')), 'installed lock')['packages'], 'installed packages');
  for (const name of Object.keys(versions)) {
    const key = `node_modules/${name}`;
    const entry = asRecord(installed[key], 'copied dev tool lock entry');
    expect(entry['version'], 'copied fixture dev tools retain the exact installed lock version').toBe(versions[name]);
    packages[key] = entry;
  }
  writeFileSync(join(source, 'package-lock.json'), JSON.stringify(lock));
  writeFileSync(join(source, 'fixture-toolchain.json'), JSON.stringify({ syntheticUnitFixture: true, copiedOrdinaryPackages: versions }));
  for (const [suite, cases] of [['lab', LAB_CASES], ['chaos', CHAOS_CASES]] as const) {
    mkdirSync(join(source, `test/${suite}`), { recursive: true });
    const file = cases[0]?.file;
    if (!file) throw new Error('source-defined synthetic suite must not be empty');
    const titles = cases.map(row => row.name + (nestedIdentity ? ' > literal title' : ''));
    writeFileSync(join(source, file), `// Synthetic unit source only; no native or CI validation claimed.\nimport {describe,expect,it} from 'vitest';\nconst titles=${JSON.stringify(titles)},cases=(names=titles)=>{for(const name of names)it(name,()=>{expect(true).toBe(true);});};\n${nestedIdentity && suite === 'chaos' ? "describe('outer > literal suite',()=>{describe('inner',()=>cases(titles.slice(0,4)));describe('inner',()=>cases(titles.slice(4)));});" : 'cases();'}\n`);
    writeFileSync(join(source, `vitest.${suite}.config.ts`), `import {defineConfig} from 'vitest/config';\nexport default defineConfig({test:{include:['test/${suite}/**/*.test.ts'],allowOnly:false,passWithNoTests:false,maxWorkers:1,fileParallelism:false,testTimeout:180000,hookTimeout:180000}});\n`);
  }
  if (nestedIdentity) {
    // Retain the existing explicitly synthetic observation producer, but obtain
    // report bytes from actual Vitest bodies and the pinned JSON reporter.
    const original = readFileSync(join(source, 'produce.mjs'), 'utf8');
    const tail = original.slice(original.indexOf('for(const id of ids.filter'));
    writeFileSync(join(source, 'produce.mjs'), `import {spawnSync} from 'node:child_process';import {writeFileSync} from 'node:fs';import {join} from 'node:path';\nconst ids=${JSON.stringify(REQUIRED_ROWS)};\nfor(const suite of ['lab','chaos']){const result=spawnSync(process.execPath,['scripts/ci-test-driver.mjs','run','--config','vitest.'+suite+'.config.ts','--reporter=json','--outputFile='+join(process.env.FLUXWARDEN_EVIDENCE_DIR,'vitest-'+suite+'.json')],{env:process.env,stdio:'inherit',timeout:30000});if(result.status!==0)process.exit(result.status??1);}\n${tail}`);
  }
}

export function collectAggregateSource(fixture: Pick<SealFixture, 'source' | 'env' | 'sourceCommit'>, nestedIdentity = false): { lab: SourceCase[]; chaos: SourceCase[] } {
  const result = { lab: [] as SourceCase[], chaos: [] as SourceCase[] };
  for (const [suite, expected] of [['lab', LAB_CASES], ['chaos', CHAOS_CASES]] as const) {
    const path = join(fixture.env['TEMP'] ?? '', `aggregate-source-${suite}.json`);
    const collection = spawnSync(process.execPath, ['scripts/ci-test-driver.mjs', 'list', '--staticParse=false', '--maxWorkers=1', '--fileParallelism=false',
      '--config', join(fixture.source, `vitest.${suite}.config.ts`), `--json=${path}`], {
      cwd: fixture.source, env: fixture.env, windowsHide: true, timeout: 30_000,
    });
    expect(collection.error, 'the source-defined collection retains its bounded child deadline').toBeUndefined();
    expect(collection.status, `${suite} is independently collectable from actual committed source`).toBe(0);
    const rows = JSON.parse(readFileSync(path, 'utf8')) as { file: string; name: string }[];
    result[suite] = rows.map(row => ({ file: relative(fixture.source, row.file).replaceAll('\\', '/'), name: row.name }));
    const order = (rows: SourceCase[]): string[] => rows.map(row => `${row.file}\n${row.name}`).sort();
    const declared = expected.map(row => ({ ...row, name: (nestedIdentity && suite === 'chaos' ? 'outer > literal suite > inner > ' : '') + row.name + (nestedIdentity ? ' > literal title' : '') }));
    expect(order(result[suite]), 'source declarations, collected inventory and producer reports must agree').toEqual(order(declared));
  }
  writeFileSync(join(fixture.env['TEMP'] ?? '', 'aggregate-source-collection.json'), JSON.stringify({ sourceCommit: fixture.sourceCommit, syntheticUnitFixture: true, cases: result }));
  return result;
}
