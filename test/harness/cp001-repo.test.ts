// Repository configuration and documentation, checked through public files and commands.
// Expected values follow the public package identity, toolchain, documentation and reporting policy.
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, readFileSync, readdirSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { asRecord, binPath, childEnv, isRecord, readJson, readText, repoRoot, runNpmScript, scratchDir } from '../helpers/cli.js';
import { parseYaml, type Yaml } from '../helpers/yaml.js';

// Toolchain versions recorded from the reference package on 2026-10-11.
const PINS: Record<string, string> = {
  typescript: '6.0.3',
  vitest: '5.0.3',
  vite: '8.3.2',
  eslint: '10.11.0',
  '@eslint/js': '10.0.1',
  'typescript-eslint': '8.71.0',
  '@types/node': '22.20.5',
  globals: '17.13.0',
  ajv: '8.20.0',
};
const ENGINES = '^22.23.2 || ^24.18.1 || >=26.5.1';
const SCRIPT_NAMES = ['test', 'test:harness', 'test:related', 'lint', 'build', 'test:lab', 'test:chaos', 'test:full', 'lab:up', 'lab:down', 'fixtures:record'];
const CHECKOUT = 'actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd';
const SETUP_NODE = 'actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444';

/** JSON with comments and trailing commas (tsconfig.json may use them). */
function parseJsonc(source: string): unknown {
  let out = '';
  for (let i = 0; i < source.length; i += 1) {
    const ch = source.charAt(i);
    if (ch === '"') {
      let j = i + 1;
      while (j < source.length && source.charAt(j) !== '"') j += source.charAt(j) === '\\' ? 2 : 1;
      out += source.slice(i, j + 1);
      i = j;
    } else if (ch === '/' && source.charAt(i + 1) === '/') {
      while (i < source.length && source.charAt(i) !== '\n') i += 1;
      out += '\n';
    } else if (ch === '/' && source.charAt(i + 1) === '*') {
      i = source.indexOf('*/', i + 2) + 1;
    } else {
      out += ch;
    }
  }
  const value: unknown = JSON.parse(out.replace(/,(\s*[}\]])/g, '$1'));
  return value;
}

function map(value: Yaml | undefined, what: string): { [key: string]: Yaml } {
  if (value === undefined || value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${what} is not a mapping`);
  return value;
}

function list(value: Yaml | undefined, what: string): Yaml[] {
  if (!Array.isArray(value)) throw new Error(`${what} is not a sequence`);
  return value;
}

function walkFiles(dir: string, skip: ReadonlySet<string>): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (skip.has(entry)) continue;
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) files.push(...walkFiles(path, skip));
    else files.push(path);
  }
  return files;
}

// Bug caught: a caret range, a runtime dependency, a missing script, a lockfile resolving another
// version, or a tsconfig missing one of the additional strict flags that `strict` does not include.
it('CP-001/B9 package.json, package-lock.json and tsconfig.json carry the exact pins, engines, identity, scripts and additional strict flags', () => {
  const pkg = asRecord(readJson('package.json'), 'package.json');
  expect(pkg['name']).toBe('fluxwarden');
  expect(pkg['license']).toBe('MIT');
  expect(asRecord(pkg['engines'], 'engines')['node']).toBe(ENGINES);
  expect(asRecord(pkg['bin'], 'bin')['fluxwarden']).toMatch(/^(\.\/)?dist\//);
  expect(pkg['devDependencies']).toEqual(PINS);
  for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'bundledDependencies']) {
    const value = pkg[field];
    expect(value === undefined || (isRecord(value) && Object.keys(value).length === 0) || (Array.isArray(value) && value.length === 0), field).toBe(true);
  }
  const scripts = asRecord(pkg['scripts'], 'scripts');
  for (const name of SCRIPT_NAMES) expect(typeof scripts[name], `script ${name}`).toBe('string');

  const lockPackages = asRecord(asRecord(readJson('package-lock.json'), 'package-lock.json')['packages'], 'lock packages');
  const lockRoot = asRecord(lockPackages[''], 'lock root');
  expect(lockRoot['devDependencies']).toEqual(PINS);
  expect(lockRoot['dependencies'] ?? {}).toEqual({});
  for (const [name, version] of Object.entries(PINS)) {
    expect(asRecord(lockPackages[`node_modules/${name}`], `lock ${name}`)['version'], `lock ${name}`).toBe(version);
  }

  const options = asRecord(asRecord(parseJsonc(readText('tsconfig.json')), 'tsconfig')['compilerOptions'], 'compilerOptions');
  for (const flag of ['strict', 'noUncheckedIndexedAccess', 'exactOptionalPropertyTypes', 'noImplicitOverride', 'noImplicitReturns', 'noFallthroughCasesInSwitch', 'noPropertyAccessFromIndexSignature', 'verbatimModuleSyntax']) {
    expect(options[flag], flag).toBe(true);
  }
});

// Bug caught: a missing .gitattributes, an ignore list that lets .ratchet/ or dist/ be committed, a non-MIT licence.
it('CP-001/B10 .gitattributes exists, .gitignore lists the four paths and LICENSE is the MIT text', () => {
  expect(existsSync(join(repoRoot, '.gitattributes'))).toBe(true);
  const ignored = readText('.gitignore').split(/\r?\n/).map(line => line.trim().replace(/^\//, ''));
  for (const entry of ['.ratchet/', 'labs/.runtime/', 'dist/', 'node_modules/']) expect(ignored, entry).toContain(entry);
  const license = readText('LICENSE').replace(/\s+/g, ' ');
  expect(license).toMatch(/^MIT License Copyright \(c\) \d{4} \S/);
  expect(license).toContain('Permission is hereby granted, free of charge, to any person obtaining a copy of this software');
  expect(license).toContain('The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.');
  expect(license).toContain('THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND');
});

// Bug caught: write permissions, an unpinned or tag-pinned action, persisted checkout credentials,
// a missing Windows shard or floor job, tests before build, incomplete or overlapping Windows coverage,
// a no-pending step not reading the active shard's reports,
// a step allowed to fail, or lab jobs running on every push.
it('CP-001/B11 the CI workflow has the triggers, permissions, matrix, pinned actions, step order and dispatch-only lab jobs', () => {
  const wf = map(parseYaml(readText('.github/workflows/ci.yml')), 'workflow');
  const on = map(wf['on'], 'on');
  expect(Object.keys(on).sort()).toEqual(['pull_request', 'push', 'workflow_dispatch']);
  expect(map(on['push'], 'on.push')['branches']).toEqual(['main']);
  expect(wf['permissions']).toEqual({ contents: 'read' });

  const jobs = map(wf['jobs'], 'jobs');
  expect(Object.keys(jobs).sort()).toEqual(['chaos', 'lab', 'test']);
  for (const [name, jobValue] of Object.entries(jobs)) {
    const job = map(jobValue, name);
    if (job['permissions'] !== undefined) expect(job['permissions'], `${name} permissions`).toEqual({ contents: 'read' });
    for (const stepValue of list(job['steps'], `${name}.steps`)) {
      const step = map(stepValue, `${name} step`);
      const uses = step['uses'];
      if (typeof uses !== 'string') continue;
      expect(uses, `${name} uses`).toMatch(/^[^@\s]+@[0-9a-f]{40}$/);
      if (uses.startsWith('actions/checkout@')) {
        expect(uses).toBe(CHECKOUT);
        expect(map(step['with'], 'checkout.with')['persist-credentials'], `${name} persist-credentials`).toBe(false);
      }
      if (uses.startsWith('actions/setup-node@')) expect(uses).toBe(SETUP_NODE);
    }
  }

  // Matrix, expanded as GitHub does: the product of the keys, then `include` entries.
  const test = map(jobs['test'], 'jobs.test');
  expect(test['timeout-minutes']).toBe('30');
  const strategy = map(test['strategy'], 'strategy');
  expect(strategy['fail-fast']).toBe(false);
  const matrix = map(strategy['matrix'], 'matrix');
  let combos: Record<string, string>[] = [{}];
  for (const [key, values] of Object.entries(matrix)) {
    if (key === 'include' || key === 'exclude') continue;
    combos = combos.flatMap(c => list(values, key).map(v => ({ ...c, [key]: String(v) })));
  }
  const baseKeys = Object.keys(matrix).filter(k => k !== 'include' && k !== 'exclude');
  for (const ex of matrix['exclude'] === undefined ? [] : list(matrix['exclude'], 'exclude')) {
    const e = map(ex, 'exclude entry');
    combos = combos.filter(c => !Object.entries(e).every(([k, v]) => c[k] === String(v)));
  }
  for (const inc of matrix['include'] === undefined ? [] : list(matrix['include'], 'include')) {
    const entry = Object.fromEntries(Object.entries(map(inc, 'include entry')).map(([k, v]) => [k, String(v)]));
    const matching = combos.filter(c => baseKeys.every(k => entry[k] === undefined || entry[k] === c[k]));
    if (matching.length > 0 && Object.keys(entry).some(k => !baseKeys.includes(k))) matching.forEach(c => Object.assign(c, entry));
    else if (matching.length === 0 || baseKeys.every(k => entry[k] !== undefined)) combos.push(entry);
  }
  const steps = list(test['steps'], 'test.steps').map(s => map(s, 'test step'));
  const setupNode = steps.find(s => s['uses'] === SETUP_NODE);
  const nodeVersionExpr = String(map(setupNode?.['with'], 'setup-node.with')['node-version']);
  const subst = (expr: string, c: Record<string, string>): string => expr.replace(/\$\{\{\s*matrix\.([\w-]+)\s*\}\}/g, (_m, k: string) => c[k] ?? '<unset>');
  const runsOn = String(test['runs-on']);
  expect(combos.map(c => `${subst(runsOn, c)} ${subst(nodeVersionExpr, c)} ${c['shard'] ?? '<unset>'} ${c['coreShard'] ?? '<unset>'}`).sort()).toEqual([
    'ubuntu-latest 22.23.2 core <unset>', 'ubuntu-latest 22.x core <unset>', 'ubuntu-latest 24.18.1 core <unset>', 'ubuntu-latest 24.x core <unset>',
    'windows-latest 22.23.2 core-1 1/2', 'windows-latest 22.23.2 core-2 2/2', 'windows-latest 22.23.2 native <unset>',
    'windows-latest 24.x core-1 1/2', 'windows-latest 24.x core-2 2/2', 'windows-latest 24.x native <unset>',
  ]);

  // CI step order: checkout, setup-node, npm ci, lint, build, product, harness, no-pending.
  const kind = (s: { [key: string]: Yaml }): string | null => {
    const uses = s['uses'];
    if (uses === CHECKOUT) return 'checkout';
    if (uses === SETUP_NODE) return 'setup-node';
    const run = typeof s['run'] === 'string' ? s['run'].trim() : '';
    if (/^npm ci(\s|$)/.test(run)) return 'npm ci';
    if (/^npm run lint(\s|$)/.test(run)) return 'lint';
    if (/^npm run build(\s|$)/.test(run)) return 'build';
    if (/^npm (run )?test(\s|$)/.test(run)) return 'product';
    if (/^npm run test:harness(\s|$)/.test(run)) return 'harness';
    if (/^node scripts\//.test(run)) return 'no-pending';
    return null;
  };
  const active = (step: { [key: string]: Yaml }, combo: Record<string, string>): boolean => {
    if (step['if'] === undefined) return true;
    const condition = String(step['if']).trim().replace(/^\$\{\{\s*|\s*\}\}$/g, '');
    return condition.split(/\s*\|\|\s*/).some(alternative => alternative.split(/\s*&&\s*/).every(term => {
      const equal = /^matrix\.(os|shard) == '([^']+)'$/.exec(term);
      if (equal) return combo[equal[1] ?? ''] === equal[2];
      const prefix = /^startsWith\(matrix\.(os|shard), '([^']+)'\)$/.exec(term);
      if (prefix) return (combo[prefix[1] ?? ''] ?? '').startsWith(prefix[2] ?? '');
      throw new Error(`unsupported CI shard condition: ${condition}`);
    }));
  };
  for (const s of steps.filter(s => kind(s) !== null)) {
    if (['checkout', 'setup-node', 'npm ci', 'lint', 'build'].includes(kind(s) ?? '')) {
      expect(s['if'], `${String(kind(s))} must not be conditional`).toBeUndefined();
    }
    expect(s['continue-on-error'], `${String(kind(s))} must not be allowed to fail`).toBeUndefined();
  }
  const reportOf = (ordered: { [key: string]: Yaml }[], k: string): string => {
    const run = String(ordered.find(s => kind(s) === k)?.['run']);
    expect(run, `${k} uses a JSON reporter`).toMatch(/--reporter[= ]json\b/);
    const file = /--outputFile(?:\.json)?[= ](\S+)/.exec(run)?.[1];
    if (file === undefined) throw new Error(`${k} names no JSON output file`);
    return file.replace(/^["']|["']$/g, '');
  };
  for (const combo of combos) {
    const ordered = steps.filter(s => kind(s) !== null && active(s, combo));
    const windows = combo['os'] === 'windows-latest';
    const core = combo['shard'] === 'core' || combo['shard'] === 'core-1' || combo['shard'] === 'core-2';
    const harness = combo['shard'] === 'core' || combo['shard'] === 'core-1';
    expect(ordered.map(kind), JSON.stringify(combo)).toEqual([
      'checkout', 'setup-node', 'npm ci', 'lint', 'build', 'product', ...(harness ? ['harness'] : []), 'no-pending',
    ]);
    const productRun = String(ordered.find(s => kind(s) === 'product')?.['run']);
    expect(productRun, 'no title or additional subset filtering').not.toMatch(/--(?:testNamePattern|exclude|include|dir|project|changed|related)\b|(?:^|\s)-t(?:\s|$)/);
    expect(productRun.match(/--maxWorkers(?:=|\s+)\S+/g), 'bounded worker allocation').toEqual([`--maxWorkers=${windows ? '1' : '2'}`]);
    if (windows) expect(productRun.match(/--fileParallelism(?:=|\s+)\S+/g), 'Windows files run serially').toEqual(['--fileParallelism=false']);
    if (windows && core) {
      expect(productRun.match(/--shard\b/g), 'one explicit Windows core shard').toHaveLength(1);
      expect(productRun).toContain('--shard=${{ matrix.coreShard }}');
      expect(subst(productRun, combo)).toContain(`--shard=${combo['coreShard'] ?? '<unset>'}`);
    } else {
      expect(productRun).not.toMatch(/--shard\b/);
      expect(productRun).not.toMatch(/--config\b/);
    }
    const noPending = String(ordered.find(s => kind(s) === 'no-pending')?.['run']);
    expect(noPending).toMatch(/^node scripts\/no-pending\.mjs\s/);
    expect(noPending).toContain(reportOf(ordered, 'product'));
    if (harness) expect(noPending).toContain(reportOf(ordered, 'harness'));
    else expect(noPending).not.toContain('vitest-harness.json');
  }

  // Approved Windows split: the native commands and the generated core configuration must partition
  // the complete product file inventory. Use Vitest's public listing command, without running product tests.
  const nativeFiles = [
    'test/labs/cp006-cp008-owner-lifecycle.test.ts',
    'test/persistence/cp015-concurrency.test.ts',
    'test/chaos/t01-t12.test.ts',
    'test/cli/cp038-reconcile-evidence.test.ts',
    'test/commands/cp043-driver.test.ts',
    'test/executor/cp029-preflight.test.ts',
    'test/output/cp003-output.test.ts',
    'test/persistence/cp015-command-data-readonly.test.ts',
    'test/persistence/cp015-persistence.test.ts',
    'test/daemon/cp041-daemon.test.ts',
    'test/ledger/cp037-ledger.test.ts',
    'test/commands/cp043-t05-repository.test.ts',
  ];
  const coreCombo = combos.find(c => c['os'] === 'windows-latest' && c['shard'] === 'core-1');
  const nativeCombo = combos.find(c => c['os'] === 'windows-latest' && c['shard'] === 'native');
  if (!coreCombo || !nativeCombo) throw new Error('both Windows shards are required');
  const coreProduct = steps.find(s => kind(s) === 'product' && active(s, coreCombo));
  const nativeProduct = steps.find(s => kind(s) === 'product' && active(s, nativeCombo));
  const nativeArgs = String(nativeProduct?.['run']).match(/\btest\/[\w./-]+\.test\.ts\b/g) ?? [];
  expect(nativeArgs).toEqual(nativeFiles);
  const configuration = steps.filter(s => active(s, coreCombo)).find(s => typeof s['run'] === 'string' && s['run'].includes('FLUXWARDEN_CI_CORE_CONFIG='));
  expect(configuration).toBeDefined();
  if (configuration === undefined || coreProduct === undefined) throw new Error('core configuration and product steps are required');
  expect(configuration['continue-on-error']).toBeUndefined();
  expect(steps.indexOf(configuration), 'configure core before running it').toBeLessThan(steps.indexOf(coreProduct));
  const configurationSource = /<<'NODE'\s*\n([^]*?)\nNODE\s*$/.exec(String(configuration['run']))?.[1];
  if (configurationSource === undefined) throw new Error('core configuration preparation is missing');
  const scratch = scratchDir('ci-shard-config'), githubEnv = join(scratch, 'github-env');
  const configured = spawnSync(process.execPath, ['--input-type=module'], {
    cwd: repoRoot, env: { ...childEnv(), RUNNER_TEMP: scratch, GITHUB_ENV: githubEnv }, input: configurationSource,
    encoding: 'utf8', windowsHide: true, timeout: 10000,
  });
  expect(configured.error).toBeUndefined();
  expect(configured.status, configured.stderr).toBe(0);
  const coreConfig = /^FLUXWARDEN_CI_CORE_CONFIG=(.+)$/m.exec(readFileSync(githubEnv, 'utf8'))?.[1];
  if (coreConfig === undefined) throw new Error('core configuration path was not published');
  expect(dirname(coreConfig)).toBe(scratch);
  expect(String(coreProduct['run'])).toContain('--config="$FLUXWARDEN_CI_CORE_CONFIG"');
  const productFiles = (args: readonly string[] = []): string[] => {
    const outputFile = join(scratchDir('ci-product-files'), 'inventory.json');
    const result = spawnSync(process.execPath, [join(repoRoot, 'node_modules', 'vitest', 'vitest.mjs'),
      'list', '--project', 'product', '--filesOnly', ...args, `--json=${outputFile}`], {
      cwd: repoRoot, env: childEnv(), encoding: 'utf8', windowsHide: true, timeout: 10000,
    });
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    const files: unknown = JSON.parse(readFileSync(outputFile, 'utf8'));
    if (!Array.isArray(files)) throw new Error('product file inventory is not a list');
    return files.map(value => {
      const file = asRecord(value, 'product file');
      expect(file['projectName']).toBe('product');
      if (typeof file['file'] !== 'string') throw new Error('product file path is missing');
      return relative(repoRoot, file['file']).replace(/\\/g, '/');
    }).sort();
  };
  const complete = productFiles(), coreFiles = productFiles(['--config', coreConfig]), native = productFiles(nativeArgs);
  // `list --filesOnly` lists eligible files without applying execution sharding.
  // Exercise the pinned public sequencer over that inventory instead.
  const partition = spawnSync(process.execPath, ['--input-type=module'], {
    cwd: repoRoot, env: { ...childEnv(), CI_CORE_FILES: JSON.stringify(coreFiles) },
    input: `import { BaseSequencer } from 'vitest/node';
const files = JSON.parse(process.env.CI_CORE_FILES).map(moduleId => ({ moduleId }));
const groups = await Promise.all([1, 2].map(index => new BaseSequencer({ config: { root: process.cwd(), shard: { index, count: 2 } } }).shard(files)));
console.log(JSON.stringify({ first: groups[0].map(file => file.moduleId), second: groups[1].map(file => file.moduleId) }));`,
    encoding: 'utf8', windowsHide: true, timeout: 10000,
  });
  expect(partition.error).toBeUndefined();
  expect(partition.status, partition.stderr).toBe(0);
  const partitions = asRecord(JSON.parse(partition.stdout), 'core file partitions');
  const shardFiles = (key: string): string[] => {
    const files = partitions[key];
    if (!Array.isArray(files)) throw new Error('core partition is not a file list');
    return files.map((file: unknown) => {
      if (typeof file !== 'string') throw new Error('core partition file is not a path');
      return file;
    });
  };
  const firstCore = shardFiles('first'), secondCore = shardFiles('second');
  expect(complete.length).toBeGreaterThan(nativeFiles.length);
  expect(native).toEqual([...nativeFiles].sort());
  expect(firstCore.length).toBeGreaterThan(0);
  expect(secondCore.length).toBeGreaterThan(0);
  expect(firstCore.filter(file => secondCore.includes(file)), 'Windows core shards are disjoint').toEqual([]);
  expect([...firstCore, ...secondCore].sort(), 'Windows core shards cover the complete core inventory').toEqual(coreFiles);
  expect(coreFiles.filter(file => native.includes(file)), 'Windows shards are disjoint').toEqual([]);
  expect([...coreFiles, ...native].sort(), 'Windows shards cover the complete product inventory').toEqual(complete);

  for (const [name, script] of [['lab', 'test:lab'], ['chaos', 'test:chaos']] as const) {
    const job = map(jobs[name], name);
    expect(job['timeout-minutes'], `${name} bounded duration`).toBe('60');
    expect(job['runs-on'], `${name} runs-on`).toBe('ubuntu-latest');
    expect(job['strategy'], `${name} has no matrix`).toBeUndefined();
    expect(String(job['if']).replace(/\s+/g, ' '), `${name} if`).toMatch(/^(\$\{\{ )?github\.event_name == 'workflow_dispatch'( \}\})?$/);
    const runs = list(job['steps'], `${name}.steps`).map(s => map(s, 'step')['run']).filter((r): r is string => typeof r === 'string');
    // Chaos may request real reporter output for its scanned artifact. Keep the
    // exact npm script identity; only reporter/output arguments may follow it.
    const invocation = script === 'test:chaos'
      ? /^npm run test:chaos(?:\s+--)?(?:\s+--(?:reporter|outputFile(?:\.json)?)(?:=|\s+)(?:"[^"\r\n]+"|'[^'\r\n]+'|[^\s]+))*$/
      : /^npm run test:lab$/;
    expect(runs.some(r => invocation.test(r.trim()) && !/[;&|`\r\n]/.test(r.trim())), `${name} runs npm run ${script}`).toBe(true);
  }
});

const DOCUMENT_FILES = ['README.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md', 'LICENSE', 'NOTICE-SOURCE-REUSE.md', 'docs/spec.md', 'docs/architecture.md', 'docs/security-model.md', 'docs/references.md', 'docs/references/failure-catalogue.md', 'docs/source-provenance.json'];
const DOCUMENT_DIRS = ['docs/runbooks', 'docs/decisions'];

// Bug caught: a missing document or empty directory, a placeholder without its public purpose,
// or a SECURITY.md that sends reports to public issues.
it('CP-001/B12 the public documents exist, placeholders name their purpose, SECURITY.md routes reports to advisories', () => {
  for (const file of DOCUMENT_FILES) expect(existsSync(join(repoRoot, file)) && statSync(join(repoRoot, file)).isFile(), file).toBe(true);
  const dirFiles = DOCUMENT_DIRS.flatMap(dir => {
    const files = existsSync(join(repoRoot, dir)) ? walkFiles(join(repoRoot, dir), new Set()) : [];
    expect(files.length, `${dir} holds at least one file`).toBeGreaterThan(0);
    return files.map(f => relative(repoRoot, f).replace(/\\/g, '/'));
  });
  const purposes: Record<string, RegExp> = {
    'NOTICE-SOURCE-REUSE.md': /source (code )?(reuse|adapted)|code adapted/i,
    'docs/spec.md': /specification/i,
    'docs/architecture.md': /architecture/i,
    'docs/security-model.md': /security model/i,
    'docs/references.md': /external facts|references/i,
    'docs/references/failure-catalogue.md': /catalogue of failures|failure catalogue/i,
    'docs/source-provenance.json': /provenance of source code|source provenance/i,
  };
  for (const [file, purpose] of Object.entries(purposes)) expect(readText(file), `${file} names its public purpose`).toMatch(purpose);
  for (const file of dirFiles) {
    expect(readText(file), `${file} names its public purpose`).toMatch(file.startsWith('docs/runbooks/') ? /runbook|recovery|troubleshoot/i : /architecture decision|decision record/i);
  }
  expect(() => { JSON.parse(readText('docs/source-provenance.json')); }).not.toThrow();

  // SECURITY.md §6.3: private report through GitHub security advisories of ZilverZtream/fluxwarden,
  // and no real credential in the report.
  const security = readText('SECURITY.md').replace(/\s+/g, ' ');
  expect(security).toContain('ZilverZtream/fluxwarden');
  expect(security).toMatch(/security advisor(y|ies)/i);
  expect(security).toMatch(/(do not|don't|never)[^.]*\breal credential/i);
});

// Public positioning: README.md (which holds the positioning paragraph) and
// CONTRIBUTING.md contain none of the phrases "the first", "the only", "first-of-its-kind" or the word
// "unique", case-insensitive. Specification documents are not subject to this rule.
const FORBIDDEN_WORDING = [/\bthe\s+first\b/i, /\bthe\s+only\b/i, /\bfirst-of-its-kind\b/i, /\bunique\b/i];
const forbiddenHit = (text: string): string | undefined => {
  for (const pattern of FORBIDDEN_WORDING) {
    const hit = pattern.exec(text);
    if (hit !== null) return hit[0];
  }
  return undefined;
};

// Bug caught: a superlative ("the first", "the only", "first-of-its-kind", "unique") in README.md or
// CONTRIBUTING.md, in any letter case or with a line break inside the phrase.
it('CP-001/B12 README.md and CONTRIBUTING.md contain none of the forbidden superlative phrases', () => {
  // The rule itself, on literals: one negative literal per phrase; the bare words stay allowed.
  expect(forbiddenHit('FluxWarden is The First rebalancer')).toBe('The First');
  expect(forbiddenHit('it is THE\nonly tool')).toBe('THE\nonly');
  expect(forbiddenHit('a First-of-its-kind controller')).toBe('First-of-its-kind');
  expect(forbiddenHit('a Unique design')).toBe('Unique');
  expect(forbiddenHit('regtest only; first run; uniquely named')).toBeUndefined();
  for (const doc of ['README.md', 'CONTRIBUTING.md']) {
    expect(forbiddenHit(readText(doc)), `${doc} contains a forbidden phrase`).toBeUndefined();
  }
});

// CI rejects reports that contain tests without a passing result. Fixtures under test/fixtures/no-pending/ follow
// the report shape of Vitest 5.0.3's JSON reporter (testResults[].assertionResults[].status, one of
// passed, failed, skipped, pending, todo).
// Bug caught: a check that only rejects failed tests (skipped or todo pass CI), that accepts a test file
// which failed to load (no assertion results), an empty or missing report, a call without reports, or
// that reads only the first report it is given.
it('CP-001/B11 scripts/no-pending.mjs exits 1 for a skipped, todo or failed test, a file without results, no tests, a missing report or no argument, and 0 when all passed', () => {
  const fixture = (name: string): string => join(repoRoot, 'test', 'fixtures', 'no-pending', name);
  const noPending = (reports: readonly string[]): number | null => spawnSync(process.execPath, [join(repoRoot, 'scripts', 'no-pending.mjs'), ...reports], {
    cwd: repoRoot, encoding: 'utf8', windowsHide: true, timeout: 30000,
  }).status;
  const passed = [fixture('all-passed-a.json'), fixture('all-passed-b.json')];
  expect(noPending(passed), 'two reports, every test passed').toBe(0);
  const rejected: [string, string[]][] = [
    ['a skipped test', [fixture('skipped.json')]],
    ['a todo test', [fixture('todo.json')]],
    ['a failed test', [fixture('failed.json')]],
    ['a test file with no assertion results', [fixture('file-without-results.json')]],
    ['a report with no tests', [fixture('no-tests.json')]],
    ['a missing report file', [fixture('does-not-exist.json')]],
    ['no argument', []],
    ['a skipped test in the second report', [...passed, fixture('skipped.json')]],
  ];
  for (const [name, reports] of rejected) expect(noPending(reports), name).toBe(1);
});

// Decision D40: lab availability advances at CP-006; later capabilities keep their exact refusal.
const LATER = ['test:full'];
// Bug caught: an unavailable script exiting 0, writing stdout, or printing an inconsistent message.
it.each(LATER)('CP-001/B13 npm run %s exits 1 with the exact unavailable-capability stderr line and no stdout', script => {
  const r = runNpmScript(script);
  expect(r.status).toBe(1);
  expect(r.stdout).toBe('');
  const lines = r.stderr.replace(/\r?\n$/, '').split(/\r?\n/);
  expect(lines).toHaveLength(1);
  expect(lines[0]).toBe('fluxwarden: this capability is not yet available');
}, 60000);

// D40 public CLI contract: missing owner is refused before Docker, with a safe owner diagnostic.
// Bug caught: leaving the unavailable stub in place, accepting no owner, or contacting Docker first.
it.each(['lab:up', 'lab:down'])('CP-006/B6 npm run %s without an owner refuses before any Docker invocation', async script => {
  const base = process.env['FLUXWARDEN_TEST_TMP'];
  const npmCli = process.env['npm_execpath'];
  if (!base || !npmCli || !/npm-cli\.js$/.test(npmCli)) throw new Error('private temporary root and npm CLI are required');
  const scratch = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as {
    createPrivateDirectory(parent: string, prefix: string): Promise<string>;
  };
  const root = await scratch.createPrivateDirectory(base, 'docker-guard-');
  const marker = join(root, 'invoked.txt');
  const guard = join(root, 'guard.cjs');
  const executable = join(root, process.platform === 'win32' ? 'docker.exe' : 'docker');
  const env: NodeJS.ProcessEnv = Object.fromEntries(Object.entries(childEnv()).filter(([key]) => key.toLowerCase() !== 'path'));
  // A real controlled executable replaces Docker on PATH; its preload only acts when that
  // executable runs. No production imports or child-process calls are mocked.
  if (process.platform === 'win32') {
    copyFileSync(process.execPath, executable);
    writeFileSync(guard, `if (require('node:path').basename(process.execPath).toLowerCase() === 'docker.exe') { require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'invoked'); process.exit(97); }\n`);
    env['NODE_OPTIONS'] = `--require ${JSON.stringify(guard)}`;
  } else {
    writeFileSync(executable, `#!${process.execPath}\nimport { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'invoked'); process.exit(97);\n`, { mode: 0o700 });
  }
  env['PATH'] = [root, dirname(process.execPath), ...(process.platform === 'win32' ? [join(process.env['SystemRoot'] ?? 'C:\\Windows', 'System32')] : ['/bin', '/usr/bin'])].join(process.platform === 'win32' ? ';' : ':');
  try {
    const control = spawnSync(executable, ['compose', 'version'], { env, encoding: 'utf8', windowsHide: true, timeout: 10000 });
    expect(control.error).toBeUndefined();
    expect(control.status, 'the controlled Docker executable must detect an invocation').toBe(97);
    expect(existsSync(marker)).toBe(true);
    unlinkSync(marker);
    const result = spawnSync(process.execPath, [npmCli, 'run', '--silent', script], {
      cwd: repoRoot, env, encoding: 'utf8', windowsHide: true, timeout: 10000,
    });
    expect(result.error).toBeUndefined();
    expect(existsSync(marker), 'no Docker invocation without an owner').toBe(false);
    expect(result.status).toBe(1);
    expect(result.stdout).toBe('');
    expect(result.stderr).toMatch(/\bowner\b/i);
    expect(result.stderr).toMatch(/\brequir(?:e|ed|es|ement)\b|\bmissing\b|\bneeded\b|--owner|\bmust\b|\bprovide\b/i);
    expect(result.stderr).not.toMatch(/^\s+at\s/m);
  } finally {
    // Remove only this fixture's executable copy before artifact scanning.
    unlinkSync(executable);
  }
});

// Bug caught: repository-only files left in the checkout or shipped in the package, an empty
// package, or a package containing the executable while omitting its compiled runtime modules.
it('CP-001/B14 the package includes the complete built runtime and essential public files within its public allowlist', () => {
  const npmCli = process.env['npm_execpath'];
  if (npmCli === undefined || !/npm-cli\.js$/.test(npmCli)) throw new Error('npm CLI path is required to inspect the package');
  const packed = spawnSync(process.execPath, [npmCli, 'pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: repoRoot, env: childEnv(), shell: false, encoding: 'utf8', windowsHide: true, timeout: 60000,
  });
  if (packed.error !== undefined) throw packed.error;
  expect(packed.status, 'npm pack dry-run succeeds').toBe(0);
  const value: unknown = JSON.parse(packed.stdout);
  expect(Array.isArray(value), 'npm pack returns a manifest list').toBe(true);
  if (!Array.isArray(value) || value.length !== 1) throw new Error('npm pack must return exactly one manifest');
  const files = asRecord(value[0], 'package manifest')['files'];
  if (!Array.isArray(files)) throw new Error('package manifest has no file list');
  const paths = files.map((file: unknown) => {
    const path = asRecord(file, 'package file')['path'];
    if (typeof path !== 'string') throw new Error('package file has no path');
    return path;
  });
  const executable = relative(repoRoot, binPath()).replace(/\\/g, '/');
  const runtime = walkFiles(join(repoRoot, 'dist'), new Set()).filter(file => file.endsWith('.js')).map(file => relative(repoRoot, file).replace(/\\/g, '/'));
  expect(runtime.length, 'compiled executable and runtime modules exist').toBeGreaterThan(1);
  expect(runtime, 'executable is compiled JavaScript').toContain(executable);
  for (const file of [executable, 'README.md', 'package.json', 'LICENSE', ...runtime]) expect(paths, `${file} is packaged`).toContain(file);
  const publicFiles = new Set(['README.md', 'SECURITY.md', 'LICENSE', 'CHANGELOG.md', 'package.json']);
  for (const path of paths) {
    expect(publicFiles.has(path) || /^dist\/.+/.test(path), `${path} belongs to the public package`).toBe(true);
    expect(path, 'package excludes local files').not.toMatch(/^(?:\.ratchet\/|tools\/validation\/schemas\/|CLAUDE\.local\.md$|fluxwarden\.md$)/);
  }
  expect(existsSync(join(repoRoot, 'tools', 'validation', 'schemas')), 'repository excludes local validation schema copies').toBe(false);
}, 60000);

it('CP-009/B4 npm run fixtures:record without an owner is a usage refusal, not the unavailable stub', () => {
  const r = runNpmScript('fixtures:record');
  expect(r.status).toBe(2);
  expect(r.stdout).toBe('');
  expect(r.stderr).not.toContain('this capability is not yet available');
});
