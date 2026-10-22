// Repository configuration and documentation, checked through public files and commands.
// Expected values follow the public package identity, toolchain, documentation and reporting policy.
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { asRecord, binPath, childEnv, isRecord, readJson, readText, repoRoot, runNpmScript, scratchDir } from '../helpers/cli.js';
import { parseYaml, type Yaml } from '../helpers/yaml.js';
import { ownedCaptureToolArgs } from '../helpers/capture-fixture.js';

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
  const scalar = (expression: string, combo: Record<string, string>): string => {
    const direct = /^\s*matrix\.([\w-]+)\s*$/.exec(expression);
    const choice = /^\s*matrix\.([\w-]+)\s*==\s*'((?:[^']|'')*)'\s*&&\s*'((?:[^']|'')*)'\s*\|\|\s*'((?:[^']|'')*)'\s*$/.exec(expression);
    const property = direct?.[1] ?? choice?.[1];
    const value = property === undefined ? undefined : combo[property];
    if (value === undefined) throw new Error(`unsupported CI scalar expression: ${expression}`);
    if (direct) return value;
    if (!choice) throw new Error(`unsupported CI scalar choice: ${expression}`);
    const literal = (index: number): string => (choice[index] ?? '').replace(/''/g, "'");
    return (value === literal(2) ? literal(3) : '') || literal(4);
  };
  const subst = (expr: string, c: Record<string, string>): string => expr.replace(/\$\{\{\s*([^{}]+?)\s*\}\}/g,
    (_match, expression: string) => scalar(expression, c));
  const runsOn = String(test['runs-on']);
  const linuxVersions = ['22.23.2', '22.x', '24.18.1', '24.x'];
  const windowsVersions = ['22.23.2', '24.x'];
  // D29 Windows budget repair: three core-product and two harness shards,
  // plus the original native job, for each original Windows Node version.
  expect(combos).toHaveLength(28);
  expect(combos.length + Object.keys(jobs).length - 1, 'dispatch retains all thirty independent jobs').toBe(30);
  expect(combos.filter(c => subst(runsOn, c) === 'ubuntu-latest').map(c => subst(nodeVersionExpr, c)).sort())
    .toEqual(linuxVersions.flatMap(version => [version, version, version, version]).sort());
  expect(combos.filter(c => subst(runsOn, c) === 'windows-latest')
    .map(c => `${subst(nodeVersionExpr, c)} ${c['shard'] ?? '<unset>'}`).sort()).toEqual(windowsVersions.flatMap(version =>
      ['core-1', 'core-2', 'core-3', 'harness-1', 'harness-2', 'native'].map(shard => `${version} ${shard}`)).sort());

  const captureCommand = (run: string): string => run.replace(
    /^node scripts\/ci-capture\.mjs --root "\$PWD" --capture-dir "\$FLUXWARDEN_CI_CAPTURE_DIR" -- /, '');
  const jobPrefix = /^node scripts\/ci-job\.mjs(?: --commands-only)? -- /;
  const commandsOf = (step: { [key: string]: Yaml }): string[] => captureCommand(typeof step['run'] === 'string' ? step['run'].trim() : '')
    .replace(jobPrefix, '').split(/\s+--next\s+/);
  const commandOf = (step: { [key: string]: Yaml }): string => {
    const commands = commandsOf(step);
    return commands.find(command => /^npm (?:test\s|run test:harness(?:\s|$))/.test(command)) ?? commands[0] ?? '';
  };
  // Product, optional harness and no-pending remain ordered inside the finite
  // job invocation. Its public command is exercised below, including failures.
  const kind = (s: { [key: string]: Yaml }): string | null => {
    const uses = s['uses'];
    if (uses === CHECKOUT) return 'checkout';
    if (uses === SETUP_NODE) return 'setup-node';
    const run = commandOf(s);
    if (/^node scripts\/ci-install\.mjs --root "\$PWD"$/.test(run)) return 'npm ci';
    if (/^npm ci(\s|$)/.test(run)) return 'npm ci';
    if (/^npm run lint(\s|$)/.test(run)) return 'lint';
    if (/^npm run build(\s|$)/.test(run)) return 'build';
    if (/^npm (run )?test(\s|$)/.test(run)) return 'product';
    if (/^npm run test:harness(\s|$)/.test(run)) return 'harness';
    if (/^node scripts\/no-pending\.mjs\s/.test(run)) return 'no-pending';
    return null;
  };
  const active = (step: { [key: string]: Yaml }, combo: Record<string, string>): boolean => {
    if (step['if'] === undefined) return true;
    let condition = String(step['if']).trim().replace(/^\$\{\{\s*|\s*\}\}$/g, '');
    if (condition.includes('always()')) {
      const run = String(step['run'] ?? '').trim();
      const verification = /^node scripts\/ci-capture\.mjs verify --root "\$PWD" --capture-dir "\$FLUXWARDEN_CI_CAPTURE_DIR"$/.test(run);
      const upload = typeof step['uses'] === 'string' && step['uses'].startsWith('actions/upload-artifact@');
      const failedSetupCapture = /^node scripts\/ci-job\.mjs\b/.test(captureCommand(run))
        && commandsOf(step)[0] === 'node scripts/ci-install.mjs verify --root "$PWD"';
      expect(verification || upload || failedSetupCapture, 'only finalization, safe upload or a capture gated by original installer verification runs after failure').toBe(true);
      expect(step['continue-on-error'], 'finalization cannot waive a failure').toBeUndefined();
      if (!failedSetupCapture) {
        expect(condition).toBe(verification ? 'always()' : "always() && steps.capture-verify.outcome == 'success'");
        return true;
      }
      expect(condition, 'failure capture preserves the original matrix selector').toMatch(/^always\(\)\s*&&\s+/);
      condition = condition.replace(/^always\(\)\s*&&\s+/, '');
    }
    return condition.split(/\s*\|\|\s*/).some(alternative => alternative.split(/\s*&&\s*/).every(term => {
      const equal = /^matrix\.([\w-]+) == '([^']+)'$/.exec(term);
      if (equal) return combo[equal[1] ?? ''] === equal[2];
      const prefix = /^startsWith\(matrix\.([\w-]+), '([^']+)'\)$/.exec(term);
      if (prefix) return (combo[prefix[1] ?? ''] ?? '').startsWith(prefix[2] ?? '');
      throw new Error(`unsupported CI shard condition: ${condition}`);
    }));
  };
  for (const step of steps) if (String(step['if'] ?? '').includes('always()')) active(step, combos[0] ?? {});
  for (const s of steps.filter(s => kind(s) !== null)) {
    if (['checkout', 'setup-node', 'npm ci', 'lint', 'build'].includes(kind(s) ?? '')) {
      expect(s['if'], `${String(kind(s))} must not be conditional`).toBeUndefined();
    }
    expect(s['continue-on-error'], `${String(kind(s))} must not be allowed to fail`).toBeUndefined();
  }
  const reportOf = (ordered: { [key: string]: Yaml }[], k: string): string => {
    const run = commandOf(ordered.find(s => kind(s) === k) ?? {});
    expect(run, `${k} uses a JSON reporter`).toMatch(/--reporter[= ]json\b/);
    const file = /--outputFile(?:\.json)?[= ](\S+)/.exec(run)?.[1];
    if (file === undefined) throw new Error(`${k} names no JSON output file`);
    return file.replace(/^["']|["']$/g, '');
  };
  const linuxCoverage = new Map<string, string[]>();
  const windowsCoverage = new Map<string, string[]>();
  for (const combo of combos) {
    const ordered = steps.filter(s => kind(s) !== null && active(s, combo));
    const windows = subst(runsOn, combo) === 'windows-latest';
    const core = /^core-[123]$/.test(combo['shard'] ?? '');
    const harnessOnly = ordered.some(step => kind(step) === 'harness');
    if (windows) expect(harnessOnly, 'only the two Windows harness partitions execute the harness suite').toBe(/^harness-[12]$/.test(combo['shard'] ?? ''));
    const suite = harnessOnly ? 'harness' : 'product';
    expect(ordered.map(kind), JSON.stringify(combo)).toEqual([
      'checkout', 'setup-node', 'npm ci', suite,
    ]);
    const productStep = ordered.find(s => kind(s) === suite) ?? {};
    const wrapped = String(productStep['run']);
    expect(captureCommand(wrapped), 'one transparent finite wrapper encloses the job').not.toBe(wrapped);
    const job = captureCommand(subst(wrapped, combo)).replace(/\s+/g, ' ');
    expect(job.startsWith(`node scripts/ci-job.mjs ${harnessOnly ? '--commands-only ' : ''}-- node scripts/ci-install.mjs verify --root "$PWD" --next `), 'capture starts with the original installer failure gate and retains each independent suite').toBe(true);
    const stages = commandsOf(productStep);
    expect(stages.slice(0, harnessOnly ? -2 : -1), 'all original preparation stages are inside capture in their original order').toEqual([
      'node scripts/ci-install.mjs verify --root "$PWD"', 'npm run lint', 'npm run build', 'node scripts/ci-database-check.mjs',
      ...(windows && core ? ['node scripts/ci-windows-core.mjs'] : []),
    ]);
    expect(stages.at(harnessOnly ? -2 : -1), 'the selected suite follows all captured preparation stages').toBe(commandOf(productStep));
    if (harnessOnly) {
      const final = stages.at(-1) ?? '';
      const args = (final.match(/"[^"]*"|'[^']*'|[^\s]+/g) ?? []).map(arg => arg.replace(/^(["'])(.*)\1$/, '$2'));
      expect(args, 'the independent harness accepts only its own complete report').toEqual([
        'node', 'scripts/no-pending.mjs', '$FLUXWARDEN_EVIDENCE_DIR/vitest-harness.json',
      ]);
    }
    const productRun = commandOf(productStep);
    expect(productRun, 'no title or additional subset filtering').not.toMatch(/--(?:testNamePattern|exclude|include|dir|project|changed|related)\b|(?:^|\s)-t(?:\s|$)/);
    expect(productRun.match(/--maxWorkers(?:=|\s+)\S+/g), 'bounded worker allocation').toEqual([`--maxWorkers=${windows || harnessOnly ? '1' : '2'}`]);
    if (windows || harnessOnly) expect(productRun.match(/--fileParallelism(?:=|\s+)\S+/g), 'Windows and harness files run serially').toEqual(['--fileParallelism=false']);
    if (windows && (core || harnessOnly)) {
      const shards = [...subst(productRun, combo).matchAll(/--shard(?:=|\s+)(\S+)/g)];
      expect(shards, 'one explicit independent Windows suite shard').toHaveLength(1);
      const shard = shards[0]?.[1], index = (combo['shard'] ?? '').split('-')[1];
      expect(shard).toBe(`${index ?? '<unset>'}/${core ? '3' : '2'}`);
      const version = subst(nodeVersionExpr, combo);
      windowsCoverage.set(version, [...(windowsCoverage.get(version) ?? []), `${core ? 'core' : 'harness'} ${shard ?? '<unset>'}`]);
      if (core) {
        expect(productRun).toContain('--config="$FLUXWARDEN_CI_CORE_CONFIG"');
        expect(map(productStep['env'], 'core environment')['FLUXWARDEN_CI_CORE_CONFIG']).toBe('${{ env.TEMP }}/vitest-windows-core.config.mjs');
      } else expect(productRun).not.toMatch(/--config\b|\btest\/[\w./-]+\.test\.[cm]?[jt]s\b/);
    } else if (windows) {
      expect(productRun).not.toMatch(/--shard\b/);
      expect(productRun).not.toMatch(/--config\b/);
      const version = subst(nodeVersionExpr, combo);
      windowsCoverage.set(version, [...(windowsCoverage.get(version) ?? []), 'native']);
    } else {
      const shards = [...subst(productRun, combo).matchAll(/--shard(?:=|\s+)(\S+)/g)];
      expect(shards, 'one explicit independent Linux suite shard').toHaveLength(1);
      const shard = shards[0]?.[1];
      expect(shard).toMatch(/^[12]\/2$/);
      expect(productRun).not.toMatch(/--config\b|\btest\/[\w./-]+\.test\.[cm]?[jt]s\b/);
      const version = subst(nodeVersionExpr, combo);
      linuxCoverage.set(version, [...(linuxCoverage.get(version) ?? []), `${suite} ${shard ?? '<unset>'}`]);
    }
    expect(reportOf(ordered, suite), 'the active suite report remains in scanned evidence').toBe(`$FLUXWARDEN_EVIDENCE_DIR/vitest-${suite}.json`);
    const verification = steps.filter(step => active(step, combo)
      && String(step['run'] ?? '').trim() === 'node scripts/ci-capture.mjs verify --root "$PWD" --capture-dir "$FLUXWARDEN_CI_CAPTURE_DIR"');
    expect(verification, 'every independent invocation has its own final verification').toHaveLength(1);
    expect(verification[0]?.['if']).toBe('always()');
    expect(steps.indexOf(verification[0] ?? {})).toBeGreaterThan(steps.indexOf(productStep));
  }
  for (const version of linuxVersions) {
    expect(linuxCoverage.get(version)?.sort(), `${version}: complete product and harness coverage occurs exactly once`).toEqual([
      'harness 1/2', 'harness 2/2', 'product 1/2', 'product 2/2',
    ]);
  }
  for (const version of windowsVersions) {
    expect(windowsCoverage.get(version)?.sort(), `${version}: every Windows core, harness and native partition occurs exactly once`).toEqual([
      'core 1/3', 'core 2/3', 'core 3/3', 'harness 1/2', 'harness 2/2', 'native',
    ]);
  }

  // Execute the real public job runner with a finite owned npm fixture. The
  // reports use the existing no-pending fixture shape; no test code or selector
  // is substituted into the actual CI workflow.
  const jobRoot = scratchDir('ci-job-contract'), jobEvidence = join(jobRoot, 'evidence');
  mkdirSync(jobEvidence);
  mkdirSync(join(jobRoot, 'scripts'));
  copyFileSync(join(repoRoot, 'scripts/no-pending.mjs'), join(jobRoot, 'scripts/no-pending.mjs'));
  writeFileSync(join(jobRoot, 'package.json'), JSON.stringify({ name: 'owned-ci-job-control', version: '1.0.0', type: 'module',
    scripts: { lint: 'node record.mjs lint', build: 'node record.mjs build', test: 'node record.mjs product', 'test:harness': 'node record.mjs harness' } }));
  writeFileSync(join(jobRoot, 'package-lock.json'), JSON.stringify({ name: 'owned-ci-job-control', version: '1.0.0', lockfileVersion: 3,
    packages: { '': { name: 'owned-ci-job-control', version: '1.0.0' } } }));
  writeFileSync(join(jobRoot, 'scripts/ci-database-check.mjs'), "process.argv[2] = 'database'; await import('../record.mjs');\n");
  writeFileSync(join(jobRoot, 'record.mjs'), `import { appendFileSync, copyFileSync, existsSync, writeFileSync } from 'node:fs'; import { join } from 'node:path';
const kind = process.argv[2], mode = process.env['CONTROL_' + kind.toUpperCase()];
if (kind === 'lint' && existsSync('node_modules/install-canary')) process.exit(11);
appendFileSync(process.env.CONTROL_TRACE, kind + '\\n');
writeFileSync(process.env.CONTROL_TRACE + '.' + kind, JSON.stringify(process.argv.slice(3)));
copyFileSync(join(process.env.CONTROL_REPORTS, mode === 'skip' ? 'skipped.json' : 'all-passed-a.json'), join(process.env.FLUXWARDEN_EVIDENCE_DIR, 'vitest-' + kind + '.json'));
process.exitCode = mode === 'fail' ? 7 : 0;
`);
  for (const [harness, product, harnessResult, expected, trace, preparation] of [
    [true, 'pass', 'pass', 0, ['lint', 'build', 'database', 'product', 'harness'], 'pass'], [false, 'pass', 'pass', 0, ['product'], 'pass'],
    [true, 'fail', 'pass', 7, ['product'], 'pass'], [true, 'pass', 'fail', 7, ['product', 'harness'], 'pass'],
    [true, 'skip', 'pass', 1, ['product', 'harness'], 'pass'], [true, 'pass', 'skip', 1, ['product', 'harness'], 'pass'],
    [true, 'pass', 'pass', 7, ['lint'], 'fail'],
  ] as const) {
    const traceFile = join(jobRoot, `trace-${String(harness)}-${product}-${harnessResult}-${preparation}.log`);
    const fullOrder = harness && product === 'pass' && harnessResult === 'pass';
    if (fullOrder) {
      mkdirSync(join(jobRoot, 'node_modules'), { recursive: true });
      writeFileSync(join(jobRoot, 'node_modules/install-canary'), 'owned stale install canary');
    }
    const result = spawnSync(process.execPath, [...ownedCaptureToolArgs([join(repoRoot, 'scripts/ci-job.mjs'), ...(harness ? ['--harness'] : []), '--',
      ...(fullOrder ? ['npm', 'ci', '--ignore-scripts', '--next', 'npm', 'run', 'lint', '--next', 'npm', 'run', 'build',
        '--next', 'node', 'scripts/ci-database-check.mjs', '--next'] : []),
      'npm', 'test', '--', '--reporter=default', '--reporter=json', `--outputFile.json=${join(jobEvidence, 'vitest-product.json')}`])], {
      cwd: jobRoot, env: { ...childEnv(), FLUXWARDEN_EVIDENCE_DIR: jobEvidence, CONTROL_PRODUCT: product,
        CONTROL_HARNESS: harnessResult, CONTROL_LINT: preparation, CONTROL_TRACE: traceFile, CONTROL_REPORTS: join(repoRoot, 'test/fixtures/no-pending') },
      encoding: 'utf8', windowsHide: true, timeout: 10_000,
    });
    expect(result.error).toBeUndefined();
    expect(result.status, 'actual runner preserves child failure and rejects nonpassing reports').toBe(expected);
    expect(readFileSync(traceFile, 'utf8').trim().split('\n'), 'product precedes the selected harness').toEqual(trace);
    if (harness && product === 'pass' && preparation === 'pass') {
      const args: unknown = JSON.parse(readFileSync(traceFile + '.harness', 'utf8'));
      expect(args, 'harness report is included in the same final no-pending acceptance').toContain(`--outputFile.json=${join(jobEvidence, 'vitest-harness.json')}`);
    }
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
  for (const version of windowsVersions) {
    const combo = combos.find(c => subst(runsOn, c) === 'windows-latest' && subst(nodeVersionExpr, c) === version && c['shard'] === 'native');
    if (combo === undefined) throw new Error('each original Windows Node version retains its native product job');
    const selected = steps.find(s => kind(s) === 'product' && active(s, combo));
    expect(String(selected?.['run']).match(/\btest\/[\w./-]+\.test\.ts\b/g) ?? [], `${version}: native product inventory is unchanged`).toEqual(nativeFiles);
  }
  if (coreProduct === undefined) throw new Error('core product step is required');
  expect(map(coreProduct['env'], 'core environment')['FLUXWARDEN_CI_CORE_CONFIG']).toBe('${{ env.TEMP }}/vitest-windows-core.config.mjs');
  expect(commandsOf(coreProduct).slice(-2, -1), 'configuration precedes the core product inside capture').toEqual(['node scripts/ci-windows-core.mjs']);
  const scratch = scratchDir('ci-shard-config'), coreConfig = join(scratch, 'vitest-windows-core.config.mjs');
  const configured = spawnSync(process.execPath, [join(repoRoot, 'scripts/ci-windows-core.mjs')], {
    cwd: repoRoot, env: { ...childEnv(), TEMP: scratch, FLUXWARDEN_CI_CORE_CONFIG: coreConfig },
    encoding: 'utf8', windowsHide: true, timeout: 10000,
  });
  expect(configured.error).toBeUndefined();
  expect(configured.status, configured.stderr).toBe(0);
  expect(existsSync(coreConfig), 'actual extracted stage creates the selected core configuration').toBe(true);
  expect(dirname(coreConfig)).toBe(scratch);
  expect(String(coreProduct['run'])).toContain('--config="$FLUXWARDEN_CI_CORE_CONFIG"');
  const projectFiles = (project: 'product' | 'harness-docs', args: readonly string[] = []): string[] => {
    const outputFile = join(scratchDir('ci-product-files'), 'inventory.json');
    const result = spawnSync(process.execPath, [join(repoRoot, 'node_modules', 'vitest', 'vitest.mjs'),
      'list', '--project', project, '--filesOnly', ...args, `--json=${outputFile}`], {
      cwd: repoRoot, env: childEnv(), encoding: 'utf8', windowsHide: true, timeout: 10000,
    });
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    const files: unknown = JSON.parse(readFileSync(outputFile, 'utf8'));
    if (!Array.isArray(files)) throw new Error('product file inventory is not a list');
    return files.map(value => {
      const file = asRecord(value, 'product file');
      expect(file['projectName']).toBe(project);
      if (typeof file['file'] !== 'string') throw new Error('product file path is missing');
      return relative(repoRoot, file['file']).replace(/\\/g, '/');
    }).sort();
  };
  const productFiles = (args: readonly string[] = []): string[] => projectFiles('product', args);
  const complete = productFiles(), coreFiles = productFiles(['--config', coreConfig]), native = productFiles(nativeArgs);
  const fullHarness = projectFiles('harness-docs');
  expect(fullHarness, 'both Windows harness shards retain the original sixteen-file project inventory').toHaveLength(16);
  // `list --filesOnly` lists eligible files without applying execution sharding.
  // Exercise the pinned public sequencer over that inventory instead.
  const partition = spawnSync(process.execPath, ['--input-type=module'], {
    cwd: repoRoot, env: { ...childEnv(), CI_CORE_FILES: JSON.stringify(coreFiles),
      CI_LINUX_PRODUCT_FILES: JSON.stringify(complete), CI_LINUX_HARNESS_FILES: JSON.stringify(fullHarness) },
    input: `import { BaseSequencer } from 'vitest/node';
const split = async (value, count) => {
 const files = JSON.parse(value).map(moduleId => ({ moduleId }));
 return Promise.all(Array.from({ length: count }, (_, offset) => new BaseSequencer({ config: { root: process.cwd(), shard: { index: offset + 1, count } } }).shard(files)));
};
const [groups, product, harness] = await Promise.all([split(process.env.CI_CORE_FILES, 3), split(process.env.CI_LINUX_PRODUCT_FILES, 2), split(process.env.CI_LINUX_HARNESS_FILES, 2)]);
console.log(JSON.stringify({ first: groups[0].map(file => file.moduleId), second: groups[1].map(file => file.moduleId), third: groups[2].map(file => file.moduleId),
 productFirst: product[0].map(file => file.moduleId), productSecond: product[1].map(file => file.moduleId),
 harnessFirst: harness[0].map(file => file.moduleId), harnessSecond: harness[1].map(file => file.moduleId) }));`,
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
  const firstCore = shardFiles('first'), secondCore = shardFiles('second'), thirdCore = shardFiles('third');
  expect(complete.length).toBeGreaterThan(nativeFiles.length);
  expect(native).toEqual([...nativeFiles].sort());
  for (const version of windowsVersions) {
    expect(firstCore.length, `${version}: first core shard is nonempty`).toBeGreaterThan(0);
    expect(secondCore.length, `${version}: second core shard is nonempty`).toBeGreaterThan(0);
    expect(thirdCore.length, `${version}: third core shard is nonempty`).toBeGreaterThan(0);
    expect(firstCore.filter(file => secondCore.includes(file) || thirdCore.includes(file)), `${version}: first core shard is disjoint`).toEqual([]);
    expect(secondCore.filter(file => thirdCore.includes(file)), `${version}: second and third core shards are disjoint`).toEqual([]);
    expect([...firstCore, ...secondCore, ...thirdCore].sort(), `${version}: Windows core shards cover the complete original core inventory`).toEqual(coreFiles);
    const first = shardFiles('harnessFirst'), second = shardFiles('harnessSecond');
    expect(first.length, `${version}: first Windows harness shard is nonempty`).toBeGreaterThan(0);
    expect(second.length, `${version}: second Windows harness shard is nonempty`).toBeGreaterThan(0);
    expect(first.filter(file => second.includes(file)), `${version}: Windows harness shards are disjoint`).toEqual([]);
    expect([...first, ...second].sort(), `${version}: Windows harness shards preserve all sixteen original files`).toEqual(fullHarness);
  }
  expect(coreFiles.filter(file => native.includes(file)), 'Windows shards are disjoint').toEqual([]);
  expect([...coreFiles, ...native].sort(), 'Windows shards cover the complete product inventory').toEqual(complete);
  for (const [suite, inventory] of [['product', complete], ['harness', fullHarness]] as const) {
    const first = shardFiles(`${suite}First`), second = shardFiles(`${suite}Second`);
    expect(first.length, `${suite} first Linux shard is nonempty`).toBeGreaterThan(0);
    expect(second.length, `${suite} second Linux shard is nonempty`).toBeGreaterThan(0);
    expect(first.filter(file => second.includes(file)), `${suite} Linux shards are disjoint`).toEqual([]);
    expect([...first, ...second].sort(), `${suite} Linux shards preserve the complete original project inventory`).toEqual(inventory);
  }

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
    const wrapped = runs.find(r => r.includes(`npm run ${script}`)) ?? '';
    expect(runs.indexOf('node scripts/ci-install.mjs --root "$PWD"'), `${name} performs trusted setup before validation capture`).toBeGreaterThanOrEqual(0);
    expect(runs.indexOf('node scripts/ci-install.mjs --root "$PWD"')).toBeLessThan(runs.indexOf(wrapped));
    const stream = captureCommand(wrapped.trim()).replace(/^node scripts\/ci-job\.mjs --commands-only -- /, '');
    const stages = stream.split(/\s+--next\s+|\s+--finally\s+/);
    expect(captureCommand(wrapped.trim()), `${name} capture encloses installer verification and validation`).not.toBe(wrapped.trim());
    expect(stages.slice(0, 2), `${name} checks original setup before the original build`).toEqual(['node scripts/ci-install.mjs verify --root "$PWD"', 'npm run build']);
    expect(invocation.test(stages[2] ?? '') && !/[;&|`\r\n]/.test(wrapped.trim()), `${name} retains the exact selected test command`).toBe(true);
    expect(stages.length, `${name} has only its original selected stages`).toBe(name === 'chaos' ? 4 : 3);
    if (name === 'chaos') {
      expect(stream, 'unchanged evidence scanner is an explicit failure finalizer').toContain(' --finally node scripts/leak-check.mjs ');
      expect(stages[3]).toBe('node scripts/leak-check.mjs --sentinels test/sentinels.json --sentinel-dir "$FLUXWARDEN_SENTINEL_DIR" "$FLUXWARDEN_EVIDENCE_DIR"');
    }
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

// Owner-delegated orchestration contract: the explicit alternative flag runs the
// full harness after prerequisites and before the final product command, then
// accepts both reports together. The existing --harness ordering stays covered above.
// Bugs caught: an unsupported flag, a duplicated/reordered stage, a failure that
// allows a later stage, or final acceptance that omits either selected report.
it('CP-044/REG-CI-ORDER selected harness runs before final product stage with failures propagated', () => {
  const jobRoot = scratchDir('ci-job-harness-before-final');
  mkdirSync(join(jobRoot, 'scripts'));
  copyFileSync(join(repoRoot, 'scripts/no-pending.mjs'), join(jobRoot, 'scripts/no-pending-check.mjs'));
  writeFileSync(join(jobRoot, 'scripts/no-pending.mjs'), `import { appendFileSync, writeFileSync } from 'node:fs';
appendFileSync(process.env.CONTROL_TRACE, 'no-pending\\n');
writeFileSync(process.env.CONTROL_TRACE + '.no-pending', JSON.stringify(process.argv.slice(2)));
await import('./no-pending-check.mjs');
`);
  writeFileSync(join(jobRoot, 'package.json'), JSON.stringify({ name: 'owned-ci-job-order-control', version: '1.0.0', type: 'module',
    scripts: { lint: 'node record.mjs lint', build: 'node record.mjs build', test: 'node record.mjs product', 'test:harness': 'node record.mjs harness' } }));
  writeFileSync(join(jobRoot, 'scripts/ci-database-check.mjs'), "process.argv[2] = 'database'; await import('../record.mjs');\n");
  writeFileSync(join(jobRoot, 'record.mjs'), `import { appendFileSync, copyFileSync, writeFileSync } from 'node:fs'; import { join } from 'node:path';
const kind = process.argv[2], mode = process.env['CONTROL_' + kind.toUpperCase()];
appendFileSync(process.env.CONTROL_TRACE, kind + '\\n');
writeFileSync(process.env.CONTROL_TRACE + '.' + kind, JSON.stringify(process.argv.slice(3)));
copyFileSync(join(process.env.CONTROL_REPORTS, mode === 'skip' ? 'skipped.json' : 'all-passed-a.json'), join(process.env.FLUXWARDEN_EVIDENCE_DIR, 'vitest-' + kind + '.json'));
process.exitCode = mode === 'fail' ? 7 : 0;
`);
  for (const [name, lint, build, database, harness, product, expected, trace] of [
    ['all-pass', 'pass', 'pass', 'pass', 'pass', 'pass', 0, ['lint', 'build', 'database', 'harness', 'product', 'no-pending']],
    ['harness-fails', 'pass', 'pass', 'pass', 'fail', 'pass', 7, ['lint', 'build', 'database', 'harness']],
    ['product-fails', 'pass', 'pass', 'pass', 'pass', 'fail', 7, ['lint', 'build', 'database', 'harness', 'product']],
    ['lint-fails', 'fail', 'pass', 'pass', 'pass', 'pass', 7, ['lint']],
    ['build-fails', 'pass', 'fail', 'pass', 'pass', 'pass', 7, ['lint', 'build']],
    ['database-fails', 'pass', 'pass', 'fail', 'pass', 'pass', 7, ['lint', 'build', 'database']],
    ['harness-skips', 'pass', 'pass', 'pass', 'skip', 'pass', 1, ['lint', 'build', 'database', 'harness', 'product', 'no-pending']],
    ['product-skips', 'pass', 'pass', 'pass', 'pass', 'skip', 1, ['lint', 'build', 'database', 'harness', 'product', 'no-pending']],
  ] as const) {
    const evidence = join(jobRoot, name), traceFile = join(evidence, 'trace.log');
    mkdirSync(evidence);
    const result = spawnSync(process.execPath, [...ownedCaptureToolArgs([join(repoRoot, 'scripts/ci-job.mjs'), '--harness-before-final', '--',
      'npm', 'run', 'lint', '--next', 'npm', 'run', 'build', '--next', 'node', 'scripts/ci-database-check.mjs', '--next',
      'npm', 'test', '--', '--reporter=default', '--reporter=json', `--outputFile.json=${join(evidence, 'vitest-product.json')}`])], {
      cwd: jobRoot, env: { ...childEnv(), FLUXWARDEN_EVIDENCE_DIR: evidence, CONTROL_LINT: lint, CONTROL_BUILD: build,
        CONTROL_DATABASE: database, CONTROL_HARNESS: harness, CONTROL_PRODUCT: product,
        CONTROL_TRACE: traceFile, CONTROL_REPORTS: join(repoRoot, 'test/fixtures/no-pending') },
      encoding: 'utf8', windowsHide: true, timeout: 10_000,
    });
    expect(result.error, name).toBeUndefined();
    expect(result.status, `${name}: the selected stages preserve failures and validate both reports`).toBe(expected);
    expect(readFileSync(traceFile, 'utf8').trim().split('\n'), `${name}: every requested stage runs once in order and stops on failure`).toEqual(trace);
    const reached: readonly string[] = trace;
    if (reached.includes('harness')) {
      const args: unknown = JSON.parse(readFileSync(traceFile + '.harness', 'utf8'));
      expect(args, `${name}: full harness writes its selected report`).toContain(`--outputFile.json=${join(evidence, 'vitest-harness.json')}`);
    }
    if (reached.includes('no-pending')) {
      const reports: unknown = JSON.parse(readFileSync(traceFile + '.no-pending', 'utf8'));
      expect(reports, `${name}: final acceptance selects exactly two reports`).toHaveLength(2);
      expect(reports, `${name}: final acceptance validates both product and harness reports`).toEqual(expect.arrayContaining([
        join(evidence, 'vitest-product.json'), join(evidence, 'vitest-harness.json'),
      ]));
    }
  }
});
