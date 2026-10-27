// Repository configuration and documentation, checked through public files and commands.
// Expected values follow the public package identity, toolchain, documentation and reporting policy.
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { asRecord, binPath, childEnv, isRecord, readJson, readText, repoRoot, runNpmScript, scratchDir } from '../helpers/cli.js';
import { ownedCaptureToolArgs } from '../helpers/capture-fixture.js';
import { NATIVE_FILES, NODE_TARGETS, proveCiGraph, proveDispatcherExit, provePlatformPlans } from '../helpers/oct26-ci-oracles.js';

// October 26 audit F08 authorizes compatible patched exact pins. Preserve the
// reviewed tool set and major versions; lock every selected pin without ranges.
const PINS: Record<string, string> = {
  typescript: '6.0.3',
  vitest: '5.0.3',
  vite: '8.3.3',
  eslint: '10.11.0',
  '@eslint/js': '10.0.1',
  'typescript-eslint': '8.71.0',
  '@types/node': '22.20.5',
  globals: '17.13.0',
  ajv: '8.20.0',
};
const ENGINES = '^22.23.2 || ^24.18.1 || >=26.5.1';
const SCRIPT_NAMES = ['test', 'test:harness', 'test:related', 'lint', 'build', 'test:lab', 'test:chaos', 'test:full', 'lab:up', 'lab:down', 'fixtures:record'];

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
  const direct = asRecord(pkg['devDependencies'], 'exact direct pins');
  expect(Object.keys(direct).sort()).toEqual(Object.keys(PINS).sort());
  for (const [name, floor] of Object.entries(PINS)) {
    const pin = direct[name];
    expect(pin, `${name} remains an exact stable pin`).toMatch(/^\d+\.\d+\.\d+$/);
    const [major = 0, minor = 0, patch = 0] = String(pin).split('.').map(Number);
    const [minimumMajor = 0, minimumMinor = 0, minimumPatch = 0] = floor.split('.').map(Number);
    expect(major, `${name} compatible major`).toBe(minimumMajor);
    expect(minor > minimumMinor || minor === minimumMinor && patch >= minimumPatch, `${name} reviewed patch floor`).toBe(true);
  }
  for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'bundledDependencies']) {
    const value = pkg[field];
    expect(value === undefined || (isRecord(value) && Object.keys(value).length === 0) || (Array.isArray(value) && value.length === 0), field).toBe(true);
  }
  const scripts = asRecord(pkg['scripts'], 'scripts');
  for (const name of SCRIPT_NAMES) expect(typeof scripts[name], `script ${name}`).toBe('string');

  const lockPackages = asRecord(asRecord(readJson('package-lock.json'), 'package-lock.json')['packages'], 'lock packages');
  const lockRoot = asRecord(lockPackages[''], 'lock root');
  expect(lockRoot['devDependencies']).toEqual(direct);
  expect(lockRoot['dependencies'] ?? {}).toEqual({});
  for (const [name, version] of Object.entries(direct)) {
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
  proveCiGraph();
});

it('CP-044/CI-DISPATCH every platform target retains original ordered stage argv worker limits and no-pending reports', async () => {
  await provePlatformPlans();
}, 300_000);

it('CP-044/CI-DISPATCH the actual dispatcher captures once and propagates success and failure without bypass', async () => {
  await proveDispatcherExit();
}, 300_000);

it('CP-001/B11 the public finite job runner preserves stage order failure propagation and no-pending acceptance', () => {
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
  // Seven real job controls retain their existing finite allowance; their
  // completion margin does not assert npm performance.
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
      encoding: 'utf8', windowsHide: true, timeout: 30_000,
    });
    expect(result.error).toBeUndefined();
    expect(result.signal, 'every stage control completes without being killed').toBeNull();
    expect(result.status, 'a completed control has an actual exit status').not.toBeNull();
    expect(result.status, 'actual runner preserves child failure and rejects nonpassing reports').toBe(expected);
    expect(readFileSync(traceFile, 'utf8').trim().split('\n'), 'product precedes the selected harness').toEqual(trace);
    if (harness && product === 'pass' && preparation === 'pass') {
      const args: unknown = JSON.parse(readFileSync(traceFile + '.harness', 'utf8'));
      expect(args, 'harness report is included in the same final no-pending acceptance').toContain(`--outputFile.json=${join(jobEvidence, 'vitest-harness.json')}`);
    }
  }

}, 300_000);

it('CP-001/B11 source-eligible files remain in disjoint complete bounded platform partitions', () => {
  const windowsVersions = NODE_TARGETS;
  // Approved Windows split: the native commands and the generated core configuration must partition
  // the complete product file inventory. Use Vitest's public listing command, without running product tests.
  const nativeFiles = NATIVE_FILES;
  const harnessFiles = [
    'test/harness/ci-dependency-setup.test.ts',
    'test/harness/ci-secret-output.test.ts',
    'test/harness/ci-worker-source-lifetime.test.ts',
    'test/harness/config.test.ts',
    'test/harness/cp001-repo.test.ts',
    'test/harness/cp002-byte-boundary-gold.test.ts',
    'test/harness/cp002-declaration-freshness.test.ts',
    'test/harness/cp002-encoding-completeness.test.ts',
    'test/harness/cp002-leak.test.ts',
    'test/harness/cp004-provenance.test.ts',
    'test/harness/cp028-worker-completion.test.ts',
    'test/harness/current-ci-capture.test.ts',
    'test/harness/docs.test.ts',
    'test/harness/docs-consistency.test.ts',
    'test/harness/public-ci-chaos-evidence.test.ts',
    'test/harness/release.test.ts',
    'test/harness/release-smoke-retention.test.ts',
  ];
  const nativeSelections = windowsVersions.flatMap(version => [1, 2].map(index => ({ version, index, files: nativeFiles, sharded: true })));
  const scratch = scratchDir('ci-shard-config'), coreConfig = join(scratch, 'vitest-windows-core.config.mjs');
  const configured = spawnSync(process.execPath, [join(repoRoot, 'scripts/ci-windows-core.mjs')], {
    cwd: repoRoot, env: { ...childEnv(), TEMP: scratch, FLUXWARDEN_CI_CORE_CONFIG: coreConfig },
    encoding: 'utf8', windowsHide: true, timeout: 10000,
  });
  expect(configured.error).toBeUndefined();
  expect(configured.status, configured.stderr).toBe(0);
  expect(existsSync(coreConfig), 'actual extracted stage creates the selected core configuration').toBe(true);
  expect(dirname(coreConfig)).toBe(scratch);
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
  const complete = productFiles(), coreFiles = productFiles(['--config', coreConfig]), native = productFiles(nativeFiles);
  const fullHarness = projectFiles('harness-docs');
  // D29 followup: preserve every frozen original member without freezing the
  // file count. Runtime and operational regressions extend the eligible set.
  const reference = asRecord(readJson('test/fixtures/oct26-release-gate/source-cases.json'), 'independent source reference');
  const platforms = asRecord(reference['casesByPlatform'], 'source platform cases');
  const baselineRows = asRecord(platforms['windows-latest'], 'baseline file membership')['product'];
  if (!Array.isArray(baselineRows)) throw new Error('independent baseline case membership required');
  const baselineFiles = [...new Set(baselineRows.map(row => {
    const file = asRecord(row, 'baseline source case')['file'];
    if (typeof file !== 'string') throw new Error('baseline source file required');
    return file;
  }))];
  const newProductFiles = [
    'test/cli/cp044-daemon-recovery.test.ts', 'test/cli/cp044-multinode-selection.test.ts',
    'test/executor/cp044-snapshot-age.test.ts', 'test/labs/owned-reference-admission.test.ts',
    'test/operations/operational-recovery.test.ts', 'test/persistence/cp044-node-identity.test.ts',
    'test/reconciler/cp044-terminal-contention.test.ts',
  ];
  const requiredComplete = [...baselineFiles, ...newProductFiles];
  const requiredCore = requiredComplete.filter(file => !nativeFiles.includes(file));
  const assertProductInventory = (files: readonly string[], requiredMembers: readonly string[]): void => {
    expect(new Set(files).size, 'eligible source files occur once').toBe(files.length);
    for (const file of requiredMembers) expect(files, file + ' remains eligible alongside all new source files').toContain(file);
  };
  assertProductInventory(complete, requiredComplete);
  assertProductInventory(coreFiles, requiredCore);
  // Exercise the same acceptance boundary with an omitted new file and an
  // omitted original file: neither inventory may silently lose either kind.
  for (const omitted of ['test/commands/post-audit-demand-gold.test.ts', 'test/commands/reaudit-history-gold.test.ts',
    'test/commands/reaudit-protocol-gold.test.ts', 'test/cli/cp016-commands.test.ts']) {
    expect(complete).toContain(omitted);
    expect(coreFiles).toContain(omitted);
    expect(() => { assertProductInventory(complete.filter(file => file !== omitted), requiredComplete); }).toThrow();
    expect(() => { assertProductInventory(coreFiles.filter(file => file !== omitted), requiredCore); }).toThrow();
  }
  expect(native, 'two Windows native allocations retain all twelve original files').toHaveLength(12);
  for (const file of harnessFiles) expect(fullHarness, 'every original harness file remains eligible').toContain(file);
  for (const file of ['test/harness/oct26-distribution-runtime.test.ts', 'test/harness/oct26-live-selection.test.ts', 'test/harness/oct26-release-gate.test.ts']) expect(fullHarness, 'release regressions remain eligible alongside original files').toContain(file);
  expect(fullHarness, 'the real worker completion regression remains in the harness inventory').toContain('test/harness/cp028-worker-completion.test.ts');
  // `list --filesOnly` lists eligible files without applying execution sharding.
  // Exercise the pinned public sequencer over that inventory instead.
  const partition = spawnSync(process.execPath, ['--input-type=module'], {
    cwd: repoRoot, env: { ...childEnv(), CI_CORE_FILES: JSON.stringify(coreFiles), CI_NATIVE_SELECTIONS: JSON.stringify(nativeSelections),
      CI_LINUX_PRODUCT_FILES: JSON.stringify(complete), CI_LINUX_HARNESS_FILES: JSON.stringify(fullHarness) },
    input: `import { BaseSequencer } from 'vitest/node';
const split = async (value, count) => {
 const files = JSON.parse(value).map(moduleId => ({ moduleId }));
 return Promise.all(Array.from({ length: count }, (_, offset) => new BaseSequencer({ config: { root: process.cwd(), shard: { index: offset + 1, count } } }).shard(files)));
};
const [groups, product, harness, windowsHarness] = await Promise.all([split(process.env.CI_CORE_FILES, 3), split(process.env.CI_LINUX_PRODUCT_FILES, 2), split(process.env.CI_LINUX_HARNESS_FILES, 2), split(process.env.CI_LINUX_HARNESS_FILES, 8)]);
const native = await Promise.all(JSON.parse(process.env.CI_NATIVE_SELECTIONS).map(async selection => {
 const files = selection.files.map(moduleId => ({ moduleId }));
 const selected = selection.sharded ? await new BaseSequencer({ config: { root: process.cwd(), shard: { index: selection.index, count: 2 } } }).shard(files) : files;
 return ['native-' + selection.version + '-' + selection.index, selected.map(file => file.moduleId)];
}));
console.log(JSON.stringify({ first: groups[0].map(file => file.moduleId), second: groups[1].map(file => file.moduleId), third: groups[2].map(file => file.moduleId),
 productFirst: product[0].map(file => file.moduleId), productSecond: product[1].map(file => file.moduleId),
 harnessFirst: harness[0].map(file => file.moduleId), harnessSecond: harness[1].map(file => file.moduleId),
 windowsHarness: windowsHarness.map(group => group.map(file => file.moduleId)), ...Object.fromEntries(native) }));`,
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
    const firstNative = shardFiles(`native-${version}-1`), secondNative = shardFiles(`native-${version}-2`);
    expect([firstNative.length, secondNative.length], `${version}: native allocations are two nonempty six-file groups`).toEqual([6, 6]);
    expect(firstNative.filter(file => secondNative.includes(file)), `${version}: native allocations are disjoint`).toEqual([]);
    expect([...firstNative, ...secondNative].sort(), `${version}: native allocations preserve the exact twelve-file inventory`).toEqual([...nativeFiles].sort());
    expect(firstCore.length, `${version}: first core shard is nonempty`).toBeGreaterThan(0);
    expect(secondCore.length, `${version}: second core shard is nonempty`).toBeGreaterThan(0);
    expect(thirdCore.length, `${version}: third core shard is nonempty`).toBeGreaterThan(0);
    expect(firstCore.filter(file => secondCore.includes(file) || thirdCore.includes(file)), `${version}: first core shard is disjoint`).toEqual([]);
    expect(secondCore.filter(file => thirdCore.includes(file)), `${version}: second and third core shards are disjoint`).toEqual([]);
    expect([...firstCore, ...secondCore, ...thirdCore].sort(), `${version}: Windows core shards cover the complete original core inventory`).toEqual(coreFiles);
    const groups = partitions['windowsHarness'];
    if (!Array.isArray(groups)) throw new Error('Windows harness partitions are not a list');
    expect(groups).toHaveLength(8);
    const files = groups.map((group: unknown) => {
      if (!Array.isArray(group) || !group.every((file: unknown) => typeof file === 'string')) throw new Error('Windows harness partition is not a path list');
      return group;
    });
    expect(Math.max(...files.map(group => group.length)) - Math.min(...files.map(group => group.length)), `${version}: harness allocation remains balanced as eligible files grow`).toBeLessThanOrEqual(1);
    for (const [index, group] of files.entries()) {
      expect(group.length, `${version}: Windows harness shard ${String(index + 1)} is nonempty`).toBeGreaterThan(0);
      expect(group.filter(file => files.slice(index + 1).flat().includes(file)), `${version}: Windows harness shard ${String(index + 1)} is disjoint`).toEqual([]);
    }
    expect(files.flat().sort(), `${version}: eight Windows harness shards preserve every current eligible file`).toEqual(fullHarness);
    // D29 followup: growing beyond seventeen files changes incidental hashes.
    // Preserve both proofs, complete balanced isolation and original limits;
    // the specification does not require these files in different official jobs.
    for (const proof of ['test/harness/ci-secret-output.test.ts', 'test/harness/public-ci-chaos-evidence.test.ts']) {
      expect(files.flat().filter(file => file === proof), `${version}: each original isolation/failure proof remains once`).toHaveLength(1);
    }
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


}, 300_000);

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
  for (const file of [executable, 'README.md', 'package.json', 'LICENSE', 'NOTICE-SOURCE-REUSE.md', ...runtime]) expect(paths, `${file} is packaged`).toContain(file);
  const publicFiles = new Set(['README.md', 'SECURITY.md', 'LICENSE', 'NOTICE-SOURCE-REUSE.md', 'CHANGELOG.md', 'package.json']);
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
