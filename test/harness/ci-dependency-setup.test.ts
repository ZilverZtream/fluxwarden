// Source: adopted CP-044 trusted-dependency-setup decision, 2026-10-21,
// SHA256 8f4e83b62bad4940be142239352e443788d778d2ad10a24e76400bdf40f7bc27.
// Public setup interface adopted by ROOT: ci-install.mjs [verify] --root ROOT.
// These are disposable local packages, real npm commands and ordinary files;
// no network, shared dependency tree, substituted npm return, or product hooks.
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, copyFileSync, cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, realpathSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it, onTestFinished } from 'vitest';
import { asRecord, childEnv, repoRoot } from '../helpers/cli.js';
import { declareFixtureCapture, declareFixturePaths, ownedCaptureToolArgs } from '../helpers/capture-fixture.js';
import { testRoot } from '../helpers/env.js';
import { assertStrictWindowsOwnerOnly, readWindowsSecurity } from '../helpers/windows-security.js';

const sha = (bytes: Buffer | string): string => createHash('sha256').update(bytes).digest('hex');
const npm = join(dirname(process.execPath), process.platform === 'win32'
  ? 'node_modules/npm/bin/npm-cli.js' : '../lib/node_modules/npm/bin/npm-cli.js');
const setup = join(repoRoot, 'scripts/ci-install.mjs');
function files(directory: string): string[] {
  if (!existsSync(directory)) return [];
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? files(path) : entry.isFile() ? [path] : [];
  });
}
function objects(value: unknown): Record<string, unknown>[] {
  if (!value || typeof value !== 'object') return [];
  if (Array.isArray(value)) return value.flatMap(objects);
  const object = value as Record<string, unknown>;
  return [object, ...Object.values(object).flatMap(objects)];
}

async function fixture(broken = false) {
  const parent = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'dependency-setup-'));
  const root = join(parent, 'checkout'), capture = join(parent, 'capture');
  const roots = ['temp', 'tmp', 'scratch', 'sources', 'evidence'].map(name => join(parent, name));
  for (const directory of [root, capture, ...roots]) mkdirSync(directory, { mode: 0o700 });
  const permission = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as {
    assertPrivateDirectories: (paths: string[]) => Promise<void>;
  };
  await permission.assertPrivateDirectories(roots);
  const env: NodeJS.ProcessEnv = { ...childEnv(), TEMP: roots[0], TMP: roots[1], FLUXWARDEN_TEST_TMP: roots[2],
    FLUXWARDEN_SENTINEL_DIR: roots[3], FLUXWARDEN_EVIDENCE_DIR: roots[4],
    // Both the fixture's lock generation and baseline npm stay in owned storage.
    // The setup command must replace inherited npm configuration with its own.
    npm_config_cache: join(roots[2] ?? '', 'fixture-npm-cache'), npm_config_offline: 'true',
    npm_config_loglevel: 'verbose', HOME: parent, USERPROFILE: parent, LOCALAPPDATA: parent };
  let sequence = 0;
  const commandProof = join(parent, 'commands');
  mkdirSync(commandProof);
  const run = (command: string, args: string[], cwd = root, prerequisiteNpm = false) => {
    // Fixture-authoring npm calls precede the target invocation; their optional
    // Node cache must not inflate its original owned output census. The actual
    // ci-install/capture/validation commands retain the normal environment.
    const commandEnv = prerequisiteNpm ? { ...env, NODE_DISABLE_COMPILE_CACHE: '1' } : env;
    const result = spawnSync(command, args, { cwd, env: commandEnv, encoding: 'utf8', windowsHide: true, timeout: 10_000 });
    const id = String(sequence++);
    writeFileSync(join(commandProof, `${id}.stdout`), result.stdout);
    writeFileSync(join(commandProof, `${id}.stderr`), result.stderr);
    appendFileSync(join(commandProof, 'results.jsonl'), JSON.stringify({ id, command, args, cwd, execPath: process.execPath,
      status: result.status, signal: result.signal, error: result.error?.name ?? null }) + '\n');
    return result;
  };
  const seed = randomBytes(32), source = join(root, 'test/sentinels/control.bin');
  mkdirSync(dirname(source), { recursive: true });
  declareFixturePaths([source]);
  writeFileSync(source, seed, { mode: 0o600 });
  writeFileSync(join(root, 'test/sentinels.json'), JSON.stringify(['test/sentinels/control.bin']));
  mkdirSync(join(root, 'scripts'));
  const support = readdirSync(join(repoRoot, 'scripts')).filter(name => /^ci-.*\.mjs$/.test(name));
  for (const name of ['leak-check.mjs', 'private-scratch.mjs', ...support]) copyFileSync(join(repoRoot, 'scripts', name), join(root, 'scripts', name));
  const vendor = join(root, 'vendor');
  mkdirSync(vendor);
  writeFileSync(join(vendor, 'package.json'), JSON.stringify({ name: 'fixture-tool', version: '1.0.0',
    scripts: { install: 'node forbidden-hook.mjs' } }));
  writeFileSync(join(vendor, 'input.txt'), 'authenticated regular dependency bytes\n');
  writeFileSync(join(vendor, 'forbidden-hook.mjs'), "throw new Error('dependency lifecycle hook must stay disabled');\n");
  const packed = run(process.execPath, [npm, 'pack', '--offline', '--ignore-scripts', '--json', '--pack-destination', root], vendor, true);
  expect(packed.status, 'real local dependency tarball can be packed offline').toBe(0);
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'owned-setup-fixture', version: '1.0.0', private: true,
    scripts: { install: 'node forbidden-hook.mjs' },
    dependencies: { 'fixture-tool': 'file:fixture-tool-1.0.0.tgz' } }));
  writeFileSync(join(root, 'forbidden-hook.mjs'), "throw new Error('candidate lifecycle hook must stay disabled');\n");
  const lock = run(process.execPath, [npm, 'install', '--package-lock-only', '--ignore-scripts', '--offline', '--no-audit', '--no-fund'], root, true);
  expect(lock.status, 'real npm produces an integrity-bound local lock without network').toBe(0);
  // The real missing-tarball failure needs no link topology. Keep that fixture
  // physical so failed npm cannot leave an incidental dangling setup link.
  if (!broken) {
  const manifest = asRecord(JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as unknown, 'fixture manifest');
  asRecord(manifest['dependencies'], 'dependencies')['fixture-linked'] = 'file:node_modules/fixture-tool';
  const locked = asRecord(JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8')) as unknown, 'fixture lock');
  const packages = asRecord(locked['packages'], 'locked packages');
  asRecord(asRecord(packages[''], 'locked root')['dependencies'], 'locked dependencies')['fixture-linked'] = 'file:node_modules/fixture-tool';
  packages['node_modules/fixture-linked'] = { resolved: 'node_modules/fixture-tool', link: true };
  writeFileSync(join(root, 'package.json'), JSON.stringify(manifest));
  writeFileSync(join(root, 'package-lock.json'), JSON.stringify(locked));
  }
  // Prove this exact lock is accepted by real npm and creates a contained link;
  // ci-install must perform its own fresh install and authentication afterwards.
  const baseline = run(process.execPath, [npm, 'ci', '--ignore-scripts', '--offline', '--no-audit', '--no-fund'], root, true);
  if (broken) expect(baseline.status, 'real offline npm accepts the frozen physical tarball dependency before removal').toBe(0);
  else expect(baseline.status, 'real offline npm accepts the fixture lock and contained-link dependency').toBe(0);
  const dependencyLink = join(root, 'node_modules/fixture-linked');
  if (!broken) expect(lstatSync(dependencyLink).isSymbolicLink()).toBe(true);
  const originalLinkTarget = broken ? '' : readlinkSync(dependencyLink), containedTarget = join(root, 'node_modules/fixture-tool');
  if (!broken) {
  if (resolve(dirname(dependencyLink), originalLinkTarget) !== containedTarget) throw new Error('owned original dependency link must be contained');
  writeFileSync(join(commandProof, 'original-input-link.json'), JSON.stringify({ path: dependencyLink, target: originalLinkTarget }));
  }
  let expectedLinkIdentity: { dev: number; ino: number; modules: string; modulesDev: number; modulesIno: number;
    target: string; targetDev: number; targetIno: number };
  let disposalEligible = false;
  const bindKnownLink = (phase: 'prerequisite' | 'trusted-install' | 'known-restoration') => {
    const info = lstatSync(dependencyLink);
    const modules = realpathSync.native(join(root, 'node_modules'));
    const modulesInfo = lstatSync(join(root, 'node_modules')), target = realpathSync.native(dependencyLink), targetInfo = lstatSync(target);
    const targetRelative = relative(modules, target);
    if (!info.isSymbolicLink() || readlinkSync(dependencyLink) !== originalLinkTarget
      || resolve(dirname(dependencyLink), originalLinkTarget) !== containedTarget
      || !modulesInfo.isDirectory() || !targetInfo.isDirectory() || targetRelative === ''
      || targetRelative === '..' || targetRelative.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)
      || isAbsolute(targetRelative) || target !== realpathSync.native(containedTarget)) {
      throw new Error('unexpected dependency INPUT cannot be authenticated');
    }
    expectedLinkIdentity = { dev: info.dev, ino: info.ino, modules, modulesDev: modulesInfo.dev, modulesIno: modulesInfo.ino,
      target, targetDev: targetInfo.dev, targetIno: targetInfo.ino };
    appendFileSync(join(commandProof, 'input-link-identities.jsonl'), JSON.stringify({ phase, ...expectedLinkIdentity }) + '\n');
  };
  if (!broken) {
  bindKnownLink('prerequisite');
  onTestFinished(() => {
    // This nonsecret setup INPUT is no longer used after the original inner
    // checks. Keep target bytes, read-set evidence, receipts and streams intact.
    let info;
    try { info = lstatSync(dependencyLink); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return; throw error; }
    if (!disposalEligible) throw new Error('dependency INPUT retained because inner assertions did not complete');
    const modules = realpathSync.native(join(root, 'node_modules')), modulesInfo = lstatSync(join(root, 'node_modules'));
    const target = realpathSync.native(dependencyLink), targetInfo = lstatSync(target);
    if (!info.isSymbolicLink() || info.dev !== expectedLinkIdentity.dev || info.ino !== expectedLinkIdentity.ino
      || readlinkSync(dependencyLink) !== originalLinkTarget
      || resolve(dirname(dependencyLink), readlinkSync(dependencyLink)) !== containedTarget
      || modules !== expectedLinkIdentity.modules || modulesInfo.dev !== expectedLinkIdentity.modulesDev
      || modulesInfo.ino !== expectedLinkIdentity.modulesIno || !modulesInfo.isDirectory()
      || target !== expectedLinkIdentity.target || targetInfo.dev !== expectedLinkIdentity.targetDev
      || targetInfo.ino !== expectedLinkIdentity.targetIno || !targetInfo.isDirectory()) {
      throw new Error('unexpected dependency INPUT replacement retained for investigation');
    }
    unlinkSync(dependencyLink);
  });
  }
  if (broken) {
    rmSync(join(root, 'fixture-tool-1.0.0.tgz'));
    const failed = run(process.execPath, [npm, 'ci', '--ignore-scripts', '--offline', '--no-audit', '--no-fund',
      '--cache', join(roots[2] ?? '', 'missing-package-probe-cache')], root, true);
    expect(failed.status !== null && failed.status !== 0, 'real offline npm rejects the missing locked local tarball with an empty owned cache').toBe(true);
  }
  const validation = join(root, 'validate.mjs'), marker = join(roots[2] ?? '', 'validation-ran');
  writeFileSync(validation, `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'candidate validation ran');\n`);
  for (const args of [['init', '--quiet'], ['add', '--', 'package.json', 'package-lock.json', 'forbidden-hook.mjs', 'vendor',
    'validate.mjs', 'test/sentinels.json', 'test/sentinels/control.bin', 'scripts', ...(broken ? [] : ['fixture-tool-1.0.0.tgz'])],
  ['-c', 'user.name=Dependency fixture', '-c', 'user.email=fixture@invalid', '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'owned dependency setup fixture']]) {
    expect(run('git', [...args]).status, 'minimal owned candidate has real Git identity').toBe(0);
  }
  const evidence = roots[4] ?? '', scratch = roots[2] ?? '';
  declareFixtureCapture(capture, [seed], [{ path: join(root, 'node_modules/.vite/leaked.log'), bytes: seed }]);
  const install = (verify = false) => {
    const result = run(process.execPath, ownedCaptureToolArgs([setup, ...(verify ? ['verify'] : []), '--root', root]));
    // The real trusted installer may recreate this exact original setup INPUT.
    // Bind its new identity before any candidate validation is started.
    if (!broken && !verify && !result.error && result.status !== null) {
      try { bindKnownLink('trusted-install'); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    }
    return result;
  };
  let innerEvidence: { receipt: string; custody: string } | undefined;
  const validationCapture = (directory = capture) => {
    const result = run(process.execPath, ownedCaptureToolArgs([join(repoRoot, 'scripts/ci-capture.mjs'), '--root', root, '--capture-dir', directory,
      '--', process.execPath, join(root, 'scripts/ci-job.mjs'), '--commands-only', '--', 'node', setup, 'verify', '--root', root,
      '--next', 'node', validation, '--next', 'node', setup, 'verify', '--root', root]));
    if (!result.error && result.status !== null) innerEvidence = { receipt: join(directory, 'receipt.json'), custody: join(directory, 'custody.json') };
    return result;
  };
  const finishInputAssertions = () => {
    if (!innerEvidence) throw new Error('dependency INPUT retained without completed inner capture');
    const receipt = readFileSync(innerEvidence.receipt), custody = readFileSync(innerEvidence.custody);
    // This is called only after every original assertion in the case. Retain
    // the evidence binding even for deliberately rejected candidate mutations.
    JSON.parse(receipt.toString());
    JSON.parse(custody.toString());
    writeFileSync(join(commandProof, 'input-link-disposal-eligibility.json'), JSON.stringify({
      receiptSha256: sha(receipt), custodySha256: sha(custody), assertionsCompleted: true }));
    disposalEligible = true;
  };
  const setValidation = (body: string) => {
    if (existsSync(marker)) rmSync(marker);
    writeFileSync(validation, `import { mkdirSync, readFileSync, writeFileSync, rmSync, symlinkSync, unlinkSync } from 'node:fs';
writeFileSync(${JSON.stringify(marker)}, 'candidate validation ran');\n${body}\n`);
    expect(run('git', ['add', '--', 'validate.mjs']).status).toBe(0);
    expect(run('git', ['-c', 'user.name=Dependency fixture', '-c', 'user.email=fixture@invalid', '-c', 'commit.gpgsign=false',
      'commit', '--quiet', '-m', 'owned validation control']).status).toBe(0);
  };
  const restoreDependencyLink = (plantedTarget: string) => {
    const info = lstatSync(dependencyLink);
    if (!info.isSymbolicLink()) throw new Error('unexpected dependency INPUT replacement retained for investigation');
    const currentTarget = readlinkSync(dependencyLink);
    if (currentTarget === originalLinkTarget && info.dev === expectedLinkIdentity.dev && info.ino === expectedLinkIdentity.ino) return;
    if (currentTarget !== plantedTarget) throw new Error('unexpected dependency INPUT replacement retained for investigation');
    unlinkSync(dependencyLink);
    symlinkSync(originalLinkTarget, dependencyLink, process.platform === 'win32' ? 'junction' : 'dir');
    bindKnownLink('known-restoration');
  };
  return { parent, root, roots, capture, evidence, scratch, seed, source, marker, validation, env, run, install, validationCapture, setValidation, restoreDependencyLink, finishInputAssertions,
    regular: join(root, 'node_modules/fixture-tool/input.txt'), dependencyLink, originalLinkTarget,
    status() {
      expect(existsSync(join(evidence, 'npm-install.json')), 'trusted setup must retain its original execution status').toBe(true);
      return JSON.parse(readFileSync(join(evidence, 'npm-install.json'), 'utf8')) as unknown;
    } };
}

it('CP-044/DEPENDENCY-SETUP successful frozen-lock install disables hooks and retains scanned original installer evidence', async () => {
  const f = await fixture(), lock = sha(readFileSync(join(f.root, 'package-lock.json')));
  const installed = f.install();
  expect(installed.error).toBeUndefined();
  expect(installed.status, 'trusted setup succeeds before any candidate validation').toBe(0);
  expect(existsSync(f.marker)).toBe(false);
  expect(f.install(true).status, 'original successful setup permits candidate validation').toBe(0);
  expect(lstatSync(f.dependencyLink).isSymbolicLink(), 'real npm installed the contained local dependency link').toBe(true);
  const metadata = f.status(), rows = objects(metadata);
  expect(JSON.stringify(metadata).includes(lock), 'installer status binds the original frozen lock bytes').toBe(true);
  expect(rows.some(row => (row['exitCode'] ?? row['status']) === 0 && row['complete'] === true
    && row['signal'] === null && row['errorCode'] === null), 'original installer success/signal/error classification is retained').toBe(true);
  const originals = ['npm-install.stdout.log', 'npm-install.stderr.log'].map(name => join(f.evidence, name));
  expect(originals.every(existsSync), 'both complete original installer channels remain private').toBe(true);
  expect(readFileSync(originals[0] ?? '', 'utf8'), 'retained stdout contains the actual pinned npm installation result').toContain('added 2 packages');
  const logs = files(join(f.evidence, 'npm-install-logs'));
  expect(logs.length, 'actual npm diagnostic logs survive disposable cache cleanup').toBeGreaterThan(0);
  const result = f.validationCapture();
  expect(result.status, 'clean candidate validation begins only after authenticated setup').toBe(0);
  expect(existsSync(f.marker)).toBe(true);
  const receipt = asRecord(JSON.parse(readFileSync(join(f.capture, 'receipt.json'), 'utf8')) as unknown, 'receipt');
  const artifacts = objects(receipt['artifacts']);
  expect([...originals, ...logs, join(f.evidence, 'npm-install.json')].every(path => artifacts.some(row => row['path'] === path
    && row['purpose'] === 'EGRESS' && row['sha256'] === sha(readFileSync(path)))), 'every original installer channel, status and log is in the scanned Closing census').toBe(true);
  f.finishInputAssertions();
});

it('CP-044/DEPENDENCY-SETUP actual offline install failure retains status and logs and prevents candidate validation', async () => {
  const f = await fixture(true), installed = f.install();
  expect(installed.error).toBeUndefined();
  expect(installed.status !== null && installed.status !== 0).toBe(true);
  expect(objects(f.status()).some(row => typeof (row['exitCode'] ?? row['status']) === 'number'
    && (row['exitCode'] ?? row['status']) !== 0 && row['complete'] === true && row['signal'] === null && row['errorCode'] === null),
  'actual nonzero npm failure has retained bounded classification').toBe(true);
  expect(['npm-install.stdout.log', 'npm-install.stderr.log'].every(name => existsSync(join(f.evidence, name)))).toBe(true);
  expect(readFileSync(join(f.evidence, 'npm-install.stderr.log')).length, 'actual failed npm diagnostics are retained rather than replaced with an empty file').toBeGreaterThan(0);
  expect(files(join(f.evidence, 'npm-install-logs')).length).toBeGreaterThan(0);
  expect(f.validationCapture().status !== 0, 'failed setup verification prevents subsequent validation stages').toBe(true);
  expect(existsSync(f.marker), 'candidate code never begins after installation failure').toBe(false);
  f.finishInputAssertions();
});

for (const mutation of ['changed', 'missing', 'extra'] as const) {
  it(`CP-044/DEPENDENCY-SETUP Closing rejects ${mutation} dependency input`, async () => {
    const f = await fixture();
    expect(f.install().status).toBe(0);
    expect(f.install(true).status).toBe(0);
    if (mutation === 'changed') f.setValidation(`writeFileSync(${JSON.stringify(f.regular)}, 'different dependency bytes\\n');`);
    else if (mutation === 'missing') f.setValidation(`rmSync(${JSON.stringify(f.regular)});`);
    else f.setValidation(`writeFileSync(${JSON.stringify(join(dirname(f.regular), 'new-input.txt'))}, 'unregistered new dependency\\n');`);
    const result = f.validationCapture();
    expect(result.error).toBeUndefined();
    expect(existsSync(f.marker), 'candidate mutation executes after initial dependency authentication').toBe(true);
    expect(result.status !== null && result.status !== 0, 'dependency read-set cannot gain, lose or replace bytes at Closing').toBe(true);
    f.finishInputAssertions();
  });
}

for (const kind of ['escaping', 'dangling', 'cyclic'] as const) {
  it(`CP-044/DEPENDENCY-SETUP link verification rejects ${kind} replacement`, async () => {
    const f = await fixture();
    expect(f.install().status).toBe(0);
    const outside = join(f.parent, 'unauthenticated-target');
    if (kind === 'escaping') {
      mkdirSync(outside);
      writeFileSync(join(outside, 'input.txt'), 'not authenticated dependency input');
    }
    const target = kind === 'escaping' ? outside : kind === 'dangling' ? join(f.root, 'missing-target') : f.dependencyLink;
    f.setValidation(`unlinkSync(${JSON.stringify(f.dependencyLink)}); symlinkSync(${JSON.stringify(target)},
${JSON.stringify(f.dependencyLink)}, process.platform === 'win32' ? 'junction' : 'dir');`);
    const result = f.validationCapture();
    expect(result.error).toBeUndefined();
    expect(existsSync(f.marker), 'the candidate attempts each replacement after original contained-link authentication').toBe(true);
    expect(result.status !== null && result.status !== 0, 'unauthenticated, unresolved and cyclic dependency links fail closed').toBe(true);
    f.restoreDependencyLink(target);
    f.finishInputAssertions();
  });
}

it('CP-044/DEPENDENCY-SETUP originally excluded generated .vite output stays EGRESS and its original secret bytes are detected', async () => {
  const f = await fixture();
  expect(f.install().status).toBe(0);
  f.setValidation(`mkdirSync('node_modules/.vite', { recursive: true }); writeFileSync('node_modules/.vite/leaked.log', readFileSync(${JSON.stringify(f.source)}));`);
  const result = f.validationCapture();
  expect(result.error).toBeUndefined();
  expect(result.status !== null && result.status !== 0, 'generated dependency cache output cannot receive INPUT credit').toBe(true);
  const receipt = asRecord(JSON.parse(readFileSync(join(f.capture, 'receipt.json'), 'utf8')) as unknown, 'receipt');
  expect(receipt['result']).toMatchObject({ complete: true, leakFree: false });
  expect(objects(receipt['artifacts']).some(row => row['path'] === join(f.root, 'node_modules/.vite/leaked.log')
    && row['purpose'] === 'EGRESS' && row['sha256'] === sha(f.seed))).toBe(true);
  f.finishInputAssertions();
});

async function diagnosticFixture() {
  const parent = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'setup-diagnostic-'));
  const roots = ['temp', 'tmp', 'scratch', 'sources', 'evidence'].map(name => join(parent, name));
  for (const directory of roots) mkdirSync(directory, { mode: 0o700 });
  const permission = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as {
    assertPrivateDirectories: (paths: string[]) => Promise<void>;
  };
  await permission.assertPrivateDirectories(roots);
  const env = { ...childEnv(), TEMP: roots[0], TMP: roots[1], FLUXWARDEN_TEST_TMP: roots[2],
    FLUXWARDEN_SENTINEL_DIR: roots[3], FLUXWARDEN_EVIDENCE_DIR: roots[4] };
  let sequence = 0;
  return { parent, run(command: string, args: string[]) {
    const result = spawnSync(command, args, { cwd: parent, env, encoding: 'utf8', windowsHide: true, timeout: 10_000 });
    const id = String(sequence++);
    writeFileSync(join(parent, `${id}.stdout`), result.stdout);
    writeFileSync(join(parent, `${id}.stderr`), result.stderr);
    writeFileSync(join(parent, `${id}.status.json`), JSON.stringify({ status: result.status, signal: result.signal,
      error: result.error?.name ?? null }));
    return result;
  } };
}

it('CP-044/DEPENDENCY-SETUP recorder failures expose stable safe classification without private paths or error text', async () => {
  const f = await diagnosticFixture();
  const diagnostics = ['first-private-missing-root', 'second-private-missing-root'].map(name => {
    const privateRoot = join(f.parent, name);
    const result = f.run(process.execPath, [setup, 'verify', '--root', privateRoot]);
    expect(result.status !== null && result.status !== 0).toBe(true);
    const text = result.stdout + result.stderr;
    expect(text.includes(privateRoot) || text.includes(f.parent), 'public failure diagnostic does not disclose private path arguments').toBe(false);
    expect(/\b(?:Error:|ENOENT|at file:)|[\\/]/.test(text), 'raw filesystem errors and stack paths are private').toBe(false);
    expect(text.trim().length, 'failure still has an actionable stable classification').toBeGreaterThan(0);
    return text;
  });
  expect(diagnostics[0], 'same failure class is independent of private path and OS error text').toBe(diagnostics[1]);
});

// Adopted Windows CI ordering: authentic setup precedes Opening, and the actual
// database smoke then runs inside capture. Existing setup INPUT identities must
// survive that stage; recreating their ACLs after Opening is a mutation too.
if (process.platform === 'win32') it('CP-044/DEPENDENCY-SETUP Windows database preflight preserves the original authenticated setup namespace', async () => {
  const permission = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as {
    createPrivateDirectory: (parent: string, prefix: string) => Promise<string>;
    assertPrivateDirectories: (paths: string[]) => Promise<void>;
  };
  const base = testRoot('FLUXWARDEN_TEST_TMP');
  const parent = await permission.createPrivateDirectory(base, 'fluxwarden-ci-');
  const root = await permission.createPrivateDirectory(base, 'db-');
  const names = ['TEMP', 'TMP', 'FLUXWARDEN_TEST_TMP', 'FLUXWARDEN_SENTINEL_DIR', 'FLUXWARDEN_EVIDENCE_DIR', 'FLUXWARDEN_CI_CAPTURE_DIR'] as const;
  const roots: string[] = [];
  for (const prefix of ['ci-temp-', 'ci-tmp-', 'ci-tests-', 'ci-sentinels-', 'ci-evidence-', 'ci-capture-']) {
    roots.push(await permission.createPrivateDirectory(parent, prefix));
  }
  await permission.assertPrivateDirectories([parent, root, ...roots]);
  const env = { ...childEnv(), ...Object.fromEntries(names.map((name, index) => [name, roots[index]])),
    FLUXWARDEN_CI_OWNED_ROOT: parent, npm_config_offline: 'true' };
  const evidence = roots[4] ?? '', capture = roots[5] ?? '';
  const proof = join(root, 'command-proof');
  mkdirSync(proof);
  let sequence = 0;
  const run = (command: string, args: string[]) => {
    const result = spawnSync(command, args, { cwd: root, env, encoding: 'utf8', windowsHide: true, timeout: 60_000 });
    const id = String(sequence++);
    writeFileSync(join(proof, `${id}.stdout`), result.stdout);
    writeFileSync(join(proof, `${id}.stderr`), result.stderr);
    writeFileSync(join(proof, `${id}.status.json`), JSON.stringify({ status: result.status, signal: result.signal,
      error: result.error?.name ?? null }));
    return result;
  };
  const seed = randomBytes(32), source = join(root, 'test/control.bin');
  const built = files(join(repoRoot, 'dist'));
  expect(built.length, 'the real database smoke uses the already built current product').toBeGreaterThan(0);
  const support = ['private-scratch.mjs', 'leak-check.mjs', ...readdirSync(join(repoRoot, 'scripts')).filter(name => /^ci-.*\.mjs$/.test(name))];
  const inputs = [...built.map(path => ({ from: path, to: join(root, 'dist', path.slice(join(repoRoot, 'dist').length + 1)) })),
    ...support.map(name => ({ from: join(repoRoot, 'scripts', name), to: join(root, 'scripts', name) }))];
  declareFixturePaths([source, ...inputs.map(input => input.to)]);
  writeFileSync(join(proof, 'original-inputs.json'), JSON.stringify(inputs.map(input => ({ path: input.to, sha256: sha(readFileSync(input.from)) }))));
  cpSync(join(repoRoot, 'dist'), join(root, 'dist'), { recursive: true });
  mkdirSync(join(root, 'scripts'));
  for (const name of support) copyFileSync(join(repoRoot, 'scripts', name), join(root, 'scripts', name));
  expect(inputs.every(input => sha(readFileSync(input.from)) === sha(readFileSync(input.to))), 'fixture executes exact original built product and public tools').toBe(true);
  mkdirSync(join(root, 'test'));
  writeFileSync(source, seed, { mode: 0o600 });
  writeFileSync(join(root, 'test/sentinels.json'), JSON.stringify(['test/control.bin']));
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'owned-windows-database-preflight', version: '1.0.0', private: true, type: 'module' }));
  writeFileSync(join(root, 'package-lock.json'), JSON.stringify({ name: 'owned-windows-database-preflight', version: '1.0.0', lockfileVersion: 3,
    packages: { '': { name: 'owned-windows-database-preflight', version: '1.0.0' } } }));
  writeFileSync(join(root, '.gitignore'), 'node_modules/\ncommand-proof/\n');
  for (const args of [['init', '--quiet'], ['config', 'core.longpaths', 'true'], ['add', '--', '.gitignore', 'package.json', 'package-lock.json', 'test', 'scripts', 'dist'],
    ['-c', 'user.name=Database preflight fixture', '-c', 'user.email=fixture@invalid', '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'owned database preflight']]) {
    expect(run('git', args).status, 'real immutable fixture identity is established before setup').toBe(0);
  }
  declareFixtureCapture(capture, [seed], []);
  const installed = run(process.execPath, ownedCaptureToolArgs([join(root, 'scripts/ci-install.mjs'), '--root', root]));
  expect(installed.error).toBeUndefined();
  expect(installed.status, 'real offline trusted setup completes before Opening').toBe(0);
  const retained = [join(evidence, 'npm-install.stdout.log'), join(evidence, 'npm-install.stderr.log'), join(evidence, 'npm-install.json')];
  expect(retained.every(existsSync), 'both original setup channels and execution status pre-exist Opening').toBe(true);
  const namespace = (directory: string): string[] => [directory, ...readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? namespace(path) : [path];
  })];
  const original = namespace(evidence).sort();
  const snapshot = () => original.map(path => {
    const info = lstatSync(path, { bigint: true });
    return { path, device: String(info.dev), inode: String(info.ino), mode: String(info.mode),
      sddl: readWindowsSecurity(path, env).sddl,
      ...(info.isFile() ? { sha256: sha(readFileSync(path)), bytes: String(info.size), mtime: String(info.mtimeNs), ctime: String(info.ctimeNs) } : {}) };
  });
  const before = snapshot();
  for (const path of [parent, ...roots]) assertStrictWindowsOwnerOnly(readWindowsSecurity(path, env), 'directory');
  const result = run(process.execPath, ownedCaptureToolArgs([join(root, 'scripts/ci-capture.mjs'), '--root', root, '--capture-dir', capture, '--',
    process.execPath, join(root, 'scripts/ci-job.mjs'), '--commands-only', '--', 'node', join(root, 'scripts/ci-install.mjs'), 'verify', '--root', root,
    '--next', 'node', join(root, 'scripts/ci-database-check.mjs')]));
  expect(result.error).toBeUndefined();
  const receipt = asRecord(JSON.parse(readFileSync(join(capture, 'receipt.json'), 'utf8')) as unknown, 'database preflight receipt');
  expect(asRecord(receipt['result'], 'result')['exitCode'], 'actual database preflight completes its ownership and durability smoke checks').toBe(0);
  const after = snapshot();
  writeFileSync(join(proof, 'setup-namespace-comparison.json'), JSON.stringify({ before, after, result: receipt['result'] }));
  for (const path of [parent, ...roots]) assertStrictWindowsOwnerOnly(readWindowsSecurity(path, env), 'directory');
  expect(after, 'database preflight preserves authentic setup bytes, physical identities and original Windows security descriptors').toEqual(before);
  expect(result.status, 'the completed original database smoke also has valid Closing evidence').toBe(0);
  expect(receipt['result']).toMatchObject({ exitCode: 0, complete: true, leakFree: true });
  expect(run(process.execPath, ownedCaptureToolArgs([join(root, 'scripts/ci-capture.mjs'), 'verify', '--root', root, '--capture-dir', capture])).status).toBe(0);
}, 75_000);
