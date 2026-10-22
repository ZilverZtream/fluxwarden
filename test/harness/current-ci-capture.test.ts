// Sources: SECURITY INV-11; SPEC 12.2; RATCHET 6, 13 and 15. This is a
// finite, owned CI command boundary, not a claim about unrelated host files.
// Public contract: ci-capture.mjs --root ROOT --capture-dir PRIVATE -- COMMAND;
// ci-capture.mjs verify --root ROOT --capture-dir PRIVATE. Only safe receipts
// and scanned output are publishable; original source bytes remain private.
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, utimesSync, writeFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { asRecord, childEnv, readText, repoRoot } from '../helpers/cli.js';
import { testRoot } from '../helpers/env.js';
import { liveSentinelDetected, scanner } from '../helpers/leak-scan.js';
import { parseYaml } from '../helpers/yaml.js';
import { declareFixtureCapture, declareFixturePaths, ownedCaptureToolArgs } from '../helpers/capture-fixture.js';

const captureCli = join(repoRoot, 'scripts/ci-capture.mjs');
const digest = (bytes: Buffer | string): string => createHash('sha256').update(bytes).digest('hex');
function files(root: string): string[] {
  return readdirSync(root, { withFileTypes: true }).flatMap(entry => {
    const path = join(root, entry.name);
    return entry.isDirectory() ? files(path) : entry.isFile() ? [path] : [];
  });
}
function records(value: unknown, label: string): Record<string, unknown>[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value.map(item => asRecord(item, label));
}

function fixture() {
  const root = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'ci-owned-root-'));
  const sourceRoot = mkdtempSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), 'ci-owned-sources-'));
  const scratch = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'ci-owned-scratch-'));
  // Controlled negative evidence is outer scratch, but remains the inner
  // invocation's actual evidenceDir: its evidence-priority checks still apply.
  const evidence = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'ci-owned-evidence-'));
  const capture = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'ci-owned-capture-'));
  const temp = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'ci-owned-os-tmp-'));
  mkdirSync(join(root, 'test/sentinels'), { recursive: true });
  mkdirSync(join(root, 'scripts'));
  // Frozen public scanner is copied without editing. The synthetic checkout has
  // no product modules, lab or network endpoints and uses only disposable bytes.
  for (const name of ['leak-check.mjs', 'private-scratch.mjs']) copyFileSync(join(repoRoot, 'scripts', name), join(root, 'scripts', name));
  const seed = randomBytes(32), signature = randomBytes(32), der = randomBytes(39), runtime = randomBytes(32);
  const macaroon = Buffer.concat([Buffer.from([2, 1, 4, 9, 8, 7, 6, 0, 6, 32]), signature]);
  const pem = Buffer.from(`-----BEGIN PRIVATE KEY-----\n${der.toString('base64')}\n-----END PRIVATE KEY-----\n`);
  const source = join(root, 'test/sentinels/seed.bin');
  const macSource = join(sourceRoot, 'runtime-macaroon.bin'), pemSource = join(sourceRoot, 'runtime-key.pem');
  const runtimeSource = join(sourceRoot, 'runtime-created.bin');
  declareFixturePaths([source]);
  const plant = (path: string, bytes: string | Buffer, purpose: 'INPUT' | 'EGRESS' = 'EGRESS') => ({ path, bytes: Buffer.from(bytes), purpose });
  declareFixtureCapture(capture, [seed, macaroon, macaroon.subarray(1), signature, pem, der, runtime], [
    plant(join(scratch, 'owned.db'), seed), plant(join(scratch, 'deliberate-input.bin'), seed),
    plant(join(evidence, 'report.json'), seed), plant(join(evidence, 'report.json'), seed.toString('base64url')),
    plant(join(temp, 'child-temp.log'), seed.toString('hex')),
    plant(join(capture, 'stdout.log'), `ordinary child stdout\n${seed.toString('hex')}`),
    plant(join(capture, 'stdout.log'), `ordinary child stdout\n${runtime.toString('hex')}`),
    plant(join(capture, 'stderr.log'), `ordinary child stderr\n${seed.toString('base64')}`),
    plant(join(capture, 'stderr.log'), `ordinary child stderr\n${signature.toString('base64url')}`),
    plant(join(capture, 'unlisted-retained.log'), seed),
    plant(join(scratch, `${seed.toString('hex')}.log`), 'ordinary output'),
    plant(join(scratch, `${seed.toString('hex')}.bin`), 'ordinary output', 'INPUT'),
    plant(join(evidence, seed.toString('hex'), 'ordinary.log'), 'ordinary output'),
    plant(join(scratch, 'declared-out.txt'), `${join(scratch, `${seed.toString('hex')}.bin`)}\n`),
  ]);
  writeFileSync(source, seed, { mode: 0o600 });
  writeFileSync(macSource, macaroon, { mode: 0o600 });
  writeFileSync(pemSource, pem, { mode: 0o600 });
  writeFileSync(join(root, 'test/sentinels.json'), JSON.stringify(['test/sentinels/seed.bin']));
  writeFileSync(join(root, 'candidate.txt'), 'frozen synthetic candidate\n');
  const env = { ...childEnv(), TEMP: temp, TMP: temp, FLUXWARDEN_CI_FIXTURE_RUNTIME: runtime.toString('base64'), FLUXWARDEN_TEST_TMP: scratch,
    FLUXWARDEN_SENTINEL_DIR: sourceRoot, FLUXWARDEN_EVIDENCE_DIR: evidence };
  const git = (...args: string[]): string => {
    const result = spawnSync('git', args, { cwd: root, env, encoding: 'utf8', windowsHide: true, timeout: 10_000 });
    expect(result.status, 'synthetic checkout setup succeeds').toBe(0);
    return result.stdout.trim();
  };
  git('init', '--quiet');
  git('add', '--', 'candidate.txt', 'test/sentinels.json', 'test/sentinels/seed.bin',
    'scripts/leak-check.mjs', 'scripts/private-scratch.mjs');
  git('-c', 'user.name=CI contract fixture', '-c', 'user.email=fixture@invalid', '-c', 'commit.gpgsign=false',
    'commit', '--quiet', '-m', 'disposable capture fixture');
  const identity = { commit: git('rev-parse', 'HEAD'), tree: git('rev-parse', 'HEAD^{tree}') };
  const child = join(temp, 'command.mjs');
  const invoke = (verify = false, extraArgs: string[] = []) => spawnSync(process.execPath,
    [...ownedCaptureToolArgs([...extraArgs, captureCli, ...(verify ? ['verify'] : []), '--root', root, '--capture-dir', capture,
      ...(verify ? [] : ['--', process.execPath, child])])],
    { cwd: root, env, encoding: 'utf8', windowsHide: true, timeout: 10_000 });
  const script = (body: string, exitCode = 0) => { writeFileSync(child, `
import { readFileSync, writeFileSync, appendFileSync, rmSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
const scratch = process.env.FLUXWARDEN_TEST_TMP, evidence = process.env.FLUXWARDEN_EVIDENCE_DIR;
const sourceRoot = process.env.FLUXWARDEN_SENTINEL_DIR;
const capture = ${JSON.stringify(capture)};
const source = ${JSON.stringify(source)};
const bytes = readFileSync(source), signature = readFileSync(${JSON.stringify(macSource)}).subarray(-32);
writeFileSync(join(sourceRoot, 'runtime-created.bin'), Buffer.from(process.env.FLUXWARDEN_CI_FIXTURE_RUNTIME, 'base64'), { mode: 0o600 });
writeFileSync(join(scratch, 'owned.db'), 'ordinary scratch state');
writeFileSync(join(evidence, 'report.json'), JSON.stringify({ success: ${String(exitCode === 0)} }));
writeFileSync(join(process.env.TEMP, 'child-temp.log'), 'ordinary OS temporary output');
process.stdout.write('ordinary child stdout\\n'); process.stderr.write('ordinary child stderr\\n');
${body}
process.exitCode = ${String(exitCode)};
`); };
  script('');
  return { root, sourceRoot, scratch, evidence, capture, temp, source, runtimeSource, macSource, pemSource,
    seed, signature, der, macaroon, pem, identity, env, script, invoke, extraBytes: randomBytes(32),
    get runtime() { return readFileSync(runtimeSource); },
    receipt() { return asRecord(JSON.parse(readFileSync(join(capture, 'receipt.json'), 'utf8')) as unknown, 'safe receipt'); },
  };
}

// Node 24.21 fs.link, fs.linkSync and fsPromises.link create a new hard-link
// destination; they do not overwrite an existing destination. Source:
// https://nodejs.org/download/release/v24.21.0/docs/api/fs.html#fslinkexistingpath-newpath-callback
// SECURITY INV-11: declaration authority must precede the first destination write,
// independently of the source inode's existing recognition or input purpose.
const linkAdapter = (api: 'sync' | 'callback' | 'promise'): string => `
const { linkSync, link, unlinkSync, statSync, existsSync } = await import('node:fs');
const { link: promiseLink } = await import('node:fs/promises');
let callbackCount = 0;
async function createLink(from, to) {
 if (${JSON.stringify(api)} === 'sync') return linkSync(from, to);
 if (${JSON.stringify(api)} === 'promise') return promiseLink(from, to);
 return new Promise((resolve, reject) => link(from, to, error => {
  callbackCount++; if (error) reject(error); else resolve();
 }));
}
const stage = join(scratch, 'hardlink-stage.bin');
appendFileSync(join(scratch, 'declared-out.txt'), stage + '\\n');
writeFileSync(stage, bytes, { mode: 0o600 });
`;

for (const api of ['sync', 'callback', 'promise'] as const) {
  it(`CP-044/CI-LINK ${api} prospective hard-link destination retains observed INPUT bytes and ordinary semantics`, () => {
    const f = fixture(), destination = join(f.scratch, 'hardlink-input.bin');
    declareFixturePaths([join(f.scratch, 'hardlink-stage.bin'), destination]);
    writeFileSync(join(f.scratch, 'declared-out.txt'), '', { mode: 0o600 });
    f.script(`${linkAdapter(api)}
const destination = join(scratch, 'hardlink-input.bin');
appendFileSync(join(scratch, 'declared-out.txt'), destination + '\\n');
const returned = await createLink(stage, destination);
const original = statSync(stage), linked = statSync(destination);
const sharedInode = original.dev === linked.dev && original.ino === linked.ino && linked.nlink > 1;
unlinkSync(stage);
writeFileSync(join(evidence, 'link-control.json'), JSON.stringify({ callbackCount, sharedInode,
 returnedUndefined: returned === undefined, stageRemoved: !existsSync(stage), exactBytes: readFileSync(destination).equals(bytes) }));`);
    const result = f.invoke();
    expect(result.error, 'the ordinary capture deadline is unchanged').toBeUndefined();
    const control = asRecord(JSON.parse(readFileSync(join(f.evidence, 'link-control.json'), 'utf8')) as unknown, 'actual link result');
    expect(control).toEqual({ callbackCount: api === 'callback' ? 1 : 0, sharedInode: true,
      returnedUndefined: true, stageRemoved: true, exactBytes: true });
    expect(result.status, 'prospective declaration applies to the actual first hard-link destination write').toBe(0);
    const receipt = f.receipt();
    expect(receipt['result']).toMatchObject({ exitCode: 0, complete: true, leakFree: true, policySatisfied: true });
    expect(records(receipt['artifacts'], 'destination census').some(row => row['path'] === destination
      && row['purpose'] === 'INPUT' && row['sha256'] === digest(f.seed)), 'exact destination bytes have witnessed INPUT purpose').toBe(true);
    expect(f.invoke(true).status, 'independent verification accepts the retained prospective input').toBe(0);
  });

  it(`CP-044/CI-LINK ${api} undeclared late and existing destinations retain EGRESS and existing-file refusal`, () => {
    const f = fixture();
    const destinations = ['undeclared', 'late', 'existing'].map(kind => join(f.scratch, `hardlink-${kind}.bin`));
    // These exact deliberate negative artifacts are only outer fixture inputs;
    // the inner invocation receives the declaration ordering exercised below.
    declareFixturePaths([join(f.scratch, 'hardlink-stage.bin'), ...destinations]);
    writeFileSync(join(f.scratch, 'declared-out.txt'), '', { mode: 0o600 });
    f.script(`${linkAdapter(api)}
const undeclared = join(scratch, 'hardlink-undeclared.bin'), late = join(scratch, 'hardlink-late.bin');
const first = await createLink(stage, undeclared), second = await createLink(stage, late);
appendFileSync(join(scratch, 'declared-out.txt'), late + '\\n');
const existing = join(scratch, 'hardlink-existing.bin');
writeFileSync(existing, bytes, { mode: 0o600 });
const before = statSync(existing);
appendFileSync(join(scratch, 'declared-out.txt'), existing + '\\n');
let existingError = null;
try { await createLink(stage, existing); } catch (error) { existingError = error.code; }
const after = statSync(existing);
unlinkSync(stage);
writeFileSync(join(evidence, 'link-control.json'), JSON.stringify({ callbackCount, existingError,
 successfulReturnsUndefined: first === undefined && second === undefined,
 existingUnchanged: before.dev === after.dev && before.ino === after.ino && readFileSync(existing).equals(bytes) }));`);
    const result = f.invoke();
    expect(result.error, 'negative controls retain the ordinary capture deadline').toBeUndefined();
    const control = asRecord(JSON.parse(readFileSync(join(f.evidence, 'link-control.json'), 'utf8')) as unknown, 'negative link result');
    expect(control).toEqual({ callbackCount: api === 'callback' ? 3 : 0, existingError: 'EEXIST',
      successfulReturnsUndefined: true, existingUnchanged: true });
    expect(result.status !== null && result.status !== 0, 'source equality and later declarations cannot authorize output').toBe(true);
    const receipt = f.receipt();
    expect(receipt['result']).toMatchObject({ exitCode: 0, complete: true, leakFree: false, policySatisfied: false });
    const artifacts = records(receipt['artifacts'], 'negative destination census');
    for (const destination of destinations) expect(artifacts.some(row => row['path'] === destination
      && row['purpose'] === 'EGRESS' && row['sha256'] === digest(f.seed)), 'every original disclosure keeps its bytes and EGRESS purpose').toBe(true);
    expect(f.invoke(true).status !== 0, 'independent verification preserves the original disclosures').toBe(true);
  });

  it(`CP-044/CI-LINK ${api} rejects recorder-private source and destination operands without creating aliases`, () => {
    const f = fixture(), alias = join(f.scratch, 'private-source-alias.bin');
    declareFixturePaths([join(f.scratch, 'hardlink-stage.bin'), alias]);
    writeFileSync(join(f.scratch, 'declared-out.txt'), '', { mode: 0o600 });
    f.script(`${linkAdapter(api)}
const { createHash } = await import('node:crypto');
const protectedSource = join(capture, 'private/sources', createHash('sha256').update(bytes).digest('hex'));
const alias = join(scratch, 'private-source-alias.bin'), protectedDestination = join(capture, 'private/link-destination.bin');
let sourceDenied = false, destinationDenied = false;
try { await createLink(protectedSource, alias); } catch (error) { sourceDenied = error.code !== 'ENOENT'; }
try { await createLink(stage, protectedDestination); } catch (error) { destinationDenied = error.code !== 'ENOENT'; }
unlinkSync(stage);
writeFileSync(join(evidence, 'link-control.json'), JSON.stringify({ sourceDenied, destinationDenied,
 aliasAbsent: !existsSync(alias), privateDestinationAbsent: !existsSync(protectedDestination) }));`);
    const result = f.invoke();
    expect(result.error, 'private-operand controls retain the ordinary capture deadline').toBeUndefined();
    expect(asRecord(JSON.parse(readFileSync(join(f.evidence, 'link-control.json'), 'utf8')) as unknown, 'private operand results'))
      .toEqual({ sourceDenied: true, destinationDenied: true, aliasAbsent: true, privateDestinationAbsent: true });
    expect(readFileSync(join(f.capture, 'private/sources', digest(f.seed))).equals(f.seed), 'original private source remains unchanged').toBe(true);
    expect(result.status !== null && result.status !== 0, 'private namespace access remains a rejected invocation').toBe(true);
    expect(f.invoke(true).status !== 0, 'independent verification preserves private-namespace rejection').toBe(true);
  });
}

for (const exitCode of [0, 7]) {
  it(`CP-044/CI-CAPTURE clean finite command retains complete sources, output census and exact failure ${String(exitCode)}`, () => {
    const f = fixture();
    f.script('', exitCode);
    const result = f.invoke();
    expect(result.error === undefined, 'bounded finite capture completes').toBe(true);
    expect(result.status, 'capture preserves the child exit, including failure').toBe(exitCode);
    expect(existsSync(join(f.capture, 'receipt.json')), 'capture emits an independently recheckable safe receipt').toBe(true);
    const receipt = f.receipt();
    const identity = asRecord(receipt['identity'], 'candidate identity');
    expect(identity['before']).toMatchObject(f.identity);
    expect(identity['after']).toEqual(identity['before']);
    expect(receipt['result']).toMatchObject({ exitCode, complete: true, leakFree: true });
    const sources = records(receipt['sources'], 'input sources');
    const expectedSources = [f.seed, f.macaroon, f.macaroon.subarray(1), f.signature, f.pem, f.der, f.runtime];
    expect([...new Set(sources.map(row => row['sha256']))].sort(), 'full original and scanner-derived source union retained').toEqual(expectedSources.map(digest).sort());
    expect(sources.every(row => row['purpose'] === 'INPUT'), 'source purpose is explicit').toBe(true);
    const artifacts = records(receipt['artifacts'], 'owned output census');
    for (const path of [join(f.scratch, 'owned.db'), join(f.evidence, 'report.json'), join(f.temp, 'child-temp.log'),
      join(f.capture, 'stdout.log'), join(f.capture, 'stderr.log')]) {
      expect(artifacts.some(row => row['path'] === path && row['purpose'] === 'EGRESS' && row['sha256'] === digest(readFileSync(path))),
        'every owned output and failure channel has exact content identity').toBe(true);
    }
    expect(readFileSync(join(f.capture, 'stdout.log'), 'utf8')).toContain('ordinary child stdout');
    expect(readFileSync(join(f.capture, 'stderr.log'), 'utf8')).toContain('ordinary child stderr');
    const safe = Buffer.from(JSON.stringify(receipt) + result.stdout + result.stderr);
    expect(expectedSources.every(bytes => !safe.includes(bytes) && !safe.includes(bytes.toString('hex')) && !safe.includes(bytes.toString('base64'))),
      'receipt and wrapper diagnostics contain fingerprints rather than raw sources').toBe(true);
    expect(f.invoke(true).status, 'a complete failure receipt is valid evidence without changing its failed result').toBe(0);
  });
}

const leakCases = [
  ['stdout', "process.stdout.write(bytes.toString('hex'))"],
  ['stderr on failure', "process.stderr.write(bytes.toString('base64'))"],
  ['scratch database', "writeFileSync(join(scratch, 'owned.db'), bytes)"],
  ['capture-root unlisted retained file', "writeFileSync(join(capture, 'unlisted-retained.log'), bytes)"],
  ['retained evidence', "writeFileSync(join(evidence, 'report.json'), bytes.toString('base64url'))"],
  ['OS temporary output', "writeFileSync(join(process.env.TMP, 'child-temp.log'), bytes.toString('hex'))"],
  ['artifact name', "writeFileSync(join(scratch, bytes.toString('hex') + '.log'), 'ordinary output')"],
  ['artifact parent path', "mkdirSync(join(evidence, bytes.toString('hex'))); writeFileSync(join(evidence, bytes.toString('hex'), 'ordinary.log'), 'ordinary output')"],
  ['derived macaroon signature', "process.stderr.write(signature.toString('base64url'))"],
  ['new runtime registration', "process.stdout.write(readFileSync(join(sourceRoot, 'runtime-created.bin')).toString('hex'))"],
  ['declared evidence cannot become input', "appendFileSync(join(scratch, 'declared-out.txt'), join(evidence, 'report.json') + '\\n'); writeFileSync(join(evidence, 'report.json'), bytes)"],
  ['declaration text', "appendFileSync(join(scratch, 'declared-out.txt'), join(scratch, bytes.toString('hex') + '.bin') + '\\n'); writeFileSync(join(scratch, bytes.toString('hex') + '.bin'), 'ordinary output')"],
  ['wildcard declaration cannot widen inputs', "writeFileSync(join(scratch, 'declared-out.txt'), join(scratch, '*') + '\\n'); writeFileSync(join(scratch, 'owned.db'), bytes)"],
] as const;
for (const [label, body] of leakCases) {
  it(`CP-044/CI-CAPTURE rejects ${label} through the unchanged detector and retains failure evidence`, () => {
    const f = fixture();
    f.script(body, label === 'stderr on failure' ? 7 : 0);
    const result = f.invoke();
    expect(result.error === undefined, 'leak rejection finishes inside ordinary deadline').toBe(true);
    expect(result.status !== null && result.status !== 0, 'a leaking finite invocation cannot pass').toBe(true);
    expect(existsSync(join(f.capture, 'receipt.json')), 'failed capture retains a safe, truthful receipt').toBe(true);
    expect(f.receipt()['result']).toMatchObject({ complete: true, leakFree: false });
    const published = Buffer.from(result.stdout + result.stderr + JSON.stringify(f.receipt()));
    expect([f.seed, f.signature, f.runtime].every(bytes => !published.includes(bytes) && !published.includes(bytes.toString('hex')) && !published.includes(bytes.toString('base64url'))),
      'failure receipt and diagnostics never echo planted secret values or unsafe names').toBe(true);
    expect(existsSync(join(f.capture, 'stdout.log')) && existsSync(join(f.capture, 'stderr.log')) && existsSync(join(f.scratch, 'owned.db')),
      'original failed outputs remain privately available').toBe(true);
  });
}

it('CP-044/CI-CAPTURE exact declaration excludes only its intended scratch input and remains auditable', () => {
  const f = fixture(), declared = join(f.scratch, 'deliberate-input.bin');
  writeFileSync(join(f.scratch, 'declared-out.txt'), `${declared}\n`, { mode: 0o600 });
  f.script("writeFileSync(join(scratch, 'deliberate-input.bin'), bytes)");
  const result = f.invoke();
  expect(result.status, 'existing exact deliberate input declaration is respected').toBe(0);
  const artifacts = records(f.receipt()['artifacts'], 'artifacts');
  expect(artifacts.some(row => row['path'] === declared && row['purpose'] === 'INPUT' && row['sha256'] === digest(f.seed)),
    'declared input still has exact path, content and purpose identity').toBe(true);
  expect(artifacts.some(row => row['path'] === join(f.scratch, 'declared-out.txt') && row['purpose'] === 'DECLARATION'),
    'the declaration itself is retained and checked as output').toBe(true);
  expect(f.invoke(true).status).toBe(0);
});

for (const channel of ['source', 'artifact'] as const) {
  for (const mutation of ['lost', 'extra', 'changed', 'unreadable'] as const) {
    it(`CP-044/CI-CAPTURE recheck rejects ${mutation} ${channel} after a complete clean capture`, () => {
      const f = fixture();
      expect(f.invoke().status, 'clean capture baseline succeeds before tampering').toBe(0);
      const path = channel === 'source' ? f.runtimeSource : join(f.scratch, 'owned.db');
      let preload: string | undefined;
      if (mutation === 'lost') rmSync(path);
      else if (mutation === 'extra') writeFileSync(join(dirname(path), 'unexpected.bin'), f.extraBytes);
      else if (mutation === 'changed') {
        const before = statSync(path), bytes = readFileSync(path);
        bytes[0] = (bytes[0] ?? 0) ^ 1;
        writeFileSync(path, bytes); utimesSync(path, before.atime, before.mtime);
      } else {
        // Inject ordinary filesystem EIO rather than relying on platform ACL
        // semantics or making a test inaccessible to its owning user.
        preload = join(mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'ci-readfault-')), 'unreadable.mjs');
        writeFileSync(preload, `import fs from 'node:fs'; import fsp from 'node:fs/promises'; import { syncBuiltinESMExports } from 'node:module';
const target = ${JSON.stringify(resolve(path))};
const fault = () => { const error = new Error('owned file read failed'); error.code = 'EIO'; throw error; };
for (const name of ['readFileSync', 'openSync']) { const original = fs[name]; fs[name] = function(path, ...args) { return String(path) === target ? fault() : original.call(this, path, ...args); }; }
for (const name of ['readFile', 'open']) { const original = fsp[name]; fsp[name] = async function(path, ...args) { return String(path) === target ? fault() : original.call(this, path, ...args); }; }
syncBuiltinESMExports();`);
      }
      const result = f.invoke(true, preload ? ['--import', preload] : []);
      expect(result.error === undefined, 'recheck does not time out').toBe(true);
      expect(result.status !== null && result.status !== 0, 'incomplete or changed census cannot be accepted').toBe(true);
    });
  }
}

it('CP-044/CI-CAPTURE original registered source loss or replacement and candidate changes cannot become clean completion', () => {
  for (const body of ["rmSync(source)", "writeFileSync(source, Buffer.alloc(bytes.length, 19))", "writeFileSync('candidate.txt', 'different candidate bytes\\n')"]) {
    const f = fixture(); f.script(body);
    const result = f.invoke();
    expect(result.status !== null && result.status !== 0, 'source loss or before/after candidate drift fails closed').toBe(true);
    expect(existsSync(join(f.capture, 'receipt.json')), 'incomplete invocation retains a safe receipt').toBe(true);
    expect(asRecord(f.receipt()['result'], 'result')['complete']).toBe(false);
  }
});

it('CP-044/CI-CAPTURE initial checkout identity includes a tracked deletion already staged before capture', () => {
  const f = fixture(), deleted = join(f.root, 'candidate.txt');
  const git = (...args: string[]) => spawnSync('git', args, {
    cwd: f.root, env: f.env, encoding: 'utf8', windowsHide: true, timeout: 10_000,
  });
  expect(git('rm', '--quiet', '--', 'candidate.txt').status).toBe(0);
  expect(existsSync(deleted), 'tracked deletion is present on disk before Opening').toBe(false);
  const tree = git('write-tree');
  expect(tree.status).toBe(0);
  const expectedTree = tree.stdout.trim();
  expect(expectedTree, 'Git independently identifies the changed initial checkout tree').not.toBe(f.identity.tree);
  const result = f.invoke();
  expect(result.error).toBeUndefined();
  expect(result.status, 'an unchanged staged checkout is valid without an invented clean-index precondition').toBe(0);
  const identity = asRecord(f.receipt()['identity'], 'actual checkout identity');
  expect(identity['before'], 'Opening describes the actual checkout including its staged deletion')
    .toMatchObject({ commit: f.identity.commit, tree: expectedTree });
  expect(identity['after'], 'unchanged Closing read-set has the same actual checkout identity').toEqual(identity['before']);
  expect(existsSync(deleted), 'the deleted path is not recreated to match historical HEAD').toBe(false);
});

it('CP-044/CI-CAPTURE recheck refuses expanded source declarations and missing failure channels', () => {
  for (const target of ['declared-out.txt', 'stdout.log', 'stderr.log']) {
    const f = fixture();
    writeFileSync(join(f.scratch, 'declared-out.txt'), '');
    expect(f.invoke().status).toBe(0);
    if (target === 'declared-out.txt') appendFileSync(join(f.scratch, target), `${join(f.scratch, 'owned.db')}\n`);
    else rmSync(join(f.capture, target));
    const rechecked = f.invoke(true);
    expect(rechecked.error, 'negative verification completes within its original child deadline').toBeUndefined();
    expect(rechecked.signal, 'negative verification exits normally').toBeNull();
    expect(typeof rechecked.status, 'negative verification reports a completed numeric exit status').toBe('number');
    expect(rechecked.status !== 0, 'expanded input contexts or omitted original output streams cannot pass').toBe(true);
  }
}, 240_000);

it('CP-044/CI-CAPTURE live positive control retains its originally registered source through completion', async () => {
  const f = fixture(), before = new Set(files(f.sourceRoot));
  const leakScanner = await scanner();
  expect(liveSentinelDetected(leakScanner, { root: f.root, sentinelDir: f.sourceRoot,
    sentinels: join(f.root, 'test/sentinels.json'), testTmp: f.scratch, evidenceDir: f.evidence, paths: [] })).toBe(true);
  const retained = files(f.sourceRoot).filter(path => !before.has(path));
  expect(retained.length, 'the actual live positive-control registration must survive the invocation for final full-union scan').toBeGreaterThan(0);
  expect(retained.every(path => readFileSync(path).length > 0), 'retained positive-control sources are readable and nonempty').toBe(true);
});

it('CP-044/CI-CAPTURE every current hosted job captures commands before a final always-run verification and safe upload', () => {
  const jobs = asRecord(asRecord(parseYaml(readText('.github/workflows/ci.yml')), 'workflow')['jobs'], 'jobs');
  for (const name of ['test', 'lab', 'chaos']) {
    const stepsValue = asRecord(jobs[name], name)['steps'];
    const steps = records(stepsValue, `${name} steps`);
    const commandSteps = steps.filter(step => typeof step['run'] === 'string' && /\bnpm (?:test\b|run test:(?:harness|lab|chaos)\b)/.test(step['run']));
    expect(commandSteps.length, 'current real test commands remain selected').toBeGreaterThan(0);
    for (const step of commandSteps) expect(String(step['run']), `${name}: each real command enters the finite capture boundary`).toMatch(/scripts\/ci-capture\.mjs\b/);
    const lastCommand = Math.max(...commandSteps.map(step => steps.indexOf(step)));
    const verification = steps.findIndex((step, index) => index > lastCommand && typeof step['run'] === 'string' && /ci-capture\.mjs\s+verify\b/.test(step['run']));
    expect(verification, `${name}: final invocation census verification follows generated outputs`).toBeGreaterThan(lastCommand);
    expect(String(steps[verification]?.['if']), `${name}: failures still receive final verification`).toMatch(/always\(\)/);
    const uploads = steps.filter(step => typeof step['uses'] === 'string' && step['uses'].startsWith('actions/upload-artifact@'));
    expect(uploads.length, `${name}: safe receipt is retained`).toBeGreaterThan(0);
    for (const step of uploads) {
      expect(steps.indexOf(step), 'safe upload follows final verification').toBeGreaterThan(verification);
      const options = asRecord(step['with'], 'upload options');
      expect(options['if-no-files-found']).toBe('error');
      expect(String(options['path']), 'raw source roots are never upload paths').not.toMatch(/SENTINEL|sentinel|sources|inputs/i);
      expect(String(step['if']), 'upload is conditional on successful final verification').toMatch(/success/);
    }
  }
});

it('CP-044/CI-CAPTURE clean unlisted capture-root files have complete content identity and reject tampering', () => {
  const f = fixture(), retained = join(f.capture, 'unlisted-retained.log');
  f.script("writeFileSync(join(capture, 'unlisted-retained.log'), 'ordinary retained output')");
  expect(f.invoke().status, 'ordinary retained output remains a successful finite invocation').toBe(0);
  const artifacts = records(f.receipt()['artifacts'], 'complete retained output census');
  expect(artifacts.some(row => row['path'] === retained && row['purpose'] === 'EGRESS' && row['sha256'] === digest('ordinary retained output')),
    'an arbitrary retained capture-root file is included with its actual content identity').toBe(true);
  expect(f.invoke(true).status, 'complete retained output verifies before mutation').toBe(0);
  const original = statSync(retained), changed = readFileSync(retained);
  changed[0] = (changed[0] ?? 0) ^ 1;
  writeFileSync(retained, changed);
  utimesSync(retained, original.atime, original.mtime);
  const recheck = f.invoke(true);
  expect(recheck.error === undefined, 'changed retained output recheck finishes inside its ordinary deadline').toBe(true);
  expect(recheck.status !== null && recheck.status !== 0, 'equal-size retained-file replacement cannot preserve a valid capture').toBe(true);
});

it('CP-044/CI-CAPTURE descriptor-created and replaced runtime sources retain both originals and reject earlier stdout', () => {
  const f = fixture(), first = randomBytes(32), replacement = randomBytes(32);
  f.env['FLUXWARDEN_CI_FIXTURE_DESCRIPTOR_FIRST'] = first.toString('base64');
  f.env['FLUXWARDEN_CI_FIXTURE_DESCRIPTOR_REPLACEMENT'] = replacement.toString('base64');
  declareFixtureCapture(f.capture, [first, replacement], [{ path: join(f.capture, 'stdout.log'), bytes: Buffer.from(`ordinary child stdout\n${first.toString('hex')}`) }]);
  f.script(`const { openSync, writeSync, closeSync } = await import('node:fs');
const first = Buffer.from(process.env.FLUXWARDEN_CI_FIXTURE_DESCRIPTOR_FIRST, 'base64');
const replacement = Buffer.from(process.env.FLUXWARDEN_CI_FIXTURE_DESCRIPTOR_REPLACEMENT, 'base64');
const registered = join(sourceRoot, 'descriptor-source.bin');
let descriptor = openSync(registered, 'w', 0o600); writeSync(descriptor, first); closeSync(descriptor);
process.stdout.write(first.toString('hex'));
descriptor = openSync(registered, 'w', 0o600); writeSync(descriptor, replacement); closeSync(descriptor);`);
  const result = f.invoke();
  expect(result.error === undefined, 'descriptor lifetime capture finishes within the existing deadline').toBe(true);
  expect(result.status !== null && result.status !== 0, 'replacement cannot erase the original runtime source from leak detection').toBe(true);
  const receipt = f.receipt(), sources = records(receipt['sources'], 'complete source lifetimes');
  expect(receipt['result']).toMatchObject({ complete: true, leakFree: false });
  for (const bytes of [first, replacement]) {
    expect(sources.some(row => row['purpose'] === 'INPUT' && row['sha256'] === digest(bytes)),
      'both descriptor source lifetimes retain original INPUT bytes').toBe(true);
  }
  expect(readFileSync(join(f.capture, 'stdout.log'), 'utf8').includes(first.toString('hex')),
    'the original failed stdout is retained privately without rewriting its contents').toBe(true);
  const published = Buffer.from(result.stdout + result.stderr + JSON.stringify(receipt));
  expect([first, replacement].every(bytes => !published.includes(bytes) && !published.includes(bytes.toString('hex')) && !published.includes(bytes.toString('base64'))),
    'safe receipts and diagnostics disclose no source lifetime values').toBe(true);
});

it('CP-044/CI-CAPTURE runtime declarations must precede disclosure and cannot retrospectively turn EGRESS into INPUT', () => {
  // The existing exact-declaration control declares before command start. This
  // positive control establishes that a declaration made during the command is
  // valid when it precedes the first write to the exact deliberate input path.
  const prospective = fixture(), input = join(prospective.scratch, 'deliberate-input.bin');
  writeFileSync(join(prospective.scratch, 'declared-out.txt'), '', { mode: 0o600 });
  prospective.script(`const input = join(scratch, 'deliberate-input.bin');
appendFileSync(join(scratch, 'declared-out.txt'), input + '\\n');
writeFileSync(input, bytes);`);
  const beforeWrite = prospective.invoke();
  expect(beforeWrite.error === undefined, 'prospective runtime declaration finishes inside the ordinary deadline').toBe(true);
  expect(beforeWrite.status, 'runtime declaration before the write permits the exact intended input').toBe(0);
  const positiveReceipt = prospective.receipt();
  expect(positiveReceipt['result']).toMatchObject({ complete: true, leakFree: true });
  expect(records(positiveReceipt['artifacts'], 'prospective input census').some(row => row['path'] === input &&
    row['purpose'] === 'INPUT' && row['sha256'] === digest(prospective.seed)), 'prospective input has its actual content and authorized purpose').toBe(true);

  const late = fixture(), disclosed = join(late.scratch, 'deliberate-input.bin');
  writeFileSync(join(late.scratch, 'declared-out.txt'), '', { mode: 0o600 });
  // The only ordering difference is that the original registered bytes reach
  // ordinary output before this path is appended to the initially empty list.
  late.script(`const output = join(scratch, 'deliberate-input.bin');
writeFileSync(output, bytes);
appendFileSync(join(scratch, 'declared-out.txt'), output + '\\n');`);
  const afterWrite = late.invoke();
  expect(afterWrite.error === undefined, 'retrospective-purpose rejection finishes inside the ordinary deadline').toBe(true);
  const receipt = late.receipt(), result = asRecord(receipt['result'], 'late-declaration result');
  const artifact = records(receipt['artifacts'], 'original disclosure census').find(row => row['path'] === disclosed);
  expect({ rejected: afterWrite.status !== null && afterWrite.status !== 0, complete: result['complete'],
    leakFree: result['leakFree'], originalPurpose: artifact?.['purpose'] },
  'a later declaration cannot grant input purpose to a prior secret disclosure').toEqual({ rejected: true, complete: true, leakFree: false, originalPurpose: 'EGRESS' });
  expect(late.invoke(true).status !== 0, 'the retained original disclosure cannot receive a successful final verification').toBe(true);
});

it('CP-044/CI-CAPTURE ordinary child writes cannot replace recorder authorization and gain INPUT credit', () => {
  const f = fixture(), disclosed = join(f.scratch, 'deliberate-input.bin');
  writeFileSync(join(f.scratch, 'declared-out.txt'), '', { mode: 0o600 });
  // Routed recorder-integrity regression: the child performs only ordinary
  // synchronous filesystem writes against its owned synthetic invocation.
  f.script(`const { createHash } = await import('node:crypto');
const fingerprint = value => createHash('sha256').update(value).digest('hex');
const output = join(scratch, 'deliberate-input.bin'), declaration = join(scratch, 'declared-out.txt');
writeFileSync(output, bytes);
appendFileSync(declaration, output + '\\n');
const pathSha256 = fingerprint(output);
writeFileSync(join(capture, 'private/authorizations', pathSha256 + '.json'), JSON.stringify({
 pathSha256, purpose: 'INPUT', declarationSha256: fingerprint(readFileSync(declaration))
}));`);
  const run = f.invoke();
  expect(run.error === undefined, 'recorder-integrity control finishes within the unchanged deadline').toBe(true);
  const receipt = f.receipt(), result = asRecord(receipt['result'], 'recorder-integrity result');
  const artifacts = Array.isArray(receipt['artifacts']) ? records(receipt['artifacts'], 'retained original artifact purposes') : [];
  const verification = f.invoke(true);
  expect(verification.error === undefined, 'recorder-integrity recheck finishes within the unchanged deadline').toBe(true);
  expect({ rejected: run.status !== null && run.status !== 0, verificationRejected: verification.status !== null && verification.status !== 0,
    gainedInputCredit: artifacts.some(row => row['path'] === disclosed && row['purpose'] === 'INPUT'),
    trustedCleanReceipt: result['complete'] === true && result['leakFree'] === true },
  'child-controlled recorder mutations fail closed without granting retrospective input purpose').toEqual({
    rejected: true, verificationRejected: true, gainedInputCredit: false, trustedCleanReceipt: false,
  });
  expect(readFileSync(disclosed).equals(f.seed), 'the original failed output remains privately retained').toBe(true);
  const published = Buffer.from(run.stdout + run.stderr + verification.stdout + verification.stderr + JSON.stringify(receipt));
  expect(!published.includes(f.seed) && !published.includes(f.seed.toString('hex')) && !published.includes(f.seed.toString('base64')),
    'safe failure receipts and diagnostics never publish the registered synthetic value').toBe(true);
});

it('CP-044/CI-CAPTURE individual custody removal cannot erase a runtime source already disclosed to stdout', () => {
  const f = fixture(), original = randomBytes(32), registered = join(f.sourceRoot, 'removed-runtime-source.bin');
  expect(existsSync(registered), 'this independent runtime source is absent before command start').toBe(false);
  f.env['FLUXWARDEN_CI_FIXTURE_REMOVAL_SOURCE'] = original.toString('base64');
  declareFixtureCapture(f.capture, [original], [{ path: join(f.capture, 'stdout.log'), bytes: Buffer.from(`ordinary child stdout\n${original.toString('hex')}`) }]);
  f.script(`const { readdirSync, existsSync } = await import('node:fs');
const { createHash } = await import('node:crypto');
const original = Buffer.from(process.env.FLUXWARDEN_CI_FIXTURE_REMOVAL_SOURCE, 'base64');
const registered = join(sourceRoot, 'removed-runtime-source.bin');
writeFileSync(registered, original, { mode: 0o600 });
process.stdout.write(original.toString('hex'));
const fingerprint = createHash('sha256').update(original).digest('hex');
rmSync(registered);
let matchedRecords = 0;
for (const name of readdirSync(join(capture, 'private/records'))) {
 const record = join(capture, 'private/records', name), context = JSON.parse(readFileSync(record, 'utf8'));
 if (context.path === registered && context.sha256 === fingerprint && context.purpose === 'INPUT') {
  matchedRecords++;
  rmSync(record);
  rmSync(join(capture, 'private/identities', name.replace(/\\.json$/, '.jsonl')), { force: true });
 }
}
rmSync(join(capture, 'private/bytes', fingerprint), { force: true });
rmSync(join(capture, 'private/sources', fingerprint), { force: true });
writeFileSync(join(scratch, 'custody-removal-control.json'), JSON.stringify({ matchedRecords, originalSourceRemoved: !existsSync(registered) }));`);
  const run = f.invoke();
  expect(run.error === undefined, 'custody-removal control finishes within the unchanged deadline').toBe(true);
  const receipt = f.receipt(), result = asRecord(receipt['result'], 'custody-removal result');
  const sources = Array.isArray(receipt['sources']) ? records(receipt['sources'], 'retained source lifetimes') : [];
  const verification = f.invoke(true);
  expect(verification.error === undefined, 'custody-removal verification finishes within the unchanged deadline').toBe(true);
  expect({ rejected: run.status !== null && run.status !== 0, verificationRejected: verification.status !== null && verification.status !== 0,
    trustedCleanReceipt: result['complete'] === true && result['leakFree'] === true,
    sourceRetainedOrLifecycleUnestablished: sources.some(row => row['purpose'] === 'INPUT' && row['sha256'] === digest(original)) || result['complete'] === false },
  'individual custody loss fails closed and never establishes a clean invocation with a forgotten source').toEqual({
    rejected: true, verificationRejected: true, trustedCleanReceipt: false, sourceRetainedOrLifecycleUnestablished: true,
  });
  expect(readFileSync(join(f.capture, 'stdout.log'), 'utf8').includes(original.toString('hex')),
    'the original disclosed stdout remains privately retained').toBe(true);
  const published = Buffer.from(run.stdout + run.stderr + verification.stdout + verification.stderr + JSON.stringify(receipt));
  expect(!published.includes(original) && !published.includes(original.toString('hex')) && !published.includes(original.toString('base64')),
    'safe receipts and diagnostics disclose no runtime source value').toBe(true);
});

// D29 owner-delegated failure-diagnostic contract: optional details contains
// bounded report metadata and hashed exceptions, never report strings. These
// exercise the public command and its real retained report, not a parser import.
function failureDetails(result: { stdout: string; stderr: string }): Record<string, unknown> {
  const envelopes = [result.stdout, result.stderr].flatMap(stream => stream.split(/\r?\n/).flatMap(line => {
    try {
      const value = JSON.parse(line) as unknown;
      return value !== null && typeof value === 'object' && 'details' in value ? [asRecord(value, 'failure envelope')] : [];
    } catch { return []; }
  }));
  expect(envelopes.length, 'one public failure envelope carries bounded diagnostic metadata').toBe(1);
  const details = asRecord(envelopes[0]?.['details'], 'safe failure details');
  expect(Array.isArray(details['reports']) && Array.isArray(details['errors']), 'diagnostics use fixed report and error arrays').toBe(true);
  return details;
}
function failureReport(details: Record<string, unknown>): Record<string, unknown> {
  const reports = records(details['reports'], 'safe report metadata').filter(row => row['report'] === 'vitest-harness.json');
  expect(reports.length, 'the report is identified by its fixed basename').toBe(1);
  return reports[0] ?? {};
}
function diagnosticFixture() {
  const f = fixture(), relativeFile = 'test/diagnostic.test.mjs';
  const vitest = pathToFileURL(join(repoRoot, 'node_modules/vitest/dist/index.js')).href;
  writeFileSync(join(f.root, relativeFile), `import { expect, it } from ${JSON.stringify(vitest)};
it('bounded passing control', () => expect(true).toBe(true));
it('bounded failure control', () => {
  throw Object.assign(new Error('bounded fixture failure'), { code: 'ETIMEDOUT' });
});\n`);
  writeFileSync(join(f.root, 'vitest.config.mjs'), `export default { test: { include: ['${relativeFile}'],
allowOnly: false, passWithNoTests: false, maxWorkers: 1, fileParallelism: false } };\n`);
  for (const args of [['add', '--', relativeFile, 'vitest.config.mjs'],
    ['-c', 'user.name=CI diagnostic fixture', '-c', 'user.email=fixture@invalid', '-c', 'commit.gpgsign=false',
      'commit', '--quiet', '-m', 'tracked diagnostic test source']]) {
    const result = spawnSync('git', args, { cwd: f.root, env: f.env, encoding: 'utf8', windowsHide: true, timeout: 10_000 });
    expect(result.status, 'diagnostic source provenance uses explicit tracked fixture inputs').toBe(0);
  }
  return Object.assign(f, { relativeFile, reportPath: join(f.evidence, 'vitest-harness.json') });
}

it('CP-044/CI-DIAGNOSTIC actual failed Vitest report exposes counts and hashes with a tracked source frame', () => {
  const f = diagnosticFixture();
  f.script(`const { spawnSync } = await import('node:child_process');
const run = spawnSync(process.execPath, ${JSON.stringify([join(repoRoot, 'scripts/ci-test-driver.mjs'), 'run',
    '--config', join(f.root, 'vitest.config.mjs'), '--root', f.root, '--maxWorkers=1', '--fileParallelism=false',
    '--reporter=json', `--outputFile.json=${f.reportPath}`])},
 { cwd: ${JSON.stringify(f.root)}, env: process.env, encoding: 'utf8', windowsHide: true, timeout: 10000 });
process.stdout.write(run.stdout ?? ''); process.stderr.write(run.stderr ?? '');
writeFileSync(join(evidence, 'driver-status.json'), JSON.stringify({ status: run.status, signal: run.signal, error: run.error?.name ?? null }));
writeFileSync(join(scratch, 'owned.db'), bytes);`, 1);
  const result = f.invoke();
  expect(result.error, 'actual worker and capture retain their original deadline').toBeUndefined();
  expect(result.status, 'the real failing test exit remains the command result').toBe(1);
  expect(JSON.parse(readFileSync(join(f.evidence, 'driver-status.json'), 'utf8')) as unknown).toEqual({ status: 1, signal: null, error: null });
  const reportBytes = readFileSync(f.reportPath), original = asRecord(JSON.parse(reportBytes.toString()) as unknown, 'actual failed report');
  expect({ passed: original['numPassedTests'], failed: original['numFailedTests'], pending: original['numPendingTests'] })
    .toEqual({ passed: 1, failed: 1, pending: 0 });
  const failures = records(records(original['testResults'], 'actual suites')[0]?.['assertionResults'], 'actual assertions')
    .filter(row => row['status'] === 'failed');
  expect(failures.length).toBe(1);
  const failed = failures[0] ?? {}, messages = failed['failureMessages'];
  if (!Array.isArray(messages) || !messages.every(message => typeof message === 'string')) throw new Error('actual failure messages are required');
  expect(f.receipt()['result']).toMatchObject({ exitCode: 1, leakFree: false, policySatisfied: false });
  const verification = f.invoke(true);
  expect(verification.status !== null && verification.status !== 0, 'actual failed-report diagnostics cannot excuse the deliberate source disclosure').toBe(true);
  const metadata = failureReport(failureDetails(result));
  expect(metadata).toMatchObject({ status: 'OK', passed: 1, failed: 1, pending: 0, sha256: digest(reportBytes) });
  const rows = records(metadata['failures'], 'failed case metadata');
  expect(rows).toHaveLength(1);
  expect(rows[0]).toMatchObject({ titleSha256: digest(String(failed['fullName'])), messageSha256: digest(messages.join('\n')),
    file: f.relativeFile, line: 4 });
  expect(Number.isSafeInteger(rows[0]?.['column']) && Number(rows[0]?.['column']) > 0, 'actual tracked source column is a bounded positive integer').toBe(true);
  expect(JSON.stringify(metadata).includes('bounded fixture failure') || JSON.stringify(metadata).includes('bounded failure control')
    || JSON.stringify(metadata).includes(f.root), 'raw title, exception and absolute frame path remain private').toBe(false);
}, 15_000);

it('CP-044/CI-DIAGNOSTIC poisoned report fields stay hashed and untracked frames cannot become public source paths', () => {
  const f = diagnosticFixture(), marker = 'REPLACE_FIXTURE_SECRET';
  const suites = Array.from({ length: 17 }, (_, index) => {
    const path = index === 0 ? `${f.root}/../${marker}/escape.test.mjs` : `${f.root}/test/${marker}-${String(index)}.test.mjs`;
    return { name: path, status: 'failed', assertionResults: [{ fullName: `${marker} title ${String(index)}`, title: `${marker} title ${String(index)}`,
      status: 'failed', failureMessages: [`Error: ENOENT: ${marker} private message UNKNOWN_FIXTURE_CODE\n    at ${path}:4:9`] }] };
  });
  const template = { numPassedTests: 0, numFailedTests: 17, numPendingTests: 0, success: false, testResults: suites };
  const reportBytes = Buffer.from(JSON.stringify(template).replaceAll(marker, f.seed.toString('hex')));
  // Known synthetic poison stays inner EGRESS. Only these exact original bytes
  // and retained copies belong to the outer fixture's prospective INPUT setup.
  declareFixtureCapture(f.capture, [], [{ path: f.reportPath, bytes: reportBytes }]);
  f.script(`const report = JSON.parse(${JSON.stringify(JSON.stringify(template))}.replaceAll(${JSON.stringify(marker)}, bytes.toString('hex')));
writeFileSync(join(evidence, 'vitest-harness.json'), JSON.stringify(report));`, 7);
  const result = f.invoke(), receipt = f.receipt(), verify = f.invoke(true);
  expect(result.error).toBeUndefined();
  expect(result.status, 'diagnostics preserve the original child failure').toBe(7);
  expect(receipt['result']).toMatchObject({ exitCode: 7, complete: true, leakFree: false, policySatisfied: false });
  expect(verify.status !== null && verify.status !== 0, 'the genuine report disclosure still fails independent verification').toBe(true);
  expect(readFileSync(f.reportPath).equals(reportBytes), 'the actual unsafe report remains privately retained').toBe(true);
  const published = Buffer.from(result.stdout + result.stderr + verify.stdout + verify.stderr + JSON.stringify(receipt));
  expect([f.seed, Buffer.from(f.seed.toString('hex')), Buffer.from(f.seed.toString('base64'))].every(bytes => !published.includes(bytes)),
    'synthetic registered secrets in title, message and path never appear in public channels').toBe(true);
  const metadata = failureReport(failureDetails(result));
  expect(metadata).toMatchObject({ status: 'OK', passed: 0, failed: 17, pending: 0, sha256: digest(reportBytes) });
  const rows = records(metadata['failures'], 'bounded poisoned case metadata');
  expect(rows, 'failure diagnostics have the original fixed sixteen-case bound').toHaveLength(16);
  expect(rows.every(row => row['file'] === null && row['line'] === null && row['column'] === null),
    'escaping and untracked report frames cannot identify a trusted source location').toBe(true);
  expect(rows.every(row => JSON.stringify(row['codes']) === JSON.stringify(['ENOENT'])), 'only finite known error codes may be emitted').toBe(true);
  const first = suites[0]?.assertionResults[0];
  expect(rows[0]).toMatchObject({ titleSha256: digest(String(first?.fullName).replaceAll(marker, f.seed.toString('hex'))),
    messageSha256: digest((first?.failureMessages ?? []).join('\n').replaceAll(marker, f.seed.toString('hex'))) });
}, 15_000);

for (const status of ['INVALID', 'OVERSIZE', 'MISSING'] as const) {
  it(`CP-044/CI-DIAGNOSTIC ${status} report cannot change original failure receipt or verification`, () => {
    const f = fixture();
    const body = status === 'MISSING' ? '' : status === 'INVALID' ? "writeFileSync(join(evidence, 'vitest-harness.json'), '{');"
      : "writeFileSync(join(evidence, 'vitest-harness.json'), ' '.repeat(16 * 1024 * 1024 + 1));";
    f.script(body, 7);
    const result = f.invoke();
    expect(result.error, 'diagnostic parsing retains the ordinary capture deadline').toBeUndefined();
    expect(result.status, 'diagnostic-only refusal does not replace the original child failure').toBe(7);
    expect(f.receipt()['result']).toMatchObject({ exitCode: 7, complete: true, leakFree: true, policySatisfied: true });
    expect(f.invoke(true).status, 'report diagnostic status cannot alter independent evidence verification').toBe(0);
    const metadata = failureReport(failureDetails(result));
    expect(metadata['status']).toBe(status);
    expect(['passed', 'failed', 'pending'].every(key => metadata[key] === undefined || metadata[key] === null),
      'unvalidated reports cannot publish invented numeric counts').toBe(true);
  }, 15_000);
}

it('CP-044/CI-DIAGNOSTIC real missing-receipt exception exposes only finite codes and hashed error data', () => {
  const f = fixture(), receiptPath = join(f.capture, 'receipt.json');
  let expectedMessage = '';
  try { readFileSync(receiptPath); } catch (error) { expectedMessage = (error as Error).message; }
  const result = f.invoke(true);
  expect(result.error).toBeUndefined();
  expect(result.status !== null && result.status !== 0, 'verification still refuses genuinely absent evidence').toBe(true);
  expect(existsSync(receiptPath), 'diagnostics cannot fabricate a replacement receipt').toBe(false);
  const errors = records(failureDetails(result)['errors'], 'bounded exception metadata');
  const missing = errors.find(row => row['code'] === 'ENOENT');
  expect(missing, 'an actual filesystem exception is useful without publishing its raw strings').toMatchObject({
    name: 'Error', code: 'ENOENT', messageSha256: digest(expectedMessage), pathSha256: digest(receiptPath) });
  const frame = missing?.['frame'];
  if (frame !== null) {
    const source = asRecord(frame, 'public capture source frame');
    expect(source['file']).toBe('scripts/ci-capture.mjs');
    expect(Number.isSafeInteger(source['line']) && Number(source['line']) > 0
      && Number.isSafeInteger(source['column']) && Number(source['column']) > 0).toBe(true);
  }
  const safe = result.stdout + result.stderr;
  expect(safe.includes(expectedMessage) || safe.includes(receiptPath) || safe.includes(f.root), 'raw exception message and private paths remain private').toBe(false);
}, 15_000);

it('CP-044/CI-DIAGNOSTIC clean passing capture keeps failure diagnostics absent', () => {
  const f = fixture();
  f.script("writeFileSync(join(evidence, 'vitest-harness.json'), JSON.stringify({ numPassedTests: 1, numFailedTests: 0, numPendingTests: 0, success: true, testResults: [] }));");
  const result = f.invoke(), verify = f.invoke(true);
  expect(result.error).toBeUndefined();
  expect(verify.error).toBeUndefined();
  expect(result.status).toBe(0);
  expect(f.receipt()['result']).toMatchObject({ exitCode: 0, complete: true, leakFree: true, policySatisfied: true });
  expect(verify.status).toBe(0);
  expect(/"details"\s*:/.test(result.stdout + result.stderr + verify.stdout + verify.stderr), 'passing command and verification retain their existing public output').toBe(false);
}, 15_000);

it('CP-044/CI-DIAGNOSTIC registered numeric source cannot escape through diagnostic counts or frame coordinates', () => {
  const f = diagnosticFixture();
  // This benign random sixteen-digit decimal is an independently registered
  // SOURCE. A safe integer alone is not authority to publish its original bytes.
  const numeric = `1${[...randomBytes(15)].map(value => String(value % 10)).join('')}`;
  const sourceBytes = Buffer.from(numeric), numericSource = join(f.sourceRoot, 'numeric-control.bin');
  expect(Number.isSafeInteger(Number(numeric)), 'the control exercises accepted finite integer syntax').toBe(true);
  const frame = `Error: bounded numeric control\n    at ${join(f.root, f.relativeFile)}:${numeric}:${numeric}`;
  const report = { numPassedTests: Number(numeric), numFailedTests: 1, numPendingTests: 0, success: false,
    testResults: [{ name: join(f.root, f.relativeFile), status: 'failed', assertionResults: [{
      fullName: 'bounded numeric control', title: 'bounded numeric control', status: 'failed', failureMessages: [frame],
      location: { line: Number(numeric), column: Number(numeric) },
    }] }] };
  declareFixturePaths([numericSource]);
  declareFixtureCapture(f.capture, [sourceBytes], [{ path: f.reportPath, bytes: Buffer.from(JSON.stringify(report)) }]);
  writeFileSync(numericSource, sourceBytes, { mode: 0o600 });
  if (process.env['FLUXWARDEN_CI_CAPTURE']) {
    // Witness this exact known synthetic INPUT in the outer test worker before
    // the nested recorder owns its child's writes. Leave the inner report absent
    // at Opening so the original command still creates fresh refused EGRESS.
    writeFileSync(f.reportPath, JSON.stringify(report), { flag: 'wx', mode: 0o600 });
    expect(readFileSync(f.reportPath).equals(Buffer.from(JSON.stringify(report))), 'outer fixture setup witnesses only the exact known synthetic report bytes').toBe(true);
    rmSync(f.reportPath);
    expect(existsSync(f.reportPath), 'the inner capture opens with its report path still absent').toBe(false);
  }
  f.script(`const numeric = readFileSync(join(sourceRoot, 'numeric-control.bin'), 'utf8');
const file = ${JSON.stringify(join(f.root, f.relativeFile))};
const report = { numPassedTests: Number(numeric), numFailedTests: 1, numPendingTests: 0, success: false,
 testResults: [{ name: file, status: 'failed', assertionResults: [{
  fullName: 'bounded numeric control', title: 'bounded numeric control', status: 'failed',
  failureMessages: ['Error: bounded numeric control\\n    at ' + file + ':' + numeric + ':' + numeric],
  location: { line: Number(numeric), column: Number(numeric) }
 }] }] };
writeFileSync(join(evidence, 'vitest-harness.json'), JSON.stringify(report));`, 7);
  const result = f.invoke();
  expect(result.error).toBeUndefined();
  expect(result.status, 'diagnostics preserve the original child failure').toBe(7);
  expect(f.receipt()['result']).toMatchObject({ exitCode: 7, complete: true, leakFree: false, policySatisfied: false });
  expect(records(f.receipt()['sources'], 'actual runtime SOURCE union').some(row => row['purpose'] === 'INPUT' && row['sha256'] === digest(sourceBytes)),
    'the numeric control is an actual capture SOURCE, not only a test-side matcher').toBe(true);
  expect(readFileSync(f.reportPath).equals(Buffer.from(JSON.stringify(report))), 'the controlled report retains its actual original numeric fields').toBe(true);
  // A real missing-receipt verification must also sanitize report diagnostics;
  // the retained report is not made safe by the earlier command's failure.
  rmSync(join(f.capture, 'receipt.json'));
  const verification = f.invoke(true);
  expect(verification.error).toBeUndefined();
  expect(verification.status !== null && verification.status !== 0, 'verification still refuses absent evidence').toBe(true);
  expect(existsSync(join(f.capture, 'receipt.json')), 'diagnostics cannot replace missing evidence').toBe(false);
  const published = Buffer.from(result.stdout + result.stderr + verification.stdout + verification.stderr);
  expect([sourceBytes, Buffer.from(sourceBytes.toString('hex')), Buffer.from(sourceBytes.toString('base64'))]
    .every(value => !published.includes(value)), 'all public metadata fields retain SOURCE confidentiality, including numbers and validated frames').toBe(true);
  expect(failureReport(failureDetails(verification))['status'], 'claimed counts inconsistent with the actual assertion population cannot be OK').not.toBe('OK');
}, 15_000);
