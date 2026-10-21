// Sources: SECURITY INV-11; SPEC 12.2; RATCHET 6, 13 and 15. This is a
// finite, owned CI command boundary, not a claim about unrelated host files.
// Public contract: ci-capture.mjs --root ROOT --capture-dir PRIVATE -- COMMAND;
// ci-capture.mjs verify --root ROOT --capture-dir PRIVATE. Only safe receipts
// and scanned output are publishable; original source bytes remain private.
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, utimesSync, writeFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { asRecord, childEnv, readText, repoRoot } from '../helpers/cli.js';
import { testRoot } from '../helpers/env.js';
import { liveSentinelDetected, scanner } from '../helpers/leak-scan.js';
import { parseYaml } from '../helpers/yaml.js';
import { declareFixtureCapture, declareFixturePaths } from '../helpers/capture-fixture.js';

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
    [...extraArgs, captureCli, ...(verify ? ['verify'] : []), '--root', root, '--capture-dir', capture,
      ...(verify ? [] : ['--', process.execPath, child])],
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

it('CP-044/CI-CAPTURE recheck refuses expanded source declarations and missing failure channels', () => {
  for (const target of ['declared-out.txt', 'stdout.log', 'stderr.log']) {
    const f = fixture();
    writeFileSync(join(f.scratch, 'declared-out.txt'), '');
    expect(f.invoke().status).toBe(0);
    if (target === 'declared-out.txt') appendFileSync(join(f.scratch, target), `${join(f.scratch, 'owned.db')}\n`);
    else rmSync(join(f.capture, target));
    expect(f.invoke(true).status !== 0, 'expanded input contexts or omitted original output streams cannot pass').toBe(true);
  }
});

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
