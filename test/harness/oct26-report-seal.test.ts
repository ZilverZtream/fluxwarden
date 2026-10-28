import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { asRecord, readJson } from '../helpers/cli.js';
import { ownedCaptureToolArgs } from '../helpers/capture-fixture.js';
import { capturedSealFixture, loadPublicSeal, REQUIRED_ROWS, runPublicSeal } from '../helpers/oct26-seal-fixture.js';
import { sha256 } from '../helpers/oct26-release-gate.js';

function hasPass(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;
  if (Array.isArray(value)) return value.some(hasPass);
  return Object.entries(value).some(([key, row]) => key === 'status' && row === 'PASS' || hasPass(row));
}

it('CP-044/SEAL real unchanged capture fixtures preserve actual success and failure and pass independent custody verification', () => {
  for (const code of [0, 7] as const) capturedSealFixture(code);
}, 120_000);

it('CP-044/SEAL bounded successful proof preserves original report bytes and source artifact and actual exit bindings', async () => {
  await loadPublicSeal(); const fixture = capturedSealFixture(0);
  expect(runPublicSeal(fixture)).toBe(0);
  expect(readFileSync(join(fixture.output, 'report.json')).equals(fixture.originalReport)).toBe(true);
  const receipt = asRecord(JSON.parse(readFileSync(join(fixture.output, 'receipt.json'), 'utf8')), 'bounded receipt');
  expect(receipt['sourceCommit']).toBe(fixture.sourceCommit); expect(receipt['compiledCommit']).toBe(fixture.sourceCommit);
  expect(receipt['tarballSha256']).toBe(sha256(readFileSync(fixture.tarball))); expect(receipt['reportSha256']).toBe(sha256(fixture.originalReport));
  expect(receipt['exitCode']).toBe(0); expect(receipt['jobId']).toBe(4242);
  for (const row of REQUIRED_ROWS) expect(readdirSync(fixture.output)).toContain(`${row}.json`);
  expect(readdirSync(fixture.output)).toContain('row.json');
  const t18 = asRecord(JSON.parse(readFileSync(join(fixture.output, 'T-18.json'), 'utf8')), 'bounded complete T18');
  expect(t18['complete'], 'the positive control represents both required T18 variants').toBe(true);
  const observations = t18['observations'];
  expect(Array.isArray(observations), 'T18 retains hashed raw observations, not only assertion names').toBe(true);
  if (!Array.isArray(observations)) throw new Error('positive T18 lacks bound observations');
  const variants: unknown[] = [];
  for (const reference of observations) {
    const ref = asRecord(reference, 'bound raw observation'), path = String(ref['path']);
    expect(isAbsolute(path)).toBe(false); expect(path.split('/')).not.toContain('..'); expect(path).not.toContain('\\');
    const bytes = readFileSync(join(fixture.output, path));
    expect(sha256(bytes)).toBe(ref['sha256']);
    const raw = asRecord(JSON.parse(bytes.toString('utf8')), 'raw T18 observation');
    expect(raw['scenario']).toBe('T-18'); expect(raw['status']).toBe('PASS');
    expect(raw['sourceCommit']).toBe(fixture.sourceCommit);
    variants.push(raw['variant']);
  }
  expect(variants.sort()).toEqual(['FIRST_HOP_SPENDABLE', 'LAST_HOP_RECEIVABLE']);
}, 120_000);

it('CP-044/SEAL completed failing report retains original failed bytes and actual nonzero exit without any scenario PASS', async () => {
  await loadPublicSeal(); const fixture = capturedSealFixture(7);
  runPublicSeal(fixture);
  expect(readFileSync(join(fixture.output, 'report.json')).equals(fixture.originalReport)).toBe(true);
  const receipt = asRecord(JSON.parse(readFileSync(join(fixture.output, 'receipt.json'), 'utf8')), 'bounded failure receipt');
  expect(receipt['exitCode'], 'capture exit cannot become a successful proof').toBe(7);
  for (const file of readdirSync(fixture.output).filter(name => name.endsWith('.json'))) {
    expect(hasPass(JSON.parse(readFileSync(join(fixture.output, file), 'utf8'))), 'failed invocation cannot authorize any scenario PASS').toBe(false);
  }
}, 120_000);

it('CP-044/LN-044-001 a passing T18 assertion cannot seal retained GAP PARTIAL or INVALID observations as complete proof', async () => {
  await loadPublicSeal();
  // Exact GAP source: cp034-balance-reference.live.test.ts retain call after
  // LAST_HOP_RECEIVABLE + RESERVE_FLOOR, explicitly not FIRST_HOP_SPENDABLE.
  const gap = asRecord(readJson('test/fixtures/oct26-release-gate/t18-first-hop-specific-gap.json'), 'retained native GAP shape');
  for (const status of ['GAP', 'PARTIAL', 'INVALID']) {
    const fixture = capturedSealFixture(0, { 't18-first-hop-specific-gap.json': { ...gap, status } });
    const original = readFileSync(join(fixture.evidence, 't18-first-hop-specific-gap.json'));
    runPublicSeal(fixture);
    expect(readFileSync(join(fixture.evidence, 't18-first-hop-specific-gap.json')), 'sealing preserves the contradictory original observation').toEqual(original);
    expect(readFileSync(join(fixture.evidence, 'vitest-chaos.json')), 'the otherwise passing report remains unchanged').toEqual(fixture.originalReport);
    const scenario = join(fixture.output, 'T-18.json');
    if (existsSync(scenario)) {
      const sealed = asRecord(JSON.parse(readFileSync(scenario, 'utf8')), 'bounded T18');
      expect(sealed['complete'], `${status} observation cannot become complete`).not.toBe(true);
      expect(hasPass(sealed), `${status} observation cannot become scenario PASS`).toBe(false);
    }
  }
}, 120_000);

it('CP-044/SEAL final bounded output scanning rejects registered credential bytes even in an additional JSON file', async () => {
  await loadPublicSeal(); const fixture = capturedSealFixture(0);
  try {
    const status = runPublicSeal(fixture, true);
    expect(fixture.plantObserved, 'real final output transport must have produced the deliberate plant').toBe(true);
    expect(status !== 0 || !existsSync(fixture.leakPath), 'registered secret bytes cannot remain in authorized bounded output').toBe(true);
  } finally { if (existsSync(fixture.leakPath)) unlinkSync(fixture.leakPath); }
}, 120_000);

it('CP-044/SEAL-TRANSPORT descriptor output writes actually plant the same registered source for both synchronous write APIs', () => {
  const fixture = capturedSealFixture(0), reportPath = join(fixture.output, 'report.json');
  for (const method of ['writeFileSync', 'writeSync']) {
    try {
      const result = spawnSync(process.execPath, [...ownedCaptureToolArgs(['--import', pathToFileURL(join(fixture.source, 'seal-output-transport.mjs')).href,
        '--input-type=module', '--eval', `import fs from 'node:fs';import {join} from 'node:path';
const fd=fs.openSync(join(process.env.FLUXWARDEN_RELEASE_OUTPUT,'report.json'),'wx',0o600);
try{fs[${JSON.stringify(method)}](fd,'{}');}finally{fs.closeSync(fd);}`])], {
        cwd: fixture.source, env: { ...fixture.env, CONTROL_SEAL_SOURCE: join(fixture.source, 'test/sentinels/source.bin') }, windowsHide: true, timeout: 10_000,
      });
      expect(result.error).toBeUndefined(); expect(result.signal).toBeNull(); expect(result.status).toBe(0);
      expect(result.stdout.toString('utf8').split('fixture-output-plant\n')).toHaveLength(2);
      expect(existsSync(fixture.leakPath), 'actual descriptor content write must produce the registered leak plant').toBe(true);
      expect(readFileSync(fixture.leakPath).includes(fixture.seed.toString('hex')), 'the planted value remains the existing registered SOURCE').toBe(true);
    } finally {
      if (existsSync(fixture.leakPath)) unlinkSync(fixture.leakPath);
      if (existsSync(reportPath)) unlinkSync(reportPath);
    }
  }
});

it('CP-044/SEAL mutated original capture custody refuses before producing an authorized row', async () => {
  await loadPublicSeal(); const fixture = capturedSealFixture(0);
  const receiptPath = join(fixture.capture, 'receipt.json');
  writeFileSync(receiptPath, Buffer.concat([readFileSync(receiptPath), Buffer.from(' ')]));
  expect(runPublicSeal(fixture), 'unchanged independent capture verification must detect mutation').not.toBe(0);
  expect(readdirSync(fixture.output), 'unverified custody cannot produce an uploadable proof').not.toContain('row.json');
}, 120_000);
