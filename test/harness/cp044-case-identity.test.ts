// Vitest5 primary protocol: list uses getNames(...).slice(1).join(' > ');
// JSON preserves ancestorTitles/title and joins fullName with spaces. The real
// nested source/reports below are format controls, never native/official CI proof.
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, expect, it } from 'vitest';
import { measureValidation, setRunner } from '../../labs/scenarios/live-profile.mjs';
import { asRecord, repoRoot } from '../helpers/cli.js';
import { aggregateFixture, runPublicAggregate, type AggregateFixture } from '../helpers/oct26-aggregate-fixture.js';
import { changeMember, releaseFixture, sha256, verifyFixture, type ReleaseFixture } from '../helpers/oct26-release-gate.js';
import { runPublicSeal } from '../helpers/oct26-seal-fixture.js';
import { verifyValidationObservations } from '../helpers/cp006-validation-observations.js';

let fixture: AggregateFixture;
let selected: { lab: { file: string; name: string }[]; chaos: { file: string; name: string }[] };
beforeAll(() => {
  fixture = aggregateFixture(false, true);
  selected = asRecord(JSON.parse(readFileSync(join(fixture.seal.env['TEMP'] ?? '', 'aggregate-source-collection.json'), 'utf8')), 'actual selection')['cases'] as typeof selected;
}, 180000);

function gateWithOriginalReports(): ReleaseFixture {
  const model = releaseFixture();
  for (const suite of ['lab', 'chaos'] as const) {
    const row = model.bundle.live[suite]; if (!row) throw new Error('complete gate fixture needs both live reports');
    const original = readFileSync(join(fixture.seal.evidence, `vitest-${suite}.json`));
    model.inventory.cases[suite] = selected[suite];
    model.files.set(row.report.path, original); row.report.sha256 = sha256(original);
    changeMember(model, row.receipt, receipt => { receipt['reportSha256'] = row.report.sha256; });
  }
  return model;
}

it('CP-044/IDENTITY real nested and literal-separator JSON seals without rewriting original fullName bytes', () => {
  const original = fixture.seal.originalReport;
  const report = asRecord(JSON.parse(original.toString('utf8')), 'original JSON');
  const files = report['testResults'] as { assertionResults: { ancestorTitles: string[]; title: string; fullName: string }[] }[];
  const actual = files.flatMap(file => file.assertionResults);
  expect(actual).toHaveLength(8);
  for (const result of actual) {
    expect(result.ancestorTitles).toEqual(['outer > literal suite', 'inner']);
    expect(result.title).toContain(' > literal title');
    expect(result.fullName).toBe([...result.ancestorTitles, result.title].join(' '));
    expect(selected.chaos.some(row => row.name === [...result.ancestorTitles, result.title].join(' > '))).toBe(true);
  }
  expect(runPublicSeal(fixture.seal)).toBe(0);
  expect(readFileSync(join(fixture.seal.output, 'report.json'))).toEqual(original);
}, 180000);

it('CP-044/IDENTITY real nested reports aggregate with their exact independent display names and original bytes', () => {
  expect(runPublicAggregate(fixture)).toBe(0);
  const root = join(fixture.seal.output, 'aggregate');
  const allFiles = (directory: string): string[] => readdirSync(directory, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? allFiles(join(directory, entry.name)) : [join(directory, entry.name)]);
  expect(allFiles(root).some(file => readFileSync(file).equals(fixture.seal.originalReport))).toBe(true);
}, 180000);

it('CP-044/IDENTITY final authenticated gate admits actual nested and top-level literal-separator reports', async () => {
  expect(await verifyFixture(gateWithOriginalReports())).toBe(0);
}, 180000);

it('CP-044/IDENTITY authentic hashes cannot authorize malformed structure inconsistent names or omitted original cases', async () => {
  for (const mutate of [
    (assertion: Record<string, unknown>) => { assertion['ancestorTitles'] = 'not-an-array'; },
    (assertion: Record<string, unknown>) => { assertion['ancestorTitles'] = ['invented parent']; },
    (assertion: Record<string, unknown>) => { assertion['title'] = 'wrong exact title'; },
    (assertion: Record<string, unknown>) => { assertion['fullName'] = 'wrong original full name'; },
  ]) {
    const model = releaseFixture(), row = model.bundle.live.chaos;
    if (!row) throw new Error('complete fixture requires chaos');
    changeMember(model, row.report, report => {
      const files = report['testResults'] as { assertionResults: Record<string, unknown>[] }[];
      const assertion = files[0]?.assertionResults[0]; if (!assertion) throw new Error('control requires a case'); mutate(assertion);
    });
    changeMember(model, row.receipt, receipt => { receipt['reportSha256'] = row.report.sha256; });
    expect(await verifyFixture(model), 'valid source/job/tarball/report hashes do not excuse invalid reporter structure').toBe(1);
  }
  const omitted = gateWithOriginalReports(), row = omitted.bundle.live.chaos;
  if (!row) throw new Error('complete fixture requires chaos');
  changeMember(omitted, row.report, report => {
    const files = report['testResults'] as { assertionResults: unknown[] }[]; files[0]?.assertionResults.pop();
    report['numTotalTests'] = Number(report['numTotalTests']) - 1; report['numPassedTests'] = Number(report['numPassedTests']) - 1;
  });
  changeMember(omitted, row.receipt, receipt => { receipt['reportSha256'] = row.report.sha256; });
  expect(await verifyFixture(omitted)).toBe(1);
}, 180000);

it('CP-044/IDENTITY independent measurement consumes a real selected nested run with original structural report fields', async () => {
  const root = join(fixture.seal.env['FLUXWARDEN_TEST_TMP'] ?? '', 'measured-identity'); mkdirSync(root);
  const input = join(root, 'input.ts'), built = join(root, 'built'), setup = join(root, 'setup.mjs'), down = join(root, 'down.mjs'), state = join(root, 'state');
  writeFileSync(input, 'export const identityFixtureValue = 4;\n');
  writeFileSync(setup, `import{writeFileSync}from'node:fs';writeFileSync(${JSON.stringify(state)},'owned setup');\n`);
  writeFileSync(down, `import{unlinkSync}from'node:fs';unlinkSync(${JSON.stringify(state)});\n`);
  setRunner((file, args, options) => spawnSync(file, args, options));
  const output = join(root, 'evidence'); mkdirSync(output);
  const measured = await measureValidation({ sourceRoot: fixture.seal.source, sourceSha256: sha256(readFileSync(join(fixture.seal.source, 'test/chaos/contract.live.test.ts'))), invocation: 'real-nested-format-control', evidenceRoot: output,
    selection: selected.chaos.map(row => ({ file: row.file, fullName: row.name })), collectedAt: Date.now(), env: fixture.seal.env,
    commands: { build: [process.execPath, join(repoRoot, 'node_modules/typescript/bin/tsc'), '--ignoreConfig', '--noCheck', '--module', 'NodeNext', '--target', 'ES2022', '--outDir', built, input],
      setup: [process.execPath, setup], run: [{ argv: [process.execPath, 'scripts/ci-test-driver.mjs', 'run', '--config', 'vitest.chaos.config.ts', '--reporter=json', `--outputFile=${join(output, 'original.json')}`], report: 'original.json' }],
      teardown: [process.execPath, down], leak: [process.execPath, 'scripts/leak-check.mjs', '--sentinels', 'test/sentinels.json', '--sentinel-dir', fixture.seal.env['FLUXWARDEN_SENTINEL_DIR'] ?? '', output] } });
  const original = readFileSync(join(output, 'original.json'));
  expect(verifyValidationObservations(measured.planPath).cases).toBe(8);
  expect(readFileSync(join(output, 'original.json'))).toEqual(original);
  expect(readFileSync(join(built, 'input.js'), 'utf8')).toContain('identityFixtureValue = 4');
  const originalReport = asRecord(JSON.parse(original.toString('utf8')), 'original nested report');
  expect(originalReport['numTotalTestSuites']).toBe(4); // file + outer + two real same-named inner suites
  const originalFiles = originalReport['testResults'] as { endTime: number; assertionResults: { duration: number }[] }[];
  expect(originalFiles.some(file => !Number.isInteger(file.endTime) || file.assertionResults.some(assertion => !Number.isInteger(assertion.duration)))).toBe(true);
  // Mutated copies are explicit negative inputs. Never rewrite the original
  // report to claim a completed run; keep every actual process/report byte.
  const mutations: ((report: Record<string, unknown>) => void)[] = [
    report => { report['numTotalTestSuites'] = 1; report['numPassedTestSuites'] = 1; },
    report => { report['numPassedTestSuites'] = 3; },
    report => { report['numPendingTests'] = 1; },
    report => { report['numTotalTestSuites'] = 4.5; report['numPassedTestSuites'] = 4.5; },
    report => { const files = report['testResults'] as { endTime: number }[]; if (files[0]) files[0].endTime = Number.MAX_SAFE_INTEGER; },
    report => { const files = report['testResults'] as { assertionResults: Record<string, unknown>[] }[]; const first = files[0]?.assertionResults[0]; if (first) first['duration'] = -1; },
    report => { const files = report['testResults'] as { assertionResults: Record<string, unknown>[] }[]; const first = files[0]?.assertionResults[0]; if (first) first['duration'] = Infinity; },
    report => { const files = report['testResults'] as { assertionResults: Record<string, unknown>[] }[]; const first = files[0]?.assertionResults[0]; if (first) first['ancestorTitles'] = 'not-structural'; },
    report => { const files = report['testResults'] as { assertionResults: Record<string, unknown>[] }[]; const first = files[0]?.assertionResults[0]; if (first) first['fullName'] = 'wrong original full name'; },
  ];
  for (const [index, mutate] of mutations.entries()) {
    const negative = join(root, `negative-${String(index)}`); mkdirSync(negative);
    for (const file of ['inventory.json', 'observations.json']) copyFileSync(join(output, file), join(negative, file));
    const plan = asRecord(JSON.parse(readFileSync(measured.planPath, 'utf8')), 'actual measurement plan'), altered = structuredClone(originalReport);
    mutate(altered); const alteredBytes = Buffer.from(JSON.stringify(altered)); writeFileSync(join(negative, 'original.json'), alteredBytes);
    plan['evidenceRoot'] = negative; plan['reports'] = [{ file: 'original.json', sha256: sha256(alteredBytes) }];
    const path = join(negative, 'plan.json'); writeFileSync(path, JSON.stringify(plan));
    expect(() => verifyValidationObservations(path), 'structural metric and pending refusals survive authentic copied-artifact hashes').toThrow();
  }
  expect(readFileSync(join(output, 'original.json'))).toEqual(original);
}, 180000);
