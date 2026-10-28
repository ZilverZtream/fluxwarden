// Owner-routed public aggregate envelopes, LN-044-001. All jobs, reports and
// node observations are synthetic transport inputs, never CI/native outcomes.
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect } from 'vitest';
import { asRecord, readJson, repoRoot } from './cli.js';
import { capturedSealFixture, REQUIRED_ROWS, type SealFixture } from './oct26-seal-fixture.js';
import { collectAggregateSource, prepareAggregateSource } from './oct26-aggregate-source.js';
import { readMember, releaseFixture, sha256, zip, type OfficialJob, type Reference } from './oct26-release-gate.js';

interface Artifact {
  id: number; name: string; size_in_bytes: number; digest: string; expired: boolean;
  workflow_run: { id: number; head_sha: string };
}
export interface AggregateFixture {
  seal: SealFixture; inputs: string; driver: string; chaosArchive: string; chaosArchiveSha256: string; gapBytes?: Buffer;
}

export async function loadPublicAggregate(): Promise<void> {
  await import(pathToFileURL(join(repoRoot, 'scripts/release-ci.mjs')).href);
}

export function aggregateFixture(gap = false, nestedIdentity = false): AggregateFixture {
  let collectedCases: ReturnType<typeof collectAggregateSource> | undefined;
  const seal = capturedSealFixture(0, {}, source => { prepareAggregateSource(source, nestedIdentity); },
    fixture => { collectedCases = collectAggregateSource(fixture, nestedIdentity); });
  if (!collectedCases) throw new Error('aggregate inventory must be collected before capture closure');
  const liveCases = collectedCases;
  const model = releaseFixture(), inputs = join(dirname(seal.source), 'aggregate-inputs');
  mkdirSync(inputs, { mode: 0o700 });
  const sourceCommit = seal.sourceCommit, tarballSha256 = sha256(readFileSync(seal.tarball));
  const jobs: OfficialJob[] = model.jobs.map(job => ({ ...job, head_sha: sourceCommit })), artifacts: Artifact[] = [];
  const bound = (extra: object) => ({ sourceCommit, compiledCommit: sourceCommit, tarballSha256, ...extra });
  const bytes = (value: unknown): Buffer => Buffer.from(JSON.stringify(value));
  const archive = (name: string, members: Map<string, Buffer>): string => {
    const id = 5000 + artifacts.length, contents = zip(members), path = join(inputs, `${String(id)}.zip`);
    writeFileSync(path, contents);
    artifacts.push({ id, name, size_in_bytes: contents.length, digest: `sha256:${sha256(contents)}`, expired: false,
      workflow_run: { id: 777, head_sha: sourceCommit } });
    return path;
  };
  const ownerPlan = bytes({ schemaVersion: 1, sourceCommit, exclusive: true, network: 'regtest', ownerId: 'synthetic-seal-owner' });
  const liveReport = (suite: 'lab' | 'chaos'): Buffer => {
    if (nestedIdentity) return readFileSync(join(seal.evidence, `vitest-${suite}.json`));
    const cases = liveCases[suite], names = [...new Set(cases.map(row => row.file))];
    return bytes({ success: true, numTotalTests: cases.length, numPassedTests: cases.length, numFailedTests: 0, numPendingTests: 0, numTodoTests: 0,
      testResults: names.map(file => ({ name: join(seal.source, file), assertionResults: cases.filter(row => row.file === file)
        .map(row => ({ fullName: row.name, ancestorTitles: [], title: row.name, status: 'passed' })) })) });
  };
  const capture = readFileSync(join(seal.capture, 'receipt.json'));
  let chaosArchive = '', gapBytes: Buffer | undefined;
  for (const row of [...model.bundle.platform, model.bundle.live.lab, model.bundle.live.chaos]) {
    if (!row) throw new Error('public aggregate fixture requires both live producers');
    const report = row.key === 'live/lab' ? liveReport('lab') : row.key === 'live/chaos' ? liveReport('chaos') : model.files.get(row.report.path);
    if (!report) throw new Error('public report fixture missing');
    const reportSha256 = sha256(report), receipt = bytes(bound({ jobId: row.jobId, complete: true, exitCode: 0, reportSha256 }));
    const members = new Map<string, Buffer>([['report.json', report], ['receipt.json', receipt], ['capture.json', capture]]);
    members.set('row.json', bytes({ key: row.key, jobId: row.jobId, report: { path: 'report.json', sha256: reportSha256 },
      receipt: { path: 'receipt.json', sha256: sha256(receipt) } }));
    if (row.key.startsWith('live/')) members.set('owner-plan.json', ownerPlan);
    if (row.key === 'live/chaos') {
      for (const id of REQUIRED_ROWS) {
        const observations: Reference[] = [];
        if (id === 'T-18') {
          for (const variant of ['LAST_HOP_RECEIVABLE', 'FIRST_HOP_SPENDABLE']) {
            const path = `t18-${variant.toLowerCase()}.json`, raw = bytes(bound({ scenario: 'T-18', variant, status: 'PASS', ownerId: 'synthetic-seal-owner',
              syntheticUnitFixture: true, facts: { principalMsat: '100000000', observedAvailableMsat: '60000000', refusalCode: variant, exitCode: 5, nodePaymentsBefore: 0, nodePaymentsAfter: 0 } }));
            members.set(path, raw); observations.push({ path, sha256: sha256(raw) });
          }
          if (gap) {
            const path = 't18-first-hop-specific-gap.json';
            gapBytes = bytes(readJson('test/fixtures/oct26-release-gate/t18-first-hop-specific-gap.json'));
            members.set(path, gapBytes); observations.push({ path, sha256: sha256(gapBytes) });
          }
        } else {
          const path = `${id.toLowerCase().replace('-', '')}-contract-observation.json`;
          const raw = bytes(bound({ scenario: id, status: 'PASS', ownerId: 'synthetic-seal-owner', syntheticUnitFixture: true, observation: 'nonempty synthetic unit input, no native outcome claimed' }));
          members.set(path, raw); observations.push({ path, sha256: sha256(raw) });
        }
        // Assertions prove report selection only. Raw variant observations,
        // including any contradiction, independently determine completeness.
        const reportObject = asRecord(JSON.parse(report.toString('utf8')), 'synthetic report');
        const results = reportObject['testResults'];
        if (!Array.isArray(results)) throw new Error('synthetic report lacks testResults');
        const assertions = results.flatMap(result => {
          const file = asRecord(result, 'test file'), values = file['assertionResults'];
          if (!Array.isArray(values)) throw new Error('synthetic report lacks assertions');
          return values.map(value => asRecord(value, 'assertion')).filter(value => String(value['fullName']).includes(id))
            .map(value => ({ file: String(file['name']), name: String(value['fullName']), status: value['status'] }));
        });
        members.set(`${id}.json`, bytes(bound({ row: id, complete: true, assertions, observations })));
      }
    }
    const path = archive(`fluxwarden-${row.key.replaceAll('/', '-')}`, members);
    if (row.key === 'live/chaos') chaosArchive = path;
  }
  for (const row of [model.bundle.demo, model.bundle.installedSmoke, model.bundle.publisher, model.bundle.leakScan]) {
    const fields = { ...readMember(model, row.evidence) };
    for (const field of ['sourceCommit', 'compiledCommit', 'tarballSha256']) Reflect.deleteProperty(fields, field);
    const members = new Map<string, Buffer>();
    if (row.key === 'release/demo') {
      const scenario = bytes(bound({ scenario: 'T-05', sendCount: 1, paymentHashFingerprint: '3'.repeat(64) }));
      members.set('scenario.json', scenario); fields['scenarioRecord'] = { path: 'release/demo/scenario.json', sha256: sha256(scenario) };
    }
    const evidence = bytes(bound(fields)); members.set('evidence.json', evidence);
    members.set('row.json', bytes({ key: row.key, jobId: row.jobId, evidence: { path: 'evidence.json', sha256: sha256(evidence) } }));
    archive(`fluxwarden-${row.key.replaceAll('/', '-')}`, members);
  }
  const moving: Record<string, string> = { '22.x': '22.23.2', '24.x': '24.21.0', '26.x': '26.12.1' };
  for (const [key, cases] of Object.entries(model.inventory.casesByTarget)) {
    const [os = '', node = ''] = key.split('/'), jobId = 2000 + jobs.length;
    jobs.push({ id: jobId, run_id: 777, head_sha: sourceCommit, name: `inventory/${key}`, status: 'completed', conclusion: 'success',
      steps: [{ name: 'Complete frozen target collection', status: 'completed', conclusion: 'success' }] });
    const payload = bound({ schemaVersion: 1, key, jobId, os, node, platform: os === 'windows-latest' ? 'win32' : 'linux', runtime: `v${moving[node] ?? node}`, cases });
    archive(`fluxwarden-inventory-${os}-${node}`, new Map([['inventory.json', bytes(payload)]]));
  }
  writeFileSync(join(inputs, 'transport.json'), bytes({ jobs, artifacts }));
  const driver = join(inputs, 'aggregate-driver.mjs');
  writeFileSync(driver, `import {readFileSync} from 'node:fs';import {join} from 'node:path';
import {aggregateEvidence} from ${JSON.stringify(pathToFileURL(join(seal.source, 'scripts/release-ci.mjs')).href)};
const root=${JSON.stringify(inputs)},data=JSON.parse(readFileSync(join(root,'transport.json'),'utf8'));
await aggregateEvidence({listJobs:()=>Promise.resolve(data.jobs),listArtifacts:()=>Promise.resolve(data.artifacts),
getArtifact:id=>Promise.resolve(data.artifacts.find(row=>row.id===id)),downloadArtifact:id=>Promise.resolve(readFileSync(join(root,String(id)+'.zip')))});
`);
  return { seal, inputs, driver, chaosArchive, chaosArchiveSha256: sha256(readFileSync(chaosArchive)), gapBytes };
}

export function runPublicAggregate(fixture: AggregateFixture): number | null {
  const result = spawnSync(process.execPath, [fixture.driver], { cwd: fixture.seal.source,
    env: { ...fixture.seal.env, EXPECTED_TARBALL_SHA256: sha256(readFileSync(fixture.seal.tarball)) }, windowsHide: true, timeout: 120_000 });
  expect(result.error).toBeUndefined(); expect(result.signal).toBeNull();
  return result.status;
}
