// Independent synthetic GitHub transport and artifact builder. These fixtures
// never run or claim platform/live validation. Source case names were collected
// independently with Vitest's dynamic collector; no test bodies or hooks ran.
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';
import { asRecord, repoRoot } from './cli.js';
import { testRoot } from './env.js';

export const SOURCE = '1'.repeat(40);
export const OTHER_SOURCE = '2'.repeat(40);
export const REPOSITORY = 'ZilverZtream/fluxwarden';
export interface SourceCase { file: string; name: string }
export interface PlatformJob { key: string; os: string; node: string; shard: string; suite: 'product' | 'harness' }
export interface Inventory { platformJobs: PlatformJob[]; cases: Record<string, SourceCase[]>; casesByTarget: Record<string, { product: SourceCase[]; harness: SourceCase[] }>; requiredLiveRows: string[] }
export interface Reference { path: string; sha256: string }
export interface ReportRow { jobId: number; key: string; report: Reference; receipt: Reference; ownerPlan?: Reference }
export interface PlatformRow extends ReportRow, PlatformJob {}
export interface EvidenceRow { jobId: number; key: string; evidence: Reference }
export interface Bundle {
  schemaVersion: number; sourceCommit: string; compiledCommit: string; tarball: { sha256: string; bytes: number };
  platform: PlatformRow[];
  live: { ownerPlan?: Reference; lab?: ReportRow; chaos?: ReportRow; rows: { id: string; status: string; evidence: Reference }[] };
  demo: EvidenceRow; leakScan: EvidenceRow; installedSmoke: EvidenceRow; publisher: EvidenceRow;
}
export interface OfficialJob { id: number; run_id: number; head_sha: string; name: string; status: string; conclusion: string | null; steps: { name: string; status: string; conclusion: string | null }[] }
export interface TestReport { success: boolean; numTotalTests: number; numPassedTests: number; numFailedTests: number; numPendingTests: number; numTodoTests: number; testResults: { name: string; assertionResults: { fullName: string; ancestorTitles: string[]; title: string; status: string }[] }[] }
export const sha256 = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');
const jsonBytes = (value: unknown): Buffer => Buffer.from(JSON.stringify(value));

export function independentInventory(): Inventory {
  const frozen = JSON.parse(readFileSync(join(repoRoot, 'test/fixtures/oct26-release-gate/source-cases.json'), 'utf8')) as {
    cases: Record<string, SourceCase[]>; casesByPlatform: Record<string, { product: SourceCase[]; harness: SourceCase[] }>;
  };
  const platformJobs: PlatformJob[] = [];
  const casesByTarget: Inventory['casesByTarget'] = {};
  for (const os of ['ubuntu-latest', 'windows-latest']) {
    // D29/D30 explicit bounded-profile reference: 6 * (10 Linux + 18 Windows).
    const harness = Array.from({ length: 8 }, (_, i) => `harness-${String(i + 1)}`);
    const shards = os === 'ubuntu-latest' ? ['product-1', 'product-2', ...harness]
      : [...Array.from({ length: 8 }, (_, i) => `core-${String(i + 1)}`), ...harness, 'native-1', 'native-2'];
    for (const node of ['22.23.2', '22.x', '24.18.1', '24.x', '26.5.1', '26.x']) {
      const eligible = frozen.casesByPlatform[os];
      if (!eligible) throw new Error('independent target fixture missing');
      casesByTarget[`${os}/${node}`] = structuredClone(eligible);
      for (const shard of shards) platformJobs.push({ key: `platform/${os}/${node}/${shard}`, os, node, shard, suite: shard.startsWith('harness-') ? 'harness' : 'product' });
    }
  }
  return { platformJobs, cases: frozen.cases, casesByTarget, requiredLiveRows: ['T-01', 'T-03', 'T-05', 'T-06', 'T-07', 'T-16', 'T-18', 'T-25'] };
}

function report(cases: SourceCase[]): TestReport {
  const files = new Map<string, { fullName: string; ancestorTitles: string[]; title: string; status: string }[]>();
  for (const row of cases) {
    const tests = files.get(row.file) ?? [];
    // Synthetic transport cases use each collected display name as a literal
    // top-level title; never guess hierarchy by splitting a display delimiter.
    tests.push({ fullName: row.name, ancestorTitles: [], title: row.name, status: 'passed' }); files.set(row.file, tests);
  }
  return { success: true, numTotalTests: cases.length, numPassedTests: cases.length, numFailedTests: 0, numPendingTests: 0, numTodoTests: 0,
    testResults: [...files].map(([name, assertionResults]) => ({ name, assertionResults })) };
}

// POSIX ustar with regular file members; generated independently of release-smoke.
function tar(files: Map<string, Buffer>): Buffer {
  const parts: Buffer[] = [];
  for (const [path, bytes] of files) {
    const header = Buffer.alloc(512);
    header.write(path, 0, 100, 'utf8'); header.write('0000600\0', 100, 8, 'ascii');
    header.write('0000000\0', 108, 8, 'ascii'); header.write('0000000\0', 116, 8, 'ascii');
    header.write(`${bytes.length.toString(8).padStart(11, '0')}\0`, 124, 12, 'ascii');
    header.write('00000000000\0', 136, 12, 'ascii'); header.fill(32, 148, 156); header[156] = 48;
    header.write('ustar\0', 257, 6, 'ascii'); header.write('00', 263, 2, 'ascii');
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
    parts.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  return Buffer.concat([...parts, Buffer.alloc(1024)]);
}

const crcTable = Array.from({ length: 256 }, (_, value) => {
  let row = value;
  for (let i = 0; i < 8; i += 1) row = row & 1 ? 0xedb88320 ^ row >>> 1 : row >>> 1;
  return row >>> 0;
});
function crc32(bytes: Buffer): number {
  let value = 0xffffffff;
  for (const byte of bytes) value = (crcTable[(value ^ byte) & 255] ?? 0) ^ value >>> 8;
  return (value ^ 0xffffffff) >>> 0;
}

// Actual ZIP bytes, including central directory and CRCs. GitHub's official
// artifact digest authenticates these bytes, not a caller's decoded PASS object.
export function zip(files: Map<string, Buffer>): Buffer {
  const parts: Buffer[] = [], central: Buffer[] = [];
  let offset = 0;
  for (const [path, bytes] of files) {
    const name = Buffer.from(path), crc = crc32(bytes), local = Buffer.alloc(30), entry = Buffer.alloc(46);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(bytes.length, 18); local.writeUInt32LE(bytes.length, 22); local.writeUInt16LE(name.length, 26);
    entry.writeUInt32LE(0x02014b50, 0); entry.writeUInt16LE(20, 4); entry.writeUInt16LE(20, 6);
    entry.writeUInt32LE(crc, 16); entry.writeUInt32LE(bytes.length, 20); entry.writeUInt32LE(bytes.length, 24);
    entry.writeUInt16LE(name.length, 28); entry.writeUInt32LE(offset, 42);
    parts.push(local, name, bytes); central.push(entry, name); offset += local.length + name.length + bytes.length;
  }
  const directory = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.size, 8); end.writeUInt16LE(files.size, 10);
  end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, directory, end]);
}

export function releaseFixture(compiledCommit = SOURCE): ReleaseFixture {
  const inventory = independentInventory(), root = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'oct26-gate-'));
  const tarballPath = join(root, 'fluxwarden-1.0.0.tgz');
  const packageFiles = new Map<string, Buffer>([
    ['package/package.json', jsonBytes({ name: 'fluxwarden', version: '1.0.0', bin: { fluxwarden: 'dist/cli/bin.js' } })],
    ['package/dist/cli/bin.js', Buffer.from('#!/usr/bin/env node\n')],
    ['package/dist/evidence/build-info.json', jsonBytes({ gitCommit: compiledCommit })],
    ...['LICENSE', 'README.md', 'SECURITY.md', 'CHANGELOG.md', 'NOTICE-SOURCE-REUSE.md'].map(name => [`package/${name}`, readFileSync(join(repoRoot, name))] as [string, Buffer]),
  ]);
  writeFileSync(tarballPath, gzipSync(tar(packageFiles)));
  const tarball = { sha256: sha256(readFileSync(tarballPath)), bytes: readFileSync(tarballPath).length };
  const files = new Map<string, Buffer>();
  const put = (path: string, value: unknown): Reference => {
    const bytes = jsonBytes(value); files.set(path, bytes); return { path, sha256: sha256(bytes) };
  };
  const jobs: OfficialJob[] = [];
  function job(key: string): number {
    const id = 1000 + jobs.length;
    jobs.push({ id, run_id: 777, head_sha: SOURCE, name: key, status: 'completed', conclusion: 'success',
      steps: [{ name: 'Complete required validation', status: 'completed', conclusion: 'success' }] });
    return id;
  }
  function reportRow(key: string, cases: SourceCase[]): ReportRow {
    const jobId = job(key), reportRef = put(`reports/${String(jobId)}.json`, report(cases));
    const receipt = put(`receipts/${String(jobId)}.json`, { sourceCommit: SOURCE, compiledCommit: SOURCE, tarballSha256: tarball.sha256,
      jobId, complete: true, exitCode: 0, reportSha256: reportRef.sha256 });
    return { key, jobId, report: reportRef, receipt };
  }
  const platform = inventory.platformJobs.map(row => {
    const peers = inventory.platformJobs.filter(peer => peer.os === row.os && peer.node === row.node && peer.suite === row.suite);
    const index = peers.findIndex(peer => peer.key === row.key), all = inventory.casesByTarget[`${row.os}/${row.node}`]?.[row.suite] ?? [];
    const fileNames = [...new Set(all.map(item => item.file))];
    const assigned = new Set(fileNames.filter((_, i) => i % peers.length === index));
    return { ...row, ...reportRow(row.key, all.filter(item => assigned.has(item.file))) };
  });
  const bound = (path: string, extra: object = {}): Reference => put(path, { sourceCommit: SOURCE, compiledCommit: SOURCE, tarballSha256: tarball.sha256, ...extra });
  const evidenceRow = (key: string, extra: object = {}): EvidenceRow => ({ key, jobId: job(key), evidence: bound(`${key}.json`, extra) });
  const scenarioRecord = bound('demo/scenario-T-05.json', { scenario: 'T-05', paymentHashFingerprint: '3'.repeat(64), sendCount: 1 });
  // Owner D29 LN-044-001 minimal raw binding. These are synthetic contract
  // inputs representing both distinct SPEC variants, never native lab proof.
  const t18Observations = ['LAST_HOP_RECEIVABLE', 'FIRST_HOP_SPENDABLE'].map(variant => bound(`live/observations/t18-${variant.toLowerCase()}.json`, {
    scenario: 'T-18', variant, status: 'PASS', ownerId: 'synthetic-verifier-owner', syntheticUnitFixture: true,
    facts: { principalMsat: '100000000', observedAvailableMsat: '60000000', refusalCode: variant, exitCode: 5, nodePaymentsBefore: 0, nodePaymentsAfter: 0 },
  }));
  const ownerPlan = put('live/owner-plan.json', { schemaVersion: 1, sourceCommit: SOURCE, network: 'regtest', exclusive: true, ownerId: 'synthetic-verifier-owner' });
  const bundle: Bundle = { schemaVersion: 1, sourceCommit: SOURCE, compiledCommit: SOURCE, tarball, platform,
    live: { ownerPlan,
      lab: { ...reportRow('live/lab', inventory.cases['lab'] ?? []), ownerPlan }, chaos: reportRow('live/chaos', inventory.cases['chaos'] ?? []),
      rows: inventory.requiredLiveRows.map(id => ({ id, status: 'PASS', evidence: bound(`live/${id}.json`, {
        row: id, complete: true, ...(id === 'T-18' ? { observations: t18Observations } : {}),
      }) })) },
    demo: evidenceRow('release/demo', { scenarioRecord, sameHashRecovery: true, sendCount: 1, ledgerVerified: true, checksumsVerified: true, completeLeakScan: true }),
    leakScan: evidenceRow('release/leak-scan', { complete: true, exitCode: 0 }),
    installedSmoke: evidenceRow('release/installed-smoke', { complete: true, exitCode: 0 }),
    publisher: evidenceRow('release/publisher', { environment: 'npm-release', repository: REPOSITORY, workflow: 'release.yml', package: 'fluxwarden', oidc: true, trustedPublisherVerified: true }) };
  return { root, tarballPath, files, inventory, bundle,
    manifest: { schemaVersion: 1, repository: REPOSITORY, sourceCommit: SOURCE,
      ci: { runId: 777, runAttempt: 1, workflowPath: '.github/workflows/ci.yml', artifactId: 888 }, tarball: { ...tarball } },
    run: { id: 777, run_attempt: 1, path: '.github/workflows/ci.yml', head_sha: SOURCE, status: 'completed', conclusion: 'success', repository: { full_name: REPOSITORY } },
    jobs, artifact: { id: 888, name: 'fluxwarden-release-evidence', expired: false, workflow_run: { id: 777, head_sha: SOURCE } },
    environment: { name: 'npm-release', can_admins_bypass: false,
      protection_rules: [{ type: 'required_reviewers', prevent_self_review: false, reviewers: [{ type: 'User', reviewer: { id: 197366966, login: 'ZilverZtream' } }] }],
      deployment_branch_policy: { protected_branches: false, custom_branch_policies: true } },
    deploymentPolicies: [{ id: 1, name: 'v1.*', type: 'tag' }],
  };
}

export interface ReleaseFixture {
  root: string; tarballPath: string; files: Map<string, Buffer>; inventory: Inventory; bundle: Bundle;
  manifest: { schemaVersion: number; repository: string; sourceCommit: string; ci: { runId: number; runAttempt: number; workflowPath: string; artifactId: number }; tarball: { sha256: string; bytes: number } };
  run: { id: number; run_attempt: number; path: string; head_sha: string; status: string; conclusion: string | null; repository: { full_name: string } };
  jobs: OfficialJob[]; artifact: { id: number; name: string; expired: boolean; workflow_run: { id: number; head_sha: string } };
  environment: { name: string; can_admins_bypass: boolean; protection_rules: object[]; deployment_branch_policy: { protected_branches: boolean; custom_branch_policies: boolean } };
  deploymentPolicies: { id: number; name: string; type: string }[];
  digestOverride?: string; downloadedOverride?: Buffer; offline?: boolean;
}

export function readMember(fixture: ReleaseFixture, reference: Reference): Record<string, unknown> {
  const bytes = fixture.files.get(reference.path);
  if (!bytes) throw new Error('test fixture member absent');
  return asRecord(JSON.parse(bytes.toString('utf8')), 'synthetic artifact member');
}
export function changeMember(fixture: ReleaseFixture, reference: Reference, change: (value: Record<string, unknown>) => void): void {
  const value = readMember(fixture, reference); change(value);
  const bytes = jsonBytes(value); fixture.files.set(reference.path, bytes); reference.sha256 = sha256(bytes);
}
export function changeReport(fixture: ReleaseFixture, row: ReportRow, change: (value: TestReport) => void): void {
  const value = readMember(fixture, row.report) as unknown as TestReport; change(value);
  const bytes = jsonBytes(value); fixture.files.set(row.report.path, bytes); row.report.sha256 = sha256(bytes);
  changeMember(fixture, row.receipt, receipt => { receipt['reportSha256'] = row.report.sha256; });
}

export async function verifyFixture(fixture: ReleaseFixture): Promise<number> {
  fixture.files.set('release-evidence.json', jsonBytes(fixture.bundle));
  const bytes = zip(fixture.files);
  writeFileSync(join(fixture.root, 'synthetic-github-artifact.zip'), bytes);
  const artifact = { ...fixture.artifact, size_in_bytes: bytes.length, digest: fixture.digestOverride ?? `sha256:${sha256(bytes)}` };
  const github = {
    getRun: (): Promise<unknown> => fixture.offline ? Promise.reject(new Error('synthetic unavailable transport')) : Promise.resolve(fixture.run),
    listJobs: (): Promise<unknown> => Promise.resolve(fixture.jobs),
    getArtifact: (): Promise<unknown> => Promise.resolve(artifact),
    downloadArtifact: (): Promise<Buffer> => Promise.resolve(fixture.downloadedOverride ?? bytes),
    getEnvironment: (): Promise<unknown> => Promise.resolve(fixture.environment),
    getDeploymentBranchPolicies: (): Promise<unknown> => Promise.resolve(fixture.deploymentPolicies),
  };
  const api = await import(pathToFileURL(join(repoRoot, 'scripts/release-gate.mjs')).href) as {
    verifyRelease(input: { sourceCommit: string; tarballPath: string; manifest: ReleaseFixture['manifest'] }, dependencies: { inventory: Inventory; github: typeof github }): Promise<number>;
  };
  return api.verifyRelease({ sourceCommit: SOURCE, tarballPath: fixture.tarballPath, manifest: fixture.manifest }, { inventory: fixture.inventory, github });
}
