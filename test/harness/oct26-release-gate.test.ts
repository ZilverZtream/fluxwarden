// Audit F03/F04 and owner D29 public gate contract. All PASS reports below are
// synthetic transport fixtures, never candidate release or live-node evidence.
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { expect, it } from 'vitest';
import { asRecord, readJson, readText } from '../helpers/cli.js';
import { parseYaml } from '../helpers/yaml.js';
import {
  changeMember, changeReport, OTHER_SOURCE, readMember, releaseFixture, sha256, verifyFixture,
  type PlatformRow, type Reference, type ReportRow, type ReleaseFixture, type TestReport,
} from '../helpers/oct26-release-gate.js';

function firstPlatform(fixture: ReleaseFixture): PlatformRow {
  const row = fixture.bundle.platform[0];
  if (!row) throw new Error('independent fixture requires platform rows');
  return row;
}
function liveRow(fixture: ReleaseFixture, suite: 'lab' | 'chaos'): ReportRow {
  const row = fixture.bundle.live[suite];
  if (!row) throw new Error('independent fixture requires both live suites');
  return row;
}
function firstAssertion(report: TestReport): { fullName: string; status: string } {
  const first = report.testResults[0]?.assertionResults[0];
  if (!first) throw new Error('independent fixture requires nonempty assertions');
  return first;
}
function t18Evidence(fixture: ReleaseFixture): Reference {
  const row = fixture.bundle.live.rows.find(candidate => candidate.id === 'T-18');
  if (!row) throw new Error('independent fixture needs required T18');
  return row.evidence;
}
function t18Observations(fixture: ReleaseFixture): Reference[] {
  const observations = readMember(fixture, t18Evidence(fixture))['observations'];
  if (!Array.isArray(observations)) throw new Error('T18 fixture needs bound raw observations');
  return observations as Reference[];
}
function changeT18Observation(fixture: ReleaseFixture, reference: Reference, change: (value: Record<string, unknown>) => void): void {
  changeMember(fixture, reference, change);
  // Keep every raw-member and enclosing summary hash authentic: refusal must
  // follow semantic incompleteness, not an accidental stale fixture digest.
  changeMember(fixture, t18Evidence(fixture), summary => {
    summary['observations'] = t18Observations(fixture).map(current => current.path === reference.path ? reference : current);
  });
  for (const current of t18Observations(fixture)) {
    const bytes = fixture.files.get(current.path);
    if (!bytes) throw new Error('semantic mutation must retain its raw member');
    expect(sha256(bytes), 'semantic negative input has an authentic raw-member digest').toBe(current.sha256);
  }
}

it('CP-044/F03 publication requires the real source-and-final-tarball verifier after smoke without failure bypass', () => {
  const workflow = asRecord(parseYaml(readText('.github/workflows/release.yml')), 'release');
  const jobs = asRecord(workflow['jobs'], 'jobs');
  const publishing = Object.values(jobs).map(value => asRecord(value, 'job')).filter(job =>
    Array.isArray(job['steps']) && job['steps'].some(step => /\bnpm publish\b/.test(String(asRecord(step, 'step')['run'] ?? ''))));
  expect(publishing).toHaveLength(1);
  for (const job of publishing) {
    const steps = (job['steps'] as unknown[]).map(step => asRecord(step, 'step'));
    const gate = steps.findIndex(step => /\bnode scripts\/release-gate\.mjs\b/.test(String(step['run'] ?? '')));
    expect(gate, 'audit F03: current publication must execute the verifier').toBeGreaterThanOrEqual(0);
    const publish = steps.findIndex(step => /\bnpm publish\b/.test(String(step['run'] ?? '')));
    const smoke = steps.findIndex(step => /\bnode scripts\/release-smoke\.mjs\b/.test(String(step['run'] ?? '')));
    expect(gate).toBeGreaterThan(smoke);
    expect(publish).toBeGreaterThan(gate);
    const step = steps[gate];
    if (!step) throw new Error('release gate step absent');
    expect(step['continue-on-error'] ?? false).toBe(false);
    expect(job['continue-on-error'] ?? false).toBe(false);
    expect(step['if'] ?? 'success()').toBe('success()');
    const command = String(step['run']);
    expect(command).toMatch(/--source\s+["']?(?:\$\{?GITHUB_SHA\}?|\$\{\{\s*github\.sha\s*\}\})/);
    expect(command).toMatch(/--evidence\s+\S+/);
    expect(command, 'gate failure cannot be masked by a later shell command').not.toMatch(/\|\|\s*(?:true|:)|;\s*(?:true|exit\s+0)|continue-on-error/);
    const tarball = /--tarball\s+("[^"]+"|'[^']+'|\S+)/.exec(command)?.[1];
    expect(tarball, 'gate names the actual tarball').toBeDefined();
    expect(String(steps[publish]?.['run']), 'publish consumes exactly the gate artifact').toContain(String(tarball));
    expect(steps.slice(gate + 1, publish).some(row => /\bnpm pack\b/.test(String(row['run'] ?? ''))), 'no repack after verification').toBe(false);
  }
});

it('CP-044/F03 complete authenticated platform live and final-artifact evidence accepts the synthetic control without publication', async () => {
  const fixture = releaseFixture();
  expect(fixture.inventory.platformJobs).toHaveLength(102);
  expect(fixture.inventory.casesByTarget['windows-latest/24.x']?.product).toHaveLength(1685);
  expect(fixture.inventory.casesByTarget['ubuntu-latest/24.x']?.product).toHaveLength(1658);
  expect(fixture.inventory.casesByTarget['windows-latest/24.x']?.harness).toHaveLength(196);
  expect(fixture.inventory.casesByTarget['ubuntu-latest/24.x']?.harness).toHaveLength(195);
  expect(t18Observations(fixture).map(reference => readMember(fixture, reference)['variant']).sort()).toEqual(['FIRST_HOP_SPENDABLE', 'LAST_HOP_RECEIVABLE']);
  for (const observation of t18Observations(fixture)) expect(readMember(fixture, observation)['status']).toBe('PASS');
  expect(await verifyFixture(fixture)).toBe(0);
});

it('CP-044/LN-044-001 forged T18 complete and PASS wrappers cannot override incomplete missing substituted or contradictory raw observations', async () => {
  for (const nested of [false, true]) for (const status of ['GAP', 'PARTIAL', 'INVALID']) {
    const fixture = releaseFixture(), firstHop = t18Observations(fixture).find(reference => readMember(fixture, reference)['variant'] === 'FIRST_HOP_SPENDABLE');
    if (!firstHop) throw new Error('positive fixture requires first-hop proof');
    changeT18Observation(fixture, firstHop, observation => {
      if (nested) {
        observation['complete'] = true;
        observation['details'] = { status: 'PASS', complete: true, descendants: [{ status }] };
      } else observation['status'] = status;
    });
    if (nested) expect(readMember(fixture, firstHop)['status'], 'raw ancestors still claim PASS above the incomplete descendant').toBe('PASS');
    expect(readMember(fixture, t18Evidence(fixture))['complete'], 'forged completeness remains asserted by the caller').toBe(true);
    expect(await verifyFixture(fixture), `authenticated ${nested ? 'nested' : 'top-level'} raw ${status} defeats forged complete:true`).toBe(1);
  }
  for (const missing of ['file', 'reference', 'required-variant']) {
    const fixture = releaseFixture(), observations = t18Observations(fixture);
    const firstHop = observations.find(reference => readMember(fixture, reference)['variant'] === 'FIRST_HOP_SPENDABLE');
    if (!firstHop) throw new Error('positive fixture requires first-hop proof');
    if (missing === 'file') fixture.files.delete(firstHop.path);
    else if (missing === 'reference') changeMember(fixture, t18Evidence(fixture), summary => { summary['observations'] = observations.filter(reference => reference.path !== firstHop.path); });
    else changeT18Observation(fixture, firstHop, observation => { observation['variant'] = 'RESERVE_FLOOR'; });
    expect(await verifyFixture(fixture), `T18 missing ${missing} cannot be inferred from passed assertion titles`).toBe(1);
  }
  for (const referenced of [true, false]) {
    const fixture = releaseFixture(), path = 'live/observations/t18-first-hop-specific-gap.json';
    const bytes = Buffer.from(JSON.stringify(readJson('test/fixtures/oct26-release-gate/t18-first-hop-specific-gap.json')));
    fixture.files.set(path, bytes);
    if (referenced) changeMember(fixture, t18Evidence(fixture), summary => { summary['observations'] = [...t18Observations(fixture), { path, sha256: sha256(bytes) }]; });
    expect(await verifyFixture(fixture), `legacy GAP cannot be discarded by ${referenced ? 'labelling both other variants PASS' : 'omitting its reference'}`).toBe(1);
  }
});

it('CP-044/LN-044-001 no required scenario may turn an explicit incomplete raw status into complete PASS', async () => {
  const statuses = ['GAP', 'PARTIAL', 'INVALID'];
  for (const [index, id] of ['T-01', 'T-03', 'T-05', 'T-06', 'T-07', 'T-16', 'T-18', 'T-25'].entries()) {
    const fixture = releaseFixture(), row = fixture.bundle.live.rows.find(candidate => candidate.id === id);
    if (!row) throw new Error('fixed required scenario absent from fixture');
    const status = statuses[index % statuses.length];
    changeMember(fixture, row.evidence, observation => { observation['status'] = status; });
    expect(row.status).toBe('PASS');
    expect(readMember(fixture, row.evidence)['complete']).toBe(true);
    expect(await verifyFixture(fixture), `${id} raw ${String(status)} defeats its forged complete PASS wrapper`).toBe(1);
  }
});

it('CP-044/F10 target-specific inventories reject cross-platform substitution missing target scope and runtime-local omissions', async () => {
  const fixture = releaseFixture();
  Reflect.deleteProperty(fixture.inventory.casesByTarget, 'ubuntu-latest/26.x');
  expect(await verifyFixture(fixture), 'a global case list cannot replace an absent runtime inventory').toBe(1);
  const crossed = releaseFixture();
  const windows = crossed.inventory.casesByTarget['windows-latest/24.x'];
  const linux = crossed.inventory.casesByTarget['ubuntu-latest/24.x'];
  if (!windows || !linux) throw new Error('independent fixture needs both target inventories');
  const windowsOnly = windows.product.find(candidate => !linux.product.some(row => row.file === candidate.file && row.name === candidate.name));
  if (!windowsOnly) throw new Error('source-derived target fixture must retain genuine platform eligibility differences');
  const linuxRow = crossed.bundle.platform.find(row => row.os === 'ubuntu-latest' && row.node === '24.x' && row.suite === 'product');
  if (!linuxRow) throw new Error('independent Linux report fixture absent');
  changeReport(crossed, linuxRow, report => {
    report.testResults.push({ name: windowsOnly.file, assertionResults: [{ fullName: windowsOnly.name, ancestorTitles: [], title: windowsOnly.name, status: 'passed' }] });
    report.numTotalTests += 1; report.numPassedTests += 1;
  });
  expect(await verifyFixture(crossed), 'a Windows-only native case cannot stand in for Linux eligibility').toBe(1);
  const runtime = releaseFixture();
  const selected = runtime.bundle.platform.find(row => row.os === 'windows-latest' && row.node === '26.x' && row.suite === 'product');
  if (!selected) throw new Error('independent Node26 report fixture absent');
  changeReport(runtime, selected, report => {
    const file = report.testResults[0];
    if (!file) throw new Error('independent report must retain actual source cases');
    file.assertionResults.shift(); report.numTotalTests -= 1; report.numPassedTests -= 1;
    if (!file.assertionResults.length) report.testResults.shift();
  });
  expect(await verifyFixture(runtime), 'complete other runtimes cannot conceal an omitted Node26 case').toBe(1);
});

it('CP-044/F03 missing failing canceled skipped and unfinished required platform jobs each refuse', async () => {
  for (const outcome of ['missing', 'failure', 'cancelled', 'skipped', 'in_progress']) {
    const fixture = releaseFixture(), job = fixture.jobs[0];
    if (!job) throw new Error('required official job absent from fixture');
    if (outcome === 'missing') fixture.jobs.shift();
    else if (outcome === 'in_progress') { job.status = 'in_progress'; job.conclusion = null; }
    else job.conclusion = outcome;
    expect(await verifyFixture(fixture), `actual required job ${outcome}`).toBe(1);
  }
  const fixture = releaseFixture(), job = fixture.jobs[0];
  if (!job) throw new Error('required official job absent from fixture');
  job.steps = [{ name: 'Required validation', status: 'completed', conclusion: 'skipped' }];
  expect(await verifyFixture(fixture), 'successful wrapper job cannot conceal a skipped validation step').toBe(1);
});

it('CP-044/F03 stale wrong-source wrong-repository wrong-workflow and wrong-attempt official runs refuse', async () => {
  const mutations: ((fixture: ReleaseFixture) => void)[] = [
    f => { f.run.head_sha = OTHER_SOURCE; }, f => { f.run.repository.full_name = 'unrelated/fluxwarden'; },
    f => { f.run.path = '.github/workflows/unrelated.yml'; }, f => { f.run.run_attempt = 2; },
    f => { f.run.conclusion = 'failure'; }, f => { f.run.status = 'in_progress'; },
    f => { const job = f.jobs[0]; if (job) job.head_sha = OTHER_SOURCE; },
    f => { const job = f.jobs[0]; if (job) job.run_id += 1; },
    f => { const job = f.jobs[0]; if (job) job.name = 'unrelated successful check'; },
    f => { f.manifest.sourceCommit = OTHER_SOURCE; }, f => { f.bundle.sourceCommit = OTHER_SOURCE; },
    f => { f.bundle.compiledCommit = OTHER_SOURCE; },
  ];
  for (const mutate of mutations) { const fixture = releaseFixture(); mutate(fixture); expect(await verifyFixture(fixture)).toBe(1); }
});

it('CP-044/F03 authenticated artifact IDs digests ownership expiry and transport availability are required', async () => {
  const mutations: ((fixture: ReleaseFixture) => void)[] = [
    f => { f.artifact.id += 1; }, f => { f.artifact.workflow_run.id += 1; },
    f => { f.artifact.workflow_run.head_sha = OTHER_SOURCE; }, f => { f.artifact.expired = true; },
    f => { f.artifact.name = 'unrelated-artifact'; }, f => { f.digestOverride = `sha256:${'0'.repeat(64)}`; },
    f => { f.downloadedOverride = Buffer.from('untrusted caller PASS'); }, f => { f.offline = true; },
  ];
  for (const mutate of mutations) { const fixture = releaseFixture(); mutate(fixture); expect(await verifyFixture(fixture)).toBe(1); }
});

it('CP-044/F03 full reports reject skipped pending todo failed empty and inconsistent outcomes despite successful official jobs', async () => {
  for (const status of ['skipped', 'pending', 'todo', 'failed']) {
    const fixture = releaseFixture();
    changeReport(fixture, firstPlatform(fixture), report => { firstAssertion(report).status = status; });
    expect(await verifyFixture(fixture), status).toBe(1);
  }
  for (const mutate of [
    (report: TestReport): void => { report.testResults = []; report.numTotalTests = 0; report.numPassedTests = 0; },
    (report: TestReport): void => { report.numPendingTests = 1; },
    (report: TestReport): void => { report.numTodoTests = 1; },
    (report: TestReport): void => { report.numTotalTests += 1; },
    (report: TestReport): void => { report.success = false; },
  ]) {
    const fixture = releaseFixture(); changeReport(fixture, firstPlatform(fixture), mutate); expect(await verifyFixture(fixture)).toBe(1);
  }
});

it('CP-044/F03 complete source inventory rejects missing Windows Node26 shards files and substituted cases rather than trusting caller scope', async () => {
  for (const missing of ['windows', '26.5.1', '26.x', 'one-shard']) {
    const fixture = releaseFixture();
    fixture.bundle.platform = fixture.bundle.platform.filter((row, index) => missing === 'windows' ? row.os !== 'windows-latest'
      : missing === 'one-shard' ? index !== 0 : row.node !== missing);
    expect(await verifyFixture(fixture), missing).toBe(1);
  }
  for (const substitute of [false, true]) {
    const fixture = releaseFixture();
    changeReport(fixture, firstPlatform(fixture), report => {
      if (substitute) firstAssertion(report).fullName = 'synthetic replacement cannot establish a required source case';
      else {
        const removed = report.testResults.shift();
        const count = removed?.assertionResults.length ?? 0; report.numTotalTests -= count; report.numPassedTests -= count;
      }
    });
    expect(await verifyFixture(fixture)).toBe(1);
  }
});

it('CP-044/F03 actual final tarball bytes compiled metadata and every receipt source and artifact binding must agree', async () => {
  const fixture = releaseFixture(), original = readFileSync(fixture.tarballPath), originalTar = gunzipSync(original);
  const mutation = { originalSha256: sha256(original), mutatedSha256: '', refusalExitCode: null as number | null, refusalAssertionPassed: false };
  try {
    appendFileSync(fixture.tarballPath, Buffer.from('changed final artifact'));
    mutation.mutatedSha256 = sha256(readFileSync(fixture.tarballPath));
    expect(mutation.mutatedSha256, 'the verifier receives the deliberately changed compressed artifact').not.toBe(mutation.originalSha256);
    mutation.refusalExitCode = await verifyFixture(fixture);
    expect(mutation.refusalExitCode, 'post-validation artifact replacement').toBe(1);
    mutation.refusalAssertionPassed = true;
  } finally {
    // Owner-routed Linux closure diagnosis: intentional gzip corruption is a
    // temporary negative input, not retained malformed output. Keep safe hash
    // and outcome provenance; restore even when the verifier/assertion throws.
    writeFileSync(fixture.tarballPath, original);
    const restored = readFileSync(fixture.tarballPath), restoredSha256 = sha256(restored);
    const restoredValid = gunzipSync(restored).equals(originalTar);
    writeFileSync(join(fixture.root, 'tarball-mutation.json'), JSON.stringify({ ...mutation, restoredSha256, restoredValid }));
    expect(restored, 'fixture teardown restores the exact original compressed bytes').toEqual(original);
    expect(restoredValid, 'the retained fixture is again a valid unchanged gzip archive').toBe(true);
  }
  // Actual compressed build metadata is wrong while every declared hash,
  // report, receipt, bundle and official run still consistently names SOURCE.
  const wrongMetadata = releaseFixture(OTHER_SOURCE);
  expect(await verifyFixture(wrongMetadata)).toBe(1);
  for (const field of ['sourceCommit', 'compiledCommit', 'tarballSha256', 'jobId', 'reportSha256', 'complete', 'exitCode']) {
    const candidate = releaseFixture();
    changeMember(candidate, firstPlatform(candidate).receipt, receipt => {
      receipt[field] = field === 'complete' ? false : field === 'exitCode' ? 1 : field === 'jobId' ? 999999 : OTHER_SOURCE;
    });
    expect(await verifyFixture(candidate), field).toBe(1);
  }
});

it('CP-044/F04 complete owned live plan live-case outcomes and every required scenario are mandatory', async () => {
  for (const missing of ['owner', 'lab-owner', 'lab', 'chaos', 'case', 'scenario']) {
    const fixture = releaseFixture();
    if (missing === 'owner') Reflect.deleteProperty(fixture.bundle.live, 'ownerPlan');
    else if (missing === 'lab-owner') Reflect.deleteProperty(liveRow(fixture, 'lab'), 'ownerPlan');
    else if (missing === 'lab' || missing === 'chaos') Reflect.deleteProperty(fixture.bundle.live, missing);
    else if (missing === 'scenario') fixture.bundle.live.rows = fixture.bundle.live.rows.filter(row => row.id !== 'T-05');
    else changeReport(fixture, liveRow(fixture, 'lab'), report => {
      const removed = report.testResults.shift(); const count = removed?.assertionResults.length ?? 0;
      report.numTotalTests -= count; report.numPassedTests -= count;
    });
    expect(await verifyFixture(fixture), missing).toBe(1);
  }
  for (const status of ['GAP', 'PARTIAL']) {
    const fixture = releaseFixture(), scenario = fixture.bundle.live.rows.find(row => row.id === 'T-25');
    if (!scenario) throw new Error('required T-25 fixture absent'); scenario.status = status;
    expect(await verifyFixture(fixture), status).toBe(1);
  }
  for (const field of ['exclusive', 'network', 'sourceCommit']) {
    const fixture = releaseFixture(), plan = fixture.bundle.live.ownerPlan;
    if (!plan) throw new Error('required owner fixture absent');
    changeMember(fixture, plan, value => { value[field] = field === 'exclusive' ? false : field === 'network' ? 'mainnet' : OTHER_SOURCE; });
    expect(await verifyFixture(fixture), field).toBe(1);
  }
  for (const field of ['exclusive', 'network', 'sourceCommit', 'ownerId']) {
    const fixture = releaseFixture(), shared = fixture.bundle.live.ownerPlan;
    if (!shared) throw new Error('shared chaos owner fixture absent');
    const plan = { ...readMember(fixture, shared) };
    plan[field] = field === 'exclusive' ? false : field === 'network' ? 'mainnet' : field === 'ownerId' ? '' : OTHER_SOURCE;
    const path = 'live/lab-owner-plan.json', bytes = Buffer.from(JSON.stringify(plan));
    fixture.files.set(path, bytes); liveRow(fixture, 'lab').ownerPlan = { path, sha256: sha256(bytes) };
    expect(readMember(fixture, shared)['exclusive'], 'the separate chaos plan remains valid').toBe(true);
    expect(await verifyFixture(fixture), `separate lab owner ${field}`).toBe(1);
  }
});

it('CP-044/F04 final demonstration requires retained T05 same-hash one-send ledger checksums and complete scan evidence', async () => {
  for (const field of ['compiledCommit', 'sameHashRecovery', 'sendCount', 'ledgerVerified', 'checksumsVerified', 'completeLeakScan', 'scenarioRecord']) {
    const fixture = releaseFixture();
    changeMember(fixture, fixture.bundle.demo.evidence, value => {
      if (field === 'scenarioRecord') Reflect.deleteProperty(value, field);
      else value[field] = field === 'compiledCommit' ? OTHER_SOURCE : field === 'sendCount' ? 2 : false;
    });
    expect(await verifyFixture(fixture), field).toBe(1);
  }
  const fixture = releaseFixture();
  const demo = readMember(fixture, fixture.bundle.demo.evidence) as { scenarioRecord: { path: string } };
  fixture.files.delete(demo.scenarioRecord.path);
  expect(await verifyFixture(fixture), 'record absent despite demonstration PASS fields').toBe(1);
});

it('CP-044/F03 final scan installed smoke publisher configuration and actual protected environment refuse missing or forged PASS claims', async () => {
  for (const key of ['leakScan', 'installedSmoke', 'publisher'] as const) {
    const fixture = releaseFixture(); fixture.files.delete(fixture.bundle[key].evidence.path);
    expect(await verifyFixture(fixture), `${key} actual evidence missing`).toBe(1);
    const stale = releaseFixture();
    changeMember(stale, stale.bundle[key].evidence, value => { value['tarballSha256'] = '0'.repeat(64); });
    expect(await verifyFixture(stale), `${key} unrelated artifact`).toBe(1);
  }
  const fixture = releaseFixture(); fixture.environment.protection_rules = [];
  expect(await verifyFixture(fixture), 'YAML environment name cannot prove protection configured').toBe(1);
  const publisher = releaseFixture();
  changeMember(publisher, publisher.bundle.publisher.evidence, value => { value['trustedPublisherVerified'] = false; });
  expect(await verifyFixture(publisher), 'OIDC permission cannot prove trusted publisher configured').toBe(1);
});

it('CP-044/F03 authenticated evidence refuses missing changed and traversing artifact members', async () => {
  const missing = releaseFixture(); missing.files.delete(firstPlatform(missing).report.path);
  expect(await verifyFixture(missing)).toBe(1);
  const changed = releaseFixture(); changed.files.set(firstPlatform(changed).report.path, Buffer.from('{"success":true}'));
  expect(await verifyFixture(changed)).toBe(1);
  const traversal = releaseFixture(); traversal.files.set('../escaped-evidence.json', Buffer.from('{}'));
  expect(await verifyFixture(traversal)).toBe(1);
});
