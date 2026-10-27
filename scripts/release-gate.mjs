// Authenticate immutable GitHub artifact bytes before interpreting release claims.
// ZIP central-directory validation follows nodejs/node deps/zlib/contrib/minizip/unzip.c;
// tar header checks follow npm/node-tar src/header.ts. Neither is a runtime dependency.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { gunzipSync, inflateRawSync } from 'node:zlib';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deriveInventory, reportedCaseName, requiredLiveRows } from './release-inventory.mjs';
import { validateObservations } from './release-observations.mjs';

export const repository = 'ZilverZtream/fluxwarden';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const requireThat = value => { if (!value) throw new Error('release gate: evidence refused'); };
const object = value => { requireThat(value && typeof value === 'object' && !Array.isArray(value)); return value; };
const array = value => { requireThat(Array.isArray(value)); return value; };
const positive = value => Number.isSafeInteger(value) && value > 0;
const safePath = value => typeof value === 'string' && value.length > 0 && !value.includes('\\') && !value.includes('\0') &&
  !value.startsWith('/') && !value.split('/').some(part => !part || part === '.' || part === '..') && !value.includes(':');
const json = bytes => object(JSON.parse(bytes.toString('utf8')));
const crcTable = Array.from({ length: 256 }, (_, n) => { for (let i = 0; i < 8; i++) n = n & 1 ? 0xedb88320 ^ n >>> 1 : n >>> 1; return n >>> 0; });
const crc32 = bytes => { let n = 0xffffffff; for (const byte of bytes) n = crcTable[(n ^ byte) & 255] ^ n >>> 8; return (n ^ 0xffffffff) >>> 0; };

export function zipMembers(bytes) {
  requireThat(Buffer.isBuffer(bytes) && bytes.length >= 22 && bytes.length <= 256 * 1024 * 1024);
  // No ZIP64, split archives, encrypted entries, directory entries or symlinks.
  const end = bytes.length - 22;
  requireThat(bytes.readUInt32LE(end) === 0x06054b50 && bytes.readUInt16LE(end + 20) === 0 &&
    bytes.readUInt16LE(end + 4) === 0 && bytes.readUInt16LE(end + 6) === 0);
  const count = bytes.readUInt16LE(end + 10), start = bytes.readUInt32LE(end + 16);
  requireThat(count > 0 && count === bytes.readUInt16LE(end + 8) && start + bytes.readUInt32LE(end + 12) === end);
  let at = start, localEnd = 0, expanded = 0;
  const files = new Map();
  for (let i = 0; i < count; i++) {
    requireThat(at + 46 <= end && bytes.readUInt32LE(at) === 0x02014b50);
    const flags = bytes.readUInt16LE(at + 8), method = bytes.readUInt16LE(at + 10), crc = bytes.readUInt32LE(at + 16);
    const compressed = bytes.readUInt32LE(at + 20), size = bytes.readUInt32LE(at + 24);
    const length = bytes.readUInt16LE(at + 28), extra = bytes.readUInt16LE(at + 30), comment = bytes.readUInt16LE(at + 32);
    const offset = bytes.readUInt32LE(at + 42), mode = bytes.readUInt32LE(at + 38) >>> 16;
    requireThat(at + 46 + length + extra + comment <= end && !(flags & ~0x808) && [0, 8].includes(method) &&
      bytes.readUInt16LE(at + 34) === 0 && (mode === 0 || (mode & 0xf000) === 0x8000));
    const nameBytes = bytes.subarray(at + 46, at + 46 + length), name = nameBytes.toString('utf8');
    requireThat(Buffer.from(name).equals(nameBytes) && safePath(name) && !files.has(name));
    requireThat(offset === localEnd && offset + 30 <= start && bytes.readUInt32LE(offset) === 0x04034b50 &&
      bytes.readUInt16LE(offset + 6) === flags && bytes.readUInt16LE(offset + 8) === method && bytes.readUInt16LE(offset + 26) === length);
    const localExtra = bytes.readUInt16LE(offset + 28), dataStart = offset + 30 + length + localExtra;
    requireThat(bytes.subarray(offset + 30, offset + 30 + length).equals(nameBytes) && dataStart + compressed <= start);
    if (!(flags & 8)) requireThat(bytes.readUInt32LE(offset + 14) === crc && bytes.readUInt32LE(offset + 18) === compressed && bytes.readUInt32LE(offset + 22) === size);
    expanded += size; requireThat(size <= 64 * 1024 * 1024 && expanded <= 256 * 1024 * 1024);
    const packed = bytes.subarray(dataStart, dataStart + compressed);
    const content = method === 0 ? packed : inflateRawSync(packed, { maxOutputLength: 64 * 1024 * 1024 });
    requireThat(content.length === size && crc32(content) === crc);
    localEnd = dataStart + compressed;
    if (flags & 8) {
      if (bytes.readUInt32LE(localEnd) === 0x08074b50) localEnd += 4;
      requireThat(bytes.readUInt32LE(localEnd) === crc && bytes.readUInt32LE(localEnd + 4) === compressed && bytes.readUInt32LE(localEnd + 8) === size);
      localEnd += 12;
    }
    files.set(name, content); at += 46 + length + extra + comment;
  }
  requireThat(at === end && localEnd === start);
  return files;
}

export function tarballMembers(bytes) {
  const tar = gunzipSync(bytes, { maxOutputLength: 128 * 1024 * 1024 });
  let at = 0, commit; const names = new Set(), members = new Map();
  while (at + 512 <= tar.length) {
    const header = tar.subarray(at, at + 512);
    if (header.every(byte => byte === 0)) { requireThat(tar.subarray(at).every(byte => byte === 0)); break; }
    const text = (a, b) => header.subarray(a, b).toString('utf8').replace(/\0.*$/s, '');
    const name = (text(345, 500) ? text(345, 500) + '/' : '') + text(0, 100), sizeText = text(124, 136).trim();
    requireThat(safePath(name) && name.startsWith('package/') && !names.has(name) && /^[0-7]+$/.test(sizeText) && [0, 48].includes(header[156]));
    const declared = text(148, 156).trim(); requireThat(/^[0-7]+$/.test(declared));
    const checksum = header.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
    requireThat(checksum === parseInt(declared, 8));
    const size = parseInt(sizeText, 8); requireThat(Number.isSafeInteger(size) && at + 512 + size <= tar.length);
    names.add(name);
    members.set(name, tar.subarray(at + 512, at + 512 + size));
    if (name === 'package/dist/evidence/build-info.json') {
      const info = json(tar.subarray(at + 512, at + 512 + size)); requireThat(Object.keys(info).join() === 'gitCommit'); commit = info.gitCommit;
    }
    at += 512 + Math.ceil(size / 512) * 512;
  }
  requireThat(commit && at + 1024 <= tar.length); return members;
}
export const compiledSource = bytes => json(tarballMembers(bytes).get('package/dist/evidence/build-info.json')).gitCommit;

function caseIdentity(file, name) {
  requireThat(typeof file === 'string' && typeof name === 'string' && name.length > 0);
  const clean = file.replaceAll('\\', '/');
  const normalized = clean.startsWith('test/') ? clean : clean.slice(clean.lastIndexOf('/test/') + 1);
  requireThat(safePath(normalized) && normalized.startsWith('test/'));
  return JSON.stringify([normalized, name]);
}
function exactCases(actual, expected) {
  const identities = array(expected).map(row => caseIdentity(row.file, row.name));
  requireThat(identities.length > 0 && new Set(identities).size === identities.length && actual.length === identities.length &&
    new Set(actual).size === actual.length && identities.every(id => actual.includes(id)));
}

export async function verifyPublisherEnvironment(github, environment) {
  const actual = environment ?? await github.getEnvironment('npm-release');
  requireThat(actual.name === 'npm-release' && actual.can_admins_bypass === false &&
    actual.deployment_branch_policy?.protected_branches === false && actual.deployment_branch_policy?.custom_branch_policies === true);
  const rules = array(actual.protection_rules).filter(rule => rule.type === 'required_reviewers');
  requireThat(rules.length === 1 && typeof rules[0].prevent_self_review === 'boolean' && array(rules[0].reviewers).length === 1 &&
    rules[0].reviewers[0].type === 'User' && rules[0].reviewers[0].reviewer?.id === 197366966 &&
    rules[0].reviewers[0].reviewer?.login === 'ZilverZtream');
  const policies = await github.getDeploymentBranchPolicies('npm-release');
  requireThat(array(policies).length === 1 && policies[0].type === 'tag' && policies[0].name === 'v1.*');
  return actual;
}

export async function verifyRelease(input, dependencies) {
  try {
    const { sourceCommit: source, tarballPath, manifest: m } = object(input), { inventory, github } = object(dependencies);
    requireThat(/^[0-9a-f]{40}$/.test(source) && m.schemaVersion === 1 && m.repository === repository && m.sourceCommit === source &&
      m.ci.workflowPath === '.github/workflows/ci.yml' && positive(m.ci.runId) && positive(m.ci.runAttempt) && positive(m.ci.artifactId));
    const tarball = readFileSync(tarballPath), tarballHash = hash(tarball);
    const tarBinding = value => value.sha256 === tarballHash && value.bytes === tarball.length;
    requireThat(tarBinding(m.tarball) && compiledSource(tarball) === source);
    const [run, jobs, artifact, environment] = await Promise.all([github.getRun(m.ci.runId), github.listJobs(m.ci.runId, m.ci.runAttempt),
      github.getArtifact(m.ci.artifactId), github.getEnvironment('npm-release')]);
    requireThat(run.id === m.ci.runId && run.run_attempt === m.ci.runAttempt && run.path === m.ci.workflowPath && run.head_sha === source &&
      run.repository.full_name === repository && run.status === 'completed' && run.conclusion === 'success');
    requireThat(artifact.id === m.ci.artifactId && artifact.name === 'fluxwarden-release-evidence' && artifact.expired === false &&
      artifact.workflow_run.id === m.ci.runId && artifact.workflow_run.head_sha === source && positive(artifact.size_in_bytes));
    const downloaded = await github.downloadArtifact(m.ci.artifactId);
    requireThat(Buffer.isBuffer(downloaded) && artifact.size_in_bytes === downloaded.length && artifact.digest === `sha256:${hash(downloaded)}`);
    const files = zipMembers(downloaded), used = new Set(['release-evidence.json']);
    const b = json(files.get('release-evidence.json'));
    requireThat(b.schemaVersion === 1 && b.sourceCommit === source && b.compiledCommit === source && tarBinding(b.tarball));
    const read = reference => {
      requireThat(reference && safePath(reference.path) && /^[a-f0-9]{64}$/.test(reference.sha256));
      const bytes = files.get(reference.path); requireThat(bytes && hash(bytes) === reference.sha256); used.add(reference.path); return json(bytes);
    };
    const bound = reference => { const value = read(reference); requireThat(value.sourceCommit === source && value.compiledCommit === source && value.tarballSha256 === tarballHash); return value; };
    const jobIds = new Set(), keys = new Set();
    const checkJob = (row, key) => {
      requireThat(row && row.key === key && positive(row.jobId) && !keys.has(key) && !jobIds.has(row.jobId));
      const matches = array(jobs).filter(job => job.id === row.jobId || job.name === key);
      requireThat(matches.length === 1); const job = matches[0];
      requireThat(job.id === row.jobId && job.name === key && job.run_id === run.id && job.head_sha === source &&
        job.status === 'completed' && job.conclusion === 'success' && array(job.steps).length > 0 &&
        job.steps.every(step => step.status === 'completed' && step.conclusion === 'success'));
      keys.add(key); jobIds.add(row.jobId);
    };
    const report = row => {
      const receipt = bound(row.receipt), report = read(row.report);
      requireThat(receipt.jobId === row.jobId && receipt.complete === true && receipt.exitCode === 0 && receipt.reportSha256 === row.report.sha256);
      requireThat(report.success === true && report.numFailedTests === 0 && report.numPendingTests === 0 && report.numTodoTests === 0 && array(report.testResults).length > 0);
      const identities = [];
      for (const file of report.testResults) {
        requireThat(array(file.assertionResults).length > 0);
        for (const assertion of file.assertionResults) { requireThat(assertion.status === 'passed'); identities.push(caseIdentity(file.name, reportedCaseName(assertion))); }
      }
      requireThat(identities.length > 0 && report.numTotalTests === identities.length && report.numPassedTests === identities.length);
      return identities;
    };
    requireThat(array(b.platform).length === array(inventory.platformJobs).length);
    const unions = new Map();
    for (const required of inventory.platformJobs) {
      const matches = b.platform.filter(row => row.key === required.key); requireThat(matches.length === 1); const row = matches[0];
      requireThat(['os', 'node', 'shard', 'suite'].every(field => row[field] === required[field]));
      checkJob(row, required.key); const group = `${required.os}/${required.node}/${required.suite}`;
      unions.set(group, [...(unions.get(group) ?? []), ...report(row)]);
    }
    for (const [group, cases] of unions) {
      const [os, node, suite] = group.split('/');
      exactCases(cases, inventory.casesByTarget?.[`${os}/${node}`]?.[suite]);
    }
    const plan = read(b.live.ownerPlan); requireThat(plan.sourceCommit === source && plan.exclusive === true && plan.network === 'regtest' && typeof plan.ownerId === 'string' && plan.ownerId.length > 0);
    for (const suite of ['lab', 'chaos']) {
      checkJob(b.live[suite], `live/${suite}`); exactCases(report(b.live[suite]), inventory.cases[suite]);
      if (suite === 'lab') {
        const owner = read(b.live[suite].ownerPlan);
        requireThat(owner.sourceCommit === source && owner.exclusive === true && owner.network === 'regtest' && typeof owner.ownerId === 'string' && owner.ownerId.length > 0);
      }
    }
    const liveRows = array(b.live.rows);
    requireThat(array(inventory.requiredLiveRows).length === requiredLiveRows.length && requiredLiveRows.every(id => inventory.requiredLiveRows.includes(id)) && liveRows.length === requiredLiveRows.length);
    for (const id of requiredLiveRows) {
      const matches = liveRows.filter(row => row.id === id); requireThat(matches.length === 1 && matches[0].status === 'PASS');
      const evidence = bound(matches[0].evidence); requireThat(evidence.row === id && evidence.complete === true);
      validateObservations(id, evidence, read, { sourceCommit: source, tarballSha256: tarballHash, ownerId: plan.ownerId });
    }
    for (const kind of ['demo', 'leakScan', 'installedSmoke', 'publisher']) {
      const key = { demo: 'demo', leakScan: 'leak-scan', installedSmoke: 'installed-smoke', publisher: 'publisher' }[kind];
      checkJob(b[kind], `release/${key}`); const evidence = bound(b[kind].evidence);
      if (kind === 'demo') {
        requireThat(evidence.sameHashRecovery === true && evidence.sendCount === 1 && evidence.ledgerVerified === true && evidence.checksumsVerified === true && evidence.completeLeakScan === true);
        const scenario = bound(evidence.scenarioRecord); requireThat(scenario.scenario === 'T-05' && scenario.sendCount === 1);
      } else if (kind === 'publisher') requireThat(evidence.environment === 'npm-release' && evidence.repository === repository && evidence.workflow === 'release.yml' && evidence.package === 'fluxwarden' && evidence.oidc === true && evidence.trustedPublisherVerified === true);
      else requireThat(evidence.complete === true && evidence.exitCode === 0);
    }
    await verifyPublisherEnvironment(github, environment);
    requireThat([...files.keys()].every(name => used.has(name)));
    return 0;
  } catch { return 1; }
}

// Only this API adapter performs production authentication; callers cannot choose
// another repository, API host, source inventory or decoded evidence object.
export function officialGitHub(token) {
  requireThat(typeof token === 'string' && token.length > 0);
  const base = `https://api.github.com/repos/${repository}`;
  const request = async (path, binary = false) => {
    const response = await fetch(base + path, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }, signal: AbortSignal.timeout(30_000), redirect: binary ? 'follow' : 'error' });
    requireThat(response.ok); return binary ? Buffer.from(await response.arrayBuffer()) : await response.json();
  };
  return {
    listRuns: async source => {
      requireThat(/^[a-f0-9]{40}$/.test(source));
      const runs = [];
      for (let page = 1; ; page++) {
        const result = await request(`/actions/workflows/ci.yml/runs?head_sha=${source}&status=success&per_page=100&page=${page}`);
        runs.push(...array(result.workflow_runs));
        if (runs.length === result.total_count) return runs;
        requireThat(result.workflow_runs.length > 0 && runs.length < result.total_count);
      }
    },
    listArtifacts: async id => {
      const artifacts = [];
      for (let page = 1; ; page++) {
        const result = await request(`/actions/runs/${id}/artifacts?per_page=100&page=${page}`);
        artifacts.push(...array(result.artifacts));
        if (artifacts.length === result.total_count) return artifacts;
        requireThat(result.artifacts.length > 0 && artifacts.length < result.total_count);
      }
    },
    getRun: id => request(`/actions/runs/${id}`),
    listJobs: async (id, attempt) => {
      const jobs = [];
      for (let page = 1; ; page++) { const response = await request(`/actions/runs/${id}/attempts/${attempt}/jobs?per_page=100&page=${page}`); jobs.push(...array(response.jobs)); if (jobs.length === response.total_count) return jobs; requireThat(response.jobs.length > 0 && jobs.length < response.total_count); }
    },
    getArtifact: id => request(`/actions/artifacts/${id}`), downloadArtifact: id => request(`/actions/artifacts/${id}/zip`, true),
    getEnvironment: name => request(`/environments/${name}`),
    getDeploymentBranchPolicies: async name => {
      const policies = [];
      for (let page = 1; ; page++) {
        const response = await request(`/environments/${name}/deployment-branch-policies?per_page=100&page=${page}`);
        policies.push(...array(response.branch_policies));
        if (policies.length === response.total_count) return policies;
        requireThat(response.branch_policies.length > 0 && policies.length < response.total_count);
      }
    },
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2); requireThat(args.length === 6 && args[0] === '--source' && args[2] === '--tarball' && args[4] === '--evidence');
    const sourceCommit = args[1], tarballPath = resolve(args[3]), manifest = json(readFileSync(args[5]));
    const github = officialGitHub(process.env.GITHUB_TOKEN);
    const inventory = await deriveInventory(sourceCommit, ['lab', 'chaos']);
    const { authenticateTargetInventories } = await import('./release-ci.mjs');
    inventory.casesByTarget = await authenticateTargetInventories({ github, sourceCommit, runId: manifest.ci.runId, runAttempt: manifest.ci.runAttempt, tarballSha256: hash(readFileSync(tarballPath)) });
    process.exitCode = await verifyRelease({ sourceCommit, tarballPath, manifest }, { inventory, github });
    if (process.exitCode === 0) writeFileSync(`${tarballPath}.publication-evidence.json`, JSON.stringify({ sourceCommit, tarballSha256: hash(readFileSync(tarballPath)), evidence: manifest.ci }) + '\n', { flag: 'wx', mode: 0o600 });
    else process.stderr.write('release gate: authenticated evidence refused\n');
  } catch { process.stderr.write('release gate: authenticated evidence unavailable\n'); process.exitCode = 1; }
}
