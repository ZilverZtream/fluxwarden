// D29 public authentication boundary. These are synthetic official-transport
// fixtures, never evidence that any native platform/runtime validation ran.
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';
import { independentInventory, OTHER_SOURCE, sha256, SOURCE, zip, type Inventory, type OfficialJob } from '../helpers/oct26-release-gate.js';

interface Payload {
  schemaVersion: number; sourceCommit: string; compiledCommit: string; tarballSha256: string; key: string;
  jobId: number; os: string; node: string; platform: string; runtime: string;
  cases: { product: { file: string; name: string }[]; harness: { file: string; name: string }[] };
}
interface Artifact { id: number; name: string; expired: boolean; workflow_run: { id: number; head_sha: string }; digest?: string; size_in_bytes?: number }
interface Fixture { expected: Inventory['casesByTarget']; jobs: OfficialJob[]; payloads: Map<number, Payload>; artifacts: Artifact[]; digestMismatch?: boolean }
const TARBALL_SHA256 = '4'.repeat(64);

function fixture(): Fixture {
  const expected = independentInventory().casesByTarget, jobs: OfficialJob[] = [], payloads = new Map<number, Payload>(), artifacts: Artifact[] = [];
  for (const [key, cases] of Object.entries(expected)) {
    const [os = '', node = ''] = key.split('/'), jobId = 2000 + jobs.length, artifactId = 3000 + jobs.length;
    const moving: Record<string, string> = { '22.x': '22.23.2', '24.x': '24.21.0', '26.x': '26.12.1' };
    jobs.push({ id: jobId, run_id: 777, head_sha: SOURCE, name: `inventory/${key}`, status: 'completed', conclusion: 'success',
      steps: [{ name: 'Collect complete frozen source inventory', status: 'completed', conclusion: 'success' }] });
    payloads.set(artifactId, { schemaVersion: 1, sourceCommit: SOURCE, compiledCommit: SOURCE, tarballSha256: TARBALL_SHA256,
      key, jobId, os, node, platform: os === 'windows-latest' ? 'win32' : 'linux', runtime: `v${moving[node] ?? node}`, cases });
    artifacts.push({ id: artifactId, name: `fluxwarden-inventory-${os}-${node}`, expired: false, workflow_run: { id: 777, head_sha: SOURCE } });
  }
  return { expected, jobs, payloads, artifacts };
}

function githubFor(value: Fixture): {
  listJobs: () => Promise<OfficialJob[]>; listArtifacts: () => Promise<Artifact[]>;
  getArtifact: (id: number) => Promise<Artifact | undefined>; downloadArtifact: (id: number) => Promise<Buffer>;
} {
  const archives = new Map<number, Buffer>();
  for (const artifact of value.artifacts) {
    const payload = value.payloads.get(artifact.id);
    const bytes = zip(new Map([['inventory.json', Buffer.from(JSON.stringify(payload))]]));
    artifact.digest = `sha256:${value.digestMismatch ? '0'.repeat(64) : sha256(bytes)}`; artifact.size_in_bytes = bytes.length;
    archives.set(artifact.id, bytes);
  }
  return {
    listJobs: () => Promise.resolve(value.jobs), listArtifacts: () => Promise.resolve(value.artifacts),
    getArtifact: (id: number) => Promise.resolve(value.artifacts.find(row => row.id === id)),
    downloadArtifact: (id: number) => {
      const archive = archives.get(id);
      return archive ? Promise.resolve(archive) : Promise.reject(new Error('synthetic inventory artifact absent'));
    },
  };
}
type Authenticate = (input: { github: ReturnType<typeof githubFor>; sourceCommit: string; runId: number; runAttempt: number; tarballSha256: string }) => Promise<Inventory['casesByTarget']>;
async function authenticator(): Promise<Authenticate> {
  const api = await import(pathToFileURL(join(repoRoot, 'scripts/release-ci.mjs')).href) as { authenticateTargetInventories: Authenticate };
  return api.authenticateTargetInventories;
}
const input = (value: Fixture): Parameters<Authenticate>[0] => ({ github: githubFor(value), sourceCommit: SOURCE, runId: 777, runAttempt: 1, tarballSha256: TARBALL_SHA256 });

it('CP-044/F10 authenticated complete collectors preserve unequal eligible inventories for every actual target', async () => {
  const authenticate = await authenticator(), value = fixture();
  expect(Object.keys(value.expected)).toHaveLength(12);
  expect(value.expected['ubuntu-latest/24.x']?.product).toHaveLength(1658);
  expect(value.expected['windows-latest/24.x']?.product).toHaveLength(1685);
  expect(await authenticate(input(value))).toEqual(value.expected);
});
it('CP-044/F10 absent failing canceled skipped stale and unrelated official collection jobs cannot supply expected scope', async () => {
  const authenticate = await authenticator();
  const mutations: ((value: Fixture) => void)[] = [
    value => { value.jobs.pop(); },
    ...['failure', 'cancelled', 'skipped'].map(conclusion => (value: Fixture): void => { const job = value.jobs[0]; if (job) job.conclusion = conclusion; }),
    value => { const job = value.jobs[0]; if (job) { job.status = 'in_progress'; job.conclusion = null; } },
    value => { const job = value.jobs[0]; if (job) job.head_sha = OTHER_SOURCE; },
    value => { const job = value.jobs[0]; if (job) job.run_id += 1; },
    value => { const job = value.jobs[0]; if (job) job.name = 'unrelated collection'; },
  ];
  for (const mutate of mutations) { const value = fixture(); mutate(value); await expect(authenticate(input(value))).rejects.toThrow(); }
});

it('CP-044/F10 authenticated collection rejects forged artifacts and source compiled tarball target platform or runtime rebinding', async () => {
  const authenticate = await authenticator();
  const mutations: ((value: Fixture) => void)[] = [
    value => { value.artifacts.pop(); }, value => { value.digestMismatch = true; },
    value => { const artifact = value.artifacts[0]; if (artifact) artifact.expired = true; },
    value => { const artifact = value.artifacts[0]; if (artifact) artifact.workflow_run.id += 1; },
    value => { const artifact = value.artifacts[0]; if (artifact) artifact.workflow_run.head_sha = OTHER_SOURCE; },
    ...['sourceCommit', 'compiledCommit', 'tarballSha256', 'key', 'jobId', 'os', 'node', 'platform', 'runtime'].map(field => (value: Fixture): void => {
      const payload = value.payloads.values().next().value;
      if (!payload) throw new Error('independent collection fixture absent');
      if (field === 'jobId') payload.jobId += 1;
      else if (field === 'platform') payload.platform = 'win32'; // first fixture is Linux
      else if (field === 'runtime') payload.runtime = 'v26.12.1'; // first fixture is minimum Node22
      else if (field === 'os') payload.os = 'windows-latest';
      else if (field === 'node') payload.node = '26.x';
      else if (field === 'key') payload.key = 'windows-latest/22.23.2';
      else if (field === 'sourceCommit') payload.sourceCommit = OTHER_SOURCE;
      else if (field === 'compiledCommit') payload.compiledCommit = OTHER_SOURCE;
      else payload.tarballSha256 = '0'.repeat(64);
    }),
    value => { const payload = value.payloads.values().next().value; if (payload) payload.cases.product = []; },
  ];
  for (const mutate of mutations) { const value = fixture(); mutate(value); await expect(authenticate(input(value))).rejects.toThrow(); }
});
