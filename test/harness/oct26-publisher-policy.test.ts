// Owner D29: actual repository has no protected branch; protected_branches:true
// therefore admits all branches. These public account/policy fixtures contain
// no credentials and never perform a deployment approval or publication.
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { asRecord, readText, repoRoot } from '../helpers/cli.js';
import { parseYaml } from '../helpers/yaml.js';

function policy() {
  return { environment: { name: 'npm-release', can_admins_bypass: false,
    protection_rules: [{ type: 'required_reviewers', prevent_self_review: false,
      reviewers: [{ type: 'User', reviewer: { id: 197366966, login: 'ZilverZtream' } }] }],
    deployment_branch_policy: { protected_branches: false, custom_branch_policies: true } },
  deploymentPolicies: [{ id: 1, name: 'v1.*', type: 'tag' }] };
}
type Policy = ReturnType<typeof policy>;
function github(value: Policy) {
  return { getEnvironment: (name: string): Promise<Policy['environment']> => name === 'npm-release'
    ? Promise.resolve(value.environment) : Promise.reject(new Error('unrelated environment')),
  getDeploymentBranchPolicies: (name: string): Promise<Policy['deploymentPolicies']> => name === 'npm-release'
    ? Promise.resolve(value.deploymentPolicies) : Promise.reject(new Error('unrelated environment')) };
}
async function verifier(): Promise<(source: ReturnType<typeof github>, environment?: Policy['environment']) => Promise<Policy['environment']>> {
  const api = await import(pathToFileURL(join(repoRoot, 'scripts/release-gate.mjs')).href) as {
    verifyPublisherEnvironment: (source: ReturnType<typeof github>, environment?: Policy['environment']) => Promise<Policy['environment']>;
  };
  return api.verifyPublisherEnvironment;
}

it('CP-044/F03 publisher protection accepts only the owner-approved reviewed v1 tag environment and permits single-owner self-review policy', async () => {
  const verify = await verifier(), value = policy();
  expect(await verify(github(value))).toEqual(value.environment);
  expect(await verify(github(value), value.environment)).toEqual(value.environment);
});

it('CP-044/F03 missing broad branch extra and wrong-version deployment policies cannot authorize publication', async () => {
  const verify = await verifier();
  const mutations: ((value: Policy) => void)[] = [
    value => { value.deploymentPolicies = []; },
    value => { value.deploymentPolicies[0] = { id: 1, name: '*', type: 'tag' }; },
    value => { value.deploymentPolicies[0] = { id: 1, name: 'v*', type: 'tag' }; },
    value => { value.deploymentPolicies[0] = { id: 1, name: 'v2.*', type: 'tag' }; },
    value => { value.deploymentPolicies[0] = { id: 1, name: 'v1.*', type: 'branch' }; },
    value => { value.deploymentPolicies.push({ id: 2, name: '*', type: 'branch' }); },
    value => { value.environment.deployment_branch_policy = { protected_branches: true, custom_branch_policies: false }; },
    value => { value.environment.deployment_branch_policy.custom_branch_policies = false; },
  ];
  for (const mutate of mutations) { const value = policy(); mutate(value); await expect(verify(github(value))).rejects.toThrow(); }
});

it('CP-044/F03 missing or substituted owner review and administrator bypass refuse even with a correct tag policy', async () => {
  const verify = await verifier();
  const mutations: ((value: Policy) => void)[] = [
    value => { value.environment.name = 'unrelated'; }, value => { value.environment.can_admins_bypass = true; },
    value => { Reflect.deleteProperty(value.environment, 'can_admins_bypass'); },
    value => { value.environment.protection_rules = []; },
    value => { const rule = value.environment.protection_rules[0]; if (rule) rule.reviewers = []; },
    value => { const reviewer = value.environment.protection_rules[0]?.reviewers[0]; if (reviewer) reviewer.reviewer.id = 123; },
    value => { const reviewer = value.environment.protection_rules[0]?.reviewers[0]; if (reviewer) reviewer.reviewer.login = 'unrelated'; },
    value => { const reviewer = value.environment.protection_rules[0]?.reviewers[0]; if (reviewer) reviewer.type = 'Team'; },
    value => { const rule = value.environment.protection_rules[0]; if (rule) rule.reviewers.push({ type: 'User', reviewer: { id: 123, login: 'unrelated' } }); },
    value => { const rule = value.environment.protection_rules[0]; if (rule) Reflect.deleteProperty(rule, 'prevent_self_review'); },
    value => { const rule = value.environment.protection_rules[0]; if (rule) Reflect.set(rule, 'prevent_self_review', 'false'); },
  ];
  for (const mutate of mutations) { const value = policy(); mutate(value); await expect(verify(github(value))).rejects.toThrow(); }
});

it('CP-044/F03 read-only publisher preflight does not request the protected deployment environment while actual publication does', () => {
  const ci = asRecord(parseYaml(readText('.github/workflows/ci.yml')), 'CI');
  const jobs = asRecord(ci['jobs'], 'jobs');
  const preflight = Object.entries(jobs).map(([id, job]) => ({ id, job: asRecord(job, id) }))
    .find(({ id, job }) => (job['name'] ?? id) === 'release/publisher');
  expect(preflight, 'actual CI preflight required').toBeDefined();
  expect(preflight?.job['environment'], 'v1 tag protection must not block ordinary branch CI preflight').toBeUndefined();
  const release = asRecord(parseYaml(readText('.github/workflows/release.yml')), 'release');
  const publishing = Object.values(asRecord(release['jobs'], 'release jobs')).map(job => asRecord(job, 'job')).find(job =>
    Array.isArray(job['steps']) && job['steps'].some(step => /\bnpm publish\b/.test(String(asRecord(step, 'step')['run'] ?? ''))));
  expect(publishing?.['environment'], 'actual publication requires the owner approval environment').toBe('npm-release');
});
