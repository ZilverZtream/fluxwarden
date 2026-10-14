import { expect, it } from 'vitest';
import { asRecord, readJson } from '../helpers/cli.js';
import { boundaryCases, toolingCases } from '../architecture/cases.js';
import { lintBoundary, technicalMessage } from '../architecture/lint.js';

const runtimeFields = ['dependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'bundledDependencies'];
function dependencyViolations(pkg: Record<string, unknown>): string[] {
  return runtimeFields.filter(field => {
    const value = pkg[field];
    return value !== undefined && !(Array.isArray(value) ? value.length === 0 : value !== null && typeof value === 'object' && Object.keys(value).length === 0);
  });
}

it('CP-005/B2 every runtime dependency field is refused by name and the development-only package passes', () => {
  const pkg = asRecord(readJson('package.json'), 'package.json');
  expect(dependencyViolations(pkg)).toEqual([]);
  for (const field of runtimeFields) {
    for (const entry of [{ transport: '1.0.0' }, ['transport'], true, 'transport', null]) {
      expect(dependencyViolations({ ...pkg, [field]: entry }), `${field} populated or malformed`).toEqual([field]);
    }
    for (const empty of [{}, []]) expect(dependencyViolations({ ...pkg, [field]: empty }), `${field} empty`).toEqual([]);
  }
  expect(dependencyViolations({ devDependencies: { tool: '1.0.0' } })).toEqual([]);
});

it('CP-005/B1 lint configuration selects source extensions and nested modules without suppressing forbidden network imports', async () => {
  const original = boundaryCases.find(example => example.name === 'network https' && !example.allowed);
  if (!original) throw new Error('network expectation is missing');
  for (const extension of ['ts', 'mts', 'cts', 'js', 'mjs', 'cjs']) {
    const result = await lintBoundary({ ...original, path: `src/planner/nested/boundary-probe.${extension}` });
    expect.soft(result.fatal, `${extension}: parses`).toBe(0);
    expect.soft(result.ignored, `${extension}: selected`).toBe(false);
    expect.soft(result.messages.some(message => technicalMessage.test(message)), `${extension}: boundary reported`).toBe(true);
  }
});

it('CP-005/B5 tooling permits argument-array child processes and test HTTPS servers while refusing shell execution', async () => {
  for (const example of toolingCases) {
    const result = await lintBoundary(example);
    const name = `${example.name} in ${example.path}`;
    expect.soft(result.fatal, `${name}: parses`).toBe(0);
    expect.soft(result.ignored, `${name}: selected`).toBe(false);
    if (example.allowed) expect.soft(result.messages, name).toEqual([]);
    else expect.soft(result.messages.some(message => /shell/i.test(message)), name).toBe(true);
  }
});
