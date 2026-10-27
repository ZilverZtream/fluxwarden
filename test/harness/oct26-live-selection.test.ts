// Audit F04: an ordinary Docker-free selection is supported, while required live
// validation must refuse absent owner inputs. Listing imports no live test file
// and never establishes ownership, execution or a successful live outcome.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { expect, it } from 'vitest';
import { asRecord, childEnv, repoRoot } from '../helpers/cli.js';
import { testRoot } from '../helpers/env.js';

function selection(suite: string, required: boolean, plan: string | undefined): { status: number | null; files: string[] } {
  const scratch = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'oct26-selection-'));
  const output = join(scratch, 'selected.json');
  const env = childEnv();
  Reflect.deleteProperty(env, 'FLUXWARDEN_LAB_PLAN');
  Reflect.deleteProperty(env, 'FLUXWARDEN_REQUIRE_LIVE');
  Reflect.deleteProperty(env, 'FLUXWARDEN_CHAOS_REFERENCE_PLAN');
  if (required) env['FLUXWARDEN_REQUIRE_LIVE'] = '1';
  if (plan !== undefined) env['FLUXWARDEN_LAB_PLAN'] = plan;
  const result = spawnSync(process.execPath, [join(repoRoot, 'scripts/ci-test-driver.mjs'), 'list',
    '--config', `vitest.${suite}.config.ts`, '--filesOnly', `--json=${output}`], {
    cwd: repoRoot, env, encoding: 'utf8', windowsHide: true, timeout: 15_000,
  });
  expect(result.error, 'selection subprocess must complete').toBeUndefined();
  expect(result.signal).toBeNull();
  let files: string[] = [];
  if (result.status === 0) {
    const selected: unknown = JSON.parse(readFileSync(output, 'utf8'));
    if (!Array.isArray(selected)) throw new Error('file selection must be a list');
    files = selected.map(row => relative(repoRoot, String(asRecord(row, 'selected file')['file'])).replace(/\\/g, '/'));
  }
  return { status: result.status, files };
}

for (const suite of ['lab', 'chaos']) {
  it(`CP-044/F04 ${suite} required-live selection refuses absent and empty owner plans`, () => {
    for (const plan of [undefined, '']) {
      const selected = selection(suite, true, plan);
      expect.soft(selected.status, 'required live validation cannot silently select only Docker-free cases').toBe(1);
      expect.soft(selected.files).toEqual([]);
    }
  });

  it(`CP-044/F04 ${suite} ordinary offline selection remains supported and selects no live references`, () => {
    const selected = selection(suite, false, undefined);
    expect(selected.status).toBe(0);
    expect(selected.files.length).toBeGreaterThan(0);
    expect(selected.files.filter(file => file.endsWith('.live.test.ts'))).toEqual([]);
  });

  it(`CP-044/F04 ${suite} explicit owner-plan selection retains offline cases and includes live references without executing them`, () => {
    const marker = join(testRoot('FLUXWARDEN_TEST_TMP'), 'selection-only-owner-plan.json');
    const offline = selection(suite, false, undefined);
    const selected = selection(suite, false, marker);
    expect(selected.status).toBe(0);
    for (const file of offline.files) expect(selected.files, 'retain Docker-free regression coverage').toContain(file);
    expect(selected.files.filter(file => file.endsWith('.live.test.ts')).length).toBeGreaterThan(0);
  });
}
