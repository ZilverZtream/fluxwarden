// LN-044-001, owner-approved public artifact envelopes. Authenticated synthetic
// transport acceptance is a unit control, never an actual CI/native PASS claim.
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { expect, it } from 'vitest';
import { asRecord } from '../helpers/cli.js';
import { aggregateFixture, loadPublicAggregate, runPublicAggregate } from '../helpers/oct26-aggregate-fixture.js';
import { sha256 } from '../helpers/oct26-release-gate.js';

function member(root: string, reference: unknown): Record<string, unknown> {
  const ref = asRecord(reference, 'bound member'), path = String(ref['path']);
  expect(isAbsolute(path)).toBe(false); expect(path).not.toContain('\\'); expect(path.split('/')).not.toContain('..');
  const bytes = readFileSync(join(root, path));
  expect(sha256(bytes), 'aggregate retains the exact referenced member bytes').toBe(ref['sha256']);
  return asRecord(JSON.parse(bytes.toString('utf8')), 'retained member');
}
function t18Row(bundle: Record<string, unknown>): Record<string, unknown> | undefined {
  const rows = asRecord(bundle['live'], 'live')['rows'];
  if (!Array.isArray(rows)) throw new Error('aggregate live rows required');
  return rows.map(value => asRecord(value, 'scenario')).find(row => row['id'] === 'T-18');
}
function files(root: string): string[] {
  return readdirSync(root, { withFileTypes: true }).flatMap(entry => entry.isDirectory()
    ? files(join(root, entry.name)) : entry.isFile() ? [join(root, entry.name)] : []);
}

it('CP-044/LN-044-001 authenticated synthetic aggregate control retains both required T18 variants and their raw member bindings', async () => {
  await loadPublicAggregate(); const fixture = aggregateFixture();
  expect(runPublicAggregate(fixture), 'the otherwise complete public envelope is accepted before semantic mutation').toBe(0);
  const root = join(fixture.seal.output, 'aggregate'), bundle = asRecord(JSON.parse(readFileSync(join(root, 'release-evidence.json'), 'utf8')), 'aggregate');
  const row = t18Row(bundle);
  expect(row).toBeDefined(); expect(row?.['status']).toBe('PASS');
  const summary = member(root, row?.['evidence']);
  expect(summary['complete']).toBe(true);
  const observations = summary['observations'];
  if (!Array.isArray(observations)) throw new Error('complete T18 must retain raw references');
  const raw = observations.map(reference => member(root, reference));
  expect(raw.map(value => value['variant']).sort()).toEqual(['FIRST_HOP_SPENDABLE', 'LAST_HOP_RECEIVABLE']);
  for (const observation of raw) {
    expect(observation['status']).toBe('PASS'); expect(observation['sourceCommit']).toBe(fixture.seal.sourceCommit);
  }
}, 240_000);

it('CP-044/LN-044-001 aggregation refuses or preserves retained T18 GAP despite successful official jobs reports and complete producer wrappers', async () => {
  await loadPublicAggregate(); const fixture = aggregateFixture(true);
  const status = runPublicAggregate(fixture), root = join(fixture.seal.output, 'aggregate'), path = join(root, 'release-evidence.json');
  expect(sha256(readFileSync(fixture.chaosArchive)), 'the contradictory original producer archive remains unchanged').toBe(fixture.chaosArchiveSha256);
  if (status === 0) expect(existsSync(path), 'a successful aggregate must retain its outcome').toBe(true);
  if (existsSync(path)) {
    const row = t18Row(asRecord(JSON.parse(readFileSync(path, 'utf8')), 'aggregate'));
    if (status === 0) expect(row, 'successful aggregation cannot omit the incomplete required scenario').toBeDefined();
    if (row) {
      expect(row['status'], 'retained raw GAP cannot be promoted to aggregated PASS').not.toBe('PASS');
      expect(member(root, row['evidence'])['complete'], 'retained raw GAP cannot be promoted to aggregated completeness').not.toBe(true);
    }
    if (status === 0) expect(files(root).some(file => readFileSync(file).equals(fixture.gapBytes ?? Buffer.alloc(0))), 'truthful incomplete aggregation retains the contradictory observation bytes').toBe(true);
  }
}, 240_000);
