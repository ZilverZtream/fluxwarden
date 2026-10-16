// SPEC 7.1 / 10.1 and SECURITY INV-01/15: YAML mappings contain own data;
// policy and configuration admit only their defined keys. Property spelling
// grants no additional settings, node entries or execution authority.
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { loadSource } from '../helpers/adapter-interfaces.js';
import { scratch, writeConfig, writePolicy } from '../helpers/cp016-cli.js';

type Mapping = Record<string, unknown>;
interface Parser { parseYamlSubset: (text: string) => unknown }
interface Policy { loadPolicy: (text: string) => { network: string; max_in_flight: number; fees: { max_fee_msat: bigint } } }
interface Config { loadConfig: (path: string) => unknown }
type Outcome = { ok: true; value: unknown } | { ok: false; error: unknown };
const SPECIAL_NAMES = ['__proto__', 'constructor', 'prototype'];
const outcome = (action: () => unknown): Outcome => {
  try { return { ok: true, value: action() }; } catch (error: unknown) { return { ok: false, error }; }
};
const record = (value: unknown): Mapping => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('expected ordinary YAML mapping');
  return value as Mapping;
};
const structuredRefusal = (result: Outcome) => {
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error).toBeInstanceOf(Error);
  expect(result.error).toMatchObject({ exitCode: 2 });
};

for (const key of SPECIAL_NAMES) {
  it(`CP-019/REG-POL003 mapping name ${key} is own data at every ordinary mapping location or a structured refusal`, async () => {
    const { parseYamlSubset } = await loadSource<Parser>('policy/yaml.ts');
    expect(parseYamlSubset('container:\n  name: ordinary\nentries:\n  - name: retained\n'))
      .toEqual({ container: { name: 'ordinary' }, entries: [{ name: 'retained' }] });
    for (const quoted of [key, JSON.stringify(key)]) {
      const scalar = outcome(() => parseYamlSubset(`${quoted}: ordinary-value\nsibling: retained\n`));
      if (!scalar.ok) { structuredRefusal(scalar); continue; }
      const scalarMap = record(scalar.value);
      expect(Object.keys(scalarMap).sort()).toEqual([key, 'sibling'].sort());
      expect(Object.getOwnPropertyDescriptor(scalarMap, key)).toMatchObject({ value: 'ordinary-value' });
      expect(scalarMap['sibling']).toBe('retained');

      const nested = outcome(() => parseYamlSubset(`container:\n  ${quoted}:\n    ordinary_label: retained\n  sibling: retained\n`));
      if (!nested.ok) { structuredRefusal(nested); continue; }
      const container = record(record(nested.value)['container']);
      expect(Object.keys(container).sort()).toEqual([key, 'sibling'].sort());
      const descriptor = Object.getOwnPropertyDescriptor(container, key);
      expect(descriptor).toHaveProperty('value');
      expect(record(descriptor?.value)).toEqual({ ordinary_label: 'retained' });
      expect('ordinary_label' in container).toBe(false);
      expect(container['sibling']).toBe('retained');

      const sequence = outcome(() => parseYamlSubset(`entries:\n  - ${quoted}: ordinary-value\n    sibling: retained\n`));
      if (!sequence.ok) { structuredRefusal(sequence); continue; }
      const entries = record(sequence.value)['entries'];
      expect(Array.isArray(entries)).toBe(true);
      if (!Array.isArray(entries)) return;
      expect(entries).toHaveLength(1);
      const entry = record(entries[0]);
      expect(Object.keys(entry).sort()).toEqual([key, 'sibling'].sort());
      expect(Object.getOwnPropertyDescriptor(entry, key)).toMatchObject({ value: 'ordinary-value' });
      expect(entry['sibling']).toBe('retained');
    }
  });
}

function policyText() {
  const dir = scratch('mapping-policy');
  return readFileSync(writePolicy(dir, { 'cln-m': { '105x1x0': { minInbound: '50000000' } } }), 'utf8');
}

it('CP-019/REG-POL003 valid policy retains its explicit fee cap and default execution count', async () => {
  const { loadPolicy } = await loadSource<Policy>('policy/load.ts');
  expect(loadPolicy(policyText())).toMatchObject({ network: 'regtest', max_in_flight: 1, fees: { max_fee_msat: 300_000n } });
});

it('CP-019/REG-POL003 special names do not disappear from root or fee-section allowlists', async () => {
  const { loadPolicy } = await loadSource<Policy>('policy/load.ts');
  const valid = policyText();
  for (const key of [...SPECIAL_NAMES, 'ordinary_unknown_setting']) {
    structuredRefusal(outcome(() => loadPolicy(`${valid}${key}:\n  ordinary_label: retained\n`)));
    const nested = valid.replace('fees:\n', `fees:\n  ${JSON.stringify(key)}:\n    ordinary_label: retained\n`);
    structuredRefusal(outcome(() => loadPolicy(nested)));
  }
});

function configuration() {
  const dir = scratch('mapping-config'), database = join(dir, 'unopened.db');
  const path = writeConfig(dir, { database, nodes: [{ name: 'ordinary-node', implementation: 'cln',
    url: 'https://127.0.0.1:1', tlsCert: join(dir, 'unopened.cert'), credential: join(dir, 'unopened.rune'),
    expectedPubkey: `02${'41'.repeat(32)}` }] });
  return { dir, path, database, text: readFileSync(path, 'utf8') };
}

it('CP-016/REG-POL003 ordinary valid configuration admission does not open credentials or create state', async () => {
  const { loadConfig } = await loadSource<Config>('config/config.ts'), f = configuration();
  expect(() => loadConfig(f.path)).not.toThrow();
  expect(readFileSync(f.path, 'utf8')).toBe(f.text);
  expect(readdirSync(f.dir)).toEqual(['fluxwarden.yaml']);
  expect(existsSync(f.database)).toBe(false);
});

it('CP-016/REG-POL003 configuration root and node allowlists refuse special unknown names without state creation', async () => {
  const { loadConfig } = await loadSource<Config>('config/config.ts'), f = configuration();
  for (const key of [...SPECIAL_NAMES, 'ordinary_unknown_setting']) {
    for (const [location, text] of [
      ['root', `${f.text}${JSON.stringify(key)}:\n  ordinary_label: retained\n`],
      ['node', f.text.replace('    implementation: cln\n', `    implementation: cln\n    ${JSON.stringify(key)}:\n      ordinary_label: retained\n`)],
    ] as const) {
      writeFileSync(f.path, text);
      // The published loader throws; the command boundary maps configuration errors to exit 2.
      expect.soft(() => loadConfig(f.path), `${key} at ${location} is outside the configuration allowlist`).toThrow(Error);
      expect(readFileSync(f.path, 'utf8')).toBe(text);
      expect(readdirSync(f.dir)).toEqual(['fluxwarden.yaml']);
      expect(existsSync(f.database)).toBe(false);
    }
  }
});
