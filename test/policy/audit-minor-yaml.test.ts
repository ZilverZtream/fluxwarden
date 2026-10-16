// Interface: the existing policy YAML subset parser, shared by validated policy input.
import { expect, it } from 'vitest';
import { loadSrc, thrown } from '../helpers/load-src.js';

interface Parser { readonly parseYamlSubset: (text: string) => unknown }
interface ConfigParser { readonly parseYaml: (text: string) => unknown }

it('CP-019/B6 REG-POL014 separation whitespace before a mapping colon does not become part of the key', async () => {
  const { parseYamlSubset } = await loadSrc<Parser>('policy/yaml.ts');
  expect(parseYamlSubset('fees :\n  max_fee_msat  : "300000"\n')).toEqual({ fees: { max_fee_msat: '300000' } });
  expect(thrown(() => parseYamlSubset('fees: a\nfees : b\n')).exitCode).toBe(2);
});

it('CP-019/B6 REG-POL004 supported nesting parses and excessive nesting refuses as bounded invalid input', async () => {
  const { parseYamlSubset } = await loadSrc<Parser>('policy/yaml.ts');
  const nested = (depth: number) => Array.from({ length: depth }, (_, i) => `${'  '.repeat(i)}key:`).join('\n') + ' value\n';
  expect(parseYamlSubset(nested(3))).toEqual({ key: { key: { key: 'value' } } });
  expect(thrown(() => parseYamlSubset(nested(200))).exitCode).toBe(2);
});

it('CP-016/B1 REG-POL004 the configuration parser rejects excessive nesting before schema validation', async () => {
  const { parseYaml } = await loadSrc<ConfigParser>('config/yaml.ts');
  const nested = (depth: number) => Array.from({ length: depth }, (_, i) => `${'  '.repeat(i)}key:`).join('\n') + ' value\n';
  expect(parseYaml(nested(3))).toEqual({ key: { key: { key: 'value' } } });
  let refused: unknown;
  try { parseYaml(nested(200)); } catch (error) { refused = error; }
  expect(refused).toBeInstanceOf(Error);
  expect(refused).toMatchObject({ name: 'YamlError' });
});

it('CP-019/B6 REG-POL005 a single leading document marker preserves one document and a second refuses', async () => {
  const { parseYamlSubset } = await loadSrc<Parser>('policy/yaml.ts');
  expect(parseYamlSubset('---\nfees:\n  max_fee_msat: "300000"\n')).toEqual({ fees: { max_fee_msat: '300000' } });
  expect(thrown(() => parseYamlSubset('---\na: b\n---\nc: d\n')).exitCode).toBe(2);
});
