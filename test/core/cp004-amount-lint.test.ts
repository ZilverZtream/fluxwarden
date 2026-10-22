import { ESLint } from 'eslint';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';

it('CP-004/B7 lint reports every amount conversion while permitting unrelated numeric code', async () => {
  const lint = new ESLint({ cwd: repoRoot, overrideConfig: {
    languageOptions: { parserOptions: { projectService: { allowDefaultProject: ['src/core/amount-policy-probe.ts'], defaultProject: 'tsconfig.json' } } },
  } });
  const path = join(repoRoot, 'src/core/amount-policy-probe.ts');
  // Amount identifiers are recognised by name as well as by type (sats, fee), and the
  // Number wrapper constructor is a conversion like the Number function.
  const conversions = [
    { expression: 'Number(amount)', parameter: 'amount: Msat' },
    { expression: 'parseInt(amount.toString(), 10)', parameter: 'amount: Msat' },
    { expression: 'parseFloat(amount.toString())', parameter: 'amount: Msat' },
    { expression: '+amount', parameter: 'amount: Msat' },
    { expression: 'Math.floor(amount)', parameter: 'amount: Msat' },
    { expression: 'Number(sats)', parameter: 'sats: bigint' },
    { expression: 'new Number(fee)', parameter: 'fee: bigint' },
  ];
  // Lint all probes together in one virtual fixture instead of replacing its source eight times.
  // Separate lines retain an independent named-rule assertion for each conversion.
  const source = [
    'type Msat = bigint & { readonly __msat: unique symbol };',
    ...conversions.map(({ expression, parameter }, index) => `export function convert${String(index)}(${parameter}) { return ${expression}; }`),
    'export function count(text: string, count: number) { return Number(text) + parseInt(text, 10) + parseFloat(text) + +text + Math.floor(count); }',
  ].join('\n');
  const [report] = await lint.lintText(source, { filePath: path });
  expect(report?.fatalErrorCount, 'probe parses successfully').toBe(0);
  conversions.forEach(({ expression }, index) => {
    expect.soft(report?.messages.filter(message => message.line === index + 2
      && message.severity === 2 && message.ruleId === 'money/no-number-conversion'), expression).toHaveLength(1);
  });
  expect(report?.messages.filter(message => message.line === conversions.length + 2 && message.severity === 2),
    'unrelated numeric code has zero errors').toEqual([]);
  const current = await new ESLint({ cwd: repoRoot }).lintFiles(['src/core/**/*.ts']);
  expect(current.length, 'core files are checked').toBeGreaterThan(0);
  expect(current.flatMap(file => file.messages.filter(message => message.severity === 2))).toEqual([]);
});
