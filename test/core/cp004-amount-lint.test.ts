import { ESLint } from 'eslint';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';

it('CP-004/B7 lint reports every amount conversion while permitting unrelated numeric code', async () => {
  const lint = new ESLint({ cwd: repoRoot, overrideConfig: {
    languageOptions: { parserOptions: { projectService: { allowDefaultProject: ['src/core/amount-policy-probe.ts'], defaultProject: 'tsconfig.json' } } },
  } });
  const path = join(repoRoot, 'src/core/amount-policy-probe.ts');
  const expressions = ['Number(amount)', 'parseInt(amount.toString(), 10)', 'parseFloat(amount.toString())', '+amount', 'Math.floor(amount)'];
  for (const expression of expressions) {
    const [report] = await lint.lintText(`type Msat = bigint & { readonly __msat: unique symbol }; export function convert(amount: Msat) { return ${expression}; }`, { filePath: path });
    expect(report?.fatalErrorCount, 'probe parses successfully').toBe(0);
    expect(report?.messages.some(message => message.severity === 2 && !message.fatal), expression).toBe(true);
  }
  // Amount identifiers are recognised by name as well as by type (sats, fee), and the
  // Number wrapper constructor is a conversion like the Number function.
  for (const source of ['export function convert(sats: bigint) { return Number(sats); }', 'export function convert(fee: bigint) { return new Number(fee); }']) {
    const [report] = await lint.lintText(source, { filePath: path });
    expect(report?.fatalErrorCount, 'probe parses successfully').toBe(0);
    expect(report?.messages.some(message => message.ruleId === 'money/no-number-conversion'), source).toBe(true);
  }
  const [ordinary] = await lint.lintText('export function count(text: string, count: number) { return Number(text) + parseInt(text, 10) + parseFloat(text) + +text + Math.floor(count); }', { filePath: path });
  expect(ordinary?.fatalErrorCount).toBe(0);
  expect(ordinary?.errorCount).toBe(0);
  const current = await new ESLint({ cwd: repoRoot }).lintFiles(['src/core/**/*.ts']);
  expect(current.length, 'core files are checked').toBeGreaterThan(0);
  expect(current.flatMap(file => file.messages.filter(message => message.severity === 2))).toEqual([]);
});
