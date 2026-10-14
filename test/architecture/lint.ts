import { ESLint } from 'eslint';
import { join } from 'node:path';
import tseslint from 'typescript-eslint';
import { repoRoot } from '../helpers/cli.js';
import type { BoundaryCase } from './cases.js';

// Snippets have no on-disk TypeScript project; keep the repository's boundary rules
// while disabling only rules that require an unrelated type-checking program.
const lint = new ESLint({ cwd: repoRoot, overrideConfig: [
  tseslint.configs.disableTypeChecked,
  { languageOptions: { parserOptions: { projectService: false, project: null } } },
] });

export const repositoryLint = new ESLint({ cwd: repoRoot });

export async function lintBoundary(example: BoundaryCase): Promise<{ fatal: number; ignored: boolean; messages: string[] }> {
  const [report] = await lint.lintText(example.source, { filePath: join(repoRoot, example.path) });
  if (!report) throw new Error('source snippet has no lint verdict');
  return {
    fatal: report.fatalErrorCount,
    ignored: report.messages.some(message => /ignored|no matching configuration/i.test(message.message)),
    messages: report.messages.filter(message => message.severity === 2 && /no-restricted-(?:imports|globals|syntax)|boundar|architecture|shell/i.test(message.ruleId ?? '')).map(message => message.message),
  };
}

export const technicalMessage = /core|pure|network|transport|https?|fetch|WebSocket|SQL|sqlite|stdout|stderr|console|output|child.?process|adapter|node-lnd|node-cln|clock|Date|random|write|\bfs\b|specifier|import|require|shell/i;
