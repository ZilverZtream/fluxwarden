/*
Interface: none beyond the source tree. Every SQL statement is a single string or template literal (ARCHITECTURE §7.3:
"every worker write to executions ... is a single statement of this form").

Rule under test (SPEC §6.4, ARCHITECTURE §7.3, SECURITY INV-18): every UPDATE of `executions` in src/ increments the fence
(`fence_epoch = fence_epoch + 1`) and is conditional either on the expected epoch (`fence_epoch = ?`) or, for the
re-claim, on status CLAIMED/PREFLIGHT and an expired lease (`lease_expires_at < <db now>`); no statement replaces or
deletes execution rows.
*/
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import ts from 'typescript';
import { expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';

interface Site { readonly file: string; readonly line: number; readonly sql: string }

function files(directory: string): string[] {
  return readdirSync(directory).flatMap(name => {
    const file = join(directory, name);
    const info = lstatSync(file);
    return info.isDirectory() ? files(file) : /\.[cm]?ts$/.test(name) ? [file] : [];
  });
}

/** Every string and template literal of a source text, template substitutions shown as ${}. */
function literals(file: string, text: string): Site[] {
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.ES2022, true);
  const found: Site[] = [];
  const visit = (node: ts.Node): void => {
    let sql: string | undefined;
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) sql = node.text;
    else if (ts.isTemplateExpression(node)) sql = node.head.text + node.templateSpans.map(span => '${}' + span.literal.text).join('');
    if (sql !== undefined) {
      found.push({ file, line: source.getLineAndCharacterOfPosition(node.getStart()).line + 1, sql });
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return found;
}

const UPDATE_EXECUTIONS = /\bUPDATE\s+executions\b/i;
const FORBIDDEN = /\b(?:REPLACE\s+INTO|INSERT\s+OR\s+REPLACE\s+INTO|DELETE\s+FROM)\s+executions\b/i;
const INCREMENT = /\bSET\b[\s\S]*\bfence_epoch\s*=\s*fence_epoch\s*\+\s*1\b[\s\S]*\bWHERE\b/i;

function violation(sql: string): string | undefined {
  if (FORBIDDEN.test(sql)) return 'replaces or deletes execution rows';
  if (!UPDATE_EXECUTIONS.test(sql)) return undefined;
  if (!INCREMENT.test(sql)) return 'does not increment fence_epoch in SET';
  const where = sql.slice(sql.search(/\bWHERE\b/i));
  const fenced = /\bfence_epoch\s*=\s*\?/i.test(where);
  const reclaim = /\bstatus\s+IN\s*\(\s*'CLAIMED'\s*,\s*'PREFLIGHT'\s*\)/i.test(where) && /\blease_expires_at\s*<\s*\S/i.test(where);
  return fenced || reclaim ? undefined : 'is conditional on neither the expected fence_epoch nor an expired CLAIMED/PREFLIGHT lease';
}

it('CP-028/B6 the fenced-write check reports unfenced writes and accepts the fenced and re-claim forms', () => {
  // The two statement forms of SPEC §6.4, with the database clock substituted.
  expect(violation(`UPDATE executions SET status = ?, error_code = ?, fence_epoch = fence_epoch + 1, updated_at = \${}
      WHERE id = ? AND fence_epoch = ? AND status = ?`)).toBeUndefined();
  expect(violation(`UPDATE executions SET worker_id = ?, lease_expires_at = \${} + ?, fence_epoch = fence_epoch + 1, updated_at = \${}
      WHERE proposal_id = ? AND status IN ('CLAIMED','PREFLIGHT') AND lease_expires_at < \${}`)).toBeUndefined();
  expect(violation('UPDATE executions SET status = ? WHERE id = ?')).toBeDefined();
  expect(violation('UPDATE executions SET status = ?, fence_epoch = fence_epoch + 1 WHERE id = ?')).toBeDefined();
  expect(violation('UPDATE executions SET status = ? WHERE id = ? AND fence_epoch = ?')).toBeDefined();
  expect(violation("UPDATE executions SET worker_id = ?, fence_epoch = fence_epoch + 1 WHERE proposal_id = ? AND status IN ('CLAIMED','PREFLIGHT')")).toBeDefined();
  expect(violation('DELETE FROM executions WHERE id = ?')).toBeDefined();
  expect(violation('INSERT OR REPLACE INTO executions (id) VALUES (?)')).toBeDefined();
  expect(violation('UPDATE channels SET updated_at = ? WHERE id = ?')).toBeUndefined();
});

it('CP-028/B6 every write site of executions in src/ carries the fence condition and the epoch increment', () => {
  const sites = files(join(repoRoot, 'src')).flatMap(file => literals(relative(repoRoot, file), readFileSync(file, 'utf8')));
  const writes = sites.filter(site => UPDATE_EXECUTIONS.test(site.sql) || FORBIDDEN.test(site.sql));
  const problems = writes.map(site => ({ at: `${site.file}:${String(site.line)}`, problem: violation(site.sql) })).filter(hit => hit.problem !== undefined);
  expect(problems).toEqual([]);
  // At least the re-claim and the fenced transition exist, and they live in persistence (ARCHITECTURE B3).
  expect(writes.length).toBeGreaterThanOrEqual(2);
  expect(writes.filter(site => !site.file.replace(/\\/g, '/').startsWith('src/persistence/'))).toEqual([]);
  expect(writes.some(site => /\bfence_epoch\s*=\s*\?/i.test(site.sql))).toBe(true);
  expect(writes.some(site => /status\s+IN\s*\(\s*'CLAIMED'\s*,\s*'PREFLIGHT'\s*\)/i.test(site.sql))).toBe(true);
});
