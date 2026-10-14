/*
Convention under test (SPEC §6.1 and §6.3, ARCHITECTURE §7.1): the SQLite schema stays portable to
MySQL 8.4, so every SQL statement in src/persistence carries its MySQL mapping next to it:

  - a statement inside a string or template literal has a `-- MySQL:` comment within the statement text, or
  - a literal holding exactly one statement has a `// MySQL:` (or block) comment on one of the three lines above it.

A mapping that is identical may say so (`-- MySQL: same`); a SQLite-only statement says what replaces it
(`-- MySQL: n/a, ...`). SQL text is recognised in string, no-substitution template and template literals
(the head and every span) by its leading keyword.
*/
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import ts from 'typescript';
import { expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';

const SQL = /^\s*(?:CREATE\s+(?:TABLE|INDEX|UNIQUE\s+INDEX|TRIGGER|VIEW)|ALTER\s+TABLE|DROP\s+|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|SELECT\s|WITH\s|PRAGMA\s|BEGIN\b|COMMIT\b|ROLLBACK\b|SAVEPOINT\b|RELEASE\b)/i;

export interface Unmapped { file: string; line: number; statement: string }

function literalText(node: ts.Node): string | undefined {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isTemplateExpression(node)) return [node.head.text, ...node.templateSpans.map(span => `?${span.literal.text}`)].join('');
  return undefined;
}

function splitStatements(text: string): string[] {
  // Statements end at ';'. Triggers contain ';' inside BEGIN … END, so a trigger body is kept with its header.
  const parts: string[] = [];
  let current = '';
  let depth = 0;
  for (const piece of text.split(/(;)/)) {
    current += piece;
    if (/\bBEGIN\b/i.test(piece) && /CREATE\s+TRIGGER/i.test(current)) depth += 1;
    if (/\bEND\s*$/i.test(current.trim()) && depth > 0) depth -= 1;
    if (piece === ';' && depth === 0) { parts.push(current); current = ''; }
  }
  if (current.trim()) parts.push(current);
  return parts.map(part => part.trim()).filter(part => part.replace(/--[^\n]*/g, '').replace(/;/g, '').trim().length > 0);
}

export function unmappedStatements(file: string, source: string): { unmapped: Unmapped[]; statements: string[] } {
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  const lines = source.split(/\r?\n/);
  const unmapped: Unmapped[] = [];
  const statements: string[] = [];
  const visit = (node: ts.Node): void => {
    const text = literalText(node);
    if (text !== undefined) {
      const sqlStatements = splitStatements(text).filter(statement => SQL.test(statement.replace(/^(?:\s*--[^\n]*\n)+/, '')));
      if (sqlStatements.length > 0) {
        const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line;
        const above = lines.slice(Math.max(0, line - 3), line + 1).join('\n');
        const commentAbove = /(?:\/\/|\/\*|\*)\s*MySQL:/.test(above);
        for (const statement of sqlStatements) {
          statements.push(statement);
          const mapped = /--\s*MySQL:/.test(statement) || (sqlStatements.length === 1 && commentAbove);
          if (!mapped) unmapped.push({ file, line: line + 1, statement: statement.slice(0, 80) });
        }
      }
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return { unmapped, statements };
}

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap(name => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return /\.(?:ts|mts|cts|js|mjs)$/.test(name) ? [path] : [];
  });
}

it('CP-015/B4 the mapping check flags a statement without a MySQL mapping and accepts mapped ones', () => {
  const source = [
    "const a = 'SELECT 1 FROM nodes'; // no mapping",
    '// MySQL: same',
    "const b = 'SELECT id FROM nodes WHERE id = ?';",
    'const c = `-- MySQL: CHAR(26) ascii',
    'CREATE TABLE x (id TEXT PRIMARY KEY);',
    'CREATE INDEX x_id ON x (id);`;',
    'const d = `-- MySQL: BIGINT',
    'CREATE TABLE y (amount_msat INTEGER NOT NULL);',
    '-- MySQL: SIGNAL SQLSTATE in a BEFORE UPDATE trigger',
    "CREATE TRIGGER y_ro BEFORE UPDATE ON y BEGIN SELECT RAISE(ABORT, 'append-only'); END;`;",
    "const e = 'not sql at all';",
  ].join('\n');
  const result = unmappedStatements('example.ts', source);
  expect(result.statements.length).toBe(6);
  expect(result.unmapped.map(hit => hit.statement.slice(0, 20))).toEqual(['SELECT 1 FROM nodes', 'CREATE INDEX x_id ON']);
});

it('CP-015/B4 every SQL statement under src/persistence carries its MySQL mapping comment', () => {
  const root = join(repoRoot, 'src', 'persistence');
  const files = sourceFiles(root);
  expect(files.length, 'persistence sources').toBeGreaterThan(0);
  const all: Unmapped[] = [];
  const statements: string[] = [];
  for (const file of files) {
    const result = unmappedStatements(relative(repoRoot, file), readFileSync(file, 'utf8'));
    all.push(...result.unmapped);
    statements.push(...result.statements);
  }
  // The SPEC §6.2 tables must all be among the scanned DDL, so the check cannot pass on an empty or hidden schema.
  for (const table of ['nodes', 'channels', 'channel_snapshots', 'policy_versions', 'liquidity_proposals', 'approvals', 'executions',
    'execution_events', 'budget_reservations', 'ledger_journals', 'ledger_lines', 'account_balances']) {
    expect(statements.some(s => new RegExp(`CREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?"?${table}"?\\s*\\(`, 'i').test(s.replace(/^(?:\s*--[^\n]*\n)+/, ''))), table).toBe(true);
  }
  expect(all).toEqual([]);
});
