import { existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { readText, repoRoot } from '../helpers/cli.js';

// Required paths and wording are the public specification's documentation set.
const documents = ['README.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md', 'LICENSE', 'NOTICE-SOURCE-REUSE.md', 'docs/spec.md', 'docs/architecture.md', 'docs/security-model.md', 'docs/references.md', 'docs/references/failure-catalogue.md', 'docs/source-provenance.json'];
const directories = ['docs/runbooks', 'docs/decisions'];
function positioningViolations(text: string): boolean {
  const normalized = text.normalize('NFKC').replace(/[\u2010-\u2015\u2212]/g, '-').replace(/[*_`]/g, '').replace(/\[([^\]]+)\]\([^)]*\)/g, '$1');
  return /\bthe\s+first\b|\bthe\s+only\b|\bfirst-of-its-kind\b|\bunique\b/i.test(normalized);
}
function positioning(text: string): string {
  const section = /^## Positioning\s*\r?\n([\s\S]*?)(?=^## |$(?![\s\S]))/m.exec(text)?.[1];
  if (!section) throw new Error('references must contain a Positioning section');
  const quoted = section.split(/\r?\n/).filter(line => /^> /.test(line)).map(line => line.slice(2));
  if (quoted.length === 0) throw new Error('references must record a positioning paragraph');
  return quoted.join('\n');
}
function invalidReleaseHeadings(text: string): string[] {
  const semver = '(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)(?:-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?';
  const release = new RegExp(`^## \\[${semver}\\] - (\\d{4}-\\d{2}-\\d{2})$`);
  return text.split(/\r?\n/).filter(line => /^##(?:\s|$)/.test(line)).filter(line => {
    if (line === '## [Unreleased]') return false;
    const date = release.exec(line)?.[1];
    if (!date) return true;
    const value = new Date(`${date}T00:00:00Z`);
    return !Number.isFinite(value.getTime()) || value.toISOString().slice(0, 10) !== date;
  });
}

it('CP-005/B3 every required public document and populated documentation directory exists', () => {
  for (const path of documents) expect(existsSync(join(repoRoot, path)) && statSync(join(repoRoot, path)).isFile(), path).toBe(true);
  for (const path of directories) {
    expect(existsSync(join(repoRoot, path)) && statSync(join(repoRoot, path)).isDirectory(), path).toBe(true);
    expect(readdirSync(join(repoRoot, path)).length, `${path} is populated`).toBeGreaterThan(0);
  }
});

it('CP-005/B3 positioning rejects each prohibited phrase while preserving ordinary technical language', () => {
  for (const text of ['The FIRST controller', 'THE\nONLY controller', 'First-of-its-kind controller', 'a UNIQUE controller', 'the **first** controller', 'first\u2011of\u2011its\u2011kind controller', 'a \uff55\uff4e\uff49\uff51\uff55\uff45 controller']) expect(positioningViolations(text), text).toBe(true);
  for (const text of ['regtest only; first run', 'uniquely named channels', 'the first_name field']) expect(positioningViolations(text), text).toBe(false);
  for (const path of ['README.md', 'CONTRIBUTING.md']) expect(positioningViolations(readText(path)), path).toBe(false);
  expect(positioningViolations(positioning(readText('docs/references.md'))), 'recorded positioning').toBe(false);
});

it('CP-005/B3 README includes the verbatim positioning paragraph recorded in references', () => {
  const paragraph = positioning(readText('docs/references.md'));
  expect(paragraph.length, 'nonempty recorded positioning').toBeGreaterThan(0);
  expect(readText('README.md')).toContain(paragraph);
  expect(() => positioning('# References\n\nNo positioning recorded.')).toThrow(/Positioning/);
});

it('CP-005/B3 every changelog release heading has the fixed bracketed version and calendar-date format', () => {
  for (const heading of ['## [Unreleased]', '## [1.2.3] - 2026-10-12', '## [0.1.0-rc.1+build.9] - 2024-02-29']) expect(invalidReleaseHeadings(heading), heading).toEqual([]);
  for (const heading of ['## Unreleased', '## [1.2] - 2026-10-12', '## [01.2.3] - 2026-10-12', '## [1.2.3]', '## [1.2.3] - 2026-02-30', '## [1.2.3] - 2026-1-2', '## [Next]']) expect(invalidReleaseHeadings(heading), heading).toEqual([heading]);
  const text = readText('CHANGELOG.md');
  expect(text.match(/^##(?:\s|$)/gm)?.length ?? 0, 'at least one release heading').toBeGreaterThan(0);
  expect(invalidReleaseHeadings(text)).toEqual([]);
});
