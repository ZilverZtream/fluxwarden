import { readdirSync, readFileSync, writeFileSync, rmSync, mkdtempSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, relative, isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';
import { liveSentinelDetected, productInventory } from '../helpers/leak-scan.js';
import { registerSentinels } from '../helpers/output.js';

interface Scanner {
  findLeaks(options: { root: string; sentinels: string; sentinelDir: string; testTmp: string; evidenceDir: string; paths: string[] }): { path: string; encoding: string } | null;
}

// SECURITY INV-11: each independent kind, all required encodings, exact exclusions only.
it('CP-006/Rleak independent sentinels scan original evidence and reject planted leaks and empty registration', async () => {
  const tmp = process.env['FLUXWARDEN_TEST_TMP'], sentinelDir = process.env['FLUXWARDEN_SENTINEL_DIR'], evidenceDir = process.env['FLUXWARDEN_EVIDENCE_DIR'];
  if (!tmp || !sentinelDir || !evidenceDir) throw new Error('independent private scratch sentinel and evidence roots are required');
  registerSentinels(sentinelDir);
  const sources = readdirSync(sentinelDir, { withFileTypes: true }).filter(entry => entry.isFile() && readFileSync(join(sentinelDir, entry.name)).length > 0);
  expect(sources.length, 'independent nonempty sentinel kinds').toBeGreaterThanOrEqual(5);
  const scanner = await import(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href) as Scanner;
  const inventory = spawnSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], { cwd: repoRoot, shell: false, windowsHide: true, encoding: 'utf8', timeout: 15_000 });
  expect(inventory.status, 'fresh product artifact inventory').toBe(0);
  const { paths: product, excluded } = productInventory();
  expect(excluded.length, 'exact committed fixture exclusions').toBe(5);
  expect(product.length, 'nonempty product inventory including recordings').toBeGreaterThan(0);
  const clean = { root: repoRoot, sentinels: join(repoRoot, 'test/sentinels.json'), sentinelDir, testTmp: tmp, evidenceDir, paths: [...product, tmp, evidenceDir] };
  expect(scanner.findLeaks(clean), 'original retained output and scratch are clean').toBeNull();
  expect(liveSentinelDetected(scanner, clean), 'late independent registration is detected with the complete registry').toBe(true);
  const controls = mkdtempSync(join(tmp, 'leak-')), planted = join(controls, 'unexpected-recording.bin');
  const within = relative(resolve(tmp), resolve(planted));
  if (!within || within.startsWith('..') || isAbsolute(within)) throw new Error('planted leak cleanup escaped owned scratch');
  const empty = mkdtempSync(join(controls, 'empty-'));
  const sourceInput = mkdtempSync(join(sentinelDir, 'cp006-control-input-'));
  // D77: only this never-declared planted path is scanned by single-source
  // controls. Its local context cannot alter the original corpus declarations.
  const controlOptions = { ...clean, testTmp: controls, evidenceDir: controls,
    sentinels: join(controls, 'sentinels.json'), sentinelDir: sourceInput, paths: [planted] };
  let checkedForms = 0;
  writeFileSync(join(controls, 'sentinels.json'), '[]');
  writeFileSync(join(empty, 'empty.bin'), '');
  try {
    for (const source of sources) {
      const bytes = readFileSync(join(sentinelDir, source.name));
      // Each original registered source is tested alone, preventing an unrelated source
      // from satisfying its positive control and avoiding repeated full-registry setup.
      writeFileSync(join(sourceInput, 'source.bin'), bytes, { mode: 0o600 });
      const b64 = bytes.toString('base64'), url = b64.replace(/\+/g, '-').replace(/\//g, '_');
      const encodings = [Buffer.from(bytes.toString('utf8')), Buffer.from(bytes.toString('latin1')), Buffer.from(bytes.toString('hex')), Buffer.from(bytes.toString('hex').toUpperCase()), Buffer.from(b64), Buffer.from(b64.replace(/=+$/, '')), Buffer.from(url), Buffer.from(url.replace(/=+$/, ''))];
      for (const [index, encoded] of encodings.entries()) {
        writeFileSync(planted, encoded);
        checkedForms++;
        expect(scanner.findLeaks(controlOptions) !== null, `${source.name} encoding ${String(index)} detected`).toBe(true);
      }
    }
    expect(checkedForms, 'every original source has all eight positive controls').toBe(sources.length * 8);
    for (const missing of [empty, join(controls, 'absent')]) expect(() => scanner.findLeaks({ ...clean, sentinels: join(controls, 'sentinels.json'), sentinelDir: missing, paths: [planted] }), 'missing or empty independent registration refuses').toThrow();
  } finally {
    rmSync(planted, { force: true });
    rmSync(sourceInput, { recursive: true, force: true });
  }
});
