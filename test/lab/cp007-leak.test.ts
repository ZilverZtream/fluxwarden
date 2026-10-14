import { readdirSync, readFileSync, writeFileSync, rmSync, mkdtempSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';
import { liveSentinelDetected, productInventory } from '../helpers/leak-scan.js';
import { registerSentinels } from '../helpers/output.js';
import { LabInvalidError } from '../helpers/chaos.js';
interface Scanner { findLeaks(options: { root: string; sentinels: string; sentinelDir: string; testTmp: string; evidenceDir: string; paths: string[] }): { path: string; encoding: string } | null }

// INV-11 / CP-007 Rleak: fresh original artifacts, independent five-kind registration,
// eight mandatory encodings and a planted leak plus missing-registration control.
it('CP-007/Rleak original artifacts reject independent planted credential encodings and missing registration', async () => {
  const tmp = process.env['FLUXWARDEN_TEST_TMP'], sentinelDir = process.env['FLUXWARDEN_SENTINEL_DIR'], evidenceDir = process.env['FLUXWARDEN_EVIDENCE_DIR'];
  if (!tmp || !sentinelDir || !evidenceDir) throw new LabInvalidError('explicit private temporary sentinel and evidence roots required');
  registerSentinels(sentinelDir);
  const sources = readdirSync(sentinelDir, { withFileTypes: true }).filter(entry => entry.isFile() && readFileSync(join(sentinelDir, entry.name)).length > 0);
  // SECURITY 1.1: the Ed25519 private key is the approval key.
  for (const kind of ['preimage', 'macaroon', 'rune', 'tls-key', 'ed25519-key']) expect(sources.some(source => source.name.includes(kind)), `${kind} independently registered`).toBe(true);
  const scanner = await import(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href) as Scanner;
  const inventory = spawnSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], { cwd: repoRoot, shell: false, windowsHide: true, encoding: 'utf8', timeout: 15000 });
  expect(inventory.status).toBe(0);
  const { paths: files, excluded } = productInventory(); expect(files.length).toBeGreaterThan(0);
  expect(excluded.length, 'exact committed fixture exclusions').toBe(5);
  const options = { root: repoRoot, sentinels: join(repoRoot, 'test/sentinels.json'), sentinelDir, testTmp: tmp, evidenceDir, paths: [...files, tmp, evidenceDir] };
  expect(scanner.findLeaks(options), 'fresh original outputs scratch and artifacts').toBeNull();
  expect(liveSentinelDetected(scanner, options), 'late independent registration is detected with the complete registry').toBe(true);
  const controls = mkdtempSync(join(tmp, 'cp007-leak-')), planted = join(controls, 'unexpected-recording.bin'), empty = mkdtempSync(join(controls, 'empty-'));
  const sourceInput = mkdtempSync(join(sentinelDir, 'cp007-control-input-'));
  const controlOptions = { ...options, sentinels: join(controls, 'sentinels.json'), sentinelDir: sourceInput, paths: [planted] };
  let checkedForms = 0;
  writeFileSync(join(controls, 'sentinels.json'), '[]');
  try {
    for (const source of sources) {
      const bytes = readFileSync(join(sentinelDir, source.name)), b64 = bytes.toString('base64'), url = b64.replace(/\+/g, '-').replace(/\//g, '_');
      // Isolate each original source so unrelated registrations cannot satisfy its
      // eight controls, and full-registry setup occurs only for the original scan.
      writeFileSync(join(sourceInput, 'source.bin'), bytes, { mode: 0o600 });
      const forms = [bytes.toString('utf8'), bytes.toString('latin1'), bytes.toString('hex'), bytes.toString('hex').toUpperCase(), b64, b64.replace(/=+$/, ''), url, url.replace(/=+$/, '')];
      for (const [index, encoded] of forms.entries()) {
        writeFileSync(planted, encoded); checkedForms++; expect(scanner.findLeaks(controlOptions) !== null, `${source.name} encoding ${String(index)} detected`).toBe(true);
      }
    }
    expect(checkedForms, 'every original source has all eight positive controls').toBe(sources.length * 8);
    for (const missing of [empty, join(controls, 'absent')]) expect(() => scanner.findLeaks({ ...options, sentinels: join(controls, 'sentinels.json'), sentinelDir: missing, paths: [planted] })).toThrow();
  } finally {
    rmSync(planted, { force: true });
    rmSync(sourceInput, { recursive: true, force: true });
  }
});
