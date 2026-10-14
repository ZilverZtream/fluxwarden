import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';
import { runScratch } from '../helpers/leak-scan.js';
import { declareDeliberateOutputs, registerSentinels, secretForms, sentinelRoot, sentinels } from '../helpers/output.js';

interface Scanner {
  findLeaks(options: { root: string; sentinels: string; sentinelDir: string; paths?: string[]; commandOutput?: string; testTmp?: string; evidenceDir?: string }): { path: string; encoding: string } | null;
}

it('CP-003/leak committed sentinels are detected in original output scratch databases recordings and retained evidence with exact exclusions', async () => {
  registerSentinels();
  const scanner = await import(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href) as Scanner;
  const run = runScratch();
  const root = mkdtempSync(join(run, 'leak-reference-'));
  const evidenceDir = join(root, 'retained');
  const recordings = join(root, 'labs', 'fixtures', 'recordings');
  mkdirSync(evidenceDir);
  mkdirSync(recordings, { recursive: true });
  const sentinelDir = sentinelRoot();
  const options = { root: repoRoot, sentinels: join(repoRoot, 'test/sentinels.json'), sentinelDir, testTmp: root, evidenceDir };
  const targets = [join(root, 'scratch.log'), join(evidenceDir, 'evidence.log'), join(recordings, 'unexpected.bin'), join(root, 'state.sqlite')];
  // These artifacts leak on purpose; their exact paths (and the SQLite journal) are declared
  // in this run's list so whole-product scans skip them. The checks below scan with this
  // test's own root, where they are not declared.
  declareDeliberateOutputs([...targets, ...['-journal', '-wal', '-shm'].map(suffix => `${join(root, 'state.sqlite')}${suffix}`)], run);
  try {
    for (const row of sentinels()) {
      const latin = row.bytes.toString('latin1');
      const utf16 = Buffer.from(latin, 'utf16le');
      const forms: [string, Buffer][] = [['raw', row.bytes], ['utf16le', utf16], ['utf16be', Buffer.from(utf16).swap16()], ...secretForms(row.bytes).map(([name, value]): [string, Buffer] => [name, Buffer.from(value)])];
      for (const [encoding, bytes] of forms) {
        for (const target of targets) {
          if (target.endsWith('.sqlite')) {
            rmSync(target, { force: true });
            const database = new DatabaseSync(target);
            try {
              database.exec('CREATE TABLE received (value BLOB NOT NULL)');
              database.prepare('INSERT INTO received VALUES (?)').run(bytes);
            } finally { database.close(); }
          } else writeFileSync(target, bytes);
          const hit = scanner.findLeaks({ ...options, paths: [target] });
          expect(hit !== null && hit.path === target && hit.encoding.length > 0, `${row.kind}/${encoding}: artifact is detected with path and encoding`).toBe(true);
          const diagnostic = JSON.stringify(hit);
          for (const [, encoded] of secretForms(row.bytes)) expect(!diagnostic.includes(encoded), `${row.kind}/${encoding}: safe diagnostic`).toBe(true);
        }
        if (Buffer.from(bytes.toString('utf8')).equals(bytes)) expect(scanner.findLeaks({ ...options, paths: [], commandOutput: bytes.toString('utf8') }) !== null, `${row.kind}/${encoding}: original captured output is detected`).toBe(true);
      }
    }
    const planted = targets[0];
    const secret = sentinels()[0]?.bytes;
    if (!planted || !secret) throw new Error('planted fixture missing');
    writeFileSync(planted, secret);
    writeFileSync(join(root, 'declared-out.txt'), `${planted}\n`);
    expect(scanner.findLeaks({ ...options, paths: [planted] })).toBeNull();
    writeFileSync(join(root, 'declared-out.txt'), `${planted}*\n`);
    expect(scanner.findLeaks({ ...options, paths: [planted] }) !== null, 'wildcard declaration does not suppress a leak').toBe(true);
    writeFileSync(join(root, 'declared-out.txt'), '');
    const result = spawnSync(process.execPath, [join(repoRoot, 'scripts/leak-check.mjs'), '--sentinels', options.sentinels, '--sentinel-dir', sentinelDir, planted], { cwd: repoRoot, env: { ...process.env, FLUXWARDEN_TEST_TMP: root }, encoding: 'utf8', windowsHide: true, timeout: 10000 });
    if (result.error) throw result.error;
    expect(result.status).toBe(1);
    expect((result.stdout + result.stderr).includes(planted), 'CLI names the leak path').toBe(true);
    for (const [, encoded] of secretForms(secret)) expect(!(result.stdout + result.stderr).includes(encoded), 'CLI never discloses the planted value').toBe(true);
  } finally {
    for (const target of targets) rmSync(target, { force: true });
  }
});
