import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { repoRoot } from './cli.js';
import { testRoot } from './env.js';
import { declareDeliberateOutputs, registerSentinels, scratchRoot, sentinelRoot, sentinels } from './output.js';

export type Hit = { path: string; encoding: string } | null;
export interface ScanOptions { root: string; sentinelDir: string; sentinels: string; testTmp: string; evidenceDir: string; paths: string[] }
export interface Scanner { findLeaks(options: ScanOptions): Hit }

export async function scanner(): Promise<Scanner> {
  return await import(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href) as Scanner;
}

/**
 * Scratch root private to this test process: lab tests write their artifacts here and the
 * whole-product scan covers it, while files other concurrently running suites plant in the
 * shared scratch root stay outside it.
 */
export function runScratch(): string {
  const existing = process.env['FLUXWARDEN_RUN_SCRATCH'];
  if (existing && existsSync(existing)) return existing;
  const directory = mkdtempSync(join(scratchRoot(), 'run-'));
  process.env['FLUXWARDEN_RUN_SCRATCH'] = directory;
  return directory;
}

/**
 * Repository files for a whole-product leak scan. The committed disposable fixtures named
 * in test/sentinels.json are the only exclusion, by exact resolved path; each one must be
 * present in the inventory, so the declared list cannot silently widen or go stale.
 */
export function productInventory(): { paths: string[]; excluded: string[] } {
  const inventory = spawnSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], { cwd: repoRoot, shell: false, windowsHide: true, encoding: 'utf8', timeout: 15000 });
  if (inventory.status !== 0) throw new Error('product file inventory failed');
  const all = inventory.stdout.split('\0').filter(Boolean).map(path => resolve(repoRoot, path));
  const declared = new Set(sentinels().map(row => resolve(row.file)));
  const excluded = all.filter(path => declared.has(path));
  if (excluded.length !== declared.size) throw new Error('every declared committed fixture must be in the product inventory');
  return { paths: all.filter(path => !declared.has(path)), excluded };
}

/**
 * Whole-product scan: repository files, this run's scratch and the retained evidence root,
 * against the committed registry plus every runtime sentinel. The committed fixtures are
 * registered first, so the population never depends on test order or an earlier run.
 */
export async function productLeakScan(): Promise<{ sources: number; inventory: number; excluded: number; hit: Hit; liveDetected: boolean }> {
  const sentinelDir = sentinelRoot();
  registerSentinels(sentinelDir);
  const sources = readdirSync(sentinelDir, { withFileTypes: true }).filter(entry => entry.isFile() && readFileSync(join(sentinelDir, entry.name)).length > 0).length;
  const { paths, excluded } = productInventory();
  const testTmp = runScratch();
  const evidenceDir = testRoot('FLUXWARDEN_EVIDENCE_DIR');
  const options = { root: repoRoot, sentinelDir, sentinels: join(repoRoot, 'test/sentinels.json'), testTmp, evidenceDir, paths: [...paths, testTmp, evidenceDir] };
  const leakScanner = await scanner();
  const hit = leakScanner.findLeaks(options);
  return { sources, inventory: paths.length, excluded: excluded.length, hit, liveDetected: liveSentinelDetected(leakScanner, options) };
}

/**
 * Positive control: a fresh live sentinel, registered in the sentinel directory and
 * hex-encoded into a scratch file, is found with the same registry and sentinel options.
 * The planted file is declared by exact path for concurrent scans, so this scan uses its
 * own scratch root where nothing is declared. The planted output is removed afterwards;
 * the original private input remains registered for the final invocation scan.
 */
export function liveSentinelDetected(leakScanner: Scanner, options: ScanOptions): boolean {
  const directory = mkdtempSync(join(options.testTmp, 'live-control-'));
  const planted = join(directory, 'planted.log');
  const source = join(options.sentinelDir, `${basename(directory)}.bin`);
  const live = randomBytes(32);
  declareDeliberateOutputs([planted], options.testTmp);
  try {
    writeFileSync(source, live, { mode: 0o600 });
    writeFileSync(planted, `ordinary output ${live.toString('hex')} end\n`);
    const hit = leakScanner.findLeaks({ ...options, testTmp: directory, paths: [planted] });
    return hit !== null && resolve(hit.path) === resolve(planted);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}
