import { createHash } from 'node:crypto';
import { appendFileSync, lstatSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { repoRoot } from './cli.js';
import { testRoot } from './env.js';

const hash = (value: string | Buffer): string => createHash('sha256').update(value).digest('hex');

/** Nested capture/job utilities are owned validation tools. Keep their first
 * writes under the explicit outer recorder so prospective exact declarations
 * can be witnessed. Ordinary product CLI children do not use this adapter. */
export function ownedCaptureToolArgs(args: readonly string[]): string[] {
  return process.env['FLUXWARDEN_CI_CAPTURE']
    ? ['--import', pathToFileURL(join(repoRoot, 'scripts/ci-capture-preload.mjs')).href, ...args]
    : [...args];
}

/** Exact original paths, registered before any intentional fixture write.
 * Hashing the path keeps deliberately secret-bearing names out of the outer
 * declaration's own EGRESS bytes. This is the existing scanner's exact-path form.
 */
export function declareFixturePaths(paths: readonly string[]): void {
  appendFileSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'declared-out.txt'),
    paths.map(path => `sha256:${hash(resolve(path))}\n`).join(''));
}

/** Fixture adapter for the observed private capture copy layout. Purpose comes
 * exclusively from the caller's original known INPUTs and deliberate plants,
 * never from finding a filename, content hash or a post-scan leak. No security
 * assertion depends on this layout; the unchanged inner detector still sees
 * every original artifact with its own evidence/declaration context.
 */
export function declareFixtureCapture(capture: string, inputs: readonly Buffer[], plants: readonly { path: string; bytes: Buffer; purpose?: 'INPUT' | 'EGRESS' }[]): void {
  const paths = inputs.flatMap(bytes => [join(capture, 'private/bytes', hash(bytes)), join(capture, 'private/sources', hash(bytes))]);
  // The finite private census includes the original deliberate unsafe names.
  // Declare only that exact metadata file, before any controlled plant is made.
  if (plants.length > 0) paths.push(join(capture, 'custody.json'));
  for (const plant of plants) {
    paths.push(plant.path, join(capture, 'private/bytes', hash(plant.bytes)));
    // Secret-bearing names are deliberate output too. The retained original
    // context uses this compact private artifact representation, without newline.
    const context = JSON.stringify({ path: resolve(plant.path), sha256: hash(plant.bytes), purpose: plant.purpose ?? 'EGRESS' });
    paths.push(join(capture, 'private/records', `${hash(context)}.json`));
  }
  declareFixturePaths(paths);
  if (!process.env['FLUXWARDEN_CI_CAPTURE'] || inputs.length === 0) return;
  // Qualify only caller-known INPUT copies before the tested inner invocation.
  // Runtime source registration inside that invocation remains untouched. The
  // fresh scaffold is removed so the real inner capture starts in an empty root.
  // Deliberate EGRESS plants, metadata and unknown paths are never materialized.
  const root = resolve(capture), scaffold = resolve(root, 'private');
  const info = lstatSync(root);
  if (!info.isDirectory() || info.isSymbolicLink() || readdirSync(root).length !== 0 || dirname(scaffold) !== root) {
    throw new Error('fixture INPUT preparation requires its fresh empty owned capture directory');
  }
  mkdirSync(scaffold, { mode: 0o700 });
  try {
    for (const kind of ['bytes', 'sources']) {
      const directory = join(scaffold, kind);
      mkdirSync(directory, { mode: 0o700 });
      const unique = new Map(inputs.map(bytes => [hash(bytes), bytes]));
      for (const [fingerprint, bytes] of unique) writeFileSync(join(directory, fingerprint), bytes, { flag: 'wx', mode: 0o600 });
    }
  } finally {
    // This exact child was created above, under the checked empty real root;
    // no tested command runs until its synchronous removal has completed.
    rmSync(scaffold, { recursive: true });
  }
}
