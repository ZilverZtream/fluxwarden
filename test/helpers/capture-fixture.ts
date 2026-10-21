import { createHash } from 'node:crypto';
import { appendFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { testRoot } from './env.js';

const hash = (value: string | Buffer): string => createHash('sha256').update(value).digest('hex');

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
}
