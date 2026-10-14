import { closeSync, fsyncSync, mkdtempSync, openSync, renameSync, rmSync, rmdirSync, writeSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

/**
 * Owner-only directory output (evidence bundles): files are written into a fresh staging directory beside
 * the destination, and the directory is renamed into place only once it is complete and checked.
 */

/** A new, empty, owner-only directory in the destination's parent directory. */
export function createStagingDirectory(destination: string): string {
  return mkdtempSync(join(dirname(destination), `.${basename(destination)}.staging-`));
}

/** Creates `path` exclusively, owner-only, with exactly `bytes`, and syncs it. */
export function writeNewFile(path: string, bytes: Uint8Array): void {
  const fd = openSync(path, 'wx', 0o600);
  try {
    for (let offset = 0; offset < bytes.length;) offset += writeSync(fd, bytes, offset, bytes.length - offset);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Renames the staging directory to `destination`. An empty directory at `destination` is replaced; anything
 * else there makes the rename fail and leaves it untouched.
 */
export function publishDirectory(staging: string, destination: string, destinationIsEmptyDirectory: boolean): void {
  if (destinationIsEmptyDirectory) rmdirSync(destination);
  renameSync(staging, destination);
}

export function removeDirectory(path: string): void {
  rmSync(path, { recursive: true, force: true });
}
