import { randomUUID } from 'node:crypto';
import { closeSync, fsyncSync, lstatSync, mkdtempSync, openSync, renameSync, rmSync, rmdirSync, writeSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { createOwnerOnlyDirectory, createOwnerOnlyEmptyFile, createOwnerOnlyEmptyFiles, restrictToOwner } from '../platform/owner-only.js';

/**
 * Owner-only directory output (evidence bundles): files are written into a fresh staging directory beside
 * the destination, and the directory is renamed into place only once it is complete and checked.
 */

/** A new, empty, owner-only directory in the destination's parent directory. */
export function createStagingDirectory(destination: string): string {
  const parent = dirname(resolve(destination));
  for (let current = parent; ; current = dirname(current)) {
    const stat = lstatSync(current);
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error('evidence: invalid staging parent');
    if (dirname(current) === current) break;
  }
  const prefix = join(parent, `.${basename(destination)}.staging-`);
  if (process.platform === 'win32') {
    const staging = `${prefix}${randomUUID()}`;
    // The protected DACL is supplied to the native creating call, before any evidence exists.
    if (!createOwnerOnlyDirectory(staging)) throw new Error('evidence: staging directory already exists');
    return staging;
  }
  const staging = mkdtempSync(prefix);
  const fd = openSync(staging, 'r');
  try { restrictToOwner(staging, 'directory', { fd }); }
  catch (error) { rmdirSync(staging); throw error; }
  finally { closeSync(fd); }
  return staging;
}

/** Creates `path` exclusively, owner-only, with exactly `bytes`, and syncs it. */
export function writeNewFile(path: string, bytes: Uint8Array): void {
  const windows = process.platform === 'win32';
  if (windows && !createOwnerOnlyEmptyFile(resolve(path))) throw new Error('evidence: file already exists');
  writeCreatedFile(path, bytes, windows);
}

/** Creates the bounded bundle's private files in one native query, then writes and syncs each. */
export function writeNewFiles(files: ReadonlyMap<string, Uint8Array>): void {
  if (process.platform !== 'win32') {
    for (const [path, bytes] of files) writeNewFile(path, bytes);
    return;
  }
  const created = createOwnerOnlyEmptyFiles([...files.keys()].map(path => resolve(path)));
  if (created.some(value => !value)) throw new Error('evidence: file already exists');
  for (const [path, bytes] of files) writeCreatedFile(path, bytes, true);
}

function writeCreatedFile(path: string, bytes: Uint8Array, windows: boolean): void {
  const fd = openSync(path, windows ? 'r+' : 'wx', 0o600);
  try {
    if (!windows) restrictToOwner(path, 'file', { fd });
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
