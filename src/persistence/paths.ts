import { randomBytes } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, realpathSync, rmdirSync, statSync, unlinkSync, type Stats } from 'node:fs';
import { dirname, parse, resolve } from 'node:path';
import { PersistenceError } from './errors.js';
import { createOwnerOnlyFile, onlyOwnerAccessMany, pathAccessMany, pathGroupsAccessMany, present, restrictCreated } from './owner-files.js';
import { createOwnerOnlyDirectory, createOwnerOnlyDirectories } from '../platform/owner-only.js';

const posix = process.platform !== 'win32';

/** Validates a private directory and its trusted ancestry without changing it. */
export function checkPrivateDirectory(path: string): string {
  const absolute = resolve(path);
  if (checkAncestry(absolute).length !== 0) throw unsafe('state: a private directory is missing');
  return absolute;
}

/** Exclusive private directory creation; existing directories and links are never adopted. */
export function createPrivateDirectoryExclusive(path: string): string {
  const absolute = resolve(path);
  checkPrivateDirectory(dirname(absolute));
  if (posix) mkdirSync(absolute, { mode: 0o700 });
  else if (!createOwnerOnlyDirectory(absolute)) throw unsafe('state: the destination already exists');
  return absolute;
}

/** New sibling directories only; no existing destination or its permissions are adopted. */
export function createPrivateDirectoriesExclusive(paths: readonly string[]): void {
  const absolute = paths.map(path => resolve(path));
  checkPrivateFiles([], [...new Set(absolute.map(path => dirname(path)))]);
  for (const path of absolute) if (lstatOrUndefined(path) !== undefined) throw unsafe('state: the destination already exists');
  if (posix) for (const path of absolute) mkdirSync(path, { mode: 0o700 });
  else if (createOwnerOnlyDirectories(absolute).some(created => !created)) throw unsafe('state: the destination already exists');
}

/** One permission read for a batch; each file and every distinct private ancestry is still admitted. */
export function checkPrivateFiles(paths: readonly string[], directories: readonly string[] = []): void {
  const parents = [...new Set([...paths.map(path => dirname(resolve(path))), ...directories.map(path => resolve(path))])];
  if (posix) {
    for (const parent of parents) checkPrivateDirectory(parent);
    for (const path of paths) checkSingleFile(lstatSync(path), path);
    return;
  }
  settled(() => {
    const groups = parents.map(stateDir => {
      const { chain, missingFrom } = inspectAncestry(stateDir);
      if (missingFrom !== chain.length) throw unsafe('state: a private directory is missing');
      return { ancestors: chain.map(entry => entry.path), creationParent: undefined, stateDir };
    });
    for (const path of paths) checkSingleFile(lstatSync(path), path);
    for (const access of pathGroupsAccessMany(groups, paths)) {
      if (access.ancestors.some(allowed => !allowed) || access.objects.some(allowed => !allowed)) throw unsafe('state: a retained path has unsafe access');
    }
  });
}

function lstatOrUndefined(path: string): Stats | undefined {
  try {
    return lstatSync(path);
  } catch (error) {
    if ((error as { code?: unknown }).code === 'ENOENT') return undefined;
    throw error;
  }
}

function unsafe(message: string): PersistenceError {
  return new PersistenceError('UNSAFE_PATH', message);
}

/** The directories from the filesystem root down to `dir`, each with its lstat result (undefined when missing). */
function ancestry(dir: string): { path: string; stat: Stats | undefined }[] {
  const chain: string[] = [];
  const root = parse(dir).root;
  for (let current = dir; ; current = dirname(current)) {
    chain.unshift(current);
    if (current === root || dirname(current) === current) break;
  }
  return chain.map(path => ({ path, stat: lstatOrUndefined(path) }));
}

/**
 * Refuses symbolic links, junctions and other reparse points at the database path and in every parent
 * directory (SECURITY.md §5). A link owned by root above the state directory (such as /var or /tmp on macOS)
 * is accepted on POSIX hosts: only an administrator can place one there.
 * Returns the directories that do not exist yet, outermost first (empty when `dir` exists).
 */
function checkAncestry(dir: string, objects: readonly string[] = []): string[] {
  const { chain, missingFrom } = inspectAncestry(dir);
  if (!posix) {
    const existing = chain.slice(0, missingFrom).map(entry => entry.path);
    const creationParent = missingFrom < chain.length ? existing.at(-1) : undefined;
    settled(() => {
      const access = pathAccessMany(existing, creationParent, dir, objects);
      for (const [index, path] of existing.entries()) {
        if (access.ancestors[index] !== true) throw unsafe(`${path} has an untrusted owner or allows other users to change the path`);
      }
      for (const [index, path] of objects.entries()) {
        if (access.objects[index] !== true && (index === 0 || present(path))) throw unsafe(`${path} has an unsafe owner or access list`);
      }
    });
  }
  return chain.slice(missingFrom).map(entry => entry.path);
}

/** Inspect every component afresh before combining Windows ACL reads for one operation. */
function inspectAncestry(dir: string): { chain: { path: string; stat: Stats | undefined }[]; missingFrom: number } {
  const chain = ancestry(dir);
  let missingFrom = chain.length;
  chain.forEach(({ path, stat }, index) => {
    if (stat === undefined) {
      missingFrom = Math.min(missingFrom, index);
      return;
    }
    if (index > missingFrom) return;
    const stateDir = index === chain.length - 1;
    if (stat.isSymbolicLink() && (stateDir || !posix || stat.uid !== 0)) throw unsafe(`${path} is a symbolic link or junction`);
    if (!stat.isSymbolicLink() && !stat.isDirectory()) throw unsafe(`${path} is not a directory`);
    if (posix) {
      const directory = stat.isSymbolicLink() ? statSync(path) : stat;
      trustedPosixAncestor(directory, path);
      if (stat.isSymbolicLink()) {
        for (const resolved of ancestry(realpathSync(path))) {
          if (resolved.stat === undefined) throw unsafe(`${resolved.path} is missing`);
          trustedPosixAncestor(resolved.stat, resolved.path);
        }
      }
      if (stateDir) ownerOnly(directory, path, 0o077);
    }
  });
  return { chain, missingFrom };
}

function trustedPosixAncestor(stat: Stats, path: string): void {
  const uid = process.getuid?.();
  if (!stat.isDirectory() || (stat.uid !== 0 && stat.uid !== uid)) throw unsafe(`${path} has an untrusted owner`);
  if ((stat.mode & 0o022) !== 0 && (stat.mode & 0o1000) === 0) throw unsafe(`${path} is writable by other users`);
}

function ownerOnly(stat: Stats, path: string, forbidden: number): void {
  if (!posix) return;
  if ((stat.mode & forbidden) !== 0) throw unsafe(`${path} is accessible to other users (mode ${(stat.mode & 0o777).toString(8)})`);
  const uid = process.getuid?.();
  if (uid !== undefined && stat.uid !== uid) throw unsafe(`${path} is owned by another user`);
}

/** How long a check may keep meeting another process's transient state before the open is refused. */
const TRANSIENT_RETRY_MS = 1_500;

/** Blocks the thread for `ms` milliseconds without spinning. */
function pause(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Runs `check` until it passes or the bounded time on the monotonic clock is over. Concurrent opens meet
 * transient states (a database being linked into place has two names for a moment; icacls fails while another
 * icacls holds the object; a side file is being restricted), so only a refusal that persists is reported.
 */
function settled(check: () => void): void {
  const deadline = performance.now() + TRANSIENT_RETRY_MS;
  for (let attempt = 0; ; attempt += 1) {
    try {
      check();
      return;
    } catch (error) {
      if (performance.now() >= deadline) {
        if (error instanceof PersistenceError) throw error;
        throw new PersistenceError('UNSAFE_PATH', 'the access list could not be read or set', { cause: error });
      }
    }
    pause(Math.min(200, 10 * 2 ** attempt) + randomBytes(1).readUInt8(0) % 20);
  }
}

function sides(path: string): string[] {
  return [`${path}-wal`, `${path}-shm`];
}

/** The checks an existing database passes before use, including fresh ancestry and object permissions. */
function checkExisting(path: string): void {
  settled(() => {
    const stat = lstatOrUndefined(path);
    if (stat === undefined) {
      checkAncestry(dirname(path));
      throw new PersistenceError('NOT_FOUND', `no database at ${path}`);
    }
    checkExistingFile(stat, path);
    if (checkAncestry(dirname(path), posix ? [] : [path, ...sides(path).filter(present)]).length > 0) {
      throw new PersistenceError('NOT_FOUND', `no database at ${path}`);
    }
  });
}

/**
 * Windows: after a read-write connection is open, its -wal and -shm files exist. SQLite created them with the
 * directory's inherited access list, so any that is not owner-only yet is restricted; these are files FluxWarden
 * created.
 */
export function secureSideFiles(path: string): void {
  if (posix) return;
  settled(() => {
    const targets = sides(path).filter(present);
    const access = onlyOwnerAccessMany(targets);
    for (const [index, side] of targets.entries()) {
      if (access[index] === true || !present(side)) continue;
      try {
        restrictCreated(side, 'file');
      } catch (error) {
        if (present(side)) throw new PersistenceError('UNSAFE_PATH', `${side} could not be made owner-only`, { cause: error });
      }
    }
  });
}

/**
 * Prepares the database path for a read-write open. Missing directories are created owner-only (POSIX 0700; on
 * Windows a protected DACL for the current user). A directory that already exists is never changed: on POSIX it
 * is refused if other users can write to it. A missing database is created owner-only from the start: on POSIX
 * exclusively with mode 0600 (SQLite gives -wal and -shm the same mode), on Windows through createOwnerOnlyFile.
 * An existing database, -wal or -shm that is not owner-only is refused, never changed.
 */
export function prepareWritablePath(path: string): string {
  const absolute = resolve(path);
  const dir = dirname(absolute);
  if (lstatOrUndefined(absolute) !== undefined) {
    checkExisting(absolute);
    return absolute;
  }
  const missing = checkAncestry(dir);
  if (missing.length > 0) {
    const created: string[] = [];
    try {
      for (const target of missing) {
        if (!posix) {
          // Native creation supplies the protected DACL before the directory exists.
          // A concurrent existing directory is inspected without mutation or cleanup ownership.
          settled(() => { createOwnerOnlyDirectory(target); });
          continue;
        }
        try {
          mkdirSync(target, { mode: 0o700 });
          created.push(target);
        } catch (error) {
          if ((error as { code?: unknown }).code !== 'EEXIST') throw error;
          checkAncestry(target);
          continue;
        }
      }
      // Recheck directories won by another creator, including children of sticky temporary directories.
      checkAncestry(dir);
    } catch (error) {
      for (const target of created.reverse()) removeQuietly(() => { rmdirSync(target); });
      if (error instanceof PersistenceError) throw error;
      throw new PersistenceError('UNSAFE_PATH', `${dir} could not be made owner-only`, { cause: error });
    }
  }
  if (posix) ownerOnly(lstatSync(dir), dir, 0o077);
  if (lstatOrUndefined(absolute) !== undefined) {
    checkExisting(absolute);
    return absolute;
  }
  if (!posix) {
    let created: boolean;
    try {
      created = createOwnerOnlyFile(dir, absolute);
    } catch (error) {
      throw new PersistenceError('UNSAFE_PATH', `${absolute} could not be created owner-only`, { cause: error });
    }
    if (!created) checkExisting(absolute);
    return absolute;
  }
  let fd: number;
  try {
    fd = openSync(absolute, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
  } catch (error) {
    // Another process created the file first: it is checked like any existing database.
    if ((error as { code?: unknown }).code !== 'EEXIST') throw error;
    checkExisting(absolute);
    return absolute;
  }
  try {
    ownerOnly(fstatSync(fd), absolute, 0o077);
  } catch (error) {
    removeQuietly(() => { unlinkSync(absolute); });
    throw error;
  } finally {
    closeSync(fd);
  }
  return absolute;
}

function removeQuietly(remove: () => void): void {
  try {
    remove();
  } catch {
    // The original failure is what the caller reports.
  }
}

/**
 * Checks the database path for a read-only open without creating or changing anything; a missing file is
 * NOT_FOUND, and a database or side file that is not owner-only is refused.
 */
export function checkReadablePath(path: string): string {
  const absolute = resolve(path);
  checkExisting(absolute);
  return absolute;
}

/** The database file and any -wal or -shm beside it: regular files, not links, with a single name, owner-only. */
function checkExistingFile(stat: Stats, path: string): void {
  checkSingleFile(stat, path);
  for (const side of [`${path}-wal`, `${path}-shm`]) {
    const sideStat = lstatOrUndefined(side);
    if (sideStat !== undefined) checkSingleFile(sideStat, side);
  }
}

function checkSingleFile(stat: Stats, path: string): void {
  if (stat.isSymbolicLink()) throw unsafe(`${path} is a symbolic link`);
  if (!stat.isFile()) throw unsafe(`${path} is not a regular file`);
  if (stat.nlink > 1) throw unsafe(`${path} has another hard link`);
  ownerOnly(stat, path, 0o077);
}
