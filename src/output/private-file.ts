// The owner-only file writer. The file is private before any content is written, and a file that
// cannot be made private, or whose write fails, is removed. An existing file (or link) at the path
// is never opened or changed, and a symbolic link or junction among the parent directories is refused.
//
// POSIX: the file is created exclusively with mode 0600, then its mode and owner are set and read
// back on the open descriptor. Windows: the staging directory and file are created with protected
// owner-only native DACLs and verified before writing. The completed file is linked to the target
// path, which fails if that exists.
import { closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, openSync, rmdirSync, unlinkSync, writeSync } from 'node:fs';
import { dirname, join, parse, resolve } from 'node:path';
import { createOwnerOnlyDirectory, createOwnerOnlyEmptyFile, restrictToOwner, type OwnerOnlyTarget } from '../platform/owner-only.js';

export type OwnerOnlyWrite = 'written' | 'exists' | 'failed' | 'invalid-path';

const windows = process.platform === 'win32';

function errorCode(error: unknown): unknown {
  return typeof error === 'object' && error !== null && 'code' in error ? error.code : undefined;
}

function quietly(action: () => void): void {
  try {
    action();
  } catch {
    // Cleanup after a failure; the command reports the failure itself.
  }
}

/**
 * True when every parent directory of `path` is a real directory. On POSIX a link owned by root
 * above the immediate parent (such as /tmp or /var on macOS) is accepted: only an administrator can
 * place one there. On Windows every symbolic link and junction is refused.
 */
function parentsAreDirectories(path: string): boolean {
  const parent = dirname(path);
  const root = parse(parent).root;
  for (let current = parent; ; current = dirname(current)) {
    let stat;
    try {
      stat = lstatSync(current, { throwIfNoEntry: false });
    } catch {
      return false;
    }
    if (stat === undefined) return false;
    if (stat.isSymbolicLink()) {
      if (windows || current === parent || stat.uid !== 0) return false;
    } else if (!stat.isDirectory()) {
      return false;
    }
    if (current === root || dirname(current) === current) return true;
  }
}

const RESERVED_DEVICE = /^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[0-9\u00b9\u00b2\u00b3]|LPT[0-9\u00b9\u00b2\u00b3])$/i;

/**
 * Windows paths that Win32 would rewrite or resolve elsewhere are refused: the device and verbatim
 * namespaces (\\?\ and \\.\), alternate data streams, names ending in a dot or a space, and
 * reserved device names with any extension.
 */
function acceptablePath(path: string): boolean {
  if (!windows) return true;
  if (/^[\\/]{2}[?.][\\/]/.test(path)) return false;
  const root = parse(path).root;
  const components = path.slice(root.length).split(/[\\/]/).filter(part => part !== '');
  return components.every(part => !/[:]/.test(part) && !/[. ]$/.test(part) && !RESERVED_DEVICE.test(part.split('.')[0]?.trim() ?? ''));
}

function writeAll(fd: number, bytes: Uint8Array): void {
  for (let offset = 0; offset < bytes.byteLength;) offset += writeSync(fd, bytes, offset);
  fsyncSync(fd);
}

/**
 * Creates `path` exclusively, restricts it to its owner, then writes `bytes`. Returns false when the
 * path already exists; a file this call created is removed if a later step fails.
 */
function createPrivate(path: string, bytes: Uint8Array, flags: number, scratch?: string): boolean {
  let fd: number;
  try {
    fd = openSync(path, flags, 0o600);
  } catch (error) {
    if (errorCode(error) === 'EEXIST') return false;
    throw error;
  }
  let done = false;
  try {
    const target: OwnerOnlyTarget = scratch === undefined ? { fd } : { fd, scratch };
    restrictToOwner(path, 'file', target);
    writeAll(fd, bytes);
    done = true;
  } finally {
    closeSync(fd);
    if (!done) quietly(() => { unlinkSync(path); });
  }
  return true;
}

function writeWindows(path: string, bytes: Uint8Array): OwnerOnlyWrite {
  if (lstatSync(path, { throwIfNoEntry: false }) !== undefined) return 'exists';
  // This name reserves no authority: native creation and the owner/DACL
  // readback below admit the directory. Avoid OpenSSL entropy for a public name;
  // its Windows initialization can depend on the caller's SystemRoot setting.
  const dir = join(dirname(path), `.fluxwarden-${String(process.pid)}-${process.hrtime.bigint().toString(16)}`);
  try {
    // Reuse the persistence native CreateNew/DACL readback (microsoft/referencesource
    // mscorlib/system/io/{directory,filestream}.cs), rather than restrict an inherited object.
    if (!createOwnerOnlyDirectory(dir)) return 'failed';
  } catch {
    return 'failed';
  }
  const staged = join(dir, 'file');
  let created = false;
  try {
    if (!createOwnerOnlyEmptyFile(staged)) return 'failed';
    created = true;
    const before = lstatSync(staged);
    const fd = openSync(staged, constants.O_WRONLY | constants.O_NOFOLLOW);
    try {
      const held = fstatSync(fd);
      if (!held.isFile() || held.nlink !== 1 || held.size !== 0 || before.isSymbolicLink()
        || before.dev !== held.dev || before.ino !== held.ino) return 'failed';
      writeAll(fd, bytes);
    } finally { closeSync(fd); }
    try {
      linkSync(staged, path);
    } catch (error) {
      return errorCode(error) === 'EEXIST' ? 'exists' : 'failed';
    }
    return 'written';
  } catch {
    return 'failed';
  } finally {
    if (created) quietly(() => { unlinkSync(staged); });
    quietly(() => { rmdirSync(dir); });
  }
}

function writePosix(path: string, bytes: Uint8Array): OwnerOnlyWrite {
  try {
    return createPrivate(path, bytes, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW) ? 'written' : 'exists';
  } catch {
    return 'failed';
  }
}

/** Writes `bytes` to a new owner-only file at `path`. */
export function writeOwnerOnlyFile(path: string, bytes: Uint8Array): OwnerOnlyWrite {
  if (!acceptablePath(path)) return 'invalid-path';
  const absolute = resolve(path);
  if (!acceptablePath(absolute)) return 'invalid-path';
  if (!parentsAreDirectories(absolute)) return 'failed';
  try {
    return windows ? writeWindows(absolute, bytes) : writePosix(absolute, bytes);
  } catch {
    return 'failed';
  }
}
