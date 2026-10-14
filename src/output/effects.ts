// Adapted from ZilverZtream/macwarden examples/payment-lab/src/outbox/effects.ts (25bbfa4).
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { closeSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync, unlinkSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { writeOwnerOnlyFile } from './private-file.js';
import { onlyOwnerAccess, restrictCreated } from '../persistence/owner-files.js';

/**
 * Signed effect files: a JSON object of text or number fields plus `hmacSha256`, an HMAC-SHA256 over the
 * fields with the state directory's outbox key. The HMAC lets a writer recognise a file it wrote itself.
 *
 * Publication is exclusive: the content is written to a temporary file (created owner-only with O_EXCL,
 * written, fsynced), then hard-linked to the final name, which fails if the name exists. A reader never
 * sees a partial file, an existing file is never replaced, and no temporary file is left behind.
 */

export type EffectFields = Record<string, string | number>;

/** Effect files are small; anything larger is not one of them and is not parsed. */
export const MAX_EFFECT_BYTES = 64 * 1024;

const RESERVED = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])$/i;
const MAX_BASE = 200;
const hexByte = (byte: number): string => `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;

/**
 * The file name for a subject, distinct for distinct subjects on every platform, including file systems
 * that ignore letter case: lower-case letters, digits, '_' and '-' stay, every other byte is percent-encoded
 * with upper-case hex; a Windows device name has its first letter encoded; an encoding longer than 200
 * characters becomes '=sha256-' and the SHA-256 of the subject. A name never starts with '.'.
 */
export function fileBase(subject: string): string {
  let base = Array.from(Buffer.from(subject, 'utf8'))
    .map(byte => /[a-z0-9_-]/.test(String.fromCharCode(byte)) ? String.fromCharCode(byte) : hexByte(byte))
    .join('');
  if (RESERVED.test(base)) base = `${hexByte(base.charCodeAt(0))}${base.slice(1)}`;
  if (base.length > MAX_BASE) base = `=sha256-${createHash('sha256').update(subject, 'utf8').digest('hex')}`;
  return base;
}

export function effectPath(dir: string, subject: string): string {
  return join(dir, `${fileBase(subject)}.json`);
}

/** The signed text: the fields as [name, value] pairs sorted by name, as JSON. */
function canonical(fields: EffectFields): string {
  return JSON.stringify(Object.keys(fields).sort().map(name => [name, fields[name] ?? null]));
}

export function sign(key: Uint8Array, fields: EffectFields): string {
  return createHmac('sha256', key).update(canonical(fields)).digest('hex');
}

export type ReadResult =
  | { state: 'absent' }
  | { state: 'invalid'; reason: string }
  | { state: 'valid'; fields: EffectFields };

/** Reads an effect file and checks its HMAC. Bounded: a file over MAX_EFFECT_BYTES is invalid, not read. */
export function readEffect(path: string, key: Uint8Array): ReadResult {
  let size: number;
  try {
    const stat = lstatSync(path);
    if (!stat.isFile()) return { state: 'invalid', reason: 'not a regular file' };
    size = stat.size;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { state: 'absent' };
    throw error;
  }
  if (size > MAX_EFFECT_BYTES) return { state: 'invalid', reason: `${String(size)} bytes, more than ${String(MAX_EFFECT_BYTES)}` };
  let parsed: unknown;
  try { parsed = JSON.parse(readFileSync(path, 'utf8')); } catch { return { state: 'invalid', reason: 'not JSON' }; }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return { state: 'invalid', reason: 'not an object' };
  const { hmacSha256, ...rest } = parsed as Record<string, unknown>;
  if (typeof hmacSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(hmacSha256)) return { state: 'invalid', reason: 'no HMAC' };
  for (const value of Object.values(rest)) {
    if (typeof value !== 'string' && typeof value !== 'number') return { state: 'invalid', reason: 'a field is not text or a number' };
  }
  const fields = rest as EffectFields;
  if (!timingSafeEqual(Buffer.from(sign(key, fields), 'hex'), Buffer.from(hmacSha256, 'hex'))) return { state: 'invalid', reason: 'HMAC does not match' };
  return { state: 'valid', fields };
}

/** The bytes of the effect file for `fields`. */
export function effectContent(key: Uint8Array, fields: EffectFields): Buffer {
  return Buffer.from(`${JSON.stringify({ ...fields, hmacSha256: sign(key, fields) })}\n`, 'utf8');
}

/**
 * Creates `<dir>/<fileBase(subject)>.json` holding `content`, exclusively. `exists`: a file already holds the
 * name, and nothing was written.
 */
export function publishEffect(dir: string, subject: string, content: Uint8Array): 'written' | 'exists' {
  if (content.length > MAX_EFFECT_BYTES) throw new Error(`an effect file is at most ${String(MAX_EFFECT_BYTES)} bytes`);
  prepareEffectDirectory(dir);
  const base = fileBase(subject);
  const path = join(dir, `${base}.json`);
  const tmp = join(dir, `.${base}.${randomBytes(8).toString('hex')}.tmp`);
  if (writeOwnerOnlyFile(tmp, content) !== 'written') throw new Error('effects: the effect file could not be prepared');
  try {
    linkSync(tmp, path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') return 'exists';
    throw error;
  } finally { unlinkSync(tmp); }
  syncDir(dir);
  return 'written';
}

/**
 * fsync of the directory, so a new name in it survives power loss (POSIX). Where directory sync is not
 * supported (Windows refuses to open or fsync a directory; some file systems answer EINVAL or ENOTSUP) it is
 * skipped; any other error propagates.
 */
function syncDir(dir: string): void {
  let fd: number | undefined;
  try {
    fd = openSync(dir, 'r');
    fsyncSync(fd);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    const unsupported = code === 'EINVAL' || code === 'ENOTSUP' || (process.platform === 'win32' && (code === 'EISDIR' || code === 'EPERM' || code === 'EACCES'));
    if (!unsupported) throw error;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/** Creates the effect directory owner-only when missing; anything but a real directory (a file, a link) is refused. */
export function prepareEffectDirectory(dir: string): void {
  const missing: string[] = [];
  for (let current = resolve(dir); ; current = dirname(current)) {
    const stat = lstatSync(current, { throwIfNoEntry: false });
    if (stat !== undefined) {
      if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error('effects: an ancestor is not a real directory');
    } else missing.unshift(current);
    if (dirname(current) === current) break;
  }
  for (const path of missing) {
    try { mkdirSync(path, { mode: 0o700 }); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'EEXIST') continue; throw error; }
    if (process.platform === 'win32') restrictCreated(path, 'directory');
  }
  const stat = lstatSync(dir);
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error('effects: the effect directory is not a directory');
  if (process.platform === 'win32' ? !onlyOwnerAccess(dir) : stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0) {
    throw new Error('effects: the effect directory is not owner-only');
  }
}
