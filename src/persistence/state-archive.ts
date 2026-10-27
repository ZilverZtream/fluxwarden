import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, openSync, readFileSync, readdirSync, readSync, rmdirSync, unlinkSync, writeSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { openDatabase, type StoredNode } from './db.js';
import { checkPrivateDirectory, checkPrivateFiles, checkReadablePath, createPrivateDirectoriesExclusive, createPrivateDirectoryExclusive } from './paths.js';
import { createOwnerOnlyEmptyFiles } from '../platform/owner-only.js';
import { SCHEMA_VERSION } from './schema.js';
import { readEffect } from '../output/effects.js';
import { writeOwnerOnlyFile } from '../output/private-file.js';
import { RUN_ID } from '../evidence/bundle.js';

interface Payload { path: string; sha256: string; bytes: number }
interface Identity { id: string; name: string; implementation: string; pubkey: string }
interface Manifest { format: 1; schema: number; nodes: Identity[]; files: Payload[] }
const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;
function fail(): never { throw new Error('state: backup or restore integrity and private-path validation failed'); }
const identity = (node: StoredNode): Identity => ({ id: node.id, name: node.name, implementation: node.implementation, pubkey: node.expectedPubkey });
const runName = (name: string): boolean => name.endsWith('.json') && RUN_ID.test(name.slice(0, -5));
const alertName = (name: string): boolean => /^[a-zA-Z0-9_%=.-]+\.json$/.test(name) && !name.startsWith('.');

/** SQLite backups are hashed with fixed-size reads, as FluxWarden's immutable database reader does. */
function payload(path: string, name: string): Payload {
  const fd = openSync(path, 'r');
  try {
    const before = fstatSync(fd), hash = createHash('sha256'), buffer = Buffer.allocUnsafe(65_536);
    if (!before.isFile() || before.nlink !== 1) fail();
    for (;;) {
      const n = readSync(fd, buffer, 0, buffer.length, null);
      if (n === 0) break;
      hash.update(buffer.subarray(0, n));
    }
    const after = fstatSync(fd), named = lstatSync(path);
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs
      || named.ino !== after.ino || named.dev !== after.dev || named.isSymbolicLink() || named.nlink !== 1) fail();
    return { path: name, sha256: hash.digest('hex'), bytes: after.size };
  } finally { closeSync(fd); }
}

function copyPrivate(entries: readonly { source: string; destination: string }[]): void {
  // Reuse FluxWarden src/platform/owner-only.ts native CreateNew batching: files are protected
  // before any secret byte is copied, without starting a separate ACL process for every payload.
  for (let start = 0; start < entries.length; start += 128) {
    const group = entries.slice(start, start + 128);
    if (process.platform === 'win32' && createOwnerOnlyEmptyFiles(group.map(entry => entry.destination)).some(created => !created)) fail();
    for (const entry of group) {
      const source = openSync(entry.source, constants.O_RDONLY | constants.O_NOFOLLOW);
      let destination: number | undefined;
      try {
        destination = process.platform === 'win32' ? openSync(entry.destination, 'r+') : openSync(entry.destination, 'wx', 0o600);
        const buffer = Buffer.allocUnsafe(65_536);
        for (;;) {
          const n = readSync(source, buffer, 0, buffer.length, null);
          if (n === 0) break;
          for (let offset = 0; offset < n;) offset += writeSync(destination, buffer, offset, n - offset);
        }
        fsyncSync(destination);
      } finally { if (destination !== undefined) closeSync(destination); closeSync(source); }
    }
  }
}

function retained(database: string, alertDir: string): { source: string; name: string }[] {
  const parent = dirname(database);
  const prefix = `${basename(database)}.`;
  const runs = readdirSync(parent).filter(name => name.startsWith(prefix) && runName(name.slice(prefix.length)))
    .map(name => ({ source: join(parent, name), name: `runs/${name.slice(prefix.length)}` }));
  checkPrivateDirectory(alertDir);
  const alerts = readdirSync(alertDir).map(name => {
    if (!alertName(name)) fail();
    return { source: join(alertDir, name), name: `alerts/${name}` };
  });
  return [{ source: join(parent, 'outbox.key'), name: 'outbox.key' }, ...runs, ...alerts].sort((a, b) => a.name.localeCompare(b.name));
}

function verifySignedAlerts(root: string, files: readonly Payload[]): void {
  const keyPath = join(root, 'outbox.key');
  if (lstatSync(keyPath).size !== 32) fail();
  const key = readFileSync(keyPath);
  try {
    for (const file of files) if (file.path.startsWith('alerts/') && readEffect(join(root, file.path), key).state !== 'valid') fail();
  } finally { key.fill(0); }
}

export async function backupState(database: string, alertDir: string, destination: string): Promise<void> {
  const db = openDatabase(database, { readOnly: true });
  try {
    const entries = retained(database, alertDir);
    checkPrivateFiles(entries.map(entry => entry.source));
    const before = entries.map(entry => payload(entry.source, entry.name));
    if (before.find(entry => entry.path === 'outbox.key')?.bytes !== 32) fail();
    const root = createPrivateDirectoryExclusive(destination);
    createPrivateDirectoriesExclusive([join(root, 'runs'), join(root, 'alerts')]);
    // nodejs/node doc/api/sqlite.md backup: a consistent SQLite online backup includes committed WAL pages.
    await db.backupTo(join(root, 'state.sqlite3'));
    copyPrivate(entries.map(entry => ({ source: entry.source, destination: join(root, entry.name) })));
    const retainedAfter = retained(database, alertDir);
    checkPrivateFiles(retainedAfter.map(entry => entry.source));
    const after = retainedAfter.map(entry => payload(entry.source, entry.name));
    if (JSON.stringify(before) !== JSON.stringify(after)) fail();
    const files = [payload(join(root, 'state.sqlite3'), 'state.sqlite3'), ...before];
    for (const file of files) if (JSON.stringify(payload(join(root, file.path), file.path)) !== JSON.stringify(file)) fail();
    verifySignedAlerts(root, files);
    const snapshot = openDatabase(join(root, 'state.sqlite3'), { readOnly: true });
    let nodes: Identity[];
    try { snapshot.integrityCheck(); nodes = snapshot.nodes.list().map(identity); } finally { snapshot.close(); }
    const manifest: Manifest = { format: 1, schema: SCHEMA_VERSION, nodes, files };
    if (writeOwnerOnlyFile(join(root, 'manifest.json'), Buffer.from(JSON.stringify(manifest))) !== 'written') fail();
  } finally { db.close(); }
}

function inventory(root: string, directories: string[], prefix = ''): string[] {
  directories.push(root);
  return readdirSync(root).flatMap(name => {
    const path = join(root, name), stat = lstatSync(path);
    if (stat.isSymbolicLink()) fail();
    if (stat.isDirectory()) return inventory(path, directories, `${prefix}${name}/`);
    if (!stat.isFile()) fail();
    return [`${prefix}${name}`];
  });
}

function verifiedManifest(root: string): Manifest {
  const path = checkReadablePath(join(root, 'manifest.json'));
  if (lstatSync(path).size > MAX_MANIFEST_BYTES) fail();
  const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'));
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) fail();
  const m = parsed as Partial<Manifest>;
  if (m.format !== 1 || m.schema !== SCHEMA_VERSION || !Array.isArray(m.nodes) || !Array.isArray(m.files)) fail();
  const directories: string[] = [];
  const actualFiles = inventory(root, directories);
  checkPrivateFiles(actualFiles.map(name => join(root, name)), directories);
  const names = new Set<string>();
  for (const file of m.files) {
    if (typeof file.path !== 'string' || names.has(file.path) || !/^[0-9a-f]{64}$/.test(file.sha256)
      || !Number.isSafeInteger(file.bytes) || file.bytes < 0) fail();
    const accepted = file.path === 'state.sqlite3' || file.path === 'outbox.key'
      || file.path.startsWith('runs/') && runName(file.path.slice(5))
      || file.path.startsWith('alerts/') && alertName(file.path.slice(7));
    if (!accepted || file.path.includes('\\')) fail();
    names.add(file.path);
    if (JSON.stringify(payload(join(root, file.path), file.path)) !== JSON.stringify(file)) fail();
  }
  if (!names.has('state.sqlite3') || !names.has('outbox.key')
    || JSON.stringify(actualFiles.sort()) !== JSON.stringify(['manifest.json', ...names].sort())) fail();
  verifySignedAlerts(root, m.files);
  const db = openDatabase(join(root, 'state.sqlite3'), { readOnly: true });
  try { db.integrityCheck(); if (JSON.stringify(db.nodes.list().map(identity)) !== JSON.stringify(m.nodes)) fail(); }
  finally { db.close(); }
  return m as Manifest;
}

export function restoreState(bundle: string, database: string, alertDir: string): void {
  const source = checkPrivateDirectory(bundle), manifest = verifiedManifest(source);
  const target = resolve(database), state = dirname(target);
  // Restored signing identity and alert history share the new private state root.
  if (resolve(alertDir) !== join(state, 'alerts')) fail();
  createPrivateDirectoryExclusive(state);
  const stage = join(state, '.restore');
  createPrivateDirectoriesExclusive([alertDir, stage]);
  const stagedDb = join(stage, 'state.sqlite3');
  copyPrivate([{ source: join(source, 'state.sqlite3'), destination: stagedDb }]);
  const databasePayload = manifest.files.find(file => file.path === 'state.sqlite3');
  if (JSON.stringify(payload(stagedDb, 'state.sqlite3')) !== JSON.stringify(databasePayload)) fail();
  const db = openDatabase(stagedDb, { readOnly: false });
  try { db.state.installRestoreBarrier(); } finally { db.close(); }
  const copies = manifest.files.filter(file => file.path !== 'state.sqlite3').map(file => {
    const destination = file.path === 'outbox.key' ? join(state, 'outbox.key')
      : file.path.startsWith('runs/') ? `${target}.${file.path.slice(5)}` : join(alertDir, file.path.slice(7));
    return { source: join(source, file.path), destination, expected: file };
  });
  copyPrivate(copies);
  for (const copy of copies) if (JSON.stringify(payload(copy.destination, copy.expected.path)) !== JSON.stringify(copy.expected)) fail();
  // Only publish the verified copy after its persistent barrier and every retained payload are durable.
  linkSync(stagedDb, target);
  unlinkSync(stagedDb);
  rmdirSync(stage);
  checkReadablePath(target);
}
