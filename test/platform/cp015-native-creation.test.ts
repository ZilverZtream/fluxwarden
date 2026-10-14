// SECURITY §5: native creation must preserve every existing object and refuse unsafe ancestry.
/*
Interface (src/platform/owner-only.ts):
  createOwnerOnlyEmptyFile(path: string): boolean;
    True for a new verified, empty owner-only file; false only for an existing regular-file collision.
  createOwnerOnlyDirectory(path: string): void;
    Create a verified owner-only directory; existing directories remain unchanged.
  Both throw on other failures, and directory creation never creates an unrequested parent.
  Path, link, ancestry and identity admission belongs to the normal persistence caller.
*/
import childProcess, { spawnSync } from 'node:child_process';
import { existsSync, linkSync, mkdirSync, mkdtempSync, readdirSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { syncBuiltinESMExports } from 'node:module';
import { expect, it, vi } from 'vitest';
import { codeOf, descriptor, grantDirectoryMutation, loadPersistence, makeOwnerOnlyDir } from '../helpers/cp015-persistence.js';
import { testRoot } from '../helpers/env.js';
import { loadSrc } from '../helpers/load-src.js';
import { nativeCreationSecurity, objectIdentity, ordinaryFileHash, WINDOWS_POWERSHELL } from '../helpers/windows-creation-oracle.js';
import { readWindowsSecurity } from '../helpers/windows-security.js';

function protectedRoot(): string {
  const path = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'native-create-'));
  makeOwnerOnlyDir(path);
  return path;
}

function security(paths: readonly string[]) {
  return process.platform === 'win32' ? nativeCreationSecurity(paths) : paths.map(descriptor);
}

interface CreationModule {
  createOwnerOnlyEmptyFile(path: string): boolean;
  createOwnerOnlyDirectory(path: string): void;
}

interface CreatedFileModule { restrictOwnerOnlyCreatedFile(path: string, expectedUserSid: string): void }
async function createdFileModule(): Promise<CreatedFileModule> {
  const m = await loadSrc<CreatedFileModule>('platform/owner-only.ts');
  expect(typeof m.restrictOwnerOnlyCreatedFile, 'the ordinary created-file protection interface exists').toBe('function');
  return m;
}

function heldFileIdentity(path: string) {
  const identity = objectIdentity(path);
  return { dev: identity.dev, ino: identity.ino, birthtimeNs: identity.birthtimeNs, size: identity.size,
    links: identity.links, file: identity.file, directory: identity.directory, link: identity.link };
}

async function creationModule(): Promise<CreationModule> {
  const m = await loadSrc<CreationModule>('platform/owner-only.ts');
  expect(typeof m.createOwnerOnlyEmptyFile, 'the ordinary native file creation interface exists').toBe('function');
  expect(typeof m.createOwnerOnlyDirectory, 'the ordinary native directory creation interface exists').toBe('function');
  return m;
}

function expectNewSecurity(path: string, kind: 'file' | 'directory'): void {
  const actual = nativeCreationSecurity([path])[0];
  expect(actual?.currentOwner).toBe(true);
  expect(actual?.protected).toBe(true);
  // Win32 FULL_CONTROL includes every file right; directories propagate to both objects and containers.
  expect(actual?.rules).toEqual([{ currentUser: true, type: 0, flags: kind === 'directory' ? 3 : 0, mask: 0x1f01ff }]);
}

interface NativeCreationRequest { operation: 'create-empty-file' | 'create-directory'; path: string }
interface NativeCreationReply { created: boolean; ownerSid: string; sddl: string; length?: number }
const realExec = childProcess.execFileSync;
type NativePortHook = (request: NativeCreationRequest, invoke: () => string | Buffer) => string | Buffer;

/** The ordinary process request is data; the product's fixed PowerShell script stays opaque. */
async function withNativePort(hook: NativePortHook, run: (m: CreationModule) => Promise<void> | void): Promise<void> {
  vi.spyOn(childProcess, 'execFileSync').mockImplementation((executable, args = [], options) => {
    if (executable.toLowerCase() === WINDOWS_POWERSHELL.toLowerCase() && typeof options?.input === 'string') {
      const request = JSON.parse(options.input) as { operation: string; path: string };
      if (request.operation === 'create-empty-file' || request.operation === 'create-directory') {
        return hook({ operation: request.operation, path: request.path }, () => realExec(executable, args, options));
      }
    }
    return realExec(executable, args, options);
  });
  syncBuiltinESMExports(); vi.resetModules();
  try { await run(await creationModule()); }
  finally { vi.restoreAllMocks(); syncBuiltinESMExports(); vi.resetModules(); }
}

function corruptReply(result: string | Buffer, alter: (reply: NativeCreationReply) => void): string | Buffer {
  const reply = JSON.parse(result.toString()) as NativeCreationReply;
  alter(reply);
  const encoded = JSON.stringify(reply);
  return typeof result === 'string' ? encoded : Buffer.from(encoded);
}

if (process.platform === 'win32') {
  it('CP-015/B1 created-file native protection preserves content and identity and yields sole current-owner full control', async () => {
    const m = await createdFileModule();
    const root = protectedRoot();
    const path = join(root, 'ordinary-owned.bin'); writeFileSync(path, 'ordinary owned-file reference bytes');
    const user = readWindowsSecurity(path).userSid;
    const identity = heldFileIdentity(path);
    const content = ordinaryFileHash(path);
    const parent = nativeCreationSecurity([root]);
    expect(nativeCreationSecurity([path])[0]?.protected, 'the fixture requires an observable permission change').toBe(false);
    m.restrictOwnerOnlyCreatedFile(path, user);
    expect(heldFileIdentity(path)).toEqual(identity);
    expect(identity.links).toBe(1n);
    expect(ordinaryFileHash(path)).toBe(content);
    expectNewSecurity(path, 'file');
    expect(nativeCreationSecurity([root])).toEqual(parent);
    expect(readdirSync(root)).toEqual(['ordinary-owned.bin']);
  });

  it('CP-015/B1 created-file native protection refuses a foreign allow grant without changing content identity or complete ACL', async () => {
    const m = await createdFileModule();
    const root = protectedRoot();
    const path = join(root, 'unsafe-owned.bin'); writeFileSync(path, 'ordinary unsafe-ACL reference bytes');
    const user = readWindowsSecurity(path).userSid;
    const grant = spawnSync('C:\\Windows\\System32\\icacls.exe', [path, '/grant', '*S-1-1-0:(R)'],
      { encoding: 'utf8', windowsHide: true, shell: false, timeout: 10000 });
    expect(grant.status, 'owned foreign-access fixture is established').toBe(0);
    const before = nativeCreationSecurity([root, path]);
    expect(before[1]?.rules.some(rule => !rule.currentUser)).toBe(true);
    const identity = objectIdentity(path);
    const content = ordinaryFileHash(path);
    expect(() => { m.restrictOwnerOnlyCreatedFile(path, user); }).toThrow();
    expect(objectIdentity(path)).toEqual(identity);
    expect(ordinaryFileHash(path)).toBe(content);
    expect(nativeCreationSecurity([root, path])).toEqual(before);
    expect(readdirSync(root)).toEqual(['unsafe-owned.bin']);
  });

  it('CP-015/B1 created-file native protection refuses missing paths stale user SIDs and multiply linked files without mutation', async () => {
    const m = await createdFileModule();
    const root = protectedRoot();
    const path = join(root, 'ordinary-owned.bin'); writeFileSync(path, 'ordinary invalid-target reference bytes');
    const user = readWindowsSecurity(path).userSid;
    const before = nativeCreationSecurity([root, path]);
    const identity = objectIdentity(path);
    const content = ordinaryFileHash(path);
    expect(() => { m.restrictOwnerOnlyCreatedFile(join(root, 'missing.bin'), user); }).toThrow();
    expect(() => { m.restrictOwnerOnlyCreatedFile(path, 'S-1-5-21-119988776-221100998-334455667-500'); }).toThrow();
    expect(objectIdentity(path)).toEqual(identity);
    expect(ordinaryFileHash(path)).toBe(content);
    expect(nativeCreationSecurity([root, path])).toEqual(before);
    const alias = join(root, 'alias.bin'); linkSync(path, alias);
    const linked = nativeCreationSecurity([root, path, alias]);
    const linkedIdentity = objectIdentity(path);
    expect(linkedIdentity.links).toBe(2n);
    expect(() => { m.restrictOwnerOnlyCreatedFile(path, user); }).toThrow();
    expect(objectIdentity(path)).toEqual(linkedIdentity);
    expect(ordinaryFileHash(path)).toBe(content);
    expect(nativeCreationSecurity([root, path, alias])).toEqual(linked);
    expect(readdirSync(root).sort()).toEqual(['alias.bin', 'ordinary-owned.bin']);
  });

  it('CP-015/B1 created-file native protection preserves live SQLite WAL and SHM identities and permits continued reads and writes', async () => {
    const m = await createdFileModule();
    const root = protectedRoot();
    const path = join(root, 'ordinary.sqlite');
    const db = new DatabaseSync(path);
    try {
      db.exec('PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE ordinary(value INTEGER NOT NULL); INSERT INTO ordinary VALUES(7)');
      const files = [path, `${path}-wal`, `${path}-shm`];
      expect(files.every(existsSync), 'SQLite keeps both side files live').toBe(true);
      const user = readWindowsSecurity(path).userSid;
      const identities = files.map(heldFileIdentity);
      const contents = files.map(ordinaryFileHash);
      for (const file of files) m.restrictOwnerOnlyCreatedFile(file, user);
      expect(files.map(heldFileIdentity)).toEqual(identities);
      expect(files.map(ordinaryFileHash)).toEqual(contents);
      for (const file of files) expectNewSecurity(file, 'file');
      expect(db.prepare('SELECT value FROM ordinary ORDER BY value').all()).toEqual([{ value: 7 }]);
      db.exec('INSERT INTO ordinary VALUES(11)');
      expect(db.prepare('SELECT value FROM ordinary ORDER BY value').all()).toEqual([{ value: 7 }, { value: 11 }]);
      expect(files.map(file => ({ dev: heldFileIdentity(file).dev, ino: heldFileIdentity(file).ino, links: heldFileIdentity(file).links })))
        .toEqual(identities.map(identity => ({ dev: identity.dev, ino: identity.ino, links: identity.links })));
    } finally { db.close(); }
  });

  it('CP-015/B1 native file creation returns true for a new zero-byte protected current-owner file', async () => {
    const m = await creationModule();
    const root = protectedRoot();
    const name = "ordinary ' file; $data.bin";
    const path = join(root, name);
    const before = nativeCreationSecurity([root]);
    expect(m.createOwnerOnlyEmptyFile(path)).toBe(true);
    expect(objectIdentity(path)).toMatchObject({ size: 0n, links: 1n, file: true, directory: false, link: false });
    expectNewSecurity(path, 'file');
    expect(nativeCreationSecurity([root])).toEqual(before);
    expect(readdirSync(root)).toEqual([name]);
  });

  it('CP-015/B1 native directory creation protects a requested directory with object and container inheritance', async () => {
    const m = await creationModule();
    const root = protectedRoot();
    const name = "ordinary ' state; $data";
    const path = join(root, name);
    const before = nativeCreationSecurity([root]);
    m.createOwnerOnlyDirectory(path);
    expect(objectIdentity(path)).toMatchObject({ file: false, directory: true, link: false });
    expectNewSecurity(path, 'directory');
    expect(readdirSync(path)).toEqual([]);
    expect(nativeCreationSecurity([root])).toEqual(before);
    expect(readdirSync(root)).toEqual([name]);
  });

  it('CP-015/B1 native CreateNew collision returns false without changing existing content identity or complete ACL', async () => {
    const m = await creationModule();
    const root = protectedRoot();
    const path = join(root, 'existing.bin'); writeFileSync(path, 'ordinary collision reference bytes');
    const before = nativeCreationSecurity([root, path]);
    const identity = objectIdentity(path);
    const content = ordinaryFileHash(path);
    expect(m.createOwnerOnlyEmptyFile(path)).toBe(false);
    expect(ordinaryFileHash(path)).toBe(content);
    expect(objectIdentity(path)).toEqual(identity);
    expect(nativeCreationSecurity([root, path])).toEqual(before);
    expect(readdirSync(root)).toEqual(['existing.bin']);
  });

  it('CP-015/B1 native directory collision leaves every descriptor byte and existing file unchanged', async () => {
    const m = await creationModule();
    const root = protectedRoot();
    const ordinary = join(root, 'ordinary.bin'); writeFileSync(ordinary, 'ordinary directory reference bytes');
    const before = nativeCreationSecurity([root, ordinary]);
    const identities = [objectIdentity(root), objectIdentity(ordinary)];
    const content = ordinaryFileHash(ordinary);
    m.createOwnerOnlyDirectory(root);
    expect(nativeCreationSecurity([root, ordinary])).toEqual(before);
    expect([objectIdentity(root), objectIdentity(ordinary)]).toEqual(identities);
    expect(ordinaryFileHash(ordinary)).toBe(content);
    expect(readdirSync(root)).toEqual(['ordinary.bin']);
  });

  it('CP-015/B1 native file creation refuses a directory collision and missing parent rather than reporting false', async () => {
    const m = await creationModule();
    const root = protectedRoot();
    const before = nativeCreationSecurity([root]);
    const identity = objectIdentity(root);
    expect(() => m.createOwnerOnlyEmptyFile(root)).toThrow();
    expect(() => m.createOwnerOnlyEmptyFile(join(root, 'missing', 'ordinary.bin'))).toThrow();
    expect(readdirSync(root)).toEqual([]);
    expect(objectIdentity(root)).toEqual(identity);
    expect(nativeCreationSecurity([root])).toEqual(before);
  });

  it('CP-015/B1 native directory creation refuses missing parents and an existing file without mutating either', async () => {
    const m = await creationModule();
    const root = protectedRoot();
    const file = join(root, 'ordinary.bin'); writeFileSync(file, 'ordinary type reference bytes');
    const before = nativeCreationSecurity([root, file]);
    const identities = [objectIdentity(root), objectIdentity(file)];
    const content = ordinaryFileHash(file);
    expect(() => { m.createOwnerOnlyDirectory(join(root, 'missing', 'unrequested')); }).toThrow();
    expect(() => { m.createOwnerOnlyDirectory(file); }).toThrow();
    expect(readdirSync(root)).toEqual(['ordinary.bin']);
    expect([objectIdentity(root), objectIdentity(file)]).toEqual(identities);
    expect(ordinaryFileHash(file)).toBe(content);
    expect(nativeCreationSecurity([root, file])).toEqual(before);
  });

  it('CP-015/B1 a regular file appearing at the native CreateNew boundary wins without truncation or ACL changes', async () => {
    const root = protectedRoot();
    const path = join(root, 'race.bin');
    expect(existsSync(path)).toBe(false);
    let calls = 0;
    let captured: { identity: ReturnType<typeof objectIdentity>; hash: string; security: ReturnType<typeof nativeCreationSecurity> } | undefined;
    await withNativePort((request, invoke) => {
      expect(request).toEqual({ operation: 'create-empty-file', path });
      calls++;
      expect(existsSync(path), 'collision occurs after the request reaches the native operation').toBe(false);
      writeFileSync(path, 'ordinary concurrent creator bytes');
      captured = { identity: objectIdentity(path), hash: ordinaryFileHash(path), security: nativeCreationSecurity([root, path]) };
      return invoke();
    }, m => { expect(m.createOwnerOnlyEmptyFile(path)).toBe(false); });
    expect(calls).toBe(1);
    expect(captured).toBeDefined();
    expect(objectIdentity(path)).toEqual(captured?.identity);
    expect(ordinaryFileHash(path)).toBe(captured?.hash);
    expect(nativeCreationSecurity([root, path])).toEqual(captured?.security);
    expect(readdirSync(root)).toEqual(['race.bin']);
  });

  it.each(['foreign-owner', 'unprotected', 'additional-ace', 'nonempty'] as const)(
    'CP-015/B1 native new-file readback refuses %s before reporting successful creation', async corruption => {
      const root = protectedRoot();
      const path = join(root, 'readback.bin');
      let calls = 0;
      await withNativePort((request, invoke) => {
        expect(request).toEqual({ operation: 'create-empty-file', path });
        calls++;
        return corruptReply(invoke(), reply => {
          expect(reply.created).toBe(true);
          expect(reply.length).toBe(0);
          if (corruption === 'foreign-owner') reply.ownerSid = 'S-1-5-21-119988776-221100998-334455667-500';
          if (corruption === 'unprotected') reply.sddl = reply.sddl.replace(/D:P/, 'D:');
          if (corruption === 'additional-ace') reply.sddl += '(A;;FA;;;S-1-5-18)';
          if (corruption === 'nonempty') reply.length = 1;
        });
      }, m => { expect(() => m.createOwnerOnlyEmptyFile(path)).toThrow(); });
      expect(calls).toBe(1);
      if (existsSync(path)) {
        expect(objectIdentity(path)).toMatchObject({ file: true, size: 0n });
        expectNewSecurity(path, 'file');
      }
      expect(readdirSync(root).filter(name => name !== 'readback.bin')).toEqual([]);
    },
  );

  it('CP-015/B1 native directory readback refuses absent container inheritance without rewriting the created ACL', async () => {
    const root = protectedRoot();
    const path = join(root, 'readback-state');
    let calls = 0;
    await withNativePort((request, invoke) => {
      expect(request).toEqual({ operation: 'create-directory', path });
      calls++;
      return corruptReply(invoke(), reply => { reply.sddl = reply.sddl.replace('OICI', 'OI'); });
    }, m => { expect(() => { m.createOwnerOnlyDirectory(path); }).toThrow(); });
    expect(calls).toBe(1);
    if (existsSync(path)) {
      expectNewSecurity(path, 'directory');
      expect(readdirSync(path)).toEqual([]);
    }
    expect(readdirSync(root).filter(name => name !== 'readback-state')).toEqual([]);
  });

  it('CP-015/B1 a native creation execution failure remains an error instead of an already-existing result', async () => {
    const root = protectedRoot();
    const path = join(root, 'failure.bin');
    let calls = 0;
    await withNativePort(request => {
      expect(request).toEqual({ operation: 'create-empty-file', path });
      calls++;
      throw Object.assign(new Error('ordinary native access-denied reference'), { status: 5, code: 'EACCES' });
    }, m => { expect(() => m.createOwnerOnlyEmptyFile(path)).toThrow(); });
    expect(calls).toBe(1);
    expect(readdirSync(root)).toEqual([]);
  });

  it('CP-015/B1 persistence refuses a missing-object collision response without data or other path creation', async () => {
    const root = protectedRoot();
    const path = join(root, 'database.sqlite');
    let calls = 0;
    await withNativePort((request) => {
      expect(request.operation).toBe('create-empty-file');
      calls++;
      return Buffer.from('{"created":false}');
    }, async () => {
      const p = await loadPersistence();
      expect(codeOf(() => { p.openDatabase(path, { readOnly: false }).close(); })).toBe('UNSAFE_PATH');
    });
    expect(calls).toBeGreaterThan(0);
    expect(readdirSync(root)).toEqual([]);
  });
}

if (process.platform === 'win32') it('CP-015/B1 native creation in an existing admitted directory preserves its complete ACL and ordinary files', async () => {
  const p = await loadPersistence();
  const root = protectedRoot();
  const directory = join(root, 'existing-state'); mkdirSync(directory); makeOwnerOnlyDir(directory);
  // Existing data objects may retain trusted SYSTEM access; creation cannot normalize that DACL.
  const grant = spawnSync('C:\\Windows\\System32\\icacls.exe', [directory, '/grant', '*S-1-5-18:(OI)(CI)(R)'],
    { encoding: 'utf8', windowsHide: true, shell: false, timeout: 10000 });
  expect(grant.status, 'owned trusted-access fixture is established').toBe(0);
  const ordinary = join(directory, 'ordinary.bin'); writeFileSync(ordinary, 'ordinary reference bytes');
  const before = nativeCreationSecurity([root, directory, ordinary]);
  expect(before[1]?.rules.length).toBe(2);
  const ordinaryIdentity = objectIdentity(ordinary);
  const ordinaryHash = ordinaryFileHash(ordinary);
  const path = join(directory, 'database.sqlite');
  p.openDatabase(path, { readOnly: false }).close();
  expect(existsSync(path)).toBe(true);
  expect(nativeCreationSecurity([root, directory, ordinary])).toEqual(before);
  expect(objectIdentity(ordinary)).toEqual(ordinaryIdentity);
  expect(ordinaryFileHash(ordinary)).toBe(ordinaryHash);
  const created = nativeCreationSecurity([path])[0];
  expect(created?.currentOwner).toBe(true);
  expect(created?.protected).toBe(true);
  expect(created?.rules).toEqual([{ currentUser: true, type: 0, flags: 0, mask: 0x1f01ff }]);
});

  it('CP-015/B1 native database creation refuses a junction without creating anything in its target', async () => {
    const p = await loadPersistence();
    const root = protectedRoot();
    const control = join(root, 'control.sqlite');
    p.openDatabase(control, { readOnly: false }).close();
    expect(existsSync(control), 'the same root admits an ordinary creation').toBe(true);
    const target = join(root, 'target'); mkdirSync(target);
    const junction = join(root, 'junction'); symlinkSync(target, junction, process.platform === 'win32' ? 'junction' : 'dir');
    const before = security([root, target]);
    const identity = objectIdentity(target);
    try {
      expect(codeOf(() => { p.openDatabase(join(junction, 'new-state', 'database.sqlite'), { readOnly: false }).close(); })).toBe('UNSAFE_PATH');
      expect(readdirSync(target)).toEqual([]);
      expect(readdirSync(root).sort()).toEqual(['control.sqlite', 'junction', 'target']);
      expect(security([root, target])).toEqual(before);
      expect(objectIdentity(target)).toEqual(identity);
    } finally { unlinkSync(junction); }
  });

  it('CP-015/B1 native database creation refuses foreign mutable ancestry without creating parents or staging files', async () => {
    const p = await loadPersistence();
    const root = protectedRoot();
    const control = join(root, 'control.sqlite');
    p.openDatabase(control, { readOnly: false }).close();
    expect(existsSync(control), 'the same root admits an ordinary creation').toBe(true);
    const unsafe = join(root, 'unsafe'); mkdirSync(unsafe);
    grantDirectoryMutation(unsafe);
    const before = security([root, unsafe]);
    const identity = objectIdentity(unsafe);
    const newParent = join(unsafe, 'new-state');
    expect(codeOf(() => { p.openDatabase(join(newParent, 'database.sqlite'), { readOnly: false }).close(); })).toBe('UNSAFE_PATH');
    expect(existsSync(newParent)).toBe(false);
    expect(readdirSync(unsafe)).toEqual([]);
    expect(readdirSync(root).sort()).toEqual(['control.sqlite', 'unsafe']);
    expect(security([root, unsafe])).toEqual(before);
    expect(objectIdentity(unsafe)).toEqual(identity);
  });
