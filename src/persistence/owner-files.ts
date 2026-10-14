// Windows owner-only database files, built on src/platform/owner-only.ts (the one module that runs icacls).
// FluxWarden changes the access list only of objects it creates itself: directories it makes, a staging
// directory for a new database, the database, its -wal and -shm files, and a private scratch directory.
// Existing objects are only read.
import { lstatSync } from 'node:fs';
import { currentUserSid, createOwnerOnlyEmptyFile, readSecurityDescriptors, restrictOwnerOnlyCreatedFile, restrictToOwner, type OwnerOnlyKind, type OwnerSecurityDescriptor } from '../platform/owner-only.js';

let userSid: string | undefined;

function sid(): string {
  userSid ??= currentUserSid();
  return userSid;
}

/** SYSTEM and the Administrators group, as SDDL abbreviations and SIDs: they can take over any file in any case. */
const SYSTEM_PRINCIPALS = new Set(['SY', 'BA', 'S-1-5-18', 'S-1-5-32-544']);
const TRUSTED_INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464';

function trustedPrincipal(principal: string): boolean {
  return principal === sid() || SYSTEM_PRINCIPALS.has(principal) || principal === TRUSTED_INSTALLER;
}

/**
 * Existing ancestors may grant read access and creation of other children, but not replacement or control
 * of a traversed directory. The parent of a missing directory must also have safe inherited permissions.
 */
export function safeAncestorAccessMany(paths: readonly string[], creationParent: string | undefined, stateDir: string): boolean[] {
  return readSecurityDescriptors(paths).map((descriptor, index) => ancestorAccess(descriptor, paths[index], creationParent, stateDir));
}

/** Reads ancestors and existing private objects together, with no permission results retained across calls. */
export function pathAccessMany(ancestors: readonly string[], creationParent: string | undefined, stateDir: string, objects: readonly string[]): { ancestors: boolean[]; objects: boolean[] } {
  const paths = [...new Set([...ancestors, ...objects])];
  const descriptors = new Map(paths.map((path, index) => [path, index]));
  const read = readSecurityDescriptors(paths);
  const descriptorFor = (path: string): OwnerSecurityDescriptor => {
    const descriptor = read[descriptors.get(path) ?? -1];
    if (descriptor === undefined) throw new Error('owner-only: missing security descriptor');
    return descriptor;
  };
  return {
    ancestors: ancestors.map(path => ancestorAccess(descriptorFor(path), path, creationParent, stateDir)),
    objects: objects.map(path => ownerAccess(descriptorFor(path))),
  };
}

function ancestorAccess(descriptor: OwnerSecurityDescriptor, path: string | undefined, creationParent: string | undefined, stateDir: string): boolean {
  if (path === stateDir) return ownerAccess(descriptor);
  if (!trustedPrincipal(descriptor.ownerSid)) return false;
  const dacl = /^D:[A-Z]*((?:\([^()]*\))*)$/.exec(descriptor.sddl);
  if (dacl === null) return false;
  for (const entry of (dacl[1] ?? '').matchAll(/\(([^()]*)\)/g)) {
    const fields = (entry[1] ?? '').split(';');
    const [type, flags, rights, objectType, inheritedType, principal] = fields;
    if (fields.length !== 6 || !['A', 'D'].includes(type ?? '') || objectType !== '' || inheritedType !== '') return false;
    if (type === 'D' || trustedPrincipal(principal ?? '')) continue;
    const inheriting = path === creationParent && (flags ?? '').includes('CI');
    if ((flags ?? '').includes('IO') && !inheriting) continue;
    if (inheriting && principal === 'CO') continue;
    const mask = accessMask(rights ?? '');
    // Read/list/execute/control/synchronise and generic read/execute. AppendData on an existing ancestor
    // can create a sibling, but cannot replace a child whose ownership and DACL are checked separately.
    const allowed = 0xA01200A9 | (path === creationParent ? 0 : 0x4);
    if (mask === undefined || (mask & ~allowed) !== 0) return false;
  }
  return true;
}

function accessMask(rights: string): number | undefined {
  if (/^0x[0-9a-f]{1,8}$/i.test(rights)) return Number.parseInt(rights.slice(2), 16);
  const aliases: Readonly<Record<string, number>> = { FR: 0x120089, FX: 0x1200A0, GR: 0x80000000, GX: 0x20000000, RC: 0x20000, LC: 0x4 };
  if (rights.length === 0 || rights.length % 2 !== 0) return undefined;
  let mask = 0;
  for (let offset = 0; offset < rights.length; offset += 2) {
    const value = aliases[rights.slice(offset, offset + 2)];
    if (value === undefined) return undefined;
    mask |= value;
  }
  return mask;
}

/**
 * Whether no principal other than the current user, SYSTEM and Administrators is granted any access to `path`,
 * read from its DACL as SDDL. Inherited entries count like explicit ones; deny entries grant nothing. Changes nothing.
 */
export function onlyOwnerAccess(path: string): boolean {
  return onlyOwnerAccessMany([path])[0] === true;
}

/** Reads each object afresh; results are reused only within this query, never across opens. */
export function onlyOwnerAccessMany(paths: readonly string[]): boolean[] {
  return readSecurityDescriptors(paths).map(ownerAccess);
}

function ownerAccess({ sddl, ownerSid }: OwnerSecurityDescriptor): boolean {
  if (ownerSid !== sid()) return false;
  const dacl = /^D:[A-Z]*((?:\([^()]*\))*)$/.exec(sddl);
  if (dacl === null) return false;
  for (const entry of (dacl[1] ?? '').matchAll(/\(([^()]*)\)/g)) {
    const fields = (entry[1] ?? '').split(';');
    const type = fields[0] ?? '';
    const principal = fields[5] ?? '';
    if (fields.length !== 6 || !['A', 'D', 'OA', 'OD'].includes(type)) return false;
    if (type === 'D' || type === 'OD') continue;
    if (principal !== sid() && !SYSTEM_PRINCIPALS.has(principal)) return false;
  }
  return true;
}

/** Gives an object FluxWarden created an owner-only protected DACL, read back exactly; throws otherwise. */
export function restrictCreated(path: string, kind: OwnerOnlyKind): void {
  if (kind === 'file') restrictOwnerOnlyCreatedFile(path, sid());
  else restrictToOwner(path, kind, {});
}

/**
 * Creates `target` empty with a protected owner-only DACL in the native CreateNew call. The descriptor is
 * read back through the held exclusive handle before any SQLite open. Returns false for an existing file;
 * existing objects receive no ownership or permission writes.
 */
export function createOwnerOnlyFile(_dir: string, target: string): boolean {
  return createOwnerOnlyEmptyFile(target);
}

/** Whether `path` currently exists (a side file can vanish when SQLite's last connection closes). */
export function present(path: string): boolean {
  return lstatSync(path, { throwIfNoEntry: false }) !== undefined;
}
