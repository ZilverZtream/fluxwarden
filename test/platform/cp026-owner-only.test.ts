/*
Interface (src/platform/owner-only.ts):
  export function isOwnerOnlyDacl(sddl: string, userSid: string, kind: 'file' | 'directory'): boolean;
    True only for the DACL part of an icacls read-back that SECURITY.md §5 calls owner-only: protected
    from inheritance (P), and exactly one entry, an allow entry granting the current user SID full
    control, not inherited, with object and container inheritance (OICI) for a directory and no
    inheritance flags for a file. restrictToOwner refuses a read-back for which this is false.
*/
import { expect, it } from 'vitest';
import { loadSrc } from '../helpers/load-src.js';

interface OwnerOnlyModule { isOwnerOnlyDacl: (sddl: string, userSid: string, kind: 'file' | 'directory') => boolean }
const ownerOnly = (): Promise<OwnerOnlyModule> => loadSrc<OwnerOnlyModule>('platform/owner-only.ts');

const USER = 'S-1-5-21-2451588979-888268432-3937270729-1000';
const OTHER = 'S-1-5-21-2451588979-888268432-3937270729-1004';

it('CP-026/B1 the owner-only DACL predicate accepts exactly one protected full-control entry for the current user', async () => {
  const { isOwnerOnlyDacl } = await ownerOnly();
  expect(isOwnerOnlyDacl(`D:PAI(A;;FA;;;${USER})`, USER, 'file')).toBe(true);
  expect(isOwnerOnlyDacl(`D:PAI(A;OICI;FA;;;${USER})`, USER, 'directory')).toBe(true);
});

it.each([
  ['not protected from inheritance', `D:AI(A;;FA;;;${USER})`, 'file'],
  ['an inherited entry', `D:PAI(A;ID;FA;;;${USER})`, 'file'],
  ['an extra entry for another user', `D:PAI(A;;FA;;;${USER})(A;;FR;;;${OTHER})`, 'file'],
  ['an extra entry for SYSTEM', `D:PAI(A;;FA;;;${USER})(A;;FA;;;SY)`, 'file'],
  ['an extra entry for Administrators', `D:PAI(A;;FA;;;${USER})(A;;FA;;;BA)`, 'file'],
  ['an extra entry for Everyone', `D:PAI(A;;FA;;;${USER})(A;;FR;;;WD)`, 'file'],
  ['only another user', `D:PAI(A;;FA;;;${OTHER})`, 'file'],
  ['less than full control', `D:PAI(A;;FR;;;${USER})`, 'file'],
  ['a deny entry instead of an allow entry', `D:PAI(D;;FA;;;${USER})`, 'file'],
  ['directory inheritance flags on a file', `D:PAI(A;OICI;FA;;;${USER})`, 'file'],
  ['no inheritance flags on a directory', `D:PAI(A;;FA;;;${USER})`, 'directory'],
  ['an empty DACL', 'D:PAI', 'file'],
  ['a null DACL', 'D:NO_ACCESS_CONTROL', 'file'],
  ['a user SID that is a prefix of the entry', `D:PAI(A;;FA;;;${USER}0)`, 'file'],
] as const)('CP-026/B1 the owner-only DACL predicate refuses %s', async (_name, sddl, kind) => {
  const { isOwnerOnlyDacl } = await ownerOnly();
  expect(isOwnerOnlyDacl(sddl, USER, kind)).toBe(false);
});
