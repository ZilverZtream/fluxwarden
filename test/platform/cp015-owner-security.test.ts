/*
Interface (src/platform/owner-only.ts):
  export function isOwnerOnlySecurityDescriptor(sddl: string, ownerSid: string, userSid: string,
    kind: 'file' | 'directory'): boolean;
  SECURITY.md §5 requires both owner and permissions to be read back. ownerSid is the canonical
  SID read from the Windows security descriptor, independently of the SID in its allow entry.
  Accept only the current owner and the strict protected, uninherited, full-control DACL.
*/
import { expect, it } from 'vitest';
import { loadSrc } from '../helpers/load-src.js';

interface OwnerSecurityModule {
  isOwnerOnlySecurityDescriptor: (sddl: string, ownerSid: string, userSid: string, kind: 'file' | 'directory') => boolean;
}
const ownerSecurity = (): Promise<OwnerSecurityModule> => loadSrc<OwnerSecurityModule>('platform/owner-only.ts');
const USER = 'S-1-5-21-2451588979-888268432-3937270729-1000';
const OTHER = 'S-1-5-21-2451588979-888268432-3937270729-1004';
const descriptor = (kind: 'file' | 'directory'): string => `D:PAI(A;${kind === 'directory' ? 'OICI' : ''};FA;;;${USER})`;

it('CP-015/B1 Windows permission read-back accepts the current owner with an owner-only file or directory DACL', async () => {
  const { isOwnerOnlySecurityDescriptor } = await ownerSecurity();
  for (const kind of ['file', 'directory'] as const) {
    expect(isOwnerOnlySecurityDescriptor(descriptor(kind), USER, USER, kind), kind).toBe(true);
  }
});

it('CP-015/B1 Windows permission read-back refuses a foreign owner even when only the current user has DACL access', async () => {
  const { isOwnerOnlySecurityDescriptor } = await ownerSecurity();
  for (const kind of ['file', 'directory'] as const) {
    expect(isOwnerOnlySecurityDescriptor(descriptor(kind), OTHER, USER, kind), kind).toBe(false);
  }
});

it('CP-015/B1 Windows permission read-back refuses absent, malformed, aliased or prefix-matching owner SIDs', async () => {
  const { isOwnerOnlySecurityDescriptor } = await ownerSecurity();
  for (const owner of ['', 'Dennis', 'BA', 'S-1', `${USER}0`, `${USER} `, ` ${USER}`]) {
    for (const kind of ['file', 'directory'] as const) {
      expect(isOwnerOnlySecurityDescriptor(descriptor(kind), owner, USER, kind), `${kind}: ${owner}`).toBe(false);
    }
  }
});

it('CP-015/B1 Windows permission read-back refuses foreign or inherited DACL access even when the owner matches', async () => {
  const { isOwnerOnlySecurityDescriptor } = await ownerSecurity();
  for (const sddl of [`D:AI(A;;FA;;;${USER})`, `D:PAI(A;ID;FA;;;${USER})`, `D:PAI(A;;FA;;;${USER})(A;;FR;;;${OTHER})`, 'D:NO_ACCESS_CONTROL']) {
    expect(isOwnerOnlySecurityDescriptor(sddl, USER, USER, 'file'), sddl).toBe(false);
  }
});
