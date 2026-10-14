// SECURITY §5/D49/D55: binary identity resolution must not change the owner-only ACL policy.
import { spawnSync } from 'node:child_process';
import { expect, it } from 'vitest';
import { assertStrictWindowsOwnerOnly, canonicalWindowsSddl, WINDOWS_SECURITY_QUERY } from '../helpers/windows-security.js';
import type { WindowsSecurity } from '../helpers/windows-security.js';

const USER = 'S-1-5-21-1643835476-1616584234-1346609752-500';
const FOREIGN = 'S-1-5-21-918273645-112233445-667788990-500';
const GUID = '00112233-4455-6677-8899-aabbccddeeff';

it('CP-026/B1 the independent native oracle preserves ACL fields and refuses foreign owners or unsafe ACEs', () => {
  const aliased: WindowsSecurity = {
    sddl: `O:LAG:BAD:PAI(D;ID;FR;;;LA)(OA;OICI;FA;${GUID};;SY)(A;;FA;;;LA)`,
    ownerSid: USER, userSid: USER, trustees: [USER, 'S-1-5-18', USER],
  };
  expect(canonicalWindowsSddl(aliased)).toBe(`O:${USER}G:BAD:PAI(D;ID;FR;;;${USER})(OA;OICI;FA;${GUID};;S-1-5-18)(A;;FA;;;${USER})`);
  for (const kind of ['file', 'directory'] as const) {
    const ace = `(A;${kind === 'directory' ? 'OICI' : ''};FA;;;${USER})`;
    const good = { ...aliased, sddl: `O:${USER}D:PAI${ace}`, trustees: [USER] };
    expect(() => { assertStrictWindowsOwnerOnly(good, kind); }).not.toThrow();
    for (const bad of [
      { ...good, ownerSid: FOREIGN },
      { ...good, sddl: good.sddl.replace(ace, ace.replace(USER, FOREIGN)) },
      { ...good, sddl: `${good.sddl}(A;;FA;;;S-1-5-18)` },
      { ...good, sddl: good.sddl.replace('(A;', '(D;') },
      { ...good, sddl: good.sddl.replace(';FA;', ';FR;') },
      { ...good, sddl: good.sddl.replace(';FA;', 'ID;FA;') },
      { ...good, sddl: good.sddl.replace('D:PAI', 'D:AI') },
      { ...good, sddl: `O:${USER}D:PAI(OA;${kind === 'directory' ? 'OICI' : ''};FA;${GUID};;${USER})` },
    ]) expect(() => { assertStrictWindowsOwnerOnly(bad, kind); }, `${kind}: ${bad.sddl}, owner ${bad.ownerSid}`).toThrow();
  }
});

if (process.platform === 'win32') it('CP-026/B1 the independent query resolves native LA identities from binary descriptors without altering ACEs', () => {
  // In-memory native descriptors only: no existing filesystem object or ACL is changed.
  const prelude = `function Get-Acl {
    param([string]$LiteralPath)
    $acl=New-Object Security.AccessControl.FileSecurity
    $acl.SetSecurityDescriptorSddlForm($LiteralPath)
    return $acl
  }; `;
  for (const source of [
    'O:LAD:PAI(A;;FA;;;LA)',
    `O:${FOREIGN}D:PAI(A;;FA;;;LA)`,
    'O:LAD:PAI(A;;FA;;;LA)(A;;FA;;;SY)',
    'O:LAD:PAI(D;;FA;;;LA)',
    'O:LAD:PAI(A;ID;FA;;;LA)',
    `O:LAD:PAI(OA;;FA;${GUID};;LA)`,
    `O:LAD:PAI(A;;FA;;;${FOREIGN})`,
  ]) {
    const run = spawnSync('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', prelude + WINDOWS_SECURITY_QUERY],
      { encoding: 'utf8', windowsHide: true, shell: false, timeout: 10000, env: { ...process.env, FLUXWARDEN_ORACLE_PATH: source } });
    expect(run.status, run.stderr).toBe(0);
    const native = JSON.parse(run.stdout) as WindowsSecurity;
    const security = { ...native, sddl: canonicalWindowsSddl(native) };
    if (source === 'O:LAD:PAI(A;;FA;;;LA)') {
      expect(native.ownerSid).toBe(native.trustees[0]);
      expect(native.ownerSid.startsWith('S-1-')).toBe(true);
      // Simulated current identity is exactly the native owner, never inferred from the RID.
      expect(() => { assertStrictWindowsOwnerOnly({ ...security, userSid: native.ownerSid }, 'file'); }).not.toThrow();
    } else {
      // Resolve the local identity with Windows independently of this fixture's foreign owner/trustee.
      const resolved = native.ownerSid === FOREIGN ? native.trustees[0] : native.ownerSid;
      if (!resolved) throw new Error('No native owner identity');
      expect(() => { assertStrictWindowsOwnerOnly({ ...security, userSid: resolved }, 'file'); }, source).toThrow();
    }
  }
});
