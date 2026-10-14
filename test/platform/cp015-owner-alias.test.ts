// SECURITY §5/D55: aliases represent resolved SIDs, not additional permitted principals.
// Microsoft SID Strings: LA is Local Administrator (DOMAIN_USER_RID_ADMIN).
// https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings
// Hosted native reference windows24-430.log: current/owner SID500, protected single LA ACE.
import childProcess from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { testRoot } from '../helpers/env.js';
import { loadSrc } from '../helpers/load-src.js';
import type { Persistence } from '../helpers/cp015-persistence.js';
import { canonicalWindowsSddl, WINDOWS_SECURITY_QUERY } from '../helpers/windows-security.js';
import type { WindowsSecurity } from '../helpers/windows-security.js';
import { nativeCreationSecurity, objectIdentity } from '../helpers/windows-creation-oracle.js';

interface OwnerModule {
  restrictToOwner(path: string, kind: 'file' | 'directory'): void;
  readSecurityDescriptors(paths: readonly string[]): { ownerSid: string; sddl: string }[];
  isOwnerOnlySecurityDescriptor(sddl: string, ownerSid: string, userSid: string, kind: 'file' | 'directory'): boolean;
}
const WINDOWS_PS = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const realExec = childProcess.execFileSync;
afterEach(() => { vi.restoreAllMocks(); syncBuiltinESMExports(); vi.resetModules(); });

// Canonical SID controls run on every platform. Never equate RID500 across machines/domains.
const CI_LOCAL = 'S-1-5-21-1643835476-1616584234-1346609752-500';
const FOREIGN_LOCAL = 'S-1-5-21-918273645-112233445-667788990-500';
const FOREIGN_DOMAIN = 'S-1-5-21-119988776-221100998-334455667-500';
it.each([FOREIGN_LOCAL, FOREIGN_DOMAIN])('CP-015/B1 resolved foreign RID500 trustee %s is refused despite a matching current owner', async trustee => {
  const m = await loadSrc<OwnerModule>('platform/owner-only.ts');
  for (const kind of ['file', 'directory'] as const) {
    expect(m.isOwnerOnlySecurityDescriptor(`D:PAI(A;${kind === 'directory' ? 'OICI' : ''};FA;;;${trustee})`, CI_LOCAL, CI_LOCAL, kind)).toBe(false);
    expect(m.isOwnerOnlySecurityDescriptor(`D:PAI(A;${kind === 'directory' ? 'OICI' : ''};FA;;;${CI_LOCAL})`, trustee, CI_LOCAL, kind)).toBe(false);
  }
});

/**
 * Fixed public OS query injection: whoami/icacls are synthetic, and the genuine Windows
 * Get-Acl dependency receives native DirectorySecurity/FileSecurity fixtures. The product's
 * fixed read-only PowerShell command remains opaque and unchanged after this prelude.
 * Windows itself resolves LA via GetAccessRules(..., SecurityIdentifier); no SID prefix inference.
 * Existing ACLs are never changed: every icacls mutation is intercepted at the OS boundary.
 * Native creation still executes under the real host token; its readback is then represented
 * by the same native binary descriptor fixture used for Get-Acl and the simulated whoami.
 */
async function windowsFixture(current: 'local-admin' | 'foreign-domain-admin', extras = '') {
  let extraAccess = extras;
  const native = realExec(WINDOWS_PS, ['-NoProfile', '-NonInteractive', '-Command',
    "$a=New-Object Security.AccessControl.DirectorySecurity; $a.SetSecurityDescriptorSddlForm('D:PAI(A;OICI;FA;;;LA)'); $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])[0].IdentityReference.Value"],
  { encoding: 'utf8', windowsHide: true, timeout: 10000 }).trim();
  expect(/^S-1-5-21-\d+-\d+-\d+-500$/.test(native), 'native local Administrator resolved to a full SID').toBe(true);
  const user = current === 'local-admin' ? native : FOREIGN_DOMAIN;
  expect(current !== 'foreign-domain-admin' || user !== native, 'foreign identity differs from actual local Administrator').toBe(true);
  vi.spyOn(childProcess, 'execFileSync').mockImplementation((executable, args = [], options) => {
    const strings = args.map(String);
    if (/whoami\.exe$/i.test(executable)) return Buffer.from(`"fixture\\Administrator","${user}"\r\n`);
    if (/icacls\.exe$/i.test(executable)) {
      const save = strings.indexOf('/save');
      if (save >= 0 && strings[save + 1]) writeFileSync(strings[save + 1] ?? '', `\ufeff${strings[0] ?? ''}\r\nD:PAI(A;OICI;FA;;;LA)\r\n`, 'utf16le');
      return Buffer.from('Successfully processed1 files\r\n');
    }
    if (executable.toLowerCase() === WINDOWS_PS.toLowerCase()) {
      const command = strings.indexOf('-Command');
      if (command < 0) throw new Error('fixture requires the documented fixed read-only query boundary');
      const prelude = `function Get-Acl { param([string]$LiteralPath) if ([IO.Directory]::Exists($LiteralPath)) { $a=New-Object Security.AccessControl.DirectorySecurity; $flags='OICI' } else { $a=New-Object Security.AccessControl.FileSecurity; $flags='' }; $a.SetSecurityDescriptorSddlForm('O:${user}D:PAI(A;'+$flags+';FA;;;LA)${extraAccess}'); return $a }; `;
      if (typeof options?.input === 'string') {
        const request = JSON.parse(options.input) as { operation: string; path: string };
        if (request.operation === 'create-empty-file' || request.operation === 'create-directory') {
          const actual = realExec(executable, strings, options);
          const reply = JSON.parse(actual.toString()) as { created: boolean; ownerSid?: string; sddl?: string; length?: number };
          if (request.operation === 'create-empty-file' && !reply.created) return actual;
          if (reply.created) {
            const physical = nativeCreationSecurity([request.path])[0];
            expect(physical?.currentOwner, 'genuine creation uses the host token').toBe(true);
            expect(physical?.protected).toBe(true);
            expect(physical?.rules).toEqual([{ currentUser: true, type: 0, flags: request.operation === 'create-directory' ? 3 : 0, mask: 0x1f01ff }]);
            if (request.operation === 'create-empty-file') {
              expect(reply.length).toBe(0);
              expect(objectIdentity(request.path)).toMatchObject({ size: 0n, links: 1n, file: true, link: false });
            }
          }
          const modeled = JSON.parse(realExec(WINDOWS_PS, ['-NoProfile', '-NonInteractive', '-Command', prelude + WINDOWS_SECURITY_QUERY],
            { encoding: 'utf8', windowsHide: true, timeout: 10000, env: { ...process.env, FLUXWARDEN_ORACLE_PATH: request.path } })) as WindowsSecurity;
          const access = /D:([^]*?)(?=S:|$)/.exec(canonicalWindowsSddl(modeled))?.[0];
          if (access === undefined) throw new Error('native fixture has no access descriptor');
          const represented = JSON.stringify({ ...reply, ownerSid: modeled.ownerSid, sddl: access });
          return typeof actual === 'string' ? represented : Buffer.from(represented);
        }
      }
      const forwarded = [...strings]; forwarded[command + 1] = prelude + (strings[command + 1] ?? '');
      return realExec(executable, forwarded, options);
    }
    throw new Error('fixture encountered an undeclared native executable');
  });
  syncBuiltinESMExports(); vi.resetModules();
  const root = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'owner-alias-'));
  const m = await loadSrc<OwnerModule>('platform/owner-only.ts');
  return { root, m, user, native, trustedDataAccess: () => { extraAccess = '(A;;FA;;;SY)(A;;FA;;;BA)'; } };
}

if (process.platform === 'win32') {
  it('CP-015/B1 the native alias fixture represents held-file creation using the same resolved identity as owner readback', async () => {
    const f = await windowsFixture('local-admin');
    const file = join(f.root, 'ordinary-native.bin');
    // .NET FileStream(FileSecurity) attaches the descriptor in CreateNew and reads it while held.
    // https://github.com/microsoft/referencesource/blob/main/mscorlib/system/io/filestream.cs
    const creationOracle = `& {
      $ErrorActionPreference='Stop'
      $request=ConvertFrom-Json ([Console]::In.ReadToEnd())
      $user=[Security.Principal.WindowsIdentity]::GetCurrent().User
      $acl=New-Object Security.AccessControl.FileSecurity
      $acl.SetOwner($user)
      $acl.SetAccessRuleProtection($true,$false)
      $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($user,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow)))
      $held=New-Object IO.FileStream($request.path,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$acl)
      try {
        $read=$held.GetAccessControl()
        $trustee=$read.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])[0].IdentityReference.Value
        [pscustomobject]@{created=$true;ownerSid=$read.GetOwner([Security.Principal.SecurityIdentifier]).Value;sddl=('D:P(A;;FA;;;'+$trustee+')');length=$held.Length}|ConvertTo-Json -Compress
      } finally { $held.Dispose() }
    }`;
    const represented = JSON.parse(childProcess.execFileSync(WINDOWS_PS, ['-NoProfile', '-NonInteractive', '-Command', creationOracle],
      { encoding: 'utf8', windowsHide: true, timeout: 10000, input: JSON.stringify({ operation: 'create-empty-file', path: file }) })) as { created: boolean; ownerSid: string; sddl: string; length: number };
    expect(represented.created).toBe(true);
    expect(represented.length).toBe(0);
    expect(represented.ownerSid).toBe(f.user);
    expect(f.m.isOwnerOnlySecurityDescriptor(represented.sddl, represented.ownerSid, f.user, 'file')).toBe(true);
    expect(f.m.readSecurityDescriptors([file]).map(d => d.ownerSid)).toEqual([f.user]);
    expect(objectIdentity(file)).toMatchObject({ size: 0n, links: 1n, file: true, link: false });
    const actual = nativeCreationSecurity([file])[0];
    expect(actual?.currentOwner).toBe(true);
    expect(actual?.protected).toBe(true);
    expect(actual?.rules).toEqual([{ currentUser: true, type: 0, flags: 0, mask: 0x1f01ff }]);
  });

  it('CP-015/B1 native same-SID LA owner-only readback permits directory and strict file restriction', async () => {
    const f = await windowsFixture('local-admin');
    const file = join(f.root, 'new-public-file.bin'); writeFileSync(file, 'ordinary test data');
    expect(f.m.readSecurityDescriptors([f.root, file]).map(d => d.ownerSid)).toEqual([f.user, f.user]);
    expect(() => { f.m.restrictToOwner(f.root, 'directory'); }).not.toThrow();
    expect(() => { f.m.restrictToOwner(file, 'file'); }).not.toThrow();
  });
  it('CP-015/B1 native same-SID LA permits public database creation and read-only reopen under an owned parent', async () => {
    const f = await windowsFixture('local-admin');
    const directory = join(f.root, 'owned-data'); mkdirSync(directory);
    const file = join(directory, 'state.sqlite');
    const p = await loadSrc<Persistence>('persistence/index.ts');
    const db = p.openDatabase(file, { readOnly: false }); db.close();
    f.trustedDataAccess(); // Data read checks permit trusted SYSTEM/Administrators; keys remain strict.
    const read = p.openDatabase(file, { readOnly: true }); read.close();
  });
  it('CP-015/B1 native LA resolution refuses a foreign domain RID500 current user despite a matching foreign owner', async () => {
    const f = await windowsFixture('foreign-domain-admin');
    expect(() => { f.m.restrictToOwner(f.root, 'directory'); }).toThrow();
  });
  it('CP-026/B1 native current LA plus SYSTEM and Administrators is still refused for a strict key file', async () => {
    const f = await windowsFixture('local-admin', '(A;;FA;;;SY)(A;;FA;;;BA)');
    const file = join(f.root, 'ordinary-test-key.bin'); writeFileSync(file, 'ordinary fixture bytes');
    expect(() => { f.m.restrictToOwner(file, 'file'); }).toThrow();
  });
  it('CP-015/B1 native same-SID LA does not hide foreign mutable ancestry from database creation', async () => {
    const f = await windowsFixture('local-admin', '(A;OICI;FA;;;WD)');
    const file = join(f.root, 'unsafe.sqlite');
    const p = await loadSrc<Persistence>('persistence/index.ts');
    expect(() => p.openDatabase(file, { readOnly: false })).toThrow();
    expect(existsSync(file)).toBe(false);
    expect(existsSync(`${file}-wal`)).toBe(false);
    expect(existsSync(`${file}-shm`)).toBe(false);
  });
}
