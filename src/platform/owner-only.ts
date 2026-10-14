// Owner-only permissions. On POSIX the mode is set on the open descriptor (0600 for files, 0700 for
// directories) and read back. On Windows Node cannot set a DACL, so the system icacls.exe is run from
// the fixed system directory with a fixed argument array and no shell: the owner becomes the current
// user, the DACL is protected from inheritance and its only entry grants the current user full
// control. A fixed read-only PowerShell script reads back the owner SID and DACL. New empty Windows
// database objects receive a protected native DACL in their creation call. Already-created database
// files are admitted and protected through a held native handle. This is the only module that starts
// a child process.
import { execFileSync } from 'node:child_process';
import { fchmodSync, fstatSync, lstatSync } from 'node:fs';
import { win32 } from 'node:path';

export type OwnerOnlyKind = 'file' | 'directory';

export interface OwnerOnlyTarget {
  /** An open descriptor of the object; required on POSIX. */
  readonly fd?: number;
  /** A caller-reserved path within its private staging directory. */
  readonly scratch?: string;
}

const windows = process.platform === 'win32';

/**
 * The system directory is fixed rather than taken from SystemRoot or windir, which the caller's
 * environment controls. A Windows installation elsewhere is refused.
 */
const SYSTEM_DIRECTORY = 'C:\\Windows\\System32';

function systemTool(name: string): string {
  const tool = win32.join(SYSTEM_DIRECTORY, name);
  const directories = ['C:\\', 'C:\\Windows', SYSTEM_DIRECTORY];
  if (name === 'WindowsPowerShell\\v1.0\\powershell.exe') directories.push(win32.join(SYSTEM_DIRECTORY, 'WindowsPowerShell'), win32.join(SYSTEM_DIRECTORY, 'WindowsPowerShell', 'v1.0'));
  for (const directory of directories) {
    const stat = lstatSync(directory, { throwIfNoEntry: false });
    if (stat === undefined || stat.isSymbolicLink() || !stat.isDirectory()) throw new Error('owner-only: the Windows system directory is not at C:\\Windows\\System32');
  }
  const stat = lstatSync(tool, { throwIfNoEntry: false });
  if (stat === undefined || stat.isSymbolicLink() || !stat.isFile()) throw new Error('owner-only: a required system tool is missing');
  return tool;
}

function run(tool: string, args: readonly string[], input?: string): string {
  if (!windows) throw new Error('owner-only: system tools are run on Windows only');
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^(?:systemroot|windir|psmodulepath)$/i.test(name)));
  env['SystemRoot'] = 'C:\\Windows';
  env['windir'] = 'C:\\Windows';
  env['PSModulePath'] = win32.join(SYSTEM_DIRECTORY, 'WindowsPowerShell', 'v1.0', 'Modules');
  return execFileSync(systemTool(tool), args, { encoding: 'utf8', shell: false, windowsHide: true, timeout: 30_000, maxBuffer: 1_048_576, input, env, stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'] });
}

/** The SID of the user running this process, read with whoami.exe. */
export function currentUserSid(): string {
  const match = /^"[^"\r\n]*","(S-1-[0-9]+(?:-[0-9]+){2,})"\r?\n?$/.exec(run('whoami.exe', ['/user', '/fo', 'csv', '/nh']));
  if (match?.[1] === undefined || !canonicalSid(match[1])) throw new Error('owner-only: the current user SID could not be read');
  return match[1];
}

export interface OwnerSecurityDescriptor {
  readonly ownerSid: string;
  readonly sddl: string;
}

const SID = /^S-1-(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*)){1,15}$/;

function canonicalSid(value: string): boolean {
  if (value.length > 184 || !SID.test(value)) return false;
  const parts = value.split('-').slice(2).map(part => BigInt(part));
  return (parts[0] ?? 0x1000000000000n) <= 0xFFFFFFFFFFFFn && parts.slice(1).every(part => part <= 0xFFFFFFFFn);
}

// The script is fixed; paths arrive as JSON on stdin and are passed only to -LiteralPath.
// Native SDDL may abbreviate an account SID (for example LA). Read each trustee from the same
// descriptor's binary ACE, preserving the original SDDL's type, flags, rights, GUIDs and order.
// .NET RawSecurityDescriptor / KnownAce.SecurityIdentifier:
// https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.rawsecuritydescriptor
const READ_SECURITY = [
  "$ErrorActionPreference = 'Stop'; Import-Module Microsoft.PowerShell.Utility, Microsoft.PowerShell.Security;",
  '[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false); $paths = ConvertFrom-Json ([Console]::In.ReadToEnd()); $result = @();',
  'foreach ($path in $paths) { $acl = Get-Acl -LiteralPath $path;',
  '$sddl = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access);',
  '$native = [System.Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0);',
  "$entries = [regex]::Matches($sddl, '\\([^()]*\\)');",
  'if ($null -ne $native.DiscretionaryAcl -and $entries.Count -eq $native.DiscretionaryAcl.Count) {',
  'for ($index = $entries.Count - 1; $index -ge 0; $index--) { $entry = $entries[$index]; $ace = $native.DiscretionaryAcl[$index];',
  "$fields = $entry.Value.Substring(1, $entry.Length - 2).Split(';');",
  "if ($fields.Length -ne 6 -or $ace -isnot [System.Security.AccessControl.KnownAce]) { throw 'unsupported native access entry' };",
  '$fields[5] = $ace.SecurityIdentifier.Value;',
  "$sddl = $sddl.Remove($entry.Index, $entry.Length).Insert($entry.Index, '(' + ($fields -join ';') + ')');",
  '} };',
  '$result += @{ ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; sddl = $sddl } };',
  'ConvertTo-Json -Compress -InputObject @($result)',
].join(' ');

/** Reads current owner identities and DACLs in one bounded query, without modifying any object. */
export function readSecurityDescriptors(paths: readonly string[]): OwnerSecurityDescriptor[] {
  if (paths.length === 0) return [];
  const input = JSON.stringify(paths);
  if (paths.length > 512 || Buffer.byteLength(input, 'utf8') > 262_144) throw new Error('owner-only: security descriptor query exceeds its input bound');
  const parsed: unknown = JSON.parse(run('WindowsPowerShell\\v1.0\\powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', READ_SECURITY], input));
  if (!Array.isArray(parsed) || parsed.length !== paths.length) throw new Error('owner-only: unexpected security descriptor read-back');
  return parsed.map((value: unknown) => {
    if (value === null || typeof value !== 'object' || !('ownerSid' in value) || !('sddl' in value)
      || typeof value.ownerSid !== 'string' || !canonicalSid(value.ownerSid) || typeof value.sddl !== 'string') {
      throw new Error('owner-only: invalid security descriptor read-back');
    }
    return { ownerSid: value.ownerSid, sddl: value.sddl };
  });
}

/**
 * Whether the DACL part of an SDDL read-back is owner-only: protected from inheritance, and exactly
 * one entry, an allow entry granting `userSid` full control, not inherited, with object and container
 * inheritance for a directory and no inheritance flags for a file.
 */
export function isOwnerOnlyDacl(sddl: string, userSid: string, kind: OwnerOnlyKind): boolean {
  const dacl = /^D:([A-Z]*)((?:\([^()]*\))*)$/.exec(sddl);
  if (dacl === null || !(dacl[1] ?? '').includes('P')) return false;
  const entries = [...(dacl[2] ?? '').matchAll(/\(([^()]*)\)/g)].map(entry => (entry[1] ?? '').split(';'));
  if (entries.length !== 1) return false;
  const [type, flags, rights, objectType, inheritedType, sid, ...rest] = entries[0] ?? [];
  return rest.length === 0 && type === 'A' && flags === (kind === 'file' ? '' : 'OICI') && rights === 'FA'
    && objectType === '' && inheritedType === '' && sid === userSid;
}

/** Strict ownership and protected DACL verification for newly created private objects. */
export function isOwnerOnlySecurityDescriptor(sddl: string, ownerSid: string, userSid: string, kind: OwnerOnlyKind): boolean {
  return canonicalSid(ownerSid) && canonicalSid(userSid) && ownerSid === userSid && isOwnerOnlyDacl(sddl, userSid, kind);
}

/**
 * Restricts `path` to the current user. Throws when the permissions could not be set or do not read
 * back as owner-only; the caller then removes the object.
 */
export function restrictToOwner(path: string, kind: OwnerOnlyKind, target: OwnerOnlyTarget): void {
  if (!windows) {
    if (target.fd === undefined) throw new Error('owner-only: an open descriptor is required');
    fchmodSync(target.fd, kind === 'file' ? 0o600 : 0o700);
    const stat = fstatSync(target.fd);
    const uid = process.getuid?.();
    if ((stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new Error('owner-only: unexpected mode or owner');
    return;
  }
  const sid = currentUserSid();
  run('icacls.exe', [path, '/setowner', `*${sid}`, '/Q']);
  run('icacls.exe', [path, '/inheritance:r', '/grant:r', kind === 'file' ? `*${sid}:F` : `*${sid}:(OI)(CI)F`, '/Q']);
  const descriptor = readSecurityDescriptors([path])[0];
  if (descriptor === undefined || !isOwnerOnlySecurityDescriptor(descriptor.sddl, descriptor.ownerSid, sid, kind)) throw new Error('owner-only: unexpected owner or access list');
}

// Native ACLs are supplied to the creation operation, never applied to an existing object.
// FileStream uses SECURITY_ATTRIBUTES with CreateNew and reads back the held handle;
// Directory.CreateDirectory leaves an existing directory's descriptor unchanged.
// microsoft/referencesource mscorlib/system/io/{filestream,directory}.cs.
const CREATE_PRIVATE_OBJECT = [
  "$ErrorActionPreference='Stop'; Import-Module Microsoft.PowerShell.Utility, Microsoft.PowerShell.Security;",
  '[Console]::InputEncoding=[Text.UTF8Encoding]::new($false); $request=ConvertFrom-Json ([Console]::In.ReadToEnd()); $path=$request.path;',
  "$file=$request.operation -eq 'create-empty-file'; if (!$file -and $request.operation -ne 'create-directory') { throw 'invalid creation operation' };",
  "$parent=[IO.Path]::GetDirectoryName($path); if (![IO.Directory]::Exists($parent) -or ([IO.File]::GetAttributes($parent) -band [IO.FileAttributes]::ReparsePoint)) { throw 'invalid creation parent' };",
  '$user=[Security.Principal.WindowsIdentity]::GetCurrent().User; $flags=if ($file) { [Security.AccessControl.InheritanceFlags]::None } else { [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit };',
  '$security=if ($file) { [Security.AccessControl.FileSecurity]::new() } else { [Security.AccessControl.DirectorySecurity]::new() };',
  '$security.SetOwner($user); $security.SetAccessRuleProtection($true,$false); $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user,[Security.AccessControl.FileSystemRights]::FullControl,$flags,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow));',
  '$created=$true; $stream=$null; try {',
  'if ($file) { try { $stream=[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$security) } catch {',
  '$nativeError=$_.Exception; while ($nativeError.InnerException) { $nativeError=$nativeError.InnerException }; $code=$nativeError.HResult -band 65535;',
  `if ($nativeError -is [IO.IOException] -and ($code -eq 80 -or $code -eq 183) -and [IO.File]::Exists($path) -and !([IO.File]::GetAttributes($path) -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint))) { [Console]::Out.Write('{"created":false}'); return }; throw;`,
  "}; if ($stream.Length -ne 0 -or ([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint)) { throw 'invalid created file' }; $acl=$stream.GetAccessControl();",
  '} else { $created=![IO.Directory]::Exists($path); if ([IO.File]::Exists($path) -or ([IO.Directory]::Exists($path) -and ([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint))) { throw \'invalid created directory\' }; [IO.Directory]::CreateDirectory($path,$security) | Out-Null; $acl=[IO.Directory]::GetAccessControl($path) };',
  '$sddl=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access); $native=[Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0);',
  "$entries=[regex]::Matches($sddl,'\\([^()]*\\)'); if ($null -ne $native.DiscretionaryAcl -and $entries.Count -eq $native.DiscretionaryAcl.Count) { for ($index=$entries.Count-1; $index -ge 0; $index--) { $entry=$entries[$index]; $ace=$native.DiscretionaryAcl[$index]; $fields=$entry.Value.Substring(1,$entry.Length-2).Split(';'); if ($fields.Length -ne 6 -or $ace -isnot [Security.AccessControl.KnownAce]) { throw 'unsupported native access entry' }; $fields[5]=$ace.SecurityIdentifier.Value; $sddl=$sddl.Remove($entry.Index,$entry.Length).Insert($entry.Index,'('+($fields -join ';')+')') } };",
  '$answer=@{created=$created;ownerSid=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;sddl=$sddl}; if ($file) { $answer.length=$stream.Length }; ConvertTo-Json -Compress -InputObject $answer;',
  '} finally { if ($stream) { $stream.Dispose() } }',
].join(' ');

function createPrivateObject(path: string, kind: OwnerOnlyKind): boolean {
  if (!windows) throw new Error('owner-only: native creation is available on Windows only');
  if (typeof path !== 'string' || !win32.isAbsolute(path)) throw new Error('owner-only: an absolute creation path is required');
  const input = JSON.stringify({ operation: kind === 'file' ? 'create-empty-file' : 'create-directory', path });
  if (Buffer.byteLength(input, 'utf8') > 262_144) throw new Error('owner-only: native creation exceeds its input bound');
  const parent = win32.dirname(path);
  const beforeParent = lstatSync(parent, { throwIfNoEntry: false });
  const before = lstatSync(path, { throwIfNoEntry: false });
  if (beforeParent === undefined || !beforeParent.isDirectory() || beforeParent.isSymbolicLink()
    || (before !== undefined && (before.isSymbolicLink() || (kind === 'file' ? !before.isFile() : !before.isDirectory())))) {
    throw new Error('owner-only: invalid native creation path');
  }
  const sid = currentUserSid();
  const value: unknown = JSON.parse(run('WindowsPowerShell\\v1.0\\powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', CREATE_PRIVATE_OBJECT], input));
  const afterParent = lstatSync(parent, { throwIfNoEntry: false });
  const after = lstatSync(path, { throwIfNoEntry: false });
  if (afterParent === undefined || afterParent.isSymbolicLink() || !afterParent.isDirectory()
    || afterParent.dev !== beforeParent.dev || afterParent.ino !== beforeParent.ino
    || after === undefined || after.isSymbolicLink() || (kind === 'file' ? !after.isFile() : !after.isDirectory())
    || (before !== undefined && (after.dev !== before.dev || after.ino !== before.ino))) {
    throw new Error('owner-only: native creation path changed');
  }
  if (value === null || typeof value !== 'object' || !('created' in value) || typeof value.created !== 'boolean') {
    throw new Error('owner-only: invalid native creation result');
  }
  if (kind === 'file' && !value.created) return false;
  if (!('ownerSid' in value) || typeof value.ownerSid !== 'string' || !('sddl' in value) || typeof value.sddl !== 'string'
    || !isOwnerOnlySecurityDescriptor(value.sddl, value.ownerSid, sid, kind)
    || (kind === 'file' && (!('length' in value) || value.length !== 0 || after.size !== 0 || after.nlink !== 1 || before !== undefined))) {
    throw new Error('owner-only: invalid native creation security');
  }
  return value.created;
}

/** Creates an empty protected file with CreateNew, or reports an existing regular-file collision. */
export function createOwnerOnlyEmptyFile(path: string): boolean {
  return createPrivateObject(path, 'file');
}

/** Creates only the requested protected directory; an existing directory is inspected without mutation. */
export function createOwnerOnlyDirectory(path: string): void {
  createPrivateObject(path, 'directory');
}

// This operation opens only an existing file. The held handle admits its identity, owner and full
// DACL before changing permissions, then reads them back from that same handle. ReadWrite sharing
// and desired rights without DELETE keep an existing SQLite WAL/SHM connection usable.
// microsoft/referencesource mscorlib/system/io/filestream.cs: GetAccessControl / SetAccessControl.
const RESTRICT_CREATED_FILE = [
  "$ErrorActionPreference='Stop'; Import-Module Microsoft.PowerShell.Utility;",
  '[Console]::InputEncoding=[Text.UTF8Encoding]::new($false); $request=ConvertFrom-Json ([Console]::In.ReadToEnd());',
  "if ($request.operation -ne 'restrict-created-file') { throw 'invalid protection operation' };",
  '$identity=[Security.Principal.WindowsIdentity]::GetCurrent(); $user=$identity.User; $tokenOwner=$identity.Owner;',
  "if ($user.Value -ne $request.expectedUserSid -or ($tokenOwner.Value -ne $user.Value -and $tokenOwner.Value -ne 'S-1-5-32-544')) { throw 'unexpected native identity' };",
  // The fixed PowerShell engine already contains this native handle-information bridge. It avoids
  // runtime compilation and reports integer file IDs without a floating-point conversion.
  "$nativeType=[System.Management.Automation.PSObject].Assembly.GetType('Microsoft.PowerShell.Commands.InternalSymbolicLinkLinkCodeMethods'); $method=$nativeType.GetMethod('GetFileInformationByHandle',[Reflection.BindingFlags]'NonPublic,Public,Static'); $infoType=$method.GetParameters()[1].ParameterType.GetElementType();",
  'function ReadHeldIdentity($stream) { $arguments=[object[]]@($stream.SafeFileHandle.DangerousGetHandle(),[Activator]::CreateInstance($infoType));',
  "if (!$method.Invoke($null,$arguments)) { throw 'held identity query failed' }; $info=$arguments[1]; $culture=[Globalization.CultureInfo]::InvariantCulture;",
  "$device=$info.VolumeSerialNumber.ToString($culture); $hex=$info.FileIndexHigh.ToString('x8')+$info.FileIndexLow.ToString('x8'); $fileId=[UInt64]::Parse($hex,[Globalization.NumberStyles]::HexNumber,$culture).ToString($culture);",
  "if ($device -ne $request.expectedDevice -or $fileId -ne $request.expectedFileId -or $info.NumberOfLinks -ne 1 -or ($info.FileAttributes -band 1040)) { throw 'held identity or type changed' }; return @{device=$device;fileId=$fileId;links=$info.NumberOfLinks} };",
  'function ReadDacl($acl,$admit) { $sddl=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access); $raw=[Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0);',
  "$entries=[regex]::Matches($sddl,'\\([^()]*\\)'); if ($null -eq $raw.DiscretionaryAcl -or $entries.Count -ne $raw.DiscretionaryAcl.Count -or $sddl -notmatch '^D:[A-Z]*(?:\\([^()]*\\))*$') { throw 'invalid native access list' };",
  'for ($index=$entries.Count-1; $index -ge 0; $index--) { $entry=$entries[$index]; $ace=$raw.DiscretionaryAcl[$index];',
  "$fields=$entry.Value.Substring(1,$entry.Length-2).Split(';'); if ($fields.Length -ne 6 -or $ace -isnot [Security.AccessControl.KnownAce] -or $fields[0] -notin @('A','D','OA','OD')) { throw 'unsupported native access entry' }; $fields[5]=$ace.SecurityIdentifier.Value;",
  "if ($admit -and $fields[0] -in @('A','OA') -and $fields[5] -notin @($user.Value,'S-1-5-18','S-1-5-32-544')) { throw 'foreign native access grant' };",
  "$sddl=$sddl.Remove($entry.Index,$entry.Length).Insert($entry.Index,'('+($fields -join ';')+')') }; return $sddl };",
  '$rights=[Security.AccessControl.FileSystemRights]::ReadWrite -bor [Security.AccessControl.FileSystemRights]::ReadPermissions -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership -bor [Security.AccessControl.FileSystemRights]::Synchronize;',
  '$stream=$null; try { $stream=[IO.FileStream]::new($request.path,[IO.FileMode]::Open,$rights,[IO.FileShare]::ReadWrite,4096,[IO.FileOptions]::None,$null);',
  '$held=ReadHeldIdentity $stream; $acl=$stream.GetAccessControl(); $beforeOwner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;',
  "if ($beforeOwner -ne $user.Value -and $beforeOwner -ne $tokenOwner.Value) { throw 'foreign native owner' }; $beforeSddl=ReadDacl $acl $true;",
  '$acl.SetOwner($user); $acl.SetAccessRuleProtection($true,$false); $acl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow)); $stream.SetAccessControl($acl);',
  '$after=$stream.GetAccessControl(); $sddl=ReadDacl $after $true; $owner=$after.GetOwner([Security.Principal.SecurityIdentifier]).Value; $held=ReadHeldIdentity $stream;',
  "if ($owner -ne $user.Value -or $sddl -notmatch ('^D:[A-Z]*P[A-Z]*\\(A;;FA;;;' + [regex]::Escape($user.Value) + '\\)$')) { throw 'unexpected protected native access list' };",
  'ConvertTo-Json -Compress -InputObject @{userSid=$user.Value;tokenOwnerSid=$tokenOwner.Value;beforeOwnerSid=$beforeOwner;beforeSddl=$beforeSddl;device=$held.device;fileId=$held.fileId;links=$held.links;ownerSid=$owner;sddl=$sddl};',
  '} finally { if ($stream) { $stream.Dispose() } }',
].join(' ');

function admittedCreatedFileDacl(sddl: string, userSid: string): boolean {
  const dacl = /^D:[A-Z]*((?:\([^()]*\))*)$/.exec(sddl);
  if (dacl === null) return false;
  return [...(dacl[1] ?? '').matchAll(/\(([^()]*)\)/g)].every(entry => {
    const fields = (entry[1] ?? '').split(';');
    const [type, , , , , trustee] = fields;
    return fields.length === 6 && ['A', 'D', 'OA', 'OD'].includes(type ?? '')
      && canonicalSid(trustee ?? '') && (type === 'D' || type === 'OD'
        || trustee === userSid || trustee === 'S-1-5-18' || trustee === 'S-1-5-32-544');
  });
}

/** Protects an already-created, admitted file through its held native handle; never creates it. */
export function restrictOwnerOnlyCreatedFile(path: string, expectedUserSid: string): void {
  if (!windows || typeof path !== 'string' || !win32.isAbsolute(path) || path.includes('\0')
    || typeof expectedUserSid !== 'string' || !canonicalSid(expectedUserSid)) {
    throw new Error('owner-only: invalid created-file protection request');
  }
  const parent = win32.dirname(path);
  const beforeParent = lstatSync(parent, { bigint: true, throwIfNoEntry: false });
  const before = lstatSync(path, { bigint: true, throwIfNoEntry: false });
  if (beforeParent === undefined || !beforeParent.isDirectory() || beforeParent.isSymbolicLink()
    || before === undefined || !before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
    throw new Error('owner-only: invalid created-file protection path');
  }
  const input = JSON.stringify({ operation: 'restrict-created-file', path, expectedUserSid,
    expectedDevice: before.dev.toString(), expectedFileId: before.ino.toString() });
  if (Buffer.byteLength(input, 'utf8') > 262_144) throw new Error('owner-only: created-file protection exceeds its input bound');
  const value: unknown = JSON.parse(run('WindowsPowerShell\\v1.0\\powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', RESTRICT_CREATED_FILE], input));
  const afterParent = lstatSync(parent, { bigint: true, throwIfNoEntry: false });
  const after = lstatSync(path, { bigint: true, throwIfNoEntry: false });
  if (afterParent === undefined || afterParent.isSymbolicLink() || !afterParent.isDirectory()
    || afterParent.dev !== beforeParent.dev || afterParent.ino !== beforeParent.ino
    || after === undefined || after.isSymbolicLink() || !after.isFile() || after.nlink !== 1n
    || after.dev !== before.dev || after.ino !== before.ino) {
    throw new Error('owner-only: created-file protection path changed');
  }
  if (value === null || typeof value !== 'object'
    || !('userSid' in value) || value.userSid !== expectedUserSid
    || !('tokenOwnerSid' in value) || (value.tokenOwnerSid !== expectedUserSid && value.tokenOwnerSid !== 'S-1-5-32-544')
    || !('beforeOwnerSid' in value) || (value.beforeOwnerSid !== expectedUserSid && value.beforeOwnerSid !== value.tokenOwnerSid)
    || !('beforeSddl' in value) || typeof value.beforeSddl !== 'string' || !admittedCreatedFileDacl(value.beforeSddl, expectedUserSid)
    || !('device' in value) || value.device !== before.dev.toString()
    || !('fileId' in value) || value.fileId !== before.ino.toString() || !('links' in value) || value.links !== 1
    || !('ownerSid' in value) || typeof value.ownerSid !== 'string' || !('sddl' in value) || typeof value.sddl !== 'string'
    || !isOwnerOnlySecurityDescriptor(value.sddl, value.ownerSid, expectedUserSid, 'file')) {
    throw new Error('owner-only: invalid created-file protection read-back');
  }
}
