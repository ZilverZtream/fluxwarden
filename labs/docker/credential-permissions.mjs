import { constants } from 'node:fs';
import { lstat, mkdir, open, unlink, appendFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { assertPrivateDirectory, assertPrivateDirectories, realDirectory } from '../../scripts/private-scratch.mjs';
import { runProcess } from './compose.mjs';

const fail = () => new Error('lab credentials permissions: failed');

// Owner SID/protected DACL construction follows ZilverZtream/macwarden
// scripts/private-scratch.mjs. File ACLs are checked on the exclusive open handle.
export function createCredentialPermissions(owner) {
  const roots = [owner.runtimeRoot, owner.sentinelRoot, owner.tmpRoot];
  const checkPath = path => {
    if (typeof path !== 'string' || !isAbsolute(path) || path.split(/[\\/]/).includes('..') || resolve(path) !== path || !roots.some(root => { const r = relative(root, path); return !r || !r.startsWith('..') && !isAbsolute(r); })) throw fail();
  };
  const windows = async (path, operation, bytes, parents) => {
    const encoded = Buffer.from(path, 'utf16le').toString('base64'), chain = Buffer.from(parents.join('|'), 'utf16le').toString('base64');
    const code = `$ErrorActionPreference='Stop'; try { $path=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('${encoded}')); $user=[Security.Principal.WindowsIdentity]::GetCurrent().User; foreach($parent in [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('${chain}')).Split([char]0x7C)){ $parentAcl=[IO.DirectoryInfo]::new($parent).GetAccessControl(); $parentRules=@($parentAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])); if($parentAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $user.Value -or !($parentRules | Where-Object {$_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -eq $user.Value}) -or ($parentRules | Where-Object {$_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -ne $user.Value})){throw 'parent'} }; $directory=${operation === 'directory' ? '$true' : '$false'}; $acl=if($directory){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}; $acl.SetOwner($user); $acl.SetAccessRuleProtection($true,$false); $flags=if($directory){[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit}else{[Security.AccessControl.InheritanceFlags]::None}; $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user,[Security.AccessControl.FileSystemRights]::FullControl,$flags,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)); ${operation === 'directory' ? '[IO.Directory]::CreateDirectory($path,$acl) | Out-Null;' : `$stream=$null; try { ${operation === 'write' ? '$stream=[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$acl); $data=[Convert]::FromBase64String([Console]::In.ReadToEnd()); if($data.Length -lt 1 -or $data.Length -gt 65536){throw \'size\'}; $stream.Write($data,0,$data.Length); $stream.Flush();' : '$stream=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None);'} if(([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -or $stream.Length -lt 1 -or $stream.Length -gt 65536){throw 'type'}; $actual=$stream.GetAccessControl(); if(!$actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $user.Value){throw 'owner'}; $rules=@($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])); if(!($rules | Where-Object {$_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -eq $user.Value}) -or ($rules | Where-Object {$_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -ne $user.Value})){throw 'access'}; ${operation === 'read' ? '$data=[byte[]]::new($stream.Length); $offset=0; while($offset -lt $data.Length){$n=$stream.Read($data,$offset,$data.Length-$offset);if($n -eq 0){throw \'read\'};$offset+=$n}; [Console]::Out.Write([Convert]::ToBase64String($data));' : ''} } finally {if($stream){$stream.Dispose()}};`} } catch {exit 1}`;
    const system = globalThis.process.env.SystemRoot || 'C:\\Windows';
    const answer = await runProcess([join(system, 'System32/WindowsPowerShell/v1.0/powershell.exe'), '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(code, 'utf16le').toString('base64')], { env: { SystemRoot: system, TEMP: globalThis.process.env.TEMP, PATH: join(system, 'System32'), PSModulePath: join(system, 'System32/WindowsPowerShell/v1.0/Modules') }, timeoutMs: 30000, stdin: bytes?.toString('base64') });
    if (answer.exitCode !== 0) throw fail();
    return operation === 'read' ? Buffer.from(answer.stdout, 'base64') : undefined;
  };
  const parentChain = path => {
    let current = dirname(path);
    const root = roots.find(root => { const r = relative(root, current); return !r || !r.startsWith('..') && !isAbsolute(r); });
    if (!root) throw fail();
    const chain = [current];
    while (current !== root) { current = dirname(current); chain.push(current); }
    return chain;
  };
  const checkParents = async path => {
    await realDirectory(dirname(path));
    await assertPrivateDirectories(parentChain(path));
  };
  // On Windows every level up to the owner root is inspected freshly inside the same
  // PowerShell process as the file operation, between two identity observations.
  const guarded = async (path, operation, bytes) => {
    const chain = parentChain(path), before = [];
    for (const directory of chain) before.push(await realDirectory(directory));
    const result = await windows(path, operation, bytes, chain);
    for (const [index, directory] of chain.entries()) {
      const after = await realDirectory(directory);
      if (after.dev !== before[index].dev || after.ino !== before[index].ino) throw fail();
    }
    return result;
  };
  const ensureDirectory = async path => {
    checkPath(path);
    try { await assertPrivateDirectory(path); return; } catch (error) { try { await lstat(path); } catch (missing) { if (missing.code === 'ENOENT') { if (process.platform === 'win32') await guarded(path, 'directory'); else { await checkParents(path); await mkdir(path, { mode: 0o700 }); } await assertPrivateDirectory(path); return; } } throw error; }
  };
  const readChecked = async path => {
    checkPath(path);
    if (process.platform === 'win32') return guarded(path, 'read');
    await checkParents(path);
    const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const info = await file.stat();
      if (!info.isFile() || info.uid !== process.getuid() || (info.mode & 0o777) !== 0o600 || info.size < 1 || info.size > 65536) throw fail();
      const bounded = Buffer.alloc(65537); const { bytesRead } = await file.read(bounded, 0, bounded.length, 0);
      const bytes = bounded.subarray(0, bytesRead); const after = await file.stat();
      if (bytes.length !== info.size || after.size !== info.size || after.mtimeMs !== info.mtimeMs || after.ctimeMs !== info.ctimeMs) throw fail();
      return bytes;
    } finally { await file.close(); }
  };
  const port = { ensureDirectory, readChecked,
    writeExclusive: async (path, input) => {
      checkPath(path);
      const bytes = Buffer.from(input); if (!bytes.length || bytes.length > 65536) throw fail();
      if (process.platform === 'win32') await guarded(path, 'write', bytes);
      else {
        await checkParents(path);
        const file = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
        try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
      }
      const testTmp = process.env.FLUXWARDEN_TEST_TMP;
      if (testTmp) {
        await assertPrivateDirectory(testTmp);
        await appendFile(join(testTmp, 'declared-out.txt'), `${path}\n`, { mode: 0o600 });
      }
    },
    remove: async path => { checkPath(path); if (process.platform !== 'win32') await checkParents(path); try { const info = await lstat(path); if (!info.isFile() || info.isSymbolicLink()) throw fail(); await readChecked(path); await unlink(path); } catch (error) { if (error.code !== 'ENOENT') throw error; } },
  };
  return Object.fromEntries(Object.entries(port).map(([name, operation]) => [name, async (...args) => { try { return await operation(...args); } catch { throw fail(); } }]));
}
