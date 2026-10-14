import { mkdir, readFile, writeFile, rm, readdir, lstat, realpath, chmod, copyFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { promisify } from 'node:util';
import { isAbsolute, relative, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fail } from './readiness.mjs';
import { assertPrivateDirectory, realDirectory } from '../../scripts/private-scratch.mjs';

const execute = promisify(execFile);
const allocations = fileURLToPath(new URL('../.runtime/allocations', import.meta.url));
const rootsOf = owner => ['runtimeRoot', 'tmpRoot', 'sentinelRoot', 'evidenceRoot'].map(key => owner[key]);
const canonical = path => process.platform === 'win32' ? resolve(path).toLowerCase() : resolve(path);
const contains = (a, b) => { const path = relative(canonical(a), canonical(b)); return !path || (!path.startsWith('..') && !isAbsolute(path)); };

export function validateOwner(owner) {
  if (!owner || owner.version !== 1 || typeof owner.id !== 'string' || !/^[a-zA-Z0-9-]+$/.test(owner.id) ||
      typeof owner.project !== 'string' || !/^fluxwarden-lab-[a-z0-9-]+$/.test(owner.project)) throw fail('owner');
  const roots = rootsOf(owner);
  if (roots.some(path => typeof path !== 'string' || !isAbsolute(path))) throw fail('owner-roots');
  for (let i = 0; i < roots.length; i++) for (let j = i + 1; j < roots.length; j++) {
    if (contains(roots[i], roots[j]) || contains(roots[j], roots[i])) throw fail('owner-roots');
  }
  const ports = ['lndRest', 'clnRest', 'toxiproxy'].map(key => owner.ports?.[key]);
  if (ports.some(port => !Number.isInteger(port) || port < 1024 || port > 65535) || new Set(ports).size !== 3) throw fail('owner-ports');
  for (const [key, limit] of [['cpus', 4], ['memoryBytes', 4294967296], ['pids', 1024]]) {
    const value = owner.resources?.[key];
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0 || value > limit || (key !== 'cpus' && !Number.isSafeInteger(value))) throw fail('owner-resources');
  }
  if (owner.resources.cpus < 0.000007 || owner.resources.memoryBytes < 7 || owner.resources.pids < 7) throw fail('owner-resources');
  return structuredClone(owner);
}

// Uses the same owner SID/DACL technique as scripts/private-scratch.mjs, adapted from
// ZilverZtream/macwarden@25bbfa4 scripts/private-scratch.mjs. Only newly owned paths are restricted.
export async function protectCreated(paths, { copies = [], privateDirectories = [] } = {}) {
  if (copies.some(copy => !paths.includes(copy.source) || !isAbsolute(copy.target))) throw fail('permissions');
  const before = [];
  for (const directory of privateDirectories) before.push(await realDirectory(directory));
  if (process.platform !== 'win32') {
    for (const directory of privateDirectories) await assertPrivateDirectory(directory);
    for (const path of paths) { const info = await lstat(path); if (info.isSymbolicLink()) throw fail('permissions'); await chmod(path, info.isDirectory() ? 0o700 : 0o600); }
    for (const copy of copies) {
      const source = await lstat(copy.source);
      if (!source.isFile() || source.isSymbolicLink() || source.size < 1 || source.size > 65536) throw fail('permissions');
      await copyFile(copy.source, copy.target, constants.COPYFILE_EXCL);
      await chmod(copy.target, 0o600);
    }
    for (const [index, directory] of privateDirectories.entries()) {
      await assertPrivateDirectory(directory);
      const after = await realDirectory(directory);
      if (after.dev !== before[index].dev || after.ino !== before[index].ino) throw fail('permissions');
    }
    return;
  }
  const encoded = Buffer.from(JSON.stringify({ paths, copies, privateDirectories }), 'utf16le').toString('base64');
  const code = `$ErrorActionPreference='Stop'; Import-Module Microsoft.PowerShell.Utility,Microsoft.PowerShell.Security,Microsoft.PowerShell.Management; $request=ConvertFrom-Json ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('${encoded}'))); $user=[Security.Principal.WindowsIdentity]::GetCurrent().User; function Assert-Directories { foreach($directory in $request.privateDirectories) { $actual=[IO.DirectoryInfo]::new($directory).GetAccessControl(); $rules=@($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])); if($actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $user.Value -or !($rules | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -eq $user.Value }) -or ($rules | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -ne $user.Value })) { throw 'unsafe private directory'; } } }; function Protect-Path($path) { $item=Get-Item -LiteralPath $path; if($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'linked owned path'; } if($item.PSIsContainer) { $acl=[Security.AccessControl.DirectorySecurity]::new(); $flags=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit; } else { $acl=[Security.AccessControl.FileSecurity]::new(); $flags=[Security.AccessControl.InheritanceFlags]::None; } $acl.SetOwner($user); $acl.SetAccessRuleProtection($true,$false); $rule=[Security.AccessControl.FileSystemAccessRule]::new($user,[Security.AccessControl.FileSystemRights]::FullControl,$flags,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow); $acl.AddAccessRule($rule); Set-Acl -LiteralPath $path -AclObject $acl; $after=Get-Acl -LiteralPath $path; if(!$after.AreAccessRulesProtected -or $after.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $user.Value -or @($after.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -ne $user.Value }).Count -gt 0) { throw 'unsafe owned path'; } }; Assert-Directories; foreach($path in $request.paths) { Protect-Path $path }; foreach($copy in $request.copies) { $source=[IO.FileInfo]::new($copy.source); if(!$source.Exists -or ($source.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $source.Length -lt 1 -or $source.Length -gt 65536) { throw 'unsafe copied file'; }; [IO.File]::Copy($copy.source,$copy.target,$false); Protect-Path $copy.target }; Assert-Directories;`;
  const system = process.env.SystemRoot || 'C:\\Windows';
  await execute(join(system, 'System32/WindowsPowerShell/v1.0/powershell.exe'),
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(code, 'utf16le').toString('base64')],
    { shell: false, windowsHide: true, timeout: 60000, maxBuffer: 16384,
      env: { SystemRoot: system, TEMP: process.env.TEMP, PATH: join(system, 'System32'), PSModulePath: join(system, 'System32/WindowsPowerShell/v1.0/Modules') } });
  for (const [index, directory] of privateDirectories.entries()) {
    const after = await realDirectory(directory);
    if (after.dev !== before[index].dev || after.ino !== before[index].ino) throw fail('permissions');
  }
}

async function registryLock(context, operation) {
  await mkdir(allocations, { recursive: true, mode: 0o700 });
  const lock = join(allocations, '.lock');
  for (;;) {
    try { await mkdir(lock, { mode: 0o700 }); break; }
    catch (error) { if (error.code !== 'EEXIST') throw fail('allocation'); }
    if (context.clock() >= context.deadline || context.signal?.aborted) throw fail('allocation-timeout');
    await context.delay(25, context.signal);
  }
  try { return await operation(); }
  finally { await rm(lock, { recursive: true }); }
}
export async function reserveOwner(owner, context) {
  await registryLock(context, async () => {
    const declarations = [];
    for (const name of await readdir(allocations)) if (name.endsWith('.json')) declarations.push(JSON.parse(await readFile(join(allocations, name), 'utf8')));
    for (const other of declarations) {
      if (other.project === owner.project || other.id === owner.id ||
          Object.values(other.ports).some(port => Object.values(owner.ports).includes(port)) ||
          rootsOf(other).some(a => rootsOf(owner).some(b => contains(a, b) || contains(b, a)))) throw fail('allocation-collision');
    }
    if (declarations.length >= 2) throw fail('allocation-owner-limit');
    for (const [key, maximum] of [['cpus', 8], ['memoryBytes', 8589934592], ['pids', 2048]]) {
      if (declarations.reduce((sum, item) => sum + item.resources[key], owner.resources[key]) > maximum) throw fail('allocation-budget');
    }
    await writeFile(join(allocations, `${owner.project}.json`), JSON.stringify(owner), { flag: 'wx', mode: 0o600 });
  });
}
export async function releaseOwner(owner, context) {
  await registryLock(context, async () => {
    const path = join(allocations, `${owner.project}.json`);
    let existing;
    try { existing = JSON.parse(await readFile(path, 'utf8')); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
    if (JSON.stringify(existing) !== JSON.stringify(owner)) throw fail('allocation-identity');
    await rm(path);
  });
}
export async function checkDeclaration(owner) {
  const path = join(allocations, `${owner.project}.json`);
  try {
    const value = JSON.parse(await readFile(path, 'utf8'));
    if (JSON.stringify(value) !== JSON.stringify(owner)) throw fail('allocation-identity');
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
}
export async function acquireWorker(owner) {
  await mkdir(allocations, { recursive: true, mode: 0o700 });
  const path = join(allocations, `${owner.project}.worker`);
  try { await mkdir(path, { mode: 0o700 }); }
  catch { throw fail('owner-busy'); }
  return async () => { await rm(path, { recursive: true }); };
}
export async function clearOwnedDirectory(path) {
  const root = await realpath(path);
  if (canonical(root) !== canonical(path) || (await lstat(path)).isSymbolicLink()) throw fail('cleanup-path');
  for (const name of await readdir(path)) {
    const target = resolve(path, name);
    if (!contains(path, target) || canonical(target) === canonical(path)) throw fail('cleanup-path');
    await rm(target, { recursive: true, force: true });
  }
}
