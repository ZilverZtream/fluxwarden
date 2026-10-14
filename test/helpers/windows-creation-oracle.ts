// Independent native oracle: compare every descriptor byte and inspect every DACL ACE.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';

export const WINDOWS_POWERSHELL = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const QUERY = `& {
  $ErrorActionPreference='Stop'
  $user=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $paths=ConvertFrom-Json $env:FLUXWARDEN_CREATION_ORACLE_PATHS
  $sha=[Security.Cryptography.SHA256]::Create()
  try {
    $results=@(foreach ($path in $paths) {
      $acl=Get-Acl -LiteralPath $path
      $bytes=$acl.GetSecurityDescriptorBinaryForm()
      $raw=New-Object Security.AccessControl.RawSecurityDescriptor($bytes,0)
      $rules=@(foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.KnownAce]) { throw 'Unknown DACL ACE' }
        [pscustomobject]@{
          currentUser=($ace.SecurityIdentifier.Value -eq $user)
          type=[int]$ace.AceType
          flags=[int]$ace.AceFlags
          mask=[int]$ace.AccessMask
        }
      })
      [pscustomobject]@{
        descriptorHash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()
        currentOwner=($raw.Owner.Value -eq $user)
        protected=[bool]($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
        rules=$rules
      }
    })
    ConvertTo-Json -Compress -Depth 5 -InputObject $results
  } finally { $sha.Dispose() }
}`;

export interface NativeCreationSecurity {
  readonly descriptorHash: string;
  readonly currentOwner: boolean;
  readonly protected: boolean;
  readonly rules: readonly { currentUser: boolean; type: number; flags: number; mask: number }[];
}

/** Read actual filesystem descriptors through Windows PowerShell 5; never print their contents. */
export function nativeCreationSecurity(paths: readonly string[]): NativeCreationSecurity[] {
  const run = spawnSync(WINDOWS_POWERSHELL, ['-NoProfile', '-NonInteractive', '-Command', QUERY], {
    encoding: 'utf8', windowsHide: true, shell: false, timeout: 10000, maxBuffer: 65536,
    env: { ...process.env, FLUXWARDEN_CREATION_ORACLE_PATHS: JSON.stringify(paths) },
  });
  if (run.status !== 0) throw new Error('Independent native creation query failed');
  const result = JSON.parse(run.stdout) as NativeCreationSecurity[];
  if (!Array.isArray(result) || result.length !== paths.length) throw new Error('Independent native query cardinality differs');
  return result;
}

/** Ignore access-time changes caused by the oracle's own reads. */
export function objectIdentity(path: string) {
  const stat = lstatSync(path, { bigint: true });
  return { dev: stat.dev, ino: stat.ino, birthtimeNs: stat.birthtimeNs, mtimeNs: stat.mtimeNs, ctimeNs: stat.ctimeNs,
    size: stat.size, links: stat.nlink, file: stat.isFile(), directory: stat.isDirectory(), link: stat.isSymbolicLink() };
}

export function ordinaryFileHash(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}
