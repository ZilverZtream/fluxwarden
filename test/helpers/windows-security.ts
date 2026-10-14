// Independent Windows oracle: read identities from the binary descriptor, never SDDL aliases.
import { spawnSync } from 'node:child_process';

export const WINDOWS_SECURITY_QUERY = `& {
  $ErrorActionPreference='Stop'
  $acl=Get-Acl -LiteralPath $env:FLUXWARDEN_ORACLE_PATH
  $raw=New-Object Security.AccessControl.RawSecurityDescriptor($acl.GetSecurityDescriptorBinaryForm(),0)
  $trustees=@(foreach ($ace in $raw.DiscretionaryAcl) {
    if ($ace -isnot [Security.AccessControl.KnownAce]) { throw 'Unknown DACL ACE' }
    $ace.SecurityIdentifier.Value
  })
  [pscustomobject]@{
    sddl=$acl.Sddl
    ownerSid=$raw.Owner.Value
    userSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    trustees=$trustees
  } | ConvertTo-Json -Compress
}`;

export interface WindowsSecurity {
  readonly sddl: string;
  readonly ownerSid: string;
  readonly userSid: string;
  readonly trustees: readonly string[];
}

/** Replace only identity fields; ACE type, flags, rights, GUIDs, order and DACL control stay intact. */
export function canonicalWindowsSddl(security: WindowsSecurity): string {
  const dacl = /D:([^]*?)(?=S:|$)/.exec(security.sddl);
  if (!dacl) throw new Error('No DACL in native descriptor');
  let index = 0;
  const canonical = dacl[0].replace(/\(([^()]*)\)/g, (_entry, body: string) => {
    const fields = body.split(';');
    const trustee = security.trustees[index++];
    if (fields.length < 6 || trustee === undefined || !/^S-1-\d+(?:-\d+)+$/.test(trustee)) throw new Error('Native ACE identity mismatch');
    fields[5] = trustee;
    return `(${fields.join(';')})`;
  });
  if (index !== security.trustees.length) throw new Error('Native ACE count mismatch');
  return security.sddl.replace(dacl[0], canonical).replace(/O:[^:]*?(?=[GDS]:|$)/, `O:${security.ownerSid}`);
}

export function readWindowsSecurity(path: string, env: NodeJS.ProcessEnv = process.env): WindowsSecurity {
  const run = spawnSync('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', WINDOWS_SECURITY_QUERY],
    { encoding: 'utf8', windowsHide: true, shell: false, timeout: 10000, env: { ...env, FLUXWARDEN_ORACLE_PATH: path } });
  if (run.status !== 0) throw new Error(`Native security query failed: ${run.stderr}`);
  const security = JSON.parse(run.stdout) as WindowsSecurity;
  return { ...security, sddl: canonicalWindowsSddl(security) };
}

/** SECURITY §5/D49/D55: current owner, protected DACL, exactly one full-control allow ACE. */
export function assertStrictWindowsOwnerOnly(security: WindowsSecurity, kind: 'file' | 'directory'): void {
  const dacl = /D:([^]*?)(?=S:|$)/.exec(security.sddl)?.[1];
  const flags = kind === 'directory' ? 'OICI' : '';
  if (security.ownerSid !== security.userSid || !/^S-1-\d+(?:-\d+)+$/.test(security.userSid)
    || (dacl !== `P(A;${flags};FA;;;${security.userSid})` && dacl !== `PAI(A;${flags};FA;;;${security.userSid})`)) {
    throw new Error(`Not current-owner-only: ${security.sddl}`);
  }
}
