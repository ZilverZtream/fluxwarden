/* SECURITY §5: evidence directories and files must be owner-only on Windows,
 * with protected DACLs. This exports only dummy public values into fresh task-owned
 * paths. The deliberately permissive destination parent contains no credentials.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { loadSource } from '../helpers/adapter-interfaces.js';
import { assertStrictWindowsOwnerOnly, readWindowsSecurity } from '../helpers/windows-security.js';

interface EvidenceCommand {
  exportEvidence: (input: {
    manifest: { runId: string; command: string; fluxwardenVersion: string; gitCommit: string;
      imageDigests: Record<string, string>; nodes: never[]; seeds: never[]; policySha256: string;
      approvalKeyIds: never[]; chaosScenarioIds: never[] };
    topologyBefore: never[]; topologyAfter: never[]; proposals: never[]; executionTrace: never[];
    ledgerAudit: { dummy: true }; reconciliation: { dummy: true }; chaosResults: never[];
  }, options: { outDir: string; secrets: never[] }) => Promise<{ exitCode: number; files: string[] }>;
}

it('PUB005/export an evidence export protects each new directory and file from permissive Windows inheritance', async () => {
  const own = mkdtempSync(join(process.env['FLUXWARDEN_TEST_TMP'] ?? tmpdir(), 'fw-pub005-'));
  const parent = join(own, 'dummy-shared-parent');
  if (process.platform === 'win32') {
    // DirectoryInfo.Create(DirectorySecurity) applies this descriptor at creation.
    // No pre-existing directory, parent ACL or product-owned object is changed.
    const script = `
      $ErrorActionPreference='Stop';
      $path=$env:FLUXWARDEN_PERMISSION_FIXTURE;
      if (Test-Path -LiteralPath $path) { throw 'fixture already exists' };
      $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User;
      $acl=[Security.AccessControl.DirectorySecurity]::new();
      $acl.SetOwner($owner); $acl.SetAccessRuleProtection($true,$false);
      $inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit';
      $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($owner,'FullControl',$inherit,'None','Allow'));
      $other=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545');
      $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($other,'ReadAndExecute',$inherit,'None','Allow'));
      [IO.DirectoryInfo]::new($path).Create($acl);
    `;
    const created = spawnSync('C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe',
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
      { encoding: 'utf8', windowsHide: true, shell: false, timeout: 10_000,
        env: { ...process.env, FLUXWARDEN_PERMISSION_FIXTURE: parent } });
    if (created.status !== 0) throw new Error(`dummy permission fixture creation failed: ${created.stderr}`);
  } else mkdirSync(parent, { mode: 0o755 });
  const before = process.platform === 'win32' ? readWindowsSecurity(parent) : null;
  if (before !== null) expect(before.trustees).toContain('S-1-5-32-545');
  const outDir = join(parent, 'dummy-evidence');
  const { exportEvidence } = await loadSource<EvidenceCommand>('commands/evidence.ts');
  const result = await exportEvidence({
    manifest: { runId: 'run_01K7ZQ8M3V6W9X2Y4Z5A7B8C9D', command: 'evidence export', fluxwardenVersion: '1.0.0',
      gitCommit: '0'.repeat(40), imageDigests: {}, nodes: [], seeds: [], policySha256: '0'.repeat(64), approvalKeyIds: [], chaosScenarioIds: [] },
    topologyBefore: [], topologyAfter: [], proposals: [], executionTrace: [], ledgerAudit: { dummy: true },
    reconciliation: { dummy: true }, chaosResults: [],
  }, { outDir, secrets: [] });
  expect(result.exitCode).toBe(0);
  expect(result.files).toHaveLength(9);
  expect(readdirSync(parent)).toEqual(['dummy-evidence']);
  if (process.platform === 'win32') {
    expect(readWindowsSecurity(parent)).toEqual(before);
    expect.soft(() => { assertStrictWindowsOwnerOnly(readWindowsSecurity(outDir), 'directory'); }).not.toThrow();
    for (const name of result.files) expect.soft(() => { assertStrictWindowsOwnerOnly(readWindowsSecurity(join(outDir, name)), 'file'); }, name).not.toThrow();
  } else {
    expect(statSync(outDir).mode & 0o077).toBe(0);
    for (const name of result.files) expect(statSync(join(outDir, name)).mode & 0o077, name).toBe(0);
  }
}, 30_000);
