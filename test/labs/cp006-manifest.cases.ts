import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { asRecord } from '../helpers/cli.js';
import { loadLab, options, owner } from '../helpers/cp006-lab.js';
import { imagePins, nodes, observedLab, services, topology } from '../helpers/cp006-observed.js';

/** Owner-only check of every path in one independent inspection (one PowerShell process on Windows). */
function privateFiles(paths: string[]): boolean[] {
  if (process.platform !== 'win32') return paths.map(path => { const info = statSync(path); return info.isFile() && info.uid === process.getuid?.() && (info.mode & 0o077) === 0; });
  if (!paths.every(path => statSync(path).isFile())) return paths.map(() => false);
  const encoded = Buffer.from(paths.join('\n'), 'utf16le').toString('base64');
  const code = `$ErrorActionPreference='Stop'; Import-Module Microsoft.PowerShell.Security,Microsoft.PowerShell.Utility; $paths=@(([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('${encoded}'))) -split [char]10); $id=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; ConvertTo-Json -Compress @(foreach ($p in $paths) { $a=Get-Acl -LiteralPath $p; $r=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])); [pscustomobject]@{sameOwner=($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $id); hasOwner=(@($r | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -eq $id }).Count -gt 0); broad=(@($r | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -ne $id }).Count -gt 0)} });`;
  const system = process.env['SystemRoot'] ?? 'C:\\Windows';
  const response = spawnSync(join(system, 'System32/WindowsPowerShell/v1.0/powershell.exe'), ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(code, 'utf16le').toString('base64')], { shell: false, windowsHide: true, encoding: 'utf8', timeout: 60000, env: { SystemRoot: system, TEMP: process.env['TEMP'], PATH: join(system, 'System32'), PSModulePath: join(system, 'System32/WindowsPowerShell/v1.0/Modules') } });
  if (response.status !== 0) throw new Error('independent private file ACL inspection failed');
  const rows: unknown = JSON.parse(response.stdout);
  if (!Array.isArray(rows) || rows.length !== paths.length) throw new Error('independent ACL inspection returned the wrong number of rows');
  return rows.map(row => { const acl = asRecord(row, 'independent file ACL'); return acl['sameOwner'] === true && acl['hasOwner'] === true && acl['broad'] === false; });
}

it('CP-006/B7 public manifest binds existing private copied files actual bytes identities pins topology and observed limits', async () => {
  // Host receipts contain only constant phase labels and monotonic durations, never owner paths or material.
  // An unfinished phase remains visible when the original case deadline fails; no failure or cleanup is intercepted.
  const began = performance.now();
  const beginPhase = (phase: string): (() => void) => {
    const start = performance.now();
    console.info(JSON.stringify({ case: 'CP-006/B7', phase, event: 'start', elapsedMs: Math.round(start - began), durationMs: 0 }));
    return () => {
      const end = performance.now();
      console.info(JSON.stringify({ case: 'CP-006/B7', phase, event: 'end', elapsedMs: Math.round(end - began), durationMs: Math.round(end - start) }));
    };
  };
  let finish = beginPhase('owner');
  const selected = await owner(); selected.resources = { cpus: 4, memoryBytes: 4294967296, pids: 1024 }; finish();
  finish = beginPhase('observed-fixture');
  const fake = observedLab(selected); finish();
  finish = beginPhase('options');
  const configured = await options(selected, fake.run); finish();
  configured.clock = fake.clock; configured.delay = fake.delay;
  finish = beginPhase('create-lab');
  const lab = (await loadLab()).createLab(configured); finish();
  finish = beginPhase('lab-up');
  await lab.up(); finish();
  try {
    finish = beginPhase('manifest-and-files');
    const path = join(selected.runtimeRoot, 'lab.json'), raw = readFileSync(path, 'utf8');
    const manifest = asRecord(JSON.parse(raw) as unknown, 'public owner manifest');
    expect(manifest['version']).toBe(1); expect(manifest['ownerId']).toBe(selected.id); expect(manifest['project']).toBe(selected.project);
    expect(manifest['ports']).toEqual(selected.ports); expect(manifest['topology']).toEqual(topology);
    expect(typeof manifest['height'] === 'string' && /^(?:0|[1-9]\d*)$/.test(manifest['height']) && BigInt(manifest['height']) >= 113n).toBe(true);
    const images = asRecord(manifest['images'], 'actual pinned images');
    for (const kind of ['bitcoind', 'lnd', 'cln', 'toxiproxy']) {
      const record = asRecord(images[kind], 'manifest image');
      const service = kind === 'lnd' ? 'lnd-p' : kind === 'cln' ? 'cln-p' : kind;
      expect(record['reference']).toBe(imagePins[service]); expect(record['digest']).toBe(imagePins[service]?.split('@')[1]);
    }
    const records = asRecord(manifest['nodes'], 'node records'); expect(Object.keys(records).sort()).toEqual([...nodes].sort());
    let copied = 0;
    const targets: string[] = [];
    for (const node of nodes) {
      const record = asRecord(records[node], 'manifest node');
      expect(record['kind']).toBe(node.startsWith('lnd-') ? 'lnd' : 'cln'); expect(record['network']).toBe('regtest');
      expect(record['version']).toBe(node.startsWith('lnd-') ? '0.21.4-beta' : 'v26.06.9'); expect(record['pubkey']).toBe(fake.pubkeys[node]);
      for (const kind of ['certificate', 'credential']) {
        if (record[kind] === undefined) continue;
        const file = asRecord(record[kind], 'manifest file reference'), target = file['path'];
        if (typeof target !== 'string' || !isAbsolute(target)) throw new Error('manifest file needs absolute canonical path');
        const inside = relative(resolve(selected.runtimeRoot), resolve(target));
        expect(inside.length > 0 && !inside.startsWith('..') && !isAbsolute(inside), 'file belongs to this runtime owner').toBe(true);
        expect(realpathSync(target).toLowerCase()).toBe(resolve(target).toLowerCase());
        targets.push(target);
        expect(fake.privateFiles.has(target), 'path came from ordinary Docker copy').toBe(true);
        const bytes = readFileSync(target);
        expect(typeof file['sha256'] === 'string' && /^[a-f0-9]{64}$/.test(file['sha256'])).toBe(true);
        expect(file['sha256'] === createHash('sha256').update(bytes).digest('hex'), 'fingerprint independently matches existing bytes').toBe(true);
        const b64 = bytes.toString('base64'), url = bytes.toString('base64url');
        expect([bytes.toString('utf8'), bytes.toString('latin1'), bytes.toString('hex'), bytes.toString('hex').toUpperCase(), b64, b64.replace(/=+$/, ''), url, url + '='.repeat((4 - url.length % 4) % 4)].every(value => !value || !raw.includes(value)), 'no raw file material enters manifest').toBe(true);
        copied += 1;
      }
    }
    finish();
    finish = beginPhase('directory-permissions');
    for (const directory of new Set(targets.map(target => dirname(target)))) await configured.permissions.assert(directory);
    finish();
    finish = beginPhase('independent-file-acl');
    expect(privateFiles(targets), 'actual files are owner-only').toEqual(targets.map(() => true));
    finish();
    finish = beginPhase('resource-and-copy-oracles');
    expect(copied, 'present disposable bootstrap files are represented').toBeGreaterThan(0);
    expect(copied).toBe(fake.privateFiles.size);
    const resources = asRecord(manifest['resources'], 'public resource allocation');
    expect(resources['declared']).toEqual(selected.resources); expect(resources['effectiveWorkers']).toBe(1);
    const observed = resources['observed']; if (!Array.isArray(observed)) throw new Error('actual Docker resource observations required');
    expect(observed).toHaveLength(7);
    const allocation = observed.map(value => asRecord(value, 'actual allocated container'));
    expect(allocation.map(value => value['service']).sort()).toEqual([...services].sort());
    for (const resource of allocation) { expect(resource['containerId']).toBe(`${selected.project}-${String(resource['service'])}`); expect(resource['cpus']).toBe(0.5); expect(resource['memoryBytes']).toBe(536870912); expect(resource['pids']).toBe(128); }
    expect(fake.observations.some(row => row.method === 'inspect'), 'observations actually inspect Docker').toBe(true);
    finish();
  } finally {
    finish = beginPhase('lab-down');
    await lab.down(); finish();
  }
});
