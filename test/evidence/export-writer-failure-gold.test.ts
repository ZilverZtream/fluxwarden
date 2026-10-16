/*
 * SPEC 10.3 EV1/EV2 and SECURITY 5: partial evidence preparation never publishes
 * a failed bundle or removes pre-existing caller inputs, bytes or permissions.
 * Public file-writer ports:
 *   writeNewFile(path: string, bytes: Uint8Array): void
 *   writeNewFiles(files: ReadonlyMap<string, Uint8Array>): void
 * The ordinary fault model prepares one requested member through the real
 * single-file port, then raises an I/O failure or an existing-object refusal.
 * It accepts either sequential or batch creation without fixing member order.
 * No native object is replaced, no file permissions are changed, and an EEXIST
 * model does not claim to reproduce a native filesystem collision.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { basename, join, relative, resolve, sep } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { loadSource } from '../helpers/adapter-interfaces.js';
import { scratchDir } from '../helpers/cli.js';
import { descriptor, makeOwnerOnlyDir } from '../helpers/cp015-persistence.js';

interface EvidenceInput {
  manifest: { runId: string; command: string; fluxwardenVersion: string; gitCommit: string;
    imageDigests: Record<string, string>; nodes: never[]; seeds: number[]; policySha256: string;
    approvalKeyIds: string[]; chaosScenarioIds: string[] };
  topologyBefore: { label: string }; topologyAfter: { label: string }; proposals: never[];
  executionTrace: { phase: string; sequence: number }[]; ledgerAudit: { balanced: boolean };
  reconciliation: { differences: never[] }; chaosResults: never[];
}
interface EvidenceCommand { exportEvidence: (input: EvidenceInput, options: { outDir: string; secrets: never[] }) =>
  Promise<{ exitCode: number; files: string[] }> }
interface FileWriters {
  writeNewFile: (path: string, bytes: Uint8Array) => void;
  writeNewFiles: (files: ReadonlyMap<string, Uint8Array>) => void;
}
const FILES = ['chaos-results.json', 'checksums.sha256', 'execution-trace.ndjson', 'ledger-audit.json',
  'manifest.json', 'proposals.json', 'reconciliation.json', 'topology-after.json', 'topology-before.json'];
afterEach(() => { vi.restoreAllMocks(); });

function input(): EvidenceInput {
  return { manifest: { runId: 'run_01K7ZQ8M3V6W9X2Y4Z5A7B8C9D', command: 'evidence export', fluxwardenVersion: '1.0.0',
    gitCommit: '0'.repeat(40), imageDigests: {}, nodes: [], seeds: [7], policySha256: '0'.repeat(64),
    approvalKeyIds: [], chaosScenarioIds: [] },
  topologyBefore: { label: 'ordinary-before' }, topologyAfter: { label: 'ordinary-after' }, proposals: [],
  executionTrace: [{ phase: 'prepared', sequence: 1 }, { phase: 'finished', sequence: 2 }],
  ledgerAudit: { balanced: true }, reconciliation: { differences: [] }, chaosResults: [] };
}

function fixture() {
  const root = scratchDir('export-writer-failure'); makeOwnerOnlyDir(root);
  const inputPath = join(root, 'input.json'), notesPath = join(root, 'operator-notes.txt'), outDir = join(root, 'bundle');
  const inputBytes = Buffer.from(`${JSON.stringify(input())}\n`), notesBytes = Buffer.from('ordinary operator notes\n');
  writeFileSync(inputPath, inputBytes, { mode: 0o600 }); writeFileSync(notesPath, notesBytes, { mode: 0o600 });
  const permissions = new Map([root, inputPath, notesPath].map(path => [path, descriptor(path)]));
  const unchanged = () => {
    expect(readFileSync(inputPath).equals(inputBytes), 'caller evidence input bytes remain exact').toBe(true);
    expect(readFileSync(notesPath).equals(notesBytes), 'pre-existing sibling bytes remain exact').toBe(true);
    for (const [path, before] of permissions) expect(descriptor(path), 'pre-existing permissions remain exact').toBe(before);
  };
  return { root, outDir, unchanged, value: JSON.parse(inputBytes.toString('utf8')) as EvidenceInput };
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonical(entry)}`).join(',')}}`;
  return JSON.stringify(value);
}
const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
function expectedFiles(value: EvidenceInput): Map<string, Buffer> {
  // Literal payload bytes follow the published canonical-JSON and NDJSON encodings.
  const files = new Map<string, Buffer>([
    ['chaos-results.json', Buffer.from('[]\n')],
    ['execution-trace.ndjson', Buffer.from('{"phase":"prepared","sequence":1}\n{"phase":"finished","sequence":2}\n')],
    ['ledger-audit.json', Buffer.from('{"balanced":true}\n')],
    ['proposals.json', Buffer.from('[]\n')],
    ['reconciliation.json', Buffer.from('{"differences":[]}\n')],
    ['topology-after.json', Buffer.from('{"label":"ordinary-after"}\n')],
    ['topology-before.json', Buffer.from('{"label":"ordinary-before"}\n')],
  ]);
  files.set('manifest.json', Buffer.from(`${canonical({ schema: 1, run_id: value.manifest.runId,
    command: 'evidence export', fluxwarden_version: '1.0.0', git_commit: '0'.repeat(40), image_digests: {}, nodes: [], seeds: [7],
    policy_sha256: '0'.repeat(64), approval_key_ids: [], chaos_scenario_ids: [],
    files: [...files].map(([path, bytes]) => ({ path, sha256: hash(bytes), bytes: bytes.length })) })}\n`));
  files.set('checksums.sha256', Buffer.from([...files].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([path, bytes]) => `${hash(bytes)}  ${path}\n`).join('')));
  return files;
}

it('CP-039/REG-EXPORTIO successful ordinary export retains exact bytes and pre-existing inputs', async () => {
  const f = fixture(), { exportEvidence } = await loadSource<EvidenceCommand>('commands/evidence.ts');
  const result = await exportEvidence(f.value, { outDir: f.outDir, secrets: [] });
  expect(result).toEqual({ exitCode: 0, files: FILES });
  expect(readdirSync(f.outDir).sort()).toEqual(FILES);
  for (const [name, bytes] of expectedFiles(f.value)) {
    expect(readFileSync(join(f.outDir, name)).equals(bytes), `${name} has independently specified bytes`).toBe(true);
  }
  expect(readdirSync(f.root).sort()).toEqual(['bundle', 'input.json', 'operator-notes.txt']);
  f.unchanged();
});

for (const fault of ['EIO', 'EEXIST'] as const) {
  it(`CP-039/REG-EXPORTIO ${fault} after member preparation refuses publication and removes only owned staging`, async () => {
    const f = fixture(), writers = await loadSource<FileWriters>('output/files.ts');
    // A missing public batch port is an API-alignment gap, never a native failure observation.
    if (typeof writers.writeNewFiles !== 'function') throw new Error('API_ALIGNMENT_GAP: batch-file boundary is unavailable');
    const realSingle = writers.writeNewFile;
    const prepared: string[] = [];
    let faultRaised = false;
    const isMember = (path: string) => {
      const inside = relative(resolve(f.root), resolve(path));
      return inside !== '' && !inside.startsWith(`..${sep}`) && inside !== '..' && FILES.includes(basename(path));
    };
    const prepare = (path: string, bytes: Uint8Array) => {
      realSingle(path, bytes); prepared.push(path);
      expect(readFileSync(path).equals(Buffer.from(bytes)), 'an earlier ordinary member was genuinely prepared').toBe(true);
    };
    const refuse = (): never => {
      faultRaised = true;
      throw Object.assign(new Error('ordinary private file operation refused'), { code: fault });
    };
    vi.spyOn(writers, 'writeNewFile').mockImplementation((path, bytes) => {
      if (!isMember(path)) { realSingle(path, bytes); return; }
      if (prepared.length === 0) { prepare(path, bytes); return; }
      refuse();
    });
    vi.spyOn(writers, 'writeNewFiles').mockImplementation(files => {
      const first = [...files].find(([path]) => isMember(path));
      if (first === undefined) throw new Error('MODEL_INTERFACE_GAP: no ordinary bundle member in writer request');
      if (prepared.length === 0) prepare(first[0], first[1]);
      refuse();
    });
    const { exportEvidence } = await loadSource<EvidenceCommand>('commands/evidence.ts');
    const result = await exportEvidence(f.value, { outDir: f.outDir, secrets: [] }).then(
      value => ({ kind: 'returned' as const, value }), (error: unknown) => ({ kind: 'rejected' as const, error }));
    expect(prepared).toHaveLength(1);
    expect(faultRaised, 'the ordinary dependency fault was reached after preparation').toBe(true);
    if (result.kind === 'returned') {
      expect([2, 8]).toContain(result.value.exitCode);
      expect(result.value.files).toEqual([]);
    } else expect(result.error).toBeInstanceOf(Error);
    expect(existsSync(f.outDir), 'failed evidence is never published').toBe(false);
    expect(readdirSync(f.root).sort(), 'only the acquired staging is cleaned').toEqual(['input.json', 'operator-notes.txt']);
    f.unchanged();
  });
}
