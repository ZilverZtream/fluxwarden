/*
Interface: src/evidence/bundle.ts (pure apart from node:crypto), src/commands/evidence.ts (writes through src/output).

  src/evidence/bundle.ts — the evidence bundle of SPEC §14.2 / ARCHITECTURE §9.4
    export const BUNDLE_FILES: readonly string[] = ['chaos-results.json', 'checksums.sha256', 'execution-trace.ndjson',
      'ledger-audit.json', 'manifest.json', 'proposals.json', 'reconciliation.json', 'topology-after.json', 'topology-before.json'];
    export interface EvidenceManifestInput {
      runId: string;                         // /^run_[0-9A-HJKMNP-TV-Z]{26}$/ (ULID); anything else is refused
      command: string; fluxwardenVersion: string; gitCommit: string;
      imageDigests: Readonly<Record<string, string>>;
      nodes: readonly { name: string; implementation: 'lnd' | 'cln'; pubkey: string; version: string;
                        credentialFingerprint: string; tlsFingerprint: string }[];
      seeds: readonly number[]; policySha256: string; approvalKeyIds: readonly string[]; chaosScenarioIds: readonly string[];
    }
    export interface EvidenceInput {          // JSON values; bigint allowed
      manifest: EvidenceManifestInput;
      topologyBefore: unknown; topologyAfter: unknown; proposals: unknown;
      executionTrace: readonly unknown[]; ledgerAudit: unknown; reconciliation: unknown; chaosResults: unknown;
    }
    export function buildBundle(input: EvidenceInput, secrets: readonly Secret[]): Map<string, Buffer>;  // name → bytes, all 9 files

    Encoding ("canonical JSON"): object keys sorted by UTF-16 code unit order at every depth, array order kept, no
    whitespace, bigint as a decimal string, then "\n". Before encoding, a copy of the value is sanitised:
      - every string (keys and values) passes through the output redactor: each registered Secret's redact(), then
        the pattern classes (BOLT11, preimage fields; ARCHITECTURE §9.2);
      - preimages are removed by field semantics, whatever the spelling and encoding (INV-11, SPEC §12.2): an object
        member whose case-folded name contains `preimage` (preimage, r_preimage, payment_preimage, paymentPreimage, ...)
        is removed; when that object has a `payment_hash` of 64 hex (either case), the member
        `preimage_sha256_matches_hash: boolean` (SHA-256 of the removed hex preimage equals payment_hash, compared
        case-insensitively) is added (ARCHITECTURE §9.4). Inside string values (raw node answers kept as text), the
        value after a key whose name contains `preimage` in JSON (`"r_preimage":"<v>"`) or key=value form is replaced
        by `[redacted]`, whether it is hex or base64.
    topology-before.json, topology-after.json, proposals.json, ledger-audit.json, reconciliation.json and
    chaos-results.json are the canonical JSON of the matching input field. execution-trace.ndjson holds one canonical
    JSON line per trace element (an empty trace is an empty file).
    manifest.json is the canonical JSON of
      { schema: 1, run_id, command, fluxwarden_version, git_commit, image_digests,
        nodes: [{ name, implementation, pubkey, version, credential_fingerprint, tls_fingerprint }],
        seeds, policy_sha256, approval_key_ids, chaos_scenario_ids,
        files: [{ path, sha256, bytes }] }        // the seven payload files above, sorted by path; sha256 lowercase hex
    checksums.sha256 lists the other eight files (payloads and manifest.json) sorted by name, one line each in
    sha256sum text format: `<64 lowercase hex>  <name>\n`.
    No wall clock, random value or host path enters any file: identical inputs give identical bytes.

  src/commands/evidence.ts (SPEC §10.3 EV1–EV3)
    export function exportEvidence(input: EvidenceInput, options: { outDir: string; secrets: readonly Secret[] }):
      Promise<{ exitCode: 0 | 2 | 8; files: string[] }>;       // files: names written, sorted; [] unless exit 0
    - an invalid run id, or an outDir that exists and is not empty → exit 2; nothing is created or changed.
      An outDir, or its parent, that is a symbolic link or junction → exit 2; neither it nor its target is changed.
    - every failure is a rejection of the returned promise, never a synchronous throw; the staging directory is
      removed on every failure path.
    - the bundle is written into a fresh temporary directory beside outDir (same parent), the leak check of SPEC
      §12.2 runs over it for every registered Secret in every encoding it supports; a hit deletes the temporary
      directory and exits 8 (outDir is not created). Otherwise the directory is renamed to outDir; exit 0.
      Nothing else is left in the parent directory.

  src/core/secret.ts (existing) — the leak check's per-secret test used by EV2
    Secret.foundIn(data: Uint8Array): boolean    // true when data holds the credential: raw bytes, UTF-16LE/BE bytes,
      // any form redact() rewrites, also after JSON string escapes (\uXXXX) are decoded and after whitespace is
      // removed (split and wrapped forms), and case-folded base64/base32 (SPEC §12.2). Never true for a part of it.
*/
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { unlinkFixture } from '../helpers/fixture-links.js';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadSource } from '../helpers/adapter-interfaces.js';
import { repoRoot } from '../helpers/cli.js';
import { sentinels } from '../helpers/output.js';

interface SecretValue { toString(): string }
type SecretClass = new (bytes: Uint8Array) => SecretValue;
interface ManifestInput {
  runId: string; command: string; fluxwardenVersion: string; gitCommit: string; imageDigests: Record<string, string>;
  nodes: { name: string; implementation: 'lnd' | 'cln'; pubkey: string; version: string; credentialFingerprint: string; tlsFingerprint: string }[];
  seeds: number[]; policySha256: string; approvalKeyIds: string[]; chaosScenarioIds: string[];
}
interface EvidenceInput {
  manifest: ManifestInput; topologyBefore: unknown; topologyAfter: unknown; proposals: unknown;
  executionTrace: unknown[]; ledgerAudit: unknown; reconciliation: unknown; chaosResults: unknown;
}
interface BundleModule { BUNDLE_FILES: readonly string[]; buildBundle: (input: EvidenceInput, secrets: readonly SecretValue[]) => Map<string, Buffer> }
interface EvidenceCommand { exportEvidence: (input: EvidenceInput, options: { outDir: string; secrets: readonly SecretValue[] }) => Promise<{ exitCode: number; files: string[] }> }
interface FoundIn { foundIn: (data: Uint8Array) => boolean }
interface Scanner { findLeaks(options: { sentinels: string; root: string; paths: string[] }): { path: string; encoding: string } | null }

const FILES = ['chaos-results.json', 'checksums.sha256', 'execution-trace.ndjson', 'ledger-audit.json', 'manifest.json',
  'proposals.json', 'reconciliation.json', 'topology-after.json', 'topology-before.json'];
const PAYLOADS: readonly [string, keyof EvidenceInput][] = [
  ['chaos-results.json', 'chaosResults'], ['ledger-audit.json', 'ledgerAudit'], ['proposals.json', 'proposals'],
  ['reconciliation.json', 'reconciliation'], ['topology-after.json', 'topologyAfter'], ['topology-before.json', 'topologyBefore'],
];
const RUN_ID = 'run_01K7ZQ8M3V6W9X2Y4Z5A7B8C9D';
const HASH = 'ab'.repeat(32);

const command = (): Promise<EvidenceCommand> => loadSource<EvidenceCommand>('commands/evidence.ts');
const bundle = (): Promise<BundleModule> => loadSource<BundleModule>('evidence/bundle.ts');
const secretClass = async (): Promise<SecretClass> => (await loadSource<{ Secret: SecretClass }>('core/secret.ts')).Secret;

/** Independent canonical JSON (the Interface's encoding), for expected bytes. */
function canonical(value: unknown): string {
  if (typeof value === 'bigint') return JSON.stringify(value.toString());
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${canonical(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
const sha256 = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');

function parent(prefix: string): string {
  return mkdtempSync(join(process.env['FLUXWARDEN_TEST_TMP'] ?? tmpdir(), `fw-cp039-${prefix}-`));
}

function input(): EvidenceInput {
  return {
    manifest: {
      runId: RUN_ID, command: 'lab chaos T-05', fluxwardenVersion: '0.1.0', gitCommit: 'c0ffee1'.padEnd(40, '0'),
      imageDigests: { lnd: `sha256:${'1a'.repeat(32)}`, cln: `sha256:${'2b'.repeat(32)}`, bitcoind: `sha256:${'3c'.repeat(32)}` },
      nodes: [
        { name: 'cln-m', implementation: 'cln', pubkey: `03${'d4'.repeat(32)}`, version: 'v26.06.9', credentialFingerprint: `fp:${'0a'.repeat(8)}`, tlsFingerprint: `fp:${'0b'.repeat(8)}` },
        { name: 'lnd-r', implementation: 'lnd', pubkey: `02${'e5'.repeat(32)}`, version: '0.21.4-beta', credentialFingerprint: `fp:${'0c'.repeat(8)}`, tlsFingerprint: `fp:${'0d'.repeat(8)}` },
      ],
      seeds: [42, 7], policySha256: 'cd'.repeat(32), approvalKeyIds: ['operator-1'], chaosScenarioIds: ['T-05'],
    },
    topologyBefore: { nodes: { 'cln-m': { channels: [{ scid: '812x1x0', local_msat: 1_250_000_000n, confidence: 'NODE_REPORTED' }] } } },
    topologyAfter: { nodes: { 'cln-m': { channels: [{ scid: '812x1x0', local_msat: 1_149_797_899n, confidence: 'NODE_REPORTED' }] } } },
    proposals: [{ id: 'prop_01K7ZQ8M3V6W9X2Y4Z5A7B8C9E', principal_msat: 100_000_000n, fee_msat: 202_101n, digest: 'ef'.repeat(32), refusals: [] }],
    executionTrace: [
      { execution_id: 'exec_01K7ZQ8M3V6W9X2Y4Z5A7B8C9F', fence_epoch: 1, from: 'CLAIMED', to: 'PREFLIGHT', at: 1_760_000_001_000 },
      { execution_id: 'exec_01K7ZQ8M3V6W9X2Y4Z5A7B8C9F', fence_epoch: 4, from: 'IN_FLIGHT', to: 'VERIFIED_SUCCESS', at: 1_760_000_009_000, evidence: { payment_hash: HASH, fee_msat: 202_101n } },
    ],
    ledgerAudit: { steps: { 'journal-balanced': 'compared', 'stored-balance': 'compared' }, balances: { 'expense:routing_fees': 202_101n } },
    reconciliation: { differences: [], nodes: [{ node: 'cln-m', status: 'compared' }] },
    chaosResults: [{ scenario: 'T-05', injection: 'drop clnrest during waitsendpay', assertions: ['exit 7', 'one payment for the hash'], pass: true }],
  };
}

function expectedManifest(value: EvidenceInput, payloads: ReadonlyMap<string, Buffer>): Buffer {
  const m = value.manifest;
  const doc = {
    schema: 1, run_id: m.runId, command: m.command, fluxwarden_version: m.fluxwardenVersion, git_commit: m.gitCommit,
    image_digests: m.imageDigests,
    nodes: m.nodes.map(node => ({
      name: node.name, implementation: node.implementation, pubkey: node.pubkey, version: node.version,
      credential_fingerprint: node.credentialFingerprint, tls_fingerprint: node.tlsFingerprint,
    })),
    seeds: m.seeds, policy_sha256: m.policySha256, approval_key_ids: m.approvalKeyIds, chaos_scenario_ids: m.chaosScenarioIds,
    files: [...payloads.keys()].sort().map(path => {
      const bytes = payloads.get(path) ?? Buffer.alloc(0);
      return { path, sha256: sha256(bytes), bytes: bytes.length };
    }),
  };
  return Buffer.from(`${canonical(doc)}\n`);
}

function readBundle(dir: string): Map<string, Buffer> {
  return new Map(readdirSync(dir).sort().map(name => [name, readFileSync(join(dir, name))]));
}

async function leakIn(dir: string): Promise<{ path: string; encoding: string } | null> {
  const scanner = await import(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href) as Scanner;
  return scanner.findLeaks({ sentinels: join(repoRoot, 'test/sentinels.json'), root: repoRoot, paths: [dir] });
}

function base32(bytes: Buffer): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, accumulator = 0, out = '';
  for (const byte of bytes) {
    accumulator = ((accumulator << 8) | byte) & 0xffff; bits += 8;
    while (bits >= 5) { bits -= 5; out += alphabet.charAt((accumulator >>> bits) & 31); }
  }
  if (bits > 0) out += alphabet.charAt((accumulator << (5 - bits)) & 31);
  return out;
}

describe('evidence export', () => {
  it('CP-039/B1 the bundle holds exactly the nine files, each payload its canonical JSON, the manifest with every field and file hash, and checksums that verify', async () => {
    const value = input();
    const root = parent('b1');
    const outDir = join(root, 'bundle');
    const { exportEvidence } = await command();
    const result = await exportEvidence(value, { outDir, secrets: [] });
    expect(result.exitCode).toBe(0);
    expect(result.files).toEqual(FILES);
    expect(readdirSync(root)).toEqual(['bundle']);
    const files = readBundle(outDir);
    expect([...files.keys()]).toEqual(FILES);

    const payloads = new Map<string, Buffer>();
    for (const [name, field] of PAYLOADS) payloads.set(name, Buffer.from(`${canonical(value[field])}\n`));
    payloads.set('execution-trace.ndjson', Buffer.from(value.executionTrace.map(line => `${canonical(line)}\n`).join('')));
    for (const [name, bytes] of payloads) expect(files.get(name)?.toString('utf8'), name).toBe(bytes.toString('utf8'));
    expect(files.get('manifest.json')?.toString('utf8')).toBe(expectedManifest(value, payloads).toString('utf8'));

    // sha256sum -c format: "<hex>  <name>", one line per file except itself, sorted.
    const lines = (files.get('checksums.sha256')?.toString('utf8') ?? '').split('\n');
    expect(lines.pop()).toBe('');
    expect(lines.map(line => line.slice(66))).toEqual(FILES.filter(name => name !== 'checksums.sha256'));
    for (const line of lines) {
      expect(line).toMatch(/^[0-9a-f]{64} {2}[a-z0-9.-]+$/);
      expect(line.slice(0, 64), line.slice(66)).toBe(sha256(files.get(line.slice(66)) ?? Buffer.alloc(0)));
    }
  });

  it('CP-039/B1 buildBundle names the same nine files as the export, in BUNDLE_FILES', async () => {
    const { BUNDLE_FILES, buildBundle } = await bundle();
    expect([...BUNDLE_FILES]).toEqual(FILES);
    expect([...buildBundle(input(), []).keys()].sort()).toEqual(FILES);
  });

  it('CP-039/B2 an out directory that exists and is not empty is refused with exit 2 and left untouched', async () => {
    const root = parent('b2');
    const outDir = join(root, 'bundle');
    mkdirSync(outDir);
    writeFileSync(join(outDir, 'keep.txt'), 'operator data\n');
    const { exportEvidence } = await command();
    const result = await exportEvidence(input(), { outDir, secrets: [] });
    expect(result).toEqual({ exitCode: 2, files: [] });
    expect(readdirSync(outDir)).toEqual(['keep.txt']);
    expect(readFileSync(join(outDir, 'keep.txt'), 'utf8')).toBe('operator data\n');
    expect(readdirSync(root)).toEqual(['bundle']);
  });

  it.each([['../run_01K7ZQ8M3V6W9X2Y4Z5A7B8C9D'], ['run_01K7ZQ8M3V6W9X2Y4Z5A7B8C9D/..'], ['run_short'], ['']])(
    'CP-039/B2 run id %j is refused with exit 2 and nothing is created', async runId => {
      const root = parent('b2-id');
      const outDir = join(root, 'bundle');
      const value = input();
      value.manifest.runId = runId;
      const { exportEvidence } = await command();
      expect(await exportEvidence(value, { outDir, secrets: [] })).toEqual({ exitCode: 2, files: [] });
      expect(readdirSync(root)).toEqual([]);
    });

  it('CP-039/B3 secrets planted in node output, approvals, errors and receipts never reach the bundle in any encoding; preimages become a hash-match flag', async () => {
    const Secret = await secretClass();
    const byKind = new Map(sentinels().map(row => [row.kind, row.bytes]));
    const macaroon = byKind.get('macaroon') ?? Buffer.alloc(0);
    const rune = byKind.get('rune') ?? Buffer.alloc(0);
    const tlsKey = byKind.get('tls-key') ?? Buffer.alloc(0);
    const approvalKey = byKind.get('ed25519-key') ?? Buffer.alloc(0);
    const preimage = byKind.get('preimage') ?? Buffer.alloc(0);
    const paymentHash = sha256(preimage);
    const value = input();
    value.topologyBefore = { raw: { lnd_listchannels: { request_headers: { 'Grpc-Metadata-macaroon': macaroon.toString('hex') } } } };
    value.proposals = [{ id: 'prop_1', approval: { key_id: 'operator-1', private_key: approvalKey.toString('base64') }, note: tlsKey.toString('utf8') }];
    value.executionTrace = [{
      execution_id: 'exec_1', to: 'VERIFIED_SUCCESS',
      evidence: { payment_hash: paymentHash, payment_preimage: preimage.toString('hex'), error: `rune rejected: ${rune.toString('utf8')}` },
    }];
    const root = parent('b3');
    const outDir = join(root, 'bundle');
    const { exportEvidence } = await command();
    const secrets = [macaroon, rune, tlsKey, approvalKey].map(bytes => new Secret(bytes));
    const result = await exportEvidence(value, { outDir, secrets });
    expect(result.exitCode).toBe(0);
    expect(await leakIn(outDir)).toBeNull();
    const trace = readFileSync(join(outDir, 'execution-trace.ndjson'), 'utf8').trimEnd().split('\n');
    expect(trace).toHaveLength(1);
    const evidence = (JSON.parse(trace[0] ?? '{}') as { evidence: Record<string, unknown> }).evidence;
    expect(evidence['payment_hash']).toBe(paymentHash);
    expect(evidence['preimage_sha256_matches_hash']).toBe(true);
    expect('payment_preimage' in evidence).toBe(false);
    expect(String(evidence['error'])).toMatch(/^rune rejected: /);
  });

  it('CP-039/B3 a secret in an encoding the redactor does not rewrite is caught by the export leak check: exit 8 and no bundle, or a clean bundle', async () => {
    const Secret = await secretClass();
    const macaroon = sentinels().find(row => row.kind === 'macaroon')?.bytes ?? Buffer.alloc(0);
    const value = input();
    value.reconciliation = { differences: [], note: `credential dump ${base32(macaroon)}` };
    const root = parent('b3-leak');
    const outDir = join(root, 'bundle');
    const { exportEvidence } = await command();
    const result = await exportEvidence(value, { outDir, secrets: [new Secret(macaroon)] });
    if (result.exitCode === 8) {
      expect(result.files).toEqual([]);
      expect(existsSync(outDir)).toBe(false);
      expect(readdirSync(root)).toEqual([]);
    } else {
      expect(result.exitCode).toBe(0);
      expect(await leakIn(outDir)).toBeNull();
    }
  });

  it('CP-039/B4 identical inputs give byte-identical bundles, whatever the key order of the input objects or the time of export', async () => {
    const { exportEvidence } = await command();
    const root = parent('b4');
    const first = input();
    const permuted = input();
    permuted.topologyBefore = { nodes: { 'cln-m': { channels: [{ confidence: 'NODE_REPORTED', local_msat: 1_250_000_000n, scid: '812x1x0' }] } } };
    permuted.ledgerAudit = { balances: { 'expense:routing_fees': 202_101n }, steps: { 'stored-balance': 'compared', 'journal-balanced': 'compared' } };
    expect((await exportEvidence(first, { outDir: join(root, 'a'), secrets: [] })).exitCode).toBe(0);
    await new Promise(resolve => setTimeout(resolve, 25));
    expect((await exportEvidence(input(), { outDir: join(root, 'b'), secrets: [] })).exitCode).toBe(0);
    expect((await exportEvidence(permuted, { outDir: join(root, 'c'), secrets: [] })).exitCode).toBe(0);
    const a = readBundle(join(root, 'a'));
    for (const other of ['b', 'c']) {
      const b = readBundle(join(root, other));
      expect([...b.keys()]).toEqual(FILES);
      for (const name of FILES) expect(b.get(name)?.equals(a.get(name) ?? Buffer.alloc(0)), `${other}/${name}`).toBe(true);
    }
    const { buildBundle } = await bundle();
    const built = buildBundle(input(), []);
    for (const name of FILES) expect(built.get(name)?.equals(a.get(name) ?? Buffer.alloc(0)), `buildBundle ${name}`).toBe(true);
  });
});

describe('evidence export: preimages, keys, links and failures', () => {
  const sentinel = (kind: string): Buffer => sentinels().find(row => row.kind === kind)?.bytes ?? Buffer.alloc(0);

  function link(target: string, path: string): void {
    try { symlinkSync(target, path, 'junction'); } catch { symlinkSync(target, path, 'dir'); }
  }

  it('CP-039/B3 a preimage under any key spelling, or inside a raw node answer kept as text, never reaches the bundle in any encoding', async () => {
    const preimage = sentinel('preimage');
    const hash = sha256(preimage);
    const value = input();
    value.executionTrace = [
      { step: 'track', evidence: { payment_hash: hash, paymentPreimage: preimage.toString('hex') } },
      { step: 'lookup', evidence: { payment_hash: hash, r_preimage: preimage.toString('base64') } },
      { step: 'list', evidence: { payment_hash: hash.toUpperCase(), preimage: preimage.toString('hex') } },
      { step: 'cln', evidence: { payment_hash: hash, payment_preimage: preimage.toString('hex').toUpperCase() } },
    ];
    // LND REST renders bytes fields (HTLCAttempt.preimage, Invoice.r_preimage) as base64 (lnrpc/lightning.proto).
    value.topologyBefore = {
      raw_lnd_payment: JSON.stringify({ payment_hash: hash, htlcs: [{ status: 'SUCCEEDED', preimage: preimage.toString('base64') }] }),
      raw_lnd_invoice: `{"r_hash":"${Buffer.from(hash, 'hex').toString('base64')}","r_preimage":"${preimage.toString('base64')}"}`,
      raw_cln_log: `sendpay complete payment_preimage=${preimage.toString('hex')} status=complete`,
    };
    const root = parent('b3-preimage');
    const outDir = join(root, 'bundle');
    const { exportEvidence } = await command();
    const result = await exportEvidence(value, { outDir, secrets: [] });
    expect(result.exitCode).toBe(0);
    expect(await leakIn(outDir)).toBeNull();
    const trace = readFileSync(join(outDir, 'execution-trace.ndjson'), 'utf8').trimEnd().split('\n')
      .map(line => (JSON.parse(line) as { evidence: Record<string, unknown> }).evidence);
    expect(trace).toHaveLength(4);
    expect(trace.map(evidence => Object.keys(evidence).filter(key => /preimage/i.test(key) && key !== 'preimage_sha256_matches_hash'))).toEqual([[], [], [], []]);
    expect(trace[0]?.['preimage_sha256_matches_hash']).toBe(true);
    expect(trace[2]?.['preimage_sha256_matches_hash']).toBe(true);
    expect(trace[3]?.['preimage_sha256_matches_hash']).toBe(true);
    expect(trace[0]?.['payment_hash']).toBe(hash);
    expect(readFileSync(join(outDir, 'topology-before.json'), 'utf8')).toContain('status=complete');
  });

  it('CP-039/B3 the hash-match flag compares the payment hash case-insensitively', async () => {
    const preimage = sentinel('preimage');
    const value = input();
    value.executionTrace = [{ evidence: { payment_hash: sha256(preimage).toUpperCase(), payment_preimage: preimage.toString('hex') } }];
    const root = parent('b3-case');
    const outDir = join(root, 'bundle');
    const { exportEvidence } = await command();
    expect((await exportEvidence(value, { outDir, secrets: [] })).exitCode).toBe(0);
    const line = readFileSync(join(outDir, 'execution-trace.ndjson'), 'utf8').trimEnd();
    expect((JSON.parse(line) as { evidence: Record<string, unknown> }).evidence['preimage_sha256_matches_hash']).toBe(true);
    expect(await leakIn(outDir)).toBeNull();
  });

  it('CP-039/B3 a registered secret used as an object key is redacted like any value (exit 0, clean bundle)', async () => {
    const Secret = await secretClass();
    const macaroon = sentinel('macaroon');
    const value = input();
    value.topologyAfter = { headers_seen: { [macaroon.toString('hex')]: 'Grpc-Metadata-macaroon' } };
    const root = parent('b3-key');
    const outDir = join(root, 'bundle');
    const { exportEvidence } = await command();
    const result = await exportEvidence(value, { outDir, secrets: [new Secret(macaroon)] });
    expect(result.exitCode).toBe(0);
    expect(await leakIn(outDir)).toBeNull();
    expect(readFileSync(join(outDir, 'topology-after.json'), 'utf8')).toContain('Grpc-Metadata-macaroon');
  });

  it('CP-039/B3 a credential wrapped over several lines is caught by the export leak check: exit 8 and no bundle, or a clean bundle', async () => {
    const Secret = await secretClass();
    const macaroon = sentinel('macaroon');
    const value = input();
    value.reconciliation = { differences: [], dump: (macaroon.toString('base64').match(/.{1,8}/g) ?? []).join('\n') };
    const root = parent('b3-wrapped');
    const outDir = join(root, 'bundle');
    const { exportEvidence } = await command();
    const result = await exportEvidence(value, { outDir, secrets: [new Secret(macaroon)] });
    if (result.exitCode === 8) {
      expect(existsSync(outDir)).toBe(false);
      expect(readdirSync(root)).toEqual([]);
    } else {
      expect(result.exitCode).toBe(0);
      expect(await leakIn(outDir)).toBeNull();
    }
  });

  it('CP-039/B3 the leak check finds a credential as UTF-16 bytes, wrapped or split text, and JSON-escaped text, never by a part of it', async () => {
    const Secret = await secretClass();
    const macaroon = sentinel('macaroon');
    const secret = new Secret(macaroon) as unknown as FoundIn;
    const utf16le = Buffer.from(macaroon.toString('latin1'), 'utf16le');
    const hex = macaroon.toString('hex');
    const forms: [string, Buffer][] = [
      ['utf16le', Buffer.concat([Buffer.from('<'), utf16le, Buffer.from('>')])],
      ['utf16be', Buffer.concat([Buffer.from('<'), Buffer.from(utf16le).swap16(), Buffer.from('>')])],
      ['wrapped-base64', Buffer.from(`dump: ${(macaroon.toString('base64').match(/.{1,8}/g) ?? []).join('\r\n')} end`)],
      ['split-hex', Buffer.from(`hex ${(hex.match(/.{1,8}/g) ?? []).join(' ')} end`)],
      ['json-escaped-hex', Buffer.from(`{"note":"${Array.from(Buffer.from(hex), code => `\\u00${code.toString(16)}`).join('')}"}`)],
    ];
    for (const [name, data] of forms) expect(secret.foundIn(data), name).toBe(true);
    expect(secret.foundIn(Buffer.from(hex.slice(0, -2))), 'a prefix').toBe(false);
    expect(secret.foundIn(macaroon.subarray(0, macaroon.length - 1)), 'a byte prefix').toBe(false);
  });

  it('CP-039/B2 an out directory that is a link (junction or symlink) to an empty directory is refused with exit 2 and its target untouched', async () => {
    const root = parent('b2-link');
    const target = join(root, 'target');
    mkdirSync(target);
    const outDir = join(root, 'out');
    link(target, outDir);
    try {
      const { exportEvidence } = await command();
      expect(await exportEvidence(input(), { outDir, secrets: [] })).toEqual({ exitCode: 2, files: [] });
      expect(readdirSync(target)).toEqual([]);
      expect(readdirSync(root).sort()).toEqual(['out', 'target']);
    } finally { unlinkFixture(outDir); }
  });

  it('CP-039/B2 an out directory whose parent is a link is refused with exit 2 and nothing is written through it', async () => {
    const root = parent('b2-parent-link');
    const real = join(root, 'real');
    mkdirSync(real);
    const linked = join(root, 'linked');
    link(real, linked);
    try {
      const { exportEvidence } = await command();
      expect(await exportEvidence(input(), { outDir: join(linked, 'bundle'), secrets: [] })).toEqual({ exitCode: 2, files: [] });
      expect(readdirSync(real)).toEqual([]);
    } finally { unlinkFixture(linked); }
  });

  it('CP-039/B2 a failure after staging rejects the returned promise (never a synchronous throw) and leaves nothing behind', async () => {
    const root = parent('b2-reject');
    const outDir = join(root, 'out');
    const failing = { redact: (text: string): string => text, redactionOverlap: 0, foundIn: (): boolean => { throw new Error('leak check failed'); }, toString: (): string => '[x]' };
    const { exportEvidence } = await command();
    let thrownSynchronously = false;
    let pending: Promise<unknown> = Promise.resolve();
    try {
      pending = exportEvidence(input(), { outDir, secrets: [failing] });
    } catch {
      thrownSynchronously = true;
    }
    expect(thrownSynchronously).toBe(false);
    await expect(pending).rejects.toThrow();
    expect(readdirSync(root)).toEqual([]);
  });
});
