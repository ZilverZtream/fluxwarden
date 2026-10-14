import { createHash } from 'node:crypto';
import type { Secret } from '../core/secret.js';
import { createRedactor } from '../output/index.js';

/**
 * The evidence bundle (SPEC.md §14.2): nine files, each payload the canonical JSON of its redacted input, a
 * manifest with every payload's SHA-256, and `checksums.sha256` in sha256sum text format. Nothing from the
 * clock, randomness or the host enters a file, so identical inputs give identical bytes.
 */

export const BUNDLE_FILES: readonly string[] = [
  'chaos-results.json', 'checksums.sha256', 'execution-trace.ndjson', 'ledger-audit.json', 'manifest.json',
  'proposals.json', 'reconciliation.json', 'topology-after.json', 'topology-before.json',
];

/** `run_` and a ULID in Crockford base32. */
export const RUN_ID = /^run_[0-9A-HJKMNP-TV-Z]{26}$/;

export interface EvidenceNode {
  readonly name: string;
  readonly implementation: 'lnd' | 'cln';
  readonly pubkey: string;
  readonly version: string;
  readonly credentialFingerprint: string;
  readonly tlsFingerprint: string;
}

export interface EvidenceManifestInput {
  readonly runId: string;
  readonly command: string;
  readonly fluxwardenVersion: string;
  readonly gitCommit: string;
  readonly imageDigests: Readonly<Record<string, string>>;
  readonly nodes: readonly EvidenceNode[];
  readonly seeds: readonly number[];
  readonly policySha256: string;
  readonly approvalKeyIds: readonly string[];
  readonly chaosScenarioIds: readonly string[];
  readonly unavailableEvidence?: Readonly<Record<string, string>>;
}

/** JSON values; bigint allowed. */
export interface EvidenceInput {
  readonly manifest: EvidenceManifestInput;
  readonly topologyBefore: unknown;
  readonly topologyAfter: unknown;
  readonly proposals: unknown;
  readonly executionTrace: readonly unknown[];
  readonly ledgerAudit: unknown;
  readonly reconciliation: unknown;
  readonly chaosResults: unknown;
}

/** Members never copied into a bundle: preimages under any spelling, and payment secrets. */
const PRIVATE_FIELD = /preimage|payment_?(?:addr|secret)/i;
const PREIMAGE_FIELD = /preimage/i;
const HEX_64 = /^[0-9a-fA-F]{64}$/;
const BASE64_32 = /^[A-Za-z0-9+/_-]{43}=?$/;
/**
 * A 32-byte value (64 hex, or base64 as LND's REST gateway renders bytes) after a preimage or payment secret
 * name inside text, such as a raw node response kept as a string.
 */
const PRIVATE_IN_TEXT = /((?:preimage|payment_?(?:addr|secret))[A-Za-z0-9_]*\\?["']?\s*[:=]\s*\\?["']?)(?:[0-9a-fA-F]{64}(?![0-9a-fA-F])|[A-Za-z0-9+/_-]{43}=?(?![A-Za-z0-9+/_=-]))/gi;

const sha256 = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

/** The 32 bytes of a hex or base64 value, or null. */
export function bytes32(value: string): Buffer | null {
  if (HEX_64.test(value)) return Buffer.from(value, 'hex');
  if (BASE64_32.test(value)) {
    const decoded = Buffer.from(value, 'base64url');
    return decoded.length === 32 ? decoded : null;
  }
  return null;
}

/** Whether the removed preimage hashes to the payment hash; anything that is not 32 bytes does not. */
function preimageMatches(preimage: unknown, paymentHash: string): boolean {
  const bytes = typeof preimage === 'string' ? bytes32(preimage) : null;
  return bytes !== null && sha256(bytes) === paymentHash.toLowerCase();
}

function cleanText(text: string, redact: (text: string) => string): string {
  return redact(text.replace(PRIVATE_IN_TEXT, '$1[redacted]'));
}

/**
 * A redacted copy: every key and string through the redactor, bigint as decimal text, preimage and payment
 * secret members removed, a preimage replaced by `preimage_sha256_matches_hash` next to a 64-hex
 * `payment_hash` (ARCHITECTURE.md §9.4). Values JSON cannot hold (undefined, functions, symbols) are left out
 * as JSON.stringify leaves them out.
 */
function sanitize(value: unknown, redact: (text: string) => string): unknown {
  if (typeof value === 'string') return cleanText(value, redact);
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (value === null || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.map((item: unknown) => sanitize(item, redact) ?? null);
  if (typeof value !== 'object') return undefined;
  const source = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  let removed: { value: unknown } | null = null;
  for (const [key, item] of Object.entries(source)) {
    if (PRIVATE_FIELD.test(key)) {
      if (PREIMAGE_FIELD.test(key)) removed ??= { value: item };
      continue;
    }
    const clean = sanitize(item, redact);
    if (clean !== undefined) out[cleanText(key, redact)] = clean;
  }
  const paymentHash = source['payment_hash'];
  if (removed !== null && typeof paymentHash === 'string' && HEX_64.test(paymentHash)) {
    out['preimage_sha256_matches_hash'] = preimageMatches(removed.value, paymentHash);
  }
  return out;
}

/**
 * Whether the text holds a preimage of a payment hash it also holds: a 32-byte value (hex or base64) whose
 * SHA-256 is one of its 64-hex values. Preimages are not registered secrets, so this is their leak check.
 */
export function holdsPreimage(texts: readonly string[]): boolean {
  const hashes = new Set<string>();
  const candidates: Buffer[] = [];
  for (const text of texts) {
    for (const match of text.matchAll(/[0-9a-fA-F]{64}(?![0-9a-fA-F])|[A-Za-z0-9+/_-]{43}=?(?![A-Za-z0-9+/_=-])/g)) {
      const token = match[0];
      if (HEX_64.test(token)) hashes.add(token.toLowerCase());
      const bytes = bytes32(token);
      if (bytes !== null) candidates.push(bytes);
    }
  }
  return candidates.some(bytes => hashes.has(sha256(bytes)));
}

/** Keys sorted by UTF-16 code unit at every depth, array order kept, no whitespace. */
function canonicalText(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalText).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${canonicalText(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function canonicalLine(value: unknown, redact: (text: string) => string): Buffer {
  return Buffer.from(`${canonicalText(sanitize(value, redact) ?? null)}\n`, 'utf8');
}

/** The bundle as file name → bytes, all nine files. Throws for a run id that is not `run_<ULID>`. */
export function buildBundle(input: EvidenceInput, secrets: readonly Secret[]): Map<string, Buffer> {
  const m = input.manifest;
  if (!RUN_ID.test(m.runId)) throw new Error('evidence: the run id is not run_<ULID>');
  const redact = createRedactor(secrets);
  const payloads = new Map<string, Buffer>([
    ['chaos-results.json', canonicalLine(input.chaosResults, redact)],
    ['execution-trace.ndjson', Buffer.concat(input.executionTrace.map(item => canonicalLine(item, redact)))],
    ['ledger-audit.json', canonicalLine(input.ledgerAudit, redact)],
    ['proposals.json', canonicalLine(input.proposals, redact)],
    ['reconciliation.json', canonicalLine(input.reconciliation, redact)],
    ['topology-after.json', canonicalLine(input.topologyAfter, redact)],
    ['topology-before.json', canonicalLine(input.topologyBefore, redact)],
  ]);
  const manifest = canonicalLine({
    schema: 1, run_id: m.runId, command: m.command, fluxwarden_version: m.fluxwardenVersion, git_commit: m.gitCommit,
    image_digests: m.imageDigests,
    ...(m.unavailableEvidence === undefined ? {} : { unavailable_evidence: m.unavailableEvidence }),
    nodes: m.nodes.map(node => ({
      name: node.name, implementation: node.implementation, pubkey: node.pubkey, version: node.version,
      credential_fingerprint: node.credentialFingerprint, tls_fingerprint: node.tlsFingerprint,
    })),
    seeds: m.seeds, policy_sha256: m.policySha256, approval_key_ids: m.approvalKeyIds, chaos_scenario_ids: m.chaosScenarioIds,
    files: [...payloads.keys()].sort().map(path => {
      const bytes = payloads.get(path) ?? Buffer.alloc(0);
      return { path, sha256: sha256(bytes), bytes: bytes.length };
    }),
  }, redact);
  const files = new Map(payloads).set('manifest.json', manifest);
  const checksums = [...files.keys()].sort().map(name => `${sha256(files.get(name) ?? Buffer.alloc(0))}  ${name}\n`).join('');
  files.set('checksums.sha256', Buffer.from(checksums, 'utf8'));
  return new Map([...files.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}
