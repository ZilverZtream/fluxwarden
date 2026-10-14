/*
Interface (src/approval/, pure apart from node:crypto; time and randomness are injected):
  interface ProposalTerms {               // the stored proposal fields the digest covers (SECURITY.md §4.1)
    id: string; nodePubkey: string; sourceChannelKey: string; targetChannelKey: string;
    principalMsat: Msat; maxFeeMsat: Msat; maxFeePpm: bigint; exemptFeeMsat: Msat; maxCltvDelta: number;
    policySha256: string;                 // 64 lowercase hex
    expiresAt: number;                    // ms since the Unix epoch
  }
  interface ApprovalPolicy { sha256: string; maxFeeMsat: Msat; maxCltvDelta: number; approvalMaxTtlSeconds: number; maxSnapshotAgeSeconds: number }
  interface ApprovalKey { keyId: string (32 hex); publicKey: string (base64 of the raw 32-byte Ed25519 key) }
  src/approval/message.ts
    export function proposalDigest(terms: ProposalTerms): Uint8Array;            // 32 bytes, SECURITY.md §4.1
    export function approvalMessage(fields: {
      proposalDigest: Uint8Array; policySha256: Uint8Array; approvedMaxFeeMsat: Msat;
      approvedMaxCltvDelta: number; expiresAt: number; nonce: Uint8Array; keyId: Uint8Array }): Uint8Array;
      Exactly the SECURITY.md §4.1 layout (155 bytes); throws on a wrong field length or a value outside its unsigned width.
  src/approval/keys.ts
    export function generateApprovalKeyPair(): { privateKey: Secret (PKCS#8 PEM bytes); publicKey: string; keyId: string };
  src/approval/sign.ts                    // the only module that reveals the private key, internally only
    export function writePrivateKeyFile(privateKey: Secret, path: string): 'written' | 'exists' | 'failed';
      Writes the key as a PKCS#8 PEM file, owner-only; returns no key bytes.
    export function createApproval(request: {
        proposal: ProposalTerms; policy: ApprovalPolicy; keys: readonly ApprovalKey[];
        approvedMaxFeeMsat?: Msat; approvedMaxCltvDelta?: number; expiresAt?: number; snapshotObservedAt: number },
      privateKey: Secret, deps: { now(): number; randomBytes(size: number): Uint8Array }): string;
      Returns the token JSON {v: 1, proposal_id, proposal_digest, policy_sha256, approved_max_fee_msat,
      approved_max_cltv_delta, expires_at, nonce, key_id, signature}: hex byte fields, caps as decimal
      strings, expires_at a JSON number (ms). Defaults: the proposal's caps; expiry min(proposal expiry,
      now + approval_max_ttl). Throws ApprovalError: caps above the proposal's or the policy's → exit 1
      FEE_CEILING_EXCEEDED / CLTV_DELTA_UNSAFE; expiry after the proposal's or after now + ttl → exit 1
      EXPIRY_TOO_LATE; expiry at or before now → exit 1 APPROVAL_EXPIRED; proposal policy digest other
      than the active policy's → exit 1 POLICY_MISMATCH; signing key not among `keys` → exit 2
      UNKNOWN_KEY_ID; snapshot older than max_snapshot_age, or timestamped after now → exit 5
      STALE_SNAPSHOT. No export of sign.ts returns key bytes or passes them to a caller's function.
  src/approval/verify.ts
    interface VerifyContext { keys: readonly ApprovalKey[]; proposal: ProposalTerms; policy: ApprovalPolicy; now: number (database clock) }
    interface ApprovalStore { insert(row: ApprovalRow): 'inserted' | 'nonce-used'; listByProposal(id: string): readonly ApprovalRow[] }
      (ApprovalRow is the SPEC §6.2 approvals row; see test/fakes/approvals.ts; signature in base64)
    export function verifyAndStoreApproval(token: string, ctx: VerifyContext, store: ApprovalStore, deps: { newId(): string }): ApprovalRow;
      SECURITY.md §4.1 steps 1-8 in order; ApprovalError exit 1 with reason MALFORMED_TOKEN, UNKNOWN_KEY_ID,
      BAD_SIGNATURE, DIGEST_MISMATCH, POLICY_MISMATCH, FEE_CEILING_EXCEEDED, CLTV_DELTA_UNSAFE,
      APPROVAL_EXPIRED, EXPIRY_TOO_LATE, NONCE_REUSED. A configured entry whose key_id is not the hash of
      its public key is ignored (UNKNOWN_KEY_ID); a token proposal_id other than the stored proposal's is
      DIGEST_MISMATCH; a stored proposal under another policy than the active one is POLICY_MISMATCH;
      expires_at after now + approval_max_ttl is EXPIRY_TOO_LATE (no clock tolerance).
    export function requireStoredApproval(proposalId: string, ctx: VerifyContext, store: ApprovalStore): ApprovalRow;
      Claim-time check: re-verifies a stored row against the stored proposal, policy and configured keys;
      no row that verifies (including a malformed stored field) → ApprovalError exit 5 (reason
      NO_APPROVAL when the proposal has no row).
  ApprovalError extends Error { name: 'ApprovalError'; exitCode: 1 | 2 | 5; reason: string }
*/
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from 'node:crypto';
import { readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { ESLint } from 'eslint';
import tseslint from 'typescript-eslint';
import { describe, expect, it } from 'vitest';
import { MemoryApprovals, type ApprovalRow } from '../fakes/approvals.js';
import { repoRoot, scratchDir } from '../helpers/cli.js';
import { loadSrc, thrown } from '../helpers/load-src.js';

interface SecretLike { toString(): string }
interface SecretModule { Secret: new (bytes: Uint8Array) => SecretLike; revealSecret: (secret: SecretLike) => Uint8Array }
interface ProposalTerms {
  id: string; nodePubkey: string; sourceChannelKey: string; targetChannelKey: string;
  principalMsat: bigint; maxFeeMsat: bigint; maxFeePpm: bigint; exemptFeeMsat: bigint; maxCltvDelta: number;
  policySha256: string; expiresAt: number;
}
interface ApprovalPolicy { sha256: string; maxFeeMsat: bigint; maxCltvDelta: number; approvalMaxTtlSeconds: number; maxSnapshotAgeSeconds: number }
interface ApprovalKey { keyId: string; publicKey: string }
interface MessageFields { proposalDigest: Uint8Array; policySha256: Uint8Array; approvedMaxFeeMsat: bigint; approvedMaxCltvDelta: number; expiresAt: number; nonce: Uint8Array; keyId: Uint8Array }
interface MessageModule { proposalDigest: (terms: ProposalTerms) => Uint8Array; approvalMessage: (fields: MessageFields) => Uint8Array }
interface KeysModule { generateApprovalKeyPair: () => { privateKey: SecretLike; publicKey: string; keyId: string } }
interface ApprovalRequest {
  proposal: ProposalTerms; policy: ApprovalPolicy; keys: readonly ApprovalKey[];
  approvedMaxFeeMsat?: bigint; approvedMaxCltvDelta?: number; expiresAt?: number; snapshotObservedAt: number;
}
interface SignModule { createApproval: (request: ApprovalRequest, privateKey: SecretLike, deps: { now: () => number; randomBytes: (size: number) => Uint8Array }) => string }
interface VerifyContext { keys: readonly ApprovalKey[]; proposal: ProposalTerms; policy: ApprovalPolicy; now: number }
interface VerifyModule {
  verifyAndStoreApproval: (token: string, ctx: VerifyContext, store: MemoryApprovals, deps: { newId: () => string }) => ApprovalRow;
  requireStoredApproval: (proposalId: string, ctx: VerifyContext, store: MemoryApprovals) => ApprovalRow;
}

const secrets = (): Promise<SecretModule> => loadSrc<SecretModule>('core/secret.ts');
const messages = (): Promise<MessageModule> => loadSrc<MessageModule>('approval/message.ts');
const keys = (): Promise<KeysModule> => loadSrc<KeysModule>('approval/keys.ts');
const signer = (): Promise<SignModule> => loadSrc<SignModule>('approval/sign.ts');
const verifier = (): Promise<VerifyModule> => loadSrc<VerifyModule>('approval/verify.ts');

// ---- Reference encodings written from SECURITY.md §4.1, independent of the code under test ----

const APPROVAL_PREFIX = Buffer.concat([Buffer.from('FluxWarden-approval-v1', 'utf8'), Buffer.from([0x00])]);
const PROPOSAL_PREFIX = Buffer.concat([Buffer.from('FluxWarden-proposal-v1', 'utf8'), Buffer.from([0x00])]);

const sha256 = (data: Buffer | string): Buffer => createHash('sha256').update(data).digest();
function u64(value: bigint): Buffer { const out = Buffer.alloc(8); out.writeBigUInt64BE(value); return out; }
function u32(value: number): Buffer { const out = Buffer.alloc(4); out.writeUInt32BE(value); return out; }
function lengthPrefixed(text: string): Buffer { const bytes = Buffer.from(text, 'utf8'); return Buffer.concat([u32(bytes.length), bytes]); }

function referenceDigest(t: ProposalTerms): Buffer {
  return sha256(Buffer.concat([PROPOSAL_PREFIX, ...[
    t.id, t.nodePubkey, t.sourceChannelKey, t.targetChannelKey, t.principalMsat.toString(), t.maxFeeMsat.toString(),
    t.maxFeePpm.toString(), t.exemptFeeMsat.toString(), String(t.maxCltvDelta), t.policySha256, String(t.expiresAt),
  ].map(lengthPrefixed)]));
}

interface TokenFields { digest: Buffer; policy: Buffer; fee: bigint; cltv: number; expires: number; nonce: Buffer; keyId: Buffer }

function referenceMessage(f: TokenFields, prefix: Buffer = APPROVAL_PREFIX): Buffer {
  return Buffer.concat([prefix, f.digest, f.policy, u64(f.fee), u32(f.cltv), u64(BigInt(f.expires)), f.nonce, f.keyId]);
}

function rawPublicKey(key: KeyObject): Buffer {
  const jwk = key.export({ format: 'jwk' });
  if (typeof jwk.x !== 'string') throw new Error('not an Ed25519 public key');
  return Buffer.from(jwk.x, 'base64url');
}

const keyIdOf = (publicKey: KeyObject): Buffer => sha256(rawPublicKey(publicKey)).subarray(0, 16);
const configEntry = (publicKey: KeyObject): ApprovalKey => ({ keyId: keyIdOf(publicKey).toString('hex'), publicKey: rawPublicKey(publicKey).toString('base64') });

// ---- Fixture ----

const NOW = 1_800_000_000_000;
const POLICY_SHA = sha256('policy version 3').toString('hex');
const PROPOSAL: ProposalTerms = {
  id: 'prop_01JABCDEFGHJKMNPQRSTVWXYZ0', nodePubkey: `03${'ab'.repeat(32)}`, sourceChannelKey: '101x1x0', targetChannelKey: '103x1x0',
  principalMsat: 100_000_000n, maxFeeMsat: 300_000n, maxFeePpm: 2500n, exemptFeeMsat: 5000n, maxCltvDelta: 144,
  policySha256: POLICY_SHA, expiresAt: NOW + 900_000,
};
const POLICY: ApprovalPolicy = { sha256: POLICY_SHA, maxFeeMsat: 300_000n, maxCltvDelta: 144, approvalMaxTtlSeconds: 900, maxSnapshotAgeSeconds: 60 };

const operator = generateKeyPairSync('ed25519');
const stranger = generateKeyPairSync('ed25519');
const SENTINEL_PEM = readFileSync(join(repoRoot, 'test/sentinels/ed25519-key.pem'));
const sentinelPrivate = createPrivateKey(SENTINEL_PEM);
const sentinelPublic = createPublicKey(sentinelPrivate);

function context(over: Partial<VerifyContext> = {}): VerifyContext {
  return { keys: [configEntry(operator.publicKey)], proposal: PROPOSAL, policy: POLICY, now: NOW, ...over };
}

let nonceCounter = 0;
const freshNonce = (): Buffer => { nonceCounter += 1; return sha256(`nonce ${String(nonceCounter)}`); };

interface HandToken {
  proposal?: ProposalTerms; policySha?: string; fee?: bigint; cltv?: number; expires?: number; nonce?: Buffer;
  signer?: KeyObject; claimedKey?: KeyObject; prefix?: Buffer;
}

/** A token signed here with node:crypto over the SECURITY.md §4.1 message. */
function handToken(o: HandToken = {}): { text: string; fields: TokenFields; signature: Buffer } {
  const proposal = o.proposal ?? PROPOSAL;
  const signingKey = o.signer ?? operator.privateKey;
  const fields: TokenFields = {
    digest: referenceDigest(proposal), policy: Buffer.from(o.policySha ?? proposal.policySha256, 'hex'),
    fee: o.fee ?? 250_000n, cltv: o.cltv ?? 120, expires: o.expires ?? NOW + 600_000, nonce: o.nonce ?? freshNonce(),
    keyId: keyIdOf(o.claimedKey ?? createPublicKey(signingKey)),
  };
  const signature = sign(null, referenceMessage(fields, o.prefix), signingKey);
  return { text: tokenText(proposal.id, fields, signature), fields, signature };
}

function tokenText(proposalId: string, f: TokenFields, signature: Buffer, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    v: 1, proposal_id: proposalId, proposal_digest: f.digest.toString('hex'), policy_sha256: f.policy.toString('hex'),
    approved_max_fee_msat: f.fee.toString(), approved_max_cltv_delta: String(f.cltv), expires_at: f.expires,
    nonce: f.nonce.toString('hex'), key_id: f.keyId.toString('hex'), signature: signature.toString('hex'), ...extra,
  });
}

function ids(): { newId: () => string } {
  let n = 0;
  return { newId: () => { n += 1; return `appr_${String(n)}`; } };
}

function refusal(action: () => unknown): { exitCode: unknown; reason: unknown } {
  const error = thrown(action);
  expect(error.name).toBe('ApprovalError');
  return { exitCode: error.exitCode, reason: error.reason };
}

function parseToken(text: string): Record<string, unknown> {
  const value: unknown = JSON.parse(text);
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('token is not an object');
  return value as Record<string, unknown>;
}

function stringField(token: Record<string, unknown>, name: string): string {
  const value = token[name];
  if (typeof value !== 'string') throw new Error(`token field ${name} is not a string`);
  return value;
}

describe('key pair', () => {
  it('CP-026/B1 a generated key pair is Ed25519 with key_id = first 16 bytes of SHA-256 of the raw public key', async () => {
    const { generateApprovalKeyPair } = await keys();
    const { revealSecret } = await secrets();
    const pair = generateApprovalKeyPair();
    const privateKey = createPrivateKey(Buffer.from(revealSecret(pair.privateKey)));
    expect(privateKey.asymmetricKeyType).toBe('ed25519');
    const raw = rawPublicKey(createPublicKey(privateKey));
    expect(pair.publicKey).toBe(raw.toString('base64'));
    expect(Buffer.from(pair.publicKey, 'base64')).toHaveLength(32);
    expect(pair.keyId).toBe(sha256(raw).subarray(0, 16).toString('hex'));
    expect(String(pair.privateKey)).toMatch(/^\[redacted fp:[0-9a-f]{16}\]$/);
    expect(JSON.stringify(pair)).not.toContain('PRIVATE KEY');
    expect(generateApprovalKeyPair().keyId).not.toBe(pair.keyId);
  });
});

describe('message and signature', () => {
  const FIELDS: TokenFields = {
    digest: Buffer.alloc(32, 0xd1), policy: Buffer.alloc(32, 0x5a), fee: 300_000n, cltv: 144,
    expires: 1_800_000_600_000, nonce: Buffer.alloc(32, 0x4e), keyId: Buffer.alloc(16, 0x1d),
  };
  const asInput = (f: TokenFields): MessageFields => ({
    proposalDigest: f.digest, policySha256: f.policy, approvedMaxFeeMsat: f.fee, approvedMaxCltvDelta: f.cltv,
    expiresAt: f.expires, nonce: f.nonce, keyId: f.keyId,
  });

  it('CP-026/B2 the signed message is exactly the SECURITY.md §4.1 byte layout', async () => {
    const { approvalMessage } = await messages();
    const hex = Buffer.from(approvalMessage(asInput(FIELDS))).toString('hex');
    expect(hex).toBe([
      '466c757857617264656e2d617070726f76616c2d763100', // "FluxWarden-approval-v1" || 0x00
      'd1'.repeat(32), // proposal_digest
      '5a'.repeat(32), // policy_sha256
      '00000000000493e0', // approved_max_fee_msat 300,000, u64 big-endian
      '00000090', // approved_max_cltv_delta 144, u32 big-endian
      '000001a3186577c0', // expires_at 1,800,000,600,000 ms, u64 big-endian
      '4e'.repeat(32), // nonce
      '1d'.repeat(16), // key_id
    ].join(''));
    expect(hex.length / 2).toBe(23 + 32 + 32 + 8 + 4 + 8 + 32 + 16);
    expect(Buffer.from(approvalMessage(asInput({ ...FIELDS, fee: 2n ** 63n - 1n, cltv: 2 ** 32 - 1 }))).subarray(87, 99).toString('hex')).toBe('7fffffffffffffffffffffff');
  });

  it('CP-026/B2 malformed message fields are refused rather than truncated or padded', async () => {
    const { approvalMessage } = await messages();
    for (const bad of [
      { ...FIELDS, digest: Buffer.alloc(31) }, { ...FIELDS, policy: Buffer.alloc(33) }, { ...FIELDS, nonce: Buffer.alloc(31) },
      { ...FIELDS, keyId: Buffer.alloc(32) }, { ...FIELDS, fee: -1n }, { ...FIELDS, fee: 2n ** 64n }, { ...FIELDS, cltv: -1 },
      { ...FIELDS, cltv: 2 ** 32 }, { ...FIELDS, cltv: 1.5 }, { ...FIELDS, expires: -1 }, { ...FIELDS, expires: 1.5 },
    ]) {
      expect(() => approvalMessage(asInput(bad))).toThrow();
    }
  });

  it('CP-026/B2 the proposal digest is SHA-256 over the length-prefixed fields and binds the proposal id', async () => {
    const { proposalDigest } = await messages();
    expect(Buffer.from(proposalDigest(PROPOSAL)).toString('hex')).toBe(referenceDigest(PROPOSAL).toString('hex'));
    const twin = { ...PROPOSAL, id: 'prop_01JABCDEFGHJKMNPQRSTVWXYZ1' };
    expect(Buffer.from(proposalDigest(twin)).toString('hex')).toBe(referenceDigest(twin).toString('hex'));
    expect(referenceDigest(twin).equals(referenceDigest(PROPOSAL))).toBe(false);
  });

  it('CP-026/B2 an approval created by the signer verifies independently over the reference message', async () => {
    const { createApproval } = await signer();
    const { Secret } = await secrets();
    const nonce = Buffer.alloc(32, 0x42);
    const sizes: number[] = [];
    const text = createApproval(
      { proposal: PROPOSAL, policy: POLICY, keys: [configEntry(sentinelPublic)], approvedMaxFeeMsat: 250_000n, approvedMaxCltvDelta: 120, expiresAt: NOW + 600_000, snapshotObservedAt: NOW - 1000 },
      new Secret(SENTINEL_PEM), { now: () => NOW, randomBytes: size => { sizes.push(size); return Buffer.from(nonce); } },
    );
    expect(sizes).toStrictEqual([32]);
    const token = parseToken(text);
    const signature = Buffer.from(stringField(token, 'signature'), 'hex');
    expect(token).toStrictEqual({
      v: 1, proposal_id: PROPOSAL.id, proposal_digest: referenceDigest(PROPOSAL).toString('hex'), policy_sha256: POLICY_SHA,
      approved_max_fee_msat: '250000', approved_max_cltv_delta: '120', expires_at: NOW + 600_000,
      nonce: nonce.toString('hex'), key_id: keyIdOf(sentinelPublic).toString('hex'), signature: signature.toString('hex'),
    });
    expect(signature).toHaveLength(64);
    const message = referenceMessage({
      digest: referenceDigest(PROPOSAL), policy: Buffer.from(POLICY_SHA, 'hex'), fee: 250_000n, cltv: 120,
      expires: NOW + 600_000, nonce, keyId: keyIdOf(sentinelPublic),
    });
    expect(verify(null, message, sentinelPublic, signature)).toBe(true);
  });

  it('CP-026/B2 without explicit caps and expiry the approval takes the proposal caps and the earliest allowed expiry', async () => {
    const { createApproval } = await signer();
    const { Secret } = await secrets();
    const proposal = { ...PROPOSAL, expiresAt: NOW + 1_800_000 };
    const token = parseToken(createApproval(
      { proposal, policy: POLICY, keys: [configEntry(sentinelPublic)], snapshotObservedAt: NOW },
      new Secret(SENTINEL_PEM), { now: () => NOW, randomBytes: size => Buffer.alloc(size, 7) },
    ));
    expect(token['approved_max_fee_msat']).toBe('300000');
    expect(token['approved_max_cltv_delta']).toBe('144');
    expect(token['expires_at']).toBe(NOW + 900_000);
  });

  it('CP-026/B2 a hand-signed token over the reference message verifies and is stored exactly once', async () => {
    const { verifyAndStoreApproval } = await verifier();
    const store = new MemoryApprovals();
    const token = handToken();
    const row = verifyAndStoreApproval(token.text, context(), store, ids());
    const expected: ApprovalRow = {
      id: 'appr_1', proposal_id: PROPOSAL.id, key_id: token.fields.keyId.toString('hex'), nonce: token.fields.nonce.toString('hex'),
      expires_at: NOW + 600_000, signature: token.signature.toString('base64'), max_fee_msat: 250_000n, max_cltv_delta: 120, created_at: NOW,
    };
    expect(row).toStrictEqual(expected);
    expect(store.rows).toStrictEqual([expected]);
  });

  it('CP-026/B2 changing any signed byte of a valid token fails verification', async () => {
    const { verifyAndStoreApproval } = await verifier();
    const token = handToken();
    const flipHex = (hex: string): string => (hex.startsWith('0') ? '1' : '0') + hex.slice(1);
    const base = parseToken(token.text);
    const tampered: Record<string, unknown>[] = [
      { signature: flipHex(stringField(base, 'signature')) },
      { nonce: flipHex(stringField(base, 'nonce')) },
      { proposal_digest: flipHex(stringField(base, 'proposal_digest')) },
      { policy_sha256: flipHex(stringField(base, 'policy_sha256')) },
      { approved_max_fee_msat: '249999' }, // tighter, but not what was signed
      { approved_max_cltv_delta: '119' },
      { expires_at: NOW + 599_999 },
    ];
    for (const change of tampered) {
      const store = new MemoryApprovals();
      expect(refusal(() => verifyAndStoreApproval(JSON.stringify({ ...base, ...change }), context(), store, ids())), JSON.stringify(change))
        .toStrictEqual({ exitCode: 1, reason: 'BAD_SIGNATURE' });
      expect(store.rows).toHaveLength(0);
    }
  });

  it('CP-026/B2 the domain prefix is part of the signed message', async () => {
    const { verifyAndStoreApproval } = await verifier();
    for (const prefix of [Buffer.alloc(0), PROPOSAL_PREFIX, Buffer.from('FluxWarden-approval-v1', 'utf8')]) {
      const store = new MemoryApprovals();
      expect(refusal(() => verifyAndStoreApproval(handToken({ prefix }).text, context(), store, ids()))).toStrictEqual({ exitCode: 1, reason: 'BAD_SIGNATURE' });
    }
  });
});

describe('verification refusals', () => {
  it('CP-026/B3 a replayed nonce is refused and nothing more is stored', async () => {
    const { verifyAndStoreApproval } = await verifier();
    const store = new MemoryApprovals();
    const newIds = ids();
    const token = handToken();
    verifyAndStoreApproval(token.text, context(), store, newIds);
    expect(refusal(() => verifyAndStoreApproval(token.text, context(), store, newIds))).toStrictEqual({ exitCode: 1, reason: 'NONCE_REUSED' });
    const sameNonce = handToken({ nonce: token.fields.nonce, fee: 200_000n });
    expect(refusal(() => verifyAndStoreApproval(sameNonce.text, context(), store, newIds))).toStrictEqual({ exitCode: 1, reason: 'NONCE_REUSED' });
    expect(store.rows).toHaveLength(1);
  });

  it('CP-026/B3 an approval must expire after the database clock and no later than the proposal', async () => {
    const { verifyAndStoreApproval } = await verifier();
    const store = new MemoryApprovals();
    const newIds = ids();
    expect(refusal(() => verifyAndStoreApproval(handToken({ expires: NOW }).text, context(), store, newIds))).toStrictEqual({ exitCode: 1, reason: 'APPROVAL_EXPIRED' });
    expect(refusal(() => verifyAndStoreApproval(handToken({ expires: NOW - 1 }).text, context(), store, newIds))).toStrictEqual({ exitCode: 1, reason: 'APPROVAL_EXPIRED' });
    expect(refusal(() => verifyAndStoreApproval(handToken({ expires: PROPOSAL.expiresAt + 1 }).text, context(), store, newIds))).toStrictEqual({ exitCode: 1, reason: 'EXPIRY_TOO_LATE' });
    expect(store.rows).toHaveLength(0);
    verifyAndStoreApproval(handToken({ expires: NOW + 1 }).text, context(), store, newIds);
    verifyAndStoreApproval(handToken({ expires: PROPOSAL.expiresAt }).text, context(), store, newIds);
    expect(store.rows).toHaveLength(2);
  });

  it('CP-026/B3 a key_id that names no configured key is refused, and a claimed key_id must match the signer', async () => {
    const { verifyAndStoreApproval } = await verifier();
    const store = new MemoryApprovals();
    expect(refusal(() => verifyAndStoreApproval(handToken({ signer: stranger.privateKey }).text, context(), store, ids()))).toStrictEqual({ exitCode: 1, reason: 'UNKNOWN_KEY_ID' });
    const impostor = handToken({ signer: stranger.privateKey, claimedKey: operator.publicKey });
    expect(refusal(() => verifyAndStoreApproval(impostor.text, context(), store, ids()))).toStrictEqual({ exitCode: 1, reason: 'BAD_SIGNATURE' });
    expect(refusal(() => verifyAndStoreApproval(handToken().text, context({ keys: [] }), store, ids()))).toStrictEqual({ exitCode: 1, reason: 'UNKNOWN_KEY_ID' });
    expect(store.rows).toHaveLength(0);
  });

  it('CP-026/B3 caps wider than the proposal are refused even when correctly signed', async () => {
    const { verifyAndStoreApproval } = await verifier();
    const store = new MemoryApprovals();
    expect(refusal(() => verifyAndStoreApproval(handToken({ fee: 300_001n }).text, context(), store, ids()))).toStrictEqual({ exitCode: 1, reason: 'FEE_CEILING_EXCEEDED' });
    expect(refusal(() => verifyAndStoreApproval(handToken({ cltv: 145 }).text, context(), store, ids()))).toStrictEqual({ exitCode: 1, reason: 'CLTV_DELTA_UNSAFE' });
    expect(store.rows).toHaveLength(0);
    verifyAndStoreApproval(handToken({ fee: 300_000n, cltv: 144 }).text, context(), store, ids());
    expect(store.rows).toHaveLength(1);
  });

  it('CP-026/B3 caps within a loose proposal but wider than the policy are refused', async () => {
    const { verifyAndStoreApproval } = await verifier();
    const loose = { ...PROPOSAL, maxFeeMsat: 400_000n, maxCltvDelta: 200 };
    const ctx = context({ proposal: loose });
    const store = new MemoryApprovals();
    expect(refusal(() => verifyAndStoreApproval(handToken({ proposal: loose, fee: 300_001n }).text, ctx, store, ids()))).toStrictEqual({ exitCode: 1, reason: 'FEE_CEILING_EXCEEDED' });
    expect(refusal(() => verifyAndStoreApproval(handToken({ proposal: loose, cltv: 145 }).text, ctx, store, ids()))).toStrictEqual({ exitCode: 1, reason: 'CLTV_DELTA_UNSAFE' });
    expect(store.rows).toHaveLength(0);
  });

  it('CP-026/B3 a stored proposal that no longer matches the signed digest is DIGEST_MISMATCH', async () => {
    const { verifyAndStoreApproval } = await verifier();
    for (const altered of [
      { ...PROPOSAL, principalMsat: PROPOSAL.principalMsat + 1n }, { ...PROPOSAL, sourceChannelKey: '102x1x0' },
      { ...PROPOSAL, targetChannelKey: '104x1x0' }, { ...PROPOSAL, maxFeePpm: 2501n }, { ...PROPOSAL, nodePubkey: `03${'ac'.repeat(32)}` },
    ]) {
      const store = new MemoryApprovals();
      expect(refusal(() => verifyAndStoreApproval(handToken().text, context({ proposal: altered }), store, ids()))).toStrictEqual({ exitCode: 1, reason: 'DIGEST_MISMATCH' });
      expect(store.rows).toHaveLength(0);
    }
  });

  it('CP-026/B3 an approval signed for another policy digest is POLICY_MISMATCH', async () => {
    const { verifyAndStoreApproval } = await verifier();
    const store = new MemoryApprovals();
    const other = { ...POLICY, sha256: sha256('policy version 4').toString('hex') };
    expect(refusal(() => verifyAndStoreApproval(handToken().text, context({ policy: other }), store, ids()))).toStrictEqual({ exitCode: 1, reason: 'POLICY_MISMATCH' });
    expect(store.rows).toHaveLength(0);
  });

  it('CP-026/B3 a token with a wrong field length, an extra or missing field, or over 4 KiB is MALFORMED_TOKEN', async () => {
    const { verifyAndStoreApproval } = await verifier();
    const token = handToken();
    const base = parseToken(token.text);
    const withoutNonce = Object.fromEntries(Object.entries(base).filter(([name]) => name !== 'nonce'));
    for (const text of [
      JSON.stringify({ ...base, extra: 'x' }),
      JSON.stringify(withoutNonce),
      JSON.stringify({ ...base, v: 2 }),
      JSON.stringify({ ...base, nonce: stringField(base, 'nonce').slice(2) }),
      JSON.stringify({ ...base, key_id: `${stringField(base, 'key_id')}00` }),
      JSON.stringify({ ...base, approved_max_fee_msat: 250000 }),
      JSON.stringify({ ...base, approved_max_fee_msat: '0250000' }),
      `${token.text}${' '.repeat(4096)}`,
      'not json',
    ]) {
      const store = new MemoryApprovals();
      expect(refusal(() => verifyAndStoreApproval(text, context(), store, ids())).reason).toBe('MALFORMED_TOKEN');
      expect(store.rows).toHaveLength(0);
    }
  });

  // Each case below breaks exactly one rule and satisfies every other one.
  it('CP-026/B3 an approval expiring after the proposal is refused even within approval_max_ttl', async () => {
    const { verifyAndStoreApproval } = await verifier();
    const shortLived = { ...PROPOSAL, expiresAt: NOW + 300_000 };
    const store = new MemoryApprovals();
    const newIds = ids();
    expect(refusal(() => verifyAndStoreApproval(handToken({ proposal: shortLived, expires: NOW + 300_001 }).text, context({ proposal: shortLived }), store, newIds))).toStrictEqual({ exitCode: 1, reason: 'EXPIRY_TOO_LATE' });
    expect(store.rows).toHaveLength(0);
    verifyAndStoreApproval(handToken({ proposal: shortLived, expires: NOW + 300_000 }).text, context({ proposal: shortLived }), store, newIds);
    expect(store.rows).toHaveLength(1);
  });

  // SPEC §7.7: expires_at <= now + approval_max_ttl, with no tolerance.
  it('CP-026/B3 an approval expiring after now + approval_max_ttl is refused even before the proposal expires', async () => {
    const { verifyAndStoreApproval } = await verifier();
    const longLived = { ...PROPOSAL, expiresAt: NOW + 3_600_000 };
    const store = new MemoryApprovals();
    const newIds = ids();
    expect(refusal(() => verifyAndStoreApproval(handToken({ proposal: longLived, expires: NOW + 900_001 }).text, context({ proposal: longLived }), store, newIds))).toStrictEqual({ exitCode: 1, reason: 'EXPIRY_TOO_LATE' });
    expect(store.rows).toHaveLength(0);
    verifyAndStoreApproval(handToken({ proposal: longLived, expires: NOW + 900_000 }).text, context({ proposal: longLived }), store, newIds);
    expect(store.rows).toHaveLength(1);
  });

  it('CP-026/B3 a database clock or approval_max_ttl that is not a number fails closed and stores nothing', async () => {
    const { verifyAndStoreApproval } = await verifier();
    for (const ctx of [context({ now: Number.NaN }), context({ policy: { ...POLICY, approvalMaxTtlSeconds: Number.NaN } }), context({ proposal: { ...PROPOSAL, expiresAt: Number.NaN } })]) {
      const store = new MemoryApprovals();
      expect(thrown(() => verifyAndStoreApproval(handToken().text, ctx, store, ids())).name).toBe('ApprovalError');
      expect(store.rows).toHaveLength(0);
    }
  });

  it.each([
    ['a proposal fee cap that is not a bigint', { proposal: { ...PROPOSAL, maxFeeMsat: undefined as unknown as bigint } }],
    ['a policy fee cap that is not a bigint', { policy: { ...POLICY, maxFeeMsat: 300_000 as unknown as bigint } }],
    ['a negative approval_max_ttl', { policy: { ...POLICY, approvalMaxTtlSeconds: -1 } }],
    ['a negative database clock', { now: -1 }],
  ] as const)('CP-026/B3 verification refuses %s and stores nothing', async (_name, over) => {
    const { verifyAndStoreApproval } = await verifier();
    const store = new MemoryApprovals();
    expect(refusal(() => verifyAndStoreApproval(handToken().text, context(over as Partial<VerifyContext>), store, ids()))).toStrictEqual({ exitCode: 2, reason: 'INVALID_REQUEST' });
    expect(store.rows).toHaveLength(0);
  });

  it('CP-026/B3 a token naming another proposal id is refused although its digest matches the stored proposal', async () => {
    const { verifyAndStoreApproval } = await verifier();
    const token = handToken();
    const store = new MemoryApprovals();
    const text = tokenText('prop_01JABCDEFGHJKMNPQRSTVWXYZ9', token.fields, token.signature);
    expect(refusal(() => verifyAndStoreApproval(text, context(), store, ids()))).toStrictEqual({ exitCode: 1, reason: 'DIGEST_MISMATCH' });
    expect(store.rows).toHaveLength(0);
  });

  it('CP-026/B3 a proposal made under another policy than the active one is POLICY_MISMATCH', async () => {
    const { verifyAndStoreApproval } = await verifier();
    const active = sha256('policy version 4').toString('hex');
    const stale = { ...PROPOSAL, policySha256: POLICY_SHA };
    const store = new MemoryApprovals();
    // The token carries the active policy digest; only the proposal's own digest is old.
    const token = handToken({ proposal: stale, policySha: active });
    expect(refusal(() => verifyAndStoreApproval(token.text, context({ proposal: stale, policy: { ...POLICY, sha256: active } }), store, ids()))).toStrictEqual({ exitCode: 1, reason: 'POLICY_MISMATCH' });
    expect(store.rows).toHaveLength(0);
  });

  it('CP-026/B3 a configured key_id that is not the hash of its public key vouches for nothing', async () => {
    const { verifyAndStoreApproval } = await verifier();
    const mislabelled: ApprovalKey = { keyId: keyIdOf(operator.publicKey).toString('hex'), publicKey: rawPublicKey(stranger.publicKey).toString('base64') };
    const store = new MemoryApprovals();
    const token = handToken({ signer: stranger.privateKey, claimedKey: operator.publicKey });
    expect(refusal(() => verifyAndStoreApproval(token.text, context({ keys: [mislabelled] }), store, ids()))).toStrictEqual({ exitCode: 1, reason: 'UNKNOWN_KEY_ID' });
    expect(store.rows).toHaveLength(0);
  });
});

describe('approval creation refusals', () => {
  const request = (over: Partial<ApprovalRequest> = {}): ApprovalRequest => ({
    proposal: PROPOSAL, policy: POLICY, keys: [configEntry(sentinelPublic)], snapshotObservedAt: NOW, ...over,
  });
  const deps = { now: () => NOW, randomBytes: (size: number) => Buffer.alloc(size, 9) };

  it('CP-026/B3 approving looser caps than the proposal or the policy exits 1', async () => {
    const { createApproval } = await signer();
    const { Secret } = await secrets();
    const key = new Secret(SENTINEL_PEM);
    expect(refusal(() => createApproval(request({ approvedMaxFeeMsat: 300_001n }), key, deps))).toStrictEqual({ exitCode: 1, reason: 'FEE_CEILING_EXCEEDED' });
    expect(refusal(() => createApproval(request({ approvedMaxCltvDelta: 145 }), key, deps))).toStrictEqual({ exitCode: 1, reason: 'CLTV_DELTA_UNSAFE' });
    const loose = { ...PROPOSAL, maxFeeMsat: 400_000n, maxCltvDelta: 200 };
    expect(refusal(() => createApproval(request({ proposal: loose, approvedMaxFeeMsat: 300_001n, approvedMaxCltvDelta: 144 }), key, deps))).toStrictEqual({ exitCode: 1, reason: 'FEE_CEILING_EXCEEDED' });
    expect(refusal(() => createApproval(request({ proposal: loose, approvedMaxFeeMsat: 300_000n, approvedMaxCltvDelta: 145 }), key, deps))).toStrictEqual({ exitCode: 1, reason: 'CLTV_DELTA_UNSAFE' });
    expect(parseToken(createApproval(request({ approvedMaxFeeMsat: 300_000n, approvedMaxCltvDelta: 144 }), key, deps))['approved_max_fee_msat']).toBe('300000');
  });

  it('CP-026/B3 an expiry after the proposal or after now + approval_max_ttl exits 1', async () => {
    const { createApproval } = await signer();
    const { Secret } = await secrets();
    const key = new Secret(SENTINEL_PEM);
    expect(refusal(() => createApproval(request({ expiresAt: PROPOSAL.expiresAt + 1 }), key, deps))).toStrictEqual({ exitCode: 1, reason: 'EXPIRY_TOO_LATE' });
    const longLived = { ...PROPOSAL, expiresAt: NOW + 3_600_000 };
    expect(refusal(() => createApproval(request({ proposal: longLived, expiresAt: NOW + 900_001 }), key, deps))).toStrictEqual({ exitCode: 1, reason: 'EXPIRY_TOO_LATE' });
    expect(parseToken(createApproval(request({ proposal: longLived, expiresAt: NOW + 900_000 }), key, deps))['expires_at']).toBe(NOW + 900_000);
  });

  it('CP-026/B3 signing with a key that is not configured exits 2', async () => {
    const { createApproval } = await signer();
    const { Secret } = await secrets();
    expect(refusal(() => createApproval(request({ keys: [configEntry(operator.publicKey)] }), new Secret(SENTINEL_PEM), deps))).toStrictEqual({ exitCode: 2, reason: 'UNKNOWN_KEY_ID' });
  });

  it('CP-026/B3 an approval that would expire exactly now exits 1', async () => {
    const { createApproval } = await signer();
    const { Secret } = await secrets();
    expect(refusal(() => createApproval(request({ expiresAt: NOW }), new Secret(SENTINEL_PEM), deps))).toStrictEqual({ exitCode: 1, reason: 'APPROVAL_EXPIRED' });
    expect(parseToken(createApproval(request({ expiresAt: NOW + 1 }), new Secret(SENTINEL_PEM), deps))['expires_at']).toBe(NOW + 1);
  });

  it('CP-026/B3 the default expiry never passes the proposal expiry', async () => {
    const { createApproval } = await signer();
    const { Secret } = await secrets();
    const shortLived = { ...PROPOSAL, expiresAt: NOW + 300_000 };
    expect(parseToken(createApproval(request({ proposal: shortLived }), new Secret(SENTINEL_PEM), deps))['expires_at']).toBe(NOW + 300_000);
  });

  it('CP-026/B3 approving a proposal made under another policy than the active one exits 1', async () => {
    const { createApproval } = await signer();
    const { Secret } = await secrets();
    const stale = { ...PROPOSAL, policySha256: sha256('policy version 2').toString('hex') };
    expect(refusal(() => createApproval(request({ proposal: stale }), new Secret(SENTINEL_PEM), deps))).toStrictEqual({ exitCode: 1, reason: 'POLICY_MISMATCH' });
  });

  // SPEC §7.7 gives no clock tolerance: a default approval made on a signer clock ahead of the
  // database clock lies beyond the database's now + approval_max_ttl and is refused there.
  it('CP-026/B3 a default approval from a signer clock ahead of the database clock is refused at verification', async () => {
    const { createApproval } = await signer();
    const { verifyAndStoreApproval } = await verifier();
    const { Secret } = await secrets();
    const longLived = { ...PROPOSAL, expiresAt: NOW + 3_600_000 };
    const keys = [configEntry(sentinelPublic)];
    const ahead = createApproval(request({ proposal: longLived, keys }), new Secret(SENTINEL_PEM), { now: () => NOW + 1, randomBytes: size => Buffer.alloc(size, 11) });
    expect(refusal(() => verifyAndStoreApproval(ahead, { keys, proposal: longLived, policy: POLICY, now: NOW }, new MemoryApprovals(), ids()))).toStrictEqual({ exitCode: 1, reason: 'EXPIRY_TOO_LATE' });
    const agreed = createApproval(request({ proposal: longLived, keys }), new Secret(SENTINEL_PEM), { now: () => NOW, randomBytes: size => Buffer.alloc(size, 12) });
    expect(verifyAndStoreApproval(agreed, { keys, proposal: longLived, policy: POLICY, now: NOW }, new MemoryApprovals(), ids()).expires_at).toBe(NOW + 900_000);
  });

  it('CP-026/B3 a non-integer explicit expiry is an invalid request (exit 2)', async () => {
    const { createApproval } = await signer();
    const { Secret } = await secrets();
    for (const expiresAt of [Number.NaN, NOW + 600_000.5, Number.POSITIVE_INFINITY]) {
      expect(refusal(() => createApproval(request({ expiresAt }), new Secret(SENTINEL_PEM), deps)), String(expiresAt)).toStrictEqual({ exitCode: 2, reason: 'INVALID_REQUEST' });
    }
  });

  it('CP-026/B3 a policy digest that is not 64 lowercase hex is refused even when proposal and policy agree', async () => {
    const { createApproval } = await signer();
    const { Secret } = await secrets();
    for (const digest of [POLICY_SHA.toUpperCase(), POLICY_SHA.slice(2)]) {
      const odd = { ...PROPOSAL, policySha256: digest };
      expect(refusal(() => createApproval(request({ proposal: odd, policy: { ...POLICY, sha256: digest } }), new Secret(SENTINEL_PEM), deps)), digest).toStrictEqual({ exitCode: 1, reason: 'POLICY_MISMATCH' });
    }
  });

  it('CP-026/B3 a clock or proposal expiry that is not a number fails closed in the signer', async () => {
    const { createApproval } = await signer();
    const { Secret } = await secrets();
    const outcomes = [
      () => createApproval(request({ expiresAt: NOW + 600_000 }), new Secret(SENTINEL_PEM), { ...deps, now: () => Number.NaN }),
      () => createApproval(request(), new Secret(SENTINEL_PEM), { ...deps, now: () => Number.NaN }),
      () => createApproval(request({ proposal: { ...PROPOSAL, expiresAt: Number.NaN } }), new Secret(SENTINEL_PEM), deps),
      () => createApproval(request({ policy: { ...POLICY, approvalMaxTtlSeconds: Number.NaN } }), new Secret(SENTINEL_PEM), deps),
    ];
    for (const [index, action] of outcomes.entries()) {
      expect(thrown(action).name, `case ${String(index)}`).toBe('ApprovalError');
    }
  });

  // Each of the signer's trusted inputs must be a non-negative safe integer (or a bigint for amounts);
  // otherwise the request is invalid (exit 2) rather than silently passing a comparison with NaN.
  it.each([
    ['proposal expiry', { proposal: { ...PROPOSAL, expiresAt: Number.NaN }, expiresAt: NOW + 600_000 }],
    ['approval_max_ttl', { policy: { ...POLICY, approvalMaxTtlSeconds: Number.NaN }, expiresAt: NOW + 600_000 }],
    ['max_snapshot_age', { policy: { ...POLICY, maxSnapshotAgeSeconds: Number.NaN } }],
    ['the proposal CLTV cap', { proposal: { ...PROPOSAL, maxCltvDelta: Number.NaN }, approvedMaxCltvDelta: 120 }],
    ['the policy CLTV cap', { policy: { ...POLICY, maxCltvDelta: Number.NaN }, approvedMaxCltvDelta: 120 }],
    ['the approved fee cap as a number', { approvedMaxFeeMsat: 250_000 as unknown as bigint }],
    ['a negative max_snapshot_age', { policy: { ...POLICY, maxSnapshotAgeSeconds: -1 } }],
  ] as const)('CP-026/B3 the signer refuses %s that is not a valid number', async (_name, over) => {
    const { createApproval } = await signer();
    const { Secret } = await secrets();
    expect(refusal(() => createApproval(request(over as Partial<ApprovalRequest>), new Secret(SENTINEL_PEM), deps))).toStrictEqual({ exitCode: 2, reason: 'INVALID_REQUEST' });
  });

  it('CP-026/B6 a snapshot time that is not an integer is stale', async () => {
    const { createApproval } = await signer();
    const { Secret } = await secrets();
    for (const snapshotObservedAt of [Number.NaN, undefined as unknown as number, NOW - 0.5]) {
      expect(refusal(() => createApproval(request({ snapshotObservedAt }), new Secret(SENTINEL_PEM), deps)), String(snapshotObservedAt)).toStrictEqual({ exitCode: 5, reason: 'STALE_SNAPSHOT' });
    }
  });

  it('CP-026/B6 a snapshot timestamped after the approval clock is not fresh', async () => {
    const { createApproval } = await signer();
    const { Secret } = await secrets();
    expect(refusal(() => createApproval(request({ snapshotObservedAt: NOW + 1 }), new Secret(SENTINEL_PEM), deps))).toStrictEqual({ exitCode: 5, reason: 'STALE_SNAPSHOT' });
  });

  it('CP-026/B6 a snapshot older than max_snapshot_age at approval time is STALE_SNAPSHOT', async () => {
    const { createApproval } = await signer();
    const { Secret } = await secrets();
    const key = new Secret(SENTINEL_PEM);
    expect(refusal(() => createApproval(request({ snapshotObservedAt: NOW - 60_001 }), key, deps))).toStrictEqual({ exitCode: 5, reason: 'STALE_SNAPSHOT' });
    expect(parseToken(createApproval(request({ snapshotObservedAt: NOW - 60_000 }), key, deps))['proposal_id']).toBe(PROPOSAL.id);
  });
});

describe('private key confinement', () => {
  // Paths that may not exist are linted without type information (the outside-module rule needs none);
  // probes standing in for src/approval/sign.ts are linted with the full, type-aware configuration.
  const plainLint = new ESLint({ cwd: repoRoot, overrideConfig: [
    tseslint.configs.disableTypeChecked,
    { languageOptions: { parserOptions: { projectService: false, project: null } } },
  ] });
  const typedLint = new ESLint({ cwd: repoRoot });
  const SIGN = 'src/approval/sign.ts';
  const header = "import { createHash, createPrivateKey } from 'node:crypto';\nimport { revealSecret, type Secret } from '../core/secret.js';\n";
  // An allow-listed export (createApproval returns the token text) that returns only a fingerprint.
  const fingerprint = `${header.replace('createHash, createPrivateKey', 'createHash')}export function createApproval(key: Secret): string { return createHash('sha256').update(revealSecret(key)).digest('hex').slice(0, 16); }\n`;
  // Revealed bytes used inside the module; the export carries neither bytes nor text.
  const internalOnly = `${header.replace('createHash, createPrivateKey', 'createPrivateKey')}function keyObject(key: Secret) { return createPrivateKey({ key: Buffer.from(revealSecret(key)), format: 'pem' }); }\n`
    + "export function isEd25519(key: Secret): boolean { return keyObject(key).asymmetricKeyType === 'ed25519'; }\n";

  async function report(source: string, path: string, typed = path === SIGN): Promise<{ errors: number; containment: number }> {
    const linter = typed ? typedLint : plainLint;
    const [result] = await linter.lintText(source, { filePath: join(repoRoot, path) });
    if (!result) throw new Error('no lint verdict');
    expect(result.messages.some(message => message.fatal === true), `${path} parses`).toBe(false);
    const containment = result.messages.filter(message => message.severity === 2 && message.ruleId !== null && !message.ruleId.startsWith('@typescript-eslint/') && message.ruleId.includes('/')).length;
    return { errors: result.errorCount, containment };
  }

  it('CP-026/B4 the reveal capability is usable only inside src/approval/sign.ts and refused elsewhere', async () => {
    expect(await report(fingerprint, SIGN)).toStrictEqual({ errors: 0, containment: 0 });
    expect(await report(internalOnly, SIGN)).toStrictEqual({ errors: 0, containment: 0 });
    for (const path of ['src/approval/verify.ts', 'src/approval/keys.ts', 'src/approval/message.ts', 'src/approval/index.ts', 'src/approval/credential.ts', 'src/policy/load.ts', 'src/cli/main.ts']) {
      expect((await report(fingerprint, path)).containment, path).toBeGreaterThan(0);
    }
  });

  // One representative of each way revealed bytes can leave the signer (D50, CP-026/B4). Each export
  // carries bytes or text and is not on the allow-list.
  const escapes: readonly (readonly [string, string])[] = [
    ['returned directly', 'export function openKey(key: Secret): Uint8Array { return revealSecret(key); }'],
    ['through a ternary', 'export function openKey(key: Secret, wanted: boolean): Uint8Array | null { return wanted ? revealSecret(key) : null; }'],
    ['through ??', 'export function openKey(key: Secret, other: Uint8Array | undefined): Uint8Array { return other ?? revealSecret(key); }'],
    ['through await', 'export async function openKey(key: Secret): Promise<Uint8Array> { return await Promise.resolve(revealSecret(key)); }'],
    ['inside an array', 'export function openKey(key: Secret): Uint8Array[] { return [revealSecret(key)]; }'],
    ['through Buffer.concat', 'export function openKey(key: Secret): Buffer { return Buffer.concat([revealSecret(key)]); }'],
    ['as base64 text', "export function openKey(key: Secret): string { return Buffer.from(revealSecret(key)).toString('base64'); }"],
    ['through subarray', 'export function openKey(key: Secret): Uint8Array { return revealSecret(key).subarray(0); }'],
    ['through new Uint8Array', 'export function openKey(key: Secret): Uint8Array { return new Uint8Array(revealSecret(key)); }'],
    ['inside an object literal', 'export const openKey = (key: Secret): { bytes: Uint8Array } => ({ bytes: revealSecret(key) });'],
    ['to a callback', 'export function openKey(key: Secret, sink: (bytes: Uint8Array) => void): void { sink(revealSecret(key)); }'],
    ['into a caller object', 'export function openKey(key: Secret, out: { bytes?: Uint8Array }): void { out.bytes = revealSecret(key); }'],
    ['as the capability under another name', 'export const openKey = revealSecret;'],
    ['as the default export', 'export default revealSecret;'],
    ['as a local alias', 'export { revealSecret as openKey };'],
    ['through a const alias of the capability', 'const open = revealSecret;\nexport function openKey(key: Secret): Uint8Array { return open(key); }'],
    ['as a re-export', "export { revealSecret } from '../core/secret.js';"],
    ['as a star re-export', "export * from '../core/secret.js';"],
    ['bytes unrelated to the key, off the allow-list', 'export function openKey(): Uint8Array { return new Uint8Array(32); }'],
  ];

  it.each(escapes)('CP-026/B4 sign.ts exporting key bytes %s is flagged', async (_name, line) => {
    const source = `${header}${line}\n`;
    expect((await report(source, SIGN)).containment).toBeGreaterThan(0);
  });

  it('CP-026/B4 an aliased import of the capability returned from sign.ts is flagged', async () => {
    const source = "import { revealSecret as open, type Secret } from '../core/secret.js';\nexport function openKey(key: Secret): Uint8Array { return open(key); }\n";
    expect((await report(source, SIGN)).containment).toBeGreaterThan(0);
    expect((await report(source, SIGN, false)).containment, 'without type information').toBeGreaterThan(0);
  });

  // Without type information (an editor or ad-hoc lint) the rule falls back to following revealed
  // values to a return, an arrow body, an exported or returned object, a member assignment or a
  // caller-supplied function; each escape that involves the key is still reported.
  it.each(escapes.filter(([name]) => !name.startsWith('bytes unrelated')))('CP-026/B4 without type information, sign.ts exporting key bytes %s is flagged', async (_name, line) => {
    expect((await report(`${header}${line}\n`, SIGN, false)).containment).toBeGreaterThan(0);
  });

  it('CP-026/B4 without type information, internal use of the capability in sign.ts is not flagged', async () => {
    expect((await report(internalOnly, SIGN, false)).containment).toBe(0);
    expect((await report(fingerprint, SIGN, false)).containment).toBe(0);
  });

  it('CP-026/B4 a CLI module that tries to obtain key bytes is flagged by the lint rule', async () => {
    const launder = "import { revealSecret, type Secret } from '../core/secret.js';\nexport const leak = (key: Secret): string => Buffer.from(revealSecret(key)).toString('base64');\n";
    expect((await report(launder, 'src/cli/launder.ts')).containment).toBeGreaterThan(0);
    const reexport = "export { revealSecret as reveal } from '../core/secret.js';\n";
    expect((await report(reexport, 'src/cli/launder.ts')).containment).toBeGreaterThan(0);
  });

  it('CP-026/B4 no shipped approval module other than sign.ts names the reveal capability', () => {
    const sign = readFileSync(join(repoRoot, 'src/approval/sign.ts'), 'utf8');
    expect(sign).toMatch(/\brevealSecret\b/);
    for (const name of ['keys.ts', 'message.ts', 'verify.ts']) {
      expect(readFileSync(join(repoRoot, 'src/approval', name), 'utf8'), name).not.toMatch(/\breveal(?:Secret)?\b/);
    }
  });

  it('CP-026/B4 writing a generated key file returns no key bytes to the caller', async () => {
    const { Secret } = await secrets();
    const signing = await loadSrc<{ writePrivateKeyFile: (key: SecretLike, path: string) => unknown }>('approval/sign.ts');
    const out = join(scratchDir('approval-key'), 'operator.key');
    try {
      const result = signing.writePrivateKeyFile(new Secret(SENTINEL_PEM), out);
      expect(result).toBe('written');
      expect(createPrivateKey(readFileSync(out)).export({ format: 'jwk' }).d).toBe(sentinelPrivate.export({ format: 'jwk' }).d);
      expect(signing.writePrivateKeyFile(new Secret(SENTINEL_PEM), out)).toBe('exists');
    } finally { rmSync(out, { force: true }); }
  });

  it('CP-026/B4 no export of the signer hands key bytes to a caller or a caller-supplied function', async () => {
    const { Secret } = await secrets();
    const signing = await loadSrc<Record<string, unknown>>('approval/sign.ts');
    const pem = SENTINEL_PEM.toString('utf8');
    const body = pem.split('\n').filter(line => line !== '' && !line.startsWith('-----')).join('');
    const carriesKey = (value: unknown): boolean => {
      if (value instanceof Uint8Array) return Buffer.from(value).toString('utf8').includes(body) || Buffer.from(value).includes(SENTINEL_PEM);
      if (typeof value === 'string') return value.includes(body);
      return false;
    };
    let leaked = false;
    const spy = (...values: unknown[]): unknown => { if (values.some(carriesKey)) leaked = true; return values[0]; };
    for (const [name, exported] of Object.entries(signing)) {
      if (typeof exported !== 'function') continue;
      let result: unknown;
      try {
        result = Reflect.apply(exported, undefined, [new Secret(SENTINEL_PEM), spy]);
      } catch {
        result = undefined;
      }
      expect(carriesKey(result), `${name} returned key bytes`).toBe(false);
      expect(leaked, `${name} passed key bytes to a callback`).toBe(false);
    }
  });

  it('CP-026/B4 neither the token nor a refusal carries the private key in any encoding', async () => {
    const { createApproval } = await signer();
    const { Secret } = await secrets();
    const jwk = sentinelPrivate.export({ format: 'jwk' });
    if (typeof jwk.d !== 'string') throw new Error('sentinel is not an Ed25519 key');
    const seed = Buffer.from(jwk.d, 'base64url');
    const body = SENTINEL_PEM.toString('utf8').split('\n').filter(line => line !== '' && !line.startsWith('-----')).join('');
    const forms = [body, SENTINEL_PEM.toString('utf8'), seed.toString('hex'), seed.toString('base64'), seed.toString('base64url'), jwk.d];
    const key = new Secret(SENTINEL_PEM);
    const outputs: string[] = [createApproval(
      { proposal: PROPOSAL, policy: POLICY, keys: [configEntry(sentinelPublic)], snapshotObservedAt: NOW },
      key, { now: () => NOW, randomBytes: size => Buffer.alloc(size, 3) },
    )];
    for (const bad of [{ approvedMaxFeeMsat: 300_001n }, { snapshotObservedAt: NOW - 120_000 }, { keys: [] }]) {
      const error = thrown(() => createApproval({ proposal: PROPOSAL, policy: POLICY, keys: [configEntry(sentinelPublic)], snapshotObservedAt: NOW, ...bad }, key, { now: () => NOW, randomBytes: size => Buffer.alloc(size, 3) }));
      outputs.push(error.message, String(error.reason), JSON.stringify(error));
    }
    for (const text of outputs) {
      for (const form of forms) expect(text.includes(form)).toBe(false);
    }
  });
});

describe('claim check', () => {
  /** Stand-in for the executor: it may dispatch only with a row the check returns. */
  function fakeExecutor(check: VerifyModule['requireStoredApproval']): { run(ctx: VerifyContext, store: MemoryApprovals): void; dispatched: ApprovalRow[] } {
    const dispatched: ApprovalRow[] = [];
    return { dispatched, run: (ctx, store) => { dispatched.push(check(PROPOSAL.id, ctx, store)); } };
  }

  it('CP-026/B5 without a stored approval row nothing is dispatched', async () => {
    const { requireStoredApproval } = await verifier();
    const executor = fakeExecutor(requireStoredApproval);
    const error = thrown(() => { executor.run(context(), new MemoryApprovals()); });
    expect({ exitCode: error.exitCode, reason: error.reason }).toStrictEqual({ exitCode: 5, reason: 'NO_APPROVAL' });
    expect(executor.dispatched).toHaveLength(0);
  });

  it('CP-026/B5 a stored approval dispatches once under the approved caps', async () => {
    const { verifyAndStoreApproval, requireStoredApproval } = await verifier();
    const store = new MemoryApprovals();
    verifyAndStoreApproval(handToken({ fee: 200_000n, cltv: 100 }).text, context(), store, ids());
    const executor = fakeExecutor(requireStoredApproval);
    executor.run(context({ now: NOW + 1000 }), store);
    expect(executor.dispatched.map(row => [row.max_fee_msat, row.max_cltv_delta])).toStrictEqual([[200_000n, 100]]);
  });

  it.each([
    ['a policy fee cap that is not a bigint', { policy: { ...POLICY, maxFeeMsat: undefined as unknown as bigint } }],
    ['a database clock that is not a number', { now: Number.NaN }],
    ['a negative approval_max_ttl', { policy: { ...POLICY, approvalMaxTtlSeconds: -1 } }],
  ] as const)('CP-026/B5 the claim check refuses %s with exit 5', async (_name, over) => {
    const { verifyAndStoreApproval, requireStoredApproval } = await verifier();
    const store = new MemoryApprovals();
    verifyAndStoreApproval(handToken().text, context(), store, ids());
    const executor = fakeExecutor(requireStoredApproval);
    expect(refusal(() => { executor.run(context(over), store); })).toStrictEqual({ exitCode: 5, reason: 'INVALID_REQUEST' });
    expect(executor.dispatched).toHaveLength(0);
  });

  it('CP-026/B5 a stored row whose fee cap is not a bigint is a safety refusal, not a crash', async () => {
    const { verifyAndStoreApproval, requireStoredApproval } = await verifier();
    const store = new MemoryApprovals();
    verifyAndStoreApproval(handToken({ fee: 200_000n, cltv: 100 }).text, context(), store, ids());
    store.tamper('appr_1', { max_fee_msat: 200_000 as unknown as bigint });
    const executor = fakeExecutor(requireStoredApproval);
    const error = thrown(() => { executor.run(context(), store); });
    expect(error.name).toBe('ApprovalError');
    expect(error.exitCode).toBe(5);
    expect(executor.dispatched).toHaveLength(0);
  });

  it('CP-026/B5 a loosened, expired, foreign or orphaned stored row dispatches nothing', async () => {
    const { verifyAndStoreApproval, requireStoredApproval } = await verifier();
    const cases: { name: string; prepare(store: MemoryApprovals): void; ctx: VerifyContext }[] = [
      { name: 'fee cap raised in the database', prepare: store => { store.tamper('appr_1', { max_fee_msat: 300_000n }); }, ctx: context() },
      { name: 'CLTV cap raised in the database', prepare: store => { store.tamper('appr_1', { max_cltv_delta: 144 }); }, ctx: context() },
      { name: 'expiry extended in the database', prepare: store => { store.tamper('appr_1', { expires_at: NOW + 900_000 }); }, ctx: context({ now: NOW + 700_000 }) },
      { name: 'expired by the database clock', prepare: () => undefined, ctx: context({ now: NOW + 600_000 }) },
      { name: 'signing key removed from the configuration', prepare: () => undefined, ctx: context({ keys: [configEntry(stranger.publicKey)] }) },
      { name: 'proposal changed after approval', prepare: () => undefined, ctx: context({ proposal: { ...PROPOSAL, principalMsat: 100_000_001n } }) },
      { name: 'active policy changed after approval', prepare: () => undefined, ctx: context({ policy: { ...POLICY, sha256: sha256('policy version 4').toString('hex') } }) },
    ];
    for (const c of cases) {
      const store = new MemoryApprovals();
      verifyAndStoreApproval(handToken({ fee: 200_000n, cltv: 100 }).text, context(), store, ids());
      c.prepare(store);
      const executor = fakeExecutor(requireStoredApproval);
      const error = thrown(() => { executor.run(c.ctx, store); });
      expect(error.exitCode, c.name).toBe(5);
      expect(executor.dispatched, c.name).toHaveLength(0);
    }
  });
});
