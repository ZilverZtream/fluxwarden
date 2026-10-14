// Approval verification: the token is checked in a fixed order and stored once, under a unique
// nonce. At claim time a stored row is verified again against the stored proposal, the active
// policy and the configured keys, so a row loosened in the database authorises nothing.
import { verify, type KeyObject } from 'node:crypto';
import { MAX_INT64, type Msat } from '../core/money.js';
import { ApprovalError, type ApprovalReason } from './errors.js';
import { findPublicKey } from './keys.js';
import { approvalMessage, proposalDigest } from './message.js';
import type { ApprovalKey, ApprovalPolicy, ApprovalRow, ApprovalStore, ProposalTerms } from './types.js';
import { sealVerified, type VerifiedApproval } from './verified.js';

export interface VerifyContext {
  readonly keys: readonly ApprovalKey[];
  readonly proposal: ProposalTerms;
  readonly policy: ApprovalPolicy;
  /** The database clock, ms since the Unix epoch. */
  readonly now: number;
}

const MAX_TOKEN_BYTES = 4096;
const TOKEN_FIELDS = [
  'v', 'proposal_id', 'proposal_digest', 'policy_sha256', 'approved_max_fee_msat', 'approved_max_cltv_delta',
  'expires_at', 'nonce', 'key_id', 'signature',
] as const;

interface Token {
  readonly proposalId: string;
  readonly proposalDigest: Buffer;
  readonly policySha256: Buffer;
  readonly fee: Msat;
  readonly cltv: number;
  readonly expiresAt: number;
  readonly nonce: Buffer;
  readonly keyId: string;
  readonly signature: Buffer;
}

function malformed(): ApprovalError {
  return new ApprovalError(1, 'MALFORMED_TOKEN');
}

function hexField(value: unknown, bytes: number): Buffer {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${String(bytes * 2)}}$`).test(value)) throw malformed();
  return Buffer.from(value, 'hex');
}

function decimalField(value: unknown, max: bigint): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value)) throw malformed();
  const parsed = BigInt(value);
  if (parsed > max) throw malformed();
  return parsed;
}

/** Step 1: the token parses, with exact field lengths and nothing extra. */
function parseToken(text: string): Token {
  if (Buffer.byteLength(text, 'utf8') > MAX_TOKEN_BYTES) throw malformed();
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw malformed();
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw malformed();
  const fields = value as Record<string, unknown>;
  const names = Object.keys(fields);
  if (names.length !== TOKEN_FIELDS.length || !TOKEN_FIELDS.every(name => Object.hasOwn(fields, name))) throw malformed();
  if (fields['v'] !== 1) throw malformed();
  const proposalId = fields['proposal_id'];
  if (typeof proposalId !== 'string' || proposalId === '' || proposalId.length > 128) throw malformed();
  const expiresAt = fields['expires_at'];
  if (typeof expiresAt !== 'number' || !Number.isSafeInteger(expiresAt) || expiresAt < 0) throw malformed();
  const keyId = fields['key_id'];
  hexField(keyId, 16);
  return {
    proposalId,
    proposalDigest: hexField(fields['proposal_digest'], 32),
    policySha256: hexField(fields['policy_sha256'], 32),
    fee: decimalField(fields['approved_max_fee_msat'], MAX_INT64) as Msat,
    cltv: Number(decimalField(fields['approved_max_cltv_delta'], 2n ** 32n - 1n)),
    expiresAt,
    nonce: hexField(fields['nonce'], 32),
    keyId: keyId as string,
    signature: hexField(fields['signature'], 64),
  };
}

function signatureValid(token: Omit<Token, 'proposalId'>, publicKey: KeyObject): boolean {
  const message = approvalMessage({
    proposalDigest: token.proposalDigest, policySha256: token.policySha256, approvedMaxFeeMsat: token.fee,
    approvedMaxCltvDelta: token.cltv, expiresAt: token.expiresAt, nonce: token.nonce, keyId: Buffer.from(token.keyId, 'hex'),
  });
  return verify(null, message, publicKey, token.signature);
}

function isTime(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

/** The context's clock and limits are whole non-negative numbers; anything else refuses. */
function validContext(ctx: VerifyContext): boolean {
  return [ctx.now, ctx.proposal.expiresAt, ctx.proposal.maxCltvDelta, ctx.policy.maxCltvDelta, ctx.policy.approvalMaxTtlSeconds].every(isTime)
    && typeof ctx.proposal.maxFeeMsat === 'bigint' && typeof ctx.policy.maxFeeMsat === 'bigint';
}

/** Steps 2 to 7; returns the first failure, or null. */
function check(token: Token, ctx: VerifyContext): ApprovalReason | null {
  const publicKey = findPublicKey(ctx.keys, token.keyId);
  if (publicKey === null) return 'UNKNOWN_KEY_ID';
  if (!signatureValid(token, publicKey)) return 'BAD_SIGNATURE';
  if (token.proposalId !== ctx.proposal.id || !Buffer.from(proposalDigest(ctx.proposal)).equals(token.proposalDigest)) return 'DIGEST_MISMATCH';
  if (token.policySha256.toString('hex') !== ctx.policy.sha256 || ctx.proposal.policySha256 !== ctx.policy.sha256) return 'POLICY_MISMATCH';
  if (token.fee > ctx.proposal.maxFeeMsat || token.fee > ctx.policy.maxFeeMsat) return 'FEE_CEILING_EXCEEDED';
  if (token.cltv > ctx.proposal.maxCltvDelta || token.cltv > ctx.policy.maxCltvDelta) return 'CLTV_DELTA_UNSAFE';
  if (token.expiresAt <= ctx.now) return 'APPROVAL_EXPIRED';
  if (token.expiresAt > ctx.proposal.expiresAt) return 'EXPIRY_TOO_LATE';
  return null;
}

/** Verifies an approval token for the stored proposal and stores it; the nonce is consumed by the insert. */
export function verifyAndStoreApproval(token: string, ctx: VerifyContext, store: ApprovalStore, deps: { newId(): string }): ApprovalRow {
  const parsed = parseToken(token);
  if (!validContext(ctx)) throw new ApprovalError(2, 'INVALID_REQUEST');
  const failure = check(parsed, ctx);
  if (failure !== null) throw new ApprovalError(1, failure);
  if (parsed.expiresAt > ctx.now + ctx.policy.approvalMaxTtlSeconds * 1000) throw new ApprovalError(1, 'EXPIRY_TOO_LATE');
  const row: ApprovalRow = {
    id: deps.newId(),
    proposal_id: parsed.proposalId,
    key_id: parsed.keyId,
    nonce: parsed.nonce.toString('hex'),
    expires_at: parsed.expiresAt,
    signature: parsed.signature.toString('base64'),
    max_fee_msat: parsed.fee,
    max_cltv_delta: parsed.cltv,
    created_at: ctx.now,
  };
  if (store.insert(row) === 'nonce-used') throw new ApprovalError(1, 'NONCE_REUSED');
  return row;
}

/** The stored row as the token it was created from; null when a stored field is malformed. */
function rowToken(row: ApprovalRow, ctx: VerifyContext): Token | null {
  if (!/^[0-9a-f]{32}$/.test(row.key_id) || !/^[0-9a-f]{64}$/.test(row.nonce) || !/^[0-9a-f]{64}$/.test(ctx.policy.sha256)) return null;
  const signature = Buffer.from(row.signature, 'base64');
  if (signature.length !== 64 || signature.toString('base64') !== row.signature) return null;
  if (!Number.isSafeInteger(row.expires_at) || row.expires_at < 0 || !Number.isInteger(row.max_cltv_delta) || row.max_cltv_delta < 0 || row.max_cltv_delta > 2 ** 32 - 1) return null;
  const fee: unknown = row.max_fee_msat;
  if (typeof fee !== 'bigint' || fee < 0n || fee > MAX_INT64) return null;
  return {
    proposalId: row.proposal_id,
    proposalDigest: Buffer.from(proposalDigest(ctx.proposal)),
    policySha256: Buffer.from(ctx.policy.sha256, 'hex'),
    fee: fee as Msat,
    cltv: row.max_cltv_delta,
    expiresAt: row.expires_at,
    nonce: Buffer.from(row.nonce, 'hex'),
    keyId: row.key_id,
    signature,
  };
}

/**
 * Claim-time check: returns a stored approval of the proposal that still verifies against the
 * stored proposal, the active policy and the configured keys; otherwise a safety refusal (exit 5).
 */
export function requireStoredApproval(proposalId: string, ctx: VerifyContext, store: ApprovalStore): ApprovalRow {
  const rows = store.listByProposal(proposalId);
  if (rows.length === 0) throw new ApprovalError(5, 'NO_APPROVAL');
  if (!validContext(ctx)) throw new ApprovalError(5, 'INVALID_REQUEST');
  let failure: ApprovalReason = 'NO_APPROVAL';
  for (const row of rows) {
    if (row.proposal_id !== proposalId || ctx.proposal.id !== proposalId) {
      failure = 'DIGEST_MISMATCH';
      continue;
    }
    const token = rowToken(row, ctx);
    if (token === null) {
      failure = 'MALFORMED_TOKEN';
      continue;
    }
    const reason = check(token, ctx);
    if (reason === null) return row;
    failure = reason;
  }
  throw new ApprovalError(5, failure);
}

export function verifiedStoredApproval(ctx: VerifyContext, store: ApprovalStore): VerifiedApproval {
  const row = requireStoredApproval(ctx.proposal.id, ctx, store);
  return sealVerified({ approvalId: row.id, proposalId: row.proposal_id, keyId: row.key_id, nonce: row.nonce,
    proposalDigest: Buffer.from(proposalDigest(ctx.proposal)).toString('hex'), policySha256: ctx.policy.sha256,
    approvedMaxFeeMsat: row.max_fee_msat, approvedMaxCltvDelta: row.max_cltv_delta, expiresAt: row.expires_at });
}
