// Approval signing on the operator's machine. This is the only module that takes the private key
// out of its Secret container: to sign, and to write a newly generated key to an owner-only file.
// No function here returns the key's bytes or passes them to a caller.
import { createPrivateKey, createPublicKey, sign, type KeyObject } from 'node:crypto';
import type { Msat } from '../core/money.js';
import { revealSecret, Secret } from '../core/secret.js';
import { readOwnerOnlyFile } from '../platform/owner-only.js';
import { writeOwnerOnlyFile, type OwnerOnlyWrite } from '../output/private-file.js';
import { ApprovalError } from './errors.js';
import { findPublicKey, keyIdOf, rawPublicKey } from './keys.js';
import { approvalMessage, proposalDigest } from './message.js';
import type { ApprovalKey, ApprovalPolicy, ProposalTerms } from './types.js';

export interface ApprovalRequest {
  readonly proposal: ProposalTerms;
  readonly policy: ApprovalPolicy;
  /** The configured approval public keys; the signing key must be one of them. */
  readonly keys: readonly ApprovalKey[];
  readonly approvedMaxFeeMsat?: Msat;
  readonly approvedMaxCltvDelta?: number;
  readonly expiresAt?: number;
  /** When the newest snapshot behind the proposal was observed (ms since the Unix epoch). */
  readonly snapshotObservedAt: number;
}

function readSigningKey(path: string): Secret {
  try {
    return new Secret(readOwnerOnlyFile(path, 4096));
  } catch { throw new ApprovalError(2, 'INVALID_KEY'); }
}

export function createApprovalFromKeyFile(request: ApprovalRequest, path: string, deps: SignDeps): string {
  return createApproval(request, readSigningKey(path), deps);
}

export interface SignDeps {
  now(): number;
  randomBytes(size: number): Uint8Array;
}

function privateKeyObject(privateKey: Secret): KeyObject {
  let key: KeyObject;
  try {
    key = createPrivateKey({ key: Buffer.from(revealSecret(privateKey)), format: 'pem' });
  } catch {
    throw new ApprovalError(2, 'INVALID_KEY');
  }
  if (key.asymmetricKeyType !== 'ed25519') throw new ApprovalError(2, 'INVALID_KEY');
  return key;
}

/** Writes the private key as a PKCS#8 PEM file at `path`, owner-only; an existing file is never changed. */
export function writePrivateKeyFile(privateKey: Secret, path: string): OwnerOnlyWrite {
  const pem = privateKeyObject(privateKey).export({ format: 'pem', type: 'pkcs8' });
  return writeOwnerOnlyFile(path, Buffer.from(pem));
}

/**
 * Signs an approval of `request.proposal`. Caps default to the proposal's and may only tighten
 * them; the expiry defaults to the earliest of the proposal's expiry and now + approval_max_ttl.
 * Returns the token JSON.
 */
function isTime(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

export function createApproval(request: ApprovalRequest, privateKey: Secret, deps: SignDeps): string {
  const { proposal, policy } = request;
  const now = deps.now();
  // Clocks, expiries and limits that are not whole non-negative numbers refuse; a comparison with NaN never passes a check.
  if (![now, proposal.expiresAt, policy.approvalMaxTtlSeconds, policy.maxSnapshotAgeSeconds].every(isTime)) throw new ApprovalError(2, 'INVALID_REQUEST');
  const key = privateKeyObject(privateKey);
  const raw = rawPublicKey(createPublicKey(key));
  const keyId = keyIdOf(raw);
  const configured = findPublicKey(request.keys, keyId);
  if (configured === null || !rawPublicKey(configured).equals(raw)) throw new ApprovalError(2, 'UNKNOWN_KEY_ID');

  if (!/^[0-9a-f]{64}$/.test(proposal.policySha256) || proposal.policySha256 !== policy.sha256) throw new ApprovalError(1, 'POLICY_MISMATCH');

  const fee: bigint = request.approvedMaxFeeMsat ?? proposal.maxFeeMsat;
  const cltv = request.approvedMaxCltvDelta ?? proposal.maxCltvDelta;
  if (typeof fee !== 'bigint' || fee < 0n || !isTime(cltv) || !isTime(proposal.maxCltvDelta) || !isTime(policy.maxCltvDelta)) throw new ApprovalError(2, 'INVALID_REQUEST');
  if (fee > proposal.maxFeeMsat || fee > policy.maxFeeMsat) throw new ApprovalError(1, 'FEE_CEILING_EXCEEDED');
  if (cltv > proposal.maxCltvDelta || cltv > policy.maxCltvDelta) throw new ApprovalError(1, 'CLTV_DELTA_UNSAFE');

  const latest = Math.min(proposal.expiresAt, now + policy.approvalMaxTtlSeconds * 1000);
  const expiresAt = request.expiresAt ?? latest;
  if (!isTime(expiresAt)) throw new ApprovalError(2, 'INVALID_REQUEST');
  if (expiresAt > latest) throw new ApprovalError(1, 'EXPIRY_TOO_LATE');
  if (expiresAt <= now) throw new ApprovalError(1, 'APPROVAL_EXPIRED');

  // A snapshot time ahead of this clock cannot be shown fresh, so it counts as stale.
  const observedAt = request.snapshotObservedAt;
  if (!isTime(observedAt) || observedAt > now || now - observedAt > policy.maxSnapshotAgeSeconds * 1000) throw new ApprovalError(5, 'STALE_SNAPSHOT');

  const nonce = deps.randomBytes(32);
  if (nonce.byteLength !== 32) throw new Error('approval: the random source returned the wrong number of bytes');
  const digest = proposalDigest(proposal);
  const message = approvalMessage({
    proposalDigest: digest, policySha256: Buffer.from(policy.sha256, 'hex'), approvedMaxFeeMsat: fee as Msat,
    approvedMaxCltvDelta: cltv, expiresAt, nonce, keyId: Buffer.from(keyId, 'hex'),
  });
  const signature = sign(null, message, key);
  return JSON.stringify({
    v: 1,
    proposal_id: proposal.id,
    proposal_digest: Buffer.from(digest).toString('hex'),
    policy_sha256: policy.sha256,
    approved_max_fee_msat: fee.toString(),
    approved_max_cltv_delta: String(cltv),
    expires_at: expiresAt,
    nonce: Buffer.from(nonce).toString('hex'),
    key_id: keyId,
    signature: signature.toString('hex'),
  });
}
