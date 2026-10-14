export type ApprovalReason =
  | 'MALFORMED_TOKEN' | 'UNKNOWN_KEY_ID' | 'BAD_SIGNATURE' | 'DIGEST_MISMATCH' | 'POLICY_MISMATCH'
  | 'FEE_CEILING_EXCEEDED' | 'CLTV_DELTA_UNSAFE' | 'APPROVAL_EXPIRED' | 'EXPIRY_TOO_LATE' | 'NONCE_REUSED'
  | 'STALE_SNAPSHOT' | 'NO_APPROVAL' | 'INVALID_KEY' | 'INVALID_REQUEST';

const MESSAGES: Readonly<Record<ApprovalReason, string>> = {
  MALFORMED_TOKEN: 'the approval token is malformed',
  UNKNOWN_KEY_ID: 'the approval key is not configured',
  BAD_SIGNATURE: 'the approval signature does not verify',
  DIGEST_MISMATCH: 'the approval was signed for a different proposal',
  POLICY_MISMATCH: 'the approval was signed for a different policy version',
  FEE_CEILING_EXCEEDED: 'the approved fee cap exceeds the proposal or the policy',
  CLTV_DELTA_UNSAFE: 'the approved CLTV cap exceeds the proposal or the policy',
  APPROVAL_EXPIRED: 'the approval has expired',
  EXPIRY_TOO_LATE: 'the approval expires after the proposal or after now + approval_max_ttl (a signing clock ahead of the database clock also causes this; there is no tolerance)',
  NONCE_REUSED: 'the approval nonce has already been used',
  STALE_SNAPSHOT: 'the channel snapshot is older than max_snapshot_age',
  NO_APPROVAL: 'the proposal has no stored approval',
  INVALID_KEY: 'the approval private key is not a usable Ed25519 key',
  INVALID_REQUEST: 'the approval request or its clock, expiry or limits are invalid',
};

/** A refused approval: exit 1 for a policy violation, 2 for invalid input, 5 for a safety refusal. */
export class ApprovalError extends Error {
  override readonly name = 'ApprovalError';
  readonly exitCode: 1 | 2 | 5;
  readonly reason: ApprovalReason;

  constructor(exitCode: 1 | 2 | 5, reason: ApprovalReason) {
    super(`${reason}: ${MESSAGES[reason]}`);
    this.exitCode = exitCode;
    this.reason = reason;
  }
}
