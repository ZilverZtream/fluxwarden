import type { Msat } from '../core/money.js';

/** The stored proposal fields the proposal digest covers. */
export interface ProposalTerms {
  readonly id: string;
  readonly nodePubkey: string;
  readonly sourceChannelKey: string;
  readonly targetChannelKey: string;
  readonly principalMsat: Msat;
  readonly maxFeeMsat: Msat;
  readonly maxFeePpm: bigint;
  readonly exemptFeeMsat: Msat;
  readonly maxCltvDelta: number;
  /** 64 lowercase hex characters. */
  readonly policySha256: string;
  /** Milliseconds since the Unix epoch. */
  readonly expiresAt: number;
}

/** The active policy version, as far as approvals depend on it. */
export interface ApprovalPolicy {
  readonly sha256: string;
  readonly maxFeeMsat: Msat;
  readonly maxCltvDelta: number;
  readonly approvalMaxTtlSeconds: number;
  readonly maxSnapshotAgeSeconds: number;
}

/** A configured approval public key. */
export interface ApprovalKey {
  /** 32 lowercase hex characters: the first 16 bytes of SHA-256 of the raw public key. */
  readonly keyId: string;
  /** Base64 of the raw 32-byte Ed25519 public key. */
  readonly publicKey: string;
}

/** An approvals row (append-only; nonce is unique). The signature is base64. */
export interface ApprovalRow {
  readonly id: string;
  readonly proposal_id: string;
  readonly key_id: string;
  readonly nonce: string;
  readonly expires_at: number;
  readonly signature: string;
  readonly max_fee_msat: Msat;
  readonly max_cltv_delta: number;
  readonly created_at: number;
}

export interface ApprovalStore {
  /** Inserts the row unless its nonce is already stored; nothing is written then. */
  insert(row: ApprovalRow): 'inserted' | 'nonce-used';
  listByProposal(proposalId: string): readonly ApprovalRow[];
}
