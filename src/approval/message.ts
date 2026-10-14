// The proposal digest and the signed approval message, byte for byte as the security model fixes them.
import { createHash } from 'node:crypto';
import type { Msat } from '../core/money.js';
import type { ProposalTerms } from './types.js';

const PROPOSAL_PREFIX = Buffer.from('FluxWarden-proposal-v1\u0000', 'utf8');
const APPROVAL_PREFIX = Buffer.from('FluxWarden-approval-v1\u0000', 'utf8');
const UINT64_MAX = 2n ** 64n - 1n;
const UINT32_MAX = 2 ** 32 - 1;

/** Length of the signed message: prefix 23, digest 32, policy 32, fee 8, CLTV 4, expiry 8, nonce 32, key id 16. */
export const APPROVAL_MESSAGE_LENGTH = 155;

function lengthPrefixed(text: string): Buffer {
  const bytes = Buffer.from(text, 'utf8');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

/** SHA-256 over the domain prefix and the length-prefixed proposal fields (32 bytes). */
export function proposalDigest(terms: ProposalTerms): Uint8Array {
  const fields = [
    terms.id, terms.nodePubkey, terms.sourceChannelKey, terms.targetChannelKey,
    terms.principalMsat.toString(), terms.maxFeeMsat.toString(), terms.maxFeePpm.toString(), terms.exemptFeeMsat.toString(),
    String(terms.maxCltvDelta), terms.policySha256, String(terms.expiresAt),
  ];
  const hash = createHash('sha256').update(PROPOSAL_PREFIX);
  for (const field of fields) hash.update(lengthPrefixed(field));
  return new Uint8Array(hash.digest());
}

export interface ApprovalMessageFields {
  readonly proposalDigest: Uint8Array;
  readonly policySha256: Uint8Array;
  readonly approvedMaxFeeMsat: Msat;
  readonly approvedMaxCltvDelta: number;
  readonly expiresAt: number;
  readonly nonce: Uint8Array;
  readonly keyId: Uint8Array;
}

function fixed(bytes: Uint8Array, length: number, name: string): Uint8Array {
  if (bytes.byteLength !== length) throw new RangeError(`approval message: ${name} must be ${String(length)} bytes`);
  return bytes;
}

/** The signed message; every field has a fixed length and is refused outside its width. */
export function approvalMessage(fields: ApprovalMessageFields): Uint8Array {
  const fee: bigint = fields.approvedMaxFeeMsat;
  if (typeof fee !== 'bigint' || fee < 0n || fee > UINT64_MAX) throw new RangeError('approval message: fee cap outside u64');
  const cltv = fields.approvedMaxCltvDelta;
  if (!Number.isInteger(cltv) || cltv < 0 || cltv > UINT32_MAX) throw new RangeError('approval message: CLTV cap outside u32');
  const expires = fields.expiresAt;
  if (!Number.isSafeInteger(expires) || expires < 0) throw new RangeError('approval message: expiry outside u64');
  const numbers = Buffer.alloc(20);
  numbers.writeBigUInt64BE(fee, 0);
  numbers.writeUInt32BE(cltv, 8);
  numbers.writeBigUInt64BE(BigInt(expires), 12);
  const message = Buffer.concat([
    APPROVAL_PREFIX,
    fixed(fields.proposalDigest, 32, 'proposal digest'),
    fixed(fields.policySha256, 32, 'policy digest'),
    numbers,
    fixed(fields.nonce, 32, 'nonce'),
    fixed(fields.keyId, 16, 'key id'),
  ]);
  return new Uint8Array(message);
}
