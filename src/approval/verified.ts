import type { ApprovalTerms, VerifiedApproval } from '../core/execution.js';

export type { VerifiedApproval } from '../core/execution.js';

/** Marks terms as verified. Only approval verification calls this, after it has checked the signature and key set. */
export function sealVerified(terms: ApprovalTerms): VerifiedApproval {
  return terms as VerifiedApproval;
}
