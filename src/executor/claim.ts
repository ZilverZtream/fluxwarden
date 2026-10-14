import type { VerifiedApproval } from '../approval/verified.js';
import { RECLAIMABLE, type ExecutionPolicy, type ExecutionStatus } from '../core/execution.js';
import type { Database, StoredAuthority } from '../persistence/index.js';
import { budgetAdmits, cooldownActive, inFlightAdmits } from './budget.js';

export interface ClaimInput {
  readonly approval: VerifiedApproval;
  readonly policy: ExecutionPolicy;
  /** key_ids of the currently configured approval keys; an approval signed by any other key no longer authorises. */
  readonly approvalKeyIds: readonly string[];
  readonly workerId: string;
  readonly leaseMs: number;
}

/**
 * APPROVAL_INVALID and POLICY_CHANGED name the two approval failures that have no policy refusal code: the stored
 * approval or proposal does not match or has expired, and the active policy is not the approved one.
 */
export type ClaimStep = 'claimed-elsewhere' | 'BUDGET_EXHAUSTED' | 'COOLDOWN_ACTIVE' | 'APPROVAL_INVALID' | 'POLICY_CHANGED';

export type ClaimOutcome =
  | { readonly ok: true; readonly executionId: string; readonly fenceEpoch: bigint }
  | { readonly ok: false; readonly exit: 5; readonly step: ClaimStep; readonly executionId: string | null };

/** A claim outcome that also says which status the held row is in (CLAIMED, or PREFLIGHT after a re-claim). */
export type HeldOutcome =
  | { readonly ok: true; readonly executionId: string; readonly fenceEpoch: bigint; readonly status: ExecutionStatus }
  | Extract<ClaimOutcome, { ok: false }>;

function authorityHolds(stored: StoredAuthority | null, approval: VerifiedApproval, now: number): stored is StoredAuthority {
  if (stored === null) return false;
  return stored.keyId === approval.keyId
    && stored.nonce === approval.nonce
    && stored.approvalExpiresAt === approval.expiresAt
    && stored.approvedMaxFeeMsat === approval.approvedMaxFeeMsat
    && stored.approvedMaxCltvDelta === approval.approvedMaxCltvDelta
    && stored.proposalStatus === 'APPROVED'
    && stored.proposalDigest === approval.proposalDigest
    && stored.approvalExpiresAt > now
    && stored.proposalExpiresAt > now
    && stored.approvalExpiresAt <= stored.proposalExpiresAt
    && stored.proposalMaxFeeMsat !== null && stored.approvedMaxFeeMsat <= stored.proposalMaxFeeMsat
    && stored.proposalMaxCltvDelta !== null && stored.approvedMaxCltvDelta <= stored.proposalMaxCltvDelta;
}

/**
 * Claims the execution of an approved proposal in one transaction: approval and policy checks, insert or re-claim
 * (only CLAIMED/PREFLIGHT with an expired lease), and for a new execution the budget reservation, the node's in-flight
 * limit and the cooldown checks. A budget, in-flight or cooldown refusal is recorded as a CANCELLED execution.
 */
export function claimHeld(db: Database, input: ClaimInput): HeldOutcome {
  const { approval, policy, approvalKeyIds, workerId, leaseMs } = input;
  return db.executions.claim((scope): HeldOutcome => {
    const now = scope.now();
    const existing = scope.existing(approval.proposalId);
    const refuse = (step: ClaimStep, executionId: string | null = existing?.executionId ?? null): HeldOutcome =>
      ({ ok: false, exit: 5, step, executionId });

    const stored = scope.authority(approval.approvalId, approval.proposalId);
    if (!approvalKeyIds.includes(approval.keyId) || !authorityHolds(stored, approval, now)) return refuse('APPROVAL_INVALID');
    if (approval.policySha256 !== policy.sha256 || stored.policySha256 !== policy.sha256) return refuse('POLICY_CHANGED');

    if (existing !== null) {
      if (existing.approvalId === approval.approvalId && RECLAIMABLE.includes(existing.status)) {
        const reclaimed = scope.reclaim(approval.proposalId, workerId, leaseMs);
        if (reclaimed !== null) return { ok: true, ...reclaimed };
      }
      return refuse('claimed-elsewhere');
    }
    if (stored.sourceChannelId === null || stored.targetChannelId === null) return refuse('APPROVAL_INVALID');

    const cancel = (step: 'BUDGET_EXHAUSTED' | 'COOLDOWN_ACTIVE'): HeldOutcome =>
      refuse(step, scope.insertCancelled({ proposalId: approval.proposalId, approvalId: approval.approvalId, workerId, errorCode: step }));
    if (!budgetAdmits(scope.committedMsat(policy.budget.periodMs), approval.approvedMaxFeeMsat, policy.budget.msat)) return cancel('BUDGET_EXHAUSTED');
    if (!inFlightAdmits(scope.inFlight(stored.nodeId), policy.maxInFlight)) return cancel('BUDGET_EXHAUSTED');
    if (cooldownActive(now, scope.lastTerminal(stored.sourceChannelId, stored.targetChannelId), policy)) return cancel('COOLDOWN_ACTIVE');

    const claimed = scope.insertClaimed({
      proposalId: approval.proposalId, approvalId: approval.approvalId, workerId, leaseMs, reservedMsat: approval.approvedMaxFeeMsat,
    });
    return { ok: true, ...claimed };
  });
}

export function claimExecution(db: Database, input: ClaimInput): ClaimOutcome {
  const outcome = claimHeld(db, input);
  if (!outcome.ok) return outcome;
  return { ok: true, executionId: outcome.executionId, fenceEpoch: outcome.fenceEpoch };
}
