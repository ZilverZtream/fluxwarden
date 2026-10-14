// The proposal document of a stored proposal: its columns, its route and its explanation tree.
import type { StoredProposal } from '../persistence/index.js';
import { PROPOSAL_ID_PREFIX, type ExplanationTree, type ProposalDocument, type RouteDocument } from '../planner/proposal.js';

function parseObject(text: string, what: string): Record<string, unknown> {
  const value: unknown = JSON.parse(text);
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`stored ${what} is not an object`);
  return value as Record<string, unknown>;
}

function tree(text: string): ExplanationTree {
  const value = parseObject(text, 'explanation');
  if (!Array.isArray(value['inputs']) || !Array.isArray(value['candidates']) || typeof value['exempt_fee_msat'] !== 'string') {
    throw new Error('stored explanation is incomplete');
  }
  return value as unknown as ExplanationTree;
}

function required<T>(value: T | null, what: string): T {
  if (value === null) throw new Error(`stored proposal has no ${what}`);
  return value;
}

/** A PROPOSED proposal at or past its expiry is shown as EXPIRED. */
export function proposalDocument(stored: StoredProposal, now: number): ProposalDocument {
  const explanation = tree(stored.reasonJson);
  return {
    proposal_id: `${PROPOSAL_ID_PREFIX}${stored.id}`,
    node: stored.nodeName,
    action: stored.actionType,
    status: stored.status === 'PROPOSED' && stored.expiresAt <= now ? 'EXPIRED' : stored.status,
    demand_source: stored.demandSource,
    source_channel: stored.sourceChannelKey,
    target_channel: stored.targetChannelKey,
    principal_msat: stored.principalMsat === null ? null : stored.principalMsat.toString(),
    caps: {
      max_fee_msat: required(stored.maxFeeMsat, 'fee cap').toString(),
      max_fee_ppm: Number(required(stored.maxFeePpm, 'ppm cap')),
      exempt_fee_msat: explanation.exempt_fee_msat,
      max_cltv_delta: required(stored.maxCltvDelta, 'CLTV cap'),
    },
    route: stored.routeJson === null ? null : parseObject(stored.routeJson, 'route') as unknown as RouteDocument,
    policy_sha256: stored.policySha256,
    digest: stored.digest,
    created_at: stored.createdAt,
    expires_at: stored.expiresAt,
    inputs: explanation.inputs,
    candidates: explanation.candidates,
    approvals: [],
  };
}
