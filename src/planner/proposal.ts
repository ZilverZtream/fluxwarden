// Proposals: the digest an approval is bound to, the choice among validated routes, and the proposal
// document that `liquidity plan` prints and stores and `liquidity explain` renders (SPEC.md §7.4, §7.6).
import { proposalDigest as digestBytes } from '../approval/message.js';
import type { Msat } from '../core/money.js';
import type { RouteVerdict } from '../core/route.js';
import { compareKeys, type PlanningPolicy } from './diagnose.js';
import type { RefusalCode } from './plan.js';

/** The fields the proposal digest covers, in digest order (SECURITY.md §4.1). */
export interface DigestFields {
  /** The stored 26-character ULID, without the `prop_` output prefix. */
  readonly proposalId: string;
  readonly nodePubkey: string;
  readonly sourceChannelKey: string;
  readonly targetChannelKey: string;
  readonly principalMsat: bigint;
  readonly maxFeeMsat: bigint;
  readonly maxFeePpm: bigint;
  readonly exemptFeeMsat: bigint;
  readonly maxCltvDelta: number;
  /** 64 lowercase hex, digested as that text. */
  readonly policySha256: string;
  /** Unix milliseconds, digested as its decimal text. */
  readonly expiresAt: number;
}

/** SHA-256 over "FluxWarden-proposal-v1" || 0x00 and the length-framed fields, as 64 lowercase hex. */
export function proposalDigest(fields: DigestFields): string {
  return Buffer.from(digestBytes({
    id: fields.proposalId,
    nodePubkey: fields.nodePubkey,
    sourceChannelKey: fields.sourceChannelKey,
    targetChannelKey: fields.targetChannelKey,
    principalMsat: fields.principalMsat as Msat,
    maxFeeMsat: fields.maxFeeMsat as Msat,
    maxFeePpm: fields.maxFeePpm,
    exemptFeeMsat: fields.exemptFeeMsat as Msat,
    maxCltvDelta: fields.maxCltvDelta,
    policySha256: fields.policySha256,
    expiresAt: fields.expiresAt,
  })).toString('hex');
}

/**
 * The absolute fee limit sent to the node: the msat cap, or the ppm cap applied to the principal when that
 * is lower, but never below the exemption (SECURITY.md §4.2).
 */
export function routeFeeLimit(policy: PlanningPolicy, principalMsat: bigint): bigint {
  const fees = policy.fees;
  const fromPpm = (fees.max_fee_ppm * principalMsat) / 1_000_000n;
  const allowed = fromPpm > fees.exempt_fee_msat ? fromPpm : fees.exempt_fee_msat;
  return allowed < fees.max_fee_msat ? allowed : fees.max_fee_msat;
}

export type ValidVerdict = Extract<RouteVerdict, { ok: true }>;

export interface AssessedPair {
  readonly sourceChannel: string;
  readonly targetChannel: string;
  readonly principalMsat: bigint;
  readonly verdict: ValidVerdict;
}

/** Score = principal − fee; ties go to the lower fee, then the source key, then the target key. */
export function bestPair(pairs: readonly AssessedPair[]): AssessedPair | undefined {
  let best: AssessedPair | undefined;
  for (const pair of pairs) {
    if (best === undefined) { best = pair; continue; }
    const score = pair.principalMsat - pair.verdict.feeMsat;
    const bestScore = best.principalMsat - best.verdict.feeMsat;
    const better = score !== bestScore ? score > bestScore
      : pair.verdict.feeMsat !== best.verdict.feeMsat ? pair.verdict.feeMsat < best.verdict.feeMsat
        : (compareKeys(pair.sourceChannel, best.sourceChannel) || compareKeys(pair.targetChannel, best.targetChannel)) < 0;
    if (better) best = pair;
  }
  return best;
}

// ---- the proposal document (schemas/output/liquidity-plan.json, result) ----

export interface RouteDocument {
  readonly hops: readonly { readonly channel: string; readonly node_out: string; readonly amount_msat: string; readonly cltv: number }[];
  readonly fee_msat: string;
  readonly fee_ppm: number;
  readonly cltv_delta: number;
  readonly padding: 1 | 3;
}

export interface InputDocument {
  readonly channel: string;
  readonly confidence: 'NODE_REPORTED' | 'DERIVED_ESTIMATE';
  readonly caveat: string | null;
  readonly snapshot_age_ms: number;
  readonly spendable_msat: string;
  readonly receivable_msat: string;
}

export interface CandidateDocument {
  readonly source_channel: string;
  readonly target_channel: string;
  /** null for a pair refused before route discovery. */
  readonly principal_msat: string | null;
  readonly code: RefusalCode | null;
  /** The node's no-route text, display only. */
  readonly detail: string | null;
  readonly chosen: boolean;
}

/** What reason_json keeps beside the proposal's own columns: the explanation tree. */
export interface ExplanationTree {
  readonly demand_source: 'TARGETS' | 'EWMA';
  readonly exempt_fee_msat: string;
  readonly inputs: readonly InputDocument[];
  readonly candidates: readonly CandidateDocument[];
}

export interface ProposalDocument {
  readonly proposal_id: string;
  readonly node: string;
  readonly action: 'CIRCULAR_REBALANCE' | 'NO_ACTION';
  readonly status: 'PROPOSED' | 'APPROVED' | 'REJECTED' | 'EXPIRED';
  readonly demand_source: 'TARGETS' | 'EWMA';
  readonly source_channel: string | null;
  readonly target_channel: string | null;
  readonly principal_msat: string | null;
  readonly caps: { readonly max_fee_msat: string; readonly max_fee_ppm: number; readonly exempt_fee_msat: string; readonly max_cltv_delta: number };
  readonly route: RouteDocument | null;
  readonly policy_sha256: string;
  readonly digest: string;
  readonly created_at: number;
  readonly expires_at: number;
  readonly inputs: readonly InputDocument[];
  readonly candidates: readonly CandidateDocument[];
  readonly approvals: readonly Record<string, unknown>[];
}

export const PROPOSAL_ID_PREFIX = 'prop_';

export function routeDocument(verdict: ValidVerdict): RouteDocument {
  return {
    hops: verdict.route.hops.map(hop => ({ channel: hop.scid, node_out: hop.nodeIdOut, amount_msat: hop.amountOutMsat.toString(), cltv: hop.cltvOut })),
    fee_msat: verdict.feeMsat.toString(),
    fee_ppm: Number(verdict.feePpm),
    cltv_delta: verdict.cltvDelta,
    padding: verdict.padding,
  };
}

/** Candidates in source, then target key order. */
export function sortCandidates(candidates: readonly CandidateDocument[]): CandidateDocument[] {
  return [...candidates].sort((a, b) => compareKeys(a.source_channel, b.source_channel) || compareKeys(a.target_channel, b.target_channel));
}

/** The human rendering of a proposal document; the caller escapes it for the terminal. */
export function renderProposal(doc: ProposalDocument): string {
  const lines: string[] = [];
  lines.push(`proposal ${doc.proposal_id}: ${doc.action}, ${doc.status}`);
  lines.push(`node ${doc.node}, demand source ${doc.demand_source}`);
  if (doc.source_channel !== null && doc.target_channel !== null && doc.principal_msat !== null) {
    lines.push(`source ${doc.source_channel} -> target ${doc.target_channel}, principal ${doc.principal_msat} msat`);
  }
  const caps = doc.caps;
  lines.push(`caps: max fee ${caps.max_fee_msat} msat, max ${String(caps.max_fee_ppm)} ppm above ${caps.exempt_fee_msat} msat, max CLTV delta ${String(caps.max_cltv_delta)}`);
  const route = doc.route;
  if (route !== null && doc.principal_msat !== null) {
    lines.push('route:');
    route.hops.forEach((hop, index) => {
      lines.push(`  ${String(index + 1)}. ${hop.channel} -> ${hop.node_out}: ${hop.amount_msat} msat, expiry ${String(hop.cltv)}`);
    });
    const ppmOk = BigInt(route.fee_msat) <= BigInt(caps.exempt_fee_msat) || route.fee_ppm <= caps.max_fee_ppm;
    lines.push(`fee ${route.fee_msat} msat (V3: ${route.fee_msat} <= ${caps.max_fee_msat})`);
    lines.push(`ppm ${String(route.fee_ppm)} (V4: ceil(${route.fee_msat} x 1000000 / ${doc.principal_msat}) = ${String(route.fee_ppm)}${ppmOk ? ' within' : ' over'} ${String(caps.max_fee_ppm)} ppm or ${caps.exempt_fee_msat} msat)`);
    lines.push(`CLTV delta ${String(route.cltv_delta)} + padding ${String(route.padding)} <= ${String(caps.max_cltv_delta)} (V5)`);
  } else {
    lines.push('route: none');
  }
  lines.push(`policy sha256 ${doc.policy_sha256}`);
  lines.push(`digest ${doc.digest}`);
  lines.push(`created ${new Date(doc.created_at).toISOString()}, expires ${new Date(doc.expires_at).toISOString()}`);
  lines.push('inputs:');
  for (const input of doc.inputs) {
    lines.push(`  ${input.channel}: ${input.confidence}, spendable ${input.spendable_msat} msat, receivable ${input.receivable_msat} msat, snapshot age ${String(input.snapshot_age_ms)} ms`);
    if (input.caveat !== null) lines.push(`    caveat: ${input.caveat}`);
  }
  lines.push('candidates:');
  if (doc.candidates.length === 0) lines.push('  none');
  for (const candidate of doc.candidates) {
    const amount = candidate.principal_msat === null ? '' : ` (${candidate.principal_msat} msat)`;
    const outcome = candidate.chosen ? 'chosen' : candidate.code ?? 'valid, not chosen';
    lines.push(`  ${candidate.source_channel} -> ${candidate.target_channel}${amount}: ${outcome}${candidate.detail === null ? '' : `: ${candidate.detail}`}`);
  }
  lines.push(`approvals: ${doc.approvals.length === 0 ? 'none' : String(doc.approvals.length)}`);
  return `${lines.join('\n')}\n`;
}
