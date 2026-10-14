// `liquidity plan`: diagnosis, candidate pairs, read-only route assessment and validation, and one stored
// proposal with its digest, expiry and explanation tree (SPEC.md §7.4, §10.3 item 5). No node mutation.
import { ExitCode } from '../core/exit-codes.js';
import type { Msat } from '../core/money.js';
import type { NormalizedChannel } from '../core/normalize.js';
import { isNoRoute, validateRoute, type CandidateRoute, type EffectivePolicy, type NoRoute, type RouteChannel, type RouteConstraints } from '../core/route.js';
import { ulid } from '../core/ulid.js';
import { envelope, renderEnvelope, terminalText } from '../output/index.js';
import type { Database } from '../persistence/index.js';
import { compareKeys, diagnose, type Clock, type PlanningPolicy } from '../planner/diagnose.js';
import { plan, type BudgetReservation, type CooldownEvent } from '../planner/plan.js';
import {
  bestPair, proposalDigest, renderProposal, routeDocument, routeFeeLimit, sortCandidates,
  type AssessedPair, type CandidateDocument, type ExplanationTree, type InputDocument,
} from '../planner/proposal.js';
import type { CommandOutcome } from './liquidity-explain.js';
import { proposalDocument } from './proposal-document.js';

const COMMAND = 'liquidity plan';

/** The read-only view of a node the planner gets: route discovery and nothing that moves funds. */
export interface RouteFinder {
  buildCircularRoute(c: RouteConstraints): Promise<CandidateRoute | NoRoute>;
}

export interface LiquidityPlanInput {
  readonly db: Database;
  readonly node: { readonly id: string; readonly name: string; readonly pubkey: string; readonly implementation: 'lnd' | 'cln' };
  /** The latest snapshot of each channel. */
  readonly channels: readonly NormalizedChannel[];
  readonly policy: PlanningPolicy;
  readonly policySha256: string;
  readonly policyCanonicalJson: string;
  readonly blockHeight: number;
  readonly finalCltvDelta: number;
  readonly cooldowns: readonly CooldownEvent[];
  readonly reservations: readonly BudgetReservation[];
  readonly routes: RouteFinder;
  readonly clock: Clock;
}

function refusal(message: string, step: string, code: number): CommandOutcome {
  return {
    exitCode: code,
    json: renderEnvelope(envelope(COMMAND, null, { code, step, message })),
    text: terminalText(`error: ${message}\n`),
  };
}

function inputs(channels: readonly NormalizedChannel[], now: number): InputDocument[] {
  return [...channels].sort((a, b) => compareKeys(a.channelKey, b.channelKey)).map(channel => ({
    channel: channel.channelKey,
    confidence: channel.confidence,
    caveat: channel.caveat,
    snapshot_age_ms: now - channel.observedAt,
    spendable_msat: channel.spendableMsat.toString(),
    receivable_msat: channel.receivableMsat.toString(),
  }));
}

export async function liquidityPlan(input: LiquidityPlanInput): Promise<CommandOutcome> {
  const { policy, node } = input;
  if (!Number.isSafeInteger(policy.proposal_ttl) || policy.proposal_ttl <= 0) throw new RangeError('proposal_ttl must be a positive number of milliseconds');
  const now = input.clock.now();
  const diagnosis = diagnose({ nodeName: node.name, channels: input.channels, policy, horizonMs: null, clock: input.clock });
  if (diagnosis.status === 'STALE_SNAPSHOT') {
    const listed = diagnosis.stale.map(entry => `${entry.channelKey} (${String(entry.ageMs)} ms)`).join(', ');
    return refusal(`snapshot age outside 0..${String(policy.max_snapshot_age)} ms for ${node.name}: ${listed}`, 'STALE_SNAPSHOT', ExitCode.SAFETY_REFUSAL);
  }

  const candidates: CandidateDocument[] = [];
  const valid: AssessedPair[] = [];
  if (diagnosis.status === 'OK') {
    const inFlight = input.db.executions.claim(scope => scope.inFlight(node.id));
    const pairs = plan({ diagnosis, policy, cooldowns: input.cooldowns, reservations: input.reservations, inFlight, clock: input.clock });
    for (const refused of pairs.refusals) {
      // The source's own deficit is too small to move: a no-action reason (SPEC.md §7.4), not a §7.5 refusal.
      if (refused.code === 'BALANCED_OR_INSUFFICIENT_SURPLUS') continue;
      candidates.push({ source_channel: refused.sourceChannel, target_channel: refused.targetChannel, principal_msat: null, code: refused.code, detail: null, chosen: false });
    }
    const byKey = new Map(input.channels.map(channel => [channel.channelKey, channel]));
    const routeChannels: RouteChannel[] = input.channels.map(channel => ({
      channelKey: channel.channelKey, scid: channel.scid, peerPubkey: channel.peerPubkey, state: channel.state,
      spendableMsat: channel.spendableMsat as Msat, receivableMsat: channel.receivableMsat as Msat,
    }));
    const effective: EffectivePolicy = {
      maxFeeMsat: policy.fees.max_fee_msat as Msat,
      maxFeePpm: policy.fees.max_fee_ppm,
      exemptFeeMsat: policy.fees.exempt_fee_msat as Msat,
      maxCltvDelta: policy.routing.max_cltv_delta,
      minChannelReserveMsat: policy.amounts.min_channel_reserve_msat as Msat,
    };
    for (const pair of pairs.candidates) {
      const principal = pair.principalMsat.toString();
      const record = (code: CandidateDocument['code'], detail: string | null): void => {
        candidates.push({ source_channel: pair.sourceChannel, target_channel: pair.targetChannel, principal_msat: principal, code, detail, chosen: false });
      };
      const source = byKey.get(pair.sourceChannel);
      const target = byKey.get(pair.targetChannel);
      if (source === undefined || target === undefined || source.scid === null || target.scid === null) { record('NO_FEASIBLE_ROUTE', null); continue; }
      const constraints: RouteConstraints = {
        selfPubkey: node.pubkey,
        implementation: node.implementation,
        sourceScid: source.scid,
        targetScid: target.scid,
        outPeer: source.peerPubkey,
        inPeer: target.peerPubkey,
        principalMsat: pair.principalMsat as Msat,
        maxFeeMsat: routeFeeLimit(policy, pair.principalMsat) as Msat,
        maxCltvDelta: policy.routing.max_cltv_delta,
        finalCltvDelta: input.finalCltvDelta,
        blockHeight: input.blockHeight,
      };
      const found = await input.routes.buildCircularRoute(constraints);
      if (isNoRoute(found)) { record(found.code, found.reason); continue; }
      const verdict = validateRoute(found, constraints, routeChannels, effective);
      if (!verdict.ok) { record(verdict.code, null); continue; }
      record(null, null);
      valid.push({ sourceChannel: pair.sourceChannel, targetChannel: pair.targetChannel, principalMsat: pair.principalMsat, verdict });
    }
  }

  const chosen = bestPair(valid);
  const sorted = sortCandidates(candidates).map(candidate => (
    chosen !== undefined && candidate.source_channel === chosen.sourceChannel && candidate.target_channel === chosen.targetChannel && candidate.code === null
      ? { ...candidate, chosen: true } : candidate));

  const id = ulid(now);
  const expiresAt = now + policy.proposal_ttl;
  const fees = policy.fees;
  const digest = proposalDigest({
    proposalId: id,
    nodePubkey: node.pubkey,
    sourceChannelKey: chosen?.sourceChannel ?? '',
    targetChannelKey: chosen?.targetChannel ?? '',
    principalMsat: chosen?.principalMsat ?? 0n,
    maxFeeMsat: fees.max_fee_msat,
    maxFeePpm: fees.max_fee_ppm,
    exemptFeeMsat: fees.exempt_fee_msat,
    maxCltvDelta: policy.routing.max_cltv_delta,
    policySha256: input.policySha256,
    expiresAt,
  });
  const explanation: ExplanationTree = {
    demand_source: 'TARGETS',
    exempt_fee_msat: fees.exempt_fee_msat.toString(),
    inputs: inputs(input.channels, now),
    candidates: sorted,
  };
  input.db.proposals.insert({
    id,
    nodeId: node.id,
    policy: { sha256: input.policySha256, canonicalJson: input.policyCanonicalJson },
    actionType: chosen === undefined ? 'NO_ACTION' : 'CIRCULAR_REBALANCE',
    sourceChannelKey: chosen?.sourceChannel ?? null,
    targetChannelKey: chosen?.targetChannel ?? null,
    principalMsat: chosen?.principalMsat ?? null,
    maxFeeMsat: fees.max_fee_msat,
    maxFeePpm: fees.max_fee_ppm,
    maxCltvDelta: policy.routing.max_cltv_delta,
    routeJson: chosen === undefined ? null : JSON.stringify(routeDocument(chosen.verdict)),
    demandSource: 'TARGETS',
    digest,
    reasonJson: JSON.stringify(explanation),
    createdAt: now,
    expiresAt,
  });

  const stored = input.db.proposals.find(id);
  if (stored === null) throw new Error('the stored proposal could not be read back');
  const doc = proposalDocument(stored, now);
  return {
    exitCode: ExitCode.SUCCESS,
    json: renderEnvelope(envelope(COMMAND, doc as unknown as Record<string, unknown>, null)),
    text: terminalText(renderProposal(doc)),
  };
}
