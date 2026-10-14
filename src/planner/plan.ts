// Candidate pairs for circular rebalancing, sized and filtered before any route is sought (SPEC.md §7.4).
import { compareKeys, type ChannelDiagnosis, type Clock, type OkDiagnosis, type PlanningPolicy } from './diagnose.js';

/** SPEC.md §7.5. */
export type RefusalCode =
  | 'NO_FEASIBLE_ROUTE' | 'FEE_CEILING_EXCEEDED' | 'PPM_CEILING_EXCEEDED' | 'CLTV_DELTA_UNSAFE' | 'RESERVE_FLOOR'
  | 'BUDGET_EXHAUSTED' | 'COOLDOWN_ACTIVE' | 'STALE_SNAPSHOT' | 'INSUFFICIENT_HISTORY' | 'CAPABILITY_UNSUPPORTED'
  | 'SINGLE_PATH_UNAVAILABLE' | 'REPEATED_CHANNEL' | 'SAME_PEER' | 'FIRST_HOP_SPENDABLE' | 'LAST_HOP_RECEIVABLE';

/** A terminal execution that starts a cooldown. */
export interface CooldownEvent {
  readonly outcome: 'VERIFIED_SUCCESS' | 'VERIFIED_FAILURE';
  readonly sourceChannel: string;
  readonly targetChannel: string;
  /** Unix milliseconds of the terminal transition. */
  readonly at: number;
}

/** A budget reservation (SPEC.md §6.6). */
export interface BudgetReservation {
  readonly state: 'HELD' | 'CONSUMED' | 'RELEASED';
  /** The approved max fee, the worst case. */
  readonly reservedMsat: bigint;
  /** The actual fee once CONSUMED. */
  readonly consumedMsat: bigint | null;
  /** Unix milliseconds the reservation was made. */
  readonly at: number;
}

export interface PlanInput {
  readonly diagnosis: OkDiagnosis;
  readonly policy: PlanningPolicy;
  readonly cooldowns: readonly CooldownEvent[];
  readonly reservations: readonly BudgetReservation[];
  /** This node's executions in SUBMITTING, IN_FLIGHT or UNKNOWN. */
  readonly inFlight: number;
  readonly clock: Clock;
}

/** A pair refusal: a SPEC.md §7.5 code, or the §7.4 no-action wording when the source's own deficit is too small to move. */
export type PairCode = RefusalCode | 'BALANCED_OR_INSUFFICIENT_SURPLUS';

export interface Candidate {
  readonly sourceChannel: string;
  readonly targetChannel: string;
  readonly principalMsat: bigint;
}

export interface PairRefusal {
  readonly sourceChannel: string;
  readonly targetChannel: string;
  readonly code: PairCode;
  /** COOLDOWN_ACTIVE only: the longest remaining cooldown in milliseconds. */
  readonly remainingMs: number | null;
}

export interface PlanResult {
  readonly action: 'CANDIDATES' | 'NO_ACTION';
  readonly reason: 'BALANCED_OR_INSUFFICIENT_SURPLUS' | null;
  /** Ranked: principal descending, then source key, then target key. */
  readonly candidates: readonly Candidate[];
  /** Sorted by source key, then target key. */
  readonly refusals: readonly PairRefusal[];
}

const min = (first: bigint, ...rest: bigint[]): bigint => rest.reduce((low, value) => value < low ? value : low, first);

function keys(list: readonly string[], excluded: ReadonlySet<string>): string[] {
  return [...new Set(list)].filter(key => !excluded.has(key)).sort(compareKeys);
}

/**
 * Fees committed in the current budget period: HELD reservations at their worst case and CONSUMED ones at the
 * actual fee. A HELD reservation counts whatever its age, because its attempt may still be charged.
 */
export function committedFees(reservations: readonly BudgetReservation[], policy: PlanningPolicy, now: number): bigint {
  const start = now - policy.budget.period;
  let total = 0n;
  for (const reservation of reservations) {
    if (reservation.state === 'HELD') total += reservation.reservedMsat;
    else if (reservation.state === 'CONSUMED' && reservation.at > start) total += reservation.consumedMsat ?? reservation.reservedMsat;
  }
  return total;
}

/** The longest remaining cooldown over (source, target), or null when none is active (SPEC.md §7.2). */
export function cooldownRemaining(source: string, target: string, cooldowns: readonly CooldownEvent[], policy: PlanningPolicy, now: number): number | null {
  let remaining: number | null = null;
  for (const event of cooldowns) {
    const covers = event.outcome === 'VERIFIED_FAILURE'
      ? event.sourceChannel === source && event.targetChannel === target
      : [event.sourceChannel, event.targetChannel].some(key => key === source || key === target);
    if (!covers) continue;
    const end = event.at + (event.outcome === 'VERIFIED_FAILURE' ? policy.cooldown_after_failure : policy.cooldown_after_success);
    // A start after the clock reading means the clock stepped back; the cooldown stays active.
    if (now >= end && event.at <= now) continue;
    const left = end - now;
    if (remaining === null || left > remaining) remaining = left;
  }
  return remaining;
}

export function plan(input: PlanInput): PlanResult {
  const { diagnosis, policy } = input;
  const now = input.clock.now();
  const excluded = new Set(policy.exclude_channels);
  const sources = keys(diagnosis.starved, excluded);
  const targets = keys(diagnosis.donors, excluded);
  if (sources.length === 0 || targets.length === 0) {
    return { action: 'NO_ACTION', reason: 'BALANCED_OR_INSUFFICIENT_SURPLUS', candidates: [], refusals: [] };
  }

  const rows = new Map<string, ChannelDiagnosis>(diagnosis.channels.map(row => [row.channelKey, row]));
  const row = (key: string): ChannelDiagnosis => {
    const found = rows.get(key);
    if (!found) throw new Error('plan: diagnosis lists a channel it has no figures for');
    return found;
  };
  // SPEC.md §7.4: budget and max_in_flight are checked at plan time, both refused as BUDGET_EXHAUSTED.
  const budgetExhausted = committedFees(input.reservations, policy, now) + policy.fees.max_fee_msat > policy.budget.msat ||
    input.inFlight >= policy.max_in_flight;

  const candidates: Candidate[] = [];
  const refusals: PairRefusal[] = [];
  const refuse = (sourceChannel: string, targetChannel: string, code: PairCode, remainingMs: number | null = null): void => {
    refusals.push({ sourceChannel, targetChannel, code, remainingMs });
  };

  for (const sourceChannel of sources) {
    const source = row(sourceChannel);
    for (const targetChannel of targets) {
      if (sourceChannel === targetChannel) continue;
      const target = row(targetChannel);
      if (source.state !== 'ACTIVE' || target.state !== 'ACTIVE') { refuse(sourceChannel, targetChannel, 'NO_FEASIBLE_ROUTE'); continue; }
      const remaining = cooldownRemaining(sourceChannel, targetChannel, input.cooldowns, policy, now);
      if (remaining !== null) { refuse(sourceChannel, targetChannel, 'COOLDOWN_ACTIVE', remaining); continue; }
      if (budgetExhausted) { refuse(sourceChannel, targetChannel, 'BUDGET_EXHAUSTED'); continue; }
      // INV-14: after sending principal + worst-case fee the source keeps min_channel_reserve_msat.
      const reserveTerm = source.spendableMsat - policy.fees.max_fee_msat - policy.amounts.min_channel_reserve_msat;
      const principalMsat = min(source.inboundDeficitMsat, target.inboundSurplusMsat, reserveTerm, policy.amounts.max_principal_msat);
      if (principalMsat < policy.amounts.min_principal_msat) {
        refuse(sourceChannel, targetChannel,
          reserveTerm === principalMsat ? 'RESERVE_FLOOR'
            : target.inboundSurplusMsat === principalMsat ? 'LAST_HOP_RECEIVABLE'
              : 'BALANCED_OR_INSUFFICIENT_SURPLUS');
        continue;
      }
      candidates.push({ sourceChannel, targetChannel, principalMsat });
    }
  }

  candidates.sort((a, b) =>
    a.principalMsat !== b.principalMsat ? (a.principalMsat > b.principalMsat ? -1 : 1)
      : compareKeys(a.sourceChannel, b.sourceChannel) || compareKeys(a.targetChannel, b.targetChannel));
  return { action: candidates.length > 0 ? 'CANDIDATES' : 'NO_ACTION', reason: null, candidates, refusals };
}
