import type { ExecutionPolicy } from '../core/execution.js';
import type { TerminalTimes } from '../persistence/index.js';

/** Committed fees plus this attempt's worst-case fee must stay within the budget; reaching it exactly is allowed. */
export function budgetAdmits(committedMsat: bigint, maxFeeMsat: bigint, budgetMsat: bigint): boolean {
  return committedMsat + maxFeeMsat <= budgetMsat;
}

/** A new execution fits while fewer than `maxInFlight` executions of the node are in SUBMITTING, IN_FLIGHT or UNKNOWN. */
export function inFlightAdmits(inFlight: number, maxInFlight: number): boolean {
  return inFlight < maxInFlight;
}

/**
 * Whether a cooldown covers the channel pair at database time `now`. A terminal time later than `now` (a clock step)
 * keeps the cooldown active.
 */
export function cooldownActive(now: number, last: TerminalTimes, policy: Pick<ExecutionPolicy, 'cooldownAfterFailureMs' | 'cooldownAfterSuccessMs'>): boolean {
  const within = (at: number | null, windowMs: number): boolean => at !== null && now - at < windowMs;
  return within(last.failureAt, policy.cooldownAfterFailureMs) || within(last.successAt, policy.cooldownAfterSuccessMs);
}
