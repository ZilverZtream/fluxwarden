import { ExitCode } from '../cli/exit-codes.js';
import { verifyLedger, type VerifyReport } from '../ledger/verify.js';
import type { Database } from '../persistence/index.js';
import {
  reconcileAccounting, type AccountingReport, type AccountingSource, type ReconcileWindow, type ReconExecution,
} from '../reconciler/accounting.js';

const DURATION = /^([1-9][0-9]{0,9}|0)(s|m|h|d)$/;
const UNIT_MS = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 } as const;
const DEFAULT_SINCE_MS = UNIT_MS.d;
const ISO_UTC = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,3})?Z$/;

function durationMs(text: string): number | null {
  const match = DURATION.exec(text);
  if (match === null) return null;
  const [, digits = '', unit = 's'] = match;
  const ms = Number(digits) * UNIT_MS[unit as keyof typeof UNIT_MS];
  return Number.isSafeInteger(ms) ? ms : null;
}

/**
 * `--since` is a duration before now; `--until` accepts a duration or the documented UTC ISO timestamp.
 * A malformed duration, or a since that does not lie before until, is invalid input (SPEC.md §10.3 G1).
 */
export function parseReconcileWindow(flags: { since?: string; until?: string }, nowMs: number):
  | { ok: true; window: ReconcileWindow } | { ok: false; exitCode: typeof ExitCode.INVALID_INPUT; message: string } {
  const since = flags.since === undefined ? DEFAULT_SINCE_MS : durationMs(flags.since);
  const untilDuration = flags.until === undefined ? 0 : durationMs(flags.until);
  const untilMs = flags.until !== undefined && ISO_UTC.test(flags.until) ? Date.parse(flags.until) : null;
  if (since === null) return { ok: false, exitCode: ExitCode.INVALID_INPUT, message: '--since is not a duration such as 30m, 24h or 7d' };
  if (untilDuration === null && (untilMs === null || !Number.isSafeInteger(untilMs))) return { ok: false, exitCode: ExitCode.INVALID_INPUT, message: '--until is not a duration or UTC ISO timestamp' };
  const window = { sinceMs: nowMs - since, untilMs: untilMs ?? nowMs - (untilDuration ?? 0) };
  if (window.sinceMs >= window.untilMs) return { ok: false, exitCode: ExitCode.INVALID_INPUT, message: '--since must lie before --until' };
  return { ok: true, window };
}

export type ReconcileExit = typeof ExitCode.SUCCESS | typeof ExitCode.OUTCOME_UNKNOWN | typeof ExitCode.INVARIANT_BREACH | typeof ExitCode.RECONCILIATION_ALERT;

export interface ReconcileResult {
  readonly exitCode: ReconcileExit;
  readonly report: { readonly verify: VerifyReport; readonly accounting: AccountingReport | null; readonly postedJournalIds: string[] };
}

/**
 * Ledger verification, then the comparison with node accounting for the window (SPEC.md §10.3 RC3, RC4).
 * A broken ledger is an invariant breach and nothing is compared or posted. Difference journals are posted
 * in one transaction and are idempotent by reference, so a rerun posts nothing new.
 */
export async function runReconcile(input: {
  db: Database; window: ReconcileWindow; executions: readonly ReconExecution[];
  sources: readonly AccountingSource[]; clock: { now(): number };
}): Promise<ReconcileResult> {
  const book = input.db.ledger.book();
  const verify = verifyLedger(book);
  if (!verify.ok) return { exitCode: ExitCode.INVARIANT_BREACH, report: { verify, accounting: null, postedJournalIds: [] } };
  const feeObservations: { executionId: string; reference: string; feeMsat: bigint; occurredAt: number }[] = [];
  const accounting = await reconcileAccounting({
    window: input.window, journals: book.journals, executions: input.executions, sources: input.sources, occurredAt: input.clock.now(),
    observeFee: observation => { feeObservations.push(observation); },
  });
  const { postedJournalIds, feeBreach } = input.db.executions.postFeeCorrections(feeObservations);
  const pending = input.executions.some(execution => execution.status === 'IN_FLIGHT' || execution.status === 'UNKNOWN');
  const exitCode = feeBreach ? ExitCode.INVARIANT_BREACH : pending ? ExitCode.OUTCOME_UNKNOWN : accounting.differences.length > 0 ? ExitCode.RECONCILIATION_ALERT : ExitCode.SUCCESS;
  return { exitCode, report: { verify, accounting, postedJournalIds } };
}
