// `actions status` and the rendering of `actions execute` outcomes. No node calls.
import { ExitCode } from '../core/exit-codes.js';
import type { ExecutionStatus } from '../core/execution.js';
import { envelope, renderEnvelope, terminalText } from '../output/index.js';
import { openDatabase, PersistenceError, type Database, type ExecutionEvent, type ExecutionView } from '../persistence/index.js';

const STATUS_COMMAND = 'actions status';
const EXECUTE_COMMAND = 'actions execute';
export const OUTCOME_UNKNOWN_MESSAGE = 'outcome unknown — run `fluxwarden reconcile`; do not retry';

export interface CommandResult {
  readonly exitCode: number;
  readonly output: string;
}

export interface ExecuteOutcome {
  readonly executionId: string;
  readonly exit: number;
  readonly step: string | null;
}

/**
 * SPEC §10.3 AS3: 0 for a verified success, 5 for a verified failure or a cancellation, 7 while a payment may have
 * reached the node (SPEC §10.2). CLAIMED and PREFLIGHT have sent nothing and exit 0.
 */
export function statusExit(status: ExecutionStatus): number {
  if (status === 'VERIFIED_FAILURE' || status === 'CANCELLED') return ExitCode.SAFETY_REFUSAL;
  return unresolved(status) ? ExitCode.OUTCOME_UNKNOWN : ExitCode.SUCCESS;
}

/** A payment may have reached the node and its outcome is not confirmed. */
function unresolved(status: ExecutionStatus): boolean {
  return status === 'SUBMITTING' || status === 'IN_FLIGHT' || status === 'UNKNOWN';
}

function terminal(status: ExecutionStatus): boolean {
  return status === 'VERIFIED_SUCCESS' || status === 'VERIFIED_FAILURE' || status === 'CANCELLED';
}

function parseRoute(text: string | null): Record<string, unknown> | null {
  if (text === null) return null;
  const parsed: unknown = JSON.parse(text);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('route_json is not an object');
  return parsed as Record<string, unknown>;
}

function resultOf(view: ExecutionView, events: readonly ExecutionEvent[]): Record<string, unknown> {
  return {
    execution_id: view.executionId,
    status: view.status,
    fence_epoch: view.fenceEpoch.toString(),
    lease_expires_at: view.leaseExpiresAt,
    payment_hash: view.paymentHash,
    route: parseRoute(view.routeJson),
    planned_fee_msat: view.plannedFeeMsat === null ? null : view.plannedFeeMsat.toString(),
    actual_fee_msat: view.actualFeeMsat === null ? null : view.actualFeeMsat.toString(),
    delta_status: view.deltaStatus,
    error_code: view.errorCode,
    events: events.filter(event => event.from !== event.to).map(event => ({ from: event.from, to: event.to, at: event.at })),
  };
}

function statusText(view: ExecutionView, events: readonly ExecutionEvent[]): string {
  const lines = [
    `execution ${view.executionId}`,
    `status: ${view.status}`,
    `fence epoch: ${view.fenceEpoch.toString()}`,
    `lease expires at: ${view.leaseExpiresAt === null ? '-' : new Date(view.leaseExpiresAt).toISOString()}`,
    `payment hash: ${view.paymentHash ?? '-'}`,
    `planned fee: ${view.plannedFeeMsat === null ? '-' : `${view.plannedFeeMsat.toString()} msat`}`,
    `actual fee: ${view.actualFeeMsat === null ? '-' : `${view.actualFeeMsat.toString()} msat`}`,
    `delta: ${view.deltaStatus ?? '-'}`,
    `error: ${view.errorCode ?? '-'}`,
    'events:',
    ...events.map(event => `  ${new Date(event.at).toISOString()} ${event.from ?? '-'} -> ${event.to}`),
  ];
  if (unresolved(view.status)) lines.push(OUTCOME_UNKNOWN_MESSAGE);
  else if (!terminal(view.status)) lines.push('not submitted yet: no payment has been sent');
  return terminalText(`${lines.join('\n')}\n`);
}

function failure(json: boolean, code: number, message: string): CommandResult {
  return {
    exitCode: code,
    output: json ? renderEnvelope(envelope(STATUS_COMMAND, null, { code, step: null, message })) : terminalText(`error: ${message}\n`),
  };
}

function open(databasePath: string): Database | null {
  try {
    return openDatabase(databasePath, { readOnly: true });
  } catch {
    return null;
  }
}

function render(db: Database, executionId: string, json: boolean): CommandResult {
  const view = db.executions.view(executionId);
  if (view === null) return failure(json, ExitCode.INVALID_INPUT, `no execution with id ${executionId}`);
  const events = db.executions.events(executionId);
  return {
    exitCode: statusExit(view.status),
    output: json ? renderEnvelope(envelope(STATUS_COMMAND, resultOf(view, events), null)) : statusText(view, events),
  };
}

/** The stored record of one execution and its events (SPEC §10.3 AS1-AS3). */
export function actionsStatus(input: { databasePath: string; executionId: string; json: boolean }): CommandResult {
  const db = open(input.databasePath);
  if (db === null) return failure(input.json, ExitCode.INVALID_INPUT, 'the database could not be opened');
  try {
    return render(db, input.executionId, input.json);
  } finally {
    db.close();
  }
}

function pause(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise<void>(resolve => {
    const done = (): void => { clearTimeout(timer); signal.removeEventListener('abort', done); resolve(); };
    const timer = setTimeout(done, ms);
    signal.addEventListener('abort', done, { once: true });
  });
}

/**
 * `actions status --watch --json`: one transition object per line as the events are stored, then the status document
 * once the execution is terminal. An interrupt ends the watch with exit 6 and changes nothing.
 */
export async function watchActionsStatus(
  input: { databasePath: string; executionId: string; pollMs: number; signal: AbortSignal },
  emit: (line: string) => void,
): Promise<{ exitCode: number }> {
  // A read-only connection sees the file as it was opened (SQLite immutable mode when no writer is active), so each
  // poll opens its own; a read that overlapped a writer fails as BUSY and is repeated at the next poll.
  let last = 0n;
  let opened = false;
  for (;;) {
    if (input.signal.aborted) return { exitCode: ExitCode.INTERRUPTED };
    const db = open(input.databasePath);
    if (db === null) {
      if (opened) { await pause(input.pollMs, input.signal); continue; }
      emit(failure(true, ExitCode.INVALID_INPUT, 'the database could not be opened').output);
      return { exitCode: ExitCode.INVALID_INPUT };
    }
    opened = true;
    try {
      const view = db.executions.view(input.executionId);
      if (view === null) {
        const missing = render(db, input.executionId, true);
        emit(missing.output);
        return { exitCode: missing.exitCode };
      }
      const lines: string[] = [];
      let seen = last;
      for (const event of db.executions.events(input.executionId, last)) {
        lines.push(`${JSON.stringify({ event: 'transition', execution_id: input.executionId, from: event.from, to: event.to, at: event.at })}
`);
        seen = event.id;
      }
      const final = terminal(view.status) ? render(db, input.executionId, true) : null;
      for (const line of lines) emit(line);
      last = seen;
      if (final !== null) {
        emit(final.output);
        return { exitCode: final.exitCode };
      }
    } catch (error) {
      if (!(error instanceof PersistenceError && error.code === 'BUSY')) throw error;
    } finally {
      db.close();
    }
    await pause(input.pollMs, input.signal);
  }
}

/** The document or text `actions execute` prints for a dispatch outcome (SPEC §10.3 AE9-AE13). */
export function renderExecuteOutcome(outcome: ExecuteOutcome, json: boolean): CommandResult {
  const exitCode = outcome.exit;
  if (exitCode === ExitCode.SUCCESS) {
    const result = { execution_id: outcome.executionId, status: 'VERIFIED_SUCCESS' };
    return { exitCode, output: json ? renderEnvelope(envelope(EXECUTE_COMMAND, result, null)) : terminalText(`execution ${outcome.executionId}: VERIFIED_SUCCESS\n`) };
  }
  const message = exitCode === ExitCode.OUTCOME_UNKNOWN
    ? OUTCOME_UNKNOWN_MESSAGE
    : `execution ${outcome.executionId} ended with ${outcome.step ?? 'an error'}`;
  const step = exitCode === ExitCode.OUTCOME_UNKNOWN && outcome.step === null ? 'OUTCOME_UNKNOWN' : outcome.step;
  return {
    exitCode,
    output: json
      ? renderEnvelope(envelope(EXECUTE_COMMAND, null, { code: exitCode, step, message }))
      : terminalText(`execution ${outcome.executionId}: ${step ?? 'error'}\n${message}\n`),
  };
}
