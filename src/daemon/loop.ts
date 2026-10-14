import type { AlertInput, RaiseResult } from './alerts.js';

/**
 * The daemon's observe → diagnose → propose loop (SPEC.md §10.4 DM4–DM6). It collects, proposes and
 * reconciles; it never executes a proposal, which is always an explicit `actions execute` (INV-02).
 */

/** The collector's answer for one node: one snapshot transaction, or the node is offline. */
export type CollectOutcome = { kind: 'ok' } | { kind: 'offline'; reason: string };

/** The planner's answer for one node: diagnose, plan and store. */
export type ProposeOutcome = { kind: 'proposed'; proposalId: string } | { kind: 'no-action' };

/** One reconciler pass and the alert conditions it found. */
export interface ReconcilePass { readonly alerts: readonly AlertInput[] }

export interface DaemonDeps {
  readonly nodes: readonly string[];
  readonly cycleMs: number;
  readonly monotonic: { now(): number };
  /** Resolves after `ms` or once `signal` aborts; never rejects. */
  sleep(ms: number, signal: AbortSignal): Promise<void>;
  readonly collector: { collect(node: string): Promise<CollectOutcome> };
  readonly planner: { propose(node: string): Promise<ProposeOutcome> };
  readonly reconciler: { reconcile(): Promise<ReconcilePass> };
  readonly alerts: { raise(alert: AlertInput): RaiseResult };
  /** Linked into the binary; the daemon never calls it. */
  readonly executor: { execute(proposalId: string): Promise<unknown> };
  /** Fenced release of the leases the daemon holds (DM6). */
  releaseLeases(): Promise<void>;
  /** Every rejected step and every raise() that throws is reported once, as it happens (DM5). */
  readonly log: { error(step: DaemonStep, message: string): void };
}

export type DaemonStep = 'collect' | 'propose' | 'reconcile' | 'alert';

/** The error's class only: a node or file error text can carry what the redactor has not seen. */
const describe = (error: unknown): string => `failed (${error instanceof Error ? error.name : typeof error})`;

/** A step's failure is the step's own: it is logged, the node or pass is skipped and the loop goes on. */
async function attempt<T>(deps: DaemonDeps, name: DaemonStep, step: () => Promise<T>): Promise<T | undefined> {
  try {
    return await step();
  } catch (error) {
    deps.log.error(name, describe(error));
    return undefined;
  }
}

async function cycle(deps: DaemonDeps, signal: AbortSignal): Promise<void> {
  const stopped = (): boolean => signal.aborted;
  for (const node of deps.nodes) {
    if (stopped()) return;
    const collected = await attempt(deps, 'collect', () => deps.collector.collect(node));
    if (collected?.kind !== 'ok' || stopped()) continue;
    await attempt(deps, 'propose', () => deps.planner.propose(node));
  }
  if (stopped()) return;
  const pass = await attempt(deps, 'reconcile', () => deps.reconciler.reconcile());
  for (const alert of pass?.alerts ?? []) {
    try {
      deps.alerts.raise(alert);
    } catch (error) {
      // An alert that cannot be written is logged, and raised again by the next pass that still finds its condition.
      deps.log.error('alert', describe(error));
    }
  }
}

/**
 * Cycle k is due at start + k × cycleMs; cycle 0 runs at once. After a cycle the loop sleeps until the next
 * due time strictly after now, so cycles missed while the host was suspended are not replayed. The signal is
 * checked before every step; a step in progress is awaited. After the abort the leases are released once.
 */
export async function runDaemon(deps: DaemonDeps, signal: AbortSignal): Promise<{ exitCode: 0 }> {
  if (!Number.isFinite(deps.cycleMs) || deps.cycleMs <= 0) throw new Error('daemon: cycleMs is a positive duration');
  const stopped = (): boolean => signal.aborted;
  const start = deps.monotonic.now();
  let k = 0;
  while (!stopped()) {
    await cycle(deps, signal);
    k = Math.max(k + 1, Math.floor((deps.monotonic.now() - start) / deps.cycleMs) + 1);
    const due = start + k * deps.cycleMs;
    for (let now = deps.monotonic.now(); !stopped() && now < due; now = deps.monotonic.now()) {
      await deps.sleep(due - now, signal);
    }
  }
  await deps.releaseLeases();
  return { exitCode: 0 };
}

/** SIGINT and SIGTERM abort the controller; the returned function removes both listeners. */
export function bindShutdownSignals(
  target: { on(event: string, listener: () => void): unknown; off(event: string, listener: () => void): unknown },
  controller: AbortController,
): () => void {
  const stop = (): void => { controller.abort(); };
  target.on('SIGINT', stop);
  target.on('SIGTERM', stop);
  return () => {
    target.off('SIGINT', stop);
    target.off('SIGTERM', stop);
  };
}
