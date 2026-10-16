#!/usr/bin/env node
// The `fluxwarden` binary: process-level handlers, signals and the exit code around main().
import { readFileSync } from 'node:fs';
import { processOutput, processRenderOutput, type Output, type RenderOutput } from '../output/index.js';
import { parseArgs } from './args.js';
import { ExitCode } from './exit-codes.js';
import { main } from './main.js';
import { reportInternal, reportInterrupted } from './report.js';

const argv = process.argv.slice(2);
let fallbackExit: NodeJS.Timeout | undefined;
let queuedWrites = 0;
let flushBoundary = 0;
const processStreams = processOutput();
const output: Output = {
  write(stream, text, done) {
    const sequence = ++queuedWrites;
    processStreams.write(stream, text, () => {
      // A scheduler pause can leave the watchdog overdue just as an earlier write completes.
      // Give the report its existing flush window from that observed output progress.
      if (fallbackExit !== undefined && sequence <= flushBoundary) armFallbackExit();
      done?.();
    });
  },
  wrote: stream => processStreams.wrote(stream),
};
let json = false;
/** The command's own exit code, once main() has returned. */
let commandCode: number = ExitCode.SUCCESS;
let pendingCode: number | null = null;
let paymentMayHaveStarted = false;
let breached = false;
let interrupted = false;
/** This file has written its interrupt or internal-error report. */
let reported = false;
/** How a long-running command (the daemon) stops at the first signal, once it has registered. */
let gracefulStop: (() => void) | null = null;
let stopRequested = false;
let exitPending = false;
const renderedOutputs = new Set<RenderOutput>();

async function finalizeRenderedOutputs(): Promise<void> {
  await Promise.all([...renderedOutputs].map(output => output.finalize()));
}

function exitFinalized(): void {
  armFallbackExit();
  void finalizeRenderedOutputs().then(exitNow, exitNow);
}

// A breach or a possibly submitted unresolved payment survives interruption: 8 > 7 > 6.
// Decide at exit too, after an aborted command has recorded its durable outcome.
function currentCode(): number {
  const code = pendingCode ?? commandCode;
  if (breached || code === ExitCode.INVARIANT_BREACH) return ExitCode.INVARIANT_BREACH;
  if (code === ExitCode.OUTCOME_UNKNOWN) return ExitCode.OUTCOME_UNKNOWN;
  if (interrupted && !paymentMayHaveStarted) return ExitCode.INTERRUPTED;
  return code;
}

// At most one report per run: with --json, stdout holds exactly one document, so once the
// command's document (or a report) is out, a late signal or failure changes only the exit code.
function mayReport(): boolean {
  return !reported && !(json && output.wrote('stdout'));
}

/** Ends the process now with the code chosen so far (a second signal, or a breach: 8 is final). */
function exitNow(): void {
  process.exit(currentCode());
}

/**
 * Ends the process after the first signal's report is out. The exit waits for the check phase
 * (setImmediate), so a rejection raised in the same tick as the signal, which Node processes only
 * after the next-tick queue has drained, is seen first and turns the code into 8.
 */
function exitAfterPending(): void {
  if (exitPending) return;
  exitPending = true;
  setImmediate(exitFinalized);
}

/**
 * How long an interrupt or internal-error report may take to reach its stream before the process
 * exits without waiting for it. Short of any timer a command would plausibly schedule, so the run
 * does not go on after an internal error, and long enough for a pipe or terminal to take one line.
 */
const REPORT_FLUSH_MS = 75;

/**
 * Bounds each wait without output progress: a write that never completes (a stalled reader)
 * must not keep the process alive. The exit code is decided when the timer fires.
 * The timer is unref'd so it never keeps an otherwise finished process running.
 */
function armFallbackExit(): void {
  // Only writes already queued at the failure can renew this finite grace period.
  // Output from later command timers cannot keep the process alive.
  if (fallbackExit === undefined) flushBoundary = queuedWrites;
  else clearTimeout(fallbackExit);
  fallbackExit = setTimeout(exitNow, REPORT_FLUSH_MS).unref();
}

// Any uncaught exception or unhandled rejection: exit 8 with a stage-only report, once
// and promptly: the run never continues after an internal error, whatever output or
// timers are pending. 8 takes precedence over
// every other code, so nothing that happens later can change it.
function onInternal(): void {
  breached = true;
  process.exitCode = currentCode();
  if (!mayReport()) {
    exitFinalized();
    return;
  }
  reported = true;
  armFallbackExit();
  try {
    reportInternal(output, json, exitFinalized);
  } catch {
    // The output channel failed as well; the exit code still reports the breach.
    exitFinalized();
  }
}

// A graceful command stops new work on the first signal. Repeated signals use the existing
// check-phase exit so the abort's pending continuation can persist UNKNOWN and report its code.
// Commands without a graceful handler have issued no payment RPC and retain pre-send exit 6.
function onSignal(): void {
  if (gracefulStop !== null) {
    if (!stopRequested) {
      stopRequested = true;
      gracefulStop();
      return;
    }
    interrupted = true;
    process.exitCode = currentCode();
    exitAfterPending();
    return;
  }
  if (interrupted) {
    exitNow();
    return;
  }
  interrupted = true;
  process.exitCode = currentCode();
  if (!mayReport()) {
    exitAfterPending();
    return;
  }
  reported = true;
  armFallbackExit();
  try {
    reportInterrupted(output, json, exitAfterPending);
  } catch {
    exitAfterPending();
  }
}

function readVersion(): string {
  const pkg: unknown = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
  if (typeof pkg === 'object' && pkg !== null && 'version' in pkg && typeof pkg.version === 'string') return pkg.version;
  throw new Error('version: package.json has no version');
}

process.on('uncaughtException', onInternal);
process.on('unhandledRejection', onInternal);
process.on('SIGINT', onSignal);
process.on('SIGTERM', onSignal);

async function settle(code: number): Promise<void> {
  commandCode = code;
  pendingCode = null;
  process.exitCode = currentCode();
  await finalizeRenderedOutputs();
}

try {
  const parsed = parseArgs(argv);
  json = parsed.kind === 'command' ? parsed.command.json : parsed.json;
  const result = main(argv, {
    output, version: readVersion, env: process.env, execArgv: process.execArgv, nodeVersion: process.versions.node,
    onSafetyCode: code => {
      if (code === ExitCode.INVARIANT_BREACH) breached = true;
      if (code === ExitCode.OUTCOME_UNKNOWN) paymentMayHaveStarted = true;
      pendingCode = code;
      process.exitCode = currentCode();
    },
    onGracefulStop: stop => { gracefulStop = stop; }, daemonOutput: () => {
      const writer = processRenderOutput();
      renderedOutputs.add(writer);
      return writer;
    },
  });
  if (typeof result === 'number') void settle(result).catch(onInternal);
  else void result.then(settle, onInternal).catch(onInternal);
} catch {
  onInternal();
}
