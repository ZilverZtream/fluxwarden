#!/usr/bin/env node
// The `fluxwarden` binary: process-level handlers, signals and the exit code around main().
import { readFileSync } from 'node:fs';
import { processOutput, processRenderOutput, type Output } from '../output/index.js';
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
let breached = false;
let interrupted = false;
/** This file has written its interrupt or internal-error report. */
let reported = false;
/** How a long-running command (the daemon) stops at the first signal, once it has registered. */
let gracefulStop: (() => void) | null = null;
let stopRequested = false;

// Exit-code precedence: 8 INVARIANT_BREACH over 6 INTERRUPTED over the command's
// own code. Decided whenever the code is set or the process exits, never captured earlier.
function currentCode(): number {
  if (breached) return ExitCode.INVARIANT_BREACH;
  if (interrupted) return ExitCode.INTERRUPTED;
  return commandCode;
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
  setImmediate(exitNow);
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
    exitNow();
    return;
  }
  reported = true;
  armFallbackExit();
  try {
    reportInternal(output, json, exitNow);
  } catch {
    // The output channel failed as well; the exit code still reports the breach.
    exitNow();
  }
}

// The first SIGINT or SIGTERM stops the run. No command issues a mutating call yet, so the
// interrupt always comes before one: exit 6, or 8 after a breach.
// A second signal ends the process at once with the code chosen so far and no second report.
// A command with a graceful stop (the daemon, SPEC.md §10.4 DM6) finishes its current work at the
// first signal and exits with its own code; a second signal then exits at once with 6.
function onSignal(): void {
  if (gracefulStop !== null && !interrupted) {
    if (!stopRequested) {
      stopRequested = true;
      gracefulStop();
      return;
    }
    interrupted = true;
    process.exitCode = currentCode();
    exitNow();
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

function settle(code: number): void {
  commandCode = code;
  process.exitCode = currentCode();
}

try {
  const parsed = parseArgs(argv);
  json = parsed.kind === 'command' ? parsed.command.json : parsed.json;
  const result = main(argv, {
    output, version: readVersion, env: process.env, execArgv: process.execArgv, nodeVersion: process.versions.node,
    onGracefulStop: stop => { gracefulStop = stop; }, daemonOutput: () => processRenderOutput(),
  });
  if (typeof result === 'number') settle(result);
  else result.then(settle, onInternal);
} catch {
  onInternal();
}
