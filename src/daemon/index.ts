// `fluxwarden daemon --collect`: the collector on the process clocks (SPEC.md §10.4).
import type { CollectorTimers } from './collector.js';

/** Production clocks: performance.now() for cadence and backoff, Date.now() only as the wall clock. */
export function systemTimers(): CollectorTimers {
  return {
    monotonic: () => performance.now(),
    wall: () => Date.now(),
    sleep: (ms, signal) => new Promise<void>(resolve => {
      if (signal.aborted) { resolve(); return; }
      const done = (): void => {
        clearTimeout(timer);
        signal.removeEventListener('abort', done);
        resolve();
      };
      const timer = setTimeout(done, ms);
      signal.addEventListener('abort', done, { once: true });
    }),
  };
}

export { runCollector, type CollectorOptions, type CollectorResult, type CollectorTimers } from './collector.js';
