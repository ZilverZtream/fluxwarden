// The owned test entry, including npm lifecycle use, opts into finite capture.
// Product CLI subprocesses receive neither loader flags nor NODE_OPTIONS.
if (process.env.FLUXWARDEN_CI_CAPTURE) {
  await import('./ci-capture-preload.mjs');
  // Vitest's documented execArgv option applies to its owned fork/thread pools.
  // Ordinary spawned CLI commands do not inherit these Node argument flags.
  process.argv.push('--execArgv=--import=' + new URL('./ci-capture-preload.mjs', import.meta.url).href);
}
await import('../node_modules/vitest/vitest.mjs');
