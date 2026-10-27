import { defineConfig } from 'vitest/config';

if (process.env['FLUXWARDEN_REQUIRE_LIVE'] === '1' && !process.env['FLUXWARDEN_LAB_PLAN']?.trim()) {
  throw new Error('required-live selection: explicit nonempty owner plan required');
}

// Docker-free lab files always run; the live lab references (*.live.test.ts) are selected only when a lab plan is
// given, and each fails closed without its required plan inputs.
const live = process.env['FLUXWARDEN_LAB_PLAN'] !== undefined && process.env['FLUXWARDEN_LAB_PLAN'] !== '';

export default defineConfig({
  test: {
    ...(process.env['FLUXWARDEN_REQUIRE_LIVE'] === '1' ? { setupFiles: ['scripts/live-owned-setup.mjs'] } : {}),
    include: ['test/lab/**/*.test.ts'],
    exclude: live ? [] : ['test/lab/**/*.live.test.ts'],
    allowOnly: false,
    passWithNoTests: true,
    maxWorkers: 1,
    fileParallelism: false,
    testTimeout: 180_000,
    hookTimeout: 180_000,
  },
});
