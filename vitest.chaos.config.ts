import { defineConfig } from 'vitest/config';

if (process.env['FLUXWARDEN_REQUIRE_LIVE'] === '1' && !process.env['FLUXWARDEN_LAB_PLAN']?.trim()) {
  throw new Error('required-live selection: explicit nonempty owner plan required');
}

// Ordinary fake-node cases always run; live references need their explicit lab inputs.
const live = Boolean(process.env['FLUXWARDEN_LAB_PLAN']);

export default defineConfig({
  test: {
    ...(process.env['FLUXWARDEN_REQUIRE_LIVE'] === '1' ? { setupFiles: ['scripts/live-owned-setup.mjs'] } : {}),
    include: ['test/chaos/**/*.test.ts'],
    exclude: live ? [] : ['test/chaos/**/*.live.test.ts'],
    allowOnly: false,
    passWithNoTests: false,
    ...(live ? { fileParallelism: false, maxWorkers: 1 } : {}),
    testTimeout: live ? 180_000 : 15_000,
    hookTimeout: live ? 180_000 : 30_000,
  },
});
