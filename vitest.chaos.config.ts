import { defineConfig } from 'vitest/config';

const live = Boolean(process.env['FLUXWARDEN_LAB_PLAN']);

export default defineConfig({
  test: {
    include: live ? ['test/chaos/**/*.live.test.ts'] : [],
    allowOnly: false,
    passWithNoTests: true,
    ...(live ? { fileParallelism: false, maxWorkers: 1 } : {}),
    testTimeout: live ? 180_000 : 15_000,
    hookTimeout: live ? 180_000 : 30_000,
  },
});
