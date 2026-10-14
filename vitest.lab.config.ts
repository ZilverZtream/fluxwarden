import { defineConfig } from 'vitest/config';

// Docker-free lab files always run; the live lab references (*.live.test.ts) are selected only when a lab plan is
// given, and each fails closed without its required plan inputs.
const live = process.env['FLUXWARDEN_LAB_PLAN'] !== undefined && process.env['FLUXWARDEN_LAB_PLAN'] !== '';

export default defineConfig({
  test: {
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
