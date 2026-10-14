import { defineConfig } from 'vitest/config';

// Two projects: `product` (the shipped code, through its public surface) and `harness-docs`
// (repository configuration, documentation and test tooling).
const harness = ['test/harness/**/*.test.ts'];
// Lab and chaos reference tests run through their dedicated configurations.
const lab = ['test/lab/**'];
const chaos = ['test/chaos/**/*.live.test.ts', 'test/chaos/cp007-reference.test.ts'];

export default defineConfig({
  test: {
    allowOnly: false,
    passWithNoTests: false,
    testTimeout: 15_000,
    hookTimeout: 30_000,
    maxWorkers: 4,
    projects: [
      { extends: true, test: { name: 'product', include: ['test/**/*.test.ts'], exclude: [...harness, ...lab, ...chaos] } },
      // Release packaging rebuilds dist while command documentation tests use it.
      { extends: true, test: { name: 'harness-docs', include: harness, maxWorkers: 1, fileParallelism: false } },
    ],
  },
});
