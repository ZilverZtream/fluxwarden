import { defineConfig } from 'vitest/config';

// Two projects: `product` (the shipped code, through its public surface) and `harness-docs`
// (repository configuration, documentation and test tooling).
const harness = ['test/harness/**/*.test.ts'];

export default defineConfig({
  test: {
    allowOnly: false,
    passWithNoTests: false,
    testTimeout: 15_000,
    hookTimeout: 30_000,
    projects: [
      { extends: true, test: { name: 'product', include: ['test/**/*.test.ts'], exclude: harness } },
      { extends: true, test: { name: 'harness-docs', include: harness } },
    ],
  },
});
