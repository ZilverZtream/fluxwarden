import { expect, it } from 'vitest';
import { verifyValidationObservations } from '../helpers/cp006-validation-observations.js';

// CP-006/R6 and B9: an independently selected completed validation, original
// Vitest reports and observed exits/timestamps prove completeness. This reference
// cannot include itself in the completed selection and never starts commands.
it('CP-006/R6 independent nonempty selected inventory is executed exactly once with complete phase measurements', () => {
  const observed = verifyValidationObservations();
  expect(observed.cases).toBeGreaterThan(0);
  expect(observed.reports).toBeGreaterThan(0);
  expect(observed.artifactHashes).toHaveLength(observed.reports + 2);
  expect(observed.totalMs).toBeGreaterThan(0);
  expect(observed.longestShardMs).toBeLessThanOrEqual(observed.criticalPathMs);
}, 180000);
