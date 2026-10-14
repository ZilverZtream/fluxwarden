import { expect, it } from 'vitest';
import { productLeakScan } from '../helpers/leak-scan.js';

// The pinned-source provenance case needs the upstream checkout and lives in cp004-provenance.live.test.ts (decision D53).
it('CP-004/leak independent nonempty sentinels are absent from product scratch and retained original output', async () => {
  const scan = await productLeakScan();
  expect(scan.sources, 'independent registered sentinels').toBeGreaterThanOrEqual(5);
  expect(scan.inventory, 'product files scanned').toBeGreaterThan(0);
  // Only the five committed disposable fixtures are excluded, each by exact path.
  expect(scan.excluded, 'exactly the declared committed fixtures are excluded').toBe(5);
  expect(scan.hit).toBeNull();
  expect(scan.liveDetected, 'a planted live sentinel is still detected by the same scan').toBe(true);
});
