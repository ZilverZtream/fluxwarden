import { expect, it } from 'vitest';
import { productLeakScan } from '../helpers/leak-scan.js';

it('CP-005/leak independent nonempty sentinels are absent from product files scratch and retained original output', async () => {
  const scan = await productLeakScan();
  expect(scan.sources, 'independent registered sentinels').toBeGreaterThanOrEqual(5);
  expect(scan.inventory, 'nonempty file inventory').toBeGreaterThan(0);
  // Only the five committed disposable fixtures are excluded, each by exact path.
  expect(scan.excluded, 'exactly the declared committed fixtures are excluded').toBe(5);
  expect(scan.hit === null, 'no sentinel found; diagnostics never include its value').toBe(true);
  expect(scan.liveDetected, 'a planted live sentinel is still detected by the same scan').toBe(true);
});
