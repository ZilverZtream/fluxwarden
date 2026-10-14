import { afterAll, beforeAll, it } from 'vitest';
import { Cohort, titles, proveR1, proveR2, proveR3, proveRA15, proveR4, proveRowner, proveRleak } from '../helpers/cp008-live.js';

// One normal two-owner bring-up, serial shared state, ordinary down in every
// outcome. Inventory-only collection never invokes hooks or external processes.
const cohort = new Cohort();
let initializationFailure: Error | undefined;
beforeAll(async () => {
  try { await cohort.initialize(); }
  catch (error) { initializationFailure = error instanceof Error ? error : new Error('owned credential cohort initialization failed'); }
}, 180_000);
afterAll(async () => { if (cohort.started.length) await cohort.close(); }, 180_000);
async function run(title: string, operation: (value: Cohort) => Promise<void>): Promise<void> {
  if (initializationFailure) throw initializationFailure;
  const start = performance.now();
  await operation(cohort); cohort.completed.push(title); cohort.phases[title] = performance.now() - start;
}

it('CP-008/R1 both LND nodes distinguish read and execute authority with valid route and administrative controls', async () => { await run(titles[0], proveR1); }, 180_000);
it('CP-008/R2 all CLN nodes prove actual method authorization and separately authenticated checkrune controls', async () => { await run(titles[1], proveR2); }, 180_000);
it('CP-008/RA15 actual pinned sendpay bounds and missing amount controls agree with OR and AND restrictions', async () => { await run(titles[3], proveRA15); }, 180_000);
it('CP-008/R4 minimal LND credentials prove invoice permission mapping and URI scoping on pinned nodes', async () => { await run(titles[4], proveR4); }, 180_000);
// Root revocation deliberately follows all live read controls.
it('CP-008/R3 stored role authority has independently revocable roots exact restrictions and owner-only fingerprints', async () => { await run(titles[2], proveR3); }, 180_000);
it('CP-008/Rowner two ordinary owners have measured allocations workers complete inventory and real cleanup', async () => { await run(titles[5], proveRowner); }, 180_000);
it('CP-008/Rleak fresh complete retained artifacts reject every planted encoding and missing sentinel registration', async () => { await run(titles[6], proveRleak); }, 180_000);
