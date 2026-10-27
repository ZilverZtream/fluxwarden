// Each live file owns its lifecycle. The independent two-owner cohorts start
// with the primary down; they retain their own ordinary startup/cleanup hooks.
import { beforeAll, afterAll, expect } from 'vitest';
import { startOwnedLive, stopOwnedLive, startFaultPeer, prepareOwnedDemo } from './release-live.mjs';
const file = expect.getState().testPath?.replaceAll('\\', '/') ?? '';
const cohort = /\/cp006-owner-resources\.live\.test\.ts$|\/cp008-credentials\.live\.test\.ts$/.test(file);
let started = false;
let stopPeer;
if (process.env.FLUXWARDEN_REQUIRE_LIVE === '1' && cohort) beforeAll(() => stopOwnedLive(), 180_000);
if (process.env.FLUXWARDEN_REQUIRE_LIVE === '1' && process.env.FLUXWARDEN_LIVE_EXTERNAL_OWNER !== '1' && file.endsWith('.live.test.ts') && !cohort) {
  beforeAll(async () => {
    if (file.endsWith('/cp043-evidence-artifact.live.test.ts')) { await prepareOwnedDemo(); return; }
    const profile = /\/cp01[456]-reference\.live\.test\.ts$/.test(file) ? 'planner' : file.includes('/test/chaos/') ? 'chaos' : '';
    await startOwnedLive(false, profile); started = true;
    if (file.endsWith('/cp007-reference.live.test.ts')) stopPeer = await startFaultPeer();
  }, 180_000);
  afterAll(async () => {
    const outcomes = await Promise.allSettled([...(stopPeer ? [stopPeer()] : []), ...(started ? [stopOwnedLive()] : [])]);
    if (outcomes.some(outcome => outcome.status === 'rejected')) throw new Error('required-live cleanup: failed');
  }, 180_000);
}
