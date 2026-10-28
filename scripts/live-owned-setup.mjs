// Each live file owns its lifecycle. The independent two-owner cohorts start
// with the primary down; they retain their own ordinary startup/cleanup hooks.
import { beforeAll, afterAll, expect } from 'vitest';
import { startOwnedLive, stopOwnedLive, startFaultPeer, prepareOwnedDemo } from './release-live.mjs';
const file = expect.getState().testPath?.replaceAll('\\', '/') ?? '';
const cohort = /\/cp006-owner-resources\.live\.test\.ts$|\/cp008-credentials\.live\.test\.ts$/.test(file);
let started = false;
let stopPeer;
const cancellation = new AbortController();
let startup;
if (process.env.FLUXWARDEN_REQUIRE_LIVE === '1' && cohort) beforeAll(() => stopOwnedLive(), 180_000);
if (process.env.FLUXWARDEN_REQUIRE_LIVE === '1' && process.env.FLUXWARDEN_LIVE_EXTERNAL_OWNER !== '1' && file.endsWith('.live.test.ts') && !cohort) {
  beforeAll(async () => {
    if (file.endsWith('/cp043-evidence-artifact.live.test.ts')) { await prepareOwnedDemo(); return; }
    const profile = file.endsWith('/cp012-reference.live.test.ts') ? 'reference-read'
      : /\/cp01[456]-reference\.live\.test\.ts$/.test(file) ? 'planner' : file.includes('/test/chaos/') ? 'chaos' : '';
    const timer = setTimeout(() => cancellation.abort(), 180_000);
    startup = (async () => {
      await startOwnedLive(false, profile, cancellation.signal); started = true;
      if (file.endsWith('/cp007-reference.live.test.ts')) stopPeer = await startFaultPeer(cancellation.signal);
    })();
    try { await startup; } finally { clearTimeout(timer); }
  }, 180_000);
  afterAll(async () => {
    cancellation.abort();
    if (startup) await Promise.allSettled([startup]);
    const outcomes = await Promise.allSettled([...(stopPeer ? [stopPeer()] : []), ...(started ? [stopOwnedLive()] : [])]);
    if (outcomes.some(outcome => outcome.status === 'rejected')) throw new Error('required-live cleanup: failed');
  }, 180_000);
}
