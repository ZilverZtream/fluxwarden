import { existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { events } from './helpers/composed-seal.js';
import { lifecycleEvents, lifecycleFixture, runLifecycle } from './helpers/seal-lifecycle.js';

it('CP-044/SEC-044-001 seal rollback preserves an atomically replaced original output after a later EIO', () => {
  const f = lifecycleFixture(), result = runLifecycle(f, 'replacement'), log = lifecycleEvents(f);
  expect(events(f), 'faults occur only after the genuine verification/provider boundary').toContain('provider');
  const replacement = log.find(row => row['event'] === 'replacement-installed');
  expect(replacement, 'an actual first exclusive report write is replaced by another inode').toBeDefined();
  if (log.some(row => row['event'] === 'replacement-awaiting-close')) {
    const closed = log.findIndex(row => row['event'] === 'report-descriptor-closed');
    expect(closed, 'descriptor writes finish closing before the replacement interleaving').toBeGreaterThan(-1);
    expect(closed).toBeLessThan(log.findIndex(row => row['event'] === 'replacement-installed'));
  }
  expect(log.some(row => row['event'] === 'injected-EIO')).toBe(true);
  expect(result.signal).toBeNull(); expect(result.status).not.toBe(0);
  const path = join(f.output, 'report.json');
  expect(existsSync(path), 'rollback may remove only its own original created object').toBe(true);
  const retained = lstatSync(path, { bigint: true });
  expect({ dev: String(retained.dev), ino: String(retained.ino) }).toEqual({ dev: replacement?.['dev'], ino: replacement?.['ino'] });
  expect(readFileSync(path, 'utf8')).toBe('operator-owned replacement\n');
  expect(readdirSync(f.output), 'failure publishes no accepted row or receipt').toEqual(['report.json']);
}, 60_000);

it('CP-044/SEC-044-001 failed exclusive report write cleans its own nine-byte ENOSPC fragment', () => {
  const f = lifecycleFixture(), result = runLifecycle(f, 'partial'), log = lifecycleEvents(f);
  expect(events(f)).toContain('provider');
  expect(log.find(row => row['event'] === 'partial-created')).toMatchObject({ bytes: 9, size: 9 });
  expect(result.signal).toBeNull(); expect(result.status).not.toBe(0);
  expect(readdirSync(f.output), 'partial exclusive creation is owned even when its first write throws').toEqual([]);
  expect(readFileSync(join(f.evidence, 'vitest-chaos.json'))).toEqual(f.originalReport);
}, 60_000);

it('CP-044/ARC-044-005 main expiry cannot disarm the real watchdog while owned provider work remains pending', () => {
  const f = lifecycleFixture(), result = runLifecycle(f, 'pending'), log = lifecycleEvents(f);
  expect(log.some(row => row['event'] === 'watchdog-ready')).toBe(true);
  const provider = log.find(row => row['event'] === 'provider-start');
  expect(provider, 'the shared clock activates only after genuine full verification reaches the provider').toMatchObject({ modelDeadlineMs: 100 });
  expect(log.some(row => row['event'] === 'provider-tick'), 'real uncancellable timer work is pending').toBe(true);
  expect(log.some(row => row['event'] === 'provider-completed'), 'rejecting the main Promise alone cannot permit later provider completion').toBe(false);
  expect(log.some(row => row['event'] === 'watchdog-expired'), 'the independent watchdog remains armed until hard stop').toBe(true);
  expect(Date.now() - Number(provider?.['wallMs']), '100ms deadline plus bounded model polling cannot run the 800ms provider to completion').toBeLessThan(500);
  expect(result.status !== 0 || result.signal !== null).toBe(true);
  expect(readdirSync(f.output), 'expiry cannot leave accepted report artifacts').toEqual([]);
  expect(events(f)).not.toContain('subordinate-cap-raised');
}, 60_000);
