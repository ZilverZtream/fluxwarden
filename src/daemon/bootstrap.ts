import { randomBytes } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { Config } from '../config/config.js';
import { Secret } from '../core/secret.js';
import { checkReadablePath } from '../persistence/paths.js';
import { prepareEffectDirectory } from '../output/effects.js';
import { writeOwnerOnlyFile } from '../output/private-file.js';
import { createAlertWriter, type AlertWriter } from './alerts.js';

/** Reuses the persistent signing key; signed files can never be adopted under a replacement key. */
export function bootstrapAlerts(config: Config): AlertWriter {
  prepareEffectDirectory(config.alertDir);
  const path = join(dirname(config.database), 'outbox.key');
  if (lstatSync(path, { throwIfNoEntry: false }) === undefined) {
    if (readdirSync(config.alertDir).some(name => name.endsWith('.json'))) throw new Error('alerts: signing key is missing while alert files exist');
    const written = writeOwnerOnlyFile(path, randomBytes(32));
    if (written !== 'written' && written !== 'exists') throw new Error('alerts: signing key could not be created');
  }
  checkReadablePath(path);
  const stat = lstatSync(path);
  if (stat.size !== 32) throw new Error('alerts: signing key has an invalid size');
  const key = readFileSync(path);
  return createAlertWriter({ dir: config.alertDir, key, monotonic: { now: () => performance.now() }, clock: { now: () => Date.now() },
    maxPerWindow: 60, windowMs: 60_000, secrets: [new Secret(key)] });
}
