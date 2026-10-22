import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { loadSource } from './adapter-interfaces.js';
import { declareFixturePaths } from './capture-fixture.js';
import { testRoot } from './env.js';
import { registerSentinels } from './output.js';

/** Existing 32-byte HMAC input for cases proving paid truth and interrupts,
 * rather than first-run key creation. SPEC's persistent alerts reuse this key. */
export async function prepareMoneySafetyAlertKey(database: string): Promise<void> {
  const path = join(dirname(database), 'outbox.key');
  if (existsSync(path)) throw new Error('synthetic alert-key fixture requires an absent key');
  const bytes = randomBytes(32);
  const files = await loadSource<{ writeOwnerOnlyFile: (path: string, bytes: Uint8Array) => string }>('output/private-file.ts');
  declareFixturePaths([path]);
  if (files.writeOwnerOnlyFile(path, bytes) !== 'written') throw new Error('synthetic owner-only alert-key fixture was not created');
  registerMoneySafetyCredentials([path]);
}

/** Declare credential fixtures by path and register their bytes for later output scans. */
export function registerMoneySafetyCredentials(paths: readonly string[]): void {
  registerSentinels();
  for (const path of paths) {
    if (!existsSync(path)) continue;
    appendFileSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'declared-out.txt'), `${path}\n`);
    const id = createHash('sha256').update(path).digest('hex').slice(0, 24);
    writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `public-money-${id}.bin`), readFileSync(path), { mode: 0o600 });
  }
}
