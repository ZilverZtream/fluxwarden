import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { testRoot } from './env.js';
import { registerSentinels } from './output.js';

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
