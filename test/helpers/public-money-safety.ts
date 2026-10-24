import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { open } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { declareFixturePaths } from './capture-fixture.js';
import { expectOwnerOnly } from './cp015-persistence.js';
import { testRoot } from './env.js';
import { publishSentinel, registerSentinels } from './output.js';

/** Existing 32-byte HMAC input for cases proving paid truth and interrupts,
 * rather than first-run key creation. SPEC's persistent alerts reuse this key. */
export async function prepareMoneySafetyAlertKey(database: string): Promise<void> {
  const path = join(dirname(database), 'outbox.key');
  if (existsSync(path)) throw new Error('synthetic alert-key fixture requires an absent key');
  const bytes = randomBytes(32);
  declareFixturePaths([path]);
  const file = await open(path, 'wx', 0o600);
  await file.close();
  if (process.platform === 'win32') {
    // The state directory grants only the owner access. Protect that entry
    // explicitly while the file is empty, before writing any fixture secret.
    const secured = spawnSync(join(process.env['SystemRoot'] ?? 'C:/Windows', 'System32', 'icacls.exe'),
      [path, '/inheritance:d'], { encoding: 'utf8', windowsHide: true, shell: false, timeout: 10_000 });
    if (secured.error !== undefined) throw secured.error;
    if (secured.status !== 0) throw new Error('synthetic alert-key fixture permissions were not protected');
  }
  expectOwnerOnly(path, 'file');
  writeFileSync(path, bytes, { flag: 'r+' });
  registerMoneySafetyCredentials([path]);
}

/** Declare credential fixtures by path and register their bytes for later output scans. */
export function registerMoneySafetyCredentials(paths: readonly string[]): void {
  registerSentinels();
  for (const path of paths) {
    if (!existsSync(path)) continue;
    appendFileSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'declared-out.txt'), `${path}\n`);
    const id = createHash('sha256').update(path).digest('hex').slice(0, 24);
    const bytes = readFileSync(path), valueId = createHash('sha256').update(bytes).digest('hex');
    // The same credential path may legitimately acquire a new fixture value.
    // Keep every literal lifetime instead of overwriting the earlier source.
    publishSentinel(testRoot('FLUXWARDEN_SENTINEL_DIR'), `public-money-${id}-${valueId}.bin`, bytes);
  }
}
