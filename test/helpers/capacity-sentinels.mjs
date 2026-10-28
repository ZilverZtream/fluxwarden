import { createHash } from 'node:crypto';
import { appendFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/** Register generated benchmark credentials before any retained evidence is scanned. */
export async function publishSentinel(context, bytes) {
  const fingerprint = createHash('sha256').update(bytes).digest('hex');
  const path = join(process.env.FLUXWARDEN_SENTINEL_DIR, `capacity-${fingerprint}.bin`);
  appendFileSync(join(process.env.FLUXWARDEN_TEST_TMP, 'declared-out.txt'), `${path}\n`);
  writeFileSync(path, bytes, { flag: 'wx', mode: 0o600 });
}
