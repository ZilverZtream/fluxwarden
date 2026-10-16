// Interface: NodeReader.paymentsPage through openClnReader; pinned CLN listsendpays uses a uint64 start index.
import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { startFakeCln } from '../fakes/cln/fake-cln.js';
import { certificatePath, type FakeServer } from '../fakes/https.js';
import { scratchDir } from '../helpers/cli.js';
import { loadSrc } from '../helpers/load-src.js';
import type { ClnRestOptions } from '../helpers/adapter-interfaces.js';

interface Reader { paymentsPage(cursor: bigint, pageSize: number): Promise<{ count: number; cursor: bigint }> }
interface ReaderModule { readonly openClnReader: (options: ClnRestOptions) => Promise<Reader> }
const servers: FakeServer[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });

for (const cursor of [7n, 9_007_199_254_740_993n, 18_446_744_073_709_551_615n]) {
  it(`CP-012/B2 REG-CLN015 preserves cursor ${String(cursor)} exactly or explicitly refuses before RPC`, async () => {
    const rune = randomBytes(48).toString('base64url');
    const runePath = join(scratchDir('cursor'), 'local.rune');
    writeFileSync(runePath, rune);
    const fake = await startFakeCln({ rune, methods: { listsendpays: (context, cln) => { cln.result(context, 'listsendpays', { payments: [] }); } } });
    servers.push(fake);
    const { openClnReader } = await loadSrc<ReaderModule>('node-cln/reader.ts');
    const reader = await openClnReader({ host: fake.host, port: fake.port, tlsCertPath: certificatePath('node'), runePath, timeoutMs: 5000 });
    let result: { count: number; cursor: bigint } | undefined;
    let error: unknown;
    try { result = await reader.paymentsPage(cursor, 5); } catch (caught) { error = caught; }
    if (error !== undefined) {
      expect(error).toBeInstanceOf(Error);
      expect(fake.requests).toEqual([]);
      expect(cursor).toBeGreaterThan(BigInt(Number.MAX_SAFE_INTEGER));
    } else {
      expect(result).toEqual({ count: 0, cursor });
      expect(fake.requests).toHaveLength(1);
      const body = fake.requests[0]?.body ?? '';
      // Numeric or canonical decimal-string wire values must retain the entire uint64.
      expect(body).toMatch(new RegExp(`"start"\\s*:\\s*(?:"${String(cursor)}"|${String(cursor)})(?=\\s*[,}])`));
    }
  });
}
