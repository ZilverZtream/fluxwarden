import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';
import { owner } from '../helpers/cp006-lab.js';
import { observedLab } from '../helpers/cp006-observed.js';
import { sentinelRoot, sentinels } from '../helpers/output.js';

// SECURITY INV-11: synthetic credential copies use the independently committed registry.
it('CP-006/B7 a fresh observed owner registers exact fixture bytes before copying within its runtime', async () => {
  const previous = sentinelRoot(), isolated = mkdtempSync(join(previous, 'copy-control-'));
  const selected = await owner(), destination = join(selected.runtimeRoot, 'lnd-p', 'admin.macaroon');
  process.env['FLUXWARDEN_SENTINEL_DIR'] = isolated;
  try {
    expect(readdirSync(isolated)).toHaveLength(0);
    const fake = observedLab(selected), fixtures = sentinels();
    expect(readdirSync(isolated).sort()).toEqual(fixtures.map(row => `product-${row.kind}.bin`).sort());
    for (const row of fixtures) expect(readFileSync(join(isolated, `product-${row.kind}.bin`)).equals(row.bytes), `${row.kind} exact committed bytes`).toBe(true);
    const expected = fixtures.find(row => row.kind === 'macaroon');
    expect(expected !== undefined && expected.bytes.length > 0, 'nonempty committed macaroon fixture').toBe(true);
    const command = { cwd: repoRoot, env: process.env, timeoutMs: 1000 };
    expect((await fake.run(['docker', 'cp', 'node:/root/admin.macaroon', destination], command)).exitCode).toBe(0);
    expect(expected !== undefined && fake.privateFiles.get(destination)?.equals(expected.bytes), 'exact independently registered copy bytes').toBe(true);
    expect([...fake.privateFiles.keys()]).toEqual([destination]);
    const escaped = join(selected.tmpRoot, 'escaped.macaroon');
    await expect(fake.run(['docker', 'cp', 'node:/root/admin.macaroon', escaped], command)).rejects.toThrow('outside declared owner runtime');
    expect(existsSync(escaped)).toBe(false);
    expect([...fake.privateFiles.keys()]).toEqual([destination]);
  } finally {
    process.env['FLUXWARDEN_SENTINEL_DIR'] = previous;
    rmSync(isolated, { recursive: true, force: true });
  }
});
