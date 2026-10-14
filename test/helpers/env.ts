import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll } from 'vitest';

// Isolated test roots. A caller may supply them (a validation runner that scans them
// afterwards); otherwise each test file creates private ones and removes them after its
// last test, so a fresh checkout runs the whole suite with no setup and leaves nothing.
const variables = ['FLUXWARDEN_TEST_TMP', 'FLUXWARDEN_SENTINEL_DIR', 'FLUXWARDEN_EVIDENCE_DIR'] as const;
type Root = typeof variables[number];
const owned: [Root, string][] = [];

export function ensureTestRoots(): void {
  for (const name of variables) {
    if (process.env[name]) continue;
    const directory = mkdtempSync(join(tmpdir(), 'fluxwarden-test-'));
    process.env[name] = directory;
    owned.push([name, directory]);
  }
}

export function testRoot(name: Root): string {
  ensureTestRoots();
  const directory = process.env[name];
  if (!directory) throw new Error(`${name} could not be provisioned`);
  return directory;
}

afterAll(() => {
  for (const [name, directory] of owned.splice(0)) {
    if (process.env[name] === directory) Reflect.deleteProperty(process.env, name);
    rmSync(directory, { recursive: true, force: true });
  }
});

ensureTestRoots();
