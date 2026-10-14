import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import { hash, sourceHashes, upstream, verifyProvenance } from '../helpers/cp004-provenance.js';

// The pinned upstream checkout is a validation input, not part of this repository. The lab config selects
// this file only when a validation plan is supplied (decision D53); without the checkout the case fails closed.
it('CP-004/provenance-hashes pinned Git bytes and candidate files independently reproduce the source manifest', () => {
  const reference = process.env['FLUXWARDEN_REFERENCE_ROOT'];
  if (!reference) throw new Error('pinned source reference root is required');
  for (const [path, expected] of [...Object.entries(sourceHashes()), ['LICENSE', { path: 'LICENSE', sha256: upstream.licenseSha256 }] as const]) {
    const source = spawnSync('git', ['show', `${upstream.commit}:${path}`], { cwd: resolve(reference), shell: false, windowsHide: true, timeout: 15000 });
    expect(source.status, path).toBe(0);
    expect(hash(source.stdout), path).toBe(expected.sha256);
  }
  verifyProvenance();
});
