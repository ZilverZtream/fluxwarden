import { readFileSync } from 'node:fs';

export function buildIdentity(): { version: string; gitCommit: string } {
  const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as { version?: unknown };
  if (typeof pkg.version !== 'string') throw new Error('package version is unavailable');
  let gitCommit = 'unavailable: build commit was not recorded';
  try {
    const build = JSON.parse(readFileSync(new URL('./build-info.json', import.meta.url), 'utf8')) as { gitCommit?: unknown };
    if (typeof build.gitCommit === 'string' && /^[0-9a-f]{40}$/.test(build.gitCommit)) gitCommit = build.gitCommit;
  } catch { /* Unpackaged source builds may lack build provenance. */ }
  return { version: pkg.version, gitCommit };
}
