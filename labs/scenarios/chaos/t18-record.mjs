import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { input, retain } from './live-reference.mjs';

export function t18Record(name, variant, status, facts) {
  const p = input(), build = JSON.parse(readFileSync(resolve('dist/evidence/build-info.json'), 'utf8'));
  if (!/^[a-f0-9]{40}$/.test(build.gitCommit) || !p.owner.id || !p.owner.evidenceRoot ||
      !['LAST_HOP_RECEIVABLE', 'FIRST_HOP_SPENDABLE'].includes(variant) ||
      !['PASS', 'GAP', 'PARTIAL', 'INVALID'].includes(status) || !/^t18-[a-z-]+$/.test(name)) {
    throw new Error('LabInvalidError: T-18 actual variant binding unavailable');
  }
  retain(name, { ...facts, scenario: 'T-18', variant, status, sourceCommit: build.gitCommit,
    ownerId: p.owner.id, project: p.owner.project });
  if (resolve(p.evidence) !== resolve(p.owner.evidenceRoot)) {
    writeFileSync(join(p.owner.evidenceRoot, `${name}.json`), readFileSync(join(p.evidence, `${name}.json`)), { mode: 0o600 });
  }
}
