// Validate the retained native records at every release-evidence boundary.
// A passing test assertion does not replace either required SPEC T-18 variant.
const check = value => { if (!value) throw new Error('release evidence: incomplete native observations'); };
const variants = ['LAST_HOP_RECEIVABLE', 'FIRST_HOP_SPENDABLE'];
export const observationPath = value => typeof value === 'string' && value.length > 0 && !value.includes('\\') && !value.includes('\0') &&
  !value.startsWith('/') && !value.includes(':') && !value.split('/').some(part => !part || part === '.' || part === '..');

export function rejectIncomplete(value) {
  if (!value || typeof value !== 'object') return;
  check(!['GAP', 'PARTIAL', 'INVALID'].includes(value.status) && value.complete !== false);
  for (const nested of Object.values(value)) rejectIncomplete(nested);
}

export function validateObservations(id, summary, read, { sourceCommit, compiledCommit = sourceCommit, tarballSha256, ownerId }) {
  rejectIncomplete(summary);
  const references = summary.observations ?? [];
  check(Array.isArray(references));
  const paths = new Set(), proved = [];
  for (const reference of references) {
    check(reference && observationPath(reference.path) && /^[a-f0-9]{64}$/.test(reference.sha256) && !paths.has(reference.path));
    paths.add(reference.path);
    const raw = read(reference);
    check(raw && typeof raw === 'object' && !Array.isArray(raw));
    rejectIncomplete(raw);
    if (raw.sourceCommit !== undefined) check(raw.sourceCommit === sourceCommit);
    if (raw.compiledCommit !== undefined) check(raw.compiledCommit === compiledCommit);
    if (raw.tarballSha256 !== undefined) check(raw.tarballSha256 === tarballSha256);
    if (raw.ownerId !== undefined) check(raw.ownerId === ownerId);
    if (id === 'T-18' && (raw.scenario !== undefined || raw.variant !== undefined)) {
      check(raw.scenario === id && variants.includes(raw.variant) && raw.status === 'PASS' && raw.sourceCommit === sourceCommit && raw.ownerId === ownerId);
      proved.push(raw.variant);
    }
  }
  if (id === 'T-18') check(proved.length === variants.length && variants.every(variant => proved.includes(variant)));
  return references;
}
