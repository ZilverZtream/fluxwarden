// Canonical JSON of a validated policy and its SHA-256: keys sorted by UTF-16 code unit at every
// level, no insignificant whitespace, msat as decimal strings and integers as JSON numbers, so
// comments, spacing, quoting and key order in the file never change the digest.
import { createHash } from 'node:crypto';
import type { Policy } from './types.js';

function canonical(value: unknown): string {
  if (typeof value === 'bigint') return JSON.stringify(value.toString());
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('canonical policy: numbers must be safe integers');
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (typeof value === 'object' && value !== null) {
    const entries = Object.entries(value).filter(([, item]) => item !== undefined);
    entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(',')}}`;
  }
  throw new Error('canonical policy: unsupported value');
}

export function canonicalPolicyJson(policy: Policy): string {
  return canonical(policy);
}

/** Lowercase hex SHA-256 of the canonical JSON (UTF-8). */
export function policySha256(policy: Policy): string {
  return createHash('sha256').update(canonicalPolicyJson(policy), 'utf8').digest('hex');
}
