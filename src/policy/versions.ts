// Policy versions are stored once per digest, with the canonical JSON that produced it.
import { canonicalPolicyJson, policySha256 } from './canonical.js';
import type { Policy } from './types.js';

/** A policy_versions row (append-only; policy_sha256 is unique). */
export interface PolicyVersionRow {
  readonly id: string;
  readonly version_no: number;
  readonly policy_sha256: string;
  readonly policy_canonical_json: string;
  readonly author: string;
  readonly created_at: number;
}

export type NewPolicyVersion = Omit<PolicyVersionRow, 'version_no'>;

export interface PolicyVersionRepository {
  findBySha256(sha256: string): PolicyVersionRow | null;
  /** Assigns the next version_no; fails when the digest is already stored. */
  insert(row: NewPolicyVersion): PolicyVersionRow;
}

export interface RecordDeps {
  now(): number;
  newId(): string;
  readonly author: string;
}

export function recordPolicyVersion(policy: Policy, repo: PolicyVersionRepository, deps: RecordDeps): { id: string; policySha256: string; created: boolean } {
  const sha256 = policySha256(policy);
  const existing = repo.findBySha256(sha256);
  if (existing !== null) return { id: existing.id, policySha256: sha256, created: false };
  try {
    const row = repo.insert({ id: deps.newId(), policy_sha256: sha256, policy_canonical_json: canonicalPolicyJson(policy), author: deps.author, created_at: deps.now() });
    return { id: row.id, policySha256: sha256, created: true };
  } catch (error) {
    // A concurrent writer may have stored the same digest between the lookup and the insert.
    const raced = repo.findBySha256(sha256);
    if (raced !== null) return { id: raced.id, policySha256: sha256, created: false };
    throw error;
  }
}
