// In-memory policy_versions table. Scripted behaviour follows the public schema: policy_sha256
// is UNIQUE (a second insert of the same digest fails as the database would), version_no counts
// up from 1, and rows are never changed.

export interface PolicyVersionRow {
  readonly id: string;
  readonly version_no: number;
  readonly policy_sha256: string;
  readonly policy_canonical_json: string;
  readonly author: string;
  readonly created_at: number;
}

export type NewPolicyVersion = Omit<PolicyVersionRow, 'version_no'>;

export class MemoryPolicyVersions {
  readonly rows: PolicyVersionRow[] = [];

  findBySha256(sha256: string): PolicyVersionRow | null {
    return this.rows.find(row => row.policy_sha256 === sha256) ?? null;
  }

  insert(row: NewPolicyVersion): PolicyVersionRow {
    if (this.rows.some(existing => existing.policy_sha256 === row.policy_sha256)) throw new Error('UNIQUE constraint failed: policy_versions.policy_sha256');
    if (this.rows.some(existing => existing.id === row.id)) throw new Error('UNIQUE constraint failed: policy_versions.id');
    const stored = { ...row, version_no: this.rows.length + 1 };
    this.rows.push(stored);
    return stored;
  }
}
