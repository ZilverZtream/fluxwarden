// In-memory approvals table. Scripted behaviour follows the public schema and security model:
// `nonce` is UNIQUE, so a second insert with a used nonce is refused and nothing is written
// (SECURITY.md §4.1 step 8); rows are append-only (INV-09), so there is no update path, and
// `tamper` stands in for someone with write access to the database file.

export interface ApprovalRow {
  readonly id: string;
  readonly proposal_id: string;
  readonly key_id: string;
  readonly nonce: string;
  readonly expires_at: number;
  readonly signature: string;
  readonly max_fee_msat: bigint;
  readonly max_cltv_delta: number;
  readonly created_at: number;
}

export class MemoryApprovals {
  rows: ApprovalRow[] = [];

  insert(row: ApprovalRow): 'inserted' | 'nonce-used' {
    if (this.rows.some(existing => existing.nonce === row.nonce)) return 'nonce-used';
    if (this.rows.some(existing => existing.id === row.id)) throw new Error('UNIQUE constraint failed: approvals.id');
    this.rows.push({ ...row });
    return 'inserted';
  }

  listByProposal(proposalId: string): readonly ApprovalRow[] {
    return this.rows.filter(row => row.proposal_id === proposalId).map(row => ({ ...row }));
  }

  /** Direct file-level modification, bypassing the append-only rule. */
  tamper(id: string, change: Partial<ApprovalRow>): void {
    this.rows = this.rows.map(row => (row.id === id ? { ...row, ...change } : row));
  }
}
