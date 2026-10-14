import type { DatabaseSync } from 'node:sqlite';
import type { ApprovalRow, ApprovalStore } from '../approval/types.js';
import type { Msat } from '../core/money.js';
import type { NormalizedChannel, ChannelState, Confidence } from '../core/normalize.js';
import { bigintColumn, numberColumn, textColumn, immediate, dbNow } from './sql.js';
import { ApprovalError } from '../approval/errors.js';

export function commandData(db: DatabaseSync, writable: (what: string) => void, run: <T>(work: () => T) => T) {
  const approvals: ApprovalStore = {
    insert(row) {
      writable('approvals.insert');
      return immediate(db, () => {
        // MySQL: same
        if (db.prepare('SELECT id FROM approvals WHERE nonce = ?').get(row.nonce) !== undefined) return 'nonce-used';
        // MySQL: same
        const proposal = db.prepare('SELECT status, expires_at FROM liquidity_proposals WHERE id = ?').get(row.proposal_id);
        if (proposal === undefined || !['PROPOSED', 'APPROVED'].includes(textColumn(proposal, 'status')) || numberColumn(proposal, 'expires_at') <= dbNow(db)) throw new ApprovalError(5, 'APPROVAL_EXPIRED');
        if (row.expires_at <= dbNow(db)) throw new ApprovalError(1, 'APPROVAL_EXPIRED');
        // MySQL: same
        db.prepare(`INSERT INTO approvals (id, proposal_id, key_id, nonce, expires_at, signature, max_fee_msat, max_cltv_delta, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(row.id, row.proposal_id, row.key_id, row.nonce, row.expires_at, row.signature, row.max_fee_msat, row.max_cltv_delta, row.created_at);
        // MySQL: same
        db.prepare("UPDATE liquidity_proposals SET status = 'APPROVED' WHERE id = ? AND status = 'PROPOSED'").run(row.proposal_id);
        return 'inserted';
      });
    },
    listByProposal(id): ApprovalRow[] {
      // MySQL: same
      return run(() => db.prepare('SELECT * FROM approvals WHERE proposal_id = ? ORDER BY created_at, id').all(id).map(row => ({
        id: textColumn(row, 'id'), proposal_id: textColumn(row, 'proposal_id'), key_id: textColumn(row, 'key_id'), nonce: textColumn(row, 'nonce'),
        expires_at: numberColumn(row, 'expires_at'), signature: textColumn(row, 'signature'), max_fee_msat: bigintColumn(row, 'max_fee_msat') as Msat,
        max_cltv_delta: numberColumn(row, 'max_cltv_delta'), created_at: numberColumn(row, 'created_at'),
      })));
    },
  };
  return {
    approvals,
    snapshots(nodeId: string): NormalizedChannel[] {
      // MySQL: same
      return run(() => db.prepare(`SELECT c.*, s.* FROM channels c JOIN channel_snapshots s ON s.channel_id = c.id
        WHERE c.node_id = ? AND s.id = (SELECT max(x.id) FROM channel_snapshots x WHERE x.channel_id = c.id) ORDER BY c.channel_key`).all(nodeId).map(row => ({
        nodeId, channelKey: textColumn(row, 'channel_key'), scid: row['scid'] === null ? null : textColumn(row, 'scid'),
        peerPubkey: textColumn(row, 'peer_pubkey'), fundingOutpoint: textColumn(row, 'funding_outpoint'), state: textColumn(row, 'lifecycle_state') as ChannelState,
        nodeState: textColumn(row, 'lifecycle_state'), opener: 'local' as const, capacityMsat: bigintColumn(row, 'capacity_msat'),
        localBalanceMsat: bigintColumn(row, 'local_msat'), remoteBalanceMsat: bigintColumn(row, 'remote_msat'), spendableMsat: bigintColumn(row, 'spendable_msat'),
        receivableMsat: bigintColumn(row, 'receivable_msat'), confidence: textColumn(row, 'confidence') as Confidence,
        caveat: null, localReserveMsat: 0n, remoteReserveMsat: 0n, pendingOutMsat: bigintColumn(row, 'pending_out_msat'), pendingInMsat: bigintColumn(row, 'pending_in_msat'),
        pendingHtlcCount: numberColumn(row, 'pending_htlc_count'), localMaxPendingAmtMsat: null, remoteMaxPendingAmtMsat: null,
        observedAt: numberColumn(row, 'observed_at'), blockHeight: numberColumn(row, 'block_height'), provenance: JSON.parse(textColumn(row, 'provenance_json')) as Record<string, string>,
      })));
    },
    // MySQL: same
    proposalIds(): string[] { return run(() => db.prepare('SELECT id FROM liquidity_proposals ORDER BY created_at, id').all().map(row => textColumn(row, 'id'))); },
    // MySQL: same
    executionIds(): string[] { return run(() => db.prepare('SELECT id FROM executions ORDER BY created_at, id').all().map(row => textColumn(row, 'id'))); },
  };
}
export type CommandData = ReturnType<typeof commandData>;
