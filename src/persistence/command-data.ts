import type { DatabaseSync } from 'node:sqlite';
import type { ApprovalRow, ApprovalStore } from '../approval/types.js';
import type { Msat } from '../core/money.js';
import type { NormalizedChannel, ChannelState, Confidence } from '../core/normalize.js';
import { bigintColumn, numberColumn, textColumn, immediate, dbNow, DB_NOW } from './sql.js';
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
    /** The same terminal anchors and global fee commitments used by execution admission. */
    planningState(nodeId: string, periodMs: number) {
      return run(() => {
        // MySQL: same
        const cooldowns = db.prepare(`SELECT e.status, s.channel_key AS source_channel, t.channel_key AS target_channel,
            coalesce((SELECT min(ev.at) FROM execution_events ev WHERE ev.execution_id = e.id
              AND ev.to_status = e.status AND (ev.from_status IS NULL OR ev.from_status <> e.status)), e.updated_at) AS at
          FROM executions e JOIN liquidity_proposals p ON p.id = e.proposal_id
          JOIN channels s ON s.id = p.source_channel_id JOIN channels t ON t.id = p.target_channel_id
          WHERE p.node_id = ? AND e.status IN ('VERIFIED_SUCCESS', 'VERIFIED_FAILURE')`).all(nodeId).map(row => ({
            outcome: textColumn(row, 'status') === 'VERIFIED_SUCCESS' ? 'VERIFIED_SUCCESS' as const : 'VERIFIED_FAILURE' as const,
            sourceChannel: textColumn(row, 'source_channel'), targetChannel: textColumn(row, 'target_channel'), at: numberColumn(row, 'at'),
          }));
        // MySQL: NOW(6) - INTERVAL ? * 1000 MICROSECOND for the window start
        const reservations = db.prepare(`SELECT state, reserved_msat, consumed_msat, coalesce((
            SELECT min(ev.at) FROM execution_events ev WHERE ev.execution_id = r.execution_id
              AND ev.to_status = 'VERIFIED_SUCCESS' AND ev.from_status <> 'VERIFIED_SUCCESS'
          ), period_start) AS at FROM budget_reservations r
          WHERE state = 'HELD' OR (state = 'CONSUMED' AND coalesce((
            SELECT min(ev.at) FROM execution_events ev WHERE ev.execution_id = r.execution_id
              AND ev.to_status = 'VERIFIED_SUCCESS' AND ev.from_status <> 'VERIFIED_SUCCESS'
          ), period_start) > ${DB_NOW} - ?)`).all(periodMs).map(row => ({
            state: textColumn(row, 'state') === 'HELD' ? 'HELD' as const : 'CONSUMED' as const,
            reservedMsat: bigintColumn(row, 'reserved_msat'), consumedMsat: row['consumed_msat'] === null ? null : bigintColumn(row, 'consumed_msat'),
            at: numberColumn(row, 'at'),
          }));
        return { cooldowns, reservations };
      });
    },
    /** Actual balance changes retained with the fenced delta-verification event. */
    executionDeltas(executionId: string): { sourceDeltaMsat: string | null; targetDeltaMsat: string | null } | null {
      return run(() => {
        // MySQL: same
        const row = db.prepare(`SELECT evidence_json FROM execution_events WHERE execution_id = ?
          AND to_status = 'VERIFIED_SUCCESS' AND (json_extract(evidence_json, '$.sourceDeltaMsat') IS NOT NULL
            OR json_extract(evidence_json, '$.targetDeltaMsat') IS NOT NULL)
          ORDER BY id DESC LIMIT 1`).get(executionId);
        if (row === undefined) return null;
        const evidence = JSON.parse(textColumn(row, 'evidence_json')) as Record<string, unknown>;
        const source = evidence['sourceDeltaMsat'];
        const target = evidence['targetDeltaMsat'];
        if (source !== null && (typeof source !== 'string' || !/^(0|-?[1-9][0-9]*)$/.test(source))) return null;
        if (target !== null && (typeof target !== 'string' || !/^(0|-?[1-9][0-9]*)$/.test(target))) return null;
        return { sourceDeltaMsat: source, targetDeltaMsat: target };
      });
    },
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
    /** Window proposals for selected nodes, plus the explicitly retained executions' inputs. */
    proposalIds(scope?: { readonly nodeIds: readonly string[]; readonly sinceMs: number; readonly untilMs: number; readonly executionIds?: readonly string[] }): string[] {
      return run(() => {
        // MySQL: same. Scope unrelated planner history before loading route and explanation documents.
        const rows = scope === undefined
          ? db.prepare('SELECT id FROM liquidity_proposals ORDER BY created_at, id').all()
          : db.prepare(`SELECT p.id FROM liquidity_proposals p WHERE
              (p.node_id IN (${scope.nodeIds.map(() => '?').join(',') || 'NULL'}) AND p.created_at >= ? AND p.created_at < ?)
              OR EXISTS (SELECT 1 FROM executions e WHERE e.proposal_id = p.id
                AND e.id IN (${scope.executionIds?.map(() => '?').join(',') || 'NULL'}))
            ORDER BY p.created_at, p.id`).all(...scope.nodeIds, scope.sinceMs, scope.untilMs, ...(scope.executionIds ?? []));
        return rows.map(row => textColumn(row, 'id'));
      });
    },
    /** Scope evidence before loading trace/proposal documents; unresolved work remains relevant at any age. */
    executionIds(scope?: { readonly nodeIds: readonly string[]; readonly sinceMs?: number; readonly untilMs?: number }): string[] {
      return run(() => {
        // MySQL: same unscoped execution-id listing.
        if (scope === undefined) return db.prepare('SELECT id FROM executions ORDER BY created_at, id').all().map(row => textColumn(row, 'id'));
        const { sinceMs, untilMs } = scope;
        const bounds = sinceMs === undefined || untilMs === undefined ? []
          : Array.from({ length: 4 }, () => [sinceMs, untilMs]).flat();
        const windowed = bounds.length > 0;
        // MySQL: same. Journal references close accounting windows whose execution started earlier.
        const rows = db.prepare(`SELECT e.id FROM executions e JOIN liquidity_proposals p ON p.id = e.proposal_id
          WHERE p.node_id IN (${scope.nodeIds.map(() => '?').join(',') || 'NULL'}) ${windowed ? `AND (
            e.status IN ('CLAIMED','PREFLIGHT','SUBMITTING','IN_FLIGHT','UNKNOWN')
            OR (e.status = 'VERIFIED_SUCCESS' AND (e.delta_status = 'PENDING' OR e.actual_fee_msat IS NULL
              OR (EXISTS (SELECT 1 FROM ledger_journals j JOIN ledger_lines l ON l.journal_id = j.id
                WHERE j.execution_id = e.id AND j.event_type = 'REBALANCE_SETTLED' AND l.account_code = 'clearing:unassigned')
                AND NOT EXISTS (SELECT 1 FROM ledger_journals j WHERE j.execution_id = e.id AND j.event_type = 'RECON_DIFFERENCE'
                  AND j.reference = 'incoming:' || e.id || ':release'))))
            OR (e.created_at >= ? AND e.created_at < ?) OR (e.updated_at >= ? AND e.updated_at < ?)
            OR EXISTS (SELECT 1 FROM execution_events ev WHERE ev.execution_id = e.id AND ev.at >= ? AND ev.at < ?)
            OR EXISTS (SELECT 1 FROM ledger_journals j WHERE j.execution_id = e.id AND j.occurred_at >= ? AND j.occurred_at < ?))` : ''}
          ORDER BY e.created_at, e.id`).all(...scope.nodeIds, ...bounds);
        return rows.map(row => textColumn(row, 'id'));
      });
    },
  };
}
export type CommandData = ReturnType<typeof commandData>;
