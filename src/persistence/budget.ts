import type { DatabaseSync } from 'node:sqlite';
import { bigintColumn, DB_NOW } from './sql.js';

/** Database times (unix milliseconds) of the latest failure on a channel pair and the latest success touching either channel. */
export interface TerminalTimes {
  readonly failureAt: number | null;
  readonly successAt: number | null;
}

/**
 * The fee budget already committed: every HELD reservation, whatever its age, plus the actual fees consumed by
 * reservations whose period started within the last `periodMs` of database time. Summed as bigint.
 */
export function committedMsat(db: DatabaseSync, periodMs: number): bigint {
  // MySQL: same, with NOW(6) - INTERVAL ? * 1000 MICROSECOND for the window start
  const rows = db.prepare(`SELECT CASE WHEN state = 'HELD' THEN reserved_msat ELSE coalesce(consumed_msat, reserved_msat) END AS amount_msat
    FROM budget_reservations
    WHERE state = 'HELD' OR (state = 'CONSUMED' AND period_start > ${DB_NOW} - ?)`).all(periodMs);
  let total = 0n;
  for (const row of rows) total += bigintColumn(row, 'amount_msat');
  return total;
}

function optionalTime(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'bigint') throw new Error('terminal time is not an integer');
  return Number(value);
}

/**
 * Cooldown anchors at database time: the latest VERIFIED_FAILURE of the source/target pair, and the latest
 * VERIFIED_SUCCESS of any execution touching S or T as either end, each at the database time of its terminal transition
 * event (the row's updated_at only when no event exists).
 */
export function lastTerminal(db: DatabaseSync, sourceChannelId: string, targetChannelId: string): TerminalTimes {
  // MySQL: same
  const row = db.prepare(`SELECT
      max(CASE WHEN e.status = 'VERIFIED_FAILURE' AND p.source_channel_id = ? AND p.target_channel_id = ?
          THEN coalesce(ev.at, e.updated_at) END) AS failure_at,
      max(CASE WHEN e.status = 'VERIFIED_SUCCESS'
          THEN coalesce(ev.at, e.updated_at) END) AS success_at
    FROM executions e
    JOIN liquidity_proposals p ON p.id = e.proposal_id
    LEFT JOIN execution_events ev ON ev.execution_id = e.id AND ev.to_status = e.status
    WHERE e.status IN ('VERIFIED_FAILURE', 'VERIFIED_SUCCESS')
      AND (p.source_channel_id IN (?, ?) OR p.target_channel_id IN (?, ?))`)
    .get(sourceChannelId, targetChannelId, sourceChannelId, targetChannelId, sourceChannelId, targetChannelId);
  return { failureAt: optionalTime(row?.['failure_at']), successAt: optionalTime(row?.['success_at']) };
}

/** Executions of the node that may have sent an HTLC and are not resolved: SUBMITTING, IN_FLIGHT or UNKNOWN. */
export function inFlightCount(db: DatabaseSync, nodeId: string, excludeExecutionId: string | null): number {
  // MySQL: same, with NOT (e.id <=> ?) in place of e.id IS NOT ?
  const row = db.prepare(`SELECT count(*) AS in_flight FROM executions e
    JOIN liquidity_proposals p ON p.id = e.proposal_id
    WHERE p.node_id = ? AND e.status IN ('SUBMITTING', 'IN_FLIGHT', 'UNKNOWN') AND e.id IS NOT ?`).get(nodeId, excludeExecutionId);
  return row === undefined ? 0 : Number(bigintColumn(row, 'in_flight'));
}
