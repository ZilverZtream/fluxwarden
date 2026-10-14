import type { DatabaseSync, SQLOutputValue } from 'node:sqlite';
import { transitionAllowed, type ExecutionStatus } from '../core/execution.js';
import { committedMsat, inFlightCount, lastTerminal, type TerminalTimes } from './budget.js';
import { PersistenceError } from './errors.js';
import { bigintColumn, checkedMsat, DB_NOW, dbNow, immediate, newUlid, numberColumn, textColumn } from './sql.js';
import { ledgerTransaction } from './ledger.js';
import { post, postAccountTransfer, postTransition } from '../ledger/post.js';
import { CLEARING_UNASSIGNED, channelLocalAccount, EXPENSE_ROUTING_FEES, RECON_DIFFERENCE } from '../ledger/accounts.js';

export type DeltaStatus = 'MATCH' | 'MISMATCH' | 'PENDING';

export interface TransitionFields {
  readonly errorCode?: string;
  readonly routeJson?: string;
  readonly plannedFeeMsat?: bigint;
  readonly actualFeeMsat?: bigint;
  /** SHA-256 of the preimage, 64 lowercase hex; stored before the invoice is created and never changed afterwards. */
  readonly paymentHash?: string;
  /** When given, the write also renews the lease to database now + leaseMs. */
  readonly leaseMs?: number;
  readonly deltaStatus?: DeltaStatus;
  /** The incoming channel proved by the node's receipt; never the route's planned last hop. */
  readonly settledChannelKey?: string | null;
  /**
   * VERIFIED_SUCCESS proven by our settled invoice while the node reported no fee: the actual fee stays NULL and the
   * reservation is consumed at its full reserved amount.
   */
  readonly feeUnreported?: boolean;
  /** Channel balances seen before the send, kept with the SUBMITTING event for delta verification. */
  readonly baseline?: Baseline;
}

/** Local balances of the source and target channels before the send. */
export interface Baseline {
  readonly sourceLocalMsat: bigint;
  readonly targetLocalMsat: bigint;
}

/** An execution the reconciler may have to resolve: SUBMITTING, IN_FLIGHT or UNKNOWN. Ages are database milliseconds. */
export interface UnresolvedExecution {
  readonly executionId: string;
  readonly status: ExecutionStatus;
  readonly fenceEpoch: bigint;
  readonly nodeId: string;
  readonly implementation: 'lnd' | 'cln';
  readonly paymentHash: string | null;
  readonly leaseExpired: boolean;
  /** Milliseconds since submitted_at; null when the row has no submission time. */
  readonly submittedAgeMs: number | null;
  readonly approvedMaxFeeMsat: bigint;
  readonly plannedFeeMsat: bigint | null;
}

export interface ExecutionEvent {
  readonly id: bigint;
  readonly from: ExecutionStatus | null;
  readonly to: ExecutionStatus;
  readonly at: number;
}

/** The stored record of an execution as `actions status` shows it. */
export interface ExecutionView {
  readonly executionId: string;
  readonly status: ExecutionStatus;
  readonly fenceEpoch: bigint;
  readonly leaseExpiresAt: number | null;
  readonly paymentHash: string | null;
  readonly routeJson: string | null;
  readonly plannedFeeMsat: bigint | null;
  readonly actualFeeMsat: bigint | null;
  readonly deltaStatus: DeltaStatus | null;
  readonly errorCode: string | null;
}

/** The stored approval of a proposal together with the proposal it authorises. Times are database unix milliseconds. */
export interface StoredAuthority {
  readonly approvalId: string;
  readonly keyId: string;
  readonly nonce: string;
  readonly approvalExpiresAt: number;
  readonly approvedMaxFeeMsat: bigint;
  readonly approvedMaxCltvDelta: number;
  readonly proposalStatus: string;
  readonly proposalDigest: string;
  readonly proposalExpiresAt: number;
  readonly proposalMaxFeeMsat: bigint | null;
  readonly proposalMaxCltvDelta: number | null;
  readonly policySha256: string;
  readonly nodeId: string;
  readonly sourceChannelId: string | null;
  readonly targetChannelId: string | null;
}

export interface ExistingExecution {
  readonly executionId: string;
  readonly approvalId: string;
  readonly status: ExecutionStatus;
}

export interface HeldClaim {
  readonly executionId: string;
  readonly fenceEpoch: bigint;
  readonly status: ExecutionStatus;
}

/** What execution needs to know about the proposal behind an execution row. */
export interface ExecutionPlan {
  readonly executionId: string;
  readonly status: ExecutionStatus;
  readonly fenceEpoch: bigint;
  readonly nodePubkey: string;
  readonly implementation: 'lnd' | 'cln';
  readonly sourceChannelId: string;
  readonly targetChannelId: string;
  readonly sourceChannelKey: string;
  readonly targetChannelKey: string;
  readonly principalMsat: bigint;
}

/** Reads and writes available inside one claim transaction. */
export interface ClaimScope {
  now(): number;
  authority(approvalId: string, proposalId: string): StoredAuthority | null;
  existing(proposalId: string): ExistingExecution | null;
  /** Takes over a CLAIMED/PREFLIGHT row of the proposal whose lease has expired by the database clock. */
  reclaim(proposalId: string, workerId: string, leaseMs: number): HeldClaim | null;
  /** Inserts a CLAIMED row (fence epoch 1) with its event and a HELD reservation of `reservedMsat`. */
  insertClaimed(row: { proposalId: string; approvalId: string; workerId: string; leaseMs: number; reservedMsat: bigint }): HeldClaim;
  /** Records a refused claim as a CANCELLED row without a reservation. */
  insertCancelled(row: { proposalId: string; approvalId: string; workerId: string; errorCode: string }): string;
  committedMsat(periodMs: number): bigint;
  lastTerminal(sourceChannelId: string, targetChannelId: string): TerminalTimes;
  /** Executions of the node in SUBMITTING, IN_FLIGHT or UNKNOWN. */
  inFlight(nodeId: string): number;
}

export interface ExecutionsRepository {
  /**
   * The fenced write: moves the row from `from` to `to` only while it still carries `fenceEpoch`, with its event and
   * reservation change in the same transaction. Returns the new epoch; zero affected rows throws LEASE_LOST.
   */
  transition(executionId: string, fenceEpoch: bigint, from: ExecutionStatus, to: ExecutionStatus, fields?: TransitionFields): bigint;
  /**
   * The fenced PREFLIGHT -> SUBMITTING write, made only while fewer than `maxInFlight` other executions of the node are in
   * SUBMITTING, IN_FLIGHT or UNKNOWN; otherwise the same fenced write cancels the execution with BUDGET_EXHAUSTED and
   * releases its reservation. The row must already carry its payment hash; SUBMITTING sets submitted_at and renews the
   * lease to database now + leaseMs only if the current lease is still live. One transaction; a stale epoch or expired
   * dispatch lease throws LEASE_LOST.
   */
  submit(executionId: string, fenceEpoch: bigint, maxInFlight: number, leaseMs: number, fields?: TransitionFields): { status: 'SUBMITTING' | 'CANCELLED'; fenceEpoch: bigint };
  /** Records an already-paid stored intent for observation only; this never authorizes a send or renews a lease. */
  recordPaidIntent(executionId: string, fenceEpoch: bigint, paymentHash: string, fields?: TransitionFields): bigint;
  /** Fenced lease renewal; an expired CLAIMED/PREFLIGHT lease cannot be revived. Returns the new epoch. */
  renewLease(executionId: string, fenceEpoch: bigint, leaseMs: number): bigint;
  /** Runs `work` inside one BEGIN IMMEDIATE transaction. */
  claim<T>(work: (scope: ClaimScope) => T): T;
  plan(executionId: string): ExecutionPlan | null;
  /** Whether the row still carries `fenceEpoch`. */
  holds(executionId: string, fenceEpoch: bigint): boolean;
  /** Whether the approval or the proposal behind the row has expired by the database clock. */
  authorityLapsed(executionId: string): boolean;
  /** CLAIMED/PREFLIGHT rows whose lease and whose approval or proposal have expired by the database clock. */
  lapsedClaims(): readonly string[];
  /** Takes the row's lease for `workerId` if it is CLAIMED/PREFLIGHT with an expired lease. */
  takeOver(executionId: string, workerId: string, leaseMs: number): HeldClaim | null;
  /** Fenced write of the delta verification result on a VERIFIED_SUCCESS row. Returns the new epoch. */
  recordDelta(executionId: string, fenceEpoch: bigint, deltaStatus: DeltaStatus): bigint;
  /** Read-only node evidence completes attribution through fenced append-only corrections, never another send. */
  recoverSettlement(executionId: string, fenceEpoch: bigint, settledChannelKey: string | null, actualFeeMsat: bigint): bigint;
  /** Every SUBMITTING, IN_FLIGHT and UNKNOWN execution with its node and lease state, oldest first. */
  unresolved(): readonly UnresolvedExecution[];
  /**
   * Takes the reconciler's fenced lease on a SUBMITTING, IN_FLIGHT or UNKNOWN row still at `fenceEpoch`: an UNKNOWN row
   * whatever its lease, the others only once their lease has expired. Null when not taken.
   */
  takeUnresolved(executionId: string, fenceEpoch: bigint, workerId: string, leaseMs: number): HeldClaim | null;
  view(executionId: string): ExecutionView | null;
  /** The execution's events in insertion order, after event id `afterId`. */
  events(executionId: string, afterId?: bigint): readonly ExecutionEvent[];
  /** The balances recorded with the execution's SUBMITTING event, if any. */
  baseline(executionId: string): Baseline | null;
  /**
   * Fenced record, on an UNKNOWN row, that the payer side was seen FAILED, or that a later read no longer agreed
   * (CLEARED). Returns the new epoch.
   */
  noteObservation(executionId: string, fenceEpoch: bigint, observation: 'FAILED' | 'CLEARED'): bigint;
  /** Milliseconds since the payer side was recorded FAILED, when that is the latest recorded observation. */
  failedSinceMs(executionId: string): number | null;
}

const STATUSES: ReadonlySet<string> = new Set<ExecutionStatus>([
  'CLAIMED', 'PREFLIGHT', 'SUBMITTING', 'IN_FLIGHT', 'VERIFIED_SUCCESS', 'VERIFIED_FAILURE', 'UNKNOWN', 'CANCELLED',
]);

function statusColumn(row: Record<string, SQLOutputValue>, key: string): ExecutionStatus {
  const value = textColumn(row, key);
  if (!STATUSES.has(value)) throw new Error(`column ${key} is not an execution status`);
  return value as ExecutionStatus;
}

function optionalBigint(row: Record<string, SQLOutputValue>, key: string): bigint | null {
  return row[key] === null ? null : bigintColumn(row, key);
}

function optionalNumber(row: Record<string, SQLOutputValue>, key: string): number | null {
  return row[key] === null ? null : numberColumn(row, key);
}

function optionalText(row: Record<string, SQLOutputValue>, key: string): string | null {
  return row[key] === null ? null : textColumn(row, key);
}

function deltaColumn(row: Record<string, SQLOutputValue>, key: string): DeltaStatus | null {
  const value = optionalText(row, key);
  if (value === null || value === 'MATCH' || value === 'MISMATCH' || value === 'PENDING') return value;
  throw new Error(`column ${key} is not a delta status`);
}

const HASH = /^[0-9a-f]{64}$/;

function implementationColumn(row: Record<string, SQLOutputValue>, key: string): 'lnd' | 'cln' {
  const value = textColumn(row, key);
  if (value !== 'lnd' && value !== 'cln') throw new Error(`column ${key} is not a node implementation`);
  return value;
}

function checkedLease(leaseMs: number): number {
  if (!Number.isSafeInteger(leaseMs) || leaseMs <= 0) throw new PersistenceError('OUT_OF_RANGE', 'leaseMs is not a positive integer');
  return leaseMs;
}

function checkedPeriod(periodMs: number): number {
  if (!Number.isSafeInteger(periodMs) || periodMs < 0) throw new PersistenceError('OUT_OF_RANGE', 'the budget period is not a non-negative integer');
  return periodMs;
}

function leaseLost(executionId: string): PersistenceError {
  return new PersistenceError('LEASE_LOST', `execution ${executionId} is no longer held at the expected fence epoch`);
}

function appendEvent(db: DatabaseSync, executionId: string, fenceEpoch: bigint, from: ExecutionStatus | null, to: ExecutionStatus, evidence: object): void {
  // MySQL: same, with NOW(6) for the clock
  db.prepare(`INSERT INTO execution_events (execution_id, fence_epoch, from_status, to_status, evidence_json, at)
    VALUES (?, ?, ?, ?, ?, ${DB_NOW})`).run(executionId, fenceEpoch, from, to, JSON.stringify(evidence));
}

function heldClaim(db: DatabaseSync, where: 'id' | 'proposal_id', key: string): HeldClaim {
  const row = where === 'id'
    // MySQL: same
    ? db.prepare('SELECT id, fence_epoch, status FROM executions WHERE id = ?').get(key)
    // MySQL: same
    : db.prepare('SELECT id, fence_epoch, status FROM executions WHERE proposal_id = ?').get(key);
  if (row === undefined) throw new Error('the claimed execution row is missing');
  return { executionId: textColumn(row, 'id'), fenceEpoch: bigintColumn(row, 'fence_epoch'), status: statusColumn(row, 'status') };
}

function holdsAt(db: DatabaseSync, executionId: string, fenceEpoch: bigint, status: ExecutionStatus): boolean {
  // MySQL: same
  return db.prepare('SELECT 1 AS held FROM executions WHERE id = ? AND fence_epoch = ? AND status = ?').get(executionId, fenceEpoch, status) !== undefined;
}

/** The single fenced status write with its event and reservation change; the caller holds the transaction. */
function fencedTransition(db: DatabaseSync, executionId: string, fenceEpoch: bigint, from: ExecutionStatus, to: ExecutionStatus, fields: TransitionFields, admission: 'dispatch' | 'paid-observation' = 'dispatch'): bigint {
  const planned = fields.plannedFeeMsat === undefined ? null : checkedMsat(fields.plannedFeeMsat, 'plannedFeeMsat');
  const actual = fields.actualFeeMsat === undefined ? null : checkedMsat(fields.actualFeeMsat, 'actualFeeMsat');
  const lease = fields.leaseMs === undefined ? null : checkedLease(fields.leaseMs);
  const unreported = fields.feeUnreported === true;
  if (to === 'VERIFIED_SUCCESS' && (actual === null) !== unreported) {
    throw new PersistenceError('INVALID_TRANSITION', 'VERIFIED_SUCCESS needs the actual fee, or an explicit unreported fee');
  }
  const hash = fields.paymentHash ?? null;
  if (hash !== null) {
    if (!HASH.test(hash)) throw new PersistenceError('OUT_OF_RANGE', 'paymentHash is not 64 lowercase hex characters');
    if (from !== 'PREFLIGHT' || to !== 'PREFLIGHT') {
      throw new PersistenceError('INVALID_TRANSITION', 'a payment hash is stored only while the execution is in PREFLIGHT');
    }
    // MySQL: same
    const current = db.prepare('SELECT payment_hash FROM executions WHERE id = ? AND fence_epoch = ? AND status = ?').get(executionId, fenceEpoch, from);
    if (current === undefined) throw leaseLost(executionId);
    const stored = current['payment_hash'];
    if (stored !== null && stored !== hash) throw new PersistenceError('INVALID_TRANSITION', 'the payment hash is already stored and cannot change');
  }
  // MySQL: same, with NOW(6) and NOW(6) + INTERVAL ? * 1000 MICROSECOND for the clock; fence_epoch always changes, so
  // affected rows equal matched rows
  const result = db.prepare(`UPDATE executions
    SET status = ?, error_code = coalesce(?, error_code), route_json = coalesce(?, route_json),
        planned_fee_msat = coalesce(?, planned_fee_msat), actual_fee_msat = coalesce(?, actual_fee_msat),
        payment_hash = coalesce(payment_hash, ?), delta_status = coalesce(?, delta_status),
        lease_expires_at = CASE WHEN ? IS NULL THEN lease_expires_at ELSE ${DB_NOW} + ? END,
        submitted_at = CASE WHEN ? = 'SUBMITTING' THEN ${DB_NOW} ELSE submitted_at END,
        fence_epoch = fence_epoch + 1, updated_at = ${DB_NOW}
    WHERE id = ? AND fence_epoch = ? AND status = ?
      AND (? = 'paid-observation' OR ? <> 'SUBMITTING' OR (lease_expires_at > ${DB_NOW} AND EXISTS (
        SELECT 1 FROM approvals a JOIN liquidity_proposals p ON p.id = a.proposal_id
        WHERE a.id = executions.approval_id AND p.id = executions.proposal_id
          AND a.expires_at > ${DB_NOW} AND p.expires_at > ${DB_NOW})))`)
    .run(to, fields.errorCode ?? null, fields.routeJson ?? null, planned, actual, hash, fields.deltaStatus ?? null, lease, lease, to,
      executionId, fenceEpoch, from, admission, to);
  if (Number(result.changes) === 0) throw leaseLost(executionId);
  const epoch = fenceEpoch + 1n;
  const evidence: Record<string, string> = {};
  if (admission === 'paid-observation') evidence['observationOnly'] = 'true';
  if (fields.errorCode !== undefined) evidence['errorCode'] = fields.errorCode;
  if (fields.settledChannelKey != null) evidence['settledChannelKey'] = fields.settledChannelKey;
  if (fields.baseline !== undefined) {
    evidence['sourceLocalMsat'] = checkedMsat(fields.baseline.sourceLocalMsat, 'baseline').toString();
    evidence['targetLocalMsat'] = checkedMsat(fields.baseline.targetLocalMsat, 'baseline').toString();
  }
  appendEvent(db, executionId, epoch, from, to, evidence);
  if (to === 'IN_FLIGHT' || to === 'VERIFIED_SUCCESS' || to === 'VERIFIED_FAILURE') {
    // MySQL: same
    const row = db.prepare(`SELECT n.name, s.channel_key AS source_key, t.channel_key AS target_key, p.principal_msat, e.planned_fee_msat
      FROM executions e JOIN liquidity_proposals p ON p.id = e.proposal_id JOIN nodes n ON n.id = p.node_id
      JOIN channels s ON s.id = p.source_channel_id JOIN channels t ON t.id = p.target_channel_id WHERE e.id = ?`).get(executionId);
    if (row !== undefined && row['planned_fee_msat'] !== null) {
      let active = true;
      const tx = ledgerTransaction(db, newUlid, () => active);
      try {
        postTransition(tx, { executionId, node: textColumn(row, 'name'), sourceChannel: textColumn(row, 'source_key'),
          principalMsat: bigintColumn(row, 'principal_msat'), routeFeeMsat: bigintColumn(row, 'planned_fee_msat') },
        to === 'VERIFIED_SUCCESS'
          ? { status: to, settledChannel: fields.settledChannelKey ?? null, actualFeeMsat: actual }
          : { status: to }, dbNow(db));
      } finally { active = false; }
    }
  }
  if (to === 'CANCELLED' || to === 'VERIFIED_FAILURE') {
    // MySQL: same
    db.prepare("UPDATE budget_reservations SET state = 'RELEASED' WHERE execution_id = ? AND state = 'HELD'").run(executionId);
  } else if (to === 'VERIFIED_SUCCESS') {
    // MySQL: same
    db.prepare(`UPDATE budget_reservations SET state = 'CONSUMED', consumed_msat = coalesce(?, reserved_msat)
      WHERE execution_id = ? AND state IN ('HELD','CONSUMED')`).run(actual, executionId);
  }
  return epoch;
}

export function executionsRepository(db: DatabaseSync, writable: (what: string) => void, run: <T>(work: () => T) => T): ExecutionsRepository {
  const scope = (): { scope: ClaimScope; close: () => void } => {
    let open = true;
    const guard = (): void => {
      if (!open) throw new Error('the claim scope is used outside its transaction');
    };
    const value: ClaimScope = {
      now: () => { guard(); return dbNow(db); },

      authority(approvalId, proposalId) {
        guard();
        // MySQL: same
        const row = db.prepare(`SELECT a.id AS approval_id, a.key_id, a.nonce, a.expires_at AS approval_expires_at, a.max_fee_msat AS approved_max_fee_msat,
            a.max_cltv_delta AS approved_max_cltv_delta, p.status AS proposal_status, p.proposal_digest, p.expires_at AS proposal_expires_at,
            p.max_fee_msat AS proposal_max_fee_msat, p.max_cltv_delta AS proposal_max_cltv_delta, v.policy_sha256,
            p.node_id, p.source_channel_id, p.target_channel_id
          FROM approvals a
          JOIN liquidity_proposals p ON p.id = a.proposal_id
          JOIN policy_versions v ON v.id = p.policy_version_id
          WHERE a.id = ? AND a.proposal_id = ?`).get(approvalId, proposalId);
        if (row === undefined) return null;
        return {
          approvalId: textColumn(row, 'approval_id'),
          keyId: textColumn(row, 'key_id'),
          nonce: textColumn(row, 'nonce'),
          approvalExpiresAt: numberColumn(row, 'approval_expires_at'),
          approvedMaxFeeMsat: bigintColumn(row, 'approved_max_fee_msat'),
          approvedMaxCltvDelta: numberColumn(row, 'approved_max_cltv_delta'),
          proposalStatus: textColumn(row, 'proposal_status'),
          proposalDigest: textColumn(row, 'proposal_digest'),
          proposalExpiresAt: numberColumn(row, 'proposal_expires_at'),
          proposalMaxFeeMsat: optionalBigint(row, 'proposal_max_fee_msat'),
          proposalMaxCltvDelta: optionalNumber(row, 'proposal_max_cltv_delta'),
          policySha256: textColumn(row, 'policy_sha256'),
          nodeId: textColumn(row, 'node_id'),
          sourceChannelId: optionalText(row, 'source_channel_id'),
          targetChannelId: optionalText(row, 'target_channel_id'),
        };
      },

      existing(proposalId) {
        guard();
        // MySQL: same
        const row = db.prepare('SELECT id, approval_id, status FROM executions WHERE proposal_id = ?').get(proposalId);
        if (row === undefined) return null;
        return { executionId: textColumn(row, 'id'), approvalId: textColumn(row, 'approval_id'), status: statusColumn(row, 'status') };
      },

      reclaim(proposalId, workerId, leaseMs) {
        guard();
        const lease = checkedLease(leaseMs);
        // MySQL: same, with NOW(6) and NOW(6) + INTERVAL ? * 1000 MICROSECOND for the clock
        const result = db.prepare(`UPDATE executions
          SET worker_id = ?, lease_expires_at = ${DB_NOW} + ?, fence_epoch = fence_epoch + 1, updated_at = ${DB_NOW}
          WHERE proposal_id = ? AND status IN ('CLAIMED','PREFLIGHT') AND lease_expires_at < ${DB_NOW}`).run(workerId, lease, proposalId);
        if (Number(result.changes) === 0) return null;
        const claim = heldClaim(db, 'proposal_id', proposalId);
        appendEvent(db, claim.executionId, claim.fenceEpoch, claim.status, claim.status, { reclaimedBy: workerId });
        return claim;
      },

      insertClaimed(row) {
        guard();
        const lease = checkedLease(row.leaseMs);
        const reserved = checkedMsat(row.reservedMsat, 'reservedMsat');
        const executionId = newUlid();
        // MySQL: same, with NOW(6) and NOW(6) + INTERVAL ? * 1000 MICROSECOND for the clock
        db.prepare(`INSERT INTO executions (id, proposal_id, approval_id, worker_id, fence_epoch, lease_expires_at, status, created_at, updated_at)
          VALUES (?, ?, ?, ?, 1, ${DB_NOW} + ?, 'CLAIMED', ${DB_NOW}, ${DB_NOW})`).run(executionId, row.proposalId, row.approvalId, row.workerId, lease);
        appendEvent(db, executionId, 1n, null, 'CLAIMED', {});
        // MySQL: same, with NOW(6) for the clock
        db.prepare(`INSERT INTO budget_reservations (id, execution_id, period_start, reserved_msat, consumed_msat, state)
          VALUES (?, ?, ${DB_NOW}, ?, NULL, 'HELD')`).run(newUlid(), executionId, reserved);
        return { executionId, fenceEpoch: 1n, status: 'CLAIMED' };
      },

      insertCancelled(row) {
        guard();
        const executionId = newUlid();
        // MySQL: same, with NOW(6) for the clock
        db.prepare(`INSERT INTO executions (id, proposal_id, approval_id, worker_id, fence_epoch, lease_expires_at, status, error_code, created_at, updated_at)
          VALUES (?, ?, ?, ?, 1, NULL, 'CANCELLED', ?, ${DB_NOW}, ${DB_NOW})`).run(executionId, row.proposalId, row.approvalId, row.workerId, row.errorCode);
        appendEvent(db, executionId, 1n, null, 'CANCELLED', { errorCode: row.errorCode });
        return executionId;
      },

      committedMsat: periodMs => { guard(); return committedMsat(db, checkedPeriod(periodMs)); },

      lastTerminal: (sourceChannelId, targetChannelId) => { guard(); return lastTerminal(db, sourceChannelId, targetChannelId); },

      inFlight: nodeId => { guard(); return inFlightCount(db, nodeId, null); },
    };
    return { scope: value, close: () => { open = false; } };
  };

  return {
    transition(executionId, fenceEpoch, from, to, fields = {}) {
      writable('executions.transition');
      if (!transitionAllowed(from, to)) throw new PersistenceError('INVALID_TRANSITION', `an execution cannot move from ${from} to ${to}`);
      return immediate(db, () => {
        if (to === 'SUBMITTING') {
          if (!holdsAt(db, executionId, fenceEpoch, from)) throw leaseLost(executionId);
          throw new PersistenceError('INVALID_TRANSITION', 'SUBMITTING is written by submit, which enforces max_in_flight');
        }
        return fencedTransition(db, executionId, fenceEpoch, from, to, fields);
      });
    },

    submit(executionId, fenceEpoch, maxInFlight, leaseMs, fields = {}) {
      writable('executions.submit');
      if (!Number.isSafeInteger(maxInFlight) || maxInFlight < 0) throw new PersistenceError('OUT_OF_RANGE', 'maxInFlight is not a non-negative integer');
      checkedLease(leaseMs);
      return immediate(db, () => {
        if (!holdsAt(db, executionId, fenceEpoch, 'PREFLIGHT')) throw leaseLost(executionId);
        // MySQL: same joins and predicate, with NOW(6) for the stored expiry comparison.
        const expired = db.prepare(`SELECT 1 FROM executions e JOIN approvals a ON a.id = e.approval_id
          JOIN liquidity_proposals p ON p.id = e.proposal_id WHERE e.id = ?
          AND (a.expires_at <= ${DB_NOW} OR p.expires_at <= ${DB_NOW})`).get(executionId);
        if (expired !== undefined) {
          return { status: 'CANCELLED' as const, fenceEpoch: fencedTransition(db, executionId, fenceEpoch, 'PREFLIGHT', 'CANCELLED', { errorCode: 'APPROVAL_INVALID' }) };
        }
        // MySQL: same
        const node = db.prepare(`SELECT p.node_id, e.payment_hash FROM executions e JOIN liquidity_proposals p ON p.id = e.proposal_id
          WHERE e.id = ?`).get(executionId);
        if (node === undefined) throw leaseLost(executionId);
        if (node['payment_hash'] === null) {
          throw new PersistenceError('INVALID_TRANSITION', 'SUBMITTING needs the payment hash stored first');
        }
        if (inFlightCount(db, textColumn(node, 'node_id'), executionId) >= maxInFlight) {
          const epoch = fencedTransition(db, executionId, fenceEpoch, 'PREFLIGHT', 'CANCELLED', { errorCode: 'BUDGET_EXHAUSTED' });
          return { status: 'CANCELLED' as const, fenceEpoch: epoch };
        }
        return { status: 'SUBMITTING' as const, fenceEpoch: fencedTransition(db, executionId, fenceEpoch, 'PREFLIGHT', 'SUBMITTING', { ...fields, leaseMs }) };
      });
    },

    recordPaidIntent(executionId, fenceEpoch, paymentHash, fields = {}) {
      writable('executions.recordPaidIntent');
      return immediate(db, () => {
        // MySQL: same SELECT with FOR UPDATE to hold the observed intent through its fenced write.
        const row = db.prepare("SELECT status FROM executions WHERE id = ? AND fence_epoch = ? AND status IN ('PREFLIGHT','CANCELLED') AND payment_hash = ?")
          .get(executionId, fenceEpoch, paymentHash);
        if (row === undefined) throw leaseLost(executionId);
        const from = statusColumn(row, 'status');
        const next = fencedTransition(db, executionId, fenceEpoch, from, 'UNKNOWN',
          fields.routeJson === undefined ? {} : { routeJson: fields.routeJson }, 'paid-observation');
        if (from === 'CANCELLED') {
          // This consumes already-observed funds conservatively; it grants no fresh dispatch reservation.
          // MySQL: same UPDATE, in the transaction of the fenced observed-payment write.
          db.prepare("UPDATE budget_reservations SET state = 'CONSUMED', consumed_msat = reserved_msat WHERE execution_id = ? AND state = 'RELEASED'")
            .run(executionId);
        }
        return next;
      });
    },

    renewLease(executionId, fenceEpoch, leaseMs) {
      writable('executions.renewLease');
      const lease = checkedLease(leaseMs);
      // MySQL: same, with NOW(6) and NOW(6) + INTERVAL ? * 1000 MICROSECOND for the clock
      const result = run(() => db.prepare(`UPDATE executions SET lease_expires_at = ${DB_NOW} + ?, fence_epoch = fence_epoch + 1, updated_at = ${DB_NOW}
        WHERE id = ? AND fence_epoch = ?
          AND (status NOT IN ('CLAIMED','PREFLIGHT') OR lease_expires_at > ${DB_NOW})`).run(lease, executionId, fenceEpoch));
      if (Number(result.changes) === 0) throw leaseLost(executionId);
      return fenceEpoch + 1n;
    },

    claim<T>(work: (claimScope: ClaimScope) => T): T {
      writable('executions.claim');
      const { scope: claimScope, close } = scope();
      try {
        return immediate(db, () => work(claimScope));
      } finally {
        close();
      }
    },

    plan: executionId => run(() => {
      // MySQL: same
      const row = db.prepare(`SELECT e.id, e.status, e.fence_epoch, n.expected_pubkey, n.implementation, p.source_channel_id, p.target_channel_id,
          s.channel_key AS source_channel_key, t.channel_key AS target_channel_key, p.principal_msat
        FROM executions e
        JOIN liquidity_proposals p ON p.id = e.proposal_id
        JOIN nodes n ON n.id = p.node_id
        JOIN channels s ON s.id = p.source_channel_id
        JOIN channels t ON t.id = p.target_channel_id
        WHERE e.id = ?`).get(executionId);
      if (row === undefined) return null;
      return {
        executionId: textColumn(row, 'id'),
        status: statusColumn(row, 'status'),
        fenceEpoch: bigintColumn(row, 'fence_epoch'),
        nodePubkey: textColumn(row, 'expected_pubkey'),
        implementation: implementationColumn(row, 'implementation'),
        sourceChannelId: textColumn(row, 'source_channel_id'),
        targetChannelId: textColumn(row, 'target_channel_id'),
        sourceChannelKey: textColumn(row, 'source_channel_key'),
        targetChannelKey: textColumn(row, 'target_channel_key'),
        principalMsat: bigintColumn(row, 'principal_msat'),
      };
    }),

    holds: (executionId, fenceEpoch) => run(() => {
      // MySQL: same
      return db.prepare('SELECT 1 AS held FROM executions WHERE id = ? AND fence_epoch = ?').get(executionId, fenceEpoch) !== undefined;
    }),

    authorityLapsed: executionId => run(() => {
      // MySQL: same, with NOW(6) for the clock
      const row = db.prepare(`SELECT 1 AS lapsed FROM executions e
        JOIN approvals a ON a.id = e.approval_id
        JOIN liquidity_proposals p ON p.id = e.proposal_id
        WHERE e.id = ? AND (a.expires_at <= ${DB_NOW} OR p.expires_at <= ${DB_NOW})`).get(executionId);
      return row !== undefined;
    }),

    lapsedClaims: () => run(() => {
      // MySQL: same, with NOW(6) for the clock
      const rows = db.prepare(`SELECT e.id FROM executions e
        JOIN approvals a ON a.id = e.approval_id
        JOIN liquidity_proposals p ON p.id = e.proposal_id
        WHERE e.status IN ('CLAIMED','PREFLIGHT') AND e.lease_expires_at < ${DB_NOW}
          AND (a.expires_at <= ${DB_NOW} OR p.expires_at <= ${DB_NOW})
        ORDER BY e.id`).all();
      return rows.map(row => textColumn(row, 'id'));
    }),

    takeOver(executionId, workerId, leaseMs) {
      writable('executions.takeOver');
      const lease = checkedLease(leaseMs);
      return immediate(db, () => {
        // MySQL: same, with NOW(6) and NOW(6) + INTERVAL ? * 1000 MICROSECOND for the clock
        const result = db.prepare(`UPDATE executions
          SET worker_id = ?, lease_expires_at = ${DB_NOW} + ?, fence_epoch = fence_epoch + 1, updated_at = ${DB_NOW}
          WHERE id = ? AND status IN ('CLAIMED','PREFLIGHT') AND lease_expires_at < ${DB_NOW}`).run(workerId, lease, executionId);
        if (Number(result.changes) === 0) return null;
        const claim = heldClaim(db, 'id', executionId);
        appendEvent(db, claim.executionId, claim.fenceEpoch, claim.status, claim.status, { reclaimedBy: workerId });
        return claim;
      });
    },

    recordDelta(executionId, fenceEpoch, deltaStatus) {
      writable('executions.recordDelta');
      return immediate(db, () => {
        // MySQL: same, with NOW(6) for the clock
        const result = db.prepare(`UPDATE executions SET delta_status = ?, fence_epoch = fence_epoch + 1, updated_at = ${DB_NOW}
          WHERE id = ? AND fence_epoch = ? AND status = 'VERIFIED_SUCCESS'`).run(deltaStatus, executionId, fenceEpoch);
        if (Number(result.changes) === 0) throw leaseLost(executionId);
        appendEvent(db, executionId, fenceEpoch + 1n, 'VERIFIED_SUCCESS', 'VERIFIED_SUCCESS', { deltaStatus });
        return fenceEpoch + 1n;
      });
    },

    recoverSettlement(executionId, fenceEpoch, settledChannelKey, actualFeeMsat) {
      writable('executions.recoverSettlement');
      const fee = checkedMsat(actualFeeMsat, 'actualFeeMsat');
      return immediate(db, () => {
        // MySQL: same SELECT with FOR UPDATE to lock the terminal execution during attribution corrections.
        const row = db.prepare(`SELECT n.name, p.principal_msat, e.actual_fee_msat FROM executions e
          JOIN liquidity_proposals p ON p.id = e.proposal_id JOIN nodes n ON n.id = p.node_id
          WHERE e.id = ? AND e.fence_epoch = ? AND e.status = 'VERIFIED_SUCCESS'`).get(executionId, fenceEpoch);
        if (row === undefined) throw leaseLost(executionId);
        const priorFee = row['actual_fee_msat'];
        if (priorFee !== null && priorFee !== fee) throw new PersistenceError('INVALID_TRANSITION', 'a terminal reported fee cannot be replaced');
        let active = true;
        const tx = ledgerTransaction(db, newUlid, () => active);
        try {
          const settled = tx.findJournal('REBALANCE_SETTLED', executionId);
          if (settled === null) throw new PersistenceError('INVALID_TRANSITION', 'a terminal settlement journal is missing');
          const unassigned = settled.lines.find(line => line.account === CLEARING_UNASSIGNED)?.debitMsat ?? 0n;
          if (settledChannelKey !== null && unassigned > 0n) {
            postAccountTransfer(tx, { from: CLEARING_UNASSIGNED, to: channelLocalAccount(textColumn(row, 'name'), settledChannelKey),
              amount: unassigned, reference: `incoming:${executionId}`, executionId, occurredAt: dbNow(db) });
          }
          if (priorFee === null && fee > 0n) {
            post(tx, { eventType: 'RECON_DIFFERENCE', reference: `fee-reported:${executionId}`, executionId, occurredAt: dbNow(db),
              lines: [{ account: EXPENSE_ROUTING_FEES, debitMsat: fee, creditMsat: 0n }, { account: RECON_DIFFERENCE, debitMsat: 0n, creditMsat: fee }] });
          }
          // MySQL: same fenced UPDATE, with NOW(6) for updated_at; changing the epoch changes the matched row.
          const result = db.prepare(`UPDATE executions SET actual_fee_msat = coalesce(actual_fee_msat, ?),
            fence_epoch = fence_epoch + 1, updated_at = ${DB_NOW} WHERE id = ? AND fence_epoch = ? AND status = 'VERIFIED_SUCCESS'`)
            .run(fee, executionId, fenceEpoch);
          if (Number(result.changes) === 0) throw leaseLost(executionId);
          // MySQL: same UPDATE, in the transaction of the fenced terminal attribution write.
          if (priorFee === null) db.prepare("UPDATE budget_reservations SET consumed_msat = ? WHERE execution_id = ? AND state = 'CONSUMED'").run(fee, executionId);
          appendEvent(db, executionId, fenceEpoch + 1n, 'VERIFIED_SUCCESS', 'VERIFIED_SUCCESS',
            { actualFeeMsat: fee.toString(), settledChannelKey, attributionPending: settledChannelKey === null });
        } finally { active = false; }
        return fenceEpoch + 1n;
      });
    },

    unresolved: () => run(() => {
      // MySQL: same, with NOW(6) and TIMESTAMPDIFF for the clock
      const rows = db.prepare(`SELECT e.id, e.status, e.fence_epoch, p.node_id, n.implementation, e.payment_hash, a.max_fee_msat AS approved_max_fee_msat, e.planned_fee_msat,
          CASE WHEN e.lease_expires_at IS NULL OR e.lease_expires_at < ${DB_NOW} THEN 1 ELSE 0 END AS lease_expired,
          CASE WHEN e.submitted_at IS NULL THEN NULL ELSE ${DB_NOW} - e.submitted_at END AS submitted_age_ms
        FROM executions e
        JOIN liquidity_proposals p ON p.id = e.proposal_id
        JOIN approvals a ON a.id = e.approval_id
        JOIN nodes n ON n.id = p.node_id
        WHERE e.status IN ('SUBMITTING','IN_FLIGHT','UNKNOWN') OR (e.status = 'VERIFIED_SUCCESS' AND (
          e.actual_fee_msat IS NULL OR (EXISTS (SELECT 1 FROM ledger_journals j JOIN ledger_lines l ON l.journal_id = j.id
            WHERE j.execution_id = e.id AND j.event_type = 'REBALANCE_SETTLED' AND l.account_code = 'clearing:unassigned')
            AND NOT EXISTS (SELECT 1 FROM ledger_journals j WHERE j.execution_id = e.id AND j.event_type = 'RECON_DIFFERENCE'
              AND j.reference = 'incoming:' || e.id || ':release'))))
        ORDER BY e.id`).all();
      return rows.map(row => ({
        executionId: textColumn(row, 'id'),
        status: statusColumn(row, 'status'),
        fenceEpoch: bigintColumn(row, 'fence_epoch'),
        nodeId: textColumn(row, 'node_id'),
        implementation: implementationColumn(row, 'implementation'),
        paymentHash: optionalText(row, 'payment_hash'),
        leaseExpired: numberColumn(row, 'lease_expired') === 1,
        submittedAgeMs: optionalNumber(row, 'submitted_age_ms'),
        approvedMaxFeeMsat: bigintColumn(row, 'approved_max_fee_msat'),
        plannedFeeMsat: optionalBigint(row, 'planned_fee_msat'),
      }));
    }),

    takeUnresolved(executionId, fenceEpoch, workerId, leaseMs) {
      writable('executions.takeUnresolved');
      const lease = checkedLease(leaseMs);
      return immediate(db, () => {
        // MySQL: same, with NOW(6) and NOW(6) + INTERVAL ? * 1000 MICROSECOND for the clock
        const result = db.prepare(`UPDATE executions
          SET worker_id = ?, lease_expires_at = ${DB_NOW} + ?, fence_epoch = fence_epoch + 1, updated_at = ${DB_NOW}
          WHERE id = ? AND fence_epoch = ? AND status IN ('SUBMITTING','IN_FLIGHT','UNKNOWN','VERIFIED_SUCCESS')
            AND (status IN ('UNKNOWN','VERIFIED_SUCCESS') OR lease_expires_at IS NULL OR lease_expires_at < ${DB_NOW})`)
          .run(workerId, lease, executionId, fenceEpoch);
        if (Number(result.changes) === 0) return null;
        const claim = heldClaim(db, 'id', executionId);
        appendEvent(db, claim.executionId, claim.fenceEpoch, claim.status, claim.status, { reclaimedBy: workerId });
        return claim;
      });
    },

    view: executionId => run(() => {
      // MySQL: same
      const row = db.prepare(`SELECT id, status, fence_epoch, lease_expires_at, payment_hash, route_json, planned_fee_msat, actual_fee_msat,
          delta_status, error_code FROM executions WHERE id = ?`).get(executionId);
      if (row === undefined) return null;
      return {
        executionId: textColumn(row, 'id'),
        status: statusColumn(row, 'status'),
        fenceEpoch: bigintColumn(row, 'fence_epoch'),
        leaseExpiresAt: optionalNumber(row, 'lease_expires_at'),
        paymentHash: optionalText(row, 'payment_hash'),
        routeJson: optionalText(row, 'route_json'),
        plannedFeeMsat: optionalBigint(row, 'planned_fee_msat'),
        actualFeeMsat: optionalBigint(row, 'actual_fee_msat'),
        deltaStatus: deltaColumn(row, 'delta_status'),
        errorCode: optionalText(row, 'error_code'),
      };
    }),

    events: (executionId, afterId = 0n) => run(() => {
      // MySQL: same
      const rows = db.prepare('SELECT id, from_status, to_status, at FROM execution_events WHERE execution_id = ? AND id > ? ORDER BY id')
        .all(executionId, afterId);
      return rows.map(row => ({
        id: bigintColumn(row, 'id'),
        from: row['from_status'] === null ? null : statusColumn(row, 'from_status'),
        to: statusColumn(row, 'to_status'),
        at: numberColumn(row, 'at'),
      }));
    }),

    baseline: executionId => run(() => {
      // MySQL: same
      const row = db.prepare(`SELECT evidence_json FROM execution_events WHERE execution_id = ? AND to_status = 'SUBMITTING'
        AND (from_status IS NULL OR from_status <> 'SUBMITTING') ORDER BY id DESC LIMIT 1`).get(executionId);
      if (row === undefined) return null;
      const evidence: unknown = JSON.parse(textColumn(row, 'evidence_json'));
      if (evidence === null || typeof evidence !== 'object') return null;
      const source = (evidence as Record<string, unknown>)['sourceLocalMsat'];
      const target = (evidence as Record<string, unknown>)['targetLocalMsat'];
      if (typeof source !== 'string' || typeof target !== 'string' || !/^(0|[1-9][0-9]*)$/.test(source) || !/^(0|[1-9][0-9]*)$/.test(target)) return null;
      return { sourceLocalMsat: BigInt(source), targetLocalMsat: BigInt(target) };
    }),

    noteObservation(executionId, fenceEpoch, observation) {
      writable('executions.noteObservation');
      return immediate(db, () => {
        // MySQL: same, with NOW(6) for the clock
        const result = db.prepare(`UPDATE executions SET fence_epoch = fence_epoch + 1, updated_at = ${DB_NOW}
          WHERE id = ? AND fence_epoch = ? AND status = 'UNKNOWN'`).run(executionId, fenceEpoch);
        if (Number(result.changes) === 0) throw leaseLost(executionId);
        appendEvent(db, executionId, fenceEpoch + 1n, 'UNKNOWN', 'UNKNOWN', { observation });
        return fenceEpoch + 1n;
      });
    },

    failedSinceMs: executionId => run(() => {
      // MySQL: JSON_UNQUOTE(JSON_EXTRACT(evidence_json, '$.observation')) and TIMESTAMPDIFF for the clock
      const row = db.prepare(`SELECT json_extract(evidence_json, '$.observation') AS observation, ${DB_NOW} - at AS age_ms
        FROM execution_events WHERE execution_id = ? AND json_extract(evidence_json, '$.observation') IS NOT NULL
        ORDER BY id DESC LIMIT 1`).get(executionId);
      if (row === undefined || row['observation'] !== 'FAILED') return null;
      return numberColumn(row, 'age_ms');
    }),
  };
}
