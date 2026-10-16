/*
Interface: claims, fenced writes, preflight, recovery and budget admission at execution time.

src/persistence/executions.ts and src/persistence/budget.ts are reached through `openDatabase` of src/persistence/index.ts,
whose Database gains:

  readonly executions: {
    // Fenced transition: UPDATE executions SET status = to, <fields>, fence_epoch = fence_epoch + 1, updated_at = <db now>
    //   WHERE id = ? AND fence_epoch = ? AND status = from (SPEC §6.4 fencedTransition). Returns fenceEpoch + 1n.
    // Zero affected rows throws PersistenceError with code 'LEASE_LOST' and writes nothing (no event, no reservation change).
    // fields.paymentHash is write-once (SPEC §8.4 resolves by hash): a write carrying a different hash than the stored one
    // throws 'INVALID_TRANSITION' and writes nothing.
    // Same transaction: one execution_events row (from_status, to_status); the budget reservation becomes RELEASED on
    // CANCELLED or VERIFIED_FAILURE, CONSUMED with consumed_msat = fields.actualFeeMsat on VERIFIED_SUCCESS (also when the
    // actual fee exceeds the reservation), and stays HELD otherwise (SPEC §6.6). fields.leaseMs renews the lease to
    // <db now> + leaseMs in the same write (SPEC §6.4 "renewed by fenced writes"). SUBMITTING is written only by submit.
    transition(executionId: string, fenceEpoch: bigint, from: ExecutionStatus, to: ExecutionStatus, fields?: TransitionFields): bigint;
    // The fenced PREFLIGHT -> SUBMITTING write (SPEC §8.2, §7.1 max_in_flight), one BEGIN IMMEDIATE transaction:
    //   stale epoch or status not PREFLIGHT -> throws 'LEASE_LOST', nothing written;
    //   payment_hash still NULL -> throws 'INVALID_TRANSITION', nothing written ("preimage hash and invoice persisted");
    //   maxInFlight or more OTHER executions of the same node in SUBMITTING, IN_FLIGHT or UNKNOWN -> the same fenced write
    //     moves the row to CANCELLED, error_code 'BUDGET_EXHAUSTED', reservation RELEASED: { status: 'CANCELLED', fenceEpoch: e + 1n };
    //   otherwise SUBMITTING with submitted_at = <db now> and lease_expires_at = <db now> + leaseMs:
    //     { status: 'SUBMITTING', fenceEpoch: e + 1n }.
    submit(executionId: string, fenceEpoch: bigint, maxInFlight: number, leaseMs: number, fields?: TransitionFields): { status: 'SUBMITTING' | 'CANCELLED'; fenceEpoch: bigint };
    // Fenced no-op that sets lease_expires_at = <db now> + leaseMs (SPEC §6.4 lease re-assertion). Returns fenceEpoch + 1n;
    // a stale epoch throws code 'LEASE_LOST'.
    renewLease(executionId: string, fenceEpoch: bigint, leaseMs: number): bigint;
  };
  TransitionFields = { errorCode?: string; routeJson?: string; plannedFeeMsat?: bigint; actualFeeMsat?: bigint;
                       paymentHash?: string; leaseMs?: number }
  PersistenceCode gains 'LEASE_LOST' and 'INVALID_TRANSITION'.

src/executor/claim.ts:
  claimExecution(db: Database, input: ClaimInput): ClaimOutcome          (synchronous)
  ClaimInput = { approval: VerifiedApproval; policy: ExecutionPolicy; approvalKeyIds: readonly string[]; workerId: string; leaseMs: number }
  approvalKeyIds are the key_ids of the configured approval_keys (SPEC §10.1); SECURITY §4.1: removing a public key
  invalidates every unclaimed approval signed by it.
  One BEGIN IMMEDIATE transaction (SPEC §6.4, §6.6, ARCHITECTURE §3 step 6):
    - approval.keyId must be one of approvalKeyIds, and the approval must be the stored `approvals` row of
      approval.proposalId with the same nonce, key_id, expires_at, max_fee_msat and max_cltv_delta, the proposal APPROVED,
      its digest equal to approval.proposalDigest, the approval and the proposal unexpired by the database clock, and the
      approval's expires_at no later than the proposal's (SECURITY §4.1 step 7, SPEC §7.7) -> else
      step 'APPROVAL_INVALID', no row written;
    - approval.policySha256 must equal policy.sha256 and the proposal's policy_versions.policy_sha256 -> else
      'POLICY_CHANGED', no row written;
    - insert-or-reclaim as SPEC §6.4: a new row starts CLAIMED with fence_epoch 1 and lease_expires_at = <db now> + leaseMs;
      re-claim only from CLAIMED/PREFLIGHT with lease_expires_at < <db now>, and only under the approval the execution was
      claimed with (executions.approval_id; an approval authorises at most one execution and is its audit link, SPEC §7.7,
      INV-09), setting worker_id, the lease and fence_epoch + 1 and keeping the existing reservation; any other existing
      row -> 'claimed-elsewhere';
    - budget (new rows only): sum of reserved_msat of every HELD reservation (whatever its age) plus consumed_msat of the
      CONSUMED reservations with period_start > <db now> - policy.budget.periodMs, plus approval.approvedMaxFeeMsat, must
      be <= policy.budget.msat, else 'BUDGET_EXHAUSTED'; an admitted claim inserts a HELD reservation with
      reserved_msat = approvedMaxFeeMsat and period_start = <db now>;
    - max_in_flight (new rows only; SPEC §7.1, §7.4): when the proposal's node already has policy.maxInFlight or more
      executions in SUBMITTING, IN_FLIGHT or UNKNOWN, the claim is refused with 'BUDGET_EXHAUSTED' (the refusal §7.4
      names for budget and max_in_flight); CLAIMED, PREFLIGHT, terminal rows and other nodes' rows do not count;
    - cooldown (new rows only; SPEC §7.1, §7.2): an execution of the same source/target channel pair that reached
      VERIFIED_FAILURE less than cooldownAfterFailureMs ago, or an execution touching the proposal's source or target
      channel (as its own source or target) that reached VERIFIED_SUCCESS less than cooldownAfterSuccessMs ago ->
      'COOLDOWN_ACTIVE'. The age is <db now> minus the terminal database time, the `at` of the execution_events row of the
      terminal transition (SECURITY §4.3); a later write to the terminal row (its updated_at) does not move it; a terminal
      time after <db now> keeps the cooldown active. CANCELLED starts none.
    - a BUDGET_EXHAUSTED or COOLDOWN_ACTIVE refusal inserts the execution row directly as CANCELLED with error_code set
      to the step and holds no reservation (SPEC §6.6 "execution CANCELLED").
    - the new CLAIMED row gets one execution_events row with to_status 'CLAIMED'.
  ClaimOutcome =
    | { ok: true; executionId: string; fenceEpoch: bigint }
    | { ok: false; exit: 5; step: 'claimed-elsewhere' | 'BUDGET_EXHAUSTED' | 'COOLDOWN_ACTIVE' | 'APPROVAL_INVALID' | 'POLICY_CHANGED';
        executionId: string | null }                       // the existing or cancelled row; null when no row exists
  SPEC §7.5 has no refusal code for an invalid approval or a changed policy digest; 'APPROVAL_INVALID' and
  'POLICY_CHANGED' are this interface's names for them (exit 5, SPEC §10.3 AE3).

src/executor/preflight.ts:
  prepareExecution(deps: PreflightDeps, input: { approval; policy; approvalKeyIds }): Promise<PreflightOutcome>
    The configured network (policy.network) must be exactly 'regtest' before the claim: otherwise
    { kind: 'REFUSED', executionId: null, exit: 5, step: 'network-lock' }, no row and no node call (SPEC §5.2 H4, T-01).
    Then claimExecution, fenced CLAIMED -> PREFLIGHT, and SPEC §8.3 P2-P4 / §10.3 AE5-AE8 in this order:
      handshake(): pubkey = the proposal node's nodes.expected_pubkey                          -> 5 'identity'
                   network exactly 'regtest'                                                  -> 5 'network-lock'
                   synced                                                                    -> 5 'chain-sync'
      capabilities() include CHANNEL_READ, PAYMENT_READ, INVOICE_CREATE, INVOICE_CANCEL, ROUTE_QUERY_PINNED, SEND_TO_ROUTE,
                   PAYMENT_TRACK (BOOKKEEPER_READ is not required)                            -> 3 'CAPABILITY_UNSUPPORTED'
      cooldown re-check as in the claim                                                       -> 5 'COOLDOWN_ACTIVE'
      listChannels(): S and T present, <db now> - observedAt <= policy.maxSnapshotAgeMs        -> 5 'STALE_SNAPSHOT'
                   Spendable(S) - (principal + approvedMaxFeeMsat) >= minChannelReserveMsat (INV-14) -> 5 'RESERVE_FLOOR'
      findCircularRoute({ sourceChannelKey, targetChannelKey, principalMsat, maxFeeMsat: approvedMaxFeeMsat,
                   maxFeePpm, exemptFeeMsat, maxCltvDelta: approvedMaxCltvDelta }) once; a { refusal } answer -> 5 refusal;
                   then SPEC §5.5 on the live route and the fresh snapshot, the first failing check recorded, with the fee
                   F recomputed from the hops (first-hop amount minus the delivered amount), never the node's total:
                   V1 first hop over S to S's peer (hops[0].nodeOut = outPeer = peer of S), last hop over T to our node,
                      inPeer = peer of T                                                       -> 5 'NO_FEASIBLE_ROUTE'
                   V12 S and T ACTIVE in the fresh snapshot                                   -> 5 'NO_FEASIBLE_ROUTE'
                   V2 no channel twice                                                        -> 5 'REPEATED_CHANNEL'
                   V3 F <= approvedMaxFeeMsat                                                 -> 5 'FEE_CEILING_EXCEEDED'
                   V5 totalTimelockDelta <= approvedMaxCltvDelta, hop expiries never increase -> 5 'CLTV_DELTA_UNSAFE'
                   V7 outPeer != inPeer                                                       -> 5 'SAME_PEER'
                   V9 Receivable(T) >= principal                                              -> 5 'LAST_HOP_RECEIVABLE'
                   V10 last hop delivers exactly the principal, amounts never grow along the path, first-hop amount =
                      principal + the route's stated totalFeeMsat                              -> 5 'NO_FEASIBLE_ROUTE'
                   V11 no hop delivering back to our node before the last hop                 -> 5 'REPEATED_CHANNEL'
      the approval still unexpired by the database clock when preflight finishes            -> 5 'APPROVAL_INVALID'
    An adapter call that throws (handshake, listChannels, findCircularRoute) cancels the execution (fenced, reservation
      RELEASED): exit 4 step 'NODE_UNREACHABLE' for a TransportError, ProtocolError or LndError of src/core/errors.ts (SPEC §5.2 H2,
      §10.2 exit 4, AE5 "still CANCELLED"), exit 8 step 'internal' for any other error (SPEC §10.2 exit 8).
    A failed check: fenced PREFLIGHT -> CANCELLED with error_code = step (reservation RELEASED) and
      { kind: 'CANCELLED', executionId, exit, step }. A claim refusal: { kind: 'REFUSED', executionId, exit: 5, step } (a
      BUDGET_EXHAUSTED / COOLDOWN_ACTIVE claim refusal reports kind 'CANCELLED', its row being CANCELLED).
    A PersistenceError BUSY from a preflight write never leaves the row PREFLIGHT with a HELD reservation behind a settled
      outcome (SPEC §6.6 every exit path): either the write is retried and preflight completes (READY with the route
      recorded), or the execution is cancelled (CANCELLED, reservation RELEASED, exit 8 'internal').
    Every status and route write of preflight goes through Database.executions.transition, the single fenced write helper
      (INV-18), with fields.leaseMs = deps.leaseMs. A write that throws LEASE_LOST:
      { kind: 'REFUSED', executionId, exit: 5, step: 'lease-lost' } and no further node call.
    Passing: the live route is recorded with a fenced write (route_json, planned_fee_msat = F), the row
      stays PREFLIGHT with payment_hash NULL, and { kind: 'READY', executionId, fenceEpoch, route } with fenceEpoch equal
      to the stored fence_epoch. Preflight never calls createInvoice, sendOnRoute or cancelUnpaidInvoice.
  recoverPreflight(deps: PreflightDeps): Promise<{ cancelled: readonly string[] }>
    Restart sweep (SPEC §6.5, §10.4 DM4): every CLAIMED/PREFLIGHT row whose lease has expired by the database clock and
    whose approval or proposal has expired is taken with its own fenced lease and moved to CANCELLED with error_code
    'APPROVAL_INVALID', reservation RELEASED. Rows with a live lease, an unexpired approval, or any other status are left
    untouched. No node call.
  PreflightDeps = { db: Database; adapter: PreflightAdapter; workerId: string; leaseMs: number }
  PreflightAdapter = the SPEC §5.1 LightningNodeAdapter methods handshake, capabilities, listChannels, findCircularRoute,
    createInvoice, sendOnRoute, cancelUnpaidInvoice, with NormalizedChannel of src/core/normalize.ts and CircularRoute of SPEC §5.1;
    findCircularRoute(req: RouteRequest) resolves to a CircularRoute or { refusal: <SPEC §7.5 code> }.
*/
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { constants, copyFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { pathToFileURL } from 'node:url';
import { childEnv, repoRoot } from './cli.js';
import { makeOwnerOnlyDir } from './cp015-persistence.js';

export type ExecutionStatus = 'CLAIMED' | 'PREFLIGHT' | 'SUBMITTING' | 'IN_FLIGHT' | 'VERIFIED_SUCCESS' | 'VERIFIED_FAILURE' | 'UNKNOWN' | 'CANCELLED';
export type NetworkType = 'regtest' | 'signet' | 'testnet' | 'testnet4' | 'mainnet';
export type NodeCapability = 'CHANNEL_READ' | 'PAYMENT_READ' | 'INVOICE_CREATE' | 'INVOICE_CANCEL' | 'ROUTE_QUERY_PINNED' | 'SEND_TO_ROUTE' | 'PAYMENT_TRACK' | 'BOOKKEEPER_READ';

/** A verified approval as the approval module hands it to the executor (SPEC §7.7, SECURITY §4.1). */
export interface VerifiedApproval {
  readonly approvalId: string;
  readonly proposalId: string;
  readonly keyId: string;
  readonly nonce: string;
  readonly proposalDigest: string;
  readonly policySha256: string;
  readonly approvedMaxFeeMsat: bigint;
  readonly approvedMaxCltvDelta: number;
  /** Unix milliseconds. */
  readonly expiresAt: number;
}

/** The validated active policy (SPEC §7.1, §7.2), durations in milliseconds. */
export interface ExecutionPolicy {
  readonly sha256: string;
  readonly network: string;
  readonly maxFeeMsat: bigint;
  readonly maxFeePpm: bigint;
  readonly exemptFeeMsat: bigint;
  readonly maxCltvDelta: number;
  readonly minChannelReserveMsat: bigint;
  readonly budget: { readonly msat: bigint; readonly periodMs: number };
  readonly cooldownAfterFailureMs: number;
  readonly cooldownAfterSuccessMs: number;
  readonly maxInFlight: number;
  readonly maxSnapshotAgeMs: number;
}

export interface TransitionFields {
  /** Existing public receipt fields for fully attributed terminal fixture setup. */
  readonly settledChannelKey?: string | null;
  readonly deltaStatus?: 'MATCH' | 'MISMATCH' | 'PENDING';
  readonly errorCode?: string;
  readonly routeJson?: string;
  readonly plannedFeeMsat?: bigint;
  readonly actualFeeMsat?: bigint;
  readonly paymentHash?: string;
  readonly leaseMs?: number;
}

export interface ExecDatabase {
  close(): void;
  readonly executions: {
    transition(executionId: string, fenceEpoch: bigint, from: ExecutionStatus, to: ExecutionStatus, fields?: TransitionFields): bigint;
    submit(executionId: string, fenceEpoch: bigint, maxInFlight: number, leaseMs: number, fields?: TransitionFields): { status: 'SUBMITTING' | 'CANCELLED'; fenceEpoch: bigint };
    renewLease(executionId: string, fenceEpoch: bigint, leaseMs: number): bigint;
  };
}

export interface ExecPersistence {
  openDatabase(path: string, options: { readOnly: boolean; busyTimeoutMs?: number }): ExecDatabase;
}

export interface ClaimInput {
  readonly approval: VerifiedApproval;
  readonly policy: ExecutionPolicy;
  readonly approvalKeyIds: readonly string[];
  readonly workerId: string;
  readonly leaseMs: number;
}

export type ClaimOutcome =
  | { readonly ok: true; readonly executionId: string; readonly fenceEpoch: bigint }
  | { readonly ok: false; readonly exit: number; readonly step: string; readonly executionId: string | null };

export interface ClaimModule {
  readonly claimExecution: (db: ExecDatabase, input: ClaimInput) => ClaimOutcome;
}

export interface RouteHop {
  readonly channelKey: string;
  readonly nodeOut: string;
  readonly amountOutMsat: bigint;
  readonly expiry: number;
}

export interface CircularRoute {
  readonly sourceChannelKey: string;
  readonly targetChannelKey: string;
  readonly outPeer: string;
  readonly inPeer: string;
  readonly principalMsat: bigint;
  readonly hops: readonly RouteHop[];
  readonly totalFeeMsat: bigint;
  readonly feePpmCeil: bigint;
  readonly totalTimelockDelta: number;
  readonly parts: 1;
}

export interface RouteRequest {
  readonly sourceChannelKey: string;
  readonly targetChannelKey: string;
  readonly principalMsat: bigint;
  readonly maxFeeMsat: bigint;
  readonly maxFeePpm: bigint;
  readonly exemptFeeMsat: bigint;
  readonly maxCltvDelta: number;
}

export interface FakeChannel {
  readonly nodeId: string; readonly channelKey: string; readonly scid: string | null; readonly peerPubkey: string;
  readonly fundingOutpoint: string; readonly state: 'ACTIVE' | 'INACTIVE' | 'PENDING' | 'CLOSING' | 'UNKNOWN'; readonly nodeState: string;
  readonly opener: 'local' | 'remote'; readonly capacityMsat: bigint; readonly localBalanceMsat: bigint; readonly remoteBalanceMsat: bigint;
  readonly spendableMsat: bigint; readonly receivableMsat: bigint; readonly confidence: 'NODE_REPORTED' | 'DERIVED_ESTIMATE';
  readonly caveat: string | null; readonly localReserveMsat: bigint; readonly remoteReserveMsat: bigint;
  readonly pendingOutMsat: bigint; readonly pendingInMsat: bigint; readonly pendingHtlcCount: number;
  readonly localMaxPendingAmtMsat: bigint | null; readonly remoteMaxPendingAmtMsat: bigint | null;
  readonly observedAt: number; readonly blockHeight: number; readonly provenance: Readonly<Record<string, string>>;
}

export interface PreflightAdapter {
  handshake(): Promise<{ pubkey: string; network: NetworkType; version: string; synced: boolean }>;
  capabilities(): ReadonlySet<NodeCapability>;
  listChannels(): Promise<readonly FakeChannel[]>;
  findCircularRoute(req: RouteRequest): Promise<CircularRoute | { readonly refusal: string }>;
  createInvoice(...args: unknown[]): Promise<never>;
  sendOnRoute(...args: unknown[]): Promise<never>;
  cancelUnpaidInvoice(...args: unknown[]): Promise<never>;
}

export interface PreflightDeps {
  readonly db: ExecDatabase;
  readonly adapter: PreflightAdapter;
  readonly workerId: string;
  readonly leaseMs: number;
}

export type PreflightOutcome =
  | { readonly kind: 'READY'; readonly executionId: string; readonly fenceEpoch: bigint; readonly route: CircularRoute }
  | { readonly kind: 'CANCELLED' | 'REFUSED'; readonly executionId: string | null; readonly exit: number; readonly step: string };

export interface PreflightModule {
  readonly prepareExecution: (deps: PreflightDeps, input: { approval: VerifiedApproval; policy: ExecutionPolicy; approvalKeyIds: readonly string[] }) => Promise<PreflightOutcome>;
  readonly recoverPreflight: (deps: PreflightDeps) => Promise<{ cancelled: readonly string[] }>;
}

const moduleUrl = (relative: string): string => pathToFileURL(join(repoRoot, relative)).href;

export async function loadPersistence(): Promise<ExecPersistence> {
  return await import(moduleUrl('src/persistence/index.ts')) as ExecPersistence;
}

export async function loadClaim(): Promise<ClaimModule> {
  return await import(moduleUrl('src/executor/claim.ts')) as ClaimModule;
}

export async function loadPreflight(): Promise<PreflightModule> {
  return await import(moduleUrl('src/executor/preflight.ts')) as PreflightModule;
}

export const builtClaim = join(repoRoot, 'dist', 'executor', 'claim.js');
export const builtPersistence = join(repoRoot, 'dist', 'persistence', 'index.js');

export function scratchDb(prefix: string): string {
  return join(mkdtempSync(join(process.env['FLUXWARDEN_TEST_TMP'] ?? tmpdir(), `fw-exec-${prefix}-`)), 'fluxwarden.db');
}

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function ulid(): string {
  return [...randomBytes(26)].map(b => CROCKFORD[b % 32] ?? '0').join('');
}

const hex = (bytes: number): string => randomBytes(bytes).toString('hex');

/** The key_id every seeded approval is signed with, and the configured approval keys that contain it. */
export const KEY_ID = '5a'.repeat(16);
export const APPROVAL_KEYS: readonly string[] = [KEY_ID];

export function raw(path: string): DatabaseSync {
  return new DatabaseSync(path, { readBigInts: true, timeout: 5_000 });
}

function withRaw<T>(path: string, work: (db: DatabaseSync) => T): T {
  const db = raw(path);
  try { return work(db); } finally { db.close(); }
}

/** The database clock as ARCHITECTURE §7.1 defines it for node:sqlite, in unix milliseconds. */
export function dbNow(path: string): number {
  return withRaw(path, db => {
    const row = db.prepare("SELECT CAST(ROUND((julianday('now') - 2440587.5) * 86400000) AS INTEGER) AS now").get() as { now: bigint };
    return Number(row.now);
  });
}

export const NODE_PUBKEY = `03${'cd'.repeat(32)}`;
export const OUT_PEER = `02${'aa'.repeat(32)}`;
export const IN_PEER = `02${'bb'.repeat(32)}`;
export const PRINCIPAL = 100_000_000n;
export const PROPOSAL_MAX_FEE = 300_000n;
export const APPROVED_MAX_FEE = 200_000n;
export const PROPOSAL_MAX_CLTV = 144;
export const APPROVED_MAX_CLTV = 100;

export interface Base {
  readonly path: string;
  readonly nodeId: string;
  readonly policyVersionId: string;
  readonly policySha256: string;
  readonly sourceChannelId: string;
  readonly targetChannelId: string;
  readonly sourceKey: string;
  readonly targetKey: string;
}

/** Closed, empty schema prepared through the public database API; scenarios mutate only their own copies. */
export function prepareEmptyDatabaseFixture(p: { openDatabase(path: string, options: { readOnly: boolean }): { close(): void } }): string {
  const path = scratchDb('empty-fixture');
  p.openDatabase(path, { readOnly: false }).close();
  return path;
}

/** Copy an immutable closed schema into a fresh owner-only scenario directory. */
export function cloneEmptyDatabaseFixture(emptyDatabase: string, path: string): void {
  makeOwnerOnlyDir(dirname(path));
  copyFileSync(emptyDatabase, path, constants.COPYFILE_EXCL);
  if (process.platform === 'win32') {
    // The protected parent grants only the owner access; preserve that ACE explicitly on the database copy.
    const run = spawnSync(join(process.env['SystemRoot'] ?? 'C:/Windows', 'System32', 'icacls.exe'),
      [path, '/inheritance:d'], { encoding: 'utf8', windowsHide: true, shell: false });
    if (run.error !== undefined) throw run.error;
    if (run.status !== 0) throw new Error(`protecting empty database fixture failed: ${run.stderr}`);
  }
}

/** A migrated database with one node, two channels (S, T) and one policy version. */
export function seedBase(p: ExecPersistence, path: string, emptyDatabase?: string): Base {
  if (emptyDatabase === undefined) p.openDatabase(path, { readOnly: false }).close();
  else cloneEmptyDatabaseFixture(emptyDatabase, path);
  const base: Base = {
    path, nodeId: ulid(), policyVersionId: ulid(), policySha256: hex(32),
    sourceChannelId: ulid(), targetChannelId: ulid(), sourceKey: '123145302376448', targetKey: '246290604752896',
  };
  withRaw(path, db => {
    db.prepare(`INSERT INTO nodes (id, name, implementation, expected_network, expected_pubkey, state) VALUES (?, 'lnd-r', 'lnd', 'regtest', ?, 'ONLINE')`)
      .run(base.nodeId, NODE_PUBKEY);
    const channel = db.prepare(`INSERT INTO channels (id, node_id, channel_key, scid, peer_pubkey, funding_outpoint, capacity_msat, lifecycle_state, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, 1000000000, 'ACTIVE', 0)`);
    channel.run(base.sourceChannelId, base.nodeId, base.sourceKey, '112x1x0', OUT_PEER, `${'c3'.repeat(32)}:0`);
    channel.run(base.targetChannelId, base.nodeId, base.targetKey, '224x1x0', IN_PEER, `${'d4'.repeat(32)}:1`);
    db.prepare(`INSERT INTO policy_versions (id, version_no, policy_sha256, policy_canonical_json, author, created_at) VALUES (?, 3, ?, '{}', 'operator', 0)`)
      .run(base.policyVersionId, base.policySha256);
  });
  return base;
}

export interface ProposalOptions {
  readonly approvalKeyId?: string;
  readonly signApproval?: (approval: VerifiedApproval) => string;
  readonly sourceChannelId?: string;
  readonly targetChannelId?: string;
  readonly approvedMaxFeeMsat?: bigint;
  /** Approval expiry relative to the database clock, in milliseconds. */
  readonly approvalTtlMs?: number;
  readonly proposalTtlMs?: number;
}

/** An APPROVED proposal with its stored approval; returns the approval record that verification produced. */
export function seedProposal(base: Base, options: ProposalOptions = {}): VerifiedApproval {
  const now = dbNow(base.path);
  const proposalId = ulid();
  const approval: VerifiedApproval = {
    approvalId: ulid(), proposalId, keyId: options.approvalKeyId ?? KEY_ID, nonce: hex(32), proposalDigest: hex(32), policySha256: base.policySha256,
    approvedMaxFeeMsat: options.approvedMaxFeeMsat ?? APPROVED_MAX_FEE, approvedMaxCltvDelta: APPROVED_MAX_CLTV,
    expiresAt: now + (options.approvalTtlMs ?? 600_000),
  };
  withRaw(base.path, db => {
    db.prepare(`INSERT INTO liquidity_proposals (id, policy_version_id, node_id, action_type, source_channel_id, target_channel_id, principal_msat,
        max_fee_msat, max_fee_ppm, max_cltv_delta, route_json, demand_source, proposal_digest, status, reason_json, expires_at, created_at)
      VALUES (?, ?, ?, 'CIRCULAR_REBALANCE', ?, ?, ?, ?, 2500, ?, NULL, 'TARGETS', ?, 'APPROVED', '{}', ?, ?)`)
      .run(proposalId, base.policyVersionId, base.nodeId, options.sourceChannelId ?? base.sourceChannelId, options.targetChannelId ?? base.targetChannelId,
        PRINCIPAL, PROPOSAL_MAX_FEE, PROPOSAL_MAX_CLTV, approval.proposalDigest, now + (options.proposalTtlMs ?? 900_000), now);
    db.prepare(`INSERT INTO approvals (id, proposal_id, key_id, nonce, expires_at, signature, max_fee_msat, max_cltv_delta, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(approval.approvalId, proposalId, approval.keyId, approval.nonce, approval.expiresAt, options.signApproval?.(approval) ?? randomBytes(64).toString('base64'),
        approval.approvedMaxFeeMsat, approval.approvedMaxCltvDelta, now);
  });
  return approval;
}

export function policyFor(base: Base, over: Partial<ExecutionPolicy> = {}): ExecutionPolicy {
  return {
    sha256: base.policySha256, network: 'regtest', maxFeeMsat: PROPOSAL_MAX_FEE, maxFeePpm: 2500n, exemptFeeMsat: 5_000n,
    maxCltvDelta: PROPOSAL_MAX_CLTV, minChannelReserveMsat: 50_000_000n, budget: { msat: 2_000_000n, periodMs: 86_400_000 },
    cooldownAfterFailureMs: 3_600_000, cooldownAfterSuccessMs: 1_800_000, maxInFlight: 1, maxSnapshotAgeMs: 60_000,
    ...over,
  };
}

export interface TerminalOptions {
  readonly status: 'VERIFIED_SUCCESS' | 'VERIFIED_FAILURE' | 'CANCELLED';
  /** Milliseconds before the database clock at which the terminal state was reached. */
  readonly agoMs: number;
  readonly sourceChannelId?: string;
  readonly targetChannelId?: string;
  readonly consumedMsat?: bigint;
  /** Milliseconds before the database clock of a later write to the terminal row (its updated_at); default: agoMs. */
  readonly touchedAgoMs?: number;
}

/** A prior execution of another proposal that reached a terminal state at a chosen database time. */
export function seedTerminal(base: Base, options: TerminalOptions): string {
  const approval = seedProposal(base, {
    ...(options.sourceChannelId === undefined ? {} : { sourceChannelId: options.sourceChannelId }),
    ...(options.targetChannelId === undefined ? {} : { targetChannelId: options.targetChannelId }),
  });
  const at = dbNow(base.path) - options.agoMs;
  const id = ulid();
  withRaw(base.path, db => {
    db.prepare(`INSERT INTO executions (id, proposal_id, approval_id, worker_id, fence_epoch, lease_expires_at, status, created_at, updated_at, actual_fee_msat)
      VALUES (?, ?, ?, 'old-worker', 7, ?, ?, ?, ?, ?)`)
      .run(id, approval.proposalId, approval.approvalId, at, options.status, at - 60_000, dbNow(base.path) - (options.touchedAgoMs ?? options.agoMs),
        options.status === 'VERIFIED_SUCCESS' ? (options.consumedMsat ?? 100_000n) : null);
    db.prepare(`INSERT INTO execution_events (execution_id, fence_epoch, from_status, to_status, evidence_json, at) VALUES (?, 7, ?, ?, '{}', ?)`)
      .run(id, options.status === 'CANCELLED' ? 'PREFLIGHT' : 'IN_FLIGHT', options.status, at);
    const state = options.status === 'VERIFIED_SUCCESS' ? 'CONSUMED' : 'RELEASED';
    db.prepare(`INSERT INTO budget_reservations (id, execution_id, period_start, reserved_msat, consumed_msat, state) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(ulid(), id, at - 60_000, APPROVED_MAX_FEE, state === 'CONSUMED' ? (options.consumedMsat ?? 100_000n) : null, state);
  });
  return id;
}

/** Another node in the same database, with its own two channels, sharing the policy version. */
export function seedOtherNode(base: Base): Base {
  const other: Base = { ...base, nodeId: ulid(), sourceChannelId: ulid(), targetChannelId: ulid(), sourceKey: '111111111111111', targetKey: '222222222222222' };
  withRaw(base.path, db => {
    db.prepare(`INSERT INTO nodes (id, name, implementation, expected_network, expected_pubkey, state) VALUES (?, ?, 'cln', 'regtest', ?, 'ONLINE')`)
      .run(other.nodeId, `cln-${hex(4)}`, `02${hex(32)}`);
    const channel = db.prepare(`INSERT INTO channels (id, node_id, channel_key, scid, peer_pubkey, funding_outpoint, capacity_msat, lifecycle_state, updated_at)
      VALUES (?, ?, ?, NULL, ?, ?, 1000000000, 'ACTIVE', 0)`);
    channel.run(other.sourceChannelId, other.nodeId, other.sourceKey, `02${hex(32)}`, `${hex(32)}:0`);
    channel.run(other.targetChannelId, other.nodeId, other.targetKey, `02${hex(32)}`, `${hex(32)}:1`);
  });
  return other;
}

/** An execution of another proposal of `base`'s node in `status`, with a live lease and a HELD reservation of `reservedMsat`. */
export function seedExecution(base: Base, status: ExecutionStatus, reservedMsat = 0n): string {
  const approval = seedProposal(base);
  const now = dbNow(base.path);
  const id = ulid();
  withRaw(base.path, db => {
    db.prepare(`INSERT INTO executions (id, proposal_id, approval_id, worker_id, fence_epoch, lease_expires_at, status, created_at, updated_at)
      VALUES (?, ?, ?, 'other-worker', 3, ?, ?, ?, ?)`)
      .run(id, approval.proposalId, approval.approvalId, now + 600_000, status, now - 1_000, now - 1_000);
    const state = status === 'VERIFIED_SUCCESS' ? 'CONSUMED' : status === 'VERIFIED_FAILURE' || status === 'CANCELLED' ? 'RELEASED' : 'HELD';
    db.prepare(`INSERT INTO budget_reservations (id, execution_id, period_start, reserved_msat, consumed_msat, state) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(ulid(), id, now - 1_000, reservedMsat, state === 'CONSUMED' ? 0n : null, state);
  });
  return id;
}

/** An unrelated execution holding or having consumed a reservation, with its reservation's period_start set directly. */
export function seedReservation(base: Base, state: 'HELD' | 'CONSUMED' | 'RELEASED', amountMsat: bigint, periodStartAgoMs: number): string {
  const approval = seedProposal(base);
  const now = dbNow(base.path);
  const id = ulid();
  const status = state === 'HELD' ? 'UNKNOWN' : state === 'CONSUMED' ? 'VERIFIED_SUCCESS' : 'VERIFIED_FAILURE';
  // A distinct channel pair keeps these rows out of every cooldown.
  withRaw(base.path, db => {
    const channel = db.prepare(`INSERT INTO channels (id, node_id, channel_key, scid, peer_pubkey, funding_outpoint, capacity_msat, lifecycle_state, updated_at)
      VALUES (?, ?, ?, NULL, ?, ?, 1000000000, 'ACTIVE', 0)`);
    const s = ulid();
    const t = ulid();
    channel.run(s, base.nodeId, `9${String(Math.floor(Math.random() * 1e9))}`, `02${hex(32)}`, `${hex(32)}:0`);
    channel.run(t, base.nodeId, `8${String(Math.floor(Math.random() * 1e9))}`, `02${hex(32)}`, `${hex(32)}:1`);
    db.prepare('UPDATE liquidity_proposals SET source_channel_id = ?, target_channel_id = ? WHERE id = ?').run(s, t, approval.proposalId);
    db.prepare(`INSERT INTO executions (id, proposal_id, approval_id, worker_id, fence_epoch, lease_expires_at, status, created_at, updated_at)
      VALUES (?, ?, ?, 'old-worker', 5, ?, ?, ?, ?)`)
      .run(id, approval.proposalId, approval.approvalId, now - periodStartAgoMs, status, now - periodStartAgoMs, now - periodStartAgoMs);
    db.prepare(`INSERT INTO budget_reservations (id, execution_id, period_start, reserved_msat, consumed_msat, state) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(ulid(), id, now - periodStartAgoMs, state === 'CONSUMED' ? APPROVED_MAX_FEE : amountMsat, state === 'CONSUMED' ? amountMsat : null, state);
  });
  return id;
}

export interface ExecRow {
  readonly id: string;
  readonly status: string;
  readonly fence_epoch: bigint;
  readonly worker_id: string | null;
  readonly lease_expires_at: bigint | null;
  readonly error_code: string | null;
  readonly payment_hash: string | null;
  readonly route_json: string | null;
  readonly planned_fee_msat: bigint | null;
  readonly actual_fee_msat: bigint | null;
  readonly updated_at: bigint;
}

const EXEC_COLUMNS = 'id, status, fence_epoch, worker_id, lease_expires_at, error_code, payment_hash, route_json, planned_fee_msat, actual_fee_msat, updated_at';

export function execByProposal(path: string, proposalId: string): ExecRow | undefined {
  return withRaw(path, db => db.prepare(`SELECT ${EXEC_COLUMNS} FROM executions WHERE proposal_id = ?`).get(proposalId) as ExecRow | undefined);
}

export function execById(path: string, id: string): ExecRow {
  const row = withRaw(path, db => db.prepare(`SELECT ${EXEC_COLUMNS} FROM executions WHERE id = ?`).get(id) as ExecRow | undefined);
  if (row === undefined) throw new Error(`no execution ${id}`);
  return row;
}

export interface ReservationRow { readonly reserved_msat: bigint; readonly consumed_msat: bigint | null; readonly state: string; readonly period_start: bigint }

export function reservationsOf(path: string, executionId: string): ReservationRow[] {
  return withRaw(path, db => db.prepare('SELECT reserved_msat, consumed_msat, state, period_start FROM budget_reservations WHERE execution_id = ?')
    .all(executionId) as unknown as ReservationRow[]);
}

export function eventsOf(path: string, executionId: string): { from_status: string | null; to_status: string }[] {
  return withRaw(path, db => db.prepare('SELECT from_status, to_status FROM execution_events WHERE execution_id = ? ORDER BY id')
    .all(executionId) as unknown as { from_status: string | null; to_status: string }[]);
}

export function scalar(path: string, sql: string, ...params: (string | number | bigint | null)[]): bigint {
  return withRaw(path, db => (db.prepare(sql).get(...params) as { v: bigint }).v);
}

/** Moves a row directly (test setup only), keeping its fence epoch. */
export function force(path: string, id: string, set: { status?: ExecutionStatus; leaseAgoMs?: number }): void {
  withRaw(path, db => {
    if (set.status !== undefined) db.prepare('UPDATE executions SET status = ? WHERE id = ?').run(set.status, id);
    if (set.leaseAgoMs !== undefined) {
      db.prepare("UPDATE executions SET lease_expires_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000) AS INTEGER) - ? WHERE id = ?")
        .run(set.leaseAgoMs, id);
    }
  });
}

export function codeOf(run: () => unknown): string | undefined {
  try { run(); } catch (error) {
    const code = (error as { code?: unknown }).code;
    return typeof code === 'string' ? code : `not-coded:${error instanceof Error ? error.message : String(error)}`;
  }
  return undefined;
}

export function claimed(outcome: ClaimOutcome): { executionId: string; fenceEpoch: bigint } {
  if (!outcome.ok) throw new Error(`claim refused: ${outcome.step}`);
  return outcome;
}

export const sleep = (ms: number): Promise<void> => new Promise(resolve => { setTimeout(resolve, ms); });

// A claim worker in its own process: loads the built modules, reports `ready`, waits for one line on stdin so that all
// workers start together, then claims each input in order and prints the outcomes as one JSON line.
const CLAIM_WORKER = `
const [claimUrl, persistenceUrl, dbPath, workerId] = process.argv.slice(1);
const revive = (_k, v) => typeof v === 'string' && v.startsWith('bigint:') ? BigInt(v.slice(7)) : v;
const inputs = JSON.parse(process.env.FW_INPUTS, revive);
const { openDatabase } = await import(persistenceUrl);
const { claimExecution } = await import(claimUrl);
const db = openDatabase(dbPath, { readOnly: false, busyTimeoutMs: 20000 });
process.stdout.write('ready\\n');
process.stdin.once('data', () => {
  const results = inputs.map(input => claimExecution(db, { ...input, workerId, leaseMs: 60000 }));
  db.close();
  const text = JSON.stringify(results, (_k, v) => typeof v === 'bigint' ? 'bigint:' + v.toString() : v);
  process.stdout.write(text + '\\n', () => process.exit(0));
});
`;

export interface WorkerResult { readonly workerId: string; readonly outcomes: ClaimOutcome[] }

const encode = (value: unknown): string => JSON.stringify(value, (_k, v: unknown) => typeof v === 'bigint' ? `bigint:${v.toString()}` : v);
const reviveBigints = (_k: string, v: unknown): unknown => typeof v === 'string' && v.startsWith('bigint:') ? BigInt(v.slice(7)) : v;

/** Runs one claim worker process per entry against the same database file and releases them at the same moment. */
export async function raceClaims(path: string, workers: readonly { workerId: string; inputs: readonly { approval: VerifiedApproval; policy: ExecutionPolicy }[] }[]): Promise<WorkerResult[]> {
  const children = workers.map(worker => {
    const child = spawn(process.execPath, ['--no-warnings', '--input-type=module', '-e', CLAIM_WORKER,
      pathToFileURL(builtClaim).href, pathToFileURL(builtPersistence).href, path, worker.workerId], {
      env: { ...childEnv(), FW_INPUTS: encode(worker.inputs.map(input => ({ approvalKeyIds: APPROVAL_KEYS, ...input }))) }, shell: false, windowsHide: true, stdio: 'pipe',
    });
    let out = '';
    let err = '';
    const closed = new Promise<void>(resolve => { child.once('close', () => { resolve(); }); });
    const ready = new Promise<void>((resolve, reject) => {
      child.stdout.on('data', (chunk: Buffer) => { out += chunk.toString(); if (out.includes('ready\n')) resolve(); });
      child.stderr.on('data', (chunk: Buffer) => { err += chunk.toString(); });
      child.once('exit', status => { if (!out.includes('ready\n')) reject(new Error(`worker exited ${String(status)} before ready: ${err}`)); });
      child.once('error', reject);
    });
    const done = new Promise<WorkerResult>((resolve, reject) => {
      child.once('error', reject);
      child.once('exit', status => {
        if (status !== 0) { reject(new Error(`worker ${worker.workerId} exited ${String(status)}: ${err}`)); return; }
        const line = out.split('\n').filter(text => text.startsWith('[')).pop() ?? '[]';
        resolve({ workerId: worker.workerId, outcomes: JSON.parse(line, reviveBigints) as ClaimOutcome[] });
      });
    });
    return { child, ready, done, closed };
  });
  const completed = Promise.all(children.map(c => c.done));
  // A worker can fail before the readiness barrier; observe that rejection
  // immediately while retaining it for the awaited result and cleanup.
  void completed.catch(() => undefined);
  try {
    await Promise.all(children.map(c => c.ready));
    for (const c of children) c.child.stdin.write('go\n');
    return await completed;
  } finally {
    for (const c of children) if (c.child.exitCode === null && c.child.signalCode === null) c.child.kill();
    await Promise.all(children.map(c => c.closed));
    await Promise.allSettled(children.map(c => c.done));
  }
}

/** A second stored approval of the same proposal (another nonce), as a second `liquidity approve` would store it. */
export function seedSecondApproval(base: Base, first: VerifiedApproval): VerifiedApproval {
  const now = dbNow(base.path);
  const second: VerifiedApproval = { ...first, approvalId: ulid(), nonce: hex(32), expiresAt: now + 600_000 };
  withRaw(base.path, db => {
    db.prepare(`INSERT INTO approvals (id, proposal_id, key_id, nonce, expires_at, signature, max_fee_msat, max_cltv_delta, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(second.approvalId, second.proposalId, second.keyId, second.nonce, second.expiresAt, randomBytes(64).toString('base64'),
        second.approvedMaxFeeMsat, second.approvedMaxCltvDelta, now);
  });
  return second;
}

/** One more channel of `base`'s node; returns its row id. */
export function seedChannel(base: Base): string {
  const id = ulid();
  withRaw(base.path, db => {
    db.prepare(`INSERT INTO channels (id, node_id, channel_key, scid, peer_pubkey, funding_outpoint, capacity_msat, lifecycle_state, updated_at)
      VALUES (?, ?, ?, NULL, ?, ?, 1000000000, 'ACTIVE', 0)`)
      .run(id, base.nodeId, `7${String(Math.floor(Math.random() * 1e12))}`, `02${hex(32)}`, `${hex(32)}:2`);
  });
  return id;
}

/**
 * The same database, except that the first `transition` call after `arm()` runs `before` first: another process taking
 * the lease between the worker's last read and its fenced write.
 */
export function racingTransition(db: ExecDatabase, before: () => void): { db: ExecDatabase; arm: () => void } {
  let armed = false;
  const executions = new Proxy(db.executions, {
    get(target, property, receiver): unknown {
      const value: unknown = Reflect.get(target, property, receiver);
      if (typeof value !== 'function') return value;
      const method = value as (...args: unknown[]) => unknown;
      return (...args: unknown[]): unknown => {
        if (property === 'transition' && armed) { armed = false; before(); }
        return method.apply(target, args);
      };
    },
  });
  const wrapped = new Proxy(db, {
    get(target, property, receiver): unknown {
      if (property === 'executions') return executions;
      const value: unknown = Reflect.get(target, property, receiver);
      return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(target) : value;
    },
  });
  return { db: wrapped, arm: () => { armed = true; } };
}

/** A claimed execution moved to PREFLIGHT with its payment hash persisted, ready for submit. */
export function preflightWithHash(db: ExecDatabase, claim: ClaimModule, base: Base, policy: ExecutionPolicy, workerId = 'worker-a'): { executionId: string; fenceEpoch: bigint } {
  const c = claimed(claim.claimExecution(db, { approval: seedProposal(base), policy, approvalKeyIds: APPROVAL_KEYS, workerId, leaseMs: 60_000 }));
  let epoch = db.executions.transition(c.executionId, c.fenceEpoch, 'CLAIMED', 'PREFLIGHT');
  epoch = db.executions.transition(c.executionId, epoch, 'PREFLIGHT', 'PREFLIGHT', { paymentHash: hex(32) });
  return { executionId: c.executionId, fenceEpoch: epoch };
}

// A submit worker: reports `ready`, waits for one stdin line, then submits each (executionId, fenceEpoch) in order.
const SUBMIT_WORKER = `
const [persistenceUrl, dbPath, maxInFlight] = process.argv.slice(1);
const rows = JSON.parse(process.env.FW_ROWS);
const { openDatabase } = await import(persistenceUrl);
const db = openDatabase(dbPath, { readOnly: false, busyTimeoutMs: 20000 });
process.stdout.write('ready\\n');
process.stdin.once('data', () => {
  const results = rows.map(r => db.executions.submit(r.executionId, BigInt(r.fenceEpoch), Number(maxInFlight), 60000).status);
  db.close();
  process.stdout.write(JSON.stringify(results) + '\\n', () => process.exit(0));
});
`;

/** Runs one submit process per row list against the same database and releases them together; returns each process's statuses. */
export async function raceSubmits(path: string, maxInFlight: number, lists: readonly (readonly { executionId: string; fenceEpoch: bigint }[])[]): Promise<string[][]> {
  const children = lists.map(rows => {
    const child = spawn(process.execPath, ['--no-warnings', '--input-type=module', '-e', SUBMIT_WORKER,
      pathToFileURL(builtPersistence).href, path, String(maxInFlight)], {
      env: { ...childEnv(), FW_ROWS: JSON.stringify(rows.map(r => ({ executionId: r.executionId, fenceEpoch: r.fenceEpoch.toString() }))) },
      shell: false, windowsHide: true, stdio: 'pipe',
    });
    let out = '';
    let err = '';
    const ready = new Promise<void>((resolve, reject) => {
      child.stdout.on('data', (chunk: Buffer) => { out += chunk.toString(); if (out.includes('ready\n')) resolve(); });
      child.stderr.on('data', (chunk: Buffer) => { err += chunk.toString(); });
      child.once('exit', status => { if (!out.includes('ready\n')) reject(new Error(`submit worker exited ${String(status)} before ready: ${err}`)); });
    });
    const done = new Promise<string[]>((resolve, reject) => {
      child.once('exit', status => {
        if (status !== 0) { reject(new Error(`submit worker exited ${String(status)}: ${err}`)); return; }
        resolve(JSON.parse(out.split('\n').filter(text => text.startsWith('[')).pop() ?? '[]') as string[]);
      });
    });
    return { child, ready, done };
  });
  try {
    await Promise.all(children.map(c => c.ready));
    for (const c of children) c.child.stdin.write('go\n');
    return await Promise.all(children.map(c => c.done));
  } finally {
    for (const c of children) if (c.child.exitCode === null) c.child.kill();
  }
}
