/*
Interface: src/ledger/ (pure apart from node:crypto; no SQL), src/persistence/ (SQL), src/commands/ledger.ts.

  src/ledger/accounts.ts — chart of accounts (SPEC §9.1)
    export const CLEARING_INFLIGHT = 'clearing:inflight';
    export const EQUITY_OPENING_BALANCE = 'equity:opening_balance';
    export const EXPENSE_ROUTING_FEES = 'expense:routing_fees';
    export const RECON_DIFFERENCE = 'recon:difference';
    export function channelLocalAccount(node: string, channel: string): string;   // `channel:${node}:${channel}:local`
    export function isKnownAccount(code: string): boolean;  // the four constants, channel:<node>:<chan>:local with
                                                            // non-empty segments without ':', onchain:<node>:wallet

  src/ledger/postings.ts — journal builders (SPEC §9.2, §9.3)
    export type EventType = 'OPENING' | 'REBALANCE_SENT' | 'REBALANCE_SETTLED' | 'REBALANCE_REVERSED' | 'RECON_DIFFERENCE';
    export interface JournalLine { account: string; debitMsat: bigint; creditMsat: bigint }  // exactly one side > 0
    export interface Journal { eventType: EventType; reference: string; executionId: string | null; occurredAt: number;
                               lines: readonly JournalLine[] }
    export interface Rebalance { executionId: string; node: string; sourceChannel: string;
                                 principalMsat: bigint; routeFeeMsat: bigint }   // node/channel = account segments
    export type ExecutionOutcome =                       // the execution status reached (SPEC §8.1)
      | { status: 'CLAIMED' | 'PREFLIGHT' | 'SUBMITTING' | 'IN_FLIGHT' | 'UNKNOWN' | 'CANCELLED' | 'VERIFIED_FAILURE' }
      | { status: 'VERIFIED_SUCCESS'; settledChannel: string; actualFeeMsat: bigint };   // T' and the node-reported fee
    export function openingJournal(i: { node; channel; localMsat: bigint; occurredAt: number }): Journal | null;
        // OPENING, reference = channelLocalAccount(node, channel), executionId null;
        // lines [Dr channel local, Cr equity:opening_balance]; null when localMsat = 0
    export function sentJournal(r: Rebalance, occurredAt: number): Journal;
        // REBALANCE_SENT, reference = executionId; [Dr clearing:inflight P+F_route, Cr channel:<node>:<S>:local P+F_route]
    export function settledJournal(r: Rebalance, s: { settledChannel; actualFeeMsat }, occurredAt: number): Journal;
        // REBALANCE_SETTLED, reference = executionId;
        // [Dr channel:<node>:<T'>:local P, Dr expense:routing_fees F_actual, Cr clearing:inflight P+F_route,
        //  then recon:difference |F_route − F_actual| as Dr when F_actual < F_route, Cr when F_actual > F_route]
    export function reversedJournal(r: Rebalance, occurredAt: number): Journal;
        // REBALANCE_REVERSED, reference = executionId; [Dr channel:<node>:<S>:local P+F_route, Cr clearing:inflight P+F_route]
    Builders omit lines whose amount is 0 (a zero fee posts no expense line).

  Journal shapes (the posting rules of SPEC §9.2; checked by post() and by verify step 1; line order is not part of it):
    OPENING             executionId null; one Dr channel:*:local and one Cr equity:opening_balance, nothing else;
                        reference = that channel account
    REBALANCE_SENT      executionId = reference (non-empty); one Dr clearing:inflight, one Cr channel:*:local
    REBALANCE_SETTLED   executionId = reference; one Dr channel:*:local, at most one Dr expense:routing_fees,
                        one Cr clearing:inflight, at most one recon:difference line (either side)
    REBALANCE_REVERSED  executionId = reference; one Dr channel:*:local, one Cr clearing:inflight
    RECON_DIFFERENCE    at least one recon:difference line

  src/ledger/post.ts
    export class LedgerError extends Error {
      code: 'UNBALANCED' | 'UNKNOWN_ACCOUNT' | 'OUT_OF_RANGE' | 'MALFORMED' | 'NOT_IN_TRANSACTION' | 'CONFLICT' }
    export function post(tx: Transaction, journal: Journal): { posted: boolean; journalId: string };
        // Checks, first failure wins, all before any write:
        //   1. the transaction has ended → NOT_IN_TRANSACTION
        //   2. unknown event type, empty reference, or no lines → MALFORMED
        //   3. per line in order: unknown account → UNKNOWN_ACCOUNT; both sides non-zero → MALFORMED;
        //      the non-zero side (or 0 when both are 0) outside 1 … 2^63 − 1 → OUT_OF_RANGE
        //   4. bigint Σdebit ≠ Σcredit → UNBALANCED
        //   5. not the shape of its event type → MALFORMED
        //   6. against the stored book → CONFLICT: the same (event_type, reference) with other content (executionId,
        //      occurredAt aside: lines compared as account/debit/credit in order); a REBALANCE_SETTLED or
        //      REBALANCE_REVERSED without the REBALANCE_SENT of its reference; SETTLED when REVERSED exists or the
        //      reverse (SPEC §8.1: VERIFIED_SUCCESS and VERIFIED_FAILURE are absorbing; one terminal journal each).
        // An identical replay → { posted: false, journalId: <the existing journal's id> } and nothing changes.
        // Lines are stored with sequence_no 1..n in the given order; account_balances moves in the same transaction:
        // balance = Σdebit − Σcredit, for every account type, canonical signed decimal text (it may exceed int64).
    export function postOpening(tx: Transaction, i: { node: string; channel: string; channelId: string }):
        { posted: boolean; openingMsat: bigint };
        // The opening is decided by the channel's FIRST recorded snapshot (channel_snapshots, channelId), read
        // through tx, never by the caller's latest one: openingJournal(node, channel, first.localMsat, first.observedAt).
        // SPEC §9.2 opens "at the first snapshot of a channel … for the local balance"; a first balance of 0 opens
        // with 0, and a 0 amount is not a line (SPEC §6.2 CHECK, §9.2 one debit and one credit), so nothing is posted
        // then or ever after for that channel: { posted: false, openingMsat: 0n }. Repeated calls replay the same journal.
    export function postTransition(tx: Transaction, r: Rebalance, to: ExecutionOutcome, occurredAt: number):
        { posted: EventType[] };
        // Posts what SPEC §8.2 attaches to reaching `to`, reading the stored book through tx (no caller flag):
        // IN_FLIGHT → REBALANCE_SENT; VERIFIED_SUCCESS → REBALANCE_SENT if it is missing, then REBALANCE_SETTLED;
        // VERIFIED_FAILURE → REBALANCE_REVERSED only when REBALANCE_SENT exists; every other status → nothing.
        // `posted` lists the event types newly written, in order (identical replays are left out).

  src/persistence/index.ts — Database gains
    transaction<T>(work: (tx: Transaction) => T): T;      // BEGIN IMMEDIATE … COMMIT; ROLLBACK and rethrow on throw
    ledger: {
      journals(): StoredJournal[];                        // every journal, lines ordered by sequence_no
      balances(): ReadonlyMap<string, bigint | null>;     // account_balances; null when the text is not a canonical decimal
      executions(): ExecutionRecord[];                    // every executions row
    };
    interface StoredJournal { id: string; executionId: string | null; eventType: string; reference: string;
                              occurredAt: number; lines: { sequenceNo: number; account; debitMsat: bigint; creditMsat: bigint }[] }
    interface ExecutionRecord { id: string; status: <executions.status>; principalMsat: bigint | null;  // proposal principal_msat
                                routeFeeMsat: bigint | null;    // executions.planned_fee_msat, the dispatched route's fee
                                actualFeeMsat: bigint | null }  // executions.actual_fee_msat, node-reported
    Transaction is the port the ledger writes and reads through (declared in src/core); unusable once its transaction ends.

  src/ledger/verify.ts (SPEC §9.5 steps 1–3)
    export type VerifyFailure =
      | { step: 'journal-balanced'; journalId: string; eventType: string; reference: string }
          // step 1: known event type, non-empty reference, sequence numbers 1..n, known accounts, one side per line in
          // 1 … 2^63 − 1, balanced in bigint, the shape of its event type
      | { step: 'stored-balance'; account: string; stored: bigint | null; recomputed: bigint }
          // step 2: missing stored row = 0; unreadable stored text = null (always a failure)
      | { step: 'execution-records'; executionId: string;
          reason: 'UNKNOWN_EXECUTION' | 'MISSING_JOURNAL' | 'UNEXPECTED_JOURNAL' | 'AMOUNT_MISMATCH' };
          // step 3, at most one finding per (executionId, reason); executionId = the journal's reference for
          // UNKNOWN_EXECUTION. Rebalance journals expected per execution status:
          //   CLAIMED, PREFLIGHT, SUBMITTING, CANCELLED: none    IN_FLIGHT: SENT    UNKNOWN: SENT or none
          //   VERIFIED_SUCCESS: SENT and SETTLED                 VERIFIED_FAILURE: SENT and REVERSED, or none
          // A missing expected journal → MISSING_JOURNAL; any other rebalance journal → UNEXPECTED_JOURNAL.
          // Amounts, where the record has them: SENT and REVERSED total and the SETTLED clearing credit = principal +
          // routeFee; SETTLED channel debit = principal; SETTLED expense (0 when absent) = actualFee → else AMOUNT_MISMATCH.
    export function verifyLedger(book: { journals; balances; executions }): { ok: boolean; failures: VerifyFailure[] };
  src/commands/ledger.ts
    export function runLedgerVerify(db: Database): { exitCode: 0 | 8; report };   // 8 = INVARIANT_BREACH (SPEC §9.5)

Worked example (SPEC §4.4, §9.3): P = 100,000,000 msat from cln-m channel 2 back through channel 5, F = 202,101 msat.
*/
import { beforeAll, describe, expect, it } from 'vitest';
import { prepareEmptyDatabaseFixture } from '../helpers/cp028-executor.js';
import {
  balanceOf, channel, codeOf, ledgerCodeOf, loadLedger, NODE_NAME, raw, rawJournal, scratchDb, seededLedger, setExecution,
  type ExecSeed, type ExecStatus, type ExecutionOutcome, type Journal, type LedgerDatabase, type LedgerModules, type Rebalance,
} from '../helpers/cp037-ledger.js';

const EXEC = 'EXE01K00000000000000000001';
const P = 100_000_000n;
const F = 202_101n;
const MAX_INT64 = 2n ** 63n - 1n;
let emptyDatabase: string;
beforeAll(async () => { emptyDatabase = prepareEmptyDatabaseFixture(await loadLedger()); });
const ch = (chan: string): string => `channel:${NODE_NAME}:${chan}:local`;
const worked: Rebalance = { executionId: EXEC, node: NODE_NAME, sourceChannel: 'ch2', principalMsat: P, routeFeeMsat: F };
const line = (account: string, debitMsat: bigint, creditMsat: bigint): { account: string; debitMsat: bigint; creditMsat: bigint } =>
  ({ account, debitMsat, creditMsat });
const execId = (n: number): string => `EXE01K${String(n).padStart(20, '0')}`;
const rebalance = (n: number, over: Partial<Rebalance> = {}): Rebalance => ({ ...worked, executionId: execId(n), ...over });

/** Stored balances without zero entries (whether a zero balance keeps its row is not specified). */
function nonZero(db: LedgerDatabase): Record<string, bigint | null> {
  return Object.fromEntries([...db.ledger.balances()].filter(([, v]) => v !== 0n));
}

function postAll(m: LedgerModules, db: LedgerDatabase, journals: readonly Journal[]): boolean[] {
  return db.transaction(tx => journals.map(j => m.post(tx, j).posted));
}

async function openSeeded(prefix: string, executions: readonly (string | ExecSeed)[] = [EXEC]): Promise<{ m: LedgerModules; db: LedgerDatabase; path: string }> {
  const m = await loadLedger();
  const path = scratchDb(prefix);
  return { m, db: seededLedger(m, path, executions, emptyDatabase), path };
}

function reopen(m: LedgerModules, path: string): LedgerDatabase {
  return m.openDatabase(path, { readOnly: false });
}

describe('opening balances', () => {
  it('CP-037/B1 the first snapshot of each channel opens its local balance against equity; later snapshots do not', async () => {
    const { m, db } = await openSeeded('opening', []);
    try {
      const idA = db.channels.upsert(channel({ channelKey: 'ch2', localBalanceMsat: 600_000_000n }));
      const idB = db.channels.upsert(channel({ channelKey: 'ch3', localBalanceMsat: 250_000_001n, fundingOutpoint: `${'d4'.repeat(32)}:1` }));
      db.snapshots.record(idA, channel({ channelKey: 'ch2', localBalanceMsat: 600_000_000n }));
      db.snapshots.record(idB, channel({ channelKey: 'ch3', localBalanceMsat: 250_000_001n }));
      const firstA = db.snapshots.latest(idA);
      expect(db.transaction(tx => m.postOpening(tx, { node: NODE_NAME, channel: 'ch2', channelId: idA }))).toEqual({ posted: true, openingMsat: 600_000_000n });
      expect(db.transaction(tx => m.postOpening(tx, { node: NODE_NAME, channel: 'ch3', channelId: idB }))).toEqual({ posted: true, openingMsat: 250_000_001n });
      // A later snapshot with a different balance does not open again (SPEC §9.2 "at the first snapshot").
      db.snapshots.record(idA, channel({ channelKey: 'ch2', localBalanceMsat: 550_000_000n }));
      expect(db.transaction(tx => m.postOpening(tx, { node: NODE_NAME, channel: 'ch2', channelId: idA }))).toEqual({ posted: false, openingMsat: 600_000_000n });

      const journals = db.ledger.journals();
      expect(journals.filter(j => j.eventType === 'OPENING')).toHaveLength(2);
      const openA = journals.find(j => j.eventType === 'OPENING' && j.reference === ch('ch2'));
      expect(openA?.executionId).toBeNull();
      expect(openA?.occurredAt).toBe(firstA?.observedAt);
      expect(openA?.lines).toEqual([
        { sequenceNo: 1, account: ch('ch2'), debitMsat: 600_000_000n, creditMsat: 0n },
        { sequenceNo: 2, account: 'equity:opening_balance', debitMsat: 0n, creditMsat: 600_000_000n },
      ]);
      expect(nonZero(db)).toEqual({ [ch('ch2')]: 600_000_000n, [ch('ch3')]: 250_000_001n, 'equity:opening_balance': -850_000_001n });
    } finally { db.close(); }
  });

  it('CP-037/B1 a channel whose first snapshot holds 0 local opens with 0 and is never opened by a later snapshot', async () => {
    const { m, db } = await openSeeded('zero-open', []);
    try {
      // A channel the peer opened: local 0 at its first snapshot, then 100,000,000 after a rebalance settled into it.
      const id = db.channels.upsert(channel({ channelKey: 'ch5', localBalanceMsat: 0n, remoteBalanceMsat: 1_000_000_000n }));
      db.snapshots.record(id, channel({ channelKey: 'ch5', localBalanceMsat: 0n, remoteBalanceMsat: 1_000_000_000n }));
      expect(db.transaction(tx => m.postOpening(tx, { node: NODE_NAME, channel: 'ch5', channelId: id }))).toEqual({ posted: false, openingMsat: 0n });
      db.snapshots.record(id, channel({ channelKey: 'ch5', localBalanceMsat: 100_000_000n, remoteBalanceMsat: 900_000_000n }));
      expect(db.transaction(tx => m.postOpening(tx, { node: NODE_NAME, channel: 'ch5', channelId: id }))).toEqual({ posted: false, openingMsat: 0n });
      expect(db.ledger.journals()).toEqual([]);
      expect(balanceOf(db, ch('ch5'))).toBe(0n);
    } finally { db.close(); }
  });

  it('CP-037/B1 an opening with other content under the same channel is refused, not silently dropped', async () => {
    const { m, db } = await openSeeded('reopen', []);
    try {
      const first = m.openingJournal({ node: NODE_NAME, channel: 'ch2', localMsat: 600_000_000n, occurredAt: 1 });
      const later = m.openingJournal({ node: NODE_NAME, channel: 'ch2', localMsat: 550_000_000n, occurredAt: 2 });
      if (first === null || later === null) throw new Error('opening journal missing');
      expect(postAll(m, db, [first])).toEqual([true]);
      expect(ledgerCodeOf(m, () => postAll(m, db, [later]))).toBe('CONFLICT');
      expect(balanceOf(db, ch('ch2'))).toBe(600_000_000n);
      expect(m.openingJournal({ node: NODE_NAME, channel: 'ch9', localMsat: 0n, occurredAt: 1 })).toBeNull();
    } finally { db.close(); }
  });
});

describe('rebalance postings', () => {
  it('CP-037/B2 send and settle post the SPEC §9.3 journal exactly to the msat', async () => {
    const { m, db } = await openSeeded('settle');
    try {
      const sent = m.sentJournal(worked, 10);
      expect(sent).toEqual({
        eventType: 'REBALANCE_SENT', reference: EXEC, executionId: EXEC, occurredAt: 10,
        lines: [line('clearing:inflight', 100_202_101n, 0n), line(ch('ch2'), 0n, 100_202_101n)],
      });
      const settled = m.settledJournal(worked, { settledChannel: 'ch5', actualFeeMsat: 202_101n }, 20);
      expect(settled).toEqual({
        eventType: 'REBALANCE_SETTLED', reference: EXEC, executionId: EXEC, occurredAt: 20,
        lines: [line(ch('ch5'), 100_000_000n, 0n), line('expense:routing_fees', 202_101n, 0n), line('clearing:inflight', 0n, 100_202_101n)],
      });
      expect(postAll(m, db, [sent])).toEqual([true]);
      expect(postAll(m, db, [settled])).toEqual([true]);
      // SPEC §9.3: "After send and settle: ch2 −100,202,101; ch5 +100,000,000; expense +202,101; clearing 0."
      expect(nonZero(db)).toEqual({ [ch('ch2')]: -100_202_101n, [ch('ch5')]: 100_000_000n, 'expense:routing_fees': 202_101n });
      expect(balanceOf(db, 'clearing:inflight')).toBe(0n);
      const stored = db.ledger.journals().find(j => j.eventType === 'REBALANCE_SETTLED');
      expect(stored?.executionId).toBe(EXEC);
      expect(stored?.lines.map(l => l.sequenceNo)).toEqual([1, 2, 3]);
    } finally { db.close(); }
  });

  it('CP-037/B2 send and failure reversal return every account to its prior balance', async () => {
    const { m, db } = await openSeeded('reverse');
    try {
      const reversed = m.reversedJournal(worked, 30);
      expect(reversed).toEqual({
        eventType: 'REBALANCE_REVERSED', reference: EXEC, executionId: EXEC, occurredAt: 30,
        lines: [line(ch('ch2'), 100_202_101n, 0n), line('clearing:inflight', 0n, 100_202_101n)],
      });
      postAll(m, db, [m.sentJournal(worked, 10)]);
      expect(balanceOf(db, 'clearing:inflight')).toBe(100_202_101n);
      postAll(m, db, [reversed]);
      expect(balanceOf(db, ch('ch2'))).toBe(0n);
      expect(balanceOf(db, 'clearing:inflight')).toBe(0n);
      expect(balanceOf(db, 'expense:routing_fees')).toBe(0n);
    } finally { db.close(); }
  });

  it('CP-037/B2 the ledger posts the node-reported fee and the planned-fee difference goes to recon:difference', async () => {
    const m = await loadLedger();
    // F_actual 202,000 < F_route 202,101: debits 100,000,000 + 202,000 fall 101 short of the credit, so Dr recon 101.
    expect(m.settledJournal(worked, { settledChannel: 'ch6', actualFeeMsat: 202_000n }, 1).lines).toEqual([
      line(ch('ch6'), 100_000_000n, 0n), line('expense:routing_fees', 202_000n, 0n),
      line('clearing:inflight', 0n, 100_202_101n), line('recon:difference', 101n, 0n),
    ]);
    // F_actual 202,500 > F_route: debits exceed the credit by 399, so Cr recon 399.
    expect(m.settledJournal(worked, { settledChannel: 'ch5', actualFeeMsat: 202_500n }, 1).lines).toEqual([
      line(ch('ch5'), 100_000_000n, 0n), line('expense:routing_fees', 202_500n, 0n),
      line('clearing:inflight', 0n, 100_202_101n), line('recon:difference', 0n, 399n),
    ]);
    // A zero-fee route posts no expense line (a line needs a non-zero side, SPEC §6.2 CHECK).
    const free: Rebalance = { ...worked, routeFeeMsat: 0n };
    expect(m.settledJournal(free, { settledChannel: 'ch5', actualFeeMsat: 0n }, 1).lines).toEqual([
      line(ch('ch5'), 100_000_000n, 0n), line('clearing:inflight', 0n, 100_000_000n),
    ]);
  });
});

describe('post() validation', () => {
  const opening = (lines: readonly { account: string; debitMsat: bigint; creditMsat: bigint }[]): Journal =>
    ({ eventType: 'OPENING', reference: ch('ch2'), executionId: null, occurredAt: 1, lines });
  const show = (j: Journal): string => JSON.stringify(j, (_k, v: unknown) => typeof v === 'bigint' ? v.toString() : v);

  it('CP-037/B3 malformed, unbalanced, unknown-account and out-of-range journals are refused and nothing is written', async () => {
    const { m, db } = await openSeeded('refuse');
    try {
      const cases: [string, Journal][] = [
        ['UNBALANCED', opening([line(ch('ch2'), 1_000n, 0n), line('equity:opening_balance', 0n, 999n)])],
        ['UNKNOWN_ACCOUNT', opening([line(`channel:${NODE_NAME}:ch2:remote`, 5n, 0n), line('equity:opening_balance', 0n, 5n)])],
        ['UNKNOWN_ACCOUNT', opening([line(ch('ch2'), 5n, 0n), line('income:forwarding_fees', 0n, 5n)])],
        ['UNKNOWN_ACCOUNT', opening([line('channel::ch2:local', 5n, 0n), line('equity:opening_balance', 0n, 5n)])],
        ['OUT_OF_RANGE', opening([line(ch('ch2'), MAX_INT64 + 1n, 0n), line('equity:opening_balance', 0n, MAX_INT64 + 1n)])],
        ['OUT_OF_RANGE', opening([line(ch('ch2'), -5n, 0n), line('equity:opening_balance', 0n, -5n)])],
        ['OUT_OF_RANGE', opening([line(ch('ch2'), 5n, 0n), line('recon:difference', 0n, 0n), line('equity:opening_balance', 0n, 5n)])],
        // A line is a debit or a credit, never both (SPEC §6.2 CHECK); post() names it before the database does.
        ['MALFORMED', opening([line(ch('ch2'), 5n, 3n), line('equity:opening_balance', 3n, 5n)])],
        ['MALFORMED', opening([])],
        ['MALFORMED', { ...opening([line(ch('ch2'), 5n, 0n), line('equity:opening_balance', 0n, 5n)]), eventType: 'BOGUS' }],
        // An empty idempotency key; RECON_DIFFERENCE is used because its shape does not involve the reference.
        ['MALFORMED', { eventType: 'RECON_DIFFERENCE', reference: '', executionId: null, occurredAt: 1,
          lines: [line('recon:difference', 5n, 0n), line(ch('ch2'), 0n, 5n)] }],
        // Shape: a send that debits the expense account is not the SPEC §9.2 send posting.
        ['MALFORMED', { ...m.sentJournal(worked, 1), lines: [line('expense:routing_fees', 5n, 0n), line(ch('ch2'), 0n, 5n)] }],
        ['MALFORMED', { ...opening([line(ch('ch2'), 5n, 0n), line('equity:opening_balance', 0n, 5n)]), executionId: EXEC }],
        // Σdebit = 2^64 + 5 and Σcredit = 5 agree modulo 2^64: only bigint sums see the difference (SPEC §4.3).
        ['UNBALANCED', { ...m.settledJournal(worked, { settledChannel: 'ch5', actualFeeMsat: F }, 1),
          lines: [line(ch('ch5'), MAX_INT64, 0n), line('expense:routing_fees', MAX_INT64, 0n), line('recon:difference', 7n, 0n), line('clearing:inflight', 0n, 5n)] }],
      ];
      for (const [code, bad] of cases) {
        expect(ledgerCodeOf(m, () => db.transaction(tx => m.post(tx, bad))), show(bad)).toBe(code);
      }
      expect(db.ledger.journals()).toEqual([]);
      expect(db.ledger.balances().size).toBe(0);
    } finally { db.close(); }
  });

  it('CP-037/B3 a refused journal rolls back the whole transaction, including earlier writes in it', async () => {
    const { m, db } = await openSeeded('rollback');
    try {
      const bad = opening([line(ch('ch2'), 10n, 0n), line('equity:opening_balance', 0n, 9n)]);
      expect(codeOf(() => db.transaction(tx => [m.post(tx, m.sentJournal(worked, 1)), m.post(tx, bad)]))).toBe('UNBALANCED');
      expect(db.ledger.journals()).toEqual([]);
      expect(db.ledger.balances().size).toBe(0);
      // The same send posts normally afterwards: the failed attempt left no (event_type, reference) behind.
      expect(postAll(m, db, [m.sentJournal(worked, 1)])).toEqual([true]);
    } finally { db.close(); }
  });

  it('CP-037/B3 post() outside its transaction is refused', async () => {
    const { m, db } = await openSeeded('outside');
    try {
      let leaked: Parameters<LedgerModules['post']>[0] | undefined;
      db.transaction(tx => { leaked = tx; });
      if (leaked === undefined) throw new Error('transaction did not run');
      const handle = leaked;
      expect(codeOf(() => m.post(handle, m.sentJournal(worked, 1)))).toBe('NOT_IN_TRANSACTION');
      expect(db.ledger.journals()).toEqual([]);
    } finally { db.close(); }
  });

  it('CP-037/B3 sums beyond int64 are kept exact in the stored balances', async () => {
    const { m, db } = await openSeeded('int64', []);
    try {
      const a = m.openingJournal({ node: NODE_NAME, channel: 'a', localMsat: MAX_INT64, occurredAt: 1 });
      const b = m.openingJournal({ node: NODE_NAME, channel: 'b', localMsat: MAX_INT64, occurredAt: 1 });
      if (a === null || b === null) throw new Error('opening journal missing');
      expect(postAll(m, db, [a, b])).toEqual([true, true]);
      // equity = −2 × (2^63 − 1) = −18,446,744,073,709,551,614, outside int64 (canonical decimal text, SPEC §4.3).
      expect(balanceOf(db, 'equity:opening_balance')).toBe(-18_446_744_073_709_551_614n);
      expect(balanceOf(db, ch('a'))).toBe(MAX_INT64);
      expect(m.runLedgerVerify(db).report).toEqual({ ok: true, failures: [] });
    } finally { db.close(); }
  });
});

describe('pending payments', () => {
  it('CP-037/B4 no fee is expensed while the execution is pending; UNKNOWN keeps the value in clearing:inflight', async () => {
    const { m, db } = await openSeeded('pending');
    try {
      const pending: ExecutionOutcome[] = [
        { status: 'CLAIMED' }, { status: 'PREFLIGHT' }, { status: 'SUBMITTING' },
        { status: 'IN_FLIGHT' }, { status: 'IN_FLIGHT' }, { status: 'UNKNOWN' }, { status: 'UNKNOWN' },
      ];
      const posted: string[] = [];
      for (const outcome of pending) {
        for (const event of db.transaction(tx => m.postTransition(tx, worked, outcome, 5)).posted) posted.push(`${outcome.status}:${event}`);
        expect(balanceOf(db, 'expense:routing_fees'), outcome.status).toBe(0n);
      }
      // SPEC §8.2: the send journal is posted at IN_FLIGHT, not at SUBMITTING, and once; UNKNOWN posts nothing.
      expect(posted).toEqual(['IN_FLIGHT:REBALANCE_SENT']);
      expect(balanceOf(db, 'clearing:inflight')).toBe(100_202_101n);
      expect(db.ledger.journals().map(j => j.eventType)).toEqual(['REBALANCE_SENT']);

      const done = db.transaction(tx => m.postTransition(tx, worked, { status: 'VERIFIED_SUCCESS', settledChannel: 'ch5', actualFeeMsat: 202_101n }, 6));
      expect(done.posted).toEqual(['REBALANCE_SETTLED']);
      expect(balanceOf(db, 'expense:routing_fees')).toBe(202_101n);
      expect(balanceOf(db, 'clearing:inflight')).toBe(0n);
    } finally { db.close(); }
  });

  it('CP-037/B4 the posting decision reads the book: a missing send is posted first, a reversal only follows a send', async () => {
    const ids = [execId(2), execId(3), execId(4), execId(5)];
    const { m, db } = await openSeeded('derive', ids);
    try {
      const success = db.transaction(tx => m.postTransition(tx, rebalance(2), { status: 'VERIFIED_SUCCESS', settledChannel: 'ch5', actualFeeMsat: F }, 7));
      expect(success.posted).toEqual(['REBALANCE_SENT', 'REBALANCE_SETTLED']);
      // A failure resolved from SUBMITTING (NOT_FOUND rule, SPEC §8.5) never sent anything, so nothing reverses.
      expect(db.transaction(tx => m.postTransition(tx, rebalance(3), { status: 'VERIFIED_FAILURE' }, 7)).posted).toEqual([]);
      expect(db.transaction(tx => m.postTransition(tx, rebalance(5), { status: 'CANCELLED' }, 7)).posted).toEqual([]);
      // After a send the failure reverses it, with no caller-supplied hint about the send.
      db.transaction(tx => m.postTransition(tx, rebalance(4, { sourceChannel: 'ch3' }), { status: 'IN_FLIGHT' }, 7));
      expect(db.transaction(tx => m.postTransition(tx, rebalance(4, { sourceChannel: 'ch3' }), { status: 'VERIFIED_FAILURE' }, 8)).posted)
        .toEqual(['REBALANCE_REVERSED']);
      expect(balanceOf(db, ch('ch3'))).toBe(0n);
      expect(balanceOf(db, 'clearing:inflight')).toBe(0n);
      expect(db.ledger.journals().filter(j => j.reference === execId(3) || j.reference === execId(5))).toEqual([]);
    } finally { db.close(); }
  });
});

describe('ledger verify', () => {
  /** Send and settle of the worked example with its execution VERIFIED_SUCCESS, closed; returns the send journal id. */
  async function settledBook(prefix: string): Promise<{ m: LedgerModules; path: string; sentId: string }> {
    const { m, db, path } = await openSeeded(prefix, [{ id: EXEC, status: 'VERIFIED_SUCCESS', actualFeeMsat: F }]);
    try {
      postAll(m, db, [m.sentJournal(worked, 10)]);
      postAll(m, db, [m.settledJournal(worked, { settledChannel: 'ch5', actualFeeMsat: F }, 20)]);
      expect(m.runLedgerVerify(db)).toEqual({ exitCode: 0, report: { ok: true, failures: [] } });
      const sentId = db.ledger.journals().find(j => j.eventType === 'REBALANCE_SENT')?.id;
      if (sentId === undefined) throw new Error('send journal missing');
      return { m, path, sentId };
    } finally { db.close(); }
  }
  function tamper(path: string, ...statements: string[]): void {
    const r = raw(path, false);
    try {
      for (const s of statements) r.exec(s);
    } finally { r.close(); }
  }
  function verifyAt(m: LedgerModules, path: string): ReturnType<LedgerModules['runLedgerVerify']> {
    const db = reopen(m, path);
    try { return m.runLedgerVerify(db); } finally { db.close(); }
  }

  it('CP-037/B5 a tampered line fails verification with the journal and account named', async () => {
    const { m, path, sentId } = await settledBook('tamper');
    // Someone with write access to the file bypasses the append-only trigger and adds 1 msat to the clearing debit.
    tamper(path, 'DROP TRIGGER ledger_lines_no_update',
      `UPDATE ledger_lines SET debit_msat = debit_msat + 1 WHERE journal_id = '${sentId}' AND sequence_no = 1`);
    const result = verifyAt(m, path);
    expect(result.exitCode).toBe(8);
    expect(result.report.ok).toBe(false);
    expect(result.report.failures).toContainEqual({ step: 'journal-balanced', journalId: sentId, eventType: 'REBALANCE_SENT', reference: EXEC });
    // Stored clearing is 0; recomputed from the lines it is 100,202,102 − 100,202,101 = 1.
    expect(result.report.failures).toContainEqual({ step: 'stored-balance', account: 'clearing:inflight', stored: 0n, recomputed: 1n });
  });

  it('CP-037/B5 a stored balance that differs from the lines, or is missing, fails step 2 alone', async () => {
    const { m, path } = await openSeeded('balance', [{ id: EXEC, status: 'IN_FLIGHT' }]).then(({ m, db, path }) => {
      postAll(m, db, [m.sentJournal(worked, 10)]);
      db.close();
      return { m, path };
    });
    tamper(path, `UPDATE account_balances SET balance_decimal = '-100202100' WHERE account_code = '${ch('ch2')}'`);
    const db = reopen(m, path);
    try {
      const book = { journals: db.ledger.journals(), balances: db.ledger.balances(), executions: db.ledger.executions() };
      expect(m.verifyLedger(book)).toEqual({
        ok: false, failures: [{ step: 'stored-balance', account: ch('ch2'), stored: -100_202_100n, recomputed: -100_202_101n }],
      });
      expect(m.runLedgerVerify(db).exitCode).toBe(8);
    } finally { db.close(); }
    // A deleted balance row reads as 0 against the lines' 100,202,101.
    tamper(path, "DELETE FROM account_balances WHERE account_code = 'clearing:inflight'");
    expect(verifyAt(m, path).report.failures).toContainEqual({ step: 'stored-balance', account: 'clearing:inflight', stored: 0n, recomputed: 100_202_101n });
  });

  it('CP-037/B5 an unreadable stored balance is a step 2 finding with exit 8, not a crash', async () => {
    const { m, path } = await settledBook('garbled');
    // The column CHECK refuses '1x', so the product can never write it. Step 2 exists for a file edited outside the
    // product (the other B5 cases drop the append-only triggers); such a writer can equally switch CHECK enforcement off.
    tamper(path, 'PRAGMA ignore_check_constraints = ON',
      `UPDATE account_balances SET balance_decimal = '1x' WHERE account_code = '${ch('ch5')}'`);
    const result = verifyAt(m, path);
    expect(result.exitCode).toBe(8);
    expect(result.report.failures).toEqual([{ step: 'stored-balance', account: ch('ch5'), stored: null, recomputed: 100_000_000n }]);
  });

  it('CP-037/B5 step 1 names a journal with a sequence gap, an unknown event type or a line off its posting rule', async () => {
    const gap = await settledBook('seq-gap');
    tamper(gap.path, 'DROP TRIGGER ledger_lines_no_update', `UPDATE ledger_lines SET sequence_no = 3 WHERE journal_id = '${gap.sentId}' AND sequence_no = 2`);
    expect(verifyAt(gap.m, gap.path)).toEqual({ exitCode: 8, report: { ok: false, failures: [
      { step: 'journal-balanced', journalId: gap.sentId, eventType: 'REBALANCE_SENT', reference: EXEC },
    ] } });

    const bogus = await settledBook('bogus-type');
    tamper(bogus.path, 'DROP TRIGGER ledger_journals_no_update', `UPDATE ledger_journals SET event_type = 'BOGUS' WHERE id = '${bogus.sentId}'`);
    const bogusResult = verifyAt(bogus.m, bogus.path);
    expect(bogusResult.exitCode).toBe(8);
    expect(bogusResult.report.failures).toContainEqual({ step: 'journal-balanced', journalId: bogus.sentId, eventType: 'BOGUS', reference: EXEC });

    // Moving the send's debit from clearing to expense keeps the journal balanced but breaks the send posting rule.
    const shape = await settledBook('shape');
    tamper(shape.path, 'DROP TRIGGER ledger_lines_no_update',
      `UPDATE ledger_lines SET account_code = 'expense:routing_fees' WHERE journal_id = '${shape.sentId}' AND sequence_no = 1`);
    const shapeResult = verifyAt(shape.m, shape.path);
    expect(shapeResult.exitCode).toBe(8);
    expect(shapeResult.report.failures).toContainEqual({ step: 'journal-balanced', journalId: shape.sentId, eventType: 'REBALANCE_SENT', reference: EXEC });
  });

  it('CP-037/B5 step 3 checks the book against the execution records', async () => {
    // One execution per rule of SPEC §9.5 step 3; E1–E6 are wrong, E7–E10 are right.
    const seeds: ExecSeed[] = [
      { id: execId(1), status: 'VERIFIED_SUCCESS', actualFeeMsat: F },   // SENT + SETTLED + REVERSED
      { id: execId(2), status: 'VERIFIED_SUCCESS', actualFeeMsat: F },   // SETTLED without SENT
      { id: execId(3), status: 'UNKNOWN' },                              // SENT + SETTLED while UNKNOWN
      { id: execId(4), status: 'IN_FLIGHT' },                            // no SENT
      { id: execId(5), status: 'VERIFIED_SUCCESS', principalMsat: 99_000_000n, actualFeeMsat: F },  // amounts differ
      { id: execId(6), status: 'CANCELLED' },                            // SENT although nothing was sent
      { id: execId(7), status: 'UNKNOWN' },                              // SENT, fine
      { id: execId(8), status: 'VERIFIED_FAILURE' },                     // SENT + REVERSED, fine
      { id: execId(9), status: 'VERIFIED_FAILURE' },                     // nothing, fine (never sent)
      { id: execId(10), status: 'SUBMITTING' },                          // nothing, fine
    ];
    const { m, db, path } = await openSeeded('records', seeds);
    const settle = (n: number): Journal => m.settledJournal(rebalance(n), { settledChannel: 'ch5', actualFeeMsat: F }, 20);
    try {
      postAll(m, db, [m.sentJournal(rebalance(1), 10), settle(1)]);
      postAll(m, db, [m.sentJournal(rebalance(3), 10)]);
      postAll(m, db, [m.sentJournal(rebalance(5), 10), settle(5)]);
      postAll(m, db, [m.sentJournal(rebalance(6), 10)]);
      postAll(m, db, [m.sentJournal(rebalance(7), 10)]);
      postAll(m, db, [m.sentJournal(rebalance(8), 10), m.reversedJournal(rebalance(8), 20)]);
    } finally { db.close(); }
    // post() refuses these; they arrive by writing the file directly, with balances moved to match.
    rawJournal(path, 'JRNRAW0000000000000000001', m.reversedJournal(rebalance(1), 30));
    rawJournal(path, 'JRNRAW0000000000000000002', settle(2));
    rawJournal(path, 'JRNRAW0000000000000000003', settle(3));
    rawJournal(path, 'JRNRAW0000000000000000004', m.sentJournal({ ...worked, executionId: 'EXE01KGONE000000000000000' }, 10), false);

    const result = verifyAt(m, path);
    expect(result.exitCode).toBe(8);
    const step3 = result.report.failures.filter(f => f.step === 'execution-records')
      .map(f => `${f.executionId} ${f.reason}`).sort();
    expect(step3).toEqual([
      `${execId(1)} UNEXPECTED_JOURNAL`, `${execId(2)} MISSING_JOURNAL`, `${execId(3)} UNEXPECTED_JOURNAL`,
      `${execId(4)} MISSING_JOURNAL`, `${execId(5)} AMOUNT_MISMATCH`, `${execId(6)} UNEXPECTED_JOURNAL`,
      'EXE01KGONE000000000000000 UNKNOWN_EXECUTION',
    ].sort());
    expect(result.report.failures.filter(f => f.step !== 'execution-records')).toEqual([]);
  });

  it('CP-037/B5 a recorded fee that differs from the expensed fee is an amount mismatch', async () => {
    const { m, db, path } = await openSeeded('fee-record', [{ id: EXEC, status: 'VERIFIED_SUCCESS', actualFeeMsat: 202_000n }]);
    try {
      postAll(m, db, [m.sentJournal(worked, 10), m.settledJournal(worked, { settledChannel: 'ch5', actualFeeMsat: F }, 20)]);
    } finally { db.close(); }
    expect(verifyAt(m, path)).toEqual({ exitCode: 8, report: { ok: false, failures: [{ step: 'execution-records', executionId: EXEC, reason: 'AMOUNT_MISMATCH' }] } });
    setExecution(path, EXEC, 'VERIFIED_SUCCESS', F);
    expect(verifyAt(m, path).exitCode).toBe(0);
  });
});

describe('random event sequences', () => {
  /** mulberry32: a small deterministic generator so failures replay from the seed. */
  function rng(seed: number): () => number {
    let a = seed >>> 0;
    return () => {
      a = (a + 0x6D2B79F5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  const NEXT: Record<string, readonly ExecStatus[]> = {
    CLAIMED: ['PREFLIGHT'], PREFLIGHT: ['SUBMITTING', 'CANCELLED'],
    SUBMITTING: ['IN_FLIGHT', 'UNKNOWN', 'VERIFIED_FAILURE'],
    IN_FLIGHT: ['VERIFIED_SUCCESS', 'VERIFIED_FAILURE', 'UNKNOWN'],
    UNKNOWN: ['VERIFIED_SUCCESS', 'VERIFIED_FAILURE', 'UNKNOWN'],
  };

  it('CP-037/B6 every journal balances and assets equal opening balances less fees after every step', async () => {
    const channels = ['ch1', 'ch2', 'ch3', 'ch4'];
    for (const seed of [1, 7, 2026]) {
      const next = rng(seed);
      const pick = <T>(items: readonly T[]): T => items[Math.floor(next() * items.length)] as T;
      const amount = (max: number): bigint => BigInt(Math.floor(next() * max));
      const execs: { status: ExecStatus; sent: boolean; r: Rebalance }[] = Array.from({ length: 12 }, (_, i) => ({
        status: 'CLAIMED', sent: false,
        r: { executionId: `EXE${String(seed).padStart(6, '0')}${String(i).padStart(17, '0')}`, node: NODE_NAME, sourceChannel: pick(channels),
             principalMsat: amount(2 ** 36) + 1n, routeFeeMsat: next() < 0.2 ? 0n : amount(2 ** 20) } satisfies Rebalance,
      }));
      const seeds = execs.map(e => ({ id: e.r.executionId, principalMsat: e.r.principalMsat, routeFeeMsat: e.r.routeFeeMsat }));
      const { m, db, path } = await openSeeded(`prop-${String(seed)}`, seeds);
      try {
        // Independent model of what the books must show (SPEC §9.2).
        const expected = new Map<string, bigint>();
        const add = (account: string, delta: bigint): void => { expected.set(account, (expected.get(account) ?? 0n) + delta); };
        let openingTotal = 0n;
        for (const c of channels) {
          const local = amount(2 ** 40) + 1n;
          openingTotal += local;
          const opening = m.openingJournal({ node: NODE_NAME, channel: c, localMsat: local, occurredAt: 1 });
          if (opening === null) throw new Error('opening journal missing');
          postAll(m, db, [opening]);
          add(ch(c), local); add('equity:opening_balance', -local);
        }
        for (let step = 0; step < 50; step += 1) {
          const open = execs.filter(e => NEXT[e.status] !== undefined);
          if (open.length === 0) break;
          const e = pick(open);
          const to = pick(NEXT[e.status] ?? []);
          const { principalMsat: p, routeFeeMsat: fr, sourceChannel: s } = e.r;
          let outcome: ExecutionOutcome;
          let actual: bigint | null = null;
          if (to === 'VERIFIED_SUCCESS') {
            const fa = next() < 0.6 ? fr : amount(2 ** 20);
            actual = fa;
            const t = pick(channels.filter(c => c !== s));
            outcome = { status: 'VERIFIED_SUCCESS', settledChannel: t, actualFeeMsat: fa };
            if (!e.sent) { add('clearing:inflight', p + fr); add(ch(s), -(p + fr)); }
            add(ch(t), p); add('expense:routing_fees', fa); add('clearing:inflight', -(p + fr)); add('recon:difference', fr - fa);
          } else {
            outcome = { status: to };
            if (to === 'IN_FLIGHT') { add('clearing:inflight', p + fr); add(ch(s), -(p + fr)); }
            if (to === 'VERIFIED_FAILURE' && e.sent) { add(ch(s), p + fr); add('clearing:inflight', -(p + fr)); }
          }
          setExecution(path, e.r.executionId, to, actual);
          db.transaction(tx => m.postTransition(tx, e.r, outcome, step + 2));
          if (next() < 0.25) db.transaction(tx => m.postTransition(tx, e.r, outcome, step + 2)); // duplicate event delivery
          if (to === 'IN_FLIGHT' || to === 'VERIFIED_SUCCESS') e.sent = true;
          e.status = to;

          const tag = `seed ${String(seed)} step ${String(step)}`;
          for (const j of db.ledger.journals()) {
            const debit = j.lines.reduce((sum, l) => sum + l.debitMsat, 0n);
            const credit = j.lines.reduce((sum, l) => sum + l.creditMsat, 0n);
            expect(debit, `${tag} ${j.eventType} ${j.reference}`).toBe(credit);
          }
          const balances = db.ledger.balances();
          for (const [account, value] of expected) expect(balances.get(account) ?? 0n, `${tag} ${account}`).toBe(value);
          let assets = 0n;
          for (const [account, value] of balances) if (account.startsWith('channel:') || account === 'clearing:inflight') assets += value ?? 0n;
          const fees = (balances.get('expense:routing_fees') ?? 0n) + (balances.get('recon:difference') ?? 0n);
          expect(assets, `${tag} assets`).toBe(openingTotal - fees);
          expect(m.runLedgerVerify(db).report, `${tag} verify`).toEqual({ ok: true, failures: [] });
        }
      } finally { db.close(); }
    }
  });
});

describe('idempotent, append-only posting', () => {
  it('CP-037/B7 a replayed event posts once; distinct references get distinct journals', async () => {
    const second = execId(2);
    const { m, db } = await openSeeded('replay', [EXEC, second]);
    try {
      const sent = m.sentJournal(worked, 10);
      const first = db.transaction(tx => m.post(tx, sent));
      const replay = db.transaction(tx => m.post(tx, sent));
      expect(first.posted).toBe(true);
      expect(replay.posted).toBe(false);
      expect(replay.journalId).toBe(first.journalId);
      expect(balanceOf(db, 'clearing:inflight')).toBe(100_202_101n);
      expect(balanceOf(db, ch('ch2'))).toBe(-100_202_101n);

      const other: Rebalance = { ...worked, executionId: second, sourceChannel: 'ch3', principalMsat: 10_000_000n, routeFeeMsat: 11_000n };
      expect(postAll(m, db, [m.sentJournal(other, 11)])).toEqual([true]);
      const journals = db.ledger.journals();
      expect(journals).toHaveLength(2);
      expect(new Set(journals.map(j => j.id)).size).toBe(2);
      expect(journals.map(j => `${j.eventType}/${j.reference}`).sort()).toEqual([`REBALANCE_SENT/${EXEC}`, `REBALANCE_SENT/${second}`]);
      expect(balanceOf(db, 'clearing:inflight')).toBe(100_202_101n + 10_011_000n);
    } finally { db.close(); }
  });

  it('CP-037/B7 a different event under a posted key, a second terminal journal or a terminal without a send is a conflict', async () => {
    const ids = [execId(1), execId(2), execId(3)];
    const { m, db } = await openSeeded('conflict', ids);
    try {
      const r1 = rebalance(1);
      postAll(m, db, [m.sentJournal(r1, 10), m.settledJournal(r1, { settledChannel: 'ch5', actualFeeMsat: F }, 20)]);
      const before = Object.fromEntries(db.ledger.balances());
      // Same (REBALANCE_SETTLED, reference), another settled channel and fee: not a replay.
      expect(ledgerCodeOf(m, () => postAll(m, db, [m.settledJournal(r1, { settledChannel: 'ch6', actualFeeMsat: 999n }, 20)]))).toBe('CONFLICT');
      expect(ledgerCodeOf(m, () => postAll(m, db, [m.sentJournal({ ...r1, routeFeeMsat: 1n }, 10)]))).toBe('CONFLICT');
      // VERIFIED_SUCCESS is absorbing: no reversal after a settlement, and the reverse (SPEC §8.1).
      expect(ledgerCodeOf(m, () => postAll(m, db, [m.reversedJournal(r1, 30)]))).toBe('CONFLICT');
      const r2 = rebalance(2);
      postAll(m, db, [m.sentJournal(r2, 10), m.reversedJournal(r2, 20)]);
      expect(ledgerCodeOf(m, () => postAll(m, db, [m.settledJournal(r2, { settledChannel: 'ch5', actualFeeMsat: F }, 30)]))).toBe('CONFLICT');
      // A settlement or reversal needs the send of its reference (SPEC §8.2).
      const r3 = rebalance(3);
      expect(ledgerCodeOf(m, () => postAll(m, db, [m.settledJournal(r3, { settledChannel: 'ch5', actualFeeMsat: F }, 30)]))).toBe('CONFLICT');
      expect(ledgerCodeOf(m, () => postAll(m, db, [m.reversedJournal(r3, 30)]))).toBe('CONFLICT');

      expect(db.ledger.journals().map(j => `${j.eventType}/${j.reference}`).sort()).toEqual([
        `REBALANCE_REVERSED/${execId(2)}`, `REBALANCE_SENT/${execId(1)}`, `REBALANCE_SENT/${execId(2)}`, `REBALANCE_SETTLED/${execId(1)}`,
      ]);
      const after = Object.fromEntries([...db.ledger.balances()].filter(([k]) => k in before));
      expect(after).toEqual({ ...before, [ch('ch2')]: -100_202_101n });
    } finally { db.close(); }
  });

  it('CP-037/B7 journals and lines cannot be updated, deleted or replaced in the file; a duplicate insert is ignored', async () => {
    const { m, db, path } = await openSeeded('append-only', []);
    let journalId = '';
    try {
      const opening = m.openingJournal({ node: NODE_NAME, channel: 'ch2', localMsat: 5_000n, occurredAt: 1 });
      if (opening === null) throw new Error('opening journal missing');
      journalId = db.transaction(tx => m.post(tx, opening)).journalId;
    } finally { db.close(); }
    const snapshot = (): string => {
      const r = raw(path);
      try {
        const rows = [
          ...r.prepare('SELECT * FROM ledger_journals ORDER BY id').all(),
          ...r.prepare('SELECT * FROM ledger_lines ORDER BY journal_id, sequence_no').all(),
        ];
        return JSON.stringify(rows, (_k, v: unknown) => typeof v === 'bigint' ? v.toString() : v);
      } finally { r.close(); }
    };
    const original = snapshot();
    // INV-09: append-only. A statement may abort or be ignored, but none may change a stored row.
    const attempts = [
      'UPDATE ledger_lines SET debit_msat = 6000 WHERE debit_msat = 5000',
      'DELETE FROM ledger_lines',
      "UPDATE ledger_journals SET reference = 'x'",
      'DELETE FROM ledger_journals',
      `INSERT OR REPLACE INTO ledger_lines (journal_id, sequence_no, account_code, debit_msat, credit_msat)
         VALUES ('${journalId}', 1, '${ch('ch2')}', 6000, 0)`,
      `REPLACE INTO ledger_lines (journal_id, sequence_no, account_code, debit_msat, credit_msat)
         VALUES ('${journalId}', 2, 'equity:opening_balance', 0, 6000)`,
      `INSERT OR REPLACE INTO ledger_journals (id, execution_id, event_type, reference, occurred_at)
         VALUES ('${journalId}', NULL, 'OPENING', 'other', 2)`,
    ];
    for (const statement of attempts) {
      const r = raw(path);
      try { r.exec(statement); } catch { /* refused */ } finally { r.close(); }
      expect(snapshot(), statement).toBe(original);
    }
    // ON CONFLICT DO NOTHING stays available: it is how post() replays (ARCHITECTURE §7.2).
    const r = raw(path);
    try {
      expect(() => { r.exec(`INSERT INTO ledger_lines (journal_id, sequence_no, account_code, debit_msat, credit_msat)
        VALUES ('${journalId}', 1, '${ch('ch2')}', 6000, 0) ON CONFLICT DO NOTHING`); }).not.toThrow();
    } finally { r.close(); }
    expect(snapshot()).toBe(original);
  });
});
