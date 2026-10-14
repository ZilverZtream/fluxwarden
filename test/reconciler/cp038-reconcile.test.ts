/*
Interface: src/reconciler/accounting.ts (depends on src/core and src/ledger only; no adapter import, ARCHITECTURE B6),
           src/commands/reconcile.ts.

  src/reconciler/accounting.ts — comparison of the ledger with node accounting (SPEC §9.4, §9.5 step 4)
    export interface ReconExecution {             // provided by the execution records (SPEC §6.2 executions)
      id: string; node: string;                   // node name, the <node> segment of channel accounts
      paymentHash: string;                        // 64 lowercase hex
      status: 'CLAIMED' | 'PREFLIGHT' | 'SUBMITTING' | 'IN_FLIGHT' | 'VERIFIED_SUCCESS' | 'VERIFIED_FAILURE' | 'UNKNOWN' | 'CANCELLED';
    }
    export interface LndAccountingApi {           // structurally the LndReadApi method of the same name
      listPayments(r: { indexOffset: bigint; maxPayments: number; includeIncomplete: boolean }): Promise<LndPaymentsPage>;
    }
    export interface ClnAccountingApi {           // structurally the ClnReadApi methods of the same names
      listSendPays(filter?: { paymentHash?: string }): Promise<ClnSendPay[]>;
      listAccountEvents(): Promise<ClnAccountEvent[]>;
    }
    export type AccountingSource =
      | { node: string; implementation: 'lnd'; api: LndAccountingApi }
      | { node: string; implementation: 'cln'; api: ClnAccountingApi };
    export interface ReconcileWindow { sinceMs: number; untilMs: number }        // half-open [sinceMs, untilMs), unix ms
    export type ComparisonSource = 'listpayments' | 'listsendpays' | 'bkpr';
    export interface Comparison {
      executionId: string; node: string; source: ComparisonSource;
      ledgerPrincipalMsat: bigint; nodePrincipalMsat: bigint | null;   // bkpr: always null
      ledgerFeeMsat: bigint; nodeFeeMsat: bigint | null;               // null: the node has no record
    }
    export interface Difference {
      kind: 'fee' | 'principal' | 'missing-on-node' | 'missing-in-ledger' | 'incomplete';
      node: string; executionId: string | null; source: ComparisonSource;
      ledgerMsat: bigint | null; nodeMsat: bigint | null; reason: string | null;
    }
    export interface NodeReadStatus { node: string; status: 'compared' | 'incomplete' | 'unavailable'; reason: string | null; requests: number }
    export interface AccountingReport {
      nodes: NodeReadStatus[];           // one per source, in source order
      comparisons: Comparison[];         // sorted by executionId, then source
      differences: Difference[];         // sorted by node, executionId (null first), source, kind
      journals: Journal[];               // RECON_DIFFERENCE journals to post (src/ledger/postings.ts Journal)
    }
    export function reconcileAccounting(input: {
      window: ReconcileWindow; journals: readonly StoredJournal[]; executions: readonly ReconExecution[];
      sources: readonly AccountingSource[]; occurredAt: number;
    }): Promise<AccountingReport>;

    Ledger side: an execution is compared when its REBALANCE_SETTLED journal has occurredAt in the window.
      Ledger principal = Σ debits of its `channel:` lines; ledger fee = Σ debits of `expense:routing_fees` (0 when absent).
    A node answer is evidence, never trusted blindly: an LND payment repeated with the same payment_index counts once
      (lnd#9410); a listsendpays part whose payment_hash is not the hash asked for is ignored; a duplicated bookkeeper
      event (same account, payment_id, part_id, debit, credit and timestamp; cln#9487) counts once.
    LND (source 'listpayments'): ListPayments pages of maxPayments 500, includeIncomplete false, first indexOffset 0n,
      next indexOffset = the previous page's lastIndexOffset. A page with fewer than 500 payments ends the read.
      At most 200 requests: a 200th full page → status 'incomplete', reason 'page-limit'. A full page whose
      lastIndexOffset ≤ the requested indexOffset → 'incomplete', reason 'offset-not-advancing', no further request.
      Node record of a hash: its SUCCEEDED payments; principal = value_msat, fee = fee_msat; time = creation_time_ns (ns).
    CLN: one listSendPays({ paymentHash }) per execution hash of that node (source 'listsendpays'): only `complete`
      parts count, every part: principal = Σ amount_msat, fee = Σ (amount_sent_msat − amount_msat); time = created_at (s).
      A complete part without amount_msat (optional, "if known") or with amount_msat > amount_sent_msat is never
      turned into a fee: the execution's listsendpays comparison has nodePrincipalMsat and nodeFeeMsat null and one
      difference { kind: 'incomplete', executionId, source: 'listsendpays', ledgerMsat: null, nodeMsat: null,
      reason: 'amount-unknown' | 'amount-exceeds-sent' }, and nothing is posted for it.
      One listAccountEvents() (source 'bkpr'): events with type 'channel', tag 'invoice', payment_id = hash, every
      part: fee = Σ fees_msat (absent = 0); the hash has a record when at least one such event exists; time = timestamp (s).
    Comparisons: one per compared execution and source of its node (LND: listpayments; CLN: bkpr and listsendpays).
    Differences:
      node record absent                         → missing-on-node {ledgerMsat: ledger principal, nodeMsat: null}
                                                   (not reported for a node whose read is incomplete)
      principal differs (not bkpr)               → principal {ledgerMsat, nodeMsat}
      fee differs                                → fee {ledgerMsat: ledger fee, nodeMsat: node fee}
      a node success record (listpayments / listsendpays) whose time is in the window for an execution
      without any REBALANCE_SETTLED journal      → missing-in-ledger {ledgerMsat: null, nodeMsat: node principal}
      incomplete read                            → incomplete {executionId: null, ledgerMsat: null, nodeMsat: null, reason}
      `reason` is null except for incomplete.
    Journals: every fee difference from listpayments, listsendpays or bkpr posts the part of d = node fee − ledger fee
      (ledger fee from the REBALANCE_SETTLED journal) that earlier RECON_DIFFERENCE fee corrections of the same
      execution across all accounting sources (found in input.journals) have not yet posted; nothing when that remainder is 0. One
      RECON_DIFFERENCE journal, executionId set, occurredAt = input.occurredAt, reference unique per execution, source
      and node fee answer (e.g. `${executionId}:fee:${source}:${nodeFee}`), with r the remainder:
        r > 0: [Dr expense:routing_fees r, Cr recon:difference r];  r < 0: [Dr recon:difference −r, Cr expense:routing_fees −r].
      So a rerun with the same answer posts nothing, and a changed answer posts only the change.
      SPEC §9.4 includes bookkeeper fee differences in these balanced, idempotent RECON_DIFFERENCE postings.
      Incomplete reads with no known monetary difference post nothing.

  src/commands/reconcile.ts
    export function parseReconcileWindow(flags: { since?: string; until?: string }, nowMs: number):
      | { ok: true; window: ReconcileWindow } | { ok: false; exitCode: 2; message: string };
      // durations <int>(s|m|h|d) (SPEC §7.1); sinceMs = now − since (default 24h), untilMs = now − until (default now);
      // a malformed duration or sinceMs ≥ untilMs → exit 2 (SPEC §10.3 G1).
    export function runReconcile(input: {
      db: Database; window: ReconcileWindow; executions: readonly ReconExecution[];
      sources: readonly AccountingSource[]; clock: { now(): number };
    }): Promise<{ exitCode: 0 | 7 | 8 | 9; report: { verify: VerifyReport; accounting: AccountingReport | null; postedJournalIds: string[] } }>;
      // 1. verifyLedger(db.ledger.book()); a failure → exit 8, accounting null, nothing posted.
      // 2. reconcileAccounting(..., occurredAt = clock.now()); 3. post every journal in one db.transaction (idempotent);
      // 4. exit 7 if an execution is IN_FLIGHT or UNKNOWN, else 9 if any difference, else 0 (SPEC §10.3 RC4).

Worked example (SPEC §4.4, §9.3): P = 100,000,000 msat out of channel 2, back through channel 5, F = 202,101 msat.
*/
import { describe, expect, it } from 'vitest';
import {
  endlessLndAccounting, fakeClnAccounting, fakeLndAccounting, preimagePair, scriptedLndPages,
  type ClnAccountingApi, type ClnEventSpec, type ClnPartSpec, type LndAccountingApi, type LndPaymentSpec,
} from '../fakes/accounting.js';
import { loadSource } from '../helpers/adapter-interfaces.js';
import { loadLedger, scratchDb, seededLedger, type Journal, type LedgerDatabase, type LedgerModules, type StoredJournal } from '../helpers/cp037-ledger.js';

type Status = 'CLAIMED' | 'PREFLIGHT' | 'SUBMITTING' | 'IN_FLIGHT' | 'VERIFIED_SUCCESS' | 'VERIFIED_FAILURE' | 'UNKNOWN' | 'CANCELLED';
interface ReconExecution { id: string; node: string; paymentHash: string; status: Status }
type AccountingSource =
  | { node: string; implementation: 'lnd'; api: LndAccountingApi }
  | { node: string; implementation: 'cln'; api: ClnAccountingApi };
interface Window { sinceMs: number; untilMs: number }
type Source = 'listpayments' | 'listsendpays' | 'bkpr';
interface Comparison {
  executionId: string; node: string; source: Source;
  ledgerPrincipalMsat: bigint; nodePrincipalMsat: bigint | null; ledgerFeeMsat: bigint; nodeFeeMsat: bigint | null;
}
interface Difference {
  kind: 'fee' | 'principal' | 'missing-on-node' | 'missing-in-ledger' | 'incomplete';
  node: string; executionId: string | null; source: Source; ledgerMsat: bigint | null; nodeMsat: bigint | null; reason: string | null;
}
interface AccountingReport {
  nodes: { node: string; status: 'compared' | 'incomplete' | 'unavailable'; reason: string | null; requests: number }[];
  comparisons: Comparison[]; differences: Difference[]; journals: Journal[];
}
interface AccountingModule {
  reconcileAccounting: (input: { window: Window; journals: readonly StoredJournal[]; executions: readonly ReconExecution[]; sources: readonly AccountingSource[]; occurredAt: number }) => Promise<AccountingReport>;
}
interface ReconcileCommand {
  parseReconcileWindow: (flags: { since?: string; until?: string }, nowMs: number) => { ok: true; window: Window } | { ok: false; exitCode: number; message: string };
  runReconcile: (input: { db: LedgerDatabase; window: Window; executions: readonly ReconExecution[]; sources: readonly AccountingSource[]; clock: { now(): number } }) =>
    Promise<{ exitCode: number; report: { verify: { ok: boolean }; accounting: AccountingReport | null; postedJournalIds: string[] } }>;
}

const P = 100_000_000n;
const F = 202_101n;
const SINCE = 1_760_000_000_000;
const UNTIL = SINCE + 86_400_000;
const WINDOW: Window = { sinceMs: SINCE, untilMs: UNTIL };
const SENT_AT = SINCE + 60_000;
const SETTLED_AT = SINCE + 120_000;
const CREATED_MS = SINCE + 55_000;
const NS = (ms: number): bigint => BigInt(ms) * 1_000_000n;
const S = (ms: number): number => Math.floor(ms / 1000);
const EXEC = 'EXE01K00000000000000000001';
const EXEC2 = 'EXE01K00000000000000000002';
const HASH = preimagePair(EXEC).hash;
const HASH2 = preimagePair(EXEC2).hash;
const CH2 = '812x1x0';
const CH5 = '812x2x0';

const accounting = (): Promise<AccountingModule> => loadSource<AccountingModule>('reconciler/accounting.ts');
const command = (): Promise<ReconcileCommand> => loadSource<ReconcileCommand>('commands/reconcile.ts');

/** A database whose ledger holds the send and settle journals of SPEC §9.3 for `node`, with the given ledger fee. */
async function settledBook(node: string, ledgerFee = F, settledAt = SETTLED_AT, routeFee = F): Promise<{ m: LedgerModules; db: LedgerDatabase }> {
  const m = await loadLedger();
  const db = seededLedger(m, scratchDb('cp038'), [{ id: EXEC, status: 'VERIFIED_SUCCESS', routeFeeMsat: routeFee, actualFeeMsat: ledgerFee }]);
  const rebalance = { executionId: EXEC, node, sourceChannel: CH2, principalMsat: P, routeFeeMsat: routeFee };
  db.transaction(tx => {
    m.post(tx, m.sentJournal(rebalance, SENT_AT));
    m.post(tx, m.settledJournal(rebalance, { settledChannel: CH5, actualFeeMsat: ledgerFee }, settledAt));
  });
  return { m, db };
}

const lndPaid = (overrides: Partial<LndPaymentSpec> = {}): LndPaymentSpec =>
  ({ seed: EXEC, status: 'SUCCEEDED', valueMsat: P, feeMsat: F, creationTimeNs: NS(CREATED_MS), ...overrides });
const clnPart = (overrides: Partial<ClnPartSpec> = {}): ClnPartSpec =>
  ({ seed: EXEC, partid: 0, status: 'complete', amountMsat: P, amountSentMsat: P + F, createdAt: S(CREATED_MS), ...overrides });
// The paying side's channel event carries the fee; the receiving side's event on channel 5 carries none.
const clnOut = (overrides: Partial<ClnEventSpec> = {}): ClnEventSpec =>
  ({ seed: EXEC, partId: 0, feesMsat: F, debitMsat: P, creditMsat: 0n, timestamp: S(SETTLED_AT), account: '78'.repeat(32), ...overrides });
const clnIn = (overrides: Partial<ClnEventSpec> = {}): ClnEventSpec =>
  ({ seed: EXEC, partId: 0, feesMsat: null, debitMsat: 0n, creditMsat: P, timestamp: S(SETTLED_AT), account: '79'.repeat(32), ...overrides });

const settled = (node: string, id = EXEC, paymentHash = HASH): ReconExecution => ({ id, node, paymentHash, status: 'VERIFIED_SUCCESS' });
const clock = { now: () => UNTIL };

function reconJournals(db: LedgerDatabase): StoredJournal[] {
  return db.ledger.journals().filter(journal => journal.eventType === 'RECON_DIFFERENCE');
}

describe('reconcile against node accounting', () => {
  it('CP-038/B1 a ledger that matches LND ListPayments to the msat reports one comparison, no difference and exit 0', async () => {
    const { db } = await settledBook('lnd-r');
    const lnd = await fakeLndAccounting([lndPaid()]);
    const { runReconcile } = await command();
    const result = await runReconcile({ db, window: WINDOW, executions: [settled('lnd-r')], sources: [{ node: 'lnd-r', implementation: 'lnd', api: lnd.api }], clock });
    expect(result.exitCode).toBe(0);
    expect(result.report.accounting?.nodes).toEqual([{ node: 'lnd-r', status: 'compared', reason: null, requests: 1 }]);
    expect(result.report.accounting?.comparisons).toEqual([{
      executionId: EXEC, node: 'lnd-r', source: 'listpayments', ledgerPrincipalMsat: P, nodePrincipalMsat: P, ledgerFeeMsat: F, nodeFeeMsat: F,
    }]);
    expect(result.report.accounting?.differences).toEqual([]);
    expect(lnd.requests).toEqual([{ indexOffset: 0n, maxPayments: 500, includeIncomplete: false }]);
    expect(reconJournals(db)).toHaveLength(0);
    expect(result.report.postedJournalIds).toEqual([]);
    db.close();
  });

  it('CP-038/B1 a ledger that matches CLN listsendpays and the bookkeeper fees_msat reports both comparisons and exit 0', async () => {
    const { db } = await settledBook('cln-m');
    const cln = await fakeClnAccounting([clnPart()], [clnOut(), clnIn()]);
    const { runReconcile } = await command();
    const result = await runReconcile({ db, window: WINDOW, executions: [settled('cln-m')], sources: [{ node: 'cln-m', implementation: 'cln', api: cln.api }], clock });
    expect(result.exitCode).toBe(0);
    expect(result.report.accounting?.comparisons).toEqual([
      { executionId: EXEC, node: 'cln-m', source: 'bkpr', ledgerPrincipalMsat: P, nodePrincipalMsat: null, ledgerFeeMsat: F, nodeFeeMsat: F },
      { executionId: EXEC, node: 'cln-m', source: 'listsendpays', ledgerPrincipalMsat: P, nodePrincipalMsat: P, ledgerFeeMsat: F, nodeFeeMsat: F },
    ]);
    expect(result.report.accounting?.differences).toEqual([]);
    expect([...cln.requests].sort()).toEqual(['bkpr-listaccountevents', `listsendpays:${HASH}`]);
    expect(reconJournals(db)).toHaveLength(0);
    db.close();
  });

  it('CP-038/B2 an extra 1 msat fee on LND is one fee difference, one balanced RECON_DIFFERENCE journal and exit 9, posted once across reruns', async () => {
    const { m, db } = await settledBook('lnd-r');
    const lnd = await fakeLndAccounting([lndPaid({ feeMsat: F + 1n })]);
    const { runReconcile } = await command();
    const input = { db, window: WINDOW, executions: [settled('lnd-r')], sources: [{ node: 'lnd-r', implementation: 'lnd' as const, api: lnd.api }], clock };
    const first = await runReconcile(input);
    expect(first.exitCode).toBe(9);
    expect(first.report.accounting?.differences).toEqual([
      { kind: 'fee', node: 'lnd-r', executionId: EXEC, source: 'listpayments', ledgerMsat: F, nodeMsat: F + 1n, reason: null },
    ]);
    const posted = reconJournals(db);
    expect(posted).toHaveLength(1);
    expect(posted[0]?.reference).toBe(`${EXEC}:fee:listpayments`);
    expect(posted[0]?.executionId).toBe(EXEC);
    expect(posted[0]?.occurredAt).toBe(UNTIL);
    expect(posted[0]?.lines.map(line => [line.account, line.debitMsat, line.creditMsat])).toEqual([
      [m.EXPENSE_ROUTING_FEES, 1n, 0n], [m.RECON_DIFFERENCE, 0n, 1n],
    ]);
    expect(first.report.postedJournalIds).toEqual([posted[0]?.id]);
    // Node fee 202,102 = ledger 202,101 + the 1 msat parked against recon:difference.
    expect(db.ledger.balances().get(m.EXPENSE_ROUTING_FEES)).toBe(F + 1n);
    expect(db.ledger.balances().get(m.RECON_DIFFERENCE)).toBe(-1n);

    const second = await runReconcile(input);
    expect(second.exitCode).toBe(9);
    expect(second.report.accounting?.differences).toHaveLength(1);
    expect(reconJournals(db)).toHaveLength(1);
    expect(second.report.postedJournalIds).toEqual([]);
    expect(db.ledger.balances().get(m.RECON_DIFFERENCE)).toBe(-1n);
    expect(m.verifyLedger({ journals: db.ledger.journals(), balances: db.ledger.balances(), executions: db.ledger.executions() }).ok).toBe(true);
    db.close();
  });

  it.each(['listsendpays', 'bkpr'] as const)('CP-038/B2 a fee missing from CLN %s posts its exact balanced difference once across reruns', async source => {
    const { m, db } = await settledBook('cln-m');
    // Isolate each accounting source's fee discrepancy against the original settlement journal.
    const cln = await fakeClnAccounting(
      [clnPart({ amountSentMsat: source === 'listsendpays' ? P : P + F })],
      [clnOut({ feesMsat: source === 'bkpr' ? null : F }), clnIn()],
    );
    const { runReconcile } = await command();
    const input = { db, window: WINDOW, executions: [settled('cln-m')], sources: [{ node: 'cln-m', implementation: 'cln' as const, api: cln.api }], clock };
    const result = await runReconcile(input);
    expect(result.exitCode).toBe(9);
    expect(result.report.accounting?.comparisons).toEqual([
      { executionId: EXEC, node: 'cln-m', source: 'bkpr', ledgerPrincipalMsat: P, nodePrincipalMsat: null, ledgerFeeMsat: F, nodeFeeMsat: source === 'bkpr' ? 0n : F },
      { executionId: EXEC, node: 'cln-m', source: 'listsendpays', ledgerPrincipalMsat: P, nodePrincipalMsat: P, ledgerFeeMsat: F, nodeFeeMsat: source === 'listsendpays' ? 0n : F },
    ]);
    expect(result.report.accounting?.differences).toEqual([
      { kind: 'fee', node: 'cln-m', executionId: EXEC, source, ledgerMsat: F, nodeMsat: 0n, reason: null },
    ]);
    const posted = reconJournals(db);
    expect(posted.map(journal => journal.reference)).toEqual([`${EXEC}:fee:${source}`]);
    expect(posted[0]?.executionId).toBe(EXEC);
    expect(posted[0]?.occurredAt).toBe(UNTIL);
    expect(posted[0]?.lines.map(line => [line.account, line.debitMsat, line.creditMsat])).toEqual([
      [m.RECON_DIFFERENCE, F, 0n], [m.EXPENSE_ROUTING_FEES, 0n, F],
    ]);
    expect(db.ledger.balances().get(m.EXPENSE_ROUTING_FEES)).toBe(0n);
    expect(db.ledger.balances().get(m.RECON_DIFFERENCE)).toBe(F);
    expect(result.report.postedJournalIds).toEqual([posted[0]?.id]);
    const replay = await runReconcile(input);
    expect(replay.exitCode).toBe(9);
    expect(replay.report.accounting?.differences).toEqual(result.report.accounting?.differences);
    expect(replay.report.postedJournalIds).toEqual([]);
    expect(reconJournals(db)).toEqual(posted);
    expect(db.ledger.balances().get(m.EXPENSE_ROUTING_FEES)).toBe(0n);
    expect(db.ledger.balances().get(m.RECON_DIFFERENCE)).toBe(F);
    expect(m.verifyLedger({ journals: db.ledger.journals(), balances: db.ledger.balances(), executions: db.ledger.executions() }).ok).toBe(true);
    db.close();
  });

  it('CP-038/B2 agreeing CLN fee observations report both sources but adjust one execution once across replay', async () => {
    const { m, db } = await settledBook('cln-m');
    // SPEC §9.4 and INV-08: these RPCs observe the same economic fee, not two expenses.
    const cln = await fakeClnAccounting([clnPart({ amountSentMsat: P + F + 1n })], [clnOut({ feesMsat: F + 1n }), clnIn()]);
    const { runReconcile } = await command();
    const input = { db, window: WINDOW, executions: [settled('cln-m')], sources: [{ node: 'cln-m', implementation: 'cln' as const, api: cln.api }], clock };
    try {
      expect(m.runLedgerVerify(db).exitCode).toBe(0);
      const first = await runReconcile(input);
      expect(first.exitCode).toBe(9);
      expect(first.report.verify.ok).toBe(true);
      expect(first.report.accounting?.comparisons).toEqual([
        { executionId: EXEC, node: 'cln-m', source: 'bkpr', ledgerPrincipalMsat: P, nodePrincipalMsat: null, ledgerFeeMsat: F, nodeFeeMsat: F + 1n },
        { executionId: EXEC, node: 'cln-m', source: 'listsendpays', ledgerPrincipalMsat: P, nodePrincipalMsat: P, ledgerFeeMsat: F, nodeFeeMsat: F + 1n },
      ]);
      expect(first.report.accounting?.differences).toEqual([
        { kind: 'fee', node: 'cln-m', executionId: EXEC, source: 'bkpr', ledgerMsat: F, nodeMsat: F + 1n, reason: null },
        { kind: 'fee', node: 'cln-m', executionId: EXEC, source: 'listsendpays', ledgerMsat: F, nodeMsat: F + 1n, reason: null },
      ]);
      const posted = reconJournals(db);
      expect(posted).toHaveLength(1);
      expect(posted[0]?.executionId).toBe(EXEC);
      expect(posted[0]?.occurredAt).toBe(UNTIL);
      expect(posted[0]?.lines.map(line => [line.account, line.debitMsat, line.creditMsat])).toEqual([
        [m.EXPENSE_ROUTING_FEES, 1n, 0n], [m.RECON_DIFFERENCE, 0n, 1n],
      ]);
      expect(first.report.postedJournalIds).toEqual([posted[0]?.id]);
      expect(db.ledger.balances().get(m.EXPENSE_ROUTING_FEES)).toBe(F + 1n);
      expect(db.ledger.balances().get(m.RECON_DIFFERENCE)).toBe(-1n);
      expect(m.runLedgerVerify(db).exitCode).toBe(0);

      const replay = await runReconcile(input);
      expect(replay.exitCode).toBe(9);
      expect(replay.report.accounting?.comparisons).toEqual(first.report.accounting?.comparisons);
      expect(replay.report.accounting?.differences).toEqual(first.report.accounting?.differences);
      expect(replay.report.postedJournalIds).toEqual([]);
      expect(reconJournals(db)).toEqual(posted);
      expect(db.ledger.balances().get(m.EXPENSE_ROUTING_FEES)).toBe(F + 1n);
      expect(db.ledger.balances().get(m.RECON_DIFFERENCE)).toBe(-1n);
      expect(m.runLedgerVerify(db).exitCode).toBe(0);
    } finally { db.close(); }
  });

  it.each([
    { initialMode: 'both', nextMode: 'listsendpays', nextFee: 170n },
    { initialMode: 'listsendpays', nextMode: 'both', nextFee: 170n },
    { initialMode: 'both', nextMode: 'listsendpays', nextFee: 80n },
    { initialMode: 'listsendpays', nextMode: 'both', nextFee: 80n },
  ] as const)('CP-038/B2 CLN fee corrections remain one economic expense when $initialMode changes to $nextMode and the fee becomes $nextFee', async ({ initialMode, nextMode, nextFee }) => {
    // SPEC §9.4, INV-08/09: both RPCs observe one execution fee; corrections are append-only and balanced.
    // Fresh available sources agree throughout. Disagreement between fresh sources is a separate policy question.
    const baseFee = 100n;
    const { m, db } = await settledBook('cln-m', baseFee, SETTLED_AT, baseFee);
    const { runReconcile } = await command();
    const original = db.ledger.journals();
    const run = async (fee: bigint, mode: 'both' | 'listsendpays') => {
      const cln = await fakeClnAccounting([clnPart({ amountSentMsat: P + fee })], [clnOut({ feesMsat: fee }), clnIn()]);
      const unavailable = () => Promise.reject(new Error('accounting source unavailable'));
      const api: ClnAccountingApi = {
        listSendPays: filter => cln.api.listSendPays(filter),
        listAccountEvents: () => mode === 'listsendpays' ? unavailable() : cln.api.listAccountEvents(),
      };
      return runReconcile({ db, window: WINDOW, executions: [settled('cln-m')], sources: [{ node: 'cln-m', implementation: 'cln', api }], clock });
    };
    const checkBook = (fee: bigint, corrections: number) => {
      expect(db.ledger.balances().get(m.EXPENSE_ROUTING_FEES)).toBe(fee);
      expect(db.ledger.balances().get(m.RECON_DIFFERENCE)).toBe(baseFee - fee);
      expect(reconJournals(db)).toHaveLength(corrections);
      expect(db.ledger.journals()).toHaveLength(original.length + corrections);
      expect(db.ledger.journals().slice(0, original.length)).toEqual(original);
      for (const journal of db.ledger.journals()) {
        expect(journal.lines.reduce((sum, line) => sum + line.debitMsat - line.creditMsat, 0n)).toBe(0n);
      }
      expect(m.runLedgerVerify(db).exitCode).toBe(0);
    };
    const checkObservations = (result: Awaited<ReturnType<typeof run>>, fee: bigint, mode: 'both' | 'listsendpays') => {
      expect(result.exitCode).toBe(9);
      expect(result.report.verify.ok).toBe(true);
      expect(result.report.accounting?.comparisons.map(row => [row.source, row.ledgerFeeMsat, row.nodeFeeMsat])).toEqual([
        ['bkpr', baseFee, mode === 'both' ? fee : null], ['listsendpays', baseFee, fee],
      ]);
    };
    try {
      expect(original.filter(journal => journal.eventType === 'REBALANCE_SENT')).toHaveLength(1);
      expect(original.filter(journal => journal.eventType === 'REBALANCE_SETTLED')).toHaveLength(1);
      expect(m.runLedgerVerify(db).exitCode).toBe(0);
      const first = await run(150n, initialMode);
      checkObservations(first, 150n, initialMode);
      expect(first.report.postedJournalIds).toHaveLength(1);
      checkBook(150n, 1);
      expect((await run(150n, initialMode)).report.postedJournalIds).toEqual([]);
      checkBook(150n, 1);

      const switched = await run(nextFee, nextMode);
      checkObservations(switched, nextFee, nextMode);
      expect(switched.report.postedJournalIds).toHaveLength(1);
      const correction = reconJournals(db).find(journal => journal.id === switched.report.postedJournalIds[0]);
      const delta = nextFee - 150n;
      expect(correction?.lines.map(line => [line.account, line.debitMsat, line.creditMsat])).toEqual(delta > 0n
        ? [[m.EXPENSE_ROUTING_FEES, delta, 0n], [m.RECON_DIFFERENCE, 0n, delta]]
        : [[m.RECON_DIFFERENCE, -delta, 0n], [m.EXPENSE_ROUTING_FEES, 0n, -delta]]);
      checkBook(nextFee, 2);
      expect((await run(nextFee, nextMode)).report.postedJournalIds).toEqual([]);
      checkBook(nextFee, 2);

      const restored = await run(nextFee, 'both');
      checkObservations(restored, nextFee, 'both');
      expect(restored.report.postedJournalIds).toEqual([]);
      expect((await run(nextFee, 'both')).report.postedJournalIds).toEqual([]);
      checkBook(nextFee, 2);
      expect(new Set(reconJournals(db).map(journal => journal.reference)).size).toBe(2);
    } finally { db.close(); }
  });

  it('CP-038/B2 a settled execution the node has no record of is a missing-on-node difference and exit 9', async () => {
    const { db } = await settledBook('lnd-r');
    const lnd = await fakeLndAccounting([lndPaid({ seed: 'someone-else' })]);
    const { runReconcile } = await command();
    const result = await runReconcile({ db, window: WINDOW, executions: [settled('lnd-r')], sources: [{ node: 'lnd-r', implementation: 'lnd', api: lnd.api }], clock });
    expect(result.exitCode).toBe(9);
    expect(result.report.accounting?.differences).toEqual([
      { kind: 'missing-on-node', node: 'lnd-r', executionId: EXEC, source: 'listpayments', ledgerMsat: P, nodeMsat: null, reason: null },
    ]);
    expect(result.report.accounting?.comparisons[0]?.nodeFeeMsat).toBeNull();
    db.close();
  });

  it('CP-038/B3 ListPayments that keeps answering full pages stops after 200 requests of 500 and reports incomplete with exit 9', async () => {
    const { db } = await settledBook('lnd-r');
    const lnd = await endlessLndAccounting('advancing');
    const { runReconcile } = await command();
    const result = await runReconcile({ db, window: WINDOW, executions: [settled('lnd-r')], sources: [{ node: 'lnd-r', implementation: 'lnd', api: lnd.api }], clock });
    expect(lnd.requests).toHaveLength(200);
    expect(lnd.requests.every(request => request.maxPayments === 500 && !request.includeIncomplete)).toBe(true);
    expect(lnd.requests.map(request => request.indexOffset)).toEqual(Array.from({ length: 200 }, (_, i) => BigInt(i) * 500n));
    expect(result.report.accounting?.nodes).toEqual([{ node: 'lnd-r', status: 'incomplete', reason: 'page-limit', requests: 200 }]);
    // Our payment may be on a page that was never read: no missing-on-node claim, only the incomplete read.
    expect(result.report.accounting?.differences).toEqual([
      { kind: 'incomplete', node: 'lnd-r', executionId: null, source: 'listpayments', ledgerMsat: null, nodeMsat: null, reason: 'page-limit' },
    ]);
    expect(result.exitCode).toBe(9);
    expect(reconJournals(db)).toHaveLength(0);
    db.close();
  });

  it('CP-038/B3 a full page whose last_index_offset does not advance ends the read at once as incomplete', async () => {
    const lnd = await endlessLndAccounting('stuck');
    const { reconcileAccounting } = await accounting();
    const report = await reconcileAccounting({
      window: WINDOW, journals: [], executions: [settled('lnd-r')], sources: [{ node: 'lnd-r', implementation: 'lnd', api: lnd.api }], occurredAt: UNTIL,
    });
    expect(lnd.requests).toEqual([{ indexOffset: 0n, maxPayments: 500, includeIncomplete: false }]);
    expect(report.nodes).toEqual([{ node: 'lnd-r', status: 'incomplete', reason: 'offset-not-advancing', requests: 1 }]);
    expect(report.differences.map(row => [row.kind, row.reason])).toEqual([['incomplete', 'offset-not-advancing']]);
    expect(report.journals).toEqual([]);
  });

  it('CP-038/B4 a CLN payment split into parts is summed over every complete part in listsendpays and the bookkeeper', async () => {
    const { db } = await settledBook('cln-m');
    // 60,000,000 + 40,000,000 = P; fees 121,261 + 80,840 = 202,101 = F. The failed part moved nothing.
    const cln = await fakeClnAccounting([
      clnPart({ partid: 1, amountMsat: 60_000_000n, amountSentMsat: 60_121_261n }),
      clnPart({ partid: 2, amountMsat: 40_000_000n, amountSentMsat: 40_080_840n }),
      clnPart({ partid: 3, status: 'failed', amountMsat: 40_000_000n, amountSentMsat: 40_080_840n }),
    ], [
      clnOut({ partId: 1, feesMsat: 121_261n, debitMsat: 60_000_000n }), clnOut({ partId: 2, feesMsat: 80_840n, debitMsat: 40_000_000n }),
      clnIn({ partId: 1, creditMsat: 60_000_000n }), clnIn({ partId: 2, creditMsat: 40_000_000n }),
    ]);
    const { runReconcile } = await command();
    const result = await runReconcile({ db, window: WINDOW, executions: [settled('cln-m')], sources: [{ node: 'cln-m', implementation: 'cln', api: cln.api }], clock });
    expect(result.report.accounting?.comparisons).toEqual([
      { executionId: EXEC, node: 'cln-m', source: 'bkpr', ledgerPrincipalMsat: P, nodePrincipalMsat: null, ledgerFeeMsat: F, nodeFeeMsat: F },
      { executionId: EXEC, node: 'cln-m', source: 'listsendpays', ledgerPrincipalMsat: P, nodePrincipalMsat: P, ledgerFeeMsat: F, nodeFeeMsat: F },
    ]);
    expect(result.report.accounting?.differences).toEqual([]);
    expect(result.exitCode).toBe(0);
    db.close();
  });

  describe('CP-038/B5 node times in ns (LND) and s (CLN) are placed in the ms window', () => {
    // EXEC2 succeeded on the node but the ledger has only its send journal: a missing-in-ledger difference exactly
    // when the node's record time falls in [since, until).
    async function unsettledBook(node: string): Promise<StoredJournal[]> {
      const m = await loadLedger();
      const db = seededLedger(m, scratchDb('cp038-b5'), [EXEC2]);
      db.transaction(tx => { m.post(tx, m.sentJournal({ executionId: EXEC2, node, sourceChannel: CH2, principalMsat: P, routeFeeMsat: F }, SENT_AT)); });
      const journals = db.ledger.journals();
      db.close();
      return journals;
    }
    const missing = (node: string, source: Source): Difference[] =>
      [{ kind: 'missing-in-ledger', node, executionId: EXEC2, source, ledgerMsat: null, nodeMsat: P, reason: null }];

    it.each([
      ['since + 1 s', true, SINCE + 1_000], ['exactly since', true, SINCE],
      ['since − 1 ms', false, SINCE - 1], ['exactly until', false, UNTIL],
    ])('CP-038/B5 an LND creation_time_ns at %s is in the window: %s', async (_label, inside, ms) => {
      const journals = await unsettledBook('lnd-r');
      const lnd = await fakeLndAccounting([lndPaid({ seed: EXEC2, creationTimeNs: NS(ms) })]);
      const { reconcileAccounting } = await accounting();
      const report = await reconcileAccounting({
        window: WINDOW, journals, executions: [settled('lnd-r', EXEC2, HASH2)], sources: [{ node: 'lnd-r', implementation: 'lnd', api: lnd.api }], occurredAt: UNTIL,
      });
      expect(report.differences).toEqual(inside ? missing('lnd-r', 'listpayments') : []);
    });

    it.each([
      ['since + 1 s', true, S(SINCE) + 1], ['since − 1 s', false, S(SINCE) - 1], ['until', false, S(UNTIL)],
    ])('CP-038/B5 a CLN created_at at %s is in the window: %s', async (_label, inside, seconds) => {
      const journals = await unsettledBook('cln-m');
      const cln = await fakeClnAccounting([clnPart({ seed: EXEC2, createdAt: seconds })], []);
      const { reconcileAccounting } = await accounting();
      const report = await reconcileAccounting({
        window: WINDOW, journals, executions: [settled('cln-m', EXEC2, HASH2)], sources: [{ node: 'cln-m', implementation: 'cln', api: cln.api }], occurredAt: UNTIL,
      });
      expect(report.differences.filter(row => row.source === 'listsendpays')).toEqual(inside ? missing('cln-m', 'listsendpays') : []);
    });

    it('CP-038/B5 a settled execution is matched by hash even when the node created the payment before the window', async () => {
      const { db } = await settledBook('lnd-r');
      const lnd = await fakeLndAccounting([lndPaid({ creationTimeNs: NS(SINCE - 3_600_000) })]);
      const { reconcileAccounting } = await accounting();
      const report = await reconcileAccounting({
        window: WINDOW, journals: db.ledger.journals(), executions: [settled('lnd-r')], sources: [{ node: 'lnd-r', implementation: 'lnd', api: lnd.api }], occurredAt: UNTIL,
      });
      expect(report.differences).toEqual([]);
      expect(report.comparisons.map(row => [row.nodePrincipalMsat, row.nodeFeeMsat])).toEqual([[P, F]]);
      db.close();
    });
  });

  it('CP-038/B6 --since equal to --until, or later than it, is invalid input (exit 2); a valid pair gives the ms window', async () => {
    const { parseReconcileWindow } = await command();
    const now = 1_760_086_400_000;
    for (const flags of [{ since: '1h', until: '1h' }, { since: '1h', until: '2h' }, { since: '3600s', until: '1h' }, { since: '1x' }, { since: '' }]) {
      const parsed = parseReconcileWindow(flags, now);
      expect(parsed.ok, JSON.stringify(flags)).toBe(false);
      if (!parsed.ok) expect(parsed.exitCode).toBe(2);
    }
    expect(parseReconcileWindow({ since: '2h', until: '1h' }, now)).toEqual({ ok: true, window: { sinceMs: now - 7_200_000, untilMs: now - 3_600_000 } });
    expect(parseReconcileWindow({ since: '1d' }, now)).toEqual({ ok: true, window: { sinceMs: now - 86_400_000, untilMs: now } });
  });
});

describe('reconcile against node accounting: hostile and changing node answers', () => {
  const lndSource = (api: LndAccountingApi): AccountingSource => ({ node: 'lnd-r', implementation: 'lnd', api });
  const clnSource = (api: ClnAccountingApi): AccountingSource => ({ node: 'cln-m', implementation: 'cln', api });
  const sendpayRows = (report: AccountingReport | null | undefined): Difference[] => (report?.differences ?? []).filter(row => row.source === 'listsendpays');

  it('CP-038/B1 an execution still UNKNOWN makes reconcile exit 7 even when every comparison matches (SPEC §10.3 RC4)', async () => {
    const { db } = await settledBook('lnd-r');
    const lnd = await fakeLndAccounting([lndPaid()]);
    const { runReconcile } = await command();
    const unknown: ReconExecution = { id: EXEC2, node: 'lnd-r', paymentHash: HASH2, status: 'UNKNOWN' };
    const result = await runReconcile({ db, window: WINDOW, executions: [settled('lnd-r'), unknown], sources: [lndSource(lnd.api)], clock });
    expect(result.report.accounting?.differences).toEqual([]);
    expect(result.exitCode).toBe(7);
    db.close();
  });

  it('CP-038/B2 a CLN part without amount_msat is never read as fee 0: incomplete amount-unknown, nothing posted', async () => {
    const { m, db } = await settledBook('cln-m');
    const cln = await fakeClnAccounting([clnPart({ amountMsat: null })], [clnOut(), clnIn()]);
    const { runReconcile } = await command();
    const result = await runReconcile({ db, window: WINDOW, executions: [settled('cln-m')], sources: [clnSource(cln.api)], clock });
    expect(sendpayRows(result.report.accounting)).toEqual([
      { kind: 'incomplete', node: 'cln-m', executionId: EXEC, source: 'listsendpays', ledgerMsat: null, nodeMsat: null, reason: 'amount-unknown' },
    ]);
    expect(result.report.accounting?.comparisons.find(row => row.source === 'listsendpays')).toMatchObject({ nodePrincipalMsat: null, nodeFeeMsat: null });
    expect(result.exitCode).toBe(9);
    expect(reconJournals(db)).toHaveLength(0);
    expect(db.ledger.balances().get(m.EXPENSE_ROUTING_FEES)).toBe(F);
    db.close();
  });

  it('CP-038/B2 a CLN part delivering more than it sent (negative fee) is refused as amount-exceeds-sent, nothing posted', async () => {
    const { m, db } = await settledBook('cln-m');
    const cln = await fakeClnAccounting([clnPart({ amountMsat: P + F + 5n, amountSentMsat: P + F })], [clnOut(), clnIn()]);
    const { runReconcile } = await command();
    const result = await runReconcile({ db, window: WINDOW, executions: [settled('cln-m')], sources: [clnSource(cln.api)], clock });
    expect(sendpayRows(result.report.accounting)).toEqual([
      { kind: 'incomplete', node: 'cln-m', executionId: EXEC, source: 'listsendpays', ledgerMsat: null, nodeMsat: null, reason: 'amount-exceeds-sent' },
    ]);
    expect(result.exitCode).toBe(9);
    expect(reconJournals(db)).toHaveLength(0);
    expect(db.ledger.balances().get(m.EXPENSE_ROUTING_FEES)).toBe(F);
    db.close();
  });

  it('CP-038/B2 when the node fee answer changes between runs only the change is posted, and an unchanged answer posts nothing', async () => {
    const { m, db } = await settledBook('lnd-r');
    const { runReconcile } = await command();
    const run = async (fee: bigint): Promise<Awaited<ReturnType<ReconcileCommand['runReconcile']>>> => runReconcile({
      db, window: WINDOW, executions: [settled('lnd-r')], sources: [lndSource((await fakeLndAccounting([lndPaid({ feeMsat: fee })])).api)], clock,
    });
    expect((await run(F + 7n)).exitCode).toBe(9);
    expect(db.ledger.balances().get(m.EXPENSE_ROUTING_FEES)).toBe(F + 7n);
    const second = await run(F + 9n);
    expect(second.report.accounting?.differences).toEqual([
      { kind: 'fee', node: 'lnd-r', executionId: EXEC, source: 'listpayments', ledgerMsat: F, nodeMsat: F + 9n, reason: null },
    ]);
    expect(db.ledger.balances().get(m.EXPENSE_ROUTING_FEES)).toBe(F + 9n);
    expect(db.ledger.balances().get(m.RECON_DIFFERENCE)).toBe(-9n);
    const corrections = reconJournals(db);
    expect(corrections).toHaveLength(2);
    const amounts = corrections.map(journal => journal.lines.map(line => [line.account, line.debitMsat, line.creditMsat]));
    expect(amounts).toContainEqual([[m.EXPENSE_ROUTING_FEES, 2n, 0n], [m.RECON_DIFFERENCE, 0n, 2n]]);
    expect(amounts).toContainEqual([[m.EXPENSE_ROUTING_FEES, 7n, 0n], [m.RECON_DIFFERENCE, 0n, 7n]]);
    const third = await run(F + 9n);
    expect(third.report.postedJournalIds).toEqual([]);
    expect(reconJournals(db)).toHaveLength(2);
    expect(m.verifyLedger({ journals: db.ledger.journals(), balances: db.ledger.balances(), executions: db.ledger.executions() }).ok).toBe(true);
    db.close();
  });

  it('CP-038/B3 an LND payment repeated with the same payment_index (lnd#9410) is counted once', async () => {
    const { db } = await settledBook('lnd-r');
    const lnd = await scriptedLndPages([[{ spec: lndPaid(), index: 7n }, { spec: lndPaid(), index: 7n }]]);
    const { runReconcile } = await command();
    const result = await runReconcile({ db, window: WINDOW, executions: [settled('lnd-r')], sources: [lndSource(lnd.api)], clock });
    expect(result.report.accounting?.comparisons.map(row => [row.nodePrincipalMsat, row.nodeFeeMsat])).toEqual([[P, F]]);
    expect(result.report.accounting?.differences).toEqual([]);
    expect(result.exitCode).toBe(0);
    db.close();
  });

  it('CP-038/B4 a listsendpays answer carrying a part of another payment hash does not count that part', async () => {
    const { db } = await settledBook('cln-m');
    const cln = await fakeClnAccounting([clnPart(), clnPart({ seed: 'foreign', amountMsat: 5_000_000n, amountSentMsat: 5_010_000n })], [clnOut(), clnIn()], { ignoreFilter: true });
    const { runReconcile } = await command();
    const result = await runReconcile({ db, window: WINDOW, executions: [settled('cln-m')], sources: [clnSource(cln.api)], clock });
    expect(result.report.accounting?.comparisons.find(row => row.source === 'listsendpays')).toMatchObject({ nodePrincipalMsat: P, nodeFeeMsat: F });
    expect(result.report.accounting?.differences).toEqual([]);
    db.close();
  });

  it('CP-038/B4 a duplicated bookkeeper event (cln#9487) counts its fee once', async () => {
    const { db } = await settledBook('cln-m');
    const cln = await fakeClnAccounting([clnPart()], [clnOut(), clnOut(), clnIn()]);
    const { runReconcile } = await command();
    const result = await runReconcile({ db, window: WINDOW, executions: [settled('cln-m')], sources: [clnSource(cln.api)], clock });
    expect(result.report.accounting?.comparisons.find(row => row.source === 'bkpr')).toMatchObject({ nodeFeeMsat: F });
    expect(result.report.accounting?.differences).toEqual([]);
    expect(result.exitCode).toBe(0);
    db.close();
  });

  it.each([['exactly since', SINCE, true], ['exactly until', UNTIL, false]])(
    'CP-038/B5 a settle journal at %s is compared (half-open ledger window)', async (_label, settledAt, compared) => {
      const { db } = await settledBook('lnd-r', F, settledAt);
      const lnd = await fakeLndAccounting([lndPaid({ feeMsat: F + 1n })]);
      const { reconcileAccounting } = await accounting();
      const report = await reconcileAccounting({ window: WINDOW, journals: db.ledger.journals(), executions: [settled('lnd-r')], sources: [lndSource(lnd.api)], occurredAt: UNTIL });
      expect(report.comparisons).toHaveLength(compared ? 1 : 0);
      expect(report.differences.map(row => row.kind)).toEqual(compared ? ['fee'] : []);
      expect(report.journals).toHaveLength(compared ? 1 : 0);
      db.close();
    });
});
