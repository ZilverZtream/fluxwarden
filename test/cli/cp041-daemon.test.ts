/*
 * Interface: `fluxwarden daemon` (the full loop, without --collect) through the built CLI (SPEC §10.4).
 *
 * Invocation: fluxwarden daemon --config <path>   (collect_interval from the configuration, design default 15s)
 *   DM1 G1-G4. DM2 G5 for every node; an identity or network mismatch aborts with exit 5 (INV-12). DM3 startup sweep.
 *   DM4 loops until SIGINT/SIGTERM: collector, planner (stores proposals as `liquidity plan --refresh` would), reconciler,
 *   lease sweeper. DM6 on a signal: stop the loops, release held leases, exit 0.
 *   The daemon never executes a proposal, approved or not (INV-02): no invoice, sendpay or other fund-moving call, no
 *   executions row.
 * Signals are delivered inside the child as test/helpers/cp016-cli.ts spawnCli does (Windows has no catchable external
 * signal).
 */
import { afterEach, describe, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { MUTATING, methodsOf } from '../fakes/cln/rebalance-node.js';
import { spawnCli } from '../helpers/cp016-cli.js';
import { approve, count, demo, plan, rows, SAFETY_REFUSAL, SUCCESS, until } from '../helpers/cpw-cli.js';

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

describe('daemon', () => {
  it('CP-041/B1 the daemon loop proposes the CLN-M rebalance and never executes, even an approved proposal', async () => {
    const d = await demo(open, { collectInterval: '1s' });
    // An approved proposal is waiting: the daemon must leave it alone.
    const approved = String((await plan(d))['proposal_id']);
    await approve(d, approved);
    const proposalsBefore = count(d.database, 'liquidity_proposals');
    const spawned = spawnCli(['daemon', '--config', d.config], { signals: true, timeoutMs: 40_000 });
    try {
      await until(() => count(d.database, 'liquidity_proposals') > proposalsBefore, 20_000, 'a proposal from the daemon');
      // Several more collector intervals pass.
      await new Promise(resolve => setTimeout(resolve, 3_000));
    } finally {
      spawned.signal('SIGINT');
    }
    const run = await spawned.done;
    expect(run.status).toBe(SUCCESS);
    const fresh = rows(d.database, "SELECT action_type, status FROM liquidity_proposals WHERE status = 'PROPOSED'");
    expect(fresh.length).toBeGreaterThan(0);
    expect(fresh.every(row => row['action_type'] === 'CIRCULAR_REBALANCE')).toBe(true);
    expect(count(d.database, 'executions')).toBe(0);
    expect(methodsOf(d.cln.fake).filter(method => MUTATING.includes(method))).toEqual([]);
    expect(rows(d.database, `SELECT status FROM liquidity_proposals WHERE id = '${approved.replace(/^prop_/, '')}'`)).toEqual([{ status: 'APPROVED' }]);
    // DM6: the database is left consistent.
    expect(rows(d.database, 'PRAGMA integrity_check')).toEqual([{ integrity_check: 'ok' }]);
  }, 90_000);

  it('CP-041/B3 SIGTERM mid-loop ends the daemon with exit 0 and an intact database', async () => {
    const d = await demo(open, { collectInterval: '1s' });
    const spawned = spawnCli(['daemon', '--config', d.config], { signals: true, timeoutMs: 40_000 });
    try {
      await until(() => methodsOf(d.cln.fake).includes('listpeerchannels'), 20_000, 'the first collection');
    } finally {
      spawned.signal('SIGTERM');
    }
    const run = await spawned.done;
    expect(run.status).toBe(SUCCESS);
    expect(rows(d.database, 'PRAGMA integrity_check')).toEqual([{ integrity_check: 'ok' }]);
    expect(count(d.database, 'executions')).toBe(0);
  }, 90_000);

  it('CP-041/W1 a node whose identity differs from expected_pubkey aborts the daemon with exit 5 before any proposal', async () => {
    const d = await demo(open, { collectInterval: '1s', fake: { id: `03${'e9'.repeat(32)}` } });
    const run = await spawnCli(['daemon', '--config', d.config], { signals: true, timeoutMs: 40_000 }).done;
    expect(run.status).toBe(SAFETY_REFUSAL);
    expect(count(d.database, 'liquidity_proposals')).toBe(0);
    expect(methodsOf(d.cln.fake).filter(method => MUTATING.includes(method))).toEqual([]);
    expect(rows(d.database, "SELECT state FROM nodes WHERE name = 'cln-m'")).toEqual([{ state: 'QUARANTINED' }]);
  }, 90_000);
});
