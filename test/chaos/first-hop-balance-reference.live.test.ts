import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { expect, it } from 'vitest';
import { firstHopSetup, observedLndSpendable } from '../../labs/scenarios/chaos/lnd-spendable.mjs';
import { t18Record } from '../../labs/scenarios/chaos/t18-record.mjs';
import { clean, cli, history, initializeRegistry, input, lndConfig, oracle, preflight, query, retain, setRunner, unchangedOld } from '../../labs/scenarios/chaos/live-reference.mjs';
import { nativeDirectCheckout } from '../helpers/native-direct-checkout.js';
import { nativeBalanceWorker } from '../helpers/native-balance-worker.js';
setRunner((file, args, options) => spawnSync(file, args, options));
type Row = Record<string, unknown>;

// This is the normal public worker API preflight→dispatch boundary, not the
// default CLI's earlier P3 reserve guard. No adapter answer/write is replaced.
it('CP-044/OPS-T18 T-18 native first-hop fee-only deficit cancels the genuine READY public worker before invoice or send', async () => {
  initializeRegistry(); await preflight('t18-worker-before');
  const p = input(), originalHistory = history();
  const manifest = p.manifest as { nodes: Record<string, { pubkey: string }> };
  const cln = manifest.nodes['cln-m']; if (!cln) throw new Error('GAP T-18 owned shared peer unavailable');
  const facts: Row = { scope: 'LND public worker API preflight→dispatch, lease180s; CLI last-hop case remains separate',
    confidence: 'DERIVED_ESTIMATE', setupPayments: [], phase: 'entry' };
  t18Record('t18-first-hop-worker', 'FIRST_HOP_SPENDABLE', 'GAP', { ...facts, reason: 'native variant has not completed' });
  const native = (): { lnd: Row; cln: Row } => ({ lnd: oracle('lnd-r', 'listchannels'), cln: oracle('cln-m', 'listpeerchannels') });
  const source = (snapshot: { lnd: Row }): Row => {
    const channel = (snapshot.lnd['channels'] as Row[]).find(channel => channel['remote_pubkey'] === cln.pubkey);
    if (!channel) throw new Error('GAP T-18 owned source channel unavailable'); return channel;
  };
  const balanceIdentity = (snapshot: { lnd: Row; cln: Row }): unknown => ({
    lnd: (snapshot.lnd['channels'] as Row[]).map(channel => Object.fromEntries(['channel_point', 'remote_pubkey', 'active', 'capacity',
      'local_balance', 'remote_balance', 'unsettled_balance', 'fee_per_kw', 'commit_weight', 'commit_fee', 'initiator',
      'commitment_type', 'local_constraints', 'remote_constraints', 'pending_htlcs'].map(key => [key, channel[key]])))
      .sort((a, b) => String(a['channel_point']).localeCompare(String(b['channel_point']))),
    cln: (snapshot.cln['channels'] as Row[]).map(channel => Object.fromEntries(['channel_id', 'peer_id', 'short_channel_id', 'state',
      'peer_connected', 'total_msat', 'to_us_msat', 'spendable_msat', 'receivable_msat', 'our_reserve_msat', 'their_reserve_msat', 'htlcs']
      .map(key => [key, channel[key]]))).sort((a, b) => String(a['channel_id']).localeCompare(String(b['channel_id']))),
  });
  const entry = native(); facts['nativeEntry'] = entry;
  let worker: Awaited<ReturnType<typeof nativeBalanceWorker>> | undefined, fixture: ReturnType<typeof lndConfig> | undefined;
  const settled: { amount: bigint; reverse: boolean }[] = [];
  let payments = 0, cleanupComplete = false;
  const checkout = async (amount: bigint, reverse: boolean, restoration = false): Promise<void> => {
    if (++payments > 4) throw new Error('LabInvalidError: T-18 four-payment bound');
    await nativeDirectCheckout(amount, reverse, () => { if (!restoration) settled.push({ amount, reverse }); });
    (facts['setupPayments'] as unknown[]).push({ amountMsat: amount.toString(), reverse, restoration, settled: true });
  };
  try {
    try {
      const entrySource = source(entry), estimate = observedLndSpendable(entrySource);
      const own = (entry.cln['channels'] as Row[]).find(channel => channel['peer_id'] === manifest.nodes['lnd-r']?.pubkey);
      if (!own || !Array.isArray(own['htlcs']) || own['htlcs'].length || !/^[0-9]+$/.test(String(own['spendable_msat']))) {
        throw new Error('GAP T-18 independent reverse capacity unavailable');
      }
      fixture = lndConfig(true); facts['financialDatabase'] = fixture.database;
      const url = (path: string): string => pathToFileURL(resolve('dist', path)).href;
      const [{ configStage }, { activePolicy }] = await Promise.all([
        import(url('commands/stages.js')) as Promise<typeof import('../../src/commands/stages.js')>,
        import(url('commands/workflow.js')) as Promise<typeof import('../../src/commands/workflow.js')>,
      ]);
      const policy = activePolicy(configStage(fixture.config)), target = policy.targets['lnd-r']?.[String(entrySource['scid'])]?.min_outbound_msat ?? 0n;
      const reserve = target > policy.amounts.min_channel_reserve_msat ? target : policy.amounts.min_channel_reserve_msat;
      const setup = firstHopSetup(estimate.spendableMsat, policy.fees.max_fee_msat, reserve, BigInt(String(own['spendable_msat'])));
      facts['entryEstimate'] = estimate; facts['finiteSetup'] = setup;
      retain('t18-worker-entry-feasibility', facts);
      facts['phase'] = 'setup';
      if (setup.topUp > 0n) await checkout(setup.topUp, true);
      expect(cli(['doctor'], 't18-worker-doctor', fixture.config).exit).toBe(0);
      const planned = cli(['liquidity', 'plan', '--refresh'], 't18-worker-plan', fixture.config);
      expect(planned.exit).toBe(0); expect(planned.body.result).toMatchObject({ action: 'CIRCULAR_REBALANCE', principal_msat: '100000000', source_channel: String(entrySource['scid']) });
      const proposal = String(planned.body.result['proposal_id']);
      expect(cli(['liquidity', 'approve', proposal, '--key', p.key], 't18-worker-approval', fixture.config).exit).toBe(0);
      worker = await nativeBalanceWorker(fixture.config, fixture.database, proposal);
      const ready = await worker.prepare(); facts['ready'] = ready; facts['verifiedApproval'] = worker.approval;
      if (ready.kind !== 'READY') throw new Error('GAP T-18 genuine native branded READY route unavailable');
      facts['phase'] = 'prepared';
      expect(ready.route.principalMsat).toBe(setup.principal);
      const fee = ready.route.totalFeeMsat; expect(fee > 0n).toBe(true);
      const healthy = native(), healthyEstimate = observedLndSpendable(source(healthy));
      facts['nativeReady'] = healthy; facts['readyEstimate'] = healthyEstimate;
      const desired = setup.principal + fee / 2000n * 1000n, drain = healthyEstimate.spendableMsat - desired;
      expect(drain > 0n && drain <= 100000000n).toBe(true);
      await checkout(drain, false);
      const deadline = Date.now() + 10000;
      let depleted = native(), observed = observedLndSpendable(source(depleted));
      while ((observed.spendableMsat < setup.principal || observed.spendableMsat >= setup.principal + fee) && Date.now() < deadline) {
        await delay(150); depleted = native(); observed = observedLndSpendable(source(depleted));
      }
      facts['nativeDepleted'] = depleted; facts['depletedEstimate'] = observed; facts['routeFeeMsat'] = fee;
      expect(observed.spendableMsat >= setup.principal && observed.spendableMsat < setup.principal + fee).toBe(true);
      const before = { payments: oracle('lnd-r', 'listpayments', ['--include_incomplete']), invoices: oracle('lnd-r', 'listinvoices') };
      facts['nativeMoneyBeforeDispatch'] = before;
      const ledgerBefore = query(fixture.database, 'SELECT * FROM ledger_journals');
      expect(worker.mutatingCalls).toEqual([]);
      facts['phase'] = 'dispatch';
      const outcome = await worker.dispatch(ready); facts['dispatchOutcome'] = outcome;
      const after = { payments: oracle('lnd-r', 'listpayments', ['--include_incomplete']), invoices: oracle('lnd-r', 'listinvoices') };
      facts['nativeMoneyAfterDispatch'] = after; facts['workerMutatingCalls'] = worker.mutatingCalls;
      facts['workerChannelObservations'] = worker.channelObservations; facts['workerAlerts'] = worker.alerts;
      expect(outcome).toMatchObject({ exit: 5, step: 'FIRST_HOP_SPENDABLE' });
      expect(worker.mutatingCalls).toEqual([]); expect(worker.alerts).toEqual([]); expect(after).toEqual(before);
      expect(worker.channelObservations.at(-1)?.find(channel => channel.channelKey === String(entrySource['scid']))?.spendableMsat).toBe(observed.spendableMsat);
      expect(query(fixture.database, 'SELECT status,payment_hash,error_code FROM executions')).toEqual([{ status: 'CANCELLED', payment_hash: null, error_code: 'FIRST_HOP_SPENDABLE' }]);
      expect(query(fixture.database, 'SELECT state,consumed_msat FROM budget_reservations')).toEqual([{ state: 'RELEASED', consumed_msat: null }]);
      expect(query(fixture.database, 'SELECT * FROM ledger_journals')).toEqual(ledgerBefore);
      unchangedOld(originalHistory, history());
    } finally {
      facts['phaseBeforeCleanup'] = facts['phase']; facts['phase'] = 'cleanup';
      try {
        for (const payment of [...settled].reverse()) await checkout(payment.amount, !payment.reverse, true);
        await clean(); await preflight('t18-worker-after');
        const restored = native(); facts['nativeRestored'] = restored;
        expect(balanceIdentity(restored)).toEqual(balanceIdentity(entry));
        cleanupComplete = true; facts['originalNativeBalancesRestored'] = true;
      } finally {
        if (fixture && worker) {
          const database = fixture.database;
          facts['financialHistory'] = Object.fromEntries(['liquidity_proposals', 'approvals', 'executions', 'execution_events', 'budget_reservations', 'ledger_journals', 'ledger_lines']
            .map(table => [table, query(database, `SELECT * FROM ${table}`)]));
        }
        worker?.db.close();
        retain('t18-worker-retained-history', facts);
      }
    }
  } catch (error) {
    t18Record('t18-first-hop-worker', 'FIRST_HOP_SPENDABLE', cleanupComplete ? facts['phaseBeforeCleanup'] === 'entry' ? 'GAP' : 'PARTIAL' : 'INVALID',
      { ...facts, reason: 'native variant did not complete all required assertions', errorName: error instanceof Error ? error.name : 'unknown' });
    throw error;
  }
  t18Record('t18-first-hop-worker', 'FIRST_HOP_SPENDABLE', 'PASS', facts);
});
