// Live reference for `liquidity plan` on CLN-M after the lab workload has drained channel 2's inbound side
// (SPEC §11.2, §10.3 item 5): one CIRCULAR_REBALANCE proposal, channel 2 → channel 5, whose stored route equals
// a fresh assembly of the live getroutes answer. Interfaces as in test/planner/cp025-proposals.test.ts.
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { adapterLabPlan, expectNoSentinelLeak, lightningCli, rows } from '../helpers/adapter-lab.js';
import { loadClnRest } from '../helpers/adapter-interfaces.js';
import { repoRoot } from '../helpers/cli.js';
import { fixedClock, policy } from '../helpers/cp020-planner.js';
import { loadPersistence, raw, scratch } from '../helpers/cp015-persistence.js';
import { isCandidate, loadClnRoutes, type RouteConstraints } from '../helpers/route-interfaces.js';

interface Normalize { normalizeClnChannel(raw: unknown, ctx: { nodeId: string; observedAt: number; blockHeight: number }): Record<string, unknown> & { channelKey: string; receivableMsat: bigint } }
interface PlanModule { liquidityPlan: (input: Record<string, unknown>) => Promise<{ exitCode: number; json: string }> }

const NODE_ID = '01JC0000000000000000000LAB';

it('CP-025/R1 db-state: a plan on the drained lab stores one CIRCULAR_REBALANCE for CLN-M from channel 2 to channel 5 with the live route', async () => {
  const plan = adapterLabPlan();
  const normalize = await import(pathToFileURL(join(repoRoot, 'src/core/normalize.ts')).href) as Normalize;
  const { liquidityPlan } = await import(pathToFileURL(join(repoRoot, 'src/commands/liquidity-plan.ts')).href) as PlanModule;
  const [{ openClnRest }, { ClnRouteApi }] = await Promise.all([loadClnRest(), loadClnRoutes()]);
  const routes = new ClnRouteApi(await openClnRest({ host: plan.cln.host, port: plan.cln.port, tlsCertPath: plan.cln.tlsCert, runePath: plan.cln.credential }));

  const info = lightningCli(plan, ['getinfo']);
  const height = Number(info['blockheight']);
  const now = Date.now();
  const channels = rows(lightningCli(plan, ['listpeerchannels'])['channels'], 'listpeerchannels')
    .filter(item => item['state'] === 'CHANNELD_NORMAL')
    .map(item => normalize.normalizeClnChannel(item, { nodeId: NODE_ID, observedAt: now, blockHeight: height }));
  const two = channels.find(item => item['peerPubkey'] === plan.lnd.pubkey);
  const five = channels.find(item => item['peerPubkey'] !== plan.lnd.pubkey);
  if (two === undefined || five === undefined) throw new Error('lab topology: channels 2 and 5 of CLN-M not found');

  const p = await loadPersistence();
  const path = join(scratch('cp025-lab'), 'fluxwarden.db');
  const db = p.openDatabase(path, { readOnly: false });
  try {
    db.nodes.insert({ id: NODE_ID, name: 'cln-m', implementation: 'cln', expectedNetwork: 'regtest', expectedPubkey: String(info['id']) });
    for (const item of channels) db.snapshots.record(db.channels.upsert(item as never), item as never);
    const targets = { 'cln-m': { [two.channelKey]: { min_inbound_msat: two.receivableMsat + 60_000_000n }, [five.channelKey]: { min_inbound_msat: 0n } } };
    const seen: RouteConstraints[] = [];
    const outcome = await liquidityPlan({
      db, node: { id: NODE_ID, name: 'cln-m', pubkey: String(info['id']), implementation: 'cln' }, channels,
      policy: policy(targets), policySha256: 'c0'.repeat(32), policyCanonicalJson: '{"version":3}', blockHeight: height, finalCltvDelta: 18,
      cooldowns: [], reservations: [], clock: fixedClock(now),
      routes: { buildCircularRoute: (c: RouteConstraints) => { seen.push(c); return routes.buildCircularRoute(c, { layer: `fluxwarden-lab-plan-${String(seen.length)}`, excludeScids: [] }); } },
    });
    expect(outcome.exitCode).toBe(0);
    const doc = (JSON.parse(outcome.json) as { result: Record<string, unknown> }).result;
    expect(doc).toMatchObject({ action: 'CIRCULAR_REBALANCE', source_channel: two.channelKey, target_channel: five.channelKey });
    const stored = (() => { const conn = raw(path); try { return conn.prepare('SELECT action_type, route_json FROM liquidity_proposals').all() as Record<string, unknown>[]; } finally { conn.close(); } })();
    expect(stored).toHaveLength(1);
    expect(stored[0]?.['action_type']).toBe('CIRCULAR_REBALANCE');
    const chosen = seen.find(c => c.sourceScid === two.channelKey && c.targetScid === five.channelKey);
    if (chosen === undefined) throw new Error('channel 2 → channel 5 was not assessed');
    const live = await routes.buildCircularRoute(chosen, { layer: 'fluxwarden-lab-plan-check', excludeScids: [] });
    if (!isCandidate(live)) throw new Error('no live route');
    const route = JSON.parse(String(stored[0]?.['route_json'])) as { hops: { channel: string; node_out: string; amount_msat: string; cltv: number }[] };
    expect(route.hops).toEqual(live.hops.map(hop => ({ channel: hop.scid, node_out: hop.nodeIdOut, amount_msat: hop.amountOutMsat.toString(), cltv: hop.cltvOut })));
  } finally { db.close(); }
});

it('CP-025/Rleak independent nonempty sentinels are absent from product files scratch and retained output', async () => {
  await expectNoSentinelLeak();
});
