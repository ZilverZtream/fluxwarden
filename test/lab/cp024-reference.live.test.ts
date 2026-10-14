// Live reference for CLN route assessment on CLN-M (SPEC §11.2: out via channel 2 to LND-R, back via channel 5
// from CLN-R). The reference getroutes runs under its own layer with the same parameters the adapter sends.
import { expect, it } from 'vitest';
import { adapterLabPlan, expectNoSentinelLeak, lightningCli, rows, type AdapterLabPlan } from '../helpers/adapter-lab.js';
import { loadClnRest } from '../helpers/adapter-interfaces.js';
import { isCandidate, loadClnRoutes, type RouteConstraints } from '../helpers/route-interfaces.js';

const P = 50_000_000n;

interface Lab { self: string; height: number; two: { scid: string; peer: string }; five: { scid: string; peer: string }; inFee: bigint; inDelta: number }

function lab(plan: AdapterLabPlan): Lab {
  const info = lightningCli(plan, ['getinfo']);
  const channels = rows(lightningCli(plan, ['listpeerchannels'])['channels'], 'listpeerchannels');
  const two = channels.find(item => item['peer_id'] === plan.lnd.pubkey);
  const five = channels.find(item => item['peer_id'] !== plan.lnd.pubkey && item['state'] === 'CHANNELD_NORMAL');
  if (two === undefined || five === undefined) throw new Error('lab topology: channels 2 and 5 of CLN-M not found');
  const remote = (five['updates'] as { remote: Record<string, unknown> }).remote;
  const amount = (value: unknown): bigint => BigInt(String(value).replace(/msat$/, ''));
  const inFee = amount(remote['fee_base_msat']) + (P * amount(remote['fee_proportional_millionths'])) / 1_000_000n;
  return {
    self: String(info['id']), height: Number(info['blockheight']), inFee, inDelta: Number(remote['cltv_expiry_delta']),
    two: { scid: String(two['short_channel_id']), peer: String(two['peer_id']) }, five: { scid: String(five['short_channel_id']), peer: String(five['peer_id']) },
  };
}

function constraints(l: Lab): RouteConstraints {
  return {
    selfPubkey: l.self, implementation: 'cln', sourceScid: l.two.scid, targetScid: l.five.scid, outPeer: l.two.peer, inPeer: l.five.peer,
    principalMsat: P, maxFeeMsat: 250_000n, maxCltvDelta: 144, finalCltvDelta: 18, blockHeight: l.height,
  };
}

async function adapter(plan: AdapterLabPlan) {
  const [{ openClnRest }, { ClnRouteApi }] = await Promise.all([loadClnRest(), loadClnRoutes()]);
  return new ClnRouteApi(await openClnRest({ host: plan.cln.host, port: plan.cln.port, tlsCertPath: plan.cln.tlsCert, runePath: plan.cln.credential }));
}

const layerNames = (plan: AdapterLabPlan): string[] => rows(lightningCli(plan, ['askrene-listlayers'])['layers'], 'layers').map(item => String(item['layer'])).sort();

it('CP-024/R1 lightning-cli getroutes from LND-R to CLN-R equals the middle of the adapter\'s assembled route', async () => {
  const plan = adapterLabPlan();
  const l = lab(plan);
  const c = constraints(l);
  const reference = 'fluxwarden-reference-r1';
  lightningCli(plan, ['askrene-create-layer', reference]);
  let path: Record<string, unknown>[];
  try {
    lightningCli(plan, ['askrene-disable-node', reference, l.self]);
    const answer = lightningCli(plan, ['-k', 'getroutes', `source=${l.two.peer}`, `destination=${l.five.peer}`, `amount_msat=${String(P + l.inFee)}`,
      `layers=["xpay","${reference}"]`, `maxfee_msat=${String(c.maxFeeMsat - l.inFee)}`, `final_cltv=${String(l.inDelta + 18)}`,
      `maxdelay=${String(144 - 18 - l.inDelta)}`, 'maxparts=1']);
    path = rows((answer['routes'] as Record<string, unknown>[])[0]?.['path'], 'path');
  } finally {
    lightningCli(plan, ['askrene-remove-layer', reference]);
  }
  const result = await (await adapter(plan)).buildCircularRoute(c, { layer: 'fluxwarden-lab-r1', excludeScids: [] });
  if (!isCandidate(result)) throw new Error('the adapter found no route');
  expect(result.hops[0]).toMatchObject({ scid: l.two.scid, nodeIdOut: l.two.peer });
  expect(result.hops.at(-1)).toMatchObject({ scid: l.five.scid, nodeIdOut: l.self, amountOutMsat: P });
  expect(result.hops.slice(1, -1).map(hop => [hop.scid, hop.nodeIdOut]))
    .toEqual(path.map(item => [String(item['short_channel_id_dir']).split('/')[0], item['node_id_out']]));
});

it('CP-024/R2 node-state: askrene-listlayers shows no leftover layer and no payment was attempted', async () => {
  const plan = adapterLabPlan();
  const l = lab(plan);
  const layers = layerNames(plan);
  const sendpays = rows(lightningCli(plan, ['listsendpays'])['payments'], 'payments').length;
  const api = await adapter(plan);
  await api.buildCircularRoute(constraints(l), { layer: 'fluxwarden-lab-r2a', excludeScids: [] });
  await api.buildCircularRoute({ ...constraints(l), maxFeeMsat: 1n }, { layer: 'fluxwarden-lab-r2b', excludeScids: [] });
  expect(layerNames(plan)).toEqual(layers);
  expect(rows(lightningCli(plan, ['listsendpays'])['payments'], 'payments')).toHaveLength(sendpays);
});

it('CP-024/Rleak independent nonempty sentinels are absent from product files scratch and retained output', async () => {
  await expectNoSentinelLeak();
});
