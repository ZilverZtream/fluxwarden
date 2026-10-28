// Live reference for LND route assessment on LND-R (SPEC §11.2 topology). `lncli queryroutes` has no
// last-hop flag and takes sat (cmd/commands/cmd_payments.go#L1120-L1300 at v0.21.4-beta), so the principal is
// a whole number of sat and the reverse-edge pairs leave one possible last hop.
import { spawnSync } from 'node:child_process';
import { expect, it } from 'vitest';
import { adapterLabPlan, expectNoSentinelLeak, lncli, lncliShortChannelId, rows, type AdapterLabPlan } from '../helpers/adapter-lab.js';
import { loadLndRest, type LndRest } from '../helpers/adapter-interfaces.js';
import { isCandidate, loadLndRoutes, type RouteConstraints } from '../helpers/route-interfaces.js';

const P = 50_000_000n;

function scid(chanId: string): string {
  const value = BigInt(chanId);
  return `${String(value >> 40n)}x${String((value >> 16n) & 0xffffffn)}x${String(value & 0xffffn)}`;
}

interface LabChannels { self: string; height: number; one: { chanId: string; peer: string }; two: { chanId: string; peer: string }; three: { chanId: string; peer: string } }

/** Channel 2 leads to CLN-M; channel 1 to LND-P, a node with one channel; channel 3 to CLN-R. */
function labChannels(plan: AdapterLabPlan): LabChannels {
  const info = lncli(plan, ['getinfo']);
  const channels = rows(lncli(plan, ['listchannels'])['channels'], 'listchannels').map(item => ({ chanId: lncliShortChannelId(item), peer: String(item['remote_pubkey']) }));
  const two = channels.find(item => item.peer === plan.cln.pubkey);
  const others = channels.filter(item => item.peer !== plan.cln.pubkey);
  const degree = (peer: string): number => Number(lncli(plan, ['getnodeinfo', '--pub_key', peer])['num_channels']);
  const one = others.find(item => degree(item.peer) === 1);
  const three = others.find(item => degree(item.peer) > 1);
  if (two === undefined || one === undefined || three === undefined) throw new Error('lab topology: channels 1, 2 and 3 of LND-R not found');
  return { self: String(info['identity_pubkey']), height: Number(info['block_height']), one, two, three };
}

function lncliRaw(plan: AdapterLabPlan, args: readonly string[]): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync('docker', ['compose', '--project-name', plan.project, '-f', plan.composeFile, 'exec', '-T', plan.lnd.service, 'lncli', '--network=regtest', ...args],
    { shell: false, windowsHide: true, encoding: 'utf8', timeout: 60_000 });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function queryArgs(lab: LabChannels, out: { chanId: string; peer: string }, back: { peer: string }, c: RouteConstraints): string[] {
  return [
    'queryroutes', '--dest', lab.self, '--amt', String(c.principalMsat / 1000n), '--fee_limit', String(c.maxFeeMsat / 1000n),
    '--final_cltv_delta', String(c.finalCltvDelta), '--cltv_limit', String(c.maxCltvDelta - 3), '--use_mc',
    '--outgoing_chan_id', out.chanId, '--ignore_pair', `${out.peer}:${lab.self}`, '--ignore_pair', `${lab.self}:${back.peer}`,
  ];
}

async function adapter(plan: AdapterLabPlan, spy?: string[]) {
  const [{ openLndRest }, { LndRouteApi }] = await Promise.all([loadLndRest(), loadLndRoutes()]);
  const real = await openLndRest({ host: plan.lnd.host, port: plan.lnd.port, tlsCertPath: plan.lnd.tlsCert, macaroonPath: plan.lnd.credential });
  const rest: LndRest = {
    call: (method, path, body) => { spy?.push(`${method} ${path}`); return real.call(method, path, body); },
    stream: (method, path, body, onMessage, signal) => { spy?.push(`STREAM ${method} ${path}`); return real.stream(method, path, body, onMessage, signal); },
  };
  return new LndRouteApi(rest);
}

function constraints(lab: LabChannels, out: { chanId: string; peer: string }, back: { chanId: string; peer: string }): RouteConstraints {
  return {
    selfPubkey: lab.self, implementation: 'lnd', sourceScid: scid(out.chanId), targetScid: scid(back.chanId), outPeer: out.peer, inPeer: back.peer,
    principalMsat: P, maxFeeMsat: 250_000n, maxCltvDelta: 144, finalCltvDelta: 18, blockHeight: lab.height,
  };
}

it('CP-023/R1 out via channel 1 back via channel 3: lncli finds no path and the adapter answers NO_FEASIBLE_ROUTE', async () => {
  const plan = adapterLabPlan();
  const lab = labChannels(plan);
  const c = constraints(lab, lab.one, lab.three);
  const live = lncliRaw(plan, queryArgs(lab, lab.one, lab.three, c));
  expect(live.status).not.toBe(0);
  expect(live.stderr).toContain('unable to find a path to destination');
  expect(await (await adapter(plan)).buildCircularRoute(c)).toMatchObject({ kind: 'no-route', code: 'NO_FEASIBLE_ROUTE' });
});

it('CP-023/R1 out via channel 3 back via channel 2: the adapter route equals lncli queryroutes hop by hop', async () => {
  const plan = adapterLabPlan();
  const lab = labChannels(plan);
  const c = constraints(lab, lab.three, lab.two);
  const live = JSON.parse(lncliRaw(plan, queryArgs(lab, lab.three, lab.two, c)).stdout) as { routes: { total_time_lock: number; hops: Record<string, unknown>[] }[] };
  const reference = live.routes[0];
  if (reference === undefined) throw new Error('lncli returned no route');
  const result = await (await adapter(plan)).buildCircularRoute(c);
  if (!isCandidate(result)) throw new Error('the adapter found no route');
  expect(result.totalTimeLock).toBe(reference.total_time_lock);
  expect(result.hops.map(hop => [hop.scid, hop.nodeIdOut, hop.amountOutMsat])).toEqual(reference.hops.map(hop => [
    scid(String(hop['chan_id'])), hop['pub_key'], BigInt(String(hop['amt_to_forward_msat'])) + BigInt(String(hop['fee_msat'])),
  ]));
});

it('CP-023/R2 node-state: an assessment issues read calls only and creates no payment', async () => {
  const plan = adapterLabPlan();
  const lab = labChannels(plan);
  const before = rows(lncli(plan, ['listpayments', '--include_incomplete'])['payments'] ?? [], 'payments').length;
  const calls: string[] = [];
  await (await adapter(plan, calls)).buildCircularRoute(constraints(lab, lab.three, lab.two));
  expect(calls.length).toBeGreaterThan(0);
  for (const call of calls) expect(call).toMatch(/^(?:POST \/v1\/graph\/routes\/[0-9a-f]{66}\/0|GET \/v1\/graph\/edge\/\d+)$/);
  expect(rows(lncli(plan, ['listpayments', '--include_incomplete'])['payments'] ?? [], 'payments')).toHaveLength(before);
});

it('CP-023/Rleak independent nonempty sentinels are absent from product files scratch and retained output', async () => {
  await expectNoSentinelLeak();
});
