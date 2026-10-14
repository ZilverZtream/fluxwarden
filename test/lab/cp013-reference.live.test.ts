import { expect, it } from 'vitest';
import { adapterLabPlan, expectNoSentinelLeak, lightningCli, lncli, type AdapterLabPlan } from '../helpers/adapter-lab.js';
import {
  loadCapabilities, loadClnProbe, loadClnRest, loadLndProbe, loadLndRest, rejection,
  type ClnRest, type LndRest, type NodeProbeUpdate, type ProbeContext,
} from '../helpers/adapter-interfaces.js';

function context(expectedPubkey: string): ProbeContext & { updates: NodeProbeUpdate[] } {
  const updates: NodeProbeUpdate[] = [];
  return { nodeId: 'lab-node', expectedPubkey, expectedNetwork: 'regtest', mutating: true, nowMs: () => Date.now(), updates, store: { recordProbe: (update: NodeProbeUpdate) => { updates.push(update); return Promise.resolve(); } } };
}

/** Request log: every call the probe makes through the transport, in order. */
async function lndRest(plan: AdapterLabPlan, log: string[]): Promise<LndRest> {
  const { openLndRest } = await loadLndRest();
  const rest = await openLndRest({ host: plan.lnd.host, port: plan.lnd.port, tlsCertPath: plan.lnd.tlsCert, macaroonPath: plan.lnd.credential });
  return {
    call: (method, path, body) => { log.push(`${method} ${path.split('?')[0] ?? ''}`); return rest.call(method, path, body); },
    stream: (method, path, body, onMessage, signal) => { log.push(`${method} ${path.split('?')[0] ?? ''}`); return rest.stream(method, path, body, onMessage, signal); },
  };
}

async function clnRest(plan: AdapterLabPlan, log: string[]): Promise<ClnRest> {
  const { openClnRest } = await loadClnRest();
  const rest = await openClnRest({ host: plan.cln.host, port: plan.cln.port, tlsCertPath: plan.cln.tlsCert, runePath: plan.cln.credential });
  return { call: (method, params) => { log.push(method); return rest.call(method, params); } };
}

// These references need the owned regtest lab. The lab config selects this file only when a validation plan is
// supplied (decision D53); every missing plan input then fails closed.
it('CP-013/R1 both lab implementations report the full capability set and the observed version', async () => {
  const plan = adapterLabPlan();
  const [{ REQUIRED_CAPABILITIES }, { probeLnd }, { probeCln }] = await Promise.all([loadCapabilities(), loadLndProbe(), loadClnProbe()]);
  const lndContext = context(plan.lnd.pubkey);
  const lnd = await probeLnd(await lndRest(plan, []), lndContext);
  for (const capability of REQUIRED_CAPABILITIES.lnd) expect(lnd.capabilities.has(capability), `lnd ${capability}`).toBe(true);
  expect(lnd.identity.version).toBe(lncli(plan, ['getinfo'])['version']);
  expect(lndContext.updates).toHaveLength(1);
  expect(lndContext.updates[0]).toMatchObject({ state: 'ONLINE', observedVersion: lnd.identity.version, observedNetwork: 'regtest' });
  const clnContext = context(plan.cln.pubkey);
  const cln = await probeCln(await clnRest(plan, []), clnContext);
  for (const capability of REQUIRED_CAPABILITIES.cln) expect(cln.capabilities.has(capability), `cln ${capability}`).toBe(true);
  expect(cln.identity.version).toBe(lightningCli(plan, ['getinfo'])['version']);
  expect(clnContext.updates[0]).toMatchObject({ state: 'ONLINE', observedVersion: cln.identity.version, observedNetwork: 'regtest' });
});

it('CP-013/R2 a node configured with the wrong pubkey aborts with zero further calls', async () => {
  const plan = adapterLabPlan();
  const [{ IdentityRefusal }, { probeLnd }, { probeCln }] = await Promise.all([loadCapabilities(), loadLndProbe(), loadClnProbe()]);
  // Each node's expected key is the other node's real key: a valid key of the wrong node.
  const lndLog: string[] = [];
  const lndContext = context(plan.cln.pubkey);
  const lndError = await rejection(probeLnd(await lndRest(plan, lndLog), lndContext));
  expect(lndError).toBeInstanceOf(IdentityRefusal);
  expect((lndError as InstanceType<typeof IdentityRefusal>).exitCode).toBe(5);
  expect((lndError as InstanceType<typeof IdentityRefusal>).step).toBe('identity');
  expect(lndLog).toEqual(['GET /v1/getinfo']);
  expect(lndContext.updates.map(update => update.state)).toEqual(['QUARANTINED']);
  const clnLog: string[] = [];
  const clnContext = context(plan.lnd.pubkey);
  const clnError = await rejection(probeCln(await clnRest(plan, clnLog), clnContext));
  expect(clnError).toBeInstanceOf(IdentityRefusal);
  expect((clnError as InstanceType<typeof IdentityRefusal>).exitCode).toBe(5);
  expect(clnLog).toEqual(['getinfo']);
  expect(clnContext.updates.map(update => update.state)).toEqual(['QUARANTINED']);
});

it('CP-013/Rleak independent nonempty sentinels are absent from product files scratch and retained output', async () => {
  await expectNoSentinelLeak();
});
