import { randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import {
  loadCapabilities, loadClnProbe, loadClnRest, loadErrors, loadLndProbe, loadLndRest, rejection,
  type NetworkType, type NodeCapability, type NodeProbeUpdate, type ProbeContext,
} from '../helpers/adapter-interfaces.js';
import { certificatePath, type FakeServer } from '../fakes/https.js';
import { startFakeLnd, type FakeLnd, type LndRoute } from '../fakes/lnd/fake-lnd.js';
import { getInfo, LND_PUBKEY } from '../fakes/lnd/responses.js';
import { startFakeCln, type ClnHandler, type FakeCln } from '../fakes/cln/fake-cln.js';
import { CLN_PUBKEY, getinfo } from '../fakes/cln/responses.js';

const scratch = mkdtempSync(join(tmpdir(), 'fw-probe-'));
const macaroon = randomBytes(64);
const macaroonPath = join(scratch, 'test.macaroon');
writeFileSync(macaroonPath, macaroon);
const rune = randomBytes(48).toString('base64url');
const runePath = join(scratch, 'test.rune');
writeFileSync(runePath, rune);
const NOW = 1760000000000;

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

/** GetMissionControlConfigResponse, lnrpc/routerrpc/router.proto#L535-L540 at v0.21.4-beta. */
const missionControl = { config: { half_life_seconds: '3600', hop_probability: 0.6, weight: 0.5, maximum_payment_results: 1000, minimum_failure_relax_interval: '60', model: 'APRIORI', apriori: null, bimodal: null } };

function context(expectedPubkey: string, expectedNetwork: NetworkType = 'regtest', mutating = true): ProbeContext & { updates: NodeProbeUpdate[] } {
  const updates: NodeProbeUpdate[] = [];
  return { nodeId: 'node-1', expectedPubkey, expectedNetwork, mutating, nowMs: () => NOW, updates, store: { recordProbe: (update: NodeProbeUpdate) => { updates.push(update); return Promise.resolve(); } } };
}

async function lnd(info: Record<string, unknown>, router: LndRoute = (ctx, fake) => { fake.answer(ctx, 'router-mccfg', missionControl); }): Promise<FakeLnd> {
  const fake = await startFakeLnd({
    macaroonHex: macaroon.toString('hex'),
    routes: { 'GET /v1/getinfo': (ctx, f) => { f.answer(ctx, 'getinfo', info); }, 'GET /v2/router/mccfg': router },
  });
  open.push(fake);
  return fake;
}

async function cln(info: Record<string, unknown>, askrene: ClnHandler = (ctx, f) => { f.result(ctx, 'askrene-listlayers', { layers: [] }); }): Promise<FakeCln> {
  const fake = await startFakeCln({ rune, methods: { getinfo: (ctx, f) => { f.result(ctx, 'getinfo', info); }, 'askrene-listlayers': askrene } });
  open.push(fake);
  return fake;
}

async function probeLnd(fake: FakeLnd, probe: ProbeContext) {
  const [{ openLndRest }, { probeLnd: run }] = await Promise.all([loadLndRest(), loadLndProbe()]);
  return run(await openLndRest({ host: fake.host, port: fake.port, tlsCertPath: certificatePath('node'), macaroonPath, timeoutMs: 5000 }), probe);
}

async function probeCln(fake: FakeCln, probe: ProbeContext) {
  const [{ openClnRest }, { probeCln: run }] = await Promise.all([loadClnRest(), loadClnProbe()]);
  return run(await openClnRest({ host: fake.host, port: fake.port, tlsCertPath: certificatePath('node'), runePath, timeoutMs: 5000 }), probe);
}

const paths = (fake: FakeServer): string[] => fake.requests.map(request => request.url.split('?')[0] ?? '');

it('CP-013/B1 a pubkey mismatch exits 5 at step identity after the identity call alone and quarantines the node', async () => {
  const { IdentityRefusal } = await loadCapabilities();
  for (const mutating of [true, false]) {
    const lndFake = await lnd(getInfo({ pubkey: '03' + 'f6'.repeat(32) }));
    const lndContext = context(LND_PUBKEY, 'regtest', mutating);
    const lndError = await rejection(probeLnd(lndFake, lndContext));
    expect(lndError).toBeInstanceOf(IdentityRefusal);
    expect((lndError as InstanceType<typeof IdentityRefusal>).exitCode).toBe(5);
    expect((lndError as InstanceType<typeof IdentityRefusal>).step).toBe('identity');
    expect(paths(lndFake)).toEqual(['/v1/getinfo']);
    expect(lndContext.updates).toHaveLength(1);
    expect(lndContext.updates[0]).toMatchObject({ nodeId: 'node-1', state: 'QUARANTINED', capabilities: [], probedAtMs: NOW });
  }
  // Identity is checked first: a wrong node is quarantined even when its network is unsupported.
  for (const [network, mutating] of [['simnet', true], ['liquid-regtest', false], ['', false]] as const) {
    const wrongContext = context(LND_PUBKEY, 'regtest', mutating);
    const wrong = await rejection(probeLnd(await lnd(getInfo({ pubkey: '03' + 'f6'.repeat(32), network })), wrongContext));
    expect(wrong, JSON.stringify(network)).toBeInstanceOf(IdentityRefusal);
    expect((wrong as InstanceType<typeof IdentityRefusal>).exitCode).toBe(5);
    expect((wrong as InstanceType<typeof IdentityRefusal>).step).toBe('identity');
    expect(wrongContext.updates.map(update => update.state)).toEqual(['QUARANTINED']);
    const wrongClnContext = context(CLN_PUBKEY, 'regtest', mutating);
    const wrongCln = await rejection(probeCln(await cln(getinfo({ id: '02' + 'f7'.repeat(32), network: network === 'simnet' ? 'liquid' : network })), wrongClnContext));
    expect((wrongCln as InstanceType<typeof IdentityRefusal>).step).toBe('identity');
    expect(wrongClnContext.updates.map(update => update.state)).toEqual(['QUARANTINED']);
  }
  const clnFake = await cln(getinfo({ id: '02' + 'f7'.repeat(32) }));
  const clnContext = context(CLN_PUBKEY);
  const clnError = await rejection(probeCln(clnFake, clnContext));
  expect(clnError).toBeInstanceOf(IdentityRefusal);
  expect((clnError as InstanceType<typeof IdentityRefusal>).exitCode).toBe(5);
  expect((clnError as InstanceType<typeof IdentityRefusal>).step).toBe('identity');
  expect(paths(clnFake)).toEqual(['/v1/getinfo']);
  expect(clnContext.updates).toHaveLength(1);
  expect(clnContext.updates[0]).toMatchObject({ state: 'QUARANTINED', capabilities: [] });
});

// Network strings per lnd NormalizeNetwork (rpcserver.go#L3419) and CLN bitcoin/chainparams.c.
const supported: { lnd: string; cln: string; normal: NetworkType }[] = [
  { lnd: 'mainnet', cln: 'bitcoin', normal: 'mainnet' }, { lnd: 'testnet', cln: 'testnet', normal: 'testnet' },
  { lnd: 'testnet4', cln: 'testnet4', normal: 'testnet4' }, { lnd: 'signet', cln: 'signet', normal: 'signet' },
];
const unsupported = ['simnet', 'liquid', 'liquid-regtest', 'REGTEST', 'Regtest', 'regtest ', '', 'regtest2'];
// Strings of the other implementation are unsupported too: LND never reports "bitcoin", CLN never "mainnet".
const unsupportedLnd = [...unsupported, 'bitcoin'];
const unsupportedCln = [...unsupported, 'mainnet'];

it('CP-013/B2 a mutating command off regtest stops at network-lock while a mismatch quarantines and a read on an unsupported network exits 3', async () => {
  const { IdentityRefusal, CapabilityUnsupported } = await loadCapabilities();
  for (const { lnd: lndName, cln: clnName, normal } of supported) {
    // Configured and observed agree: a read command may proceed, a mutating command stops at network-lock.
    const lndRead = await probeLnd(await lnd(getInfo({ network: lndName })), context(LND_PUBKEY, normal, false));
    expect(lndRead.identity.pubkey, lndName).toBe(LND_PUBKEY);
    const clnRead = await probeCln(await cln(getinfo({ network: clnName })), context(CLN_PUBKEY, normal, false));
    expect(clnRead.identity.pubkey, clnName).toBe(CLN_PUBKEY);
    const lndFake = await lnd(getInfo({ network: lndName }));
    const clnFake = await cln(getinfo({ network: clnName }));
    const locked = [
      [lndFake, await rejection(probeLnd(lndFake, context(LND_PUBKEY, normal, true)))],
      [clnFake, await rejection(probeCln(clnFake, context(CLN_PUBKEY, normal, true)))],
    ] as const;
    for (const [fake, error] of locked) {
      expect(error, `${normal} mutating`).toBeInstanceOf(IdentityRefusal);
      expect((error as InstanceType<typeof IdentityRefusal>).exitCode).toBe(5);
      expect((error as InstanceType<typeof IdentityRefusal>).step).toBe('network-lock');
      expect(paths(fake), normal).toEqual(['/v1/getinfo']);
    }
    // Configured regtest but the node reports another network: an identity mismatch, quarantined.
    const mismatchContext = context(LND_PUBKEY, 'regtest', false);
    const mismatchFake = await lnd(getInfo({ network: lndName }));
    const mismatch = await rejection(probeLnd(mismatchFake, mismatchContext));
    expect(mismatch, `lnd ${lndName} against regtest`).toBeInstanceOf(IdentityRefusal);
    expect((mismatch as InstanceType<typeof IdentityRefusal>).exitCode).toBe(5);
    expect((mismatch as InstanceType<typeof IdentityRefusal>).step).toBe('identity');
    expect(mismatchContext.updates.map(update => update.state)).toEqual(['QUARANTINED']);
    expect(paths(mismatchFake)).toEqual(['/v1/getinfo']);
  }
  // A mutating command on any network other than regtest stops at network-lock, supported or not (INV-15).
  for (const [label, names] of [['lnd', unsupportedLnd], ['cln', unsupportedCln]] as const) {
    for (const network of names) {
      const fake = label === 'lnd' ? await lnd(getInfo({ network })) : await cln(getinfo({ network }));
      const probe = (mutating: boolean): Promise<unknown> => label === 'lnd'
        ? probeLnd(fake as FakeLnd, context(LND_PUBKEY, 'regtest', mutating))
        : probeCln(fake as FakeCln, context(CLN_PUBKEY, 'regtest', mutating));
      const locked = await rejection(probe(true));
      expect(locked, `${label} ${JSON.stringify(network)} mutating`).toBeInstanceOf(IdentityRefusal);
      expect((locked as InstanceType<typeof IdentityRefusal>).exitCode).toBe(5);
      expect((locked as InstanceType<typeof IdentityRefusal>).step).toBe('network-lock');
      // A read command on an unsupported network is CAPABILITY_UNSUPPORTED (SPEC 4.7).
      const read = await rejection(probe(false));
      expect(read, `${label} ${JSON.stringify(network)} read`).toBeInstanceOf(CapabilityUnsupported);
      expect((read as InstanceType<typeof CapabilityUnsupported>).exitCode).toBe(3);
      expect(paths(fake), `${label} ${JSON.stringify(network)}`).toEqual(['/v1/getinfo', '/v1/getinfo']);
    }
  }
  // No chains entry means no network was reported.
  expect(await rejection(probeLnd(await lnd({ ...getInfo(), chains: [] }), context(LND_PUBKEY, 'regtest', false)))).toBeInstanceOf(CapabilityUnsupported);
  const noChains = await rejection(probeLnd(await lnd({ ...getInfo(), chains: [] }), context(LND_PUBKEY, 'regtest', true)));
  expect((noChains as InstanceType<typeof IdentityRefusal>).step).toBe('network-lock');
}, 120_000);

it('CP-013/B3 an LND 0.20 profile lacks explicit route control and a command needing it exits 3 naming it', async () => {
  const { CapabilityUnsupported, REQUIRED_CAPABILITIES, requireCapabilities } = await loadCapabilities();
  const current = await probeLnd(await lnd(getInfo()), context(LND_PUBKEY));
  for (const capability of REQUIRED_CAPABILITIES.lnd) expect(current.capabilities.has(capability), capability).toBe(true);
  expect(() => { requireCapabilities(current.capabilities, REQUIRED_CAPABILITIES.lnd); }).not.toThrow();
  // 0.20 still has the router service; only the version separates it (outgoing_chan_ids and the
  // SendToRouteV2 payment_addr requirement start in 0.21, release-notes-0.21.0.md).
  const older = await probeLnd(await lnd(getInfo({ version: '0.20.1-beta commit=v0.20.1-beta' })), context(LND_PUBKEY));
  expect(older.capabilities.has('EXPLICIT_ROUTE_CONTROL')).toBe(false);
  expect(older.capabilities.has('CHANNEL_READ')).toBe(true);
  const needed: NodeCapability[] = ['CHANNEL_READ', 'EXPLICIT_ROUTE_CONTROL'];
  let refusal: unknown;
  try { requireCapabilities(older.capabilities, needed); } catch (error) { refusal = error; }
  expect(refusal).toBeInstanceOf(CapabilityUnsupported);
  const unsupported = refusal as InstanceType<typeof CapabilityUnsupported>;
  expect(unsupported.exitCode).toBe(3);
  expect(unsupported.code).toBe('CAPABILITY_UNSUPPORTED');
  expect(unsupported.missing).toEqual(['EXPLICIT_ROUTE_CONTROL']);
  expect(unsupported.message).toContain('EXPLICIT_ROUTE_CONTROL');
  for (const version of ['custom-build', '0.21-beta', 'v0.21.4-beta commit=v0.21.4-beta', '']) {
    expect(await rejection(probeLnd(await lnd(getInfo({ version })), context(LND_PUBKEY))), JSON.stringify(version)).toBeInstanceOf(CapabilityUnsupported);
  }
});

it('CP-013/B4 a CLN 26.04 profile lacks askrene layer routing and 26.06 has it', async () => {
  const { CapabilityUnsupported, REQUIRED_CAPABILITIES } = await loadCapabilities();
  for (const version of ['v26.06.9', 'v26.06.9-modded', 'v26.06.9-14-gab12cd3']) {
    const current = await probeCln(await cln(getinfo({ version })), context(CLN_PUBKEY));
    for (const capability of REQUIRED_CAPABILITIES.cln) expect(current.capabilities.has(capability), `${version} ${capability}`).toBe(true);
  }
  // 26.04 has askrene but its getroutes hop fields mean the hop start (CHANGELOG [26.06] #9110).
  const older = await probeCln(await cln(getinfo({ version: 'v26.04.1' })), context(CLN_PUBKEY));
  expect(older.capabilities.has('ASKRENE_LAYER_ROUTING')).toBe(false);
  const noAskrene = await probeCln(await cln(getinfo(), (ctx, f) => { f.rpcError(ctx, 'unknown-command', -32601, "Unknown command 'askrene-listlayers'"); }), context(CLN_PUBKEY));
  expect(noAskrene.capabilities.has('ASKRENE_LAYER_ROUTING')).toBe(false);
  expect(await rejection(probeCln(await cln(getinfo({ version: 'ab12cd3-modded' })), context(CLN_PUBKEY)))).toBeInstanceOf(CapabilityUnsupported);
  // A proxy 502 without a lightningd code says nothing about askrene; the probe fails instead of recording ONLINE.
  // Only lightningd's own -32601 means the command is absent; a 404 without a code is a proxy or a wrong path.
  for (const [status, body] of [[502, '<html>Bad Gateway</html>'], [404, JSON.stringify({ message: 'Not Found' })]] as const) {
    const proxyContext = context(CLN_PUBKEY);
    const proxied = await rejection(probeCln(await cln(getinfo(), (ctx, f) => { f.raw(ctx, 'proxy-status', status, body); }), proxyContext));
    expect(proxied, String(status)).toBeInstanceOf(Error);
    expect(proxied, String(status)).not.toBeInstanceOf(CapabilityUnsupported);
    expect(proxyContext.updates.filter(update => update.state === 'ONLINE'), String(status)).toEqual([]);
  }
});

it('CP-013/B5 a gRPC 5 or 12 from a missing router service is a capability gap not a NotFound', async () => {
  const errors = await loadErrors();
  const { REQUIRED_CAPABILITIES, requireCapabilities, CapabilityUnsupported } = await loadCapabilities();
  const answers: LndRoute[] = [
    // A route the gateway never registered answers 404 with gRPC 5 "Not Found".
    (ctx, fake) => { fake.grpcError(ctx, 'route-not-found', 5, 'Not Found'); },
    (ctx, fake) => { fake.grpcError(ctx, 'grpc-error', 12, 'unknown service routerrpc.Router'); },
  ];
  for (const [index, answer] of answers.entries()) {
    const fake = await lnd(getInfo(), answer);
    let outcome: unknown;
    try { outcome = await probeLnd(fake, context(LND_PUBKEY)); } catch (error) { outcome = error; }
    expect(outcome, String(index)).not.toBeInstanceOf(errors.LndError);
    expect(outcome, String(index)).not.toBeInstanceOf(Error);
    const result = outcome as { capabilities: ReadonlySet<NodeCapability> };
    expect(result.capabilities.has('EXPLICIT_ROUTE_CONTROL')).toBe(false);
    expect(result.capabilities.has('PAYMENT_TRACK')).toBe(false);
    expect(paths(fake)).toEqual(['/v1/getinfo', '/v2/router/mccfg']);
    let refusal: unknown;
    try { requireCapabilities(result.capabilities, REQUIRED_CAPABILITIES.lnd); } catch (error) { refusal = error; }
    expect(refusal).toBeInstanceOf(CapabilityUnsupported);
  }
});

it('CP-013/B5 a 502 or 504 relaying gRPC 5 on the router call fails the probe instead of removing capabilities', async () => {
  const { CapabilityUnsupported } = await loadCapabilities();
  for (const status of [502, 504]) {
    const relayed = JSON.stringify({ code: 5, message: 'Not Found', details: [] });
    const probeContext = context(LND_PUBKEY, 'regtest', false);
    const outcome = await rejection(probeLnd(await lnd(getInfo(), (ctx, fake) => { fake.raw(ctx, 'proxy-status', status, relayed); }), probeContext));
    expect(outcome, String(status)).toBeInstanceOf(Error);
    expect(outcome, String(status)).not.toBeInstanceOf(CapabilityUnsupported);
    expect(probeContext.updates.filter(update => update.state === 'ONLINE'), String(status)).toEqual([]);
  }
});

it('CP-013/B6 probe results are recorded with the observed version network capabilities and time', async () => {
  const lndContext = context(LND_PUBKEY);
  const lndFake = await lnd(getInfo({ synced: false }));
  const lndResult = await probeLnd(lndFake, lndContext);
  expect(paths(lndFake)).toEqual(['/v1/getinfo', '/v2/router/mccfg']);
  expect(lndResult.identity).toEqual({ pubkey: LND_PUBKEY, network: 'regtest', version: '0.21.4-beta commit=v0.21.4-beta', blockHeight: 812, syncedToChain: false });
  expect(lndContext.updates).toEqual([{
    nodeId: 'node-1', state: 'ONLINE', observedVersion: '0.21.4-beta commit=v0.21.4-beta', observedNetwork: 'regtest',
    capabilities: [...lndResult.capabilities].sort(), probedAtMs: NOW,
  }]);
  expect(lndContext.updates[0]?.capabilities).toContain('EXPLICIT_ROUTE_CONTROL');

  const clnContext = context(CLN_PUBKEY);
  const clnFake = await cln(getinfo({ version: 'v26.06.9-modded', blockheight: 900 }));
  const clnResult = await probeCln(clnFake, clnContext);
  expect(paths(clnFake)).toEqual(['/v1/getinfo', '/v1/askrene-listlayers']);
  expect(clnResult.identity).toEqual({ pubkey: CLN_PUBKEY, network: 'regtest', version: 'v26.06.9-modded', blockHeight: 900, syncedToChain: true });
  expect(clnContext.updates).toEqual([{
    nodeId: 'node-1', state: 'ONLINE', observedVersion: 'v26.06.9-modded', observedNetwork: 'regtest',
    capabilities: [...clnResult.capabilities].sort(), probedAtMs: NOW,
  }]);
  expect(clnContext.updates[0]?.capabilities).toContain('ASKRENE_LAYER_ROUTING');
});

it('CP-013/B4 an askrene answer of -32601 relayed by a 502 or 504 proxy is a transport failure, not askrene absence', async () => {
  const errors = await loadErrors();
  const { CapabilityUnsupported } = await loadCapabilities();
  for (const status of [502, 504]) {
    const probeContext = context(CLN_PUBKEY);
    const relayed = JSON.stringify({ code: -32601, message: "Unknown command 'askrene-listlayers'", data: null });
    const outcome = await rejection(probeCln(await cln(getinfo(), (ctx, f) => { f.raw(ctx, 'proxy-status', status, relayed); }), probeContext));
    expect(outcome, String(status)).toBeInstanceOf(errors.TransportError);
    expect(outcome, String(status)).not.toBeInstanceOf(CapabilityUnsupported);
    expect(probeContext.updates.filter(update => update.state === 'ONLINE'), String(status)).toEqual([]);
  }
});

it('CP-013/B1 a wrong node with malformed chains is still quarantined at step identity', async () => {
  const { IdentityRefusal } = await loadCapabilities();
  for (const chains of [
    [{ chain: 'bitcoin', network: 'regtest' }, { chain: 'bitcoin', network: 'mainnet' }],
    [{ chain: 'litecoin', network: 'regtest' }],
  ]) {
    const probeContext = context(LND_PUBKEY, 'regtest', false);
    const fake = await lnd({ ...getInfo({ pubkey: '03' + 'f6'.repeat(32) }), chains });
    const error = await rejection(probeLnd(fake, probeContext));
    expect(error, JSON.stringify(chains)).toBeInstanceOf(IdentityRefusal);
    expect((error as InstanceType<typeof IdentityRefusal>).step).toBe('identity');
    expect(probeContext.updates.map(update => update.state)).toEqual(['QUARANTINED']);
    expect(paths(fake)).toEqual(['/v1/getinfo']);
  }
});

it('CP-013/B1 a wrong CLN node with a malformed getinfo is still quarantined and the record keeps each observed version', async () => {
  const { IdentityRefusal } = await loadCapabilities();
  const foreign = '02' + 'f7'.repeat(32);
  for (const malformed of [{ blockheight: '812' }, { network: 42 }, { alias: ['x'] }]) {
    const probeContext = context(CLN_PUBKEY, 'regtest', false);
    const fake = await cln(getinfo({ id: foreign, version: 'v26.06.9-modded', ...malformed }));
    const error = await rejection(probeCln(fake, probeContext));
    expect(error, JSON.stringify(malformed)).toBeInstanceOf(IdentityRefusal);
    expect((error as InstanceType<typeof IdentityRefusal>).step).toBe('identity');
    expect(probeContext.updates).toHaveLength(1);
    expect(probeContext.updates[0]).toMatchObject({ state: 'QUARANTINED', observedVersion: 'v26.06.9-modded' });
    expect(paths(fake)).toEqual(['/v1/getinfo']);
  }
  // The quarantine record carries what the foreign node reported, so an operator can tell which node answered.
  const lndContext = context(LND_PUBKEY, 'regtest', true);
  await rejection(probeLnd(await lnd(getInfo({ pubkey: '03' + 'f6'.repeat(32), version: '0.21.4-beta commit=v0.21.4-beta-foreign' })), lndContext));
  expect(lndContext.updates).toEqual([expect.objectContaining({ state: 'QUARANTINED', observedVersion: '0.21.4-beta commit=v0.21.4-beta-foreign' })]);
  const clnContext = context(CLN_PUBKEY, 'regtest', true);
  await rejection(probeCln(await cln(getinfo({ id: foreign, version: 'v26.04.1' })), clnContext));
  expect(clnContext.updates).toEqual([expect.objectContaining({ state: 'QUARANTINED', observedVersion: 'v26.04.1' })]);
});
