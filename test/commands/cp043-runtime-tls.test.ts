/* Public createRuntimeLab preparation port: SPEC §14.1, docs/demo-transcript.md;
 * SECURITY INV-12/15 and §3.3 require the configured CA and hostname verification.
 * These are synthetic transport controls, not evidence of a live owned lab.
 */
import { createECDH, createHash, randomBytes, X509Certificate } from 'node:crypto';
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, request } from 'node:https';
import { createServer as createHttpServer } from 'node:http';
import type { Socket } from 'node:net';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';
import { testRoot } from '../helpers/env.js';
import { writeConfig, writePolicy } from '../helpers/cp016-cli.js';
import { getinfo } from '../fakes/cln/responses.js';
import { getInfo } from '../fakes/lnd/responses.js';
import { managed } from '../helpers/cp007-toxiproxy.js';
import { tlsCertificate } from '../helpers/tls-material.js';

interface Runtime {
  preparation: { identity(): Promise<{ network: string }> };
  close(): Promise<void>;
}
interface RuntimeModule {
  createRuntimeLab(input: { planPath: string; configPath: string; signal?: AbortSignal }): Promise<Runtime>;
}
const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => { for (const close of cleanups.splice(0).reverse()) await close(); });

// RFC 5280 §§4.1/4.2.1.6: independent self-signed test CA with DNS SAN only.
// Node's built-in crypto keeps this test independent of OpenSSL executables and runtime code.
function dnsCertificate(input: string, names: string[]) {
  const material = tlsCertificate(input, names);
  const parsed = new X509Certificate(material.cert);
  expect(parsed.checkIP('127.0.0.1'), 'fixture has no IP SAN').toBeUndefined();
  return material;
}

async function httpsNode(material: ReturnType<typeof dnsCertificate>, implementation: 'cln' | 'lnd', identity: () => string) {
  const calls: { method: string; path: string }[] = [], sockets = new Set<Socket>();
  const server = createServer({ cert: material.cert, key: material.key }, (incoming, response) => {
    calls.push({ method: incoming.method ?? '', path: incoming.url ?? '' });
    incoming.resume();
    if (incoming.url !== '/v1/getinfo') { response.writeHead(500); response.end('{}'); return; }
    response.writeHead(implementation === 'cln' ? 201 : 200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(implementation === 'cln' ? getinfo({ id: identity() }) : getInfo({ pubkey: identity() })));
  });
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.on('tlsClientError', () => undefined);
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('synthetic HTTPS port missing');
  cleanups.push(() => new Promise(resolve => { for (const socket of sockets) socket.destroy(); server.close(() => { resolve(); }); }));
  return { port: address.port, calls };
}

// Independent positive control proves DNS-only certificate/CA/TLS server are usable.
async function certifiedEndpoint(port: number, certPath: string) {
  await new Promise<void>((resolve, reject) => {
    const outgoing = request({ host: 'localhost', port, path: '/v1/getinfo', method: 'POST',
      ca: readFileSync(certPath), rejectUnauthorized: true, agent: false }, response => {
      response.resume(); response.on('end', () => { resolve(); });
    });
    outgoing.on('error', reject); outgoing.end('{}');
  });
}

async function fixture(mode: 'valid' | 'wrong-ca' | 'wrong-host') {
  const directory = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'demo-runtime-tls-'));
  const inputs = join(directory, 'synthetic-inputs'); mkdirSync(inputs, { mode: 0o700 });
  const servingInputs = join(inputs, 'serving'), otherInputs = join(inputs, 'other'), lndInputs = join(inputs, 'lnd');
  mkdirSync(servingInputs, { mode: 0o700 }); mkdirSync(otherInputs, { mode: 0o700 }); mkdirSync(lndInputs, { mode: 0o700 });
  const material = dnsCertificate(servingInputs, mode === 'wrong-host' ? ['node.invalid'] : ['cln', 'localhost']);
  const pinned = mode === 'wrong-ca' ? dnsCertificate(otherInputs, ['cln', 'localhost']) : material;
  const lndMaterial = tlsCertificate(lndInputs, ['localhost'], ['127.0.0.1']);
  // Public Toxiproxy 2.12 HTTP API, as scripted in cp007-toxiproxy.ts.
  const proxyState: Record<string, Record<string, unknown>> = Object.fromEntries(managed.map(value => [value.name, { ...value, toxics: [] }]));
  const nodeNames = ['lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m'];
  const pubkeys: Record<string, string> = Object.fromEntries(nodeNames.map(name => {
    const key = createECDH('secp256k1'); key.generateKeys(); return [name, key.getPublicKey('hex', 'compressed')];
  }));
  expect(new Set(Object.values(pubkeys)).size, 'each owned node has a unique identity (INV-12)').toBe(nodeNames.length);
  // Readiness switches the public proxy upstream; getinfo must identify that node.
  const upstreamIdentity = (proxyName: string): string => {
    const upstream = proxyState[proxyName]?.['upstream'];
    const name = typeof upstream === 'string' ? upstream.split(':')[0] : undefined;
    const pubkey = name === undefined ? undefined : pubkeys[name];
    if (!pubkey) throw new Error('synthetic proxy has no declared node identity');
    return pubkey;
  };
  const cln = await httpsNode(material, 'cln', () => upstreamIdentity('cln-m-rest'));
  const lnd = await httpsNode(lndMaterial, 'lnd', () => upstreamIdentity('lnd-r-rest'));
  const proxy = createHttpServer((incoming, response) => {
    let body = '';
    incoming.on('data', (chunk: Buffer) => { body += chunk.toString('utf8'); });
    incoming.on('end', () => {
      const name = /^\/proxies\/([^/]+)$/.exec(incoming.url ?? '')?.[1];
      let value: unknown = proxyState;
      if (name) {
        const existing = proxyState[name];
        if (!existing) { response.writeHead(404); response.end('{}'); return; }
        if (incoming.method === 'POST') Object.assign(existing, JSON.parse(body) as object);
        value = existing;
      } else if (incoming.url !== '/proxies' || incoming.method !== 'GET') {
        response.writeHead(404); response.end('{}'); return;
      }
      response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify(value));
    });
  });
  await new Promise<void>((resolve, reject) => { proxy.once('error', reject); proxy.listen(0, '127.0.0.1', resolve); });
  const proxyAddress = proxy.address();
  if (!proxyAddress || typeof proxyAddress === 'string') throw new Error('synthetic proxy port missing');
  cleanups.push(() => new Promise(resolve => { proxy.closeAllConnections(); proxy.close(() => { resolve(); }); }));
  const roots = Object.fromEntries(['runtimeRoot', 'tmpRoot', 'sentinelRoot', 'evidenceRoot'].map(name => {
    const path = join(directory, name); mkdirSync(path, { mode: 0o700 }); return [name, path];
  }));
  const id = `tls-${randomBytes(6).toString('hex')}`;
  const selected = {
    version: 1, id, project: `fluxwarden-lab-${id}`, ...roots,
    ports: { lndRest: lnd.port, clnRest: cln.port, toxiproxy: proxyAddress.port },
    resources: { cpus: 4, memoryBytes: 4294967296, pids: 1024 },
    credentialPolicy: { maxPrincipalMsat: '100000000', callsPerMinute: '600', lndRootKeyIds: {
      'lnd-p': { read: '41001', execute: '41002' }, 'lnd-r': { read: '41001', execute: '41002' },
    } },
  };
  const fingerprint = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex');
  const runePath = join(inputs, 'credential-input.rune'), macaroonPath = join(inputs, 'credential-input.macaroon');
  const rune = randomBytes(48).toString('base64url'), macaroon = randomBytes(32);
  appendFileSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'declared-out.txt'), `${runePath}\n${macaroonPath}\n`);
  writeFileSync(runePath, rune, { mode: 0o600 }); writeFileSync(macaroonPath, macaroon, { mode: 0o600 });
  writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `${id}-rune.bin`), rune, { mode: 0o600 });
  writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `${id}-macaroon.bin`), macaroon, { mode: 0o600 });
  const entries = nodeNames.map(name => ({ name, implementation: name.startsWith('lnd-') ? 'lnd' as const : 'cln' as const,
    url: `https://localhost:${String(name.startsWith('lnd-') ? lnd.port : cln.port)}`, tlsCert: name.startsWith('lnd-') ? lndMaterial.certPath : pinned.certPath,
    credential: name.startsWith('lnd-') ? macaroonPath : runePath, expectedPubkey: pubkeys[name] ?? '' }));
  const manifest = {
    version: 1, ownerId: id, project: selected.project, ports: selected.ports,
    nodes: Object.fromEntries(entries.map(node => [node.name, { implementation: node.implementation, kind: node.implementation,
      network: 'regtest', version: node.implementation === 'cln' ? 'v26.06.9' : '0.21.4-beta', pubkey: node.expectedPubkey,
      certificate: { path: node.tlsCert, fingerprint: fingerprint(node.tlsCert), sha256: fingerprint(node.tlsCert) } }])),
    credentials: Object.fromEntries(entries.map(node => [node.name, Object.fromEntries(['read', 'execute'].map(role =>
      [role, { path: node.credential, fingerprint: fingerprint(node.credential), sha256: fingerprint(node.credential) }]))])),
  };
  const runtimeRoot = roots['runtimeRoot']; if (!runtimeRoot) throw new Error('synthetic runtime root missing');
  writeFileSync(join(runtimeRoot, 'lab.json'), JSON.stringify(manifest), { mode: 0o600 });
  const planPath = join(directory, 'owner.json'); writeFileSync(planPath, JSON.stringify(selected), { mode: 0o600 });
  const policy = writePolicy(directory, { 'cln-m': { '812x1x0': { minInbound: '100000000' }, '812x2x0': { minInbound: '0' } } });
  const configPath = writeConfig(directory, { database: join(directory, 'state.sqlite'), policy, nodes: entries });
  return { planPath, configPath, material, cln, lnd };
}

async function runtime(input: { planPath: string; configPath: string }) {
  const module = await import(pathToFileURL(join(repoRoot, 'labs/docker/demo/runtime.mjs')).href) as RuntimeModule;
  const lab = await module.createRuntimeLab({ ...input, signal: new AbortController().signal });
  cleanups.push(() => lab.close());
  return lab;
}

it('CP-043/B3 runtime identity uses the certified configured localhost endpoint with a DNS-only CLN certificate', async () => {
  const f = await fixture('valid');
  await certifiedEndpoint(f.cln.port, f.material.certPath);
  expect(f.cln.calls).toEqual([{ method: 'POST', path: '/v1/getinfo' }]);
  f.cln.calls.length = 0;
  const lab = await runtime(f);
  const identity = await lab.preparation.identity().then(value => ({ value }), (error: unknown) => {
    const failure = error as { name: string; phase: string; cause?: { code?: unknown } };
    return { error: { name: failure.name, phase: failure.phase,
      tlsCode: typeof failure.cause?.code === 'string' ? failure.cause.code : undefined } };
  });
  expect(identity).toEqual({ value: { network: 'regtest' } });
  expect(f.cln.calls.length).toBeGreaterThan(0);
  expect(f.cln.calls.every(call => call.method === 'POST' && call.path === '/v1/getinfo')).toBe(true);
  expect(f.lnd.calls.every(call => call.method === 'GET' && call.path === '/v1/getinfo')).toBe(true);
});

for (const mode of ['wrong-ca', 'wrong-host'] as const) {
  it(`CP-043/B3 runtime identity refuses ${mode} before any CLN RPC or money movement`, async () => {
    const f = await fixture(mode), lab = await runtime(f);
    await expect(lab.preparation.identity()).rejects.toMatchObject({ name: 'TlsError', phase: 'connect', notDelivered: true });
    expect(f.cln.calls).toEqual([]);
    expect(f.lnd.calls.filter(call => call.method !== 'GET' || call.path !== '/v1/getinfo')).toEqual([]);
  });
}
