// Public createRuntimeLab/LabPort checkout, SECURITY §3.2 and SPEC §14.1.
// Pinned CLN26.06.9 a2176589f235b63bc1a37e69362dfd6c925397e9 checkrune/createrune schemas and owned CLNP checkrune
// reference: execute permits sendpay with numeric10m/100m, rejects missing/decimal-string
// amount_msat with1502. Read rune lacks sendpay. No product permission arithmetic is imported.
// https://raw.githubusercontent.com/ElementsProject/lightning/a2176589f235b63bc1a37e69362dfd6c925397e9/doc/schemas/checkrune.json
// https://raw.githubusercontent.com/ElementsProject/lightning/a2176589f235b63bc1a37e69362dfd6c925397e9/doc/schemas/createrune.json
// Recorded reference: .ratchet/evidence/D48/FINAL/20261013/clnp-auth-gold/permissions-reference.json.
import { createECDH, createHash, randomBytes } from 'node:crypto';
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer as httpServer } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';
import { testRoot } from '../helpers/env.js';
import { writeConfig, writePolicy } from '../helpers/cp016-cli.js';
import { managed } from '../helpers/cp007-toxiproxy.js';
import { syntheticInvoice, hashField } from '../helpers/cp004-invoice.js';
import { getinfo, peerChannel, channelDirection, sendpay } from '../fakes/cln/responses.js';
import { getInfo } from '../fakes/lnd/responses.js';
import { tlsCertificate } from '../helpers/tls-material.js';

interface Checkout { merchant: 'cln-m'; payer: 'lnd-p' | 'cln-p'; channels: readonly number[]; amountMsat: bigint }
interface LabPort {
  status(): Promise<{ up: boolean; network: string }>;
  channel2ReceivableMsat(): Promise<bigint>;
  checkout(request: Checkout): Promise<{ status: 'SUCCEEDED' | 'FAILED'; reason: string | null }>;
}
interface Runtime { lab: LabPort; close(): Promise<void> }
const closes: (() => Promise<void>)[] = [];
afterEach(async () => { for (const close of closes.splice(0).reverse()) await close(); });

async function fixture() {
  const root = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'workload-runtime-'));
  const sentinelId = randomBytes(8).toString('hex');
  const roots = Object.fromEntries(['runtimeRoot', 'tmpRoot', 'sentinelRoot', 'evidenceRoot'].map(name => {
    const path = join(root, name); mkdirSync(path, { mode: 0o700 }); return [name, path];
  }));
  const names = ['lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m'];
  const pubkeys: Record<string, string> = Object.fromEntries(names.map(name => {
    const key = createECDH('secp256k1'); key.generateKeys(); return [name, key.getPublicKey('hex', 'compressed')];
  }));
  const proxyState: Record<string, Record<string, unknown>> = Object.fromEntries(managed.map(proxy => [proxy.name, { ...proxy, toxics: [] }]));
  const identity = (kind: 'lnd' | 'cln') => String(proxyState[kind === 'lnd' ? 'lnd-r-rest' : 'cln-m-rest']?.['upstream']).split(':')[0] ?? '';
  const calls: { node: string; method: string; path: string }[] = [];
  const dispatches: { node: string; credentialRole: string; amountType: string; amountMsat: string | null; parameterKeys: string[] }[] = [];
  const credentialBytes = new Map<string, { read: Buffer; execute: Buffer }>();
  const hash = createHash('sha256').update(randomBytes(32)).digest('hex');
  let invoiceLabel = '';
  const secret = randomBytes(32);
  writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `${sentinelId}-workload-payment-secret.bin`), secret, { mode: 0o600 });
  const tlsInput = join(root, 'tls-input'); mkdirSync(tlsInput, { mode: 0o700 });
  const { certPath: cert, key } = tlsCertificate(tlsInput, ['localhost'], ['127.0.0.1']);
  const port = async (server: ReturnType<typeof httpServer> | ReturnType<typeof httpsServer>) => {
    await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    closes.push(() => new Promise(resolve => { server.closeAllConnections(); server.close(() => { resolve(); }); }));
    const address = server.address(); if (!address || typeof address === 'string') throw new Error('fixture port');
    return address.port;
  };
  const node = (kind: 'lnd' | 'cln') => httpsServer({ cert: readFileSync(cert), key }, (request, response) => {
    const name = identity(kind), path = request.url ?? '';
    calls.push({ node: name, method: request.method ?? '', path });
    let body = '';
    request.on('data', (chunk: Buffer) => { body += chunk.toString('utf8'); });
    request.on('end', () => {
      const params = body === '' ? {} : JSON.parse(body) as Record<string, unknown>;
      let value: unknown;
      let status = kind === 'cln' ? 201 : 200;
      if (path === '/v1/getinfo') value = kind === 'cln' ? getinfo({ id: pubkeys[name] }) : getInfo({ pubkey: pubkeys[name] });
      else if (path === '/v1/listpeerchannels') value = { channels: name === 'cln-p' ? [
        peerChannel({ peer_id: pubkeys['cln-r'], short_channel_id: '108x4x0', spendable_msat: 3500000000 }),
      ] : [
        peerChannel({ peer_id: pubkeys['lnd-r'], short_channel_id: '108x2x0', receivable_msat: 5000000 }),
        peerChannel({ peer_id: pubkeys['cln-r'], short_channel_id: '108x5x0', channel_id: '25'.repeat(32) }),
      ] };
      else if (path === '/v1/listchannels') value = { channels: [
        channelDirection({ scid: '108x5x0', source: pubkeys['cln-r'] ?? '', destination: pubkeys['cln-m'] ?? '', base: 1000, ppm: 1000, delay: 34 }),
      ] };
      else if (path === '/v1/invoice') { invoiceLabel = String(params['label']); value = {
        payment_hash: hash, payment_secret: secret.toString('hex'),
        bolt11: syntheticInvoice(hash, [...hashField(16, secret.toString('hex')), 24, 0, 1, 18]),
        expires_at: Math.floor(Date.now() / 1000) + 3600, created_index: 1,
      }; }
      else if (path === '/v1/sendpay') {
        const selected = credentialBytes.get(name);
        const incoming = request.headers['rune'];
        const role = incoming === selected?.execute.toString('utf8') ? 'execute' : incoming === selected?.read.toString('utf8') ? 'read' : 'other';
        const amount = params['amount_msat'];
        dispatches.push({ node: name, credentialRole: role, amountType: typeof amount,
          amountMsat: typeof amount === 'number' && Number.isSafeInteger(amount) ? String(amount) : null,
          parameterKeys: Object.keys(params).sort() });
        if (role !== 'execute' || typeof amount !== 'number' || !Number.isSafeInteger(amount) || amount < 1 || amount > 100000000) {
          status = 401; value = { code: 1502, message: 'Not permitted by independent bounded rune model', data: null };
        } else value = sendpay({ payment_hash: hash, status: 'pending', destination: pubkeys['cln-m'], amount_msat: 10000000, amount_sent_msat: 10011000 });
      } else if (path === '/v1/waitsendpay') {
        // Pinned waitsendpay definite forwarding failure (203), ordinary FAILED checkout.
        status = 500; value = { code: 203, message: 'Payment failed', data: { status: 'failed' } };
      } else if (path === '/v1/listinvoices') value = { invoices: [{
        label: invoiceLabel, payment_hash: hash, amount_msat: 10000000,
        status: 'unpaid', expires_at: Math.floor(Date.now() / 1000) + 3600, created_index: 1,
      }] };
      else if (path === '/v1/delinvoice') value = { label: invoiceLabel, payment_hash: hash, amount_msat: 10000000,
        status: 'unpaid', expires_at: Math.floor(Date.now() / 1000) + 3600, created_index: 1 };
      else { status = 500; value = { code: -32601, message: 'Unexpected public fixture method' }; }
      response.writeHead(status, { 'content-type': 'application/json' }); response.end(JSON.stringify(value));
    });
  });
  const lndRest = await port(node('lnd')), clnRest = await port(node('cln'));
  const toxiproxy = await port(httpServer((request, response) => {
    let body = ''; request.on('data', (chunk: Buffer) => { body += chunk.toString('utf8'); });
    request.on('end', () => {
      const name = /^\/proxies\/([^/]+)$/.exec(request.url ?? '')?.[1];
      if (name && request.method === 'POST') Object.assign(proxyState[name] ?? {}, JSON.parse(body) as object);
      response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify(name ? proxyState[name] : proxyState));
    });
  }));
  const credentials = Object.fromEntries(names.map(name => {
    const roles = { read: name.startsWith('lnd') ? randomBytes(32) : Buffer.from(randomBytes(48).toString('base64url')),
      execute: name.startsWith('lnd') ? randomBytes(32) : Buffer.from(randomBytes(48).toString('base64url')) };
    credentialBytes.set(name, roles);
    return [name, Object.fromEntries(Object.entries(roles).map(([role, bytes]) => {
      const path = join(root, `${name}-${role}-credential.bin`);
      appendFileSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'declared-out.txt'), `${path}\n`);
      writeFileSync(path, bytes, { mode: 0o600 });
      writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `${sentinelId}-${name}-${role}-credential.bin`), bytes, { mode: 0o600 });
      return [role, path];
    }))];
  }));
  const id = `workload-${randomBytes(5).toString('hex')}`;
  const owner = { version: 1, id, project: `fluxwarden-lab-${id}`, ...roots, ports: { lndRest, clnRest, toxiproxy },
    resources: { cpus: 4, memoryBytes: 4294967296, pids: 1024 },
    credentialPolicy: { maxPrincipalMsat: '100000000', callsPerMinute: '600' } };
  const fingerprint = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex');
  const entries = names.map(name => ({ name, implementation: name.startsWith('lnd') ? 'lnd' as const : 'cln' as const,
    url: `https://localhost:${String(name.startsWith('lnd') ? lndRest : clnRest)}`, tlsCert: cert,
    credential: credentials[name]?.['execute'] ?? '', expectedPubkey: pubkeys[name] ?? '' }));
  const manifest = { version: 1, ownerId: id, project: owner.project, ports: owner.ports,
    nodes: Object.fromEntries(entries.map(entry => [entry.name, { kind: entry.implementation, network: 'regtest',
      version: entry.implementation === 'lnd' ? '0.21.4-beta' : 'v26.06.9', pubkey: entry.expectedPubkey,
      certificate: { path: cert, fingerprint: fingerprint(cert), sha256: fingerprint(cert) } }])),
    credentials: Object.fromEntries(entries.map(entry => [entry.name, Object.fromEntries(['read', 'execute'].map(role =>
      [role, { path: credentials[entry.name]?.[role], fingerprint: fingerprint(credentials[entry.name]?.[role] ?? ''), sha256: fingerprint(credentials[entry.name]?.[role] ?? '') }]))])),
  };
  writeFileSync(join(roots['runtimeRoot'] ?? '', 'lab.json'), JSON.stringify(manifest), { mode: 0o600 });
  const planPath = join(root, 'owner.json'); writeFileSync(planPath, JSON.stringify(owner), { mode: 0o600 });
  const policy = writePolicy(root, { 'cln-m': { '108x2x0': { minInbound: '100000000' }, '108x5x0': { minInbound: '0' } } });
  const configPath = writeConfig(root, { database: join(root, 'state.sqlite'), policy, nodes: entries });
  const m = await import(pathToFileURL(join(repoRoot, 'labs/docker/demo/runtime.mjs')).href) as {
    createRuntimeLab(options: { planPath: string; configPath: string; signal: AbortSignal }): Promise<Runtime>;
  };
  const runtime = await m.createRuntimeLab({ planPath, configPath, signal: new AbortController().signal });
  closes.push(() => runtime.close());
  return { runtime, calls, dispatches };
}

it('CP-043/B1 CLN-P checkout uses its execute rune and a numeric principal that the pinned amount restriction authorizes', async () => {
  const f = await fixture();
  expect(await f.runtime.lab.status()).toEqual({ up: true, network: 'regtest' });
  const observed = await f.runtime.lab.checkout({ merchant: 'cln-m', payer: 'cln-p', channels: [4, 5], amountMsat: 10_000_000n })
    .then(value => ({ value }), (error: unknown) => {
      // This controlled fixture returns only a fixed upstream error string; credentials are not logged.
      const e = error as { name?: string; code?: number };
      return { error: { name: e.name, code: e.code } };
    });
  expect(f.calls.filter(call => call.path === '/v1/invoice')).toHaveLength(1);
  expect(f.dispatches).toHaveLength(1);
  expect(f.dispatches[0]).toMatchObject({ node: 'cln-p', credentialRole: 'execute', amountType: 'number', amountMsat: '10000000' });
  expect(f.dispatches[0]?.parameterKeys).toEqual(expect.arrayContaining(['amount_msat', 'payment_hash', 'payment_secret', 'route']));
  expect(observed).toMatchObject({ value: { status: 'FAILED' } });
  expect(f.calls.filter(call => call.path === '/v1/waitsendpay')).toHaveLength(1);
  expect(f.calls.filter(call => call.path === '/v1/delinvoice')).toHaveLength(1);
});
