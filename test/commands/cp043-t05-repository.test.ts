/* Public RuntimeLab + actual SQLite repository regression, SPEC §14.1 / T-05,
 * §6.5 and §8.4; SECURITY INV-02/04/05/19. No execution repository is mocked.
 * CLN answers come from the existing rebalance-node fixture (pinned schemas cited there).
 * The local transport models Toxiproxy 2.12 HTTP controls and RFC 9112 §9.6:
 * limit_data closes after its byte allowance, and reset_peer resets the connection.
 * Source: https://github.com/Shopify/toxiproxy/blob/v2.12.0/toxics/limit_data.go#L13-L47
 */
import { createHash, createPrivateKey, randomBytes, sign } from 'node:crypto';
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer as httpServer } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { connect, createServer as tcpServer, type Socket } from 'node:net';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, beforeAll, expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';
import { testRoot } from '../helpers/env.js';
import { approvalMessage, approve, demo, documentOf, plan, prepareDemoFixtures, resultOf, rows, storedId, verifiesWith, type Demo, type DemoFixtures } from '../helpers/cpw-cli.js';
import { dbNow, ulid } from '../helpers/cp028-executor.js';
import { managed } from '../helpers/cp007-toxiproxy.js';
import type { FakeServer } from '../fakes/https.js';
import { tlsCertificate } from '../helpers/tls-material.js';
import { callsOf, SELF, S, T } from '../fakes/cln/rebalance-node.js';

interface Observation { exit: number; status: string; paymentHash: string; sendCount: number }
interface Runtime {
  lab: { scenario(caseId: string): Promise<Observation> };
  faults: { apply(caseId: string): Promise<void>; clear(caseId: string): Promise<void> };
  close(): Promise<void>;
}
const nodes: FakeServer[] = [], closes: (() => Promise<void>)[] = [];
let fixtures: DemoFixtures;
beforeAll(async () => {
  fixtures = await prepareDemoFixtures();
  appendFileSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'declared-out.txt'), `${fixtures.key.keyFile}\n`);
  writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), 't05-fixture-approval-key.pem'), readFileSync(fixtures.key.keyFile), { mode: 0o600 });
});
afterEach(async () => {
  for (const close of closes.splice(0).reverse()) await close();
  await Promise.all(nodes.splice(0).map(node => node.close()));
});

async function tlsDemo() {
  const inputs = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 't05-tls-input-'));
  const tls = tlsCertificate(inputs, ['localhost'], ['127.0.0.1']);
  return { ...await demo(nodes, { tls, fixtures }), tls };
}

async function runtime(d: Demo & { tls: ReturnType<typeof tlsCertificate> }) {
  appendFileSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'declared-out.txt'), `${d.cln.runeFile}\n${d.key.keyFile}\n`);
  writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), 't05-local-rune.bin'), d.cln.rune, { mode: 0o600 });
  writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), 't05-local-approval-key.pem'), readFileSync(d.key.keyFile), { mode: 0o600 });
  closes.push(() => {
    for (const [hash, invoice] of d.cln.state.invoices) {
      writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `t05-${hash}-preimage.bin`), Buffer.from(invoice.preimage, 'hex'), { mode: 0o600 });
    }
    return Promise.resolve();
  });
  const state: Record<string, { name: string; enabled: boolean; upstream: string; listen: string; toxics: Record<string, unknown>[] }> =
    Object.fromEntries(managed.map(proxy => [proxy.name, { ...proxy, toxics: [] }]));
  const events: string[] = [];
  const sockets = new Set<Socket>();
  const port = async (server: ReturnType<typeof httpServer> | ReturnType<typeof tcpServer>) => {
    await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    closes.push(() => new Promise(resolve => {
      if ('closeAllConnections' in server) server.closeAllConnections();
      for (const socket of sockets) socket.destroy();
      server.close(() => { resolve(); });
    }));
    const address = server.address(); if (!address || typeof address === 'string') throw new Error('local fixture has no port');
    return address.port;
  };
  // Opaque TCP forwarding retains the node's TLS and counts the actual downstream bytes,
  // including TLS records. A one-byte allowance therefore cannot deliver a payment answer.
  const clnRest = await port(tcpServer(incoming => {
    const outgoing = connect(d.cln.fake.port, d.cln.fake.host);
    for (const socket of [incoming, outgoing]) {
      sockets.add(socket); socket.on('close', () => sockets.delete(socket));
    }
    incoming.on('error', () => { outgoing.destroy(); }); outgoing.on('error', () => { incoming.destroy(); });
    incoming.on('close', () => { outgoing.destroy(); });
    incoming.pipe(outgoing);
    const counts = new Map<string, number>();
    outgoing.on('data', (chunk: Buffer) => {
      const proxy = state['cln-m-rest'];
      if (!proxy || !proxy.enabled || proxy.toxics.some(toxic => toxic['type'] === 'reset_peer')) {
        events.push('reset:cln-m-rest'); incoming.resetAndDestroy(); outgoing.destroy(); return;
      }
      const limit = proxy.toxics.find(toxic => toxic['type'] === 'limit_data' && (toxic['stream'] ?? 'downstream') === 'downstream');
      if (!limit) { incoming.write(chunk); return; }
      const attributes = limit['attributes'] as { bytes: number }, name = String(limit['name']);
      const remaining = Math.max(0, attributes.bytes - (counts.get(name) ?? 0));
      const prefix = chunk.subarray(0, remaining);
      counts.set(name, (counts.get(name) ?? 0) + prefix.length);
      if (prefix.length) incoming.write(prefix);
      if (prefix.length === remaining) {
        events.push(`limit_data:cln-m-rest:${String(attributes.bytes)}`); incoming.end(); outgoing.destroy();
      }
    });
    outgoing.on('end', () => { incoming.end(); });
  }));
  const toxiproxy = await port(httpServer((incoming, response) => {
    let body = ''; incoming.on('data', (chunk: Buffer) => { body += chunk.toString('utf8'); });
    incoming.on('end', () => {
      const match = /^\/proxies\/([^/]+)(?:\/toxics(?:\/([^/]+))?)?$/.exec(incoming.url ?? '');
      const name = match?.[1], proxy = name === undefined ? undefined : state[name];
      let value: unknown = state;
      if (proxy) {
        const toxicName = match?.[2];
        if (incoming.method === 'DELETE' && toxicName) {
          events.push(`clear:${String(name)}:${toxicName}`); proxy.toxics = proxy.toxics.filter(toxic => toxic['name'] !== toxicName); value = {};
        } else if (incoming.method === 'POST' && incoming.url?.endsWith('/toxics')) {
          const toxic = JSON.parse(body) as Record<string, unknown>; proxy.toxics.push(toxic); events.push(`add:${String(name)}:${String(toxic['type'])}`); value = toxic;
        } else {
          if (incoming.method === 'POST') { const change = JSON.parse(body) as object; Object.assign(proxy, change); events.push(`enabled:${String(name)}:${String(proxy.enabled)}`); }
          value = proxy;
        }
      }
      response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify(value));
    });
  }));
  const id = `t05-${randomBytes(6).toString('hex')}`;
  const roots = Object.fromEntries(['runtimeRoot', 'tmpRoot', 'sentinelRoot', 'evidenceRoot'].map(name => {
    const path = join(d.dir, name); mkdirSync(path, { mode: 0o700 }); return [name, path];
  }));
  const owner = { version: 1, id, project: `fluxwarden-lab-${id}`, ...roots,
    ports: { lndRest: d.cln.fake.port, clnRest, toxiproxy }, resources: { cpus: 4, memoryBytes: 4294967296, pids: 1024 },
    credentialPolicy: { maxPrincipalMsat: '100000000', callsPerMinute: '600' } };
  const fingerprint = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex');
  const certificate = { path: d.tls.certPath, fingerprint: fingerprint(d.tls.certPath), sha256: fingerprint(d.tls.certPath) };
  const credential = { path: d.cln.runeFile, fingerprint: fingerprint(d.cln.runeFile), sha256: fingerprint(d.cln.runeFile) };
  const manifest = { version: 1, ownerId: id, project: owner.project, ports: owner.ports,
    nodes: { 'cln-m': { kind: 'cln', implementation: 'cln', network: 'regtest', version: 'v26.06.9', pubkey: SELF, certificate } },
    credentials: { 'cln-m': { read: credential, execute: credential } } };
  writeFileSync(join(roots['runtimeRoot'] ?? '', 'lab.json'), JSON.stringify(manifest), { mode: 0o600 });
  const planPath = join(d.dir, 'owner.json'); writeFileSync(planPath, JSON.stringify(owner), { mode: 0o600 });
  d.rewrite({ node: { name: 'cln-m', url: `https://localhost:${String(clnRest)}`, runeFile: d.cln.runeFile, expectedPubkey: SELF, tlsCert: d.tls.certPath } });
  const module = await import(pathToFileURL(join(repoRoot, 'labs/docker/demo/runtime.mjs')).href) as {
    createRuntimeLab(input: { planPath: string; configPath: string; signal: AbortSignal }): Promise<Runtime>;
  };
  const lab = await module.createRuntimeLab({ planPath, configPath: d.config, signal: new AbortController().signal });
  closes.push(() => lab.close());
  return { runtime: lab, events, state, clnRest, toxiproxy };
}

function history(d: Demo) {
  return {
    executions: rows(d.database, 'SELECT * FROM executions ORDER BY id'),
    journals: rows(d.database, 'SELECT * FROM ledger_journals ORDER BY id'),
    lines: rows(d.database, 'SELECT * FROM ledger_lines ORDER BY journal_id, sequence_no'),
  };
}

function expiredApproved(d: Demo, freshId: string, policyHash: string) {
  // Initial historical rows, not time edits to an existing intent. SECURITY §4.1's
  // independent digest/signature encoding gives this old approval authentic signed terms.
  const id = ulid(), now = dbNow(d.database), expiresAt = now - 60_000, createdAt = now - 120_000;
  const prefix = (value: string) => {
    const bytes = Buffer.from(value), length = Buffer.alloc(4); length.writeUInt32BE(bytes.length);
    return Buffer.concat([length, bytes]);
  };
  const digest = createHash('sha256').update(Buffer.concat([
    Buffer.from('FluxWarden-proposal-v1\0'),
    ...[`prop_${id}`, SELF, S, T, '100000000', '300000', '2500', '5000', '144', policyHash, String(expiresAt)].map(prefix),
  ])).digest('hex');
  const nonce = randomBytes(32), approvalId = ulid();
  const message = approvalMessage({ digest, policySha256: policyHash, maxFeeMsat: 300_000n,
    maxCltvDelta: 144, expiresAt: BigInt(expiresAt), nonce, keyId: d.key.keyId });
  const signature = sign(null, message, createPrivateKey(readFileSync(d.key.keyFile)));
  expect(verifiesWith(d.key.publicKey, message, signature), 'old stored approval has a genuine operator signature').toBe(true);
  const db = new DatabaseSync(d.database);
  try {
    db.prepare(`INSERT INTO liquidity_proposals (id, policy_version_id, node_id, action_type,
      source_channel_id, target_channel_id, principal_msat, max_fee_msat, max_fee_ppm, max_cltv_delta,
      route_json, demand_source, proposal_digest, status, reason_json, expires_at, created_at)
      SELECT ?, policy_version_id, node_id, action_type, source_channel_id, target_channel_id,
        principal_msat, max_fee_msat, max_fee_ppm, max_cltv_delta, route_json, demand_source,
        ?, 'APPROVED', reason_json, ?, ? FROM liquidity_proposals WHERE id = ?`)
      .run(id, digest, expiresAt, createdAt, storedId(freshId));
    db.prepare(`INSERT INTO approvals (id, proposal_id, key_id, nonce, expires_at, signature,
      max_fee_msat, max_cltv_delta, created_at) VALUES (?, ?, ?, ?, ?, ?, 300000, 144, ?)`)
      .run(approvalId, id, d.key.keyId, nonce.toString('hex'), expiresAt, signature.toString('base64'), createdAt);
  } finally { db.close(); }
  return id;
}

it('CP-043/B2 limit_data control cuts real TLS after one downstream byte and removing it restores the endpoint', async () => {
  const d = await tlsDemo(), f = await runtime(d);
  const identity = () => new Promise<string>((resolve, reject) => {
    const outgoing = httpsRequest({ hostname: 'localhost', port: f.clnRest, path: '/v1/getinfo', method: 'POST',
      ca: readFileSync(d.tls.certPath), headers: { rune: d.cln.rune }, agent: false }, response => {
      let body = ''; response.on('data', (chunk: Buffer) => { body += chunk.toString('utf8'); });
      response.on('error', reject); response.on('end', () => {
        try { resolve((JSON.parse(body) as { id: string }).id); }
        catch (error) { reject(error instanceof Error ? error : new Error('fixture control response was invalid')); }
      });
    });
    outgoing.on('error', reject); outgoing.setTimeout(2000, () => { outgoing.destroy(new Error('fixture-control-deadline')); });
    outgoing.end('{}');
  });
  const toxicUrl = `http://127.0.0.1:${String(f.toxiproxy)}/proxies/cln-m-rest/toxics`;
  expect(await identity(), 'positive TLS/authentication control').toBe(SELF);
  const added = await fetch(toxicUrl, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name: 'transport-control', type: 'limit_data', stream: 'downstream', toxicity: 1, attributes: { bytes: 1 } }) });
  expect(added.status).toBe(200); await added.arrayBuffer();
  try {
    const cut = await identity().then(() => false, () => true);
    expect(cut, 'one downstream byte closes TLS instead of passing a complete RPC response').toBe(true);
    expect(f.events).toContain('limit_data:cln-m-rest:1');
    expect(callsOf(d.cln.fake, 'getinfo'), 'cut TLS handshake cannot deliver a second RPC').toHaveLength(1);
  } finally {
    const removed = await fetch(`${toxicUrl}/transport-control`, { method: 'DELETE' });
    expect(removed.status).toBe(200); await removed.arrayBuffer();
  }
  expect(await identity(), 'endpoint recovers after removing the toxic').toBe(SELF);
  expect(f.state['cln-m-rest']?.toxics).toEqual([]);
});

for (const withExpired of [false, true]) {
it(`CP-043/B2 T-05 selects a fresh signed approved intent${withExpired ? ' beside an expired APPROVED history row' : ''} through the real repository and persists one UNKNOWN send with clean fault removal`, async () => {
  const d = await tlsDemo(), proposal = await plan(d), proposalId = String(proposal['proposal_id']);
  const freshApproval = await approve(d, proposalId);
  const oldId = withExpired ? expiredApproved(d, proposalId, String(proposal['policy_sha256'])) : null;
  const oldProposal = oldId === null ? [] : rows(d.database, 'SELECT * FROM liquidity_proposals WHERE id = ?', oldId);
  const oldApprovals = oldId === null ? [] : rows(d.database, 'SELECT * FROM approvals WHERE proposal_id = ?', oldId);
  expect(rows(d.database, 'SELECT status FROM liquidity_proposals WHERE id = ?', storedId(proposalId))).toEqual([{ status: 'APPROVED' }]);
  expect(rows(d.database, 'SELECT id FROM executions')).toEqual([]);
  expect(callsOf(d.cln.fake, 'sendpay')).toEqual([]);
  const before = history(d), openingIds = new Set(before.journals.map(journal => journal['id']));
  expect(before.journals.map(journal => journal['event_type'])).toEqual(['OPENING', 'OPENING']);
  const f = await runtime(d);
  let observed: { value: Observation } | { error: { name: string; unavailableRepositoryMethod: boolean } };
  try {
    await f.runtime.faults.apply('T-05');
    observed = await f.runtime.lab.scenario('T-05').then(value => ({ value }), (error: unknown) => ({ error: {
      name: error instanceof Error ? error.name : 'unknown',
      unavailableRepositoryMethod: error instanceof Error && error.message.includes('executions.existing is not a function'),
    } }));
  } finally { await f.runtime.faults.clear('T-05'); }
  expect(Object.values(f.state).every(proxy => proxy.enabled && proxy.toxics.length === 0), 'fault lifecycle leaves no disabled proxy or toxic').toBe(true);
  const after = history(d);
  expect(after.journals.filter(journal => openingIds.has(journal['id'])), 'all baseline opening journals remain byte-for-byte unchanged').toEqual(before.journals);
  expect(after.lines.filter(line => openingIds.has(line['journal_id'])), 'all baseline opening lines remain unchanged').toEqual(before.lines);
  if (oldId !== null) {
    expect(rows(d.database, 'SELECT * FROM liquidity_proposals WHERE id = ?', oldId)).toEqual(oldProposal);
    expect(rows(d.database, 'SELECT * FROM approvals WHERE proposal_id = ?', oldId)).toEqual(oldApprovals);
    expect(rows(d.database, 'SELECT id FROM executions WHERE proposal_id = ?', oldId), 'expired old intent is neither claimed nor cancelled').toEqual([]);
  }
  expect(observed).toMatchObject({ value: { exit: 7, status: 'UNKNOWN', sendCount: 1 } });
  if (!('value' in observed)) throw new Error('missing public scenario observation');
  const hash = observed.value.paymentHash;
  expect(hash).toMatch(/^[0-9a-f]{64}$/);
  expect(rows(d.database, 'SELECT proposal_id, approval_id, status, payment_hash FROM executions')).toEqual([
    { proposal_id: storedId(proposalId), approval_id: freshApproval['approval_id'], status: 'UNKNOWN', payment_hash: hash },
  ]);
  expect(callsOf(d.cln.fake, 'sendpay').map(call => call['payment_hash'])).toEqual([hash]);
  expect(callsOf(d.cln.fake, 'invoice')).toHaveLength(1);
  expect(f.events.some(event => event === 'limit_data:cln-m-rest:1' || event === 'reset:cln-m-rest'), 'a supported response-cut fault was exercised').toBe(true);
  // SPEC §9.3: UNKNOWN keeps principal in clearing; no terminal settlement/fee journal.
  expect(after.journals.filter(journal => !openingIds.has(journal['id'])).map(journal => ({
    event_type: journal['event_type'], execution_id: journal['execution_id'],
  }))).toEqual([
    { event_type: 'REBALANCE_SENT', execution_id: after.executions[0]?.['id'] },
  ]);
});
}

it('CP-043/B2 T-05 cannot reuse an original successful demo execution when no fresh approved intent exists', async () => {
  const d = await tlsDemo(), proposal = await plan(d), proposalId = String(proposal['proposal_id']);
  await approve(d, proposalId);
  const executed = await d.run(['--json', 'actions', 'execute', proposalId, '--require-regtest']);
  expect(executed.status).toBe(0);
  expect(resultOf(documentOf(executed, 'actions-execute'))).toMatchObject({ status: 'VERIFIED_SUCCESS' });
  const before = history(d), hashes = [...d.cln.state.sent], f = await runtime(d);
  let name = '';
  try { await f.runtime.lab.scenario('T-05'); } catch (error) { name = error instanceof Error ? error.name : 'unknown'; }
  expect(history(d), 'terminal execution, journal and ledger-line history remains unchanged').toEqual(before);
  expect(d.cln.state.sent, 'no historical intent is dispatched a second time').toEqual(hashes);
  expect(callsOf(d.cln.fake, 'sendpay')).toHaveLength(1);
  expect(name, 'no fresh approved intent is a controlled readiness refusal').not.toBe('');
  expect(name, 'repository selection must not throw a missing-method TypeError').not.toBe('TypeError');
});
