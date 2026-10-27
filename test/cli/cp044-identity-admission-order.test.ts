// ARC-044-001: known unbound legacy provenance / incompatible implementation
// refuses with identity5 before credentials or endpoint access. A remote pin
// mismatch still requires a read-only probe; genuinely new names may register.
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, expect, it } from 'vitest';
import type { Database } from '../../src/persistence/index.js';
import type { FakeServer } from '../fakes/https.js';
import { startResettingListener } from '../fakes/https.js';
import { getInfo, LND_PUBKEY } from '../fakes/lnd/responses.js';
import { getinfo } from '../fakes/cln/responses.js';
import { clnNode, lndNode, nodeCert, runCli, writeConfig, type NodeEntry } from '../helpers/cp016-cli.js';
import { NODE_PUBKEY, raw, scratchDb, seedBase, type ExecPersistence } from '../helpers/cp028-executor.js';
import { reservationState, rowOf, seedExecution } from '../helpers/cp030-execution.js';
import { repoRoot } from '../helpers/cli.js';
import { registerMoneySafetyCredentials } from '../helpers/public-money-safety.js';

const servers: FakeServer[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });

async function persistence(): Promise<ExecPersistence> {
  return await import(pathToFileURL(join(repoRoot, 'dist/persistence/index.js')).href) as ExecPersistence;
}

for (const identity of ['legacy-unbound', 'implementation-mismatch'] as const) {
  for (const access of ['unreadable-credential', 'unavailable-endpoint', 'healthy-endpoint'] as const) {
    it(`CP-044/ARC-044-001 ${identity} refuses before ${access} access`, async () => {
      const p = await persistence(), database = scratchDb('arc044-admission'), dir = dirname(database);
      let executionId: string | undefined;
      if (identity === 'legacy-unbound') {
        // Genuine audited schema4, before any current migration is opened.
        const base = seedBase(p, database, join(repoRoot, 'labs/fixtures/cp044/legacy-schema4-empty.sqlite3'));
        executionId = seedExecution(base, { status: 'UNKNOWN', paymentHash: randomBytes(32).toString('hex'), submittedAgoMs: 300_000 }).executionId;
        const legacy = raw(database);
        try { expect(legacy.prepare('PRAGMA user_version').get()?.['user_version']).toBe(4n); }
        finally { legacy.close(); }
      }
      // Opening the public current database migrates the actual old fixture;
      // no new-schema provenance columns, clocks or identities are edited.
      p.openDatabase(database, { readOnly: false }).close();
      const lnd = await lndNode(dir, servers, { info: getInfo({ pubkey: NODE_PUBKEY }) });
      registerMoneySafetyCredentials([lnd.macaroon]);
      let entry: NodeEntry = { name: 'lnd-r', implementation: 'lnd', url: lnd.url, tlsCert: nodeCert(), credential: lnd.macaroon, expectedPubkey: NODE_PUBKEY };
      if (identity === 'implementation-mismatch') {
        const boundConfig = writeConfig(dir, { database, nodes: [entry] });
        expect((await runCli(['--json', 'nodes', 'inspect', 'lnd-r', '--config', boundConfig])).status).toBe(0);
        const cln = await clnNode(dir, servers, { info: getinfo({ id: NODE_PUBKEY }) });
        registerMoneySafetyCredentials([cln.runeFile]);
        entry = { ...entry, implementation: 'cln', url: cln.url, credential: cln.runeFile };
      }
      const observed = servers.slice();
      const before = observed.map(server => ({ server, requests: server.requests.length, connections: server.connections() }));
      if (access === 'unreadable-credential') entry = { ...entry, credential: join(dir, 'absent-reader-credential') };
      if (access === 'unavailable-endpoint') {
        const reset = await startResettingListener(); servers.push(reset);
        before.push({ server: reset, requests: 0, connections: 0 });
        entry = { ...entry, url: `https://${reset.host}:${String(reset.port)}` };
      }
      const config = writeConfig(dir, { database, nodes: [entry] });
      const prior = executionId === undefined ? null : { row: rowOf(database, executionId), reservation: reservationState(database, executionId) };
      const run = await runCli(['--json', 'nodes', 'recover', 'lnd-r', '--config', config]);
      const document = JSON.parse(run.stdout) as { error?: { code?: number; step?: string } };
      expect.soft(run.status).toBe(5);
      expect.soft(document.error).toMatchObject({ code: 5, step: 'identity' });
      for (const item of before) {
        expect.soft(item.server.requests.length - item.requests).toBe(0);
        expect.soft(item.server.connections() - item.connections).toBe(0);
      }
      if (executionId !== undefined) {
        expect.soft(rowOf(database, executionId)).toEqual(prior?.row);
        expect(reservationState(database, executionId)).toEqual(prior?.reservation);
      }
    });
  }
}

it('CP-044/ARC-044-001 a genuinely new configured name can register its first observed identity', async () => {
  const p = await persistence(), database = scratchDb('arc044-new-name'), dir = dirname(database);
  p.openDatabase(database, { readOnly: false }).close();
  const lnd = await lndNode(dir, servers);
  registerMoneySafetyCredentials([lnd.macaroon]);
  const config = writeConfig(dir, { database, nodes: [{ name: 'fresh-node', implementation: 'lnd', url: lnd.url,
    tlsCert: nodeCert(), credential: lnd.macaroon, expectedPubkey: LND_PUBKEY }] });
  // Recovery of a wholly unknown name is not a registration command. The
  // supported first observation is nodes inspect, which shares admission.
  const run = await runCli(['--json', 'nodes', 'inspect', 'fresh-node', '--config', config]);
  expect(run.status).toBe(0);
  expect(lnd.fake.requests.some(request => request.url === '/v1/getinfo')).toBe(true);
  const db = p.openDatabase(database, { readOnly: false }) as unknown as Database;
  try { expect(db.nodes.list()).toContainEqual(expect.objectContaining({ name: 'fresh-node', implementation: 'lnd', expectedPubkey: LND_PUBKEY })); }
  finally { db.close(); }
});

it('CP-044/ARC-044-001 a remote pubkey mismatch is probed safely without payment observations', async () => {
  const p = await persistence(), database = scratchDb('arc044-remote-pin'), dir = dirname(database);
  p.openDatabase(database, { readOnly: false }).close();
  const info = getInfo({ pubkey: NODE_PUBKEY }), lnd = await lndNode(dir, servers, { info });
  registerMoneySafetyCredentials([lnd.macaroon]);
  const config = writeConfig(dir, { database, nodes: [{ name: 'lnd-r', implementation: 'lnd', url: lnd.url,
    tlsCert: nodeCert(), credential: lnd.macaroon, expectedPubkey: NODE_PUBKEY }] });
  expect((await runCli(['--json', 'nodes', 'inspect', 'lnd-r', '--config', config])).status).toBe(0);
  const readsBefore = lnd.fake.requests.length;
  info['identity_pubkey'] = LND_PUBKEY;
  const run = await runCli(['--json', 'nodes', 'recover', 'lnd-r', '--config', config]);
  expect(run.status).toBe(5);
  const reads = lnd.fake.requests.slice(readsBefore).map(request => request.url);
  expect(reads.length).toBeGreaterThan(0);
  expect(reads.every(url => url === '/v1/getinfo')).toBe(true);
});
