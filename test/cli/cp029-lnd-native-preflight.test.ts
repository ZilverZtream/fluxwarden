/* SPEC 8.3 P3-P6, 5.5 V1/V12; INV-03/05/12/15/16/17.
 * Owned pinned LND observations: owned-lnd-preflight-read.json and its recorded
 * native QueryRoutes24 control (108x5x0 -> 108x2x0 -> 108x3x0).
 * The public plan names decimal channel keys; routes name the same channels as SCIDs.
 * A fresh identical valid route must reach one send. A response cut then means UNKNOWN.
 * No assertion attributes the observed live refusal to a production implementation.
 */
import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { startHttpsFake, type FakeServer } from '../fakes/https.js';
import { addInvoiceResponse, channelEdge, route, routeHop, routingPolicy } from '../fakes/lnd/responses.js';
import { syntheticInvoice } from '../helpers/cp004-invoice.js';
import { createDatabase, jsonDocument, runCli, scratch, writeConfig } from '../helpers/cp016-cli.js';
import { makeOwnerOnlyDir } from '../helpers/cp015-persistence.js';
import { approvalMessage, bytesOf, documentOf, generateKey, rec, resultOf, rows, verifiesWith, writeDemoPolicy } from '../helpers/cpw-cli.js';
import { readJson } from '../helpers/cli.js';
import { testRoot } from '../helpers/env.js';
import { tlsCertificate } from '../helpers/tls-material.js';

const SELF = '02ef20a508a650f1a6188700c680e3075a1071ea2c2343b780b50646da1533c5c3';
const OUT = '024d0117773b3f6ac3f12b2c08e249aa498dbe0047145e33691cd9cb0060b474f7';
const IN = '025644dfd25dd92e8cda3f7dbb52cff7462fd40b99791dffbb42106a3d6c153e2d';
const S = '118747256127488', M = '118747255930880', T = '118747255996416';
const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

// Native fee arithmetic, SPEC 4.4: 1000 + floor(P * 1000 / 1e6) = 101000;
// 1000 + floor((P + 101000) * 1000 / 1e6) = 101101; total 202101 (2022 ppm).
// Hop fields: pinned lnrpc/lightning.proto Hop/Route, routing/route/route.go.
// The owned native QueryRoutes24 control observes height 114, total 206 and these expiries:
// 206 - 114 = 34 + 34 + 24 = 92; the independent existing 3-block margin makes 95 <= 144.
const nativeRoute = route(206, 100_202_101n, 202_101n, [
  routeHop({ chanId: S, pubKey: OUT, forwardMsat: 100_101_000n, feeMsat: 101_101n, expiry: 172 }),
  routeHop({ chanId: M, pubKey: IN, forwardMsat: 100_000_000n, feeMsat: 101_000n, expiry: 138 }),
  routeHop({ chanId: T, pubKey: SELF, forwardMsat: 100_000_000n, feeMsat: 0n, expiry: 138 }),
]);
const policy = routingPolicy({ timeLockDelta: 34, baseMsat: 1000, rateMilliMsat: 1000 });
const edges: Record<string, Record<string, unknown>> = {
  [M]: channelEdge(M, OUT, IN, { [OUT]: policy, [IN]: policy }),
  [T]: channelEdge(T, IN, SELF, { [IN]: policy, [SELF]: policy }),
  [S]: channelEdge(S, SELF, OUT, { [SELF]: policy, [OUT]: policy }),
};

// Entity/action model from pinned LND v0.21.4-beta rpcserver.go
// MainRPCServerPermissions and routerrpc/router_server.go macPermissions:
// https://github.com/lightningnetwork/lnd/blob/v0.21.4-beta/rpcserver.go#L372-L430
// https://github.com/lightningnetwork/lnd/blob/v0.21.4-beta/lnrpc/routerrpc/router_server.go#L81-L129
// Decimal <-> SCID: https://github.com/lightningnetwork/lnd/blob/v0.21.4-beta/lnwire/short_channel_id.go#L30-L46
// GetInfo/GetChanInfo/QueryRoutes info:read; ListChannels/PendingChannels/
// GetMissionControlConfig offchain:read; AddInvoice invoices:write;
// SendToRouteV2 offchain:write. URI scopes add these exact methods only.
const readMethods = new Set(['GET /v1/getinfo', 'GET /v1/channels', 'GET /v1/channels/pending',
  'GET /v2/router/mccfg', 'POST /v1/graph/routes', 'GET /v1/graph/edge']);
const executeMethods = new Set([...readMethods, 'POST /v1/invoices', 'POST /v2/router/route/send']);

it('CP-029/B4 CP-030/B3 CP-033/B1 T-05 native LND channel keys survive fresh preflight and one response-cut send retains its hash', async () => {
  const dir = scratch('native-lnd-preflight'); makeOwnerOnlyDir(dir);
  const material = tlsCertificate(dir, ['localhost'], ['127.0.0.1']);
  const reference = rec(readJson('labs/fixtures/owned-lnd-preflight-read.json'));
  const readToken = randomBytes(48), executeToken = randomBytes(48);
  const readPath = join(dir, 'read.macaroon'), executePath = join(dir, 'execute.macaroon');
  for (const [path, value] of [[readPath, readToken], [executePath, executeToken]] as const) {
    appendFileSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'declared-out.txt'), `${path}\n`);
    writeFileSync(path, value, { mode: 0o600 });
    writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `${randomBytes(8).toString('hex')}.bin`), value, { mode: 0o600 });
  }
  const requests: { method: string; path: string; credential: string; body: Record<string, unknown> }[] = [];
  let database = '', persistedBeforeInvoice = false, persistedBeforeSend = false;
  const fake = await startHttpsFake((incoming, response) => {
    const path = incoming.url.split('?')[0] ?? '';
    const endpoint = path.startsWith('/v1/graph/routes/') ? '/v1/graph/routes'
      : path.startsWith('/v1/graph/edge/') ? '/v1/graph/edge' : path;
    const key = `${incoming.method} ${endpoint}`;
    const token = incoming.headers['grpc-metadata-macaroon'];
    const credential = token === readToken.toString('hex') ? 'read' : token === executeToken.toString('hex') ? 'execute' : 'unknown';
    const body = incoming.body === '' ? {} : rec(JSON.parse(incoming.body));
    requests.push({ method: incoming.method, path, credential, body });
    const allowed = credential === 'read' ? readMethods : credential === 'execute' ? executeMethods : new Set<string>();
    const answer = (value: unknown) => { response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify(value)); };
    if (!allowed.has(key)) { response.writeHead(403); response.end(JSON.stringify({ code: 7, message: 'permission denied', details: [] })); return; }
    if (path === '/v1/getinfo') { answer(reference['info']); return; }
    if (path === '/v1/channels') { answer(reference['channels']); return; }
    if (path === '/v1/channels/pending') { answer({ total_limbo_balance: '0', pending_open_channels: [], pending_closing_channels: [], pending_force_closing_channels: [], waiting_close_channels: [] }); return; }
    if (path === '/v2/router/mccfg') { answer({ config: { maximum_payment_results: 1000, minimum_failure_relax_interval: '60', model: 'APRIORI', apriori: { half_life_seconds: '3600', hop_probability: 0.6, weight: 0.5, capacity_fraction: 0.9999 }, bimodal: null } }); return; }
    if (endpoint === '/v1/graph/edge') {
      const edge = edges[path.split('/').at(-1) ?? ''];
      if (!edge) { response.writeHead(500); response.end(JSON.stringify({ code: 2, message: 'edge not found', details: [] })); return; }
      answer(edge); return;
    }
    if (endpoint === '/v1/graph/routes') {
      // Keep native gateway/pathfinding refusals: never turn a malformed or
      // over-cap request into a usable route (pinned lightning.pb.gw.go,
      // marshall_utils.go and routing/pathfind.go; cp023 fake references).
      const fields = new Set(['pub_key', 'amt', 'amt_msat', 'final_cltv_delta', 'fee_limit', 'ignored_nodes', 'ignored_edges',
        'source_pub_key', 'use_mission_control', 'ignored_pairs', 'cltv_limit', 'dest_custom_records', 'last_hop_pubkey',
        'route_hints', 'blinded_payment_paths', 'dest_features', 'time_pref', 'outgoing_chan_ids']);
      const unknown = Object.keys(body).find(field => !fields.has(field));
      if (unknown) { response.writeHead(400); response.end(JSON.stringify({ code: 3, message: `proto: unknown field "${unknown}"`, details: [] })); return; }
      if (!path.endsWith('/0')) { response.writeHead(500); response.end(JSON.stringify({ code: 2, message: 'sat and msat arguments are mutually exclusive', details: [] })); return; }
      const ids = body['outgoing_chan_ids'];
      const feeLimit = rec(body['fee_limit']);
      const lastPeer = Buffer.from(String(body['last_hop_pubkey']), 'base64').toString('hex');
      if (!Array.isArray(ids) || ids.length !== 1 || ids[0] !== S || lastPeer !== IN || String(body['amt_msat']) !== '100000000'
        || BigInt(String(feeLimit['fixed_msat'])) < 202_101n || Number(body['cltv_limit']) < 92) {
        response.writeHead(500); response.end(JSON.stringify({ code: 2, message: 'unable to find a path to destination', details: [] })); return;
      }
      answer({ routes: [nativeRoute], success_prob: 0.82 }); return;
    }
    if (path === '/v1/invoices') {
      // Owned native AddInvoice controls reject 18/23 and accept 24 (D60; fixture invoice_reference).
      // This minimum is an invoice rule, not an invented QueryRoutes refusal.
      const minimum = Number(rec(reference['invoice_reference'])['min_final_cltv_delta']);
      const requested = Number(body['cltv_expiry']);
      if (requested < minimum) {
        response.writeHead(500); response.end(JSON.stringify({ code: 2,
          message: `CLTV delta of ${String(requested)} must be greater than minimum of ${String(minimum)}`, details: [] })); return;
      }
      const preimage = Buffer.from(String(body['r_preimage']), 'base64');
      writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `${randomBytes(8).toString('hex')}-preimage.bin`), preimage, { mode: 0o600 });
      const hash = createHash('sha256').update(preimage).digest('hex');
      persistedBeforeInvoice = rows(database, 'SELECT payment_hash FROM executions').some(row => row['payment_hash'] === hash);
      const address = randomBytes(32);
      writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `${randomBytes(8).toString('hex')}-payment-address.bin`), address, { mode: 0o600 });
      // BOLT11's c tag (type 24), one 5-bit word: the accepted invoice's minimum delta is 24.
      answer(addInvoiceResponse(hash, address.toString('hex'), syntheticInvoice(hash, [24, 0, 1, 24]))); return;
    }
    if (path === '/v2/router/route/send') {
      const hash = Buffer.from(String(body['payment_hash']), 'base64').toString('hex');
      // The client may record IN_FLIGHT as soon as bytes are written, before
      // this server finishes reading them; both states must carry the hash.
      persistedBeforeSend = rows(database, 'SELECT status,payment_hash FROM executions').some(row =>
        ['SUBMITTING', 'IN_FLIGHT'].includes(String(row['status'])) && row['payment_hash'] === hash);
      // RFC 9112 9.6: request fully received, connection lost before response bytes.
      response.socket?.destroy(); return;
    }
  }, 'node', material);
  open.push(fake);
  mkdirSync(join(dir, 'state'), { mode: 0o700 }); makeOwnerOnlyDir(join(dir, 'state'));
  database = join(dir, 'state', 'fluxwarden.db'); await createDatabase(database);
  const key = await generateKey(dir);
  appendFileSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'declared-out.txt'), `${key.keyFile}\n`);
  writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `${randomBytes(8).toString('hex')}-approval-key.pem`), readFileSync(key.keyFile));
  const policyPath = writeDemoPolicy(dir, { targets: { 'lnd-r': { [S]: '3000404000', [T]: '0' } } });
  const config = (credential: string, name: string) => {
    const file = writeConfig(dir, { database, policy: policyPath, nodes: [{ name: 'lnd-r', implementation: 'lnd',
      url: `https://127.0.0.1:${String(fake.port)}`, tlsCert: material.certPath, credential, expectedPubkey: SELF }] });
    const target = join(dir, name);
    writeFileSync(target, `${readFileSync(file, 'utf8')}approval_keys:\n  - key_id: "${key.keyId}"\n    public_key: "${key.publicKey}"\n`); return target;
  };
  const readConfig = config(readPath, 'read.yaml'), executeConfig = config(executePath, 'execute.yaml');
  const run = (args: string[], selected = readConfig) => runCli(['--json', ...args, '--config', selected]);
  const doctor = await run(['doctor']); expect(doctor.status, doctor.stdout).toBe(0);
  const planned = await run(['liquidity', 'plan', '--refresh']); expect(planned.status, planned.stdout).toBe(0);
  const proposal = resultOf(documentOf(planned, 'liquidity-plan'));
  expect(proposal).toMatchObject({ action: 'CIRCULAR_REBALANCE', source_channel: S, target_channel: T, principal_msat: '100000000',
    route: { fee_msat: '202101', fee_ppm: 2022, cltv_delta: 92, padding: 3 } });
  for (const quote of requests.filter(r => r.path.startsWith('/v1/graph/routes/'))) expect(quote.body['final_cltv_delta']).toBe(24);
  expect((rec(proposal['route'])['hops'] as Record<string, unknown>[]).map(hop => hop['channel'])).toEqual(['108x5x0', '108x2x0', '108x3x0']);
  const approved = await run(['liquidity', 'approve', String(proposal['proposal_id']), '--key', key.keyFile, '--max-fee-msat', '300000', '--max-cltv-delta', '144']);
  expect(approved.status, approved.stdout).toBe(0);
  const signed = rec(rows(database, `SELECT a.key_id,a.nonce,a.expires_at,a.signature,a.max_fee_msat,a.max_cltv_delta,
    p.proposal_digest,p.status,v.policy_sha256 FROM approvals a JOIN liquidity_proposals p ON p.id=a.proposal_id
    JOIN policy_versions v ON v.id=p.policy_version_id`)[0]);
  expect(signed['status']).toBe('APPROVED');
  const nonce = bytesOf(String(signed['nonce']), 32), signature = bytesOf(String(signed['signature']), 64);
  if (!nonce || !signature) throw new Error('approval nonce/signature has an invalid encoding');
  expect(verifiesWith(key.publicKey, approvalMessage({ digest: String(signed['proposal_digest']), policySha256: String(signed['policy_sha256']),
    maxFeeMsat: BigInt(String(signed['max_fee_msat'])), maxCltvDelta: Number(signed['max_cltv_delta']), expiresAt: BigInt(String(signed['expires_at'])),
    nonce, keyId: String(signed['key_id']) }), signature)).toBe(true);
  const before = requests.length;
  const executed = await run(['actions', 'execute', String(proposal['proposal_id']), '--require-regtest'], executeConfig);
  const observed = requests.slice(before);
  // The assertion includes only safe RPC metadata, never tokens/preimages/send bodies.
  const metadata = { exit: executed.status, error: jsonDocument(executed)['error'],
    calls: observed.map(r => `${r.credential} ${r.method} ${r.path}`),
    executions: rows(database, 'SELECT status,error_code,payment_hash IS NOT NULL AS has_hash FROM executions') };
  writeFileSync(join(dir, 'safe-execute-observation.json'), JSON.stringify(metadata, null, 2));
  expect(metadata, JSON.stringify(metadata)).toMatchObject({ exit: 7 });
  const quotes = observed.filter(r => r.path.startsWith('/v1/graph/routes/'));
  expect(quotes.length).toBeGreaterThan(0);
  for (const quote of quotes) expect(quote.body).toMatchObject({ amt_msat: '100000000', outgoing_chan_ids: [S], fee_limit: { fixed_msat: '250000' }, cltv_limit: 141, final_cltv_delta: 24 });
  expect(observed.filter(r => r.path === '/v1/invoices').map(r => Number(r.body['cltv_expiry']))).toEqual([24]);
  const sends = observed.filter(r => r.path === '/v2/router/route/send'); expect(sends).toHaveLength(1);
  expect(sends[0]?.credential).toBe('execute'); expect(persistedBeforeInvoice).toBe(true); expect(persistedBeforeSend).toBe(true);
  expect(rows(database, 'SELECT status, payment_hash IS NOT NULL AS has_hash FROM executions')).toEqual([{ status: 'UNKNOWN', has_hash: 1 }]);
  expect(requests.filter(r => r.path === '/v2/router/send')).toHaveLength(0);
}, 30_000);
