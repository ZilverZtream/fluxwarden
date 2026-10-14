/*
 * Interface: read-only commands (doctor, nodes list, nodes inspect, channels) through the built CLI.
 *
 * Layout (ARCHITECTURE.md §2): src/commands/doctor.ts, src/commands/nodes.ts and src/commands/channels.ts
 * implement the commands; src/cli wires argv, the environment check and exit codes; the configuration
 * loader parses fluxwarden.yaml. Only src/output writes to stdout and stderr.
 *
 * Invocation: fluxwarden [--json] <command> [options]
 *   doctor                       --config <path>
 *   nodes list                   --config <path>
 *   nodes inspect <name>         --config <path> [--capabilities] [connection flags]
 *   channels                     --config <path> [--node <name>] [--sort inbound-deficit|outbound|capacity]
 *                                [connection flags]
 *   The default configuration path is ./fluxwarden.yaml.
 *
 * Configuration (SPEC.md §10.1, YAML subset of §7.1; credential keys as SECURITY.md §3.3):
 *   database: <path>   policy: <path>   collect_interval: <int>(s|m|h|d)
 *   nodes: [ { name, implementation: lnd|cln, url: https://host:port, tls_cert_path, macaroon_path (lnd) |
 *              rune_path (cln), expected_pubkey, expected_network } ]
 *   The policy's `targets.<node>.<channel key>.min_inbound_msat|min_outbound_msat` give the operator targets;
 *   without a policy every target is null. A command that opens the database (G4) and is not doctor needs it to
 *   exist; the tests create it first through the persistence module.
 *
 * One-source connection settings (the node address, its certificate and the credential presented to it) for
 * the one node a command selects (`nodes inspect <name>`, `channels --node <name>`):
 *   flags     --url <https url>  --tls-cert-path <path>     --macaroon-path <path> (lnd) | --rune-path <path> (cln)
 *   variables FLUXWARDEN_URL     FLUXWARDEN_TLS_CERT_PATH   FLUXWARDEN_MACAROON_PATH     | FLUXWARDEN_RUNE_PATH
 *   - Any connection flag given: every setting comes from flags. A connection variable set for a setting not
 *     given as a flag -> exit 2 naming the variable(s), never their values, before any credential is read.
 *   - No connection flag and any connection variable set: every setting comes from the variables.
 *   - Neither: every setting comes from the configuration's node entry.
 *   - expected_pubkey and expected_network always come from the configuration (INV-12).
 *   - A connection flag or variable with a command that does not select exactly one node (doctor, nodes list,
 *     channels without --node) -> exit 2 naming it: one credential is never presented to several nodes.
 *   - No option takes a credential value (SECURITY §3.3): any argument that looks like a macaroon, a rune, a hex or
 *     base64 run of credential length, or a private key -> exit 2 before anything else runs (no file read, no node
 *     call), the value not echoed.
 *
 * Environment check (SPEC.md §10.1, before any credential is read): NODE_OPTIONS non-empty, or NODE_DEBUG
 * naming http, https, tls or net (either name in any letter case, Node's `*` wildcard honoured) -> exit 2.
 * Diagnostic Node flags in process.execArgv (inspector, CPU/heap profiles, heap snapshots, reports, tracing,
 * V8 logging, TLS key log; `_` read as `-`) -> exit 2. Sizing flags such as --max-old-space-size are allowed.
 *
 * Exit codes (SPEC.md §10.2, §5.2): 2 G1-G3; 3 unsupported version, network or missing required capability;
 * 4 TLS, transport or authentication failure, or a protocol error on a read; 5 identity or network mismatch
 * (step "identity", node row QUARANTINED). doctor: every node is checked and the exit is the highest-priority
 * node failure, 4 before 3 before 5 (DR5); a node lacking any capability in REQUIRED_CAPABILITIES fails with 3.
 * nodes inspect and channels exit with the node's G5 code; inspect also fails with 3 on a missing required
 * capability, the text report naming each missing capability with its reason, the --json error message naming
 * each missing capability.
 *
 * --json results (schemas/output/<command>.schema.json; `result` is null whenever `error` is set):
 *   doctor        { node_version, engine_supported, sqlite, database: { path, schema_version },
 *                   nodes: [ { name, implementation, pubkey, network, version, synced, block_height, capabilities } ] }
 *   nodes list    { nodes: [ { name, implementation, expected_pubkey, expected_network, state, observed_version,
 *                   capabilities | null, last_probed_at | null } ] }   one row per configured node, from the database
 *                   only (no node call); a node never probed is OFFLINE with nulls
 *   nodes inspect { name, implementation, alias, pubkey, network, version, synced, block_height,
 *                   capabilities: sorted list with --capabilities, else null }
 *   channels      { sort: <key> | null, nodes: [ { name, implementation, channels: [ { channel, peer, state,
 *                   capacity_msat, spendable_msat, receivable_msat, confidence, caveat, pending_in_msat,
 *                   pending_out_msat, inbound_target_msat, inbound_deficit_msat, outbound_target_msat,
 *                   outbound_deficit_msat, observed_at, snapshot_age_ms } ] } ] }
 *   Node lists are ordered by name; capability lists ascending. Deficits (SPEC.md §7.3): inbound
 *   max(0, min_inbound - receivable), outbound max(0, min_outbound - spendable); 0 without a target.
 *   Sort keys order descending by that figure, ties by channel key ascending; without --sort, by channel key.
 *   channels stores one snapshot per listed channel (CH3). Text output prints the same figures as a table, the
 *   snapshot age in whole seconds, and escapes control and bidirectional characters in node-supplied strings.
 */
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { certificatePath, closedPort } from '../fakes/https.js';
import { getInfo, LND_PUBKEY, PEER_A, channel as lndChannel } from '../fakes/lnd/responses.js';
import { CLN_PUBKEY, getinfo as clnInfo, peerChannel } from '../fakes/cln/responses.js';
import {
  clnNode, createDatabase, jsonDocument, leakedForms, lndNode, nodeState, runCli, schemaErrors, scratch,
  sentinelRune, SENTINEL_MACAROON, SENTINEL_RUNE, snapshotCount, writeConfig, writePolicy, type NodeEntry, type Run,
} from '../helpers/cp016-cli.js';

const SUCCESS = 0;
const INVALID_INPUT = 2;
const CAPABILITY_UNSUPPORTED = 3;
const NODE_UNREACHABLE = 4;
const SAFETY_REFUSAL = 5;

/** A second LND identity, so no two configured nodes share (network, expected_pubkey) (INV-12, nodes UNIQUE). */
const LND_PUBKEY_B = `02${'d7'.repeat(32)}`;

/** What a rebalance needs from each implementation (src/core/capabilities.ts REQUIRED_CAPABILITIES, SPEC §5.1). */
const REQUIRED = {
  lnd: ['CHANNEL_READ', 'PAYMENT_READ', 'PAYMENT_TRACK', 'INVOICE_CREATE', 'INVOICE_CANCEL', 'EXPLICIT_ROUTE_CONTROL'],
  cln: ['CHANNEL_READ', 'PAYMENT_READ', 'PAYMENT_TRACK', 'INVOICE_CREATE', 'INVOICE_CANCEL', 'ASKRENE_LAYER_ROUTING'],
};

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

type Doc = Record<string, unknown>;
const rec = (value: unknown): Doc => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error(`not an object: ${JSON.stringify(value)}`);
  return value as Doc;
};
const list = (value: unknown): unknown[] => {
  if (!Array.isArray(value)) throw new Error(`not an array: ${JSON.stringify(value)}`);
  return value;
};

function json(run: Run, schema: Parameters<typeof schemaErrors>[0]): Doc {
  const doc = jsonDocument(run);
  expect(schemaErrors(schema, doc)).toEqual([]);
  return doc;
}

const lndEntry = (name: string, url: string, credential: string, expectedPubkey = LND_PUBKEY): NodeEntry =>
  ({ name, implementation: 'lnd', url, tlsCert: certificatePath('node'), credential, expectedPubkey });
const clnEntry = (name: string, url: string, credential: string, expectedPubkey = CLN_PUBKEY): NodeEntry =>
  ({ name, implementation: 'cln', url, tlsCert: certificatePath('node'), credential, expectedPubkey });

// CLN v26.06 listpeerchannels items (doc/schemas/listpeerchannels.json): spendable_msat and receivable_msat are
// node-reported. Listed out of key order on purpose.
const peer = (byte: string): string => `02${byte.repeat(32)}`;
function clnChannel(scid: string, n: number, totalMsat: number, toUsMsat: number, spendableMsat: number, receivableMsat: number): Record<string, unknown> {
  return peerChannel({
    peer_id: peer(`a${String(n)}`), short_channel_id: scid, channel_id: `${String(n)}c`.repeat(32), funding_txid: `${String(n)}f`.repeat(32),
    total_msat: totalMsat, to_us_msat: toUsMsat, max_to_us_msat: toUsMsat, spendable_msat: spendableMsat, receivable_msat: receivableMsat,
  });
}
const CLN_CHANNELS = [
  clnChannel('812x4x0', 4, 1_000_000_000, 500_000_000, 450_000_000, 450_000_000),
  clnChannel('812x1x0', 1, 5_000_000_000, 1_250_000_000, 1_199_000_000, 3_699_000_000),
  clnChannel('812x3x0', 3, 3_000_000_000, 100_000_000, 50_000_000, 2_850_000_000),
  clnChannel('812x2x0', 2, 2_000_000_000, 1_880_000_000, 1_820_000_000, 100_000_000),
];
// Operator targets (SPEC §7.3). 812x1x0: receivable 3,699,000,000 above its target, deficit 0 (never negative).
const CLN_TARGETS = {
  'cln-a': {
    '812x1x0': { minInbound: '3000000000' },
    '812x2x0': { minInbound: '400000000' },
    '812x3x0': { minInbound: '2950000000', minOutbound: '250000000' },
  },
};
const EXPECTED_DEFICITS: Record<string, { inbound: string; outbound: string; inTarget: string | null; outTarget: string | null; capacity: string; spendable: string; receivable: string }> = {
  '812x1x0': { inbound: '0', outbound: '0', inTarget: '3000000000', outTarget: null, capacity: '5000000000', spendable: '1199000000', receivable: '3699000000' },
  '812x2x0': { inbound: '300000000', outbound: '0', inTarget: '400000000', outTarget: null, capacity: '2000000000', spendable: '1820000000', receivable: '100000000' },
  '812x3x0': { inbound: '100000000', outbound: '200000000', inTarget: '2950000000', outTarget: '250000000', capacity: '3000000000', spendable: '50000000', receivable: '2850000000' },
  '812x4x0': { inbound: '0', outbound: '0', inTarget: null, outTarget: null, capacity: '1000000000', spendable: '450000000', receivable: '450000000' },
};
const ORDER = {
  none: ['812x1x0', '812x2x0', '812x3x0', '812x4x0'],
  'inbound-deficit': ['812x2x0', '812x3x0', '812x1x0', '812x4x0'],
  outbound: ['812x3x0', '812x1x0', '812x2x0', '812x4x0'],
  capacity: ['812x1x0', '812x3x0', '812x2x0', '812x4x0'],
} as const;

/** Index of each key in `text`, which must be increasing for the keys to appear in that order. */
function positions(text: string, keys: readonly string[]): number[] {
  return keys.map(key => text.indexOf(key));
}

async function clnSetup(): Promise<{ dir: string; config: string; database: string }> {
  const dir = scratch('cp016-ch');
  const cln = await clnNode(dir, open, { channels: CLN_CHANNELS });
  const database = join(dir, 'state', 'fluxwarden.db');
  await createDatabase(database);
  const config = writeConfig(dir, { database, policy: writePolicy(dir, CLN_TARGETS), nodes: [clnEntry('cln-a', cln.url, cln.runeFile)] });
  return { dir, config, database };
}

describe('CP-016 connection settings', () => {
  it('CP-016/B1 connection variables replace the configured node connection as one source', async () => {
    const dir = scratch('cp016-b1');
    const lnd = await lndNode(dir, open, { channels: [lndChannel()] });
    const configured = await lndNode(dir, open);
    const database = join(dir, 'fw.db');
    await createDatabase(database);
    // The configured entry names a closed port and a macaroon the fake refuses.
    const config = writeConfig(dir, { database, nodes: [lndEntry('lnd-a', `https://127.0.0.1:${String(await closedPort())}`, configured.macaroon)] });
    const env = { FLUXWARDEN_URL: lnd.url, FLUXWARDEN_TLS_CERT_PATH: certificatePath('node'), FLUXWARDEN_MACAROON_PATH: lnd.macaroon };
    const run = await runCli(['--json', 'channels', '--config', config, '--node', 'lnd-a'], { env });
    expect(run.status).toBe(SUCCESS);
    const result = rec(json(run, 'channels')['result']);
    const node = rec(list(result['nodes'])[0]);
    const row = rec(list(node['channels'])[0]);
    expect(row['channel']).toBe('892945371103232001');
    // LND liquidity figures are computed by FluxWarden (SPEC §4.2, D11).
    expect(row['confidence']).toBe('DERIVED_ESTIMATE');
    expect(lnd.fake.requests.length).toBeGreaterThan(0);
    expect(lnd.fake.requests.every(request => request.headers['grpc-metadata-macaroon'] === lnd.macaroonHex)).toBe(true);
  }, 60_000);

  it('CP-016/B1 connection flags take precedence over connection variables set for the same settings', async () => {
    const dir = scratch('cp016-b1');
    const lnd = await lndNode(dir, open, { channels: [lndChannel()] });
    const other = await lndNode(dir, open);
    const database = join(dir, 'fw.db');
    await createDatabase(database);
    const config = writeConfig(dir, { database, nodes: [lndEntry('lnd-a', other.url, other.macaroon)] });
    const env = { FLUXWARDEN_URL: other.url, FLUXWARDEN_TLS_CERT_PATH: certificatePath('node'), FLUXWARDEN_MACAROON_PATH: other.macaroon };
    const run = await runCli(['channels', '--config', config, '--node', 'lnd-a', '--url', lnd.url, '--tls-cert-path', certificatePath('node'), '--macaroon-path', lnd.macaroon], { env });
    expect(run.status).toBe(SUCCESS);
    expect(run.stdout).toContain('892945371103232001');
    expect(lnd.fake.requests.length).toBeGreaterThan(0);
    expect(lnd.fake.requests.every(request => request.headers['grpc-metadata-macaroon'] === lnd.macaroonHex)).toBe(true);
    expect(other.fake.connections()).toBe(0);
  }, 60_000);

  it('CP-016/B1 mixing flags with a variable for another setting exits 2 naming the variable and never its value', async () => {
    const dir = scratch('cp016-b1');
    const lnd = await lndNode(dir, open);
    const database = join(dir, 'fw.db');
    await createDatabase(database);
    const config = writeConfig(dir, { database, nodes: [lndEntry('lnd-a', lnd.url, lnd.macaroon)] });
    const marker = join(dir, 'mk7f3c9e2a51d8b6040.macaroon');
    const env = { FLUXWARDEN_MACAROON_PATH: marker };
    const args = ['nodes', 'inspect', 'lnd-a', '--config', config, '--url', lnd.url, '--tls-cert-path', certificatePath('node')];
    const text = await runCli(args, { env });
    expect(text.status).toBe(INVALID_INPUT);
    expect(text.stderr).toContain('FLUXWARDEN_MACAROON_PATH');
    expect(text.stdout + text.stderr).not.toContain('mk7f3c9e2a51d8b6040');
    const doc = json(await runCli(['--json', ...args], { env }), 'nodes-inspect');
    expect(rec(doc['error'])['code']).toBe(INVALID_INPUT);
    expect(String(rec(doc['error'])['message'])).toContain('FLUXWARDEN_MACAROON_PATH');
    expect(JSON.stringify(doc)).not.toContain('mk7f3c9e2a51d8b6040');
    expect(lnd.fake.connections()).toBe(0);
  }, 60_000);

  it('CP-016/B1 a connection variable with a command over every node exits 2 and contacts no node', async () => {
    const dir = scratch('cp016-b1');
    const lnd = await lndNode(dir, open);
    const cln = await clnNode(dir, open);
    const config = writeConfig(dir, { database: join(dir, 'fw.db'), nodes: [lndEntry('lnd-a', lnd.url, lnd.macaroon), clnEntry('cln-a', cln.url, cln.runeFile)] });
    const run = await runCli(['doctor', '--config', config], { env: { FLUXWARDEN_URL: lnd.url } });
    expect(run.status).toBe(INVALID_INPUT);
    expect(run.stderr).toContain('FLUXWARDEN_URL');
    expect(lnd.fake.connections() + cln.fake.connections()).toBe(0);
  }, 60_000);

  it('CP-016/B1 a credential-looking value in any argument exits 2 before any node call and is never echoed', async () => {
    const dir = scratch('cp016-b1');
    const lnd = await lndNode(dir, open);
    await createDatabase(join(dir, 'fw.db'));
    const config = writeConfig(dir, { database: join(dir, 'fw.db'), nodes: [lndEntry('lnd-a', lnd.url, lnd.macaroon)] });
    const macaroon = readFileSync(SENTINEL_MACAROON);
    const rune = Buffer.from(sentinelRune(), 'utf8');
    const preimage = randomBytes(32);
    // SECURITY §3.3: a macaroon (hex), a rune (base64url text) and a 64-hex run, wherever they appear on the command line.
    const values: { name: string; text: string; secret: Buffer }[] = [
      { name: 'macaroon-hex', text: macaroon.toString('hex'), secret: macaroon },
      { name: 'rune', text: rune.toString('utf8'), secret: rune },
      { name: 'hex-64', text: preimage.toString('hex'), secret: preimage },
    ];
    const placements = (value: string): string[][] => [
      ['nodes', 'inspect', 'lnd-a', '--config', config, '--url', lnd.url, '--tls-cert-path', certificatePath('node'), '--macaroon-path', value],
      ['nodes', 'inspect', value, '--config', config],
      ['channels', '--config', config, '--node', value],
    ];
    for (const { name, text, secret } of values) {
      for (const args of placements(text)) {
        for (const asJson of [false, true]) {
          const run = await runCli([...(asJson ? ['--json'] : []), ...args]);
          expect(run.status, `${name} ${args[0] ?? ''} ${args[1] ?? ''}`).toBe(INVALID_INPUT);
          expect(leakedForms(run.stdout + run.stderr, secret), name).toEqual([]);
        }
      }
    }
    expect(lnd.fake.connections()).toBe(0);
    const byPath = await runCli(['nodes', 'inspect', 'lnd-a', '--config', config, '--url', lnd.url, '--tls-cert-path', certificatePath('node'), '--macaroon-path', lnd.macaroon]);
    expect(byPath.status).toBe(SUCCESS);
  }, 120_000);
});

describe('CP-016 environment and Node flags', () => {
  it('CP-016/B2 NODE_OPTIONS and NODE_DEBUG naming a network module, in any case, exit 2 before any node is contacted', async () => {
    const dir = scratch('cp016-b2');
    const lnd = await lndNode(dir, open);
    const config = writeConfig(dir, { database: join(dir, 'fw.db'), nodes: [lndEntry('lnd-a', lnd.url, lnd.macaroon)] });
    const refused: Record<string, string>[] = [
      { NODE_OPTIONS: '--max-old-space-size=256' },
      { NODE_DEBUG: 'Https' },
      { NODE_DEBUG: 'fs,tls' },
      { NODE_DEBUG: 'ne*' },
      { node_debug: 'http' },
    ];
    for (const env of refused) {
      const run = await runCli(['doctor', '--config', config], { env });
      expect(run.status, JSON.stringify(env)).toBe(INVALID_INPUT);
      expect(run.stdout).toBe('');
    }
    const doc = json(await runCli(['--json', 'doctor', '--config', config], { env: { NODE_DEBUG: 'net' } }), 'doctor');
    expect(rec(doc['error'])['code']).toBe(INVALID_INPUT);
    expect(lnd.fake.connections()).toBe(0);
    // NODE_DEBUG for a module that prints no request data is allowed (SPEC §10.1 names http, https, tls, net).
    expect((await runCli(['doctor', '--config', config], { env: { NODE_DEBUG: 'worker' } })).status).toBe(SUCCESS);
  }, 90_000);

  it('CP-016/B2 diagnostic Node flags exit 2 before any node is contacted and sizing flags are allowed', async () => {
    const dir = scratch('cp016-b2');
    const lnd = await lndNode(dir, open);
    const config = writeConfig(dir, { database: join(dir, 'fw.db'), nodes: [lndEntry('lnd-a', lnd.url, lnd.macaroon)] });
    const keylog = join(dir, 'keys.log');
    for (const flag of [`--tls-keylog=${keylog}`, '--cpu_prof', '--inspect-port=0']) {
      const run = await runCli(['doctor', '--config', config], { nodeArgs: [flag] });
      expect(run.status, flag).toBe(INVALID_INPUT);
    }
    expect(lnd.fake.connections()).toBe(0);
    expect(existsSync(keylog) ? readFileSync(keylog).byteLength : 0).toBe(0);
    expect((await runCli(['doctor', '--config', config], { nodeArgs: ['--max-old-space-size=256'] })).status).toBe(SUCCESS);
  }, 60_000);
});

describe('CP-016 node failures', () => {
  it('CP-016/B3 TLS, authentication and transport failures exit 4 and print no credential in any encoding', async () => {
    const dir = scratch('cp016-b3');
    const macaroon = readFileSync(SENTINEL_MACAROON);
    const rune = Buffer.from(sentinelRune(), 'utf8');
    const hex = macaroon.toString('hex');
    // A node whose certificate is not the pinned one (SECURITY §3.3: TLS pinned to the configured certificate).
    const wrongCert = await lndNode(dir, open, { identity: 'other', macaroonHex: hex });
    // A proxy answering 401 and echoing the credential it received (RFC 9110 §15.5.2).
    const echoLnd = await lndNode(dir, open, {
      macaroonHex: hex,
      routes: { 'GET /v1/getinfo': (ctx, f) => { f.raw(ctx, 'proxy-status', 401, JSON.stringify({ code: 16, message: `denied ${hex} ${macaroon.toString('base64')}` })); } },
    });
    const echoCln = await clnNode(dir, open, {
      rune: sentinelRune(),
      methods: { getinfo: (ctx, f) => { f.raw(ctx, 'rune-invalid', 401, JSON.stringify({ code: 1502, message: `Rune is not valid: ${sentinelRune()}`, data: null })); } },
    });
    const cases: { name: string; entry: NodeEntry; secret: Buffer }[] = [
      { name: 'tls', entry: lndEntry('lnd-tls', wrongCert.url, SENTINEL_MACAROON), secret: macaroon },
      { name: 'auth-lnd', entry: lndEntry('lnd-auth', echoLnd.url, SENTINEL_MACAROON), secret: macaroon },
      { name: 'auth-cln', entry: clnEntry('cln-auth', echoCln.url, SENTINEL_RUNE), secret: rune },
      { name: 'transport', entry: lndEntry('lnd-down', `https://127.0.0.1:${String(await closedPort())}`, SENTINEL_MACAROON), secret: macaroon },
    ];
    for (const { name, entry, secret } of cases) {
      const database = join(dir, `${name}.db`);
      await createDatabase(database);
      const config = writeConfig(scratch(`cp016-b3-${name}`), { database, nodes: [entry] });
      const text = await runCli(['nodes', 'inspect', entry.name, '--config', config]);
      expect(text.status, name).toBe(NODE_UNREACHABLE);
      expect(leakedForms(text.stdout + text.stderr, secret), name).toEqual([]);
      const run = await runCli(['--json', 'doctor', '--config', config]);
      expect(run.status, name).toBe(NODE_UNREACHABLE);
      expect(rec(json(run, 'doctor')['error'])['code']).toBe(NODE_UNREACHABLE);
      expect(leakedForms(run.stdout + run.stderr, secret), name).toEqual([]);
    }
    // The pinned-certificate failure ends before any request reaches the node.
    expect(wrongCert.fake.requests).toHaveLength(0);
  }, 120_000);

  it('CP-016/B3 doctor checks every node and exits 4 before 3 when one node is unreachable and another lacks a capability', async () => {
    const dir = scratch('cp016-b3');
    const noRouter = await lndNode(dir, open, { routes: { 'GET /v2/router/mccfg': (ctx, f) => { f.grpcError(ctx, 'route-not-found', 5, 'Not Found'); } } });
    const config = writeConfig(dir, {
      database: join(dir, 'fw.db'),
      nodes: [lndEntry('lnd-down', `https://127.0.0.1:${String(await closedPort())}`, noRouter.macaroon, LND_PUBKEY_B), lndEntry('lnd-norouter', noRouter.url, noRouter.macaroon)],
    });
    const run = await runCli(['doctor', '--config', config]);
    expect(run.status).toBe(NODE_UNREACHABLE);
    // DR4: the failing first node does not stop the check of the second.
    expect(noRouter.fake.requests.some(request => request.url === '/v1/getinfo')).toBe(true);
    expect(run.stdout + run.stderr).toContain('lnd-down');
    expect(run.stdout + run.stderr).toContain('lnd-norouter');
  }, 60_000);

  it('CP-016/B4 a node with another pubkey or another network exits 5 at step identity and is quarantined', async () => {
    const dir = scratch('cp016-b4');
    const wrongKey = await lndNode(dir, open, { info: getInfo({ pubkey: PEER_A }) });
    const wrongNet = await clnNode(dir, open, { info: clnInfo({ network: 'signet' }) });
    const database = join(dir, 'fw.db');
    await createDatabase(database);
    const config = writeConfig(dir, { database, nodes: [lndEntry('lnd-a', wrongKey.url, wrongKey.macaroon), clnEntry('cln-a', wrongNet.url, wrongNet.runeFile)] });
    for (const name of ['lnd-a', 'cln-a']) {
      const run = await runCli(['--json', 'nodes', 'inspect', name, '--config', config]);
      expect(run.status, name).toBe(SAFETY_REFUSAL);
      const error = rec(json(run, 'nodes-inspect')['error']);
      expect(error['code']).toBe(SAFETY_REFUSAL);
      expect(error['step']).toBe('identity');
      expect(nodeState(database, name)).toBe('QUARANTINED');
    }
    const listed = json(await runCli(['--json', 'nodes', 'list', '--config', config]), 'nodes-list');
    expect(list(rec(listed['result'])['nodes']).map(row => rec(row)['state'])).toEqual(['QUARANTINED', 'QUARANTINED']);
  }, 60_000);

  it('CP-016/B4 two configured nodes with the same network and expected pubkey are refused with 2 before any node call', async () => {
    const dir = scratch('cp016-b4');
    const a = await lndNode(dir, open);
    const b = await lndNode(dir, open);
    const database = join(dir, 'fw.db');
    await createDatabase(database);
    // INV-12 pins each configured node to one identity; the nodes table is UNIQUE (expected_network, expected_pubkey).
    const config = writeConfig(dir, { database, nodes: [lndEntry('lnd-a', a.url, a.macaroon), lndEntry('lnd-b', b.url, b.macaroon)] });
    for (const args of [['doctor'], ['nodes', 'list'], ['nodes', 'inspect', 'lnd-a']]) {
      const text = await runCli([...args, '--config', config]);
      expect(text.status, args.join(' ')).toBe(INVALID_INPUT);
      expect(text.stderr).toContain('lnd-a');
      expect(text.stderr).toContain('lnd-b');
    }
    const doc = json(await runCli(['--json', 'doctor', '--config', config]), 'doctor');
    expect(rec(doc['error'])['code']).toBe(INVALID_INPUT);
    expect(a.fake.connections() + b.fake.connections()).toBe(0);
  }, 60_000);

  it('CP-016/B4 an unsupported network exits 3 and doctor ranks a missing capability before an identity mismatch', async () => {
    const dir = scratch('cp016-b4');
    const liquid = await clnNode(dir, open, { info: clnInfo({ network: 'liquid-regtest' }) });
    const wrongKey = await lndNode(dir, open, { info: getInfo({ pubkey: PEER_A }) });
    const noRouter = await lndNode(dir, open, {
      info: getInfo({ pubkey: LND_PUBKEY_B }),
      routes: { 'GET /v2/router/mccfg': (ctx, f) => { f.grpcError(ctx, 'route-not-found', 5, 'Not Found'); } },
    });
    await createDatabase(join(dir, 'a.db'));
    const unsupported = writeConfig(scratch('cp016-b4-net'), { database: join(dir, 'a.db'), nodes: [clnEntry('cln-l', liquid.url, liquid.runeFile)] });
    expect((await runCli(['nodes', 'inspect', 'cln-l', '--config', unsupported])).status).toBe(CAPABILITY_UNSUPPORTED);
    const ranked = writeConfig(scratch('cp016-b4-rank'), {
      database: join(dir, 'b.db'),
      nodes: [lndEntry('lnd-key', wrongKey.url, wrongKey.macaroon), lndEntry('lnd-norouter', noRouter.url, noRouter.macaroon, LND_PUBKEY_B)],
    });
    const run = await runCli(['--json', 'doctor', '--config', ranked]);
    expect(run.status).toBe(CAPABILITY_UNSUPPORTED);
    expect(rec(json(run, 'doctor')['error'])['code']).toBe(CAPABILITY_UNSUPPORTED);
  }, 60_000);

  it('CP-016/B5 a node without the router service fails inspect with 3 and names each missing capability', async () => {
    const dir = scratch('cp016-b5');
    // grpc-gateway answers an unregistered route with NotFound (runtime/mux.go#L451): routerrpc is not running.
    const noRouter = await lndNode(dir, open, { routes: { 'GET /v2/router/mccfg': (ctx, f) => { f.grpcError(ctx, 'route-not-found', 5, 'Not Found'); } } });
    await createDatabase(join(dir, 'fw.db'));
    const config = writeConfig(dir, { database: join(dir, 'fw.db'), nodes: [lndEntry('lnd-a', noRouter.url, noRouter.macaroon)] });
    const text = await runCli(['nodes', 'inspect', 'lnd-a', '--capabilities', '--config', config]);
    expect(text.status).toBe(CAPABILITY_UNSUPPORTED);
    const out = text.stdout + text.stderr;
    for (const name of ['PAYMENT_TRACK', 'EXPLICIT_ROUTE_CONTROL', 'CHANNEL_READ']) expect(out).toContain(name);
    const run = await runCli(['--json', 'nodes', 'inspect', 'lnd-a', '--capabilities', '--config', config]);
    expect(run.status).toBe(CAPABILITY_UNSUPPORTED);
    const message = String(rec(json(run, 'nodes-inspect')['error'])['message']);
    expect(message).toContain('PAYMENT_TRACK');
    expect(message).toContain('EXPLICIT_ROUTE_CONTROL');
  }, 60_000);

  it('CP-016/B5 doctor exits 3 for an LND version below 0.21 while the other node passes', async () => {
    const dir = scratch('cp016-b5');
    // SPEC §5.2 H5: below 0.21 -> CAPABILITY_UNSUPPORTED.
    const old = await lndNode(dir, open, { info: getInfo({ version: '0.20.1-beta commit=v0.20.1-beta' }) });
    const cln = await clnNode(dir, open);
    const config = writeConfig(dir, { database: join(dir, 'fw.db'), nodes: [lndEntry('lnd-old', old.url, old.macaroon), clnEntry('cln-a', cln.url, cln.runeFile)] });
    const run = await runCli(['--json', 'doctor', '--config', config]);
    expect(run.status).toBe(CAPABILITY_UNSUPPORTED);
    const error = rec(json(run, 'doctor')['error']);
    expect(error['code']).toBe(CAPABILITY_UNSUPPORTED);
    expect(String(error['message'])).toContain('lnd-old');
    expect(cln.fake.requests.some(request => request.url === '/v1/getinfo')).toBe(true);
  }, 60_000);
});

describe('CP-016 output', () => {
  it('CP-016/B6 doctor creates the database, probes every node and reports them by name', async () => {
    const dir = scratch('cp016-b6');
    const lnd = await lndNode(dir, open);
    const cln = await clnNode(dir, open);
    const database = join(dir, 'state', 'fluxwarden.db');
    const config = writeConfig(dir, { database, nodes: [lndEntry('lnd-a', lnd.url, lnd.macaroon), clnEntry('cln-a', cln.url, cln.runeFile)] });
    const run = await runCli(['--json', 'doctor', '--config', config]);
    expect(run.status).toBe(SUCCESS);
    expect(existsSync(database)).toBe(true);
    const result = rec(json(run, 'doctor')['result']);
    expect(result['node_version']).toBe(process.versions.node);
    const nodes = list(result['nodes']).map(rec);
    expect(nodes.map(node => node['name'])).toEqual(['cln-a', 'lnd-a']);
    expect(nodes.map(node => node['pubkey'])).toEqual([CLN_PUBKEY, LND_PUBKEY]);
    expect(nodes.map(node => node['network'])).toEqual(['regtest', 'regtest']);
    expect(nodes.map(node => node['block_height'])).toEqual([812, 812]);
    for (const node of nodes) {
      const capabilities = list(node['capabilities']).map(String);
      expect(capabilities).toEqual([...capabilities].sort());
      expect(capabilities).toEqual(expect.arrayContaining(REQUIRED[node['implementation'] === 'lnd' ? 'lnd' : 'cln']));
    }
    const text = await runCli(['doctor', '--config', config]);
    expect(text.status).toBe(SUCCESS);
    expect(text.stdout).toContain('lnd-a');
    expect(text.stdout).toContain('cln-a');
  }, 60_000);

  it('CP-016/B6 nodes list prints stored rows without contacting a node, the same bytes on every run', async () => {
    const dir = scratch('cp016-b6');
    const lnd = await lndNode(dir, open);
    const cln = await clnNode(dir, open);
    const database = join(dir, 'fw.db');
    await createDatabase(database);
    const config = writeConfig(dir, { database, nodes: [lndEntry('lnd-a', lnd.url, lnd.macaroon), clnEntry('cln-a', cln.url, cln.runeFile)] });
    const before = rec(json(await runCli(['--json', 'nodes', 'list', '--config', config]), 'nodes-list')['result']);
    expect(list(before['nodes']).map(rec).map(row => [row['name'], row['state'], row['observed_version'], row['capabilities'], row['last_probed_at']]))
      .toEqual([['cln-a', 'OFFLINE', null, null, null], ['lnd-a', 'OFFLINE', null, null, null]]);
    expect(lnd.fake.connections() + cln.fake.connections()).toBe(0);
    expect((await runCli(['doctor', '--config', config])).status).toBe(SUCCESS);
    const connections = lnd.fake.connections() + cln.fake.connections();
    const first = await runCli(['--json', 'nodes', 'list', '--config', config]);
    const rows = list(rec(json(first, 'nodes-list')['result'])['nodes']).map(rec);
    expect(rows.map(row => [row['name'], row['implementation'], row['expected_pubkey'], row['state'], row['observed_version']])).toEqual([
      ['cln-a', 'cln', CLN_PUBKEY, 'ONLINE', 'v26.06.9'],
      ['lnd-a', 'lnd', LND_PUBKEY, 'ONLINE', '0.21.4-beta commit=v0.21.4-beta'],
    ]);
    expect(list(rows[1]?.['capabilities'])).toEqual(expect.arrayContaining(REQUIRED.lnd));
    const second = await runCli(['--json', 'nodes', 'list', '--config', config]);
    expect(second.stdout).toBe(first.stdout);
    const text = await runCli(['nodes', 'list', '--config', config]);
    expect(text.status).toBe(SUCCESS);
    expect(text.stdout).toContain('ONLINE');
    expect(lnd.fake.connections() + cln.fake.connections()).toBe(connections);
  }, 60_000);

  it('CP-016/B6 nodes inspect reports identity and, with --capabilities, the sorted capability set', async () => {
    const dir = scratch('cp016-b6');
    const lnd = await lndNode(dir, open);
    await createDatabase(join(dir, 'fw.db'));
    const config = writeConfig(dir, { database: join(dir, 'fw.db'), nodes: [lndEntry('lnd-a', lnd.url, lnd.macaroon)] });
    const plain = rec(json(await runCli(['--json', 'nodes', 'inspect', 'lnd-a', '--config', config]), 'nodes-inspect')['result']);
    expect(plain).toMatchObject({ name: 'lnd-a', implementation: 'lnd', alias: 'lnd-r', pubkey: LND_PUBKEY, network: 'regtest', version: '0.21.4-beta commit=v0.21.4-beta', synced: true, block_height: 812, capabilities: null });
    const full = rec(json(await runCli(['--json', 'nodes', 'inspect', 'lnd-a', '--capabilities', '--config', config]), 'nodes-inspect')['result']);
    const capabilities = list(full['capabilities']).map(String);
    expect(capabilities).toEqual([...capabilities].sort());
    expect(capabilities).toEqual(expect.arrayContaining(REQUIRED.lnd));
    const text = await runCli(['nodes', 'inspect', 'lnd-a', '--capabilities', '--config', config]);
    expect(text.status).toBe(SUCCESS);
    for (const value of [LND_PUBKEY, 'regtest', '0.21.4-beta', 'EXPLICIT_ROUTE_CONTROL']) expect(text.stdout).toContain(value);
  }, 60_000);

  it('CP-016/B6 channels prints targets and deficits as msat strings, sorts by each key and stores one snapshot per channel', async () => {
    const { config, database } = await clnSetup();
    for (const sort of ['inbound-deficit', 'outbound', 'capacity'] as const) {
      const run = await runCli(['--json', 'channels', '--config', config, '--node', 'cln-a', '--sort', sort]);
      expect(run.status, sort).toBe(SUCCESS);
      const result = rec(json(run, 'channels')['result']);
      expect(result['sort']).toBe(sort);
      const nodes = list(result['nodes']).map(rec);
      expect(nodes.map(node => node['name'])).toEqual(['cln-a']);
      const rows = list(nodes[0]?.['channels']).map(rec);
      expect(rows.map(row => row['channel']), sort).toEqual(ORDER[sort]);
      for (const row of rows) {
        const want = EXPECTED_DEFICITS[String(row['channel'])];
        expect(row).toMatchObject({
          capacity_msat: want?.capacity, spendable_msat: want?.spendable, receivable_msat: want?.receivable,
          inbound_target_msat: want?.inTarget, inbound_deficit_msat: want?.inbound,
          outbound_target_msat: want?.outTarget, outbound_deficit_msat: want?.outbound,
          confidence: 'NODE_REPORTED', pending_in_msat: '0', pending_out_msat: '0', state: 'ACTIVE',
        });
        // CLN documents spendable and receivable as estimates (listpeerchannels.json); the caveat travels with them.
        expect(String(row['caveat'])).toMatch(/estimate/i);
      }
      const text = await runCli(['channels', '--config', config, '--node', 'cln-a', '--sort', sort]);
      expect(text.status, sort).toBe(SUCCESS);
      const at = positions(text.stdout, ORDER[sort]);
      expect(at.every(index => index >= 0), sort).toBe(true);
      expect(at, sort).toEqual([...at].sort((a, b) => a - b));
      expect(text.stdout).toContain('NODE_REPORTED');
    }
    const unsorted = rec(json(await runCli(['--json', 'channels', '--config', config, '--node', 'cln-a']), 'channels')['result']);
    expect(unsorted['sort']).toBeNull();
    expect(list(rec(list(unsorted['nodes'])[0])['channels']).map(row => rec(row)['channel'])).toEqual(ORDER.none);
    // Seven runs, four channels each (CH3).
    expect(snapshotCount(database, 'cln-a')).toBe(28);
  }, 120_000);

  it('CP-016/B6 an unknown sort key or node name exits 2 before any node is contacted', async () => {
    const dir = scratch('cp016-b6');
    const cln = await clnNode(dir, open, { channels: CLN_CHANNELS });
    const database = join(dir, 'fw.db');
    await createDatabase(database);
    const config = writeConfig(dir, { database, nodes: [clnEntry('cln-a', cln.url, cln.runeFile)] });
    expect((await runCli(['channels', '--config', config, '--node', 'cln-a', '--sort', 'fee'])).status).toBe(INVALID_INPUT);
    expect((await runCli(['channels', '--config', config, '--node', 'cln-b'])).status).toBe(INVALID_INPUT);
    const run = await runCli(['--json', 'nodes', 'inspect', 'cln-b', '--config', config]);
    expect(run.status).toBe(INVALID_INPUT);
    expect(rec(json(run, 'nodes-inspect')['error'])['code']).toBe(INVALID_INPUT);
    expect(cln.fake.connections()).toBe(0);
    expect((await runCli(['channels', '--config', config, '--node', 'cln-a', '--sort', 'capacity'])).status).toBe(SUCCESS);
  }, 60_000);

  it('CP-016/B7 two channels runs over the same node data print byte-identical text', async () => {
    const { config, database } = await clnSetup();
    const first = await runCli(['channels', '--config', config, '--node', 'cln-a', '--sort', 'inbound-deficit']);
    const second = await runCli(['channels', '--config', config, '--node', 'cln-a', '--sort', 'inbound-deficit']);
    expect(first.status).toBe(SUCCESS);
    expect(first.stdout.length).toBeGreaterThan(0);
    expect(second.stdout).toBe(first.stdout);
    expect(snapshotCount(database, 'cln-a')).toBe(8);
  }, 60_000);

  it('CP-016/B8 a hostile alias and hostile node error text reach the terminal escaped', async () => {
    const dir = scratch('cp016-b8');
    const hostile = 'evil\u001b[2J\u001b[31mred‮abc⁦x\r\nFAKE: ok\u0007';
    const lnd = await lndNode(dir, open, { info: { ...getInfo(), alias: hostile } });
    const noisy = 'boom\u001b[31m‮' + 'x'.repeat(5000);
    const failing = await lndNode(dir, open, { routes: { 'GET /v1/getinfo': (ctx, f) => { f.grpcError(ctx, 'grpc-error', 2, noisy); } } });
    await createDatabase(join(dir, 'fw.db'));
    const config = writeConfig(dir, { database: join(dir, 'fw.db'), nodes: [lndEntry('lnd-a', lnd.url, lnd.macaroon), lndEntry('lnd-b', failing.url, failing.macaroon, LND_PUBKEY_B)] });
    const run = await runCli(['nodes', 'inspect', 'lnd-a', '--config', config]);
    expect(run.status).toBe(SUCCESS);
    const out = run.stdout + run.stderr;
    expect(out).toContain('evil');
    expect(out).toContain('red');
    for (const raw of ['\u001b', '‮', '⁦', '\u0007', '\r']) expect(out.includes(raw), JSON.stringify(raw)).toBe(false);
    expect(out.split('\n').some(line => line.startsWith('FAKE: ok'))).toBe(false);
    const doc = json(await runCli(['--json', 'nodes', 'inspect', 'lnd-a', '--config', config]), 'nodes-inspect');
    expect(typeof rec(doc['result'])['alias']).toBe('string');
    const failed = await runCli(['nodes', 'inspect', 'lnd-b', '--config', config]);
    expect(failed.status).toBe(NODE_UNREACHABLE);
    const err = failed.stdout + failed.stderr;
    expect(err.includes('\u001b') || err.includes('‮')).toBe(false);
    // SECURITY §5: node error text is bounded to 1 KiB.
    expect(err).not.toContain('x'.repeat(1100));
  }, 60_000);
});
