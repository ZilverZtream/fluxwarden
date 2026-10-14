import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createECDH } from 'node:crypto';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { asRecord, readJson, repoRoot } from './cli.js';
import type { CommandOptions, Owner, Result, Run } from './cp006-lab.js';

export const nodes = ['lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m'];
export const services = ['bitcoind', ...nodes, 'toxiproxy'];
export const topology = {
  channels: [
    { id: '1', from: 'lnd-p', to: 'lnd-r', capacity_msat: '5000000000', push_msat: '1000000000' },
    { id: '2', from: 'lnd-r', to: 'cln-m', capacity_msat: '5000000000', push_msat: '1250000000' },
    { id: '3', from: 'lnd-r', to: 'cln-r', capacity_msat: '5000000000', push_msat: '2500000000' },
    { id: '4', from: 'cln-p', to: 'cln-r', capacity_msat: '5000000000', push_msat: '1000000000' },
    { id: '5', from: 'cln-r', to: 'cln-m', capacity_msat: '5000000000', push_msat: '1250000000' },
  ],
  policies: { base_fee_msat: '1000', fee_rate_ppm: '1000', lnd_cltv_delta: '80', cln_cltv_delta: '34' },
};
const expectations = asRecord(readJson('test/fixtures/cp006-expectations.json'), 'independent expectations');
const pins = asRecord(expectations['imagePins'], 'independent image pins');
export const imagePins: Record<string, string> = Object.fromEntries(services.map(service => [service, String(pins[service.startsWith('lnd-') ? 'lnd' : service.startsWith('cln-') ? 'cln' : service])]));

export interface Observation { argv: string[]; command: CommandOptions; node: string; method: string; ready: boolean }
export interface ScriptOptions {
  delayed?: boolean;
  never?: 'chain' | 'balance' | 'peers' | 'mempool' | 'active' | 'graph' | 'layers';
  fail?: string;
  exception?: string;
  timeout?: string;
  malformed?: string;
  abort?: { method: string; controller: AbortController };
  network?: { node: string; value: unknown };
  version?: { node: string; value: unknown };
  onCommand?: (observation: Observation) => Promise<void>;
}

/** Raw CLN shapes follow ElementsProject/lightning v26.06.9 doc/schemas:
 * getinfo/listchannels/listpeerchannels/askrene-listlayers/newaddr/listfunds/listpeers/fundchannel/setchannel.
 * Exact URLs and content hashes are committed in cp006-reference-sources.json. LND command shapes
 * follow macwarden@25bbfa4 examples/payment-lab/lab/setup.ts and test/fixture/fixture.mjs.
 * These synthetic controls establish sequencing only; they are not recordings or node-fact evidence. */
export function observedLab(owner: Owner, script: ScriptOptions = {}): {
  run: Run; observations: Observation[]; privateFiles: Map<string, Buffer>; pubkeys: Record<string, string>; clock: () => number; delay: (ms: number, signal?: AbortSignal) => Promise<void>; delays: number[]; maxMutating: () => number;
} {
  const sentinelDir = process.env['FLUXWARDEN_SENTINEL_DIR'];
  if (!sentinelDir) throw new Error('private sentinel root required');
  const registry = readJson('test/sentinels.json');
  if (!Array.isArray(registry) || registry.length !== 5) throw new Error('five disposable sentinel files are required');
  for (const entry of registry as unknown[]) {
    if (typeof entry !== 'string' || !/^test\/sentinels\/[a-z0-9-]+\.(bin|pem|txt)$/.test(entry)) throw new Error('invalid sentinel path');
    const kind = entry.split('/').at(-1)?.split('.')[0] ?? '';
    writeFileSync(join(sentinelDir, `product-${kind}.bin`), readFileSync(join(repoRoot, entry)), { mode: 0o600 });
  }
  const observations: Observation[] = [], privateFiles = new Map<string, Buffer>(), delays: number[] = [];
  const pubkeys: Record<string, string> = {};
  for (const node of nodes) { const pair = createECDH('secp256k1'); pair.generateKeys(); pubkeys[node] = pair.getPublicKey('hex', 'compressed'); }
  let height = 0, time = 0, running = false, funds = 0;
  const policyNodes = new Set<string>();
  const opened = new Set<string>(), connected = new Set<string>(), counts = new Map<string, number>();
  const count = (key: string): number => { const next = (counts.get(key) ?? 0) + 1; counts.set(key, next); return next; };
  const ready = (phase: ScriptOptions['never'], key: string): boolean => script.never !== phase && (!script.delayed || count(key) > 1);
  const scid = (id: string): string => `108x${id}x0`;
  const lndScid = (id: string): string => ((108n << 40n) | (BigInt(id) << 16n)).toString();
  const result = (value: unknown, exitCode = 0): Result => ({ exitCode, stdout: typeof value === 'string' ? value : JSON.stringify(value), stderr: exitCode === 0 ? '' : 'synthetic observed-state transport failure' });
  const allLocal = (node: string) => topology.channels.filter(channel => channel.from === node || channel.to === node);
  const local = (node: string, active: boolean) => allLocal(node).filter(channel => opened.has(channel.id)).map(channel => {
    const peer = channel.from === node ? channel.to : channel.from;
    return node.startsWith('lnd-')
      ? { active, remote_pubkey: pubkeys[peer], initiator: channel.from === node, chan_id: lndScid(channel.id), scid: lndScid(channel.id), capacity: '5000000', local_balance: channel.from === node ? ((5000000000n - BigInt(channel.push_msat)) / 1000n).toString() : (BigInt(channel.push_msat) / 1000n).toString(), channel_point: `${channel.id.padStart(64, '0')}:0`, pending_htlcs: [] }
      : { state: active ? 'CHANNELD_NORMAL' : 'CHANNELD_AWAITING_LOCKIN', opener: channel.from === node ? 'local' : 'remote', features: [], peer_connected: true, peer_id: pubkeys[peer], short_channel_id: active ? scid(channel.id) : undefined, channel_id: channel.id.padStart(64, '0'), funding_txid: channel.id.padStart(64, '0'), funding_outnum: 0, total_msat: 5000000000, to_us_msat: channel.from === node ? Number(5000000000n - BigInt(channel.push_msat)) : Number(channel.push_msat), htlcs: [] };
  });
  const graph = (node: string, complete: boolean) => {
    const channels = topology.channels.filter(channel => opened.has(channel.id));
    if (node.startsWith('lnd-')) return { edges: channels.map((channel, index) => ({ channel_id: lndScid(channel.id), node1_pub: pubkeys[channel.from], node2_pub: pubkeys[channel.to], capacity: '5000000', node1_policy: { fee_base_msat: policyNodes.has(channel.from) ? '1000' : '0', fee_rate_milli_msat: '1000', time_lock_delta: channel.from.startsWith('lnd-') ? 80 : 34, disabled: false, last_update: 1738500000 }, node2_policy: !complete && index === 4 ? null : { fee_base_msat: policyNodes.has(channel.to) ? '1000' : '0', fee_rate_milli_msat: '1000', time_lock_delta: channel.to.startsWith('lnd-') ? 80 : 34, disabled: false, last_update: 1738500000 } })) };
    return { channels: channels.flatMap(channel => [[channel.from, channel.to], [channel.to, channel.from]].map(([source, destination], direction) => ({ source: pubkeys[source ?? ''], destination: pubkeys[destination ?? ''], short_channel_id: scid(channel.id), direction, public: true, amount_msat: 5000000000, message_flags: 1, channel_flags: direction, active: true, last_update: 1738500000, base_fee_millisatoshi: policyNodes.has(source ?? '') ? 1000 : 0, fee_per_millionth: 1000, delay: source?.startsWith('lnd-') ? 80 : 34, htlc_minimum_msat: 0, htlc_maximum_msat: 4900000000, features: '' }))).slice(0, complete ? 10 : 9) };
  };
  const execute: Run = async (argv, command) => {
    const args = [...argv], exec = args.indexOf('exec'), node = exec >= 0 ? args[exec + 2] ?? '' : '';
    const cli = args.findIndex(arg => ['lncli', 'lightning-cli', 'bitcoin-cli'].includes(arg));
    const methods = ['getinfo', 'state', 'getblockcount', 'getblockchaininfo', 'getnetworkinfo', 'createwallet', 'listwallets', 'getnewaddress', 'generatetoaddress', 'sendtoaddress', 'getmempoolinfo', 'getrawmempool', 'walletbalance', 'newaddress', 'newaddr', 'listfunds', 'connect', 'listpeers', 'openchannel', 'fundchannel', 'listchannels', 'listpeerchannels', 'pendingchannels', 'describegraph', 'getchaninfo', 'updatechanpolicy', 'setchannel', 'askrene-listlayers'];
    const method = cli >= 0 ? args.slice(cli + 1).find(arg => methods.includes(arg)) ?? 'unknown-rpc' : args.includes('up') ? 'up' : args.includes('down') ? 'down' : args.includes('ps') ? 'ps' : args.includes('inspect') ? 'inspect' : args.includes('cp') ? 'cp' : args.includes('cat') ? 'cat' : args.includes('info') ? 'docker-info' : args.includes('volume') ? 'volumes' : 'other';
    const observation: Observation = { argv: args, command, node, method, ready: true }; observations.push(observation);
    const argument = (name: string): string | undefined => { const flag = args.find(arg => arg.startsWith(`${name}=`)); if (flag) return flag.slice(name.length + 1); const index = args.indexOf(name); return index >= 0 ? args[index + 1] : undefined; };
    await script.onCommand?.(observation);
    const matches = (target: string | undefined): boolean => target === method || (target === 'getmempoolinfo' && method === 'getrawmempool') || (target === 'describegraph' && method === 'getchaninfo');
    if (matches(script.timeout)) { time += command.timeoutMs; throw Object.assign(new Error('synthetic child timeout'), { code: 'ETIMEDOUT' }); }
    if (matches(script.exception)) throw new Error('synthetic child transport exception');
    if (matches(script.fail)) return result('', 23);
    if (matches(script.malformed)) return result('{invalid-json');
    if (matches(script.abort?.method)) script.abort?.controller.abort();
    if (method === 'up') { running = true; return result(''); }
    if (method === 'down') { if (command.signal?.aborted) return result('', 29); running = false; return result(''); }
    if (method === 'ps') return result(running ? services.map(service => `${owner.project}-${service}`).join('\n') : '');
    if (method === 'volumes') return result('');
    if (method === 'docker-info') return result({ NCPU: 24, MemTotal: 33511964672 });
    if (method === 'inspect') return result(services.map(service => ({ Id: `${owner.project}-${service}`, Name: `${owner.project}-${service}`, Image: imagePins[service]?.split('@')[1], RepoDigests: [imagePins[service]], Config: { Image: imagePins[service], Labels: { 'com.docker.compose.project': owner.project, 'com.docker.compose.service': service } }, State: { Running: running, Health: { Status: 'healthy' } }, HostConfig: { NanoCpus: 500000000, Memory: 536870912, PidsLimit: 128, PortBindings: {} }, NetworkSettings: { Ports: {} } })));
    if (method === 'cp') {
      const destination = args.at(-1) ?? '';
      const inside = relative(resolve(owner.runtimeRoot), resolve(destination));
      if (!isAbsolute(destination) || !inside || inside.startsWith('..') || isAbsolute(inside)) throw new Error('copy target is outside declared owner runtime');
      const source = args.at(-2) ?? '';
      const kind = /macaroon|rune|key/.test(source) ? 'macaroon' : undefined;
      const bytes = kind ? readFileSync(join(sentinelDir, `product-${kind}.bin`)) : Buffer.from('synthetic public node certificate');
      mkdirSync(dirname(destination), { recursive: true, mode: 0o700 }); writeFileSync(destination, bytes, { mode: 0o600 }); privateFiles.set(destination, bytes);
      if (kind) { const tmp = process.env['FLUXWARDEN_TEST_TMP']; if (!tmp) throw new Error('private scratch root required'); appendFileSync(join(tmp, 'declared-out.txt'), `${destination}\n`); }
      return result('');
    }
    if (method === 'state') return result({ state: 'RPC_ACTIVE' });
    if (method === 'getblockchaininfo') return result({ chain: 'regtest', blocks: height, headers: height, initialblockdownload: false });
    if (method === 'getnetworkinfo') return result({ version: 310100, subversion: '/Satoshi:31.1.0/' });
    if (method === 'getblockcount') return result(String(height));
    if (method === 'createwallet') return result({ name: 'lab', warning: '' });
    if (method === 'listwallets') return result(['lab']);
    if (method === 'getnewaddress') return result('bcrt1qwx6am26cuw38y4863pd6swrce2g8mzhaxr9xp8');
    if (method === 'generatetoaddress') { const amount = Number(args[args.indexOf(method) + 1]); height += amount; return result(Array.from({ length: amount }, (_, index) => String(index + 1).padStart(64, '0'))); }
    if (method === 'getinfo') {
      const synced = height === 0 || ready('chain', `${node}/chain/${String(height)}`); observation.ready = synced;
      const network = script.network?.node === node ? script.network.value : 'regtest';
      const version = script.version?.node === node ? script.version.value : node.startsWith('lnd-') ? '0.21.4-beta' : 'v26.06.9';
      const localCount = allLocal(node).filter(channel => opened.has(channel.id)).length;
      return result(node.startsWith('lnd-') ? { chains: [{ chain: 'bitcoin', network }], version, identity_pubkey: pubkeys[node], synced_to_chain: synced, synced_to_graph: synced, block_height: synced ? height : height - 1 } : { id: pubkeys[node], alias: node, color: '000000', num_peers: nodes.filter(peer => connected.has([node, peer].sort().join('/'))).length, num_pending_channels: height < 113 ? localCount : 0, num_active_channels: height >= 113 ? localCount : 0, num_inactive_channels: 0, version, blockheight: synced ? height : height - 1, network, fees_collected_msat: 0, 'lightning-dir': '/root/.lightning/regtest', address: [], ...(synced ? {} : { warning_bitcoind_sync: 'synthetic delayed chain sync' }) });
    }
    if (method === 'newaddress') return result({ address: 'bcrt1qwx6am26cuw38y4863pd6swrce2g8mzhaxr9xp8' });
    if (method === 'newaddr') return result({ bech32: 'bcrt1qwx6am26cuw38y4863pd6swrce2g8mzhaxr9xp8', p2tr: 'bcrt1p2gppccw6ywewmg74qqxxmqfdpjds3rpr0mf22y9tm9xcc0muggwsea9nkf' });
    if (method === 'sendtoaddress') { funds += 1; return result(String(funds).padStart(64, '0')); }
    if (method === 'walletbalance' || method === 'listfunds') {
      const confirmed = height >= 107 && ready('balance', `${node}/balance`); observation.ready = confirmed;
      return result(method === 'walletbalance' ? { total_balance: '100000000', confirmed_balance: confirmed ? '100000000' : '0', unconfirmed_balance: confirmed ? '0' : '100000000' } : { outputs: [{ txid: '1'.padStart(64, '0'), output: 0, amount_msat: 100000000000, scriptpubkey: '0014' + '01'.repeat(20), status: confirmed ? 'confirmed' : 'unconfirmed', reserved: false, ...(confirmed ? { blockheight: 102 } : {}) }], channels: [] });
    }
    if (method === 'connect') { for (const peer of nodes) if (peer !== node && args.some(arg => arg.includes(pubkeys[peer] ?? 'unmatchable'))) connected.add([node, peer].sort().join('/')); return result({ id: pubkeys[node], features: '', direction: 'out' }); }
    if (method === 'listpeers') {
      const visible = ready('peers', `${node}/peers`); observation.ready = visible;
      const peers = visible ? nodes.filter(peer => connected.has([node, peer].sort().join('/'))).map(peer => node.startsWith('lnd-') ? { pub_key: pubkeys[peer] } : { id: pubkeys[peer], connected: true, num_channels: allLocal(peer).length }) : [];
      return result({ peers });
    }
    if (method === 'openchannel' || method === 'fundchannel') {
      const channel = topology.channels.find(row => row.from === node && !opened.has(row.id) && args.some(arg => arg.includes(pubkeys[row.to] ?? 'unmatchable')));
      if (!channel) return result('', 23);
      if (method === 'openchannel' && (argument('--local_amt') !== '5000000' || argument('--push_amt') !== (BigInt(channel.push_msat) / 1000n).toString())) return result('', 23);
      if (method === 'fundchannel') {
        const amount = argument('amount') ?? args[args.indexOf(method) + 2], push = argument('push_msat');
        if (!['5000000', '5000000sat', '5000000000msat'].includes(amount ?? '') || ![channel.push_msat, `${channel.push_msat}msat`, `${(BigInt(channel.push_msat) / 1000n).toString()}sat`].includes(push ?? '')) return result('', 23);
      }
      opened.add(channel.id); return result(method === 'openchannel' ? { funding_txid: channel.id.padStart(64, '0'), output_index: 0 } : { tx: '00', txid: channel.id.padStart(64, '0'), outnum: 0, channel_type: { bits: [12, 22], names: ['static_remotekey/even', 'anchors/even'] }, channel_id: channel.id.padStart(64, '0') });
    }
    if (method === 'getmempoolinfo' || method === 'getrawmempool') { const visible = ready('mempool', 'mempool'); observation.ready = visible; return result(method === 'getmempoolinfo' ? { size: visible ? opened.size : 0 } : visible ? [...opened].map(id => id.padStart(64, '0')) : []); }
    if (method === 'pendingchannels') return result({ pending_open_channels: [], pending_closing_channels: [], pending_force_closing_channels: [], waiting_close_channels: [] });
    if (method === 'listpeerchannels' || (method === 'listchannels' && node.startsWith('lnd-'))) { const active = height >= 113 && ready('active', `${node}/active`); observation.ready = active; return result({ channels: local(node, active) }); }
    if (method === 'updatechanpolicy' || method === 'setchannel') {
      if (method === 'updatechanpolicy' && (argument('--base_fee_msat') !== '1000' || (argument('--fee_rate') !== '0.001' && argument('--fee_rate_ppm') !== '1000') || argument('--time_lock_delta') !== '80')) return result('', 23);
      if (method === 'setchannel' && (!['1000', '1000msat', '1sat'].includes(argument('feebase') ?? '') || argument('feeppm') !== '1000')) return result('', 23);
      policyNodes.add(node); return result(method === 'updatechanpolicy' ? {} : { channels: allLocal(node).map(channel => ({ peer_id: pubkeys[channel.from === node ? channel.to : channel.from], channel_id: channel.id.padStart(64, '0'), short_channel_id: scid(channel.id), fee_base_msat: 1000, fee_proportional_millionths: 1000, minimum_htlc_out_msat: 0, maximum_htlc_out_msat: 4900000000, ignore_fee_limits: false })) });
    }
    if (method === 'describegraph' || method === 'getchaninfo' || method === 'listchannels') {
      const complete = policyNodes.size === nodes.length && ready('graph', `${node}/graph`); observation.ready = complete;
      const answer = graph(node, complete);
      if (method !== 'getchaninfo') return result(answer);
      const id = args.find(arg => arg.startsWith('--chan_id='))?.split('=')[1] ?? args.at(-1), edge = 'edges' in answer ? answer.edges.find(row => row.channel_id === id) : undefined;
      return edge ? result(edge) : result('', 1);
    }
    if (method === 'askrene-listlayers') { const cleared = ready('layers', `${node}/layers`); observation.ready = cleared; return result({ layers: [{ layer: cleared ? 'xpay' : 'fluxwarden-setup', persistent: cleared, disabled_nodes: [], created_channels: [], channel_updates: [], constraints: [] }] }); }
    return result('', 99);
  };
  let mutating = 0, peakMutating = 0;
  const run: Run = (argv, command) => {
    const changes = ['up', 'down', 'cp', 'createwallet', 'generatetoaddress', 'sendtoaddress', 'connect', 'openchannel', 'fundchannel', 'updatechanpolicy', 'setchannel'].some(method => argv.includes(method));
    if (changes) { mutating += 1; peakMutating = Math.max(peakMutating, mutating); }
    return execute(argv, command).finally(() => { if (changes) mutating -= 1; });
  };
  return { run, observations, privateFiles, pubkeys, clock: () => time, delay: (ms, signal) => { if (signal?.aborted) return Promise.reject(new Error('synthetic aborted state wait')); delays.push(ms); time += ms; return Promise.resolve(); }, delays, maxMutating: () => peakMutating };
}
