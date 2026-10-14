import { expect, it } from 'vitest';
import { asRecord } from '../helpers/cli.js';
import { allServices, compose, docker, dockerText, expectedChannels, identity, lightningNodes, oracle, ownedOracle, rows, shortId, LabInvalidError } from '../helpers/cp006-oracle.js';

// SPEC 11.1 and ARCHITECTURE 10.1: independently pinned images and direct node identity.
it('CP-006/R1 owned containers and direct identities match every measured image pin on regtest', () => {
  const owner = ownedOracle();
  for (const service of allServices) {
    const id = dockerText(['compose', '--project-name', owner.project, '-f', owner.composeFile, 'ps', '-q', service]);
    expect(id.length > 0, `${service} observed container`).toBe(true);
    const observed = rows(docker(['inspect', id]), 'docker inspection')[0];
    const config = asRecord(observed?.['Config'], 'container config');
    expect(config['Image'], `${service} independently supplied digest`).toBe(owner.imagePins[service]);
    const labels = asRecord(config['Labels'], 'container labels');
    expect(labels['com.docker.compose.project']).toBe(owner.project);
    expect(asRecord(observed?.['State'], 'container state')['Running']).toBe(true);
    const actualImage = String(observed?.['Image']);
    const image = rows(docker(['image', 'inspect', actualImage]), 'observed image')[0];
    expect(image?.['Id'], `${service} actual image identity`).toBe(actualImage);
    const pin = owner.imagePins[service] ?? '';
    const digest = pin.slice(pin.indexOf('@') + 1);
    expect(Array.isArray(image?.['RepoDigests']) && image['RepoDigests'].some(value => typeof value === 'string' && value.endsWith(`@${digest}`)), `${service} observed repository digest`).toBe(true);
  }
  for (const node of lightningNodes) identity(owner, node);
  const chain = asRecord(compose(owner, ['exec', '-T', 'bitcoind', 'bitcoin-cli', '-regtest', 'getblockchaininfo']), 'chain');
  if (chain['chain'] !== 'regtest') throw new LabInvalidError('owned chain is not regtest');
  const bitcoin = asRecord(compose(owner, ['exec', '-T', 'bitcoind', 'bitcoin-cli', '-regtest', 'getnetworkinfo']), 'Bitcoin identity');
  expect(bitcoin['subversion']).toMatch(/^\/Satoshi:31\.1(?:\.0)?\/$/);
});

// ARCHITECTURE 10.3: active alone is insufficient; every viewer needs both signed policies.
it('CP-006/R2 both LND viewers observe all five edges and both policies with healthy synced endpoints', () => {
  const owner = ownedOracle(), channels = expectedChannels(owner);
  for (const node of ['lnd-p', 'lnd-r']) {
    const info = identity(owner, node);
    expect(info['synced_to_chain'], `${node} chain sync`).toBe(true);
    expect(info['synced_to_graph'], `${node} graph sync`).toBe(true);
    const state = oracle(owner, node, 'state');
    expect(['RPC_ACTIVE', 'SERVER_ACTIVE']).toContain(state['state']);
    const graph = rows(oracle(owner, node, 'describegraph')['edges'], 'LND graph');
    expect(graph).toHaveLength(5);
    for (const channel of channels) {
      const found = graph.filter(edge => shortId(edge['channel_id']) === channel.scid);
      expect(found, `${node} ${channel.scid} unique edge`).toHaveLength(1);
      for (const key of ['node1_policy', 'node2_policy']) {
        const policy = asRecord(found[0]?.[key], 'signed routing policy');
        expect(Number(policy['last_update']), `${node} ${channel.scid} policy update`).toBeGreaterThan(0);
        expect(policy['disabled']).toBe(false);
        expect(policy['fee_base_msat']).toBe('1000');
        expect(policy['fee_rate_milli_msat']).toBe('1000');
        const source = key === 'node1_policy' ? found[0]?.['node1_pub'] : found[0]?.['node2_pub'];
        expect(policy['time_lock_delta']).toBe(source === owner.pubkeys['lnd-p'] || source === owner.pubkeys['lnd-r'] ? 80 : 34);
      }
    }
    const local = rows(oracle(owner, node, 'listchannels')['channels'], 'LND local channels');
    expect(local).toHaveLength(node === 'lnd-p' ? 1 : 3);
    expect(local.every(channel => channel['active'] === true), `${node} endpoints active`).toBe(true);
  }
});

// SPEC 11.3 steps 6-8: normal local channel state, full graph and cleared setup layers.
it('CP-006/R3 all CLN viewers observe both directions for every channel with no setup layers', () => {
  const owner = ownedOracle(), channels = expectedChannels(owner);
  for (const node of ['cln-p', 'cln-r', 'cln-m']) {
    const info = identity(owner, node);
    expect(info['warning_bitcoind_sync'], `${node} chain warning`).toBeUndefined();
    expect(info['warning_lightningd_sync'], `${node} graph warning`).toBeUndefined();
    const local = rows(oracle(owner, node, 'listpeerchannels')['channels'], 'CLN local channels');
    expect(local).toHaveLength(node === 'cln-r' ? 3 : node === 'cln-m' ? 2 : 1);
    expect(local.every(channel => channel['state'] === 'CHANNELD_NORMAL' && channel['peer_connected'] === true), `${node} ready endpoints`).toBe(true);
    const graph = rows(oracle(owner, node, 'listchannels')['channels'], 'CLN graph');
    expect(graph).toHaveLength(10);
    for (const channel of channels) {
      const found = graph.filter(edge => shortId(edge['short_channel_id']) === channel.scid);
      expect(found, `${node} ${channel.scid} both directions`).toHaveLength(2);
      expect(found.map(edge => `${String(edge['source'])}:${String(edge['destination'])}`).sort()).toEqual([`${channel.left}:${channel.right}`, `${channel.right}:${channel.left}`].sort());
      for (const direction of found) {
        expect(direction['active']).toBe(true);
        expect(Number(direction['last_update'])).toBeGreaterThan(0);
        expect(direction['base_fee_millisatoshi']).toBe(1000);
        expect(direction['fee_per_millionth']).toBe(1000);
        expect(direction['delay']).toBe(direction['source'] === owner.pubkeys['lnd-p'] || direction['source'] === owner.pubkeys['lnd-r'] ? 80 : 34);
      }
    }
    const layers = rows(oracle(owner, node, 'askrene-listlayers')['layers'], 'askrene layers');
    for (const layer of layers) {
      const name = String(layer['layer']);
      // v26.06.9 askrene-listlayers schema example #2 permits an empty persistent built-in xpay layer.
      expect(name, `${node} no temporary setup layers`).toBe('xpay');
      expect(layer['persistent']).toBe(true);
      for (const key of ['disabled_nodes', 'disabled_channels', 'created_channels', 'channel_updates', 'constraints', 'biases', 'node_biases']) expect(layer[key] ?? [], `${node} xpay has no retained ${key}`).toEqual([]);
    }
  }
});

// SPEC 11.3: mining 101, 6 and 6 establishes a minimum height of 113.
it('CP-006/R4 Bitcoin height and every node sync and channel funding depth are observed directly', () => {
  const owner = ownedOracle();
  const chain = asRecord(compose(owner, ['exec', '-T', 'bitcoind', 'bitcoin-cli', '-regtest', 'getblockchaininfo']), 'chain');
  if (chain['chain'] !== 'regtest') throw new LabInvalidError('owned chain is not regtest');
  const height = chain['blocks'];
  expect(typeof height).toBe('number');
  expect(height).toBeGreaterThanOrEqual(113);
  for (const node of lightningNodes) {
    const info = identity(owner, node);
    expect(node.startsWith('lnd-') ? info['block_height'] : info['blockheight'], `${node} observed height`).toBe(height);
    const channels = rows(oracle(owner, node, node.startsWith('lnd-') ? 'listchannels' : 'listpeerchannels')['channels'], 'funding channels');
    for (const channel of channels) {
      const scid = shortId(node.startsWith('lnd-') ? channel['scid'] ?? channel['chan_id'] : channel['short_channel_id']);
      const fundingHeight = Number(scid.split('x')[0]);
      expect(Number(height) - fundingHeight + 1, `${node} funding confirmation depth`).toBeGreaterThanOrEqual(6);
    }
  }
});
