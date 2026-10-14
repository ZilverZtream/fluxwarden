export const nodes = ['lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m'];
export const services = ['bitcoind', ...nodes, 'toxiproxy'];

export function fail(stage) { return new Error(`lab ${stage}: failed`); }
export function record(value, stage) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw fail(stage);
  return value;
}
export function rows(value, stage) {
  if (!Array.isArray(value)) throw fail(stage);
  return value.map(value => record(value, stage));
}
export function decimal(value, stage) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === 'string' && /^(?:0|[1-9]\d*)(?:msat)?$/.test(value)) return BigInt(value.replace(/msat$/, ''));
  throw fail(stage);
}
export function shortId(value) {
  if (typeof value === 'string' && /^\d+x\d+x\d+$/.test(value)) return value;
  const encoded = decimal(value, 'channel-id');
  return `${encoded >> 40n}x${(encoded >> 16n) & 0xffffffn}x${encoded & 0xffffn}`;
}
export function identity(node, info, previous) {
  const lnd = node.startsWith('lnd-');
  if (lnd) {
    const chains = rows(info.chains, 'network');
    if (chains.length !== 1 || chains[0].chain !== 'bitcoin' || chains[0].network !== 'regtest') throw fail('network');
  } else if (info.network !== 'regtest') throw fail('network');
  // Only the release and its recognized official build annotation pass; arbitrary forks do not.
  if (lnd ? typeof info.version !== 'string' || !/^0\.21\.4-beta(?: commit=v0\.21\.4-beta)?$/.test(info.version)
    : info.version !== 'v26.06.9') throw fail('version');
  const pubkey = lnd ? info.identity_pubkey : info.id;
  if (typeof pubkey !== 'string' || !/^(02|03)[a-f0-9]{64}$/.test(pubkey) || (previous && previous.pubkey !== pubkey)) throw fail('identity');
  return { kind: lnd ? 'lnd' : 'cln', network: 'regtest', version: info.version, pubkey };
}
export function synced(node, info, height, requireGraph = false) {
  return decimal(node.startsWith('lnd-') ? info.block_height : info.blockheight, 'height') === height &&
    (node.startsWith('lnd-') ? info.synced_to_chain === true && (!requireGraph || info.synced_to_graph === true)
      : info.warning_bitcoind_sync === undefined && info.warning_lightningd_sync === undefined);
}

// Both routing policies are required, following ElementsProject/lightning@v26.06.9
// doc/schemas/listchannels.json. Local CHANNELD_NORMAL alone cannot prove gossip readiness.
export function graphReady(node, answer, topology, identities, channelIds) {
  const lnd = node.startsWith('lnd-'), edges = rows(lnd ? answer.edges : answer.channels, 'graph');
  if (edges.length !== (lnd ? 5 : 10)) return false;
  const policy = (row, source, lnd) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) return false;
    return decimal(lnd ? row.fee_base_msat : row.base_fee_millisatoshi, 'graph-policy') === 1000n &&
      decimal(lnd ? row.fee_rate_milli_msat : row.fee_per_millionth, 'graph-policy') === 1000n &&
      decimal(lnd ? row.time_lock_delta : row.delay, 'graph-policy') === BigInt(source.startsWith('lnd-') ? 80 : 34) &&
      decimal(row.last_update, 'graph-policy') > 0n && (lnd ? row.disabled === false : row.active === true);
  };
  return topology.channels.every(channel => {
    const a = identities[channel.from].pubkey, b = identities[channel.to].pubkey;
    const matching = edges.filter(edge => shortId(lnd ? edge.channel_id : edge.short_channel_id) === channelIds[channel.id]);
    if (lnd) {
      if (matching.length !== 1) return false;
      const edge = matching[0];
      const forward = edge.node1_pub === a && edge.node2_pub === b, reverse = edge.node1_pub === b && edge.node2_pub === a;
      return (forward || reverse) && decimal(edge.capacity, 'graph-capacity') * 1000n === BigInt(channel.capacity_msat) &&
        policy(edge.node1_policy, forward ? channel.from : channel.to, true) && policy(edge.node2_policy, forward ? channel.to : channel.from, true);
    }
    return matching.length === 2 && [[a, b, channel.from], [b, a, channel.to]].every(([source, destination, sourceNode]) => {
      const directions = matching.filter(edge => edge.source === source && edge.destination === destination);
      return directions.length === 1 && decimal(directions[0].amount_msat, 'graph-capacity') === BigInt(channel.capacity_msat) && policy(directions[0], sourceNode, false);
    });
  });
}

// The pinned askrene-listlayers schema example permits this empty built-in xpay layer.
export function layersCleared(answer) {
  return rows(answer.layers, 'layers').every(layer => layer.layer === 'xpay' && layer.persistent === true &&
    ['disabled_nodes', 'disabled_channels', 'created_channels', 'channel_updates', 'constraints', 'biases', 'node_biases']
      .every(key => layer[key] === undefined || (Array.isArray(layer[key]) && layer[key].length === 0)));
}

export async function waitFor(stage, observe, { clock, delay, signal, deadline }) {
  for (;;) {
    if (signal?.aborted) throw fail(stage);
    if (clock() >= deadline) throw fail(`${stage} timeout`);
    if (await observe()) return;
    if (clock() >= deadline) throw fail(`${stage} timeout`);
    await delay(Math.min(250, deadline - clock()), signal);
  }
}
