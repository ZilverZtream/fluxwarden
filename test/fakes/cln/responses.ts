// Core Lightning v26.06.9 answers shaped by doc/schemas/<method>.json at that tag. lightningd
// renders `msat` fields as JSON integers; the "<n>msat" string form appears where a test says so.

export const CLN_PUBKEY = '03' + 'd4'.repeat(32);
export const CLN_PEER = '02' + 'e5'.repeat(32);

/** getinfo.json response. */
export function getinfo(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: CLN_PUBKEY, alias: 'cln-m', color: '03d4d4', num_peers: 2, num_pending_channels: 0, num_active_channels: 2,
    num_inactive_channels: 0, address: [], binding: [{ type: 'ipv4', address: '0.0.0.0', port: 9735 }], version: 'v26.06.9',
    blockheight: 812, network: 'regtest', fees_collected_msat: 0, 'lightning-dir': '/root/.lightning/regtest',
    our_features: { init: '08a0802a8a59a1', node: '88a0802a8a59a1', channel: '', invoice: '02000002024100' },
    ...overrides,
  };
}

/** listpeerchannels.json channels[] item (required: state, opener, features, peer_connected, peer_id). */
export function peerChannel(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    peer_id: CLN_PEER, peer_connected: true, reestablished: true, state: 'CHANNELD_NORMAL', owner: 'channeld',
    short_channel_id: '812x1x0', direction: 1, channel_id: '78'.repeat(32), funding_txid: '9a'.repeat(32), funding_outnum: 0,
    private: false, opener: 'remote', features: ['option_static_remotekey', 'option_anchors'],
    to_us_msat: 1250000000, min_to_us_msat: 0, max_to_us_msat: 1250000000, total_msat: 5000000000,
    fee_base_msat: 1000, fee_proportional_millionths: 1000, dust_limit_msat: 546000,
    their_reserve_msat: 50000000, our_reserve_msat: 50000000, spendable_msat: 1199000000, receivable_msat: 3699000000,
    minimum_htlc_in_msat: 0, minimum_htlc_out_msat: 0, maximum_htlc_out_msat: 4950000000,
    their_to_self_delay: 144, our_to_self_delay: 144, max_accepted_htlcs: 483,
    updates: {
      local: { htlc_minimum_msat: 0, htlc_maximum_msat: 4950000000, cltv_expiry_delta: 34, fee_base_msat: 1000, fee_proportional_millionths: 1000 },
      remote: { htlc_minimum_msat: 1, htlc_maximum_msat: 4950000000, cltv_expiry_delta: 80, fee_base_msat: 1000, fee_proportional_millionths: 1000 },
    },
    state_changes: [], status: [], in_payments_offered: 0, in_offered_msat: 0, in_payments_fulfilled: 0, in_fulfilled_msat: 0,
    out_payments_offered: 0, out_offered_msat: 0, out_payments_fulfilled: 0, out_fulfilled_msat: 0, htlcs: [],
    ...overrides,
  };
}

/** listsendpays.json payments[] item. */
export function sendpay(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    created_index: 4, id: 4, payment_hash: 'ab'.repeat(32), groupid: 1, updated_index: 6, status: 'pending',
    amount_msat: 100000000, destination: CLN_PUBKEY, created_at: 1760000000, amount_sent_msat: 100202101,
    label: 'fluxwarden-exec', bolt11: 'lnbcrt1m1pfixture',
    ...overrides,
  };
}

/** listpays.json pays[] item. */
export function pay(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    payment_hash: 'ab'.repeat(32), status: 'pending', destination: CLN_PUBKEY, created_at: 1760000000, created_index: 4,
    label: 'fluxwarden-exec', bolt11: 'lnbcrt1m1pfixture', amount_msat: 100000000, amount_sent_msat: 100202101,
    ...overrides,
  };
}

/** listinvoices.json invoices[] item. */
export function clnInvoice(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    label: 'fluxwarden-exec', bolt11: 'lnbcrt1m1pfixture', payment_hash: 'ab'.repeat(32), amount_msat: 100000000,
    status: 'unpaid', description: 'fluxwarden rebalance', expires_at: 1760003600, created_index: 9,
    ...overrides,
  };
}

/** bkpr-listaccountevents.json events[] item (a channel event). */
export function accountEvent(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    account: '78'.repeat(32), type: 'channel', tag: 'invoice', credit_msat: 0, debit_msat: 100000000, currency: 'bcrt',
    timestamp: 1760000300, payment_id: 'ab'.repeat(32), part_id: 0, fees_msat: 202101, is_rebalance: true,
    ...overrides,
  };
}

/**
 * getroutes.json routes[].path[] item at v26.06 (doc/schemas/getroutes.json#L130-L229): the new hop
 * fields, plus the deprecated ones lightningd still emits until v27.06 (CHANGELOG.md#L233:
 * next_node_id = node_id_out, amount_msat = amount_in_msat, delay = cltv_in).
 */
export function pathHop(hop: { scidDir: string; nodeIn: string; nodeOut: string; amountIn: number; amountOut: number; cltvIn: number; cltvOut: number }, legacy: 'both' | 'new-only' | 'legacy-only' = 'both'): Record<string, unknown> {
  const fresh = {
    short_channel_id_dir: hop.scidDir, node_id_in: hop.nodeIn, node_id_out: hop.nodeOut,
    amount_in_msat: hop.amountIn, amount_out_msat: hop.amountOut, cltv_in: hop.cltvIn, cltv_out: hop.cltvOut,
  };
  const old = { short_channel_id_dir: hop.scidDir, next_node_id: hop.nodeOut, amount_msat: hop.amountIn, delay: hop.cltvIn };
  if (legacy === 'legacy-only') return old;
  if (legacy === 'new-only') return fresh;
  return { ...fresh, ...old };
}

/** getroutes.json response: probability and the routes (one per part). */
export function getroutesAnswer(routes: { amount: number; finalCltv: number; path: Record<string, unknown>[] }[]): Record<string, unknown> {
  return {
    probability_ppm: 950000,
    routes: routes.map(item => ({ probability_ppm: 950000, amount_msat: item.amount, final_cltv: item.finalCltv, path: item.path })),
  };
}

/** listchannels.json channels[] item: one direction of a channel, policy set by `source`. */
export function channelDirection(entry: { scid: string; source: string; destination: string; base: number; ppm: number; delay: number; min?: number; max?: number }): Record<string, unknown> {
  return {
    source: entry.source, destination: entry.destination, short_channel_id: entry.scid, direction: entry.source < entry.destination ? 0 : 1,
    public: true, amount_msat: 5000000000, message_flags: 1, channel_flags: entry.source < entry.destination ? 0 : 1, active: true,
    last_update: 1760000000, base_fee_millisatoshi: entry.base, fee_per_millionth: entry.ppm, delay: entry.delay,
    htlc_minimum_msat: entry.min ?? 1, htlc_maximum_msat: entry.max ?? 4950000000, features: '',
  };
}
