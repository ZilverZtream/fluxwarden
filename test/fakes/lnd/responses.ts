// LND v0.21.4-beta REST answers as the gateway marshals them: proto field names, every field
// emitted, 64-bit integers as decimal strings, 32-bit integers as numbers, bytes as standard
// base64 and enums by name (lnrpc/rpc_utils.go#L47-L50 RESTJsonMarshalOpts: EmitUnpopulated,
// UseProtoNames; protojson mapping https://protobuf.dev/programming-guides/json/). Field lists
// follow lnrpc/lightning.proto at that tag; the line ranges are cited per message below.

export const LND_PUBKEY = '02' + 'a1'.repeat(32);
export const PEER_A = '03' + 'b2'.repeat(32);
export const PEER_B = '02' + 'c3'.repeat(32);

export function b64(hex: string): string { return Buffer.from(hex, 'hex').toString('base64'); }

/** GetInfoResponse, lightning.proto#L1920-L2001; `chains` per rpcserver.go#L3419-L3424. */
export function getInfo(overrides: { version?: string; pubkey?: string; network?: string; synced?: boolean } = {}): Record<string, unknown> {
  return {
    version: overrides.version ?? '0.21.4-beta commit=v0.21.4-beta', commit_hash: 'f'.repeat(40),
    identity_pubkey: overrides.pubkey ?? LND_PUBKEY, alias: 'lnd-r', color: '#3399ff',
    num_pending_channels: 0, num_active_channels: 2, num_inactive_channels: 0, num_peers: 2,
    block_height: 812, block_hash: '0f'.repeat(32), best_header_timestamp: '1760000000',
    synced_to_chain: overrides.synced ?? true, synced_to_graph: true, testnet: false,
    chains: [{ chain: 'bitcoin', network: overrides.network ?? 'regtest' }], uris: [], features: {},
    require_htlc_interceptor: false, store_final_htlc_resolutions: false, wallet_synced: true, graph_cache_status: null,
  };
}

/** ChannelConstraints, lightning.proto#L1383-L1405. */
function constraints(reserveSat: string, maxPendingAmtMsat: string): Record<string, unknown> {
  return { csv_delay: 144, chan_reserve_sat: reserveSat, dust_limit_sat: '354', max_pending_amt_msat: maxPendingAmtMsat, min_htlc_msat: '1', max_accepted_htlcs: 483 };
}

/** Channel, lightning.proto#L1407-L1588 (HTLC #L1278-L1305). */
export function channel(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    active: true, remote_pubkey: PEER_A, channel_point: `${'ab'.repeat(32)}:1`, chan_id: '892945371103232001',
    capacity: '5000000', local_balance: '3746530', remote_balance: '1250000', commit_fee: '2810',
    commit_weight: '1116', fee_per_kw: '2500', unsettled_balance: '0', total_satoshis_sent: '0',
    total_satoshis_received: '0', num_updates: '4', pending_htlcs: [], csv_delay: 144, private: false,
    initiator: true, chan_status_flags: 'ChanStatusDefault', local_chan_reserve_sat: '50000',
    remote_chan_reserve_sat: '50000', static_remote_key: false, commitment_type: 'ANCHORS', lifetime: '600',
    uptime: '600', close_address: '', push_amount_sat: '1250000', thaw_height: 0,
    local_constraints: constraints('50000', '4950000000'), remote_constraints: constraints('50000', '4950000000'),
    alias_scids: [], zero_conf: false, zero_conf_confirmed_scid: '0', peer_alias: '', peer_scid_alias: '0', memo: '',
    custom_channel_data: '',
    ...overrides,
  };
}

/** PendingChannelsResponse.PendingChannel, lightning.proto#L2728-L2969. */
export function pendingChannel(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    remote_node_pub: PEER_B, channel_point: `${'cd'.repeat(32)}:0`, capacity: '2000000', local_balance: '1996530',
    remote_balance: '0', local_chan_reserve_sat: '20000', remote_chan_reserve_sat: '20000', initiator: 'INITIATOR_LOCAL',
    commitment_type: 'ANCHORS', num_forwarding_packages: '0', chan_status_flags: '', private: false, memo: '',
    custom_channel_data: '',
    ...overrides,
  };
}

/** Payment and HTLCAttempt, lightning.proto#L4293-L4398. */
export function payment(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    payment_hash: '11'.repeat(32), value: '100000', creation_date: '1760000000', fee: '101', payment_preimage: '0'.repeat(64),
    value_sat: '100000', value_msat: '100000000', payment_request: '', status: 'IN_FLIGHT', fee_sat: '101', fee_msat: '101000',
    creation_time_ns: '1760000000123456789', htlcs: [], payment_index: '1', failure_reason: 'FAILURE_REASON_NONE',
    first_hop_custom_records: {},
    ...overrides,
  };
}

export function attempt(status: 'IN_FLIGHT' | 'SUCCEEDED' | 'FAILED', id: string): Record<string, unknown> {
  return { attempt_id: id, status, route: null, attempt_time_ns: '1760000000200000000', resolve_time_ns: '0', failure: null, preimage: '' };
}

/** Invoice, lightning.proto#L3820-L4028. */
export function invoice(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    memo: 'fluxwarden exec', r_preimage: '', r_hash: '', value: '100000', value_msat: '100000000', settled: false,
    creation_date: '1760000000', settle_date: '0', payment_request: 'lnbcrt1m1pfixture', description_hash: '', expiry: '3600',
    fallback_addr: '', cltv_expiry: '80', route_hints: [], private: false, add_index: '7', settle_index: '0', amt_paid: '0',
    amt_paid_sat: '0', amt_paid_msat: '0', state: 'OPEN', htlcs: [], features: {}, is_keysend: false, payment_addr: '',
    is_amp: false, amp_invoice_state: {}, is_blinded: false, blinded_path_config: null,
    ...overrides,
  };
}

/** ForwardingEvent, lightning.proto#L4749-L4804. */
export function forward(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    timestamp: '1760000100', chan_id_in: '892945371103232001', chan_id_out: '892946470614859777', amt_in: '100101',
    amt_out: '100000', fee: '101', fee_msat: '101000', amt_in_msat: '100101000', amt_out_msat: '100000000',
    timestamp_ns: '1760000100123456789', peer_alias_in: '', peer_alias_out: '',
    ...overrides,
  };
}

/** AddInvoiceResponse, lightning.proto#L4134-L4157: r_hash and payment_addr as standard base64 bytes. */
export function addInvoiceResponse(hashHex: string, paymentAddrHex: string, paymentRequest: string): Record<string, unknown> {
  return { r_hash: b64(hashHex), payment_request: paymentRequest, add_index: '12', payment_addr: b64(paymentAddrHex) };
}

/** HTLCAttempt as SendToRouteV2 returns it, lightning.proto#L4368-L4395; `preimage` is bytes (base64). */
export function htlcAttempt(status: 'IN_FLIGHT' | 'SUCCEEDED' | 'FAILED', preimageHex: string, failureCode: string | null = null): Record<string, unknown> {
  return {
    attempt_id: '41', status, route: null, attempt_time_ns: '1760000000200000000', resolve_time_ns: '1760000000900000000',
    failure: failureCode === null ? null : { code: failureCode, channel_update: null, htlc_msat: '0', onion_sha_256: '', cltv_expiry: 0, flags: 0, failure_source_index: 3, height: 0 },
    preimage: preimageHex === '' ? '' : b64(preimageHex),
  };
}

/** RoutingPolicy, lightning.proto#L3481-L3496 (`min_htlc` is msat; inbound fees left at zero). */
export function routingPolicy(policy: { timeLockDelta: number; baseMsat: number; rateMilliMsat: number; minHtlcMsat?: string; maxHtlcMsat?: string; disabled?: boolean }): Record<string, unknown> {
  return {
    time_lock_delta: policy.timeLockDelta, min_htlc: policy.minHtlcMsat ?? '1000', fee_base_msat: String(policy.baseMsat),
    fee_rate_milli_msat: String(policy.rateMilliMsat), disabled: policy.disabled ?? false, max_htlc_msat: policy.maxHtlcMsat ?? '4950000000',
    last_update: 1760000000, custom_records: {}, inbound_fee_base_msat: 0, inbound_fee_rate_milli_msat: 0,
  };
}

/** ChannelEdge, lightning.proto#L3530-L3558; node1_pub sorts before node2_pub (BOLT 7 node ordering). */
export function channelEdge(chanId: string, nodeA: string, nodeB: string, policies: Readonly<Record<string, Record<string, unknown>>>): Record<string, unknown> {
  const [node1, node2] = nodeA < nodeB ? [nodeA, nodeB] : [nodeB, nodeA];
  return {
    channel_id: chanId, chan_point: `${'ee'.repeat(32)}:0`, last_update: 1760000000, node1_pub: node1, node2_pub: node2,
    capacity: '5000000', node1_policy: policies[node1] ?? null, node2_policy: policies[node2] ?? null, custom_records: {}, auth_proof: null,
  };
}

/**
 * Hop, lightning.proto#L3256-L3336. LND's hop k names the node it reaches (`pub_key`) over `chan_id`;
 * `amt_to_forward_msat` and `expiry` are what that node sends on, `fee_msat` is its fee (routing/route
 * newRoute). The deprecated sat fields are the truncated msat values unless given.
 */
export function routeHop(hop: { chanId: string; pubKey: string; forwardMsat: bigint; feeMsat: bigint; expiry: number; sat?: { amtToForward: string; fee: string } }): Record<string, unknown> {
  return {
    chan_id: hop.chanId, chan_capacity: '5000000', amt_to_forward: hop.sat?.amtToForward ?? (hop.forwardMsat / 1000n).toString(),
    fee: hop.sat?.fee ?? (hop.feeMsat / 1000n).toString(), expiry: hop.expiry, amt_to_forward_msat: hop.forwardMsat.toString(),
    fee_msat: hop.feeMsat.toString(), pub_key: hop.pubKey, tlv_payload: true, mpp_record: null, amp_record: null,
    custom_records: {}, metadata: '', blinding_point: '', encrypted_data: '', total_amt_msat: '0',
  };
}

/** Route, lightning.proto#L3372-L3425. */
export function route(totalTimeLock: number, totalAmtMsat: bigint, totalFeesMsat: bigint, hops: Record<string, unknown>[]): Record<string, unknown> {
  return {
    total_time_lock: totalTimeLock, total_fees: (totalFeesMsat / 1000n).toString(), total_amt: (totalAmtMsat / 1000n).toString(), hops,
    total_fees_msat: totalFeesMsat.toString(), total_amt_msat: totalAmtMsat.toString(), first_hop_amount_msat: '0', custom_channel_data: '',
  };
}
