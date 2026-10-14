// Documented volatile members: node and channel identities, chain heights and hashes, clocks,
// balances, counters, payment identities (hash, preimage fingerprint, secrets, invoices) and
// mission-control or solver probabilities. Values differ between lab instances by construction.
const volatile = new Set([
  'identity_pubkey', 'pub_key', 'remote_pubkey', 'last_hop_pubkey', 'id', 'peer_id', 'node_id', 'node_id_in', 'node_id_out', 'destination', 'source', 'color', 'uris', 'alias',
  'block_height', 'blockheight', 'block_hash', 'best_header_timestamp', 'timestamp', 'created_at', 'completed_at', 'creation_date', 'creation_time_ns',
  'attempt_time_ns', 'resolve_time_ns', 'last_update', 'last_stable_connection', 'state_changes', 'lifetime', 'uptime', 'expires_at', 'expiry',
  'total_time_lock', 'expiration_height', 'height',
  'chan_id', 'scid', 'short_channel_id', 'short_channel_id_dir', 'channel_id', 'channel_point', 'funding_txid', 'funding_outnum', 'scratch_txid', 'txid',
  'outpoint', 'close_to', 'close_to_addr', 'close_address', 'direction', 'channel_flags', 'account', 'origin',
  'local_balance', 'remote_balance', 'unsettled_balance', 'total_satoshis_sent', 'total_satoshis_received', 'num_updates', 'pending_htlcs',
  'to_us_msat', 'min_to_us_msat', 'max_to_us_msat', 'spendable_msat', 'receivable_msat', 'last_tx_fee_msat', 'fees_collected_msat',
  'in_payments_offered', 'in_offered_msat', 'in_payments_fulfilled', 'in_fulfilled_msat', 'out_payments_offered', 'out_offered_msat',
  'out_payments_fulfilled', 'out_fulfilled_msat', 'success_prob', 'probability_ppm',
  'payment_hash', 'payment_preimage', 'preimage', 'r_hash', 'payment_request', 'bolt11', 'payment_addr', 'payment_secret', 'hash_lock', 'payment_index',
  'attempt_id', 'created_index', 'updated_index', 'label', 'groupid', 'payment_id', 'onion_sha_256', 'message',
  // Commitment fees follow each node's own fee estimate at channel open and after updates (lnd
  // Channel.commit_fee = capacity - commitment outputs, L16; CLN listpeerchannels feerate.perkw/perkb is
  // the current commitment feerate, doc/schemas/listpeerchannels.json); both drift between lab runs.
  'commit_fee', 'feerate',
]);
const kind = (value: unknown): string => Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value;
/** Equal modulo the volatile members; arrays are matched element by element in any order. */
export function same(recorded: unknown, fresh: unknown, path = '$'): string | null {
  if (kind(recorded) !== kind(fresh)) return `${path}: ${kind(recorded)} recorded, ${kind(fresh)} now`;
  if (Array.isArray(recorded) && Array.isArray(fresh)) {
    if (recorded.length !== fresh.length) return `${path}: ${String(recorded.length)} items recorded, ${String(fresh.length)} now`;
    const unused: unknown[] = [...(fresh as unknown[])];
    for (const [index, item] of (recorded as unknown[]).entries()) {
      const match = unused.findIndex(candidate => same(item, candidate) === null);
      if (match < 0) return `${path}[${String(index)}]: no matching item now (${same(item, fresh[index], `${path}[${String(index)}]`) ?? 'order'})`;
      unused.splice(match, 1);
    }
    return null;
  }
  if (kind(recorded) === 'object') {
    const a = recorded as Record<string, unknown>, b = fresh as Record<string, unknown>;
    const keys = Object.keys(a).sort(), now = Object.keys(b).sort();
    if (keys.join(',') !== now.join(',')) return `${path}: members ${keys.join(',')} recorded, ${now.join(',')} now`;
    for (const key of keys) {
      if (volatile.has(key)) { if (kind(a[key]) !== kind(b[key])) return `${path}.${key}: type changed`; continue; }
      const difference = same(a[key], b[key], `${path}.${key}`);
      if (difference) return difference;
    }
    return null;
  }
  return recorded === fresh ? null : `${path}: ${JSON.stringify(recorded)} recorded, ${JSON.stringify(fresh)} now`;
}

