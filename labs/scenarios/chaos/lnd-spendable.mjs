// Independent T-18 oracle for the owned LND opener's anchored channel only.
// Pinned lnd v0.21.4-beta: lnrpc/lightning.proto Channel; lnwallet/channel.go
// CalcFeeBuffer/availableBalance; input/size.go HTLCWeight=172, anchors=660sat.
// SPEC 4.2 / public docs/architecture.md retains this conservative RPC margin.
// No product normalizer is imported, and unsupported shapes have no fallback.
export const spendableReferences = [
  'https://github.com/lightningnetwork/lnd/blob/v0.21.4-beta/lnrpc/lightning.proto#L1284',
  'https://github.com/lightningnetwork/lnd/blob/v0.21.4-beta/lnwallet/channel.go',
  'https://github.com/lightningnetwork/lnd/blob/v0.21.4-beta/input/size.go',
];
export function observedLndSpendable(channel) {
  const integer = value => {
    if ((typeof value === 'number' && !Number.isSafeInteger(value)) || !/^(0|[1-9][0-9]*)$/.test(String(value))) {
      throw new Error('GAP T-18 native amount unavailable');
    }
    return BigInt(value);
  };
  if (channel.active !== true || channel.initiator !== true ||
      !['ANCHORS', 'SCRIPT_ENFORCED_LEASE', 'SIMPLE_TAPROOT', 'SIMPLE_TAPROOT_OVERLAY', 'TAPROOT'].includes(channel.commitment_type) ||
      !Array.isArray(channel.pending_htlcs) || channel.pending_htlcs.length !== 0) {
    throw new Error('GAP T-18 requires a clean native LND opener anchored channel');
  }
  const localSat = integer(channel.local_balance), reserveSat = integer(channel.local_constraints?.chan_reserve_sat);
  const feePerKw = integer(channel.fee_per_kw), weight = integer(channel.commit_weight);
  const feeBufferSat = 2n * feePerKw * (weight + 172n) / 1000n;
  const freeSat = localSat - reserveSat - feeBufferSat - 660n;
  return { confidence: 'DERIVED_ESTIMATE', spendableMsat: (freeSat > 0n ? freeSat : 0n) * 1000n,
    fields: { localSat, reserveSat, feePerKw, weight, feeBufferSat, anchorReserveSat: 660n }, references: spendableReferences };
}

export function firstHopSetup(entry, feeCap, reserve, reverseSpendable) {
  const principal = 100000000n, cap = 100000000n;
  const healthy = (principal + feeCap + reserve + 5000000n + 999n) / 1000n * 1000n;
  const topUp = entry < healthy ? healthy - entry : 0n;
  const afterTopUp = entry + topUp;
  if (entry < 0n || feeCap <= 0n || reserve < 0n || topUp > cap || topUp > reverseSpendable || afterTopUp - principal > cap) {
    throw new Error('GAP T-18 two setup payments and two exact reversals cannot fit existing caps');
  }
  return { principal, healthy, topUp, afterTopUp, maxDrain: afterTopUp - principal };
}
