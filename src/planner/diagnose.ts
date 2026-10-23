// Liquidity diagnosis from operator targets over the latest channel snapshots (SPEC.md §7.3).
import type { ChannelState, Confidence, NormalizedChannel } from '../core/normalize.js';
import type { IncomingHistory } from '../core/node.js';
import { estimateDemand, type VolumeBucket } from './demand.js';

/** Per-channel operator target, msat. */
export interface ChannelTarget {
  readonly min_inbound_msat?: bigint;
  readonly min_outbound_msat?: bigint;
}

/** The validated policy as the planner consumes it: amounts in msat, durations in milliseconds. */
export interface PlanningPolicy {
  readonly fees: { readonly max_fee_msat: bigint; readonly max_fee_ppm: bigint; readonly exempt_fee_msat: bigint };
  readonly routing: { readonly max_cltv_delta: number };
  readonly amounts: { readonly min_channel_reserve_msat: bigint; readonly max_principal_msat: bigint; readonly min_principal_msat: bigint };
  readonly budget: { readonly msat: bigint; readonly period: number };
  readonly cooldown_after_failure: number;
  readonly cooldown_after_success: number;
  readonly max_in_flight: number;
  readonly max_snapshot_age: number;
  /** Lifetime of a proposal in milliseconds. */
  readonly proposal_ttl: number;
  readonly demand: { readonly mode: 'targets' | 'ewma'; readonly horizon: number;
    readonly burst_factor?: string; readonly ewma?: { readonly bucket_seconds: number; readonly alpha: string; readonly min_samples: number } };
  /** Node name → channel key → target. */
  readonly targets: Readonly<Record<string, Readonly<Record<string, ChannelTarget>>>>;
  readonly exclude_channels: readonly string[];
}

/** The database clock in unix milliseconds. */
export interface Clock { now(): number }

export interface DiagnoseInput {
  readonly nodeName: string;
  /** The latest snapshot of each channel; observedAt is the snapshot's observed_at. */
  readonly channels: readonly NormalizedChannel[];
  readonly policy: PlanningPolicy;
  /** null selects policy.demand.horizon. */
  readonly horizonMs: number | null;
  readonly clock: Clock;
  readonly incomingHistory?: IncomingHistory;
}

export interface ChannelDiagnosis {
  readonly channelKey: string;
  /** Copied from the snapshot; figures are computed for every state. */
  readonly state: ChannelState;
  readonly capacityMsat: bigint;
  readonly spendableMsat: bigint;
  readonly receivableMsat: bigint;
  readonly confidence: Confidence;
  readonly caveat: string | null;
  readonly observedAt: number;
  readonly snapshotAgeMs: number;
  readonly blockHeight: number;
  readonly inboundTargetMsat: bigint | null;
  readonly inboundDeficitMsat: bigint;
  readonly inboundSurplusMsat: bigint;
  readonly outboundTargetMsat: bigint | null;
  readonly outboundDeficitMsat: bigint;
  readonly outboundSurplusMsat: bigint;
}

export interface OkDiagnosis {
  readonly status: 'OK';
  readonly nodeName: string;
  readonly demandSource: 'TARGETS' | 'EWMA';
  readonly horizonMs: number;
  readonly evaluatedAt: number;
  readonly channels: readonly ChannelDiagnosis[];
  /** Channels with an inbound deficit: planning sources (SPEC.md §4.1). */
  readonly starved: readonly string[];
  /** Channels with inbound to spare: planning targets. */
  readonly donors: readonly string[];
}

/** ageMs is null for a targeted channel without any snapshot. */
export interface StaleChannel { readonly channelKey: string; readonly ageMs: number | null }

export type Diagnosis =
  | OkDiagnosis
  | { readonly status: 'STALE_SNAPSHOT'; readonly nodeName: string; readonly stale: readonly StaleChannel[] }
  | { readonly status: 'INSUFFICIENT_HISTORY'; readonly nodeName: string };

export function compareKeys(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

const positive = (value: bigint): bigint => value > 0n ? value : 0n;

export function diagnose(input: DiagnoseInput): Diagnosis {
  const { nodeName, policy } = input;
  const now = input.clock.now();
  const channels = [...input.channels].sort((a, b) => compareKeys(a.channelKey, b.channelKey));
  for (let i = 1; i < channels.length; i++) {
    if (channels[i]?.channelKey === channels[i - 1]?.channelKey) throw new Error('diagnose: more than one snapshot for one channel');
  }

  let targets = Object.hasOwn(policy.targets, nodeName) ? policy.targets[nodeName] ?? {} : {};

  // INV-06: both times come from the database clock. A snapshot dated after the clock reading cannot be
  // shown to be fresh, so it is refused like an old one; a targeted channel never observed is never a met target.
  const observed = new Set(channels.map(channel => channel.channelKey));
  const stale: StaleChannel[] = [
    ...channels
      .map(channel => ({ channelKey: channel.channelKey, ageMs: now - channel.observedAt }))
      .filter(entry => !Number.isSafeInteger(entry.ageMs) || entry.ageMs > policy.max_snapshot_age || entry.ageMs < 0),
    ...Object.keys(targets).filter(key => !observed.has(key)).map(channelKey => ({ channelKey, ageMs: null })),
  ].sort((a, b) => compareKeys(a.channelKey, b.channelKey));
  if (stale.length > 0) return { status: 'STALE_SNAPSHOT', nodeName, stale };

  if (policy.demand.mode === 'ewma') {
    const history = input.incomingHistory;
    const params = policy.demand.ewma;
    if (history === undefined || !history.complete || params === undefined || policy.demand.burst_factor === undefined || history.receipts.length === 0) return { status: 'INSUFFICIENT_HISTORY', nodeName };
    const width = params.bucket_seconds * 1000;
    const horizonMs = input.horizonMs ?? policy.demand.horizon;
    if (!Number.isSafeInteger(width) || width <= 0 || !Number.isSafeInteger(horizonMs) || horizonMs <= 0) throw new RangeError('demand window is invalid');
    const count = Math.max(params.min_samples, Math.ceil(horizonMs / width));
    // A bounded history scan cannot justify a larger window than the observations it could contain.
    if (!Number.isSafeInteger(count) || count > 100_000) return { status: 'INSUFFICIENT_HISTORY', nodeName };
    const end = Math.floor(now / width) * width;
    const start = end - count * width;
    if (!Number.isSafeInteger(start)) return { status: 'INSUFFICIENT_HISTORY', nodeName };
    const volumes = new Map<string, Map<number, bigint>>();
    let earliest = now;
    for (const receipt of history.receipts) {
      if (!Number.isSafeInteger(receipt.settledAt) || receipt.settledAt < 0 || receipt.settledAt > now || receipt.amountMsat < 0n) return { status: 'INSUFFICIENT_HISTORY', nodeName };
      earliest = Math.min(earliest, receipt.settledAt);
      const bucket = Math.floor(receipt.settledAt / width) * width;
      if (bucket < start || bucket >= end) continue;
      const channel = volumes.get(receipt.channelKey) ?? new Map<number, bigint>();
      channel.set(bucket, (channel.get(bucket) ?? 0n) + receipt.amountMsat);
      volumes.set(receipt.channelKey, channel);
    }
    // Complete scans include empty buckets; never invent observations before the first known receipt.
    if (Math.floor(earliest / width) * width > start) return { status: 'INSUFFICIENT_HISTORY', nodeName };
    const estimated: Record<string, ChannelTarget> = {};
    for (const channel of channels) {
      const buckets: VolumeBucket[] = Array.from({ length: count }, (_, i) => {
        const at = start + i * width;
        return { start: at, volumeMsat: volumes.get(channel.channelKey)?.get(at) ?? 0n };
      });
      const demand = estimateDemand({ buckets, now, targetMsat: 0n, params: {
        bucketSeconds: params.bucket_seconds, alpha: params.alpha, minSamples: params.min_samples,
        horizonSeconds: horizonMs / 1000, burstFactor: policy.demand.burst_factor,
      } });
      if (demand.source !== 'EWMA') return { status: 'INSUFFICIENT_HISTORY', nodeName };
      estimated[channel.channelKey] = { ...targets[channel.channelKey], min_inbound_msat: demand.requiredInboundMsat };
    }
    targets = estimated;
  }

  const hasTarget = Object.values(targets).some(target => target.min_inbound_msat !== undefined || target.min_outbound_msat !== undefined);
  if (!hasTarget) return { status: 'INSUFFICIENT_HISTORY', nodeName };

  const rows = channels.map((channel): ChannelDiagnosis => {
    const target = Object.hasOwn(targets, channel.channelKey) ? targets[channel.channelKey] : undefined;
    const inbound = target?.min_inbound_msat ?? null;
    const outbound = target?.min_outbound_msat ?? null;
    const requiredIn = inbound ?? 0n;
    const requiredOut = outbound ?? 0n;
    return {
      channelKey: channel.channelKey,
      state: channel.state,
      capacityMsat: channel.capacityMsat,
      spendableMsat: channel.spendableMsat,
      receivableMsat: channel.receivableMsat,
      confidence: channel.confidence,
      caveat: channel.caveat,
      observedAt: channel.observedAt,
      snapshotAgeMs: now - channel.observedAt,
      blockHeight: channel.blockHeight,
      inboundTargetMsat: inbound,
      inboundDeficitMsat: positive(requiredIn - channel.receivableMsat),
      inboundSurplusMsat: positive(channel.receivableMsat - requiredIn),
      outboundTargetMsat: outbound,
      outboundDeficitMsat: positive(requiredOut - channel.spendableMsat),
      outboundSurplusMsat: positive(channel.spendableMsat - requiredOut),
    };
  });

  return {
    status: 'OK',
    nodeName,
    demandSource: policy.demand.mode === 'ewma' ? 'EWMA' : 'TARGETS',
    horizonMs: input.horizonMs ?? policy.demand.horizon,
    evaluatedAt: now,
    channels: rows,
    starved: rows.filter(row => row.inboundDeficitMsat > 0n).map(row => row.channelKey),
    donors: rows.filter(row => row.inboundSurplusMsat > 0n).map(row => row.channelKey),
  };
}
