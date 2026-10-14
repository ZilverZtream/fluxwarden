import type { Msat } from '../core/money.js';

export interface TargetEntry {
  readonly min_inbound_msat?: Msat;
  readonly min_outbound_msat?: Msat;
}

/** A validated policy: msat as bigint, durations in whole seconds, decimal factors as their strings. */
export interface Policy {
  readonly version: number;
  readonly network: 'regtest';
  readonly fees: { readonly max_fee_msat: Msat; readonly max_fee_ppm: number; readonly exempt_fee_msat: Msat };
  readonly routing: { readonly max_cltv_delta: number };
  readonly amounts: { readonly min_channel_reserve_msat: Msat; readonly max_principal_msat: Msat; readonly min_principal_msat: Msat };
  readonly budget: { readonly msat: Msat; readonly period: number };
  readonly cooldown_after_failure: number;
  readonly cooldown_after_success: number;
  readonly max_in_flight: number;
  readonly max_snapshot_age: number;
  readonly proposal_ttl: number;
  readonly approval_max_ttl: number;
  readonly demand: {
    readonly mode: 'targets' | 'ewma';
    readonly horizon: number;
    readonly burst_factor: string;
    readonly ewma: { readonly bucket_seconds: number; readonly alpha: string; readonly min_samples: number };
  };
  readonly targets: Readonly<Record<string, Readonly<Record<string, TargetEntry>>>>;
  readonly exclude_channels: readonly string[];
}
