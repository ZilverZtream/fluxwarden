// Shared fixtures for the diagnosis and planning tests. The planner modules are loaded inside each
// case so a missing module fails every case individually.
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { repoRoot } from './cli.js';

export type Confidence = 'NODE_REPORTED' | 'DERIVED_ESTIMATE';

/** Mirrors src/core/normalize.ts NormalizedChannel. */
export interface NormalizedChannel {
  readonly nodeId: string;
  readonly channelKey: string;
  readonly scid: string | null;
  readonly peerPubkey: string;
  readonly fundingOutpoint: string;
  readonly state: 'ACTIVE' | 'INACTIVE' | 'PENDING' | 'CLOSING' | 'UNKNOWN';
  readonly nodeState: string;
  readonly opener: 'local' | 'remote';
  readonly capacityMsat: bigint;
  readonly localBalanceMsat: bigint;
  readonly remoteBalanceMsat: bigint;
  readonly spendableMsat: bigint;
  readonly receivableMsat: bigint;
  readonly confidence: Confidence;
  readonly caveat: string | null;
  readonly localReserveMsat: bigint;
  readonly remoteReserveMsat: bigint;
  readonly pendingOutMsat: bigint;
  readonly pendingInMsat: bigint;
  readonly pendingHtlcCount: number;
  readonly localMaxPendingAmtMsat: bigint | null;
  readonly remoteMaxPendingAmtMsat: bigint | null;
  readonly observedAt: number;
  readonly blockHeight: number;
  readonly provenance: Readonly<Record<string, string>>;
}

export interface ChannelTarget {
  readonly min_inbound_msat?: bigint;
  readonly min_outbound_msat?: bigint;
}

export interface PlanningPolicy {
  readonly fees: { readonly max_fee_msat: bigint; readonly max_fee_ppm: bigint; readonly exempt_fee_msat: bigint };
  readonly routing: { readonly max_cltv_delta: number };
  readonly amounts: { readonly min_channel_reserve_msat: bigint; readonly max_principal_msat: bigint; readonly min_principal_msat: bigint };
  readonly budget: { readonly msat: bigint; readonly period: number };
  readonly cooldown_after_failure: number;
  readonly cooldown_after_success: number;
  readonly max_in_flight: number;
  readonly max_snapshot_age: number;
  /** Lifetime of a proposal in milliseconds (SPEC §7.1 proposal_ttl). */
  readonly proposal_ttl: number;
  readonly demand: { readonly mode: 'targets' | 'ewma'; readonly horizon: number };
  readonly targets: Readonly<Record<string, Readonly<Record<string, ChannelTarget>>>>;
  readonly exclude_channels: readonly string[];
}

export interface Clock { now(): number }

export interface DiagnoseInput {
  readonly nodeName: string;
  readonly channels: readonly NormalizedChannel[];
  readonly policy: PlanningPolicy;
  readonly horizonMs: number | null;
  readonly clock: Clock;
}

export type ChannelState = NormalizedChannel['state'];

export interface ChannelDiagnosis {
  readonly channelKey: string;
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
  readonly demandSource: 'TARGETS';
  readonly horizonMs: number;
  readonly evaluatedAt: number;
  readonly channels: readonly ChannelDiagnosis[];
  readonly starved: readonly string[];
  readonly donors: readonly string[];
}

export type Diagnosis =
  | OkDiagnosis
  | { readonly status: 'STALE_SNAPSHOT'; readonly nodeName: string; readonly stale: readonly { readonly channelKey: string; readonly ageMs: number | null }[] }
  | { readonly status: 'INSUFFICIENT_HISTORY'; readonly nodeName: string };

export interface DiagnoseModule { readonly diagnose: (input: DiagnoseInput) => Diagnosis }

export interface CommandModule { readonly liquidityDiagnose: (input: DiagnoseInput) => { readonly exitCode: number; readonly json: string } }

export type RefusalCode =
  | 'NO_FEASIBLE_ROUTE' | 'FEE_CEILING_EXCEEDED' | 'PPM_CEILING_EXCEEDED' | 'CLTV_DELTA_UNSAFE' | 'RESERVE_FLOOR'
  | 'BUDGET_EXHAUSTED' | 'COOLDOWN_ACTIVE' | 'STALE_SNAPSHOT' | 'INSUFFICIENT_HISTORY' | 'CAPABILITY_UNSUPPORTED'
  | 'SINGLE_PATH_UNAVAILABLE' | 'REPEATED_CHANNEL' | 'SAME_PEER' | 'FIRST_HOP_SPENDABLE' | 'LAST_HOP_RECEIVABLE';

/** A pair refusal: a SPEC §7.5 code, or the SPEC §7.4 no-action wording when the source's own deficit is too small to move. */
export type PairCode = RefusalCode | 'BALANCED_OR_INSUFFICIENT_SURPLUS';

export interface CooldownEvent {
  readonly outcome: 'VERIFIED_SUCCESS' | 'VERIFIED_FAILURE';
  readonly sourceChannel: string;
  readonly targetChannel: string;
  readonly at: number;
}

export interface BudgetReservation {
  readonly state: 'HELD' | 'CONSUMED' | 'RELEASED';
  readonly reservedMsat: bigint;
  readonly consumedMsat: bigint | null;
  readonly at: number;
}

export interface PlanInput {
  readonly diagnosis: OkDiagnosis;
  readonly policy: PlanningPolicy;
  readonly cooldowns: readonly CooldownEvent[];
  readonly reservations: readonly BudgetReservation[];
  /** Executions of this node in SUBMITTING, IN_FLIGHT or UNKNOWN. */
  readonly inFlight: number;
  readonly clock: Clock;
}

export interface Candidate { readonly sourceChannel: string; readonly targetChannel: string; readonly principalMsat: bigint }
export interface PairRefusal { readonly sourceChannel: string; readonly targetChannel: string; readonly code: PairCode; readonly remainingMs: number | null }
export interface PlanResult {
  readonly action: 'CANDIDATES' | 'NO_ACTION';
  readonly reason: 'BALANCED_OR_INSUFFICIENT_SURPLUS' | null;
  readonly candidates: readonly Candidate[];
  readonly refusals: readonly PairRefusal[];
}

export interface PlanModule { readonly plan: (input: PlanInput) => PlanResult }

async function load<T>(relative: string): Promise<T> {
  return await import(pathToFileURL(join(repoRoot, relative)).href) as T;
}

export const diagnoseModule = (): Promise<DiagnoseModule> => load('src/planner/diagnose.ts');
export const planModule = (): Promise<PlanModule> => load('src/planner/plan.ts');
export const commandModule = (): Promise<CommandModule> => load('src/commands/liquidity-diagnose.ts');

/** A fixed database-clock reading in unix milliseconds. */
export const NOW = 1_800_000_000_000;
export const fixedClock = (now: number = NOW): Clock => ({ now: () => now });

export const SECOND = 1000;
export const MINUTE = 60 * SECOND;
export const HOUR = 60 * MINUTE;

export const NODE = 'cln-m';
export const NODE_ID = '01JC0000000000000000000000';

/** Quoted from CLN v26.06 doc/schemas/listpeerchannels.json, as normalisation stores it. */
export const CLN_CAVEAT =
  'spendable_msat: An estimate of the total we could send through channel (can be wrong because adding HTLCs requires an increase in fees paid to onchain miners, and onchain fees change dynamically according to onchain activity). ' +
  'receivable_msat: An estimate of the total peer could send through channel.';

/** The policy example of SPEC §7.1, durations in milliseconds, msat as bigint; targets per test. */
export function policy(targets: PlanningPolicy['targets'], overrides: Partial<PlanningPolicy> = {}): PlanningPolicy {
  return {
    fees: { max_fee_msat: 300_000n, max_fee_ppm: 2_500n, exempt_fee_msat: 5_000n },
    routing: { max_cltv_delta: 144 },
    amounts: { min_channel_reserve_msat: 50_000_000n, max_principal_msat: 100_000_000n, min_principal_msat: 10_000_000n },
    budget: { msat: 2_000_000n, period: 24 * HOUR },
    cooldown_after_failure: HOUR,
    cooldown_after_success: 30 * MINUTE,
    max_in_flight: 1,
    max_snapshot_age: 60 * SECOND,
    proposal_ttl: 15 * MINUTE,
    demand: { mode: 'targets', horizon: 6 * HOUR },
    targets,
    exclude_channels: [],
    ...overrides,
  };
}

export interface ChannelSpec {
  readonly capacity: bigint;
  readonly spendable: bigint;
  readonly receivable: bigint;
  readonly confidence?: Confidence;
  readonly state?: ChannelState;
  readonly observedAt?: number;
  readonly blockHeight?: number;
}

/** A normalised channel (ACTIVE unless given) as a snapshot stores it; observedAt is the snapshot's observed_at. */
export function channel(key: string, spec: ChannelSpec): NormalizedChannel {
  const confidence = spec.confidence ?? 'NODE_REPORTED';
  return {
    nodeId: NODE_ID,
    channelKey: key,
    scid: key,
    peerPubkey: `02${key.replace(/x/g, '0').padStart(64, '0')}`,
    fundingOutpoint: `${'ab'.repeat(32)}:${key.split('x')[2] ?? '0'}`,
    state: spec.state ?? 'ACTIVE',
    nodeState: 'CHANNELD_NORMAL',
    opener: 'local',
    capacityMsat: spec.capacity,
    localBalanceMsat: spec.spendable,
    remoteBalanceMsat: spec.receivable,
    spendableMsat: spec.spendable,
    receivableMsat: spec.receivable,
    confidence,
    caveat: confidence === 'NODE_REPORTED' ? CLN_CAVEAT : null,
    localReserveMsat: 0n,
    remoteReserveMsat: 0n,
    pendingOutMsat: 0n,
    pendingInMsat: 0n,
    pendingHtlcCount: 0,
    localMaxPendingAmtMsat: null,
    remoteMaxPendingAmtMsat: null,
    observedAt: spec.observedAt ?? NOW - 5 * SECOND,
    blockHeight: spec.blockHeight ?? 431,
    provenance: {},
  };
}

/** JSON text of a value with bigint amounts as decimal strings, for byte comparisons. */
export function canonical(value: unknown): string {
  return JSON.stringify(value, (_key, inner: unknown) => typeof inner === 'bigint' ? inner.toString() : inner);
}

export function ok(diagnosis: Diagnosis): OkDiagnosis {
  if (diagnosis.status !== 'OK') throw new Error(`diagnosis is ${diagnosis.status}, expected OK`);
  return diagnosis;
}
