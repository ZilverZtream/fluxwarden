// Policy file validation: the YAML subset is read first, then every field is checked against its
// type and bounds. Exit 2 names a malformed, unknown, missing or out-of-bounds field; exit 1 names
// a value the safety rules forbid (a network other than regtest, a snapshot age above 60 s).
import { MAX_INT64, type Msat } from '../core/money.js';
import { PolicyError } from './errors.js';
import type { Policy, TargetEntry } from './types.js';
import { parseYamlSubset, type YamlValue } from './yaml.js';

type Mapping = Readonly<Record<string, YamlValue>>;

const MAX_PPM = 1_000_000;
const MAX_CLTV_DELTA = 2016;
const MAX_SNAPSHOT_AGE_SECONDS = 60;
const UNIT_SECONDS: Readonly<Record<string, number>> = { s: 1, m: 60, h: 3600, d: 86_400 };

function isMapping(value: YamlValue | undefined): value is Mapping {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function invalid(field: string, message: string): PolicyError {
  return new PolicyError(2, field, message);
}

function join(path: string, key: string): string {
  return path === '' ? key : `${path}.${key}`;
}

function own<T>(target: Record<string, T>, key: string, value: T): void {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

/** A mapping of fixed fields: unknown keys are refused when it is opened. */
class Section {
  constructor(private readonly value: Mapping, private readonly path: string, allowed: readonly string[]) {
    for (const key of Object.keys(value)) {
      if (!allowed.includes(key)) throw invalid(join(path, key), 'unknown field');
    }
  }

  name(key: string): string {
    return join(this.path, key);
  }

  get(key: string): YamlValue | undefined {
    return Object.hasOwn(this.value, key) ? this.value[key] : undefined;
  }

  required(key: string): YamlValue {
    const value = this.get(key);
    if (value === undefined) throw invalid(this.name(key), 'is required');
    return value;
  }

  section(key: string, allowed: readonly string[], required: boolean): Section {
    const value = required ? this.required(key) : this.get(key) ?? {};
    if (!isMapping(value)) throw invalid(this.name(key), 'must be a mapping');
    return new Section(value, this.name(key), allowed);
  }

  amount(key: string, options: { positive?: boolean; fallback?: bigint } = {}): Msat {
    const value = options.fallback === undefined ? this.required(key) : this.get(key);
    if (value === undefined && options.fallback !== undefined) return options.fallback as Msat;
    return amount(value ?? null, this.name(key), options.positive === true);
  }

  integer(key: string, min: number, max: number, fallback?: number): number {
    const value = this.get(key);
    if (value === undefined && fallback !== undefined) return fallback;
    const field = this.name(key);
    const text = scalar(value ?? this.required(key), field);
    const parsed = /^(0|[1-9][0-9]{0,14})$/.test(text) ? Number(text) : Number.NaN;
    if (!(parsed >= min && parsed <= max)) throw invalid(field, `must be an integer from ${String(min)} to ${String(max)}`);
    return parsed;
  }

  duration(key: string, minSeconds: number, fallback?: number): number {
    const value = this.get(key);
    if (value === undefined && fallback !== undefined) return fallback;
    const field = this.name(key);
    const text = scalar(value ?? this.required(key), field);
    const match = /^(0|[1-9][0-9]{0,11})([smhd])$/.exec(text);
    const seconds = match === null ? Number.NaN : Number(match[1]) * (UNIT_SECONDS[match[2] ?? ''] ?? Number.NaN);
    if (!Number.isSafeInteger(seconds)) throw invalid(field, 'must be a duration <integer>(s|m|h|d)');
    if (seconds < minSeconds) throw invalid(field, `must be at least ${String(minSeconds)} s`);
    return seconds;
  }

  decimal(key: string): string {
    const field = this.name(key);
    const text = scalar(this.required(key), field);
    if (!/^(0|[1-9][0-9]*)(\.[0-9]+)?$/.test(text) || text.length > 40) throw invalid(field, 'must be a decimal number such as "1.4"');
    return text;
  }
}

function scalar(value: YamlValue, field: string): string {
  if (typeof value !== 'string') throw invalid(field, 'must be a scalar value');
  return value;
}

function amount(value: YamlValue, field: string, positive: boolean): Msat {
  const text = scalar(value, field);
  if (!/^(0|[1-9][0-9]{0,18})$/.test(text) || BigInt(text) > MAX_INT64) throw invalid(field, 'must be a decimal msat amount without unit or exponent');
  const parsed = BigInt(text);
  if (positive && parsed === 0n) throw invalid(field, 'must be greater than zero');
  return parsed as Msat;
}

function targets(value: YamlValue | undefined): Policy['targets'] {
  const result: Record<string, Record<string, TargetEntry>> = {};
  if (value === undefined || value === null) return result;
  if (!isMapping(value)) throw invalid('targets', 'must be a mapping of nodes');
  for (const [node, channels] of Object.entries(value)) {
    const nodePath = join('targets', node);
    if (!isMapping(channels)) throw invalid(nodePath, 'must be a mapping of channels');
    const perNode: Record<string, TargetEntry> = {};
    for (const [channel, entry] of Object.entries(channels)) {
      const path = join(nodePath, channel);
      if (!isMapping(entry)) throw invalid(path, 'must be a mapping with min_inbound_msat or min_outbound_msat');
      const section = new Section(entry, path, ['min_inbound_msat', 'min_outbound_msat']);
      const target: { min_inbound_msat?: Msat; min_outbound_msat?: Msat } = {};
      for (const key of ['min_inbound_msat', 'min_outbound_msat'] as const) {
        const raw = section.get(key);
        if (raw !== undefined) target[key] = amount(raw, section.name(key), false);
      }
      if (Object.keys(target).length === 0) throw invalid(path, 'must set min_inbound_msat or min_outbound_msat');
      own(perNode, channel, target);
    }
    own(result, node, perNode);
  }
  return result;
}

function excludeChannels(value: YamlValue | undefined): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw invalid('exclude_channels', 'must be a block sequence of channel keys');
  return value.map(item => {
    if (typeof item !== 'string' || item === '') throw invalid('exclude_channels', 'every entry must be a channel key');
    return item;
  });
}

function positiveDecimal(text: string): boolean {
  return /[1-9]/.test(text);
}

/** Reads and validates a policy file; throws PolicyError. */
export function loadPolicy(text: string): Policy {
  const document = parseYamlSubset(text);
  if (!isMapping(document)) throw new PolicyError(2, null, 'policy file: the document must be a mapping');
  const root = new Section(document, '', [
    'version', 'network', 'fees', 'routing', 'amounts', 'budget', 'cooldown_after_failure', 'cooldown_after_success',
    'max_in_flight', 'max_snapshot_age', 'proposal_ttl', 'approval_max_ttl', 'demand', 'targets', 'exclude_channels',
  ]);

  const version = root.integer('version', 1, 2 ** 31 - 1);
  const network = root.get('network');
  if (network !== undefined && network !== 'regtest') throw new PolicyError(1, 'network', 'only regtest is permitted');

  const feeSection = root.section('fees', ['max_fee_msat', 'max_fee_ppm', 'exempt_fee_msat'], true);
  const fees = {
    max_fee_msat: feeSection.amount('max_fee_msat'),
    max_fee_ppm: feeSection.integer('max_fee_ppm', 0, MAX_PPM),
    exempt_fee_msat: feeSection.amount('exempt_fee_msat', { fallback: 0n }),
  };

  const routingSection = root.section('routing', ['max_cltv_delta'], false);
  const routing = { max_cltv_delta: routingSection.integer('max_cltv_delta', 1, MAX_CLTV_DELTA, 144) };

  const amountSection = root.section('amounts', ['min_channel_reserve_msat', 'max_principal_msat', 'min_principal_msat'], true);
  const amounts = {
    min_channel_reserve_msat: amountSection.amount('min_channel_reserve_msat'),
    max_principal_msat: amountSection.amount('max_principal_msat', { positive: true }),
    min_principal_msat: amountSection.amount('min_principal_msat', { positive: true }),
  };
  if (amounts.min_principal_msat > amounts.max_principal_msat) throw invalid('amounts.min_principal_msat', 'must not exceed max_principal_msat');

  const budgetSection = root.section('budget', ['msat', 'period'], true);
  const budget = { msat: budgetSection.amount('msat'), period: budgetSection.duration('period', 1) };

  const cooldownAfterFailure = root.duration('cooldown_after_failure', 0, 3600);
  const cooldownAfterSuccess = root.duration('cooldown_after_success', 0, 1800);
  const maxInFlight = root.integer('max_in_flight', 1, 1_000_000, 1);
  const maxSnapshotAge = root.duration('max_snapshot_age', 1);
  if (maxSnapshotAge > MAX_SNAPSHOT_AGE_SECONDS) throw new PolicyError(1, 'max_snapshot_age', `must not exceed ${String(MAX_SNAPSHOT_AGE_SECONDS)} s`);
  const proposalTtl = root.duration('proposal_ttl', 1);
  const approvalMaxTtl = root.duration('approval_max_ttl', 1);

  const demandSection = root.section('demand', ['mode', 'horizon', 'burst_factor', 'ewma'], true);
  const mode = demandSection.required('mode');
  if (mode !== 'targets' && mode !== 'ewma') throw invalid('demand.mode', 'must be targets or ewma');
  const horizon = demandSection.duration('horizon', 1);
  const burstFactor = demandSection.decimal('burst_factor');
  if (!positiveDecimal(burstFactor)) throw invalid('demand.burst_factor', 'must be greater than zero');
  const ewmaSection = demandSection.section('ewma', ['bucket_seconds', 'alpha', 'min_samples'], true);
  const bucketSeconds = ewmaSection.integer('bucket_seconds', 1, 2 ** 31 - 1);
  const alpha = ewmaSection.decimal('alpha');
  if (!positiveDecimal(alpha) || !(/^0\./.test(alpha) || /^1(?:\.0+)?$/.test(alpha))) throw invalid('demand.ewma.alpha', 'must lie in (0, 1]');
  const minSamples = ewmaSection.integer('min_samples', 1, 1_000_000);

  return {
    version,
    network: 'regtest',
    fees,
    routing,
    amounts,
    budget,
    cooldown_after_failure: cooldownAfterFailure,
    cooldown_after_success: cooldownAfterSuccess,
    max_in_flight: maxInFlight,
    max_snapshot_age: maxSnapshotAge,
    proposal_ttl: proposalTtl,
    approval_max_ttl: approvalMaxTtl,
    demand: { mode, horizon, burst_factor: burstFactor, ewma: { bucket_seconds: bucketSeconds, alpha, min_samples: minSamples } },
    targets: targets(root.get('targets')),
    exclude_channels: excludeChannels(root.get('exclude_channels')),
  };
}
