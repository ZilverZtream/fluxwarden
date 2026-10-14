/*
Interface:
  src/policy/yaml.ts
    export type YamlValue = string | null | YamlValue[] | { [key: string]: YamlValue };
    export function parseYamlSubset(text: string): YamlValue;
      Subset of SPEC §7.1: block mappings, block sequences (also of mappings), plain and quoted
      scalars, comments. Every scalar is returned as a string (no type resolution); an empty
      value is null; single quotes escape by doubling, `#` starts a comment only after whitespace.
      Refused with PolicyError { exitCode: 2, field: null }: anchors, aliases, tags, flow
      collections, block scalars (| and >), more than one document, tab indentation, duplicate
      keys (also when one is quoted), nesting deeper than 64 levels, input over 64 KiB (65,536 bytes,
      SECURITY.md §5), a plain scalar containing ": ". A leading UTF-8 BOM is ignored.
  src/policy/errors.ts
    export class PolicyError extends Error { name: 'PolicyError'; exitCode: 1 | 2; field: string | null }
      `field` is the dotted path of the offending key (e.g. "fees.max_fee_ppm"); the message names it.
  src/policy/load.ts
    export function loadPolicy(text: string): Policy;   // throws PolicyError
      Exit 2: invalid subset, unknown or missing required field, malformed value, value outside
      its bounds (negative amounts or above 2^63 - 1, ppm outside 0..1,000,000, max_cltv_delta outside
      1..2016, zero principal bounds, min_principal_msat above max_principal_msat (named field
      amounts.min_principal_msat), max_in_flight 0, demand.ewma.alpha outside (0, 1]). Exit 1: `network` other than exactly "regtest", max_snapshot_age above 60 s.
      Amounts are canonical decimal msat strings (no unit, no exponent). Durations are
      <int>(s|m|h|d) and are held as integer seconds. Decimal factors stay strings.
      Defaults (SPEC §7.2): network regtest, exempt_fee_msat 0, max_cltv_delta 144,
      cooldown_after_failure 1h, cooldown_after_success 30m, max_in_flight 1, exclude_channels [].
  src/policy/canonical.ts
    export function canonicalPolicyJson(policy: Policy): string;
      JSON with keys sorted by UTF-16 code unit at every level, no insignificant whitespace,
      msat values as decimal strings, integers (ppm, CLTV, counts, seconds) as JSON numbers.
    export function policySha256(policy: Policy): string;   // lowercase hex SHA-256 of the canonical JSON (UTF-8)
  src/policy/versions.ts
    export function recordPolicyVersion(policy: Policy, repo: PolicyVersionRepository,
      deps: { now(): number; newId(): string; author: string }): { id: string; policySha256: string; created: boolean };
      repo: { findBySha256(sha256): PolicyVersionRow | null; insert(row without version_no): PolicyVersionRow }
      (the row shape is SPEC §6.2 policy_versions; see test/fakes/policy-versions.ts).
*/
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { MemoryPolicyVersions, type PolicyVersionRow } from '../fakes/policy-versions.js';
import { loadSrc, thrown } from '../helpers/load-src.js';

type YamlValue = string | null | YamlValue[] | { [key: string]: YamlValue };
interface TargetEntry { min_inbound_msat?: bigint; min_outbound_msat?: bigint }
interface Policy {
  version: number;
  network: string;
  fees: { max_fee_msat: bigint; max_fee_ppm: number; exempt_fee_msat: bigint };
  routing: { max_cltv_delta: number };
  amounts: { min_channel_reserve_msat: bigint; max_principal_msat: bigint; min_principal_msat: bigint };
  budget: { msat: bigint; period: number };
  cooldown_after_failure: number;
  cooldown_after_success: number;
  max_in_flight: number;
  max_snapshot_age: number;
  proposal_ttl: number;
  approval_max_ttl: number;
  demand: { mode: string; horizon: number; burst_factor: string; ewma: { bucket_seconds: number; alpha: string; min_samples: number } };
  targets: Record<string, Record<string, TargetEntry>>;
  exclude_channels: string[];
}
interface YamlModule { parseYamlSubset: (text: string) => YamlValue }
interface LoadModule { loadPolicy: (text: string) => Policy }
interface CanonicalModule { canonicalPolicyJson: (policy: Policy) => string; policySha256: (policy: Policy) => string }
interface VersionsModule {
  recordPolicyVersion: (policy: Policy, repo: MemoryPolicyVersions, deps: { now: () => number; newId: () => string; author: string }) => { id: string; policySha256: string; created: boolean };
}

const yaml = (): Promise<YamlModule> => loadSrc<YamlModule>('policy/yaml.ts');
const load = (): Promise<LoadModule> => loadSrc<LoadModule>('policy/load.ts');
const canonical = (): Promise<CanonicalModule> => loadSrc<CanonicalModule>('policy/canonical.ts');
const versions = (): Promise<VersionsModule> => loadSrc<VersionsModule>('policy/versions.ts');

// The SPEC §7.1 example, value for value. Its two flow collections are written as block
// collections, because §7.1 refuses flow collections: the per-channel targets become nested
// block mappings, and the empty `exclude_channels: []` is omitted (an empty list cannot be
// written in block style; the default is the empty list).
const EXAMPLE = `# fluxwarden policy, version 3
version: 3
network: regtest                 # the only value that permits execution (INV-15)

fees:
  max_fee_msat: "300000"         # absolute cap per rebalance, always enforced
  max_fee_ppm: 2500              # ceil(fee * 1e6 / principal) must not exceed this
  exempt_fee_msat: "5000"        # fees at or below this skip the ppm check, never the absolute cap

routing:
  max_cltv_delta: 144            # total, incl. final delta and LND padding (INV-16)

amounts:
  min_channel_reserve_msat: "50000000"   # floor left on the source channel (INV-14)
  max_principal_msat: "100000000"
  min_principal_msat: "10000000"

budget:
  msat: "2000000"                # routing fees per period, worst-case reservation of in-flight attempts
  period: 24h

cooldown_after_failure: 1h       # per channel pair
cooldown_after_success: 30m      # per channel
max_in_flight: 1                 # executions in SUBMITTING, IN_FLIGHT or UNKNOWN per node
max_snapshot_age: 60s            # INV-6 bound; values above 60s are refused
proposal_ttl: 15m
approval_max_ttl: 15m

demand:
  mode: targets                  # targets | ewma (ewma is a later milestone)
  horizon: 6h
  burst_factor: "1.4"
  ewma:
    bucket_seconds: 3600         # 10 in the lab demo
    alpha: "0.35"
    min_samples: 12

targets:                         # operator targets per node and channel
  cln-m:
    channel-2:
      min_inbound_msat: "150000000"
    channel-5:
      min_inbound_msat: "50000000"
  lnd-r:
    channel-3:
      min_inbound_msat: "100000000"
`;

// The validated example: msat as bigint, durations in seconds (24h = 86400, 1h = 3600, 30m = 1800,
// 60s = 60, 15m = 900, 6h = 21600), decimal factors as their strings.
const EXAMPLE_OBJECT: Policy = {
  version: 3,
  network: 'regtest',
  fees: { max_fee_msat: 300000n, max_fee_ppm: 2500, exempt_fee_msat: 5000n },
  routing: { max_cltv_delta: 144 },
  amounts: { min_channel_reserve_msat: 50000000n, max_principal_msat: 100000000n, min_principal_msat: 10000000n },
  budget: { msat: 2000000n, period: 86400 },
  cooldown_after_failure: 3600,
  cooldown_after_success: 1800,
  max_in_flight: 1,
  max_snapshot_age: 60,
  proposal_ttl: 900,
  approval_max_ttl: 900,
  demand: { mode: 'targets', horizon: 21600, burst_factor: '1.4', ewma: { bucket_seconds: 3600, alpha: '0.35', min_samples: 12 } },
  targets: {
    'cln-m': { 'channel-2': { min_inbound_msat: 150000000n }, 'channel-5': { min_inbound_msat: 50000000n } },
    'lnd-r': { 'channel-3': { min_inbound_msat: 100000000n } },
  },
  exclude_channels: [],
};

// Canonical form written out by hand from SPEC §7.1: sorted keys, msat as strings, no whitespace.
const EXAMPLE_CANONICAL = '{"amounts":{"max_principal_msat":"100000000","min_channel_reserve_msat":"50000000","min_principal_msat":"10000000"},'
  + '"approval_max_ttl":900,"budget":{"msat":"2000000","period":86400},"cooldown_after_failure":3600,"cooldown_after_success":1800,'
  + '"demand":{"burst_factor":"1.4","ewma":{"alpha":"0.35","bucket_seconds":3600,"min_samples":12},"horizon":21600,"mode":"targets"},'
  + '"exclude_channels":[],"fees":{"exempt_fee_msat":"5000","max_fee_msat":"300000","max_fee_ppm":2500},"max_in_flight":1,'
  + '"max_snapshot_age":60,"network":"regtest","proposal_ttl":900,"routing":{"max_cltv_delta":144},'
  + '"targets":{"cln-m":{"channel-2":{"min_inbound_msat":"150000000"},"channel-5":{"min_inbound_msat":"50000000"}},'
  + '"lnd-r":{"channel-3":{"min_inbound_msat":"100000000"}}},"version":3}';

// The same policy: keys in another order at every level, other spacing and comments, other quoting.
const REORDERED = `targets:
    lnd-r:
        channel-3:
            min_inbound_msat: '100000000'
    cln-m:
        channel-5:
            min_inbound_msat: "50000000"
        channel-2:
            min_inbound_msat: "150000000"
demand:
    ewma:
        min_samples: 12
        alpha: "0.35"
        bucket_seconds: 3600
    burst_factor: '1.4'
    horizon: 6h
    mode: targets
approval_max_ttl: 15m
proposal_ttl: 15m
max_snapshot_age: 60s
max_in_flight: 1
cooldown_after_success: 30m
cooldown_after_failure: 1h
# a comment line

budget:
    period: 24h
    msat: "2000000"
amounts:
    min_principal_msat: "10000000"
    max_principal_msat: "100000000"
    min_channel_reserve_msat: "50000000"
routing:
    max_cltv_delta:    144
fees:
    exempt_fee_msat: "5000"
    max_fee_ppm: 2500     # trailing comment
    max_fee_msat: "300000"
network: "regtest"
version: 3
`;

function variant(from: string, to: string): string {
  if (!EXAMPLE.includes(from)) throw new Error(`fixture text not found: ${from}`);
  return EXAMPLE.replace(from, to);
}

function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

describe('policy file', () => {
  it('CP-019/B1 the specification example parses to the exact validated object', async () => {
    const { loadPolicy } = await load();
    expect(loadPolicy(EXAMPLE)).toStrictEqual(EXAMPLE_OBJECT);
  });

  it('CP-019/B1 omitted optional fields take the design defaults of the field table', async () => {
    const { loadPolicy } = await load();
    const minimal = variant('network: regtest                 # the only value that permits execution (INV-15)\n', '')
      .replace('  exempt_fee_msat: "5000"        # fees at or below this skip the ppm check, never the absolute cap\n', '')
      .replace('routing:\n  max_cltv_delta: 144            # total, incl. final delta and LND padding (INV-16)\n', '')
      .replace('cooldown_after_failure: 1h       # per channel pair\n', '')
      .replace('cooldown_after_success: 30m      # per channel\n', '')
      .replace('max_in_flight: 1                 # executions in SUBMITTING, IN_FLIGHT or UNKNOWN per node\n', '');
    expect(minimal).not.toMatch(/network|exempt_fee_msat|max_cltv_delta|cooldown_after|max_in_flight/);
    expect(loadPolicy(minimal)).toStrictEqual({
      ...EXAMPLE_OBJECT,
      fees: { max_fee_msat: 300000n, max_fee_ppm: 2500, exempt_fee_msat: 0n },
      routing: { max_cltv_delta: 144 },
      cooldown_after_failure: 3600,
      cooldown_after_success: 1800,
      max_in_flight: 1,
    });
  });

  it('CP-019/B1 a block sequence of channel keys loads into exclude_channels in order', async () => {
    const { loadPolicy } = await load();
    const policy = loadPolicy(`${EXAMPLE}exclude_channels:\n  - "103x1x0"\n  - 999x2x1\n`);
    expect(policy.exclude_channels).toStrictEqual(['103x1x0', '999x2x1']);
  });

  const outOfBounds: readonly (readonly [string, string, string])[] = [
    ['max_fee_msat: "300000"', 'max_fee_msat: "-1"', 'fees.max_fee_msat'],
    ['max_fee_ppm: 2500', 'max_fee_ppm: -1', 'fees.max_fee_ppm'],
    ['max_fee_ppm: 2500', 'max_fee_ppm: 1000001', 'fees.max_fee_ppm'],
    ['max_fee_ppm: 2500', 'max_fee_ppm: 2500.5', 'fees.max_fee_ppm'],
    ['exempt_fee_msat: "5000"', 'exempt_fee_msat: "-5000"', 'fees.exempt_fee_msat'],
    ['max_cltv_delta: 144', 'max_cltv_delta: 2017', 'routing.max_cltv_delta'],
    ['max_cltv_delta: 144', 'max_cltv_delta: -1', 'routing.max_cltv_delta'],
    ['max_cltv_delta: 144', 'max_cltv_delta: 0', 'routing.max_cltv_delta'],
    ['min_channel_reserve_msat: "50000000"', 'min_channel_reserve_msat: "-1"', 'amounts.min_channel_reserve_msat'],
    // A zero principal leaves ceil(F * 10^6 / P) undefined (SPEC §4.4).
    ['min_principal_msat: "10000000"', 'min_principal_msat: "0"', 'amounts.min_principal_msat'],
    ['max_principal_msat: "100000000"', 'max_principal_msat: "0"', 'amounts.max_principal_msat'],
    ['msat: "2000000"', 'msat: "-2000000"', 'budget.msat'],
    ['max_in_flight: 1', 'max_in_flight: -1', 'max_in_flight'],
    // Unit mix-ups: amounts are bare decimal msat strings (SPEC §4.3), durations need a unit (§7.1).
    ['max_fee_msat: "300000"', 'max_fee_msat: "300sat"', 'fees.max_fee_msat'],
    ['max_fee_msat: "300000"', 'max_fee_msat: "3e5"', 'fees.max_fee_msat'],
    ['max_fee_msat: "300000"', 'max_fee_msat: "0.3"', 'fees.max_fee_msat'],
    ['max_fee_ppm: 2500', 'max_fee_ppm: 0.25%', 'fees.max_fee_ppm'],
    ['period: 24h', 'period: 24', 'budget.period'],
    ['period: 24h', 'period: 1.5h', 'budget.period'],
    ['period: 24h', 'period: 24 hours', 'budget.period'],
    ['cooldown_after_failure: 1h', 'cooldown_after_failure: -1h', 'cooldown_after_failure'],
  ];

  it.each(outOfBounds)('CP-019/B2 %s changed to %s exits 2 naming %s', async (from, to, field) => {
    const { loadPolicy } = await load();
    const error = thrown(() => loadPolicy(variant(from, to)));
    expect(error.name).toBe('PolicyError');
    expect(error.exitCode).toBe(2);
    expect(error.field).toBe(field);
    expect(error.message).toContain(field.split('.').pop());
  });

  it('CP-019/B2 a missing required field exits 2 naming it', async () => {
    const { loadPolicy } = await load();
    for (const [line, field] of [
      ['  max_fee_ppm: 2500              # ceil(fee * 1e6 / principal) must not exceed this\n', 'fees.max_fee_ppm'],
      ['  max_fee_msat: "300000"         # absolute cap per rebalance, always enforced\n', 'fees.max_fee_msat'],
      ['  min_channel_reserve_msat: "50000000"   # floor left on the source channel (INV-14)\n', 'amounts.min_channel_reserve_msat'],
    ] as const) {
      const error = thrown(() => loadPolicy(variant(line, '')));
      expect(error.exitCode, field).toBe(2);
      expect(error.field, field).toBe(field);
    }
  });

  it('CP-019/B2 the bounds themselves are accepted: ppm 1,000,000, max_cltv_delta 1 and 2016, zero exemption', async () => {
    const { loadPolicy } = await load();
    const policy = loadPolicy(variant('max_fee_ppm: 2500', 'max_fee_ppm: 1000000')
      .replace('max_cltv_delta: 144', 'max_cltv_delta: 2016')
      .replace('exempt_fee_msat: "5000"', 'exempt_fee_msat: "0"'));
    expect(policy.fees).toStrictEqual({ max_fee_msat: 300000n, max_fee_ppm: 1000000, exempt_fee_msat: 0n });
    expect(policy.routing.max_cltv_delta).toBe(2016);
    expect(loadPolicy(variant('max_cltv_delta: 144', 'max_cltv_delta: 1')).routing.max_cltv_delta).toBe(1);
    // Amounts above the JavaScript number range keep every digit (SPEC §4.3).
    expect(loadPolicy(variant('msat: "2000000"', 'msat: "9007199254740993"')).budget.msat).toBe(9007199254740993n);
  });

  // SECURITY.md §4.4 accepts exactly `regtest` and refuses every other or empty value; SPEC §10.3 G3: exit 1.
  it.each(['mainnet', 'bitcoin', 'testnet', 'testnet4', 'signet', 'simnet', 'liquid-regtest', 'Regtest', '"regtest "', '""'])(
    'CP-019/B3 network %s exits 1 naming the network field', async network => {
      const { loadPolicy } = await load();
      const error = thrown(() => loadPolicy(variant('network: regtest ', `network: ${network} `)));
      expect(error.name).toBe('PolicyError');
      expect(error.exitCode).toBe(1);
      expect(error.field).toBe('network');
    });

  // SPEC §10.3 G3 names max_snapshot_age > 60 s as an out-of-range value (exit 1); §7.1 "values above 60s are refused".
  it('CP-019/B3 max_snapshot_age above 60 s exits 1; 60 s, 1m and 59 s are accepted', async () => {
    const { loadPolicy } = await load();
    const error = thrown(() => loadPolicy(variant('max_snapshot_age: 60s', 'max_snapshot_age: 61s')));
    expect(error.exitCode).toBe(1);
    expect(error.field).toBe('max_snapshot_age');
    expect(loadPolicy(variant('max_snapshot_age: 60s', 'max_snapshot_age: 1m')).max_snapshot_age).toBe(60);
    expect(loadPolicy(variant('max_snapshot_age: 60s', 'max_snapshot_age: 59s')).max_snapshot_age).toBe(59);
  });

  it('CP-019/B4 the canonical form and SHA-256 of the example match the hand-written canonical JSON', async () => {
    const { loadPolicy } = await load();
    const { canonicalPolicyJson, policySha256 } = await canonical();
    const policy = loadPolicy(EXAMPLE);
    expect(canonicalPolicyJson(policy)).toBe(EXAMPLE_CANONICAL);
    expect(policySha256(policy)).toBe(sha256Hex(EXAMPLE_CANONICAL));
    expect(policySha256(policy)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('CP-019/B4 key order, whitespace, comments and quoting do not change the hash; a value does', async () => {
    const { loadPolicy } = await load();
    const { policySha256 } = await canonical();
    const reference = sha256Hex(EXAMPLE_CANONICAL);
    expect(policySha256(loadPolicy(REORDERED))).toBe(reference);
    expect(policySha256(loadPolicy(variant('max_fee_ppm: 2500', 'max_fee_ppm: 2501')))).not.toBe(reference);
    expect(policySha256(loadPolicy(variant('min_inbound_msat: "50000000"', 'min_inbound_msat: "50000001"')))).not.toBe(reference);
  });

  it('CP-019/B4 a policy is stored once per hash with its canonical JSON', async () => {
    const { loadPolicy } = await load();
    const { recordPolicyVersion } = await versions();
    const repo = new MemoryPolicyVersions();
    const ids = ['pv_1', 'pv_2', 'pv_3'];
    const deps = { now: () => 1_800_000_000_000, newId: () => ids.shift() ?? 'pv_exhausted', author: 'operator' };
    const first = recordPolicyVersion(loadPolicy(EXAMPLE), repo, deps);
    const again = recordPolicyVersion(loadPolicy(REORDERED), repo, deps);
    expect(first).toStrictEqual({ id: 'pv_1', policySha256: sha256Hex(EXAMPLE_CANONICAL), created: true });
    expect(again).toStrictEqual({ id: 'pv_1', policySha256: sha256Hex(EXAMPLE_CANONICAL), created: false });
    expect(repo.rows).toStrictEqual<PolicyVersionRow[]>([{
      id: 'pv_1', version_no: 1, policy_sha256: sha256Hex(EXAMPLE_CANONICAL),
      policy_canonical_json: EXAMPLE_CANONICAL, author: 'operator', created_at: 1_800_000_000_000,
    }]);
    const changed = recordPolicyVersion(loadPolicy(variant('max_fee_ppm: 2500', 'max_fee_ppm: 2400')), repo, deps);
    expect(changed.created).toBe(true);
    expect(repo.rows.map(row => row.version_no)).toStrictEqual([1, 2]);
    expect(repo.rows[1]?.policy_canonical_json).toBe(EXAMPLE_CANONICAL.replace('"max_fee_ppm":2500', '"max_fee_ppm":2400'));
  });

  it.each([
    ['a top-level unknown key', `${EXAMPLE}max_fee: "5"\n`, 'max_fee'],
    ['an unknown key inside fees', variant('  max_fee_ppm: 2500', '  max_fee_sat: "300"\n  max_fee_ppm: 2500'), 'fees.max_fee_sat'],
    ['an unknown key inside a target', variant('      min_inbound_msat: "50000000"', '      min_inbound_msat: "50000000"\n      min_inbound_sat: "5"'), 'targets.cln-m.channel-5.min_inbound_sat'],
  ])('CP-019/B5 %s exits 2 naming it', async (_name, text, field) => {
    const { loadPolicy } = await load();
    const error = thrown(() => loadPolicy(text));
    expect(error.exitCode).toBe(2);
    expect(error.field).toBe(field);
  });
});

describe('YAML subset reader', () => {
  it('CP-019/B6 the subset reads block mappings, sequences, quoted and plain scalars and comments', async () => {
    const { parseYamlSubset } = await yaml();
    const text = [
      '# leading comment',
      'plain: some words  # trailing comment',
      'hash_inside: a#b',
      'double: "x &y *z {w} [v] # not a comment"',
      "single: 'it''s: fine'",
      'number: 0012',
      'empty:',
      'nested:',
      '  inner:',
      '    deep: "1"',
      'items:',
      '  - name: first',
      '    url: "https://example.invalid"',
      '  - plain item',
      '',
    ].join('\n');
    expect(parseYamlSubset(text)).toStrictEqual({
      plain: 'some words',
      hash_inside: 'a#b',
      double: 'x &y *z {w} [v] # not a comment',
      single: "it's: fine",
      number: '0012',
      empty: null,
      nested: { inner: { deep: '1' } },
      items: [{ name: 'first', url: 'https://example.invalid' }, 'plain item'],
    });
  });

  const refused: readonly (readonly [string, string])[] = [
    ['an anchor', 'a: &anchor value\nb: other\n'],
    ['an alias', 'a: value\nb: *anchor\n'],
    ['an anchor on a mapping', 'fees: &caps\n  max_fee_ppm: "1"\n'],
    ['a merge key with an alias', 'base:\n  x: "1"\nother:\n  <<: *base\n'],
    ['a core tag', 'a: !!str value\n'],
    ['a local tag', 'a: !custom value\n'],
    ['a language-object tag', 'a: !!python/object/apply:os.system ["true"]\n'],
    ['a verbatim tag', 'a: !<tag:yaml.org,2002:str> value\n'],
    ['a flow mapping', 'a: { b: c }\n'],
    ['an empty flow mapping', 'a: {}\n'],
    ['a flow sequence', 'a: [b, c]\n'],
    ['an empty flow sequence', 'a: []\n'],
    ['a flow sequence item', 'a:\n  - [b]\n'],
    ['a literal block scalar', 'a: |\n  text\n'],
    ['a folded block scalar', 'a: >\n  text\n'],
    ['a second document', 'a: b\n---\nc: d\n'],
    ['tab indentation', 'a:\n\tb: c\n'],
    ['a duplicate key', 'a: "1"\na: "2"\n'],
    ['a duplicate nested key', 'fees:\n  max_fee_ppm: "1"\n  max_fee_ppm: "2000000"\n'],
    ['a duplicate key spelled with quotes', 'a: "1"\n"a": "2"\n'],
  ];

  it.each(refused)('CP-019/B6 %s is refused with exit 2', async (_name, text) => {
    const { parseYamlSubset } = await yaml();
    const error = thrown(() => parseYamlSubset(text));
    expect(error.name).toBe('PolicyError');
    expect(error.exitCode).toBe(2);
    expect(error.field).toBeNull();
  });

  it('CP-019/B6 subset features hidden in a policy are refused, not read as text', async () => {
    const { loadPolicy } = await load();
    // Read as a plain scalar, "&n regtest" would be a wrong network (exit 1, field network); the subset refuses it first.
    for (const text of [
      variant('network: regtest ', 'network: &n regtest '),
      variant('max_fee_ppm: 2500', 'max_fee_ppm: !!int 2500'),
      `${EXAMPLE}exclude_channels: []\n`,
      // A last-wins reader would let a second key loosen the cap.
      variant('fees:\n  max_fee_msat: "300000"', 'fees:\n  max_fee_msat: "300000"\n  max_fee_msat: "900000000"'),
    ]) {
      const error = thrown(() => loadPolicy(text));
      expect(error.exitCode).toBe(2);
      expect(error.field).toBeNull();
    }
  });

  it('CP-019/B6 hostile nesting and size are refused with exit 2 without exhausting the stack', async () => {
    const { parseYamlSubset } = await yaml();
    const nested = (depth: number): string => Array.from({ length: depth }, (_, level) => `${'  '.repeat(level)}k${String(level)}:`).join('\n') + ' "leaf"\n';
    expect(parseYamlSubset(nested(8))).toStrictEqual({ k0: { k1: { k2: { k3: { k4: { k5: { k6: { k7: 'leaf' } } } } } } } });
    const deep = thrown(() => parseYamlSubset(nested(200)));
    expect(deep.name).toBe('PolicyError');
    expect(deep.exitCode).toBe(2);
    const sequenceDeep = Array.from({ length: 200 }, (_, level) => `${'    '.repeat(level)}- k${String(level)}:`).join('\n') + ' x\n';
    expect(thrown(() => parseYamlSubset(sequenceDeep)).exitCode).toBe(2);
  });

  // SECURITY.md §5 bounded inputs: a policy or configuration file is at most 64 KiB.
  it('CP-019/B6 a policy file of exactly 64 KiB is read and one byte more is refused', async () => {
    const { parseYamlSubset } = await yaml();
    const { loadPolicy } = await load();
    const limit = 64 * 1024;
    const padded = (size: number): string => {
      const head = `${EXAMPLE}#`;
      return `${head}${'x'.repeat(size - Buffer.byteLength(head) - 1)}\n`;
    };
    expect(Buffer.byteLength(padded(limit))).toBe(limit);
    expect(loadPolicy(padded(limit))).toStrictEqual(EXAMPLE_OBJECT);
    expect(Buffer.byteLength(padded(limit + 1))).toBe(limit + 1);
    expect(thrown(() => parseYamlSubset(padded(limit + 1))).exitCode).toBe(2);
    expect(thrown(() => loadPolicy(padded(limit + 1))).exitCode).toBe(2);
  });

  it('CP-019/B6 a plain scalar containing ": " is refused', async () => {
    const { parseYamlSubset } = await yaml();
    expect(thrown(() => parseYamlSubset('a: b: c\n')).exitCode).toBe(2);
    expect(parseYamlSubset('a: "b: c"\n')).toStrictEqual({ a: 'b: c' });
  });

  it('CP-019/B6 a leading UTF-8 byte order mark is ignored', async () => {
    const { loadPolicy } = await load();
    expect(loadPolicy(`\uFEFF${EXAMPLE}`)).toStrictEqual(EXAMPLE_OBJECT);
  });
});

describe('policy bounds', () => {
  const refusedAt = async (text: string, field: string): Promise<void> => {
    const { loadPolicy } = await load();
    const error = thrown(() => loadPolicy(text));
    expect(error.exitCode, field).toBe(2);
    expect(error.field, field).toBe(field);
  };

  it('CP-019/B2 min_principal_msat above max_principal_msat is refused; equal bounds are accepted', async () => {
    const { loadPolicy } = await load();
    await refusedAt(variant('min_principal_msat: "10000000"', 'min_principal_msat: "100000001"'), 'amounts.min_principal_msat');
    expect(loadPolicy(variant('min_principal_msat: "10000000"', 'min_principal_msat: "100000000"')).amounts.min_principal_msat).toBe(100000000n);
  });

  it('CP-019/B2 the d unit is 86,400 seconds', async () => {
    const { loadPolicy } = await load();
    const policy = loadPolicy(variant('cooldown_after_failure: 1h', 'cooldown_after_failure: 2d').replace('period: 24h', 'period: 1d'));
    expect(policy.cooldown_after_failure).toBe(172800);
    expect(policy.budget.period).toBe(86400);
  });

  it('CP-019/B2 max_in_flight 0 is refused', async () => {
    await refusedAt(variant('max_in_flight: 1', 'max_in_flight: 0'), 'max_in_flight');
  });

  it('CP-019/B2 an amount above 2^63 - 1 msat is refused; 2^63 - 1 is accepted', async () => {
    const { loadPolicy } = await load();
    expect(loadPolicy(variant('msat: "2000000"', 'msat: "9223372036854775807"')).budget.msat).toBe(9223372036854775807n);
    for (const [from, to, field] of [
      ['msat: "2000000"', 'msat: "9223372036854775808"', 'budget.msat'],
      ['max_fee_msat: "300000"', 'max_fee_msat: "18446744073709551615"', 'fees.max_fee_msat'],
      ['min_inbound_msat: "50000000"', 'min_inbound_msat: "9223372036854775808"', 'targets.cln-m.channel-5.min_inbound_msat'],
    ] as const) await refusedAt(variant(from, to), field);
  });

  it('CP-019/B2 demand.ewma.alpha must lie in (0, 1]', async () => {
    const { loadPolicy } = await load();
    for (const alpha of ['"0"', '"0.0"', '"1.5"', '"1.0001"', '"2"']) await refusedAt(variant('alpha: "0.35"', `alpha: ${alpha}`), 'demand.ewma.alpha');
    expect(loadPolicy(variant('alpha: "0.35"', 'alpha: "1"')).demand.ewma.alpha).toBe('1');
    expect(loadPolicy(variant('alpha: "0.35"', 'alpha: "0.001"')).demand.ewma.alpha).toBe('0.001');
  });
});
