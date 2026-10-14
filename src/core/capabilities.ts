/**
 * Capability negotiation, identity pinning and the regtest lock at connect time (SPEC §5.2
 * H3 to H6). The probes in the adapters observe; the decisions are made here.
 */

export type NodeCapability =
  | 'CHANNEL_READ' | 'PAYMENT_READ' | 'PAYMENT_TRACK' | 'INVOICE_CREATE' | 'INVOICE_CANCEL'
  | 'FORWARDING_READ' | 'BOOKKEEPER_READ' | 'EXPLICIT_ROUTE_CONTROL' | 'ASKRENE_LAYER_ROUTING';

export type NetworkType = 'regtest' | 'signet' | 'testnet' | 'testnet4' | 'mainnet';
export type Implementation = 'lnd' | 'cln';

/** What a rebalance needs from each implementation. */
export const REQUIRED_CAPABILITIES: { readonly lnd: readonly NodeCapability[]; readonly cln: readonly NodeCapability[] } = {
  lnd: ['CHANNEL_READ', 'PAYMENT_READ', 'PAYMENT_TRACK', 'INVOICE_CREATE', 'INVOICE_CANCEL', 'EXPLICIT_ROUTE_CONTROL'],
  cln: ['CHANNEL_READ', 'PAYMENT_READ', 'PAYMENT_TRACK', 'INVOICE_CREATE', 'INVOICE_CANCEL', 'ASKRENE_LAYER_ROUTING'],
};

export const EXIT_CAPABILITY_UNSUPPORTED = 3;
export const EXIT_SAFETY_REFUSAL = 5;

/** A node version, network or feature FluxWarden does not support; nothing is approximated (INV-10). */
export class CapabilityUnsupported extends Error {
  readonly code = 'CAPABILITY_UNSUPPORTED';
  readonly exitCode = EXIT_CAPABILITY_UNSUPPORTED;
  readonly missing: readonly NodeCapability[];

  constructor(message: string, missing: readonly NodeCapability[] = []) {
    super(message);
    this.name = 'CapabilityUnsupported';
    this.missing = [...missing];
  }
}

/** The node is not the configured one (INV-12), or a mutating command met a network other than regtest (INV-15). */
export class IdentityRefusal extends Error {
  readonly step: 'identity' | 'network-lock';
  readonly exitCode = EXIT_SAFETY_REFUSAL;

  constructor(message: string, step: 'identity' | 'network-lock' = 'identity') {
    super(message);
    this.name = 'IdentityRefusal';
    this.step = step;
  }
}

/** Throws CapabilityUnsupported naming every capability in `needed` that `available` lacks, in `needed` order. */
export function requireCapabilities(available: ReadonlySet<NodeCapability>, needed: readonly NodeCapability[]): void {
  const missing = needed.filter(capability => !available.has(capability));
  if (missing.length > 0) throw new CapabilityUnsupported(`node lacks ${missing.join(', ')}`, missing);
}

export interface NodeIdentity { pubkey: string; network: string; version: string; blockHeight: number; syncedToChain: boolean }
export interface ProbeResult { identity: NodeIdentity; capabilities: ReadonlySet<NodeCapability> }

export interface NodeProbeUpdate {
  nodeId: string; state: 'ONLINE' | 'QUARANTINED'; observedVersion: string | null; observedNetwork: string | null;
  capabilities: readonly NodeCapability[]; probedAtMs: number;
}

export interface NodeProbeStore { recordProbe: (update: NodeProbeUpdate) => Promise<void> }

export interface ProbeContext {
  nodeId: string; expectedPubkey: string; expectedNetwork: NetworkType; mutating: boolean;
  store: NodeProbeStore; nowMs: () => number;
}

/**
 * Network strings each implementation reports, and their FluxWarden names (SPEC §4.7):
 * LND NormalizeNetwork (rpcserver.go), CLN bitcoin/chainparams.c network_name. Matching is
 * exact and case-sensitive; anything else, simnet and liquid included, is unsupported.
 */
const NETWORKS: Readonly<Record<Implementation, ReadonlyMap<string, NetworkType>>> = {
  lnd: new Map([['mainnet', 'mainnet'], ['testnet', 'testnet'], ['testnet4', 'testnet4'], ['signet', 'signet'], ['regtest', 'regtest']]),
  cln: new Map([['bitcoin', 'mainnet'], ['testnet', 'testnet'], ['testnet4', 'testnet4'], ['signet', 'signet'], ['regtest', 'regtest']]),
};

export function normalizeNetwork(implementation: Implementation, raw: string): NetworkType | null {
  return NETWORKS[implementation].get(raw) ?? null;
}

/** A peer string for a message: bounded and JSON-quoted, so control characters cannot reach a terminal. */
function quoted(value: string): string {
  return JSON.stringify(value.length > 80 ? `${value.slice(0, 80)}...` : value);
}

/**
 * H3 on the raw identity answer, before it is parsed: a node that is not the configured one
 * is quarantined even when the rest of its answer is malformed. `observedPubkey` and
 * `observedVersion` are whatever the node sent.
 */
export async function checkPubkey(observedPubkey: unknown, observedVersion: unknown, context: ProbeContext): Promise<void> {
  if (observedPubkey === context.expectedPubkey) return;
  await context.store.recordProbe({
    nodeId: context.nodeId, state: 'QUARANTINED', observedVersion: typeof observedVersion === 'string' ? observedVersion : null,
    observedNetwork: null, capabilities: [], probedAtMs: context.nowMs(),
  });
  const shown = typeof observedPubkey === 'string' ? quoted(observedPubkey) : 'no pubkey';
  throw new IdentityRefusal(`node ${context.nodeId} quarantined: ${shown} is not the configured pubkey ${quoted(context.expectedPubkey)}`, 'identity');
}

/**
 * H3 then H4 on the identity answer, before any further call (SPEC §5.2, INV-12, INV-15):
 * a pubkey other than the configured one, or a supported network other than the configured
 * one, quarantines the node and exits 5 at step identity, whatever else is wrong; then a
 * mutating command on any network string but exactly "regtest" exits 5 at step
 * network-lock; then a network string outside SPEC §4.7 exits 3.
 */
export async function checkIdentity(implementation: Implementation, observed: { pubkey: string; network: string; version: string }, context: ProbeContext): Promise<void> {
  const network = normalizeNetwork(implementation, observed.network);
  const otherPubkey = observed.pubkey !== context.expectedPubkey;
  if (otherPubkey || (network !== null && network !== context.expectedNetwork)) {
    await context.store.recordProbe({
      nodeId: context.nodeId, state: 'QUARANTINED', observedVersion: observed.version, observedNetwork: observed.network,
      capabilities: [], probedAtMs: context.nowMs(),
    });
    const what = otherPubkey
      ? `pubkey ${quoted(observed.pubkey)} is not the configured ${quoted(context.expectedPubkey)}`
      : `network ${quoted(observed.network)} is not the configured ${quoted(context.expectedNetwork)}`;
    throw new IdentityRefusal(`node ${context.nodeId} quarantined: ${what}`, 'identity');
  }
  if (context.mutating && (observed.network !== 'regtest' || context.expectedNetwork !== 'regtest')) {
    throw new IdentityRefusal(`mutating commands run only on regtest; node ${context.nodeId} reports ${quoted(observed.network)}`, 'network-lock');
  }
  if (network === null) throw new CapabilityUnsupported(`unsupported network ${quoted(observed.network)}`);
}

/** H8: the successful probe's record for the `nodes` row. */
export async function recordOnline(identity: NodeIdentity, capabilities: ReadonlySet<NodeCapability>, context: ProbeContext): Promise<ProbeResult> {
  await context.store.recordProbe({
    nodeId: context.nodeId, state: 'ONLINE', observedVersion: identity.version, observedNetwork: identity.network,
    capabilities: [...capabilities].sort(), probedAtMs: context.nowMs(),
  });
  return { identity, capabilities };
}

/** A version as comparable numbers: whether `version` is at least `minimum`. */
export function atLeast(version: readonly number[], minimum: readonly number[]): boolean {
  for (let index = 0; index < minimum.length; index += 1) {
    const have = version[index] ?? 0, want = minimum[index] ?? 0;
    if (have !== want) return have > want;
  }
  return true;
}

/**
 * Why a node lacks a capability, from what the probe observed (SPEC §5.2 H5, H6): the router
 * sub-server and the LND 0.21 route-control fields; the askrene plugin and CLN v26.06 hop fields.
 */
export function missingCapabilityReason(implementation: Implementation, capability: NodeCapability, available: ReadonlySet<NodeCapability>): string {
  if (implementation === 'lnd') {
    if (capability === 'PAYMENT_TRACK') return 'the router sub-server does not answer (GetMissionControlConfig)';
    if (capability === 'EXPLICIT_ROUTE_CONTROL') {
      return available.has('PAYMENT_TRACK') ? 'LND below 0.21 lacks outgoing_chan_ids and the payment_addr requirement of SendToRouteV2' : 'the router sub-server does not answer (GetMissionControlConfig)';
    }
    if (capability === 'ASKRENE_LAYER_ROUTING') return 'a Core Lightning capability';
  } else {
    if (capability === 'ASKRENE_LAYER_ROUTING') return 'askrene does not answer askrene-listlayers, or Core Lightning is below v26.06';
    if (capability === 'EXPLICIT_ROUTE_CONTROL') return 'an LND capability';
  }
  return 'not offered by the node';
}
