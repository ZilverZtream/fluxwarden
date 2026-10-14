// A scripted node behind the adapter port the executor uses before dispatch (SPEC §5.1 LightningNodeAdapter).
// It records every call so tests can prove which node calls happened. Scripted behaviours:
// - handshake: identity pubkey, network, version and chain sync as SPEC §5.2 H2-H7 normalise them from LND GetInfo
//   (identity_pubkey, chains[].network, version, synced_to_chain) and CLN getinfo (id, network, version, sync warnings);
// - capabilities: the set recorded by the handshake probe (SPEC §5.1 NodeCapability, §5.2 H6/H8); LND has no
//   BOOKKEEPER_READ (that capability is CLN bkpr-listaccountevents only, SPEC §5.1);
// - listChannels: NormalizedChannel values with the observation time the adapter stamped (src/core/normalize.ts);
// - findCircularRoute: a single-path CircularRoute (SPEC §5.1) or a refusal code (SPEC §7.5);
// - createInvoice, sendOnRoute, cancelUnpaidInvoice: the mutating methods (SPEC §5.1, INV-02); every call is recorded and
//   rejected, because nothing before dispatch may reach them.
import type { CircularRoute, FakeChannel, NetworkType, NodeCapability, PreflightAdapter, RouteRequest } from '../helpers/cp028-executor.js';
import { IN_PEER, NODE_PUBKEY, OUT_PEER, PRINCIPAL } from '../helpers/cp028-executor.js';

export const EXECUTION_CAPABILITIES: readonly NodeCapability[] = [
  'CHANNEL_READ', 'PAYMENT_READ', 'INVOICE_CREATE', 'INVOICE_CANCEL', 'ROUTE_QUERY_PINNED', 'SEND_TO_ROUTE', 'PAYMENT_TRACK',
];

export const MUTATING = ['createInvoice', 'sendOnRoute', 'cancelUnpaidInvoice'] as const;

export interface Script {
  pubkey: string;
  network: NetworkType;
  version: string;
  synced: boolean;
  capabilities: Set<NodeCapability>;
  channels: () => FakeChannel[];
  route: (req: RouteRequest) => CircularRoute | { refusal: string };
  /** Runs inside the named call before it answers (an await point of the caller). */
  during: Partial<Record<'handshake' | 'listChannels' | 'findCircularRoute', () => Promise<void> | void>>;
}

export function fakeChannel(key: string, peer: string, over: Partial<FakeChannel> = {}): FakeChannel {
  return {
    nodeId: 'lnd-r', channelKey: key, scid: null, peerPubkey: peer, fundingOutpoint: `${'e5'.repeat(32)}:0`, state: 'ACTIVE',
    nodeState: 'active', opener: 'local', capacityMsat: 1_000_000_000n, localBalanceMsat: 500_000_000n, remoteBalanceMsat: 490_000_000n,
    spendableMsat: 400_000_000n, receivableMsat: 400_000_000n, confidence: 'DERIVED_ESTIMATE', caveat: null,
    localReserveMsat: 10_000_000n, remoteReserveMsat: 10_000_000n, pendingOutMsat: 0n, pendingInMsat: 0n, pendingHtlcCount: 0,
    localMaxPendingAmtMsat: null, remoteMaxPendingAmtMsat: null, observedAt: Date.now(), blockHeight: 500, provenance: {},
    ...over,
  };
}

/**
 * A three-hop circular route us -S-> out peer -mid-> in peer -T-> us delivering `principal`, with the fee split between the
 * two forwarding nodes and the CLTV deltas carried as in SPEC §5.4 C6 (final 18, then 34, then the rest).
 */
export function circularRoute(sourceKey: string, targetKey: string, feeMsat: bigint, timelockDelta: number, principal = PRINCIPAL, height = 500): CircularRoute {
  const inFee = feeMsat / 2n;
  return {
    sourceChannelKey: sourceKey, targetChannelKey: targetKey, outPeer: OUT_PEER, inPeer: IN_PEER, principalMsat: principal,
    hops: [
      { channelKey: sourceKey, nodeOut: OUT_PEER, amountOutMsat: principal + feeMsat, expiry: height + timelockDelta },
      { channelKey: '369435906932736', nodeOut: IN_PEER, amountOutMsat: principal + inFee, expiry: height + 52 },
      { channelKey: targetKey, nodeOut: NODE_PUBKEY, amountOutMsat: principal, expiry: height + 18 },
    ],
    totalFeeMsat: feeMsat,
    feePpmCeil: (feeMsat * 1_000_000n + principal - 1n) / principal,
    totalTimelockDelta: timelockDelta,
    parts: 1,
  };
}

export class FakePreflightNode implements PreflightAdapter {
  readonly calls: string[] = [];
  readonly routeRequests: RouteRequest[] = [];
  readonly script: Script;

  constructor(sourceKey: string, targetKey: string, over: Partial<Script> = {}) {
    this.script = {
      pubkey: NODE_PUBKEY, network: 'regtest', version: '0.21.4-beta commit=v0.21.4-beta', synced: true,
      capabilities: new Set(EXECUTION_CAPABILITIES),
      channels: () => [fakeChannel(sourceKey, OUT_PEER), fakeChannel(targetKey, IN_PEER)],
      route: () => circularRoute(sourceKey, targetKey, 150_000n, 80),
      during: {},
      ...over,
    };
  }

  mutatingCalls(): string[] {
    return this.calls.filter(name => (MUTATING as readonly string[]).includes(name));
  }

  async handshake(): Promise<{ pubkey: string; network: NetworkType; version: string; synced: boolean }> {
    this.calls.push('handshake');
    await this.script.during.handshake?.();
    return { pubkey: this.script.pubkey, network: this.script.network, version: this.script.version, synced: this.script.synced };
  }

  capabilities(): ReadonlySet<NodeCapability> {
    this.calls.push('capabilities');
    return this.script.capabilities;
  }

  async listChannels(): Promise<readonly FakeChannel[]> {
    this.calls.push('listChannels');
    await this.script.during.listChannels?.();
    return this.script.channels();
  }

  async findCircularRoute(req: RouteRequest): Promise<CircularRoute | { refusal: string }> {
    this.calls.push('findCircularRoute');
    this.routeRequests.push(req);
    await this.script.during.findCircularRoute?.();
    return this.script.route(req);
  }

  createInvoice(): Promise<never> {
    this.calls.push('createInvoice');
    return Promise.reject(new Error('createInvoice reached before dispatch'));
  }

  sendOnRoute(): Promise<never> {
    this.calls.push('sendOnRoute');
    return Promise.reject(new Error('sendOnRoute reached before dispatch'));
  }

  cancelUnpaidInvoice(): Promise<never> {
    this.calls.push('cancelUnpaidInvoice');
    return Promise.reject(new Error('cancelUnpaidInvoice reached before dispatch'));
  }
}
