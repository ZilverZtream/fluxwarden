// `fluxwarden channels [--node <name>] [--sort inbound-deficit|outbound|capacity]` (SPEC.md §10.3 item 3).
import { requireCapabilities } from '../core/capabilities.js';
import { ExitCode } from '../core/exit-codes.js';
import type { NormalizedChannel } from '../core/normalize.js';
import type { ChannelTargets, NodeConfig, Targets } from '../config/config.js';
import type { Database } from '../persistence/index.js';
import { nodeText } from '../output/index.js';
import type { ConnectionFlags, SortKey } from '../cli/args.js';
import { resolveConnection, type Connection, type Environment } from '../cli/connect.js';
import { handshake, moreUrgent, nodeFailure, quarantineWarning, type NodeFailure } from './handshake.js';
import { emitJson, iso, refuse, table, writeWarnings, type Io } from './report.js';
import { configStage, connectionStage, databaseStage, StageFailure, targetsStage } from './stages.js';

const COMMAND = 'channels';

export interface ChannelsRequest {
  readonly configPath: string;
  readonly node: string | null;
  readonly sort: SortKey | null;
  readonly connection: ConnectionFlags;
  readonly env: Environment;
}

interface ChannelRow {
  readonly channel: string;
  readonly peer: string;
  readonly state: string;
  readonly capacityMsat: bigint;
  readonly spendableMsat: bigint;
  readonly receivableMsat: bigint;
  readonly confidence: string;
  readonly caveat: string | null;
  readonly pendingInMsat: bigint;
  readonly pendingOutMsat: bigint;
  readonly inboundTargetMsat: bigint | null;
  readonly inboundDeficitMsat: bigint;
  readonly outboundTargetMsat: bigint | null;
  readonly outboundDeficitMsat: bigint;
  readonly observedAt: number;
  readonly snapshotAgeMs: number;
}

interface NodeChannels { readonly node: NodeConfig; readonly synced: boolean; readonly rows: readonly ChannelRow[] }

const NO_TARGETS: ChannelTargets = { minInboundMsat: null, minOutboundMsat: null };

/** max(0, target - available); 0 without a target (SPEC.md §7.3). */
function deficit(target: bigint | null, available: bigint): bigint {
  return target === null || target <= available ? 0n : target - available;
}

const compareKeys = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Descending by the sort figure, ties by channel key ascending; without a sort key, by channel key. */
export function sortRows(rows: readonly ChannelRow[], sort: SortKey | null): ChannelRow[] {
  const figure = (row: ChannelRow): bigint => {
    if (sort === 'inbound-deficit') return row.inboundDeficitMsat;
    if (sort === 'outbound') return row.outboundDeficitMsat;
    return row.capacityMsat;
  };
  return [...rows].sort((a, b) => {
    if (sort !== null) {
      const fa = figure(a), fb = figure(b);
      if (fa !== fb) return fa > fb ? -1 : 1;
    }
    return compareKeys(a.channel, b.channel);
  });
}

function rowsFor(db: Database, channels: readonly NormalizedChannel[], ids: readonly string[], targets: ReadonlyMap<string, ChannelTargets> | undefined): ChannelRow[] {
  return channels.map((channel, index) => {
    const id = ids[index] ?? '';
    const latest = db.snapshots.latest(id);
    const age = db.snapshots.ageMs(id);
    if (latest === null) throw new Error('a stored snapshot cannot be read back');
    const target = targets?.get(channel.channelKey) ?? NO_TARGETS;
    return {
      channel: channel.channelKey, peer: channel.peerPubkey, state: channel.state, capacityMsat: channel.capacityMsat,
      spendableMsat: channel.spendableMsat, receivableMsat: channel.receivableMsat, confidence: channel.confidence, caveat: channel.caveat,
      pendingInMsat: channel.pendingInMsat, pendingOutMsat: channel.pendingOutMsat,
      inboundTargetMsat: target.minInboundMsat, inboundDeficitMsat: deficit(target.minInboundMsat, channel.receivableMsat),
      outboundTargetMsat: target.minOutboundMsat, outboundDeficitMsat: deficit(target.minOutboundMsat, channel.spendableMsat),
      observedAt: latest.observedAt, snapshotAgeMs: Math.max(0, age ?? 0),
    };
  });
}

/** G5, the channel listing and its snapshots (one transaction per node, CH3) for one node. */
async function collect(db: Database, node: NodeConfig, connection: Connection, targets: Targets, warnings: string[]): Promise<{ synced: boolean; rows: ChannelRow[] }> {
  const done = await handshake(db, node, connection);
  requireCapabilities(done.result.capabilities, ['CHANNEL_READ']);
  if (done.quarantined) warnings.push(quarantineWarning(node.name));
  // SPEC.md §5.2 H7 and ARCHITECTURE.md §3 step 1: a node behind the chain is warned about and not snapshotted.
  if (!done.result.identity.syncedToChain) {
    warnings.push(`node-not-synced: ${node.name} is not synced to chain; its channels are not listed and no snapshot is taken`);
    return { synced: false, rows: [] };
  }
  const channels = await done.reader.listChannels({ nodeId: done.rowId, observedAt: Date.now(), blockHeight: done.result.identity.blockHeight });
  const ids = db.snapshots.storeAll(channels);
  return { synced: true, rows: rowsFor(db, channels, ids, targets.get(node.name)) };
}

function jsonRow(row: ChannelRow): Record<string, unknown> {
  const msat = (value: bigint | null): string | null => (value === null ? null : value.toString());
  return {
    channel: row.channel, peer: row.peer, state: row.state, capacity_msat: msat(row.capacityMsat), spendable_msat: msat(row.spendableMsat),
    receivable_msat: msat(row.receivableMsat), confidence: row.confidence, caveat: row.caveat, pending_in_msat: msat(row.pendingInMsat),
    pending_out_msat: msat(row.pendingOutMsat), inbound_target_msat: msat(row.inboundTargetMsat), inbound_deficit_msat: msat(row.inboundDeficitMsat),
    outbound_target_msat: msat(row.outboundTargetMsat), outbound_deficit_msat: msat(row.outboundDeficitMsat), observed_at: iso(row.observedAt),
    snapshot_age_ms: row.snapshotAgeMs,
  };
}

function textTable(entry: NodeChannels): string {
  const dash = (value: bigint | null): string => (value === null ? '-' : value.toString());
  const lines = [[
    'CHANNEL', 'PEER', 'STATE', 'CAPACITY_MSAT', 'SPENDABLE_MSAT', 'RECEIVABLE_MSAT', 'CONFIDENCE', 'PENDING_IN_MSAT', 'PENDING_OUT_MSAT',
    'IN_TARGET_MSAT', 'IN_DEFICIT_MSAT', 'OUT_TARGET_MSAT', 'OUT_DEFICIT_MSAT', 'AGE_S',
  ]];
  for (const row of entry.rows) {
    lines.push([
      nodeText(row.channel, 80), nodeText(row.peer, 80), row.state, dash(row.capacityMsat), dash(row.spendableMsat), dash(row.receivableMsat),
      row.confidence, dash(row.pendingInMsat), dash(row.pendingOutMsat), dash(row.inboundTargetMsat), dash(row.inboundDeficitMsat),
      dash(row.outboundTargetMsat), dash(row.outboundDeficitMsat), String(Math.floor(row.snapshotAgeMs / 1000)),
    ]);
  }
  const caveats = [...new Set(entry.rows.flatMap(row => (row.caveat === null ? [] : [row.caveat])))];
  const notes = caveats.map(caveat => `note: ${nodeText(caveat, 1024)}\n`).join('');
  const body = !entry.synced ? 'not synced to chain: channels not listed\n' : entry.rows.length === 0 ? 'no channels\n' : table(lines);
  return `${entry.node.name} (${entry.node.implementation})\n${body}${notes}`;
}

export async function channels(io: Io, request: ChannelsRequest): Promise<number> {
  let config;
  let selected: NodeConfig[];
  let connections: Map<string, Connection>;
  let targets: Targets;
  let db;
  try {
    config = configStage(request.configPath);
    const wanted = request.node;
    selected = wanted === null ? [...config.nodes] : config.nodes.filter(node => node.name === wanted);
    if (selected.length === 0) throw new StageFailure(ExitCode.INVALID_INPUT, 'config', 'no configured node has that name');
    connections = new Map(selected.map(node => [node.name, connectionStage(() => resolveConnection(node, request.connection, request.env))]));
    targets = targetsStage(config);
    db = databaseStage(config.database, 'existing');
  } catch (error) {
    if (error instanceof StageFailure) return refuse(io, COMMAND, error.code, error.step, error.message);
    throw error;
  }
  try {
    const warnings: string[] = [];
    const listed: NodeChannels[] = [];
    const failures: { name: string; failure: NodeFailure }[] = [];
    for (const node of selected) {
      const connection = connections.get(node.name);
      if (connection === undefined) continue;
      try {
        const collected = await collect(db, node, connection, targets, warnings);
        listed.push({ node, synced: collected.synced, rows: sortRows(collected.rows, request.sort) });
      } catch (error) {
        const failure = nodeFailure(error);
        if (failure === null) throw error;
        if (failure.code === ExitCode.NODE_UNREACHABLE) db.nodes.markOffline(node.name);
        failures.push({ name: node.name, failure });
      }
    }
    const code = failures.reduce<number>((worst, { failure }) => (worst === ExitCode.SUCCESS ? failure.code : moreUrgent(worst, failure.code)), ExitCode.SUCCESS);
    if (io.json) {
      if (failures.length > 0) {
        const decisive = failures.find(({ failure }) => failure.code === code)?.failure;
        const message = failures.map(({ name, failure }) => `${name}: ${failure.message} (exit ${String(failure.code)})`).join('; ');
        return emitJson(io, COMMAND, { code, warnings, result: null, error: { code, step: decisive?.step ?? null, message } });
      }
      return emitJson(io, COMMAND, {
        code, warnings, error: null,
        result: { sort: request.sort, nodes: listed.map(entry => ({ name: entry.node.name, implementation: entry.node.implementation, channels: entry.rows.map(jsonRow) })) },
      });
    }
    io.output.write('stdout', listed.map(textTable).join('\n'));
    writeWarnings(io, COMMAND, warnings);
    for (const { name, failure } of failures) io.output.write('stderr', `fluxwarden channels: ${name}: ${nodeText(failure.message, 1024)} (exit ${String(failure.code)})\n`);
    return code;
  } finally {
    db.close();
  }
}
