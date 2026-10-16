// `fluxwarden nodes list` and `fluxwarden nodes inspect <name> [--capabilities]` (SPEC.md §10.3 item 2).
import { missingCapabilityReason, REQUIRED_CAPABILITIES, type NodeCapability } from '../core/capabilities.js';
import { ExitCode } from '../core/exit-codes.js';
import { nodeText } from '../output/index.js';
import type { ConnectionFlags } from '../cli/args.js';
import { resolveConnection, type Environment } from '../cli/connect.js';
import { handshake, networkName, nodeFailure, quarantineWarning } from './handshake.js';
import { boundedUtf8, emitJson, iso, refuse, table, writeWarnings, type Io } from './report.js';
import { configStage, connectionStage, databaseStage, StageFailure } from './stages.js';

/** Stored node rows, one per configured node; no node is contacted (NL2). */
export function nodesList(io: Io, configPath: string): number {
  const command = 'nodes list';
  let rows;
  try {
    const config = configStage(configPath);
    const db = databaseStage(config.database, 'read');
    try {
      const stored = new Map(db.nodes.list().map(row => [row.name, row]));
      rows = config.nodes.map(node => {
        const row = stored.get(node.name);
        return {
          name: node.name,
          implementation: node.implementation,
          expected_pubkey: node.expectedPubkey,
          expected_network: node.expectedNetwork,
          state: row?.state ?? 'OFFLINE',
          observed_version: row?.observedVersion ?? null,
          capabilities: row?.capabilities ?? null,
          last_probed_at: row?.lastProbedAt === null || row?.lastProbedAt === undefined ? null : iso(row.lastProbedAt),
        };
      });
    } finally {
      db.close();
    }
  } catch (error) {
    if (error instanceof StageFailure) return refuse(io, command, error.code, error.step, error.message);
    throw error;
  }
  if (io.json) return emitJson(io, command, { code: ExitCode.SUCCESS, result: { nodes: rows }, error: null, warnings: [] });
  const lines = [['NODE', 'IMPL', 'STATE', 'VERSION', 'LAST PROBED', 'CAPABILITIES']];
  for (const row of rows) {
    lines.push([
      row.name, row.implementation, row.state, row.observed_version === null ? '-' : nodeText(row.observed_version, 80),
      row.last_probed_at ?? '-', row.capabilities === null ? '-' : row.capabilities.join(','),
    ]);
  }
  io.output.write('stdout', table(lines));
  return ExitCode.SUCCESS;
}

export interface InspectRequest {
  readonly configPath: string;
  readonly node: string;
  readonly capabilities: boolean;
  readonly connection: ConnectionFlags;
  readonly env: Environment;
}

/** G5 for one node; identity, version, network, sync state and, with --capabilities, the capability set (NL2, NL3). */
export async function nodesInspect(io: Io, request: InspectRequest): Promise<number> {
  const command = 'nodes inspect';
  let config;
  let node;
  let connection;
  let db;
  try {
    config = configStage(request.configPath);
    node = config.nodes.find(entry => entry.name === request.node);
    if (node === undefined) throw new StageFailure(ExitCode.INVALID_INPUT, 'config', 'no configured node has that name');
    const selected = node;
    connection = connectionStage(() => resolveConnection(selected, request.connection, request.env));
    db = databaseStage(config.database, 'existing');
  } catch (error) {
    if (error instanceof StageFailure) return refuse(io, command, error.code, error.step, error.message);
    throw error;
  }
  try {
    let done;
    try {
      done = await handshake(db, node, connection);
    } catch (error) {
      const failure = nodeFailure(error);
      if (failure === null) throw error;
      if (failure.code === ExitCode.NODE_UNREACHABLE) db.nodes.markOffline(node.name);
      return refuse(io, command, failure.code, failure.step, `${node.name}: ${failure.message}`);
    }
    const warnings: string[] = [];
    const { identity, capabilities } = done.result;
    if (done.quarantined) warnings.push(quarantineWarning(node.name));
    if (!identity.syncedToChain) warnings.push(`node-not-synced: ${node.name}`);
    const sorted = [...capabilities].sort();
    const missing: NodeCapability[] = REQUIRED_CAPABILITIES[node.implementation].filter(capability => !capabilities.has(capability));
    const reasons = missing.map(capability => `${capability} (${missingCapabilityReason(node.implementation, capability, capabilities)})`);
    const code = missing.length === 0 ? ExitCode.SUCCESS : ExitCode.CAPABILITY_UNSUPPORTED;
    const alias = nodeText(done.alias, 256);
    if (io.json) {
      if (missing.length > 0) {
        return emitJson(io, command, {
          code, warnings, result: null,
          error: { code, step: 'capability', message: `${node.name} lacks ${reasons.join(', ')}` },
        });
      }
      return emitJson(io, command, {
        code, warnings, error: null,
        result: {
          name: node.name, implementation: node.implementation, alias: boundedUtf8(done.alias, 256),
          pubkey: identity.pubkey, network: networkName(node, identity.network), version: identity.version, synced: identity.syncedToChain,
          block_height: identity.blockHeight, capabilities: request.capabilities ? sorted : null,
        },
      });
    }
    const lines = [
      ['name', node.name],
      ['implementation', node.implementation],
      ['alias', alias],
      ['pubkey', nodeText(identity.pubkey, 80)],
      ['network', nodeText(networkName(node, identity.network), 40)],
      ['version', nodeText(identity.version, 80)],
      ['synced', identity.syncedToChain ? 'yes' : 'no'],
      ['block height', String(identity.blockHeight)],
    ];
    if (request.capabilities || missing.length > 0) lines.push(['capabilities', sorted.join(', ')]);
    io.output.write('stdout', table(lines));
    writeWarnings(io, command, warnings);
    if (missing.length > 0) {
      for (const reason of reasons) io.output.write('stderr', `fluxwarden nodes inspect: ${node.name} lacks ${reason}\n`);
    }
    return code;
  } finally {
    db.close();
  }
}
