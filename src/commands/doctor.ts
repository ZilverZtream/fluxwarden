// `fluxwarden doctor` (SPEC.md §10.3 item 1): runtime, database and every configured node, read-only.
import { requireCapabilities, REQUIRED_CAPABILITIES } from '../core/capabilities.js';
import { ExitCode } from '../core/exit-codes.js';
import { SCHEMA_VERSION } from '../persistence/index.js';
import { nodeText } from '../output/index.js';
import { handshake, moreUrgent, networkName, nodeFailure, quarantineWarning, type NodeFailure } from './handshake.js';
import { emitJson, refuse, table, writeWarnings, type Io } from './report.js';
import { configStage, databaseStage, StageFailure } from './stages.js';

const COMMAND = 'doctor';

/** Node.js releases within package.json `engines` (^22.23.2 || ^24.18.1 || >=26.5.1). */
export function engineSupported(version: string): boolean {
  const match = /^v?([0-9]+)\.([0-9]+)\.([0-9]+)/.exec(version);
  if (match === null) return false;
  const [major, minor, patch] = [Number(match[1]), Number(match[2]), Number(match[3])];
  const atLeast = (m: number, p: number): boolean => minor > m || (minor === m && patch >= p);
  if (major === 22) return atLeast(23, 2);
  if (major === 24) return atLeast(18, 1);
  if (major === 26) return atLeast(5, 1);
  return major > 26;
}

interface NodeReport {
  readonly name: string;
  readonly implementation: string;
  readonly pubkey: string;
  readonly network: string;
  readonly version: string;
  readonly synced: boolean;
  readonly block_height: number;
  readonly capabilities: readonly string[];
}

export async function doctor(io: Io, configPath: string, nodeVersion: string): Promise<number> {
  let config;
  let db;
  try {
    config = configStage(configPath);
    db = databaseStage(config.database, 'create');
  } catch (error) {
    if (error instanceof StageFailure) return refuse(io, COMMAND, error.code, error.step, error.message);
    throw error;
  }
  try {
    const warnings: string[] = [];
    const supported = engineSupported(nodeVersion);
    if (!supported) warnings.push(`engine-unsupported: Node.js ${nodeVersion} is outside package.json engines`);
    const reports: NodeReport[] = [];
    const failures: { name: string; failure: NodeFailure }[] = [];
    for (const node of config.nodes) {
      try {
        const done = await handshake(db, node, { endpoint: node.endpoint, tlsCertPath: node.tlsCertPath, credentialPath: node.credentialPath });
        const { identity, capabilities } = done.result;
        if (done.quarantined) warnings.push(quarantineWarning(node.name));
        if (!identity.syncedToChain) warnings.push(`node-not-synced: ${node.name}`);
        requireCapabilities(capabilities, REQUIRED_CAPABILITIES[node.implementation]);
        reports.push({
          name: node.name, implementation: node.implementation, pubkey: identity.pubkey, network: networkName(node, identity.network),
          version: identity.version, synced: identity.syncedToChain, block_height: identity.blockHeight, capabilities: [...capabilities].sort(),
        });
      } catch (error) {
        const failure = nodeFailure(error);
        if (failure === null) throw error;
        if (failure.code === ExitCode.NODE_UNREACHABLE) db.nodes.markOffline(node.name);
        failures.push({ name: node.name, failure });
      }
    }
    const code = failures.reduce<number>((worst, { failure }) => (worst === ExitCode.SUCCESS ? failure.code : moreUrgent(worst, failure.code)), ExitCode.SUCCESS);
    if (io.json) {
      if (failures.length === 0) {
        return emitJson(io, COMMAND, {
          code, warnings, error: null,
          result: { node_version: nodeVersion, engine_supported: supported, sqlite: true, database: { path: config.database, schema_version: SCHEMA_VERSION }, nodes: reports },
        });
      }
      const decisive = failures.find(({ failure }) => failure.code === code)?.failure;
      const message = failures.map(({ name, failure }) => `${name}: ${failure.message} (exit ${String(failure.code)})`).join('; ');
      return emitJson(io, COMMAND, { code, warnings, result: null, error: { code, step: decisive?.step ?? null, message } });
    }
    const lines = [
      `Node.js ${nodeVersion} (${supported ? 'supported' : 'outside package.json engines'})`,
      'node:sqlite available',
      `database ${nodeText(config.database, 4096)} (schema version ${String(SCHEMA_VERSION)})`,
      '',
    ];
    const rows = [['NODE', 'IMPL', 'RESULT', 'NETWORK', 'HEIGHT', 'SYNCED', 'VERSION']];
    for (const report of reports) {
      rows.push([report.name, report.implementation, 'ok', report.network, String(report.block_height), report.synced ? 'yes' : 'no', nodeText(report.version, 80)]);
    }
    for (const { name, failure } of failures) {
      const node = config.nodes.find(entry => entry.name === name);
      rows.push([name, node?.implementation ?? '', `failed (exit ${String(failure.code)})`, '', '', '', '']);
    }
    io.output.write('stdout', lines.join('\n') + table(rows));
    for (const report of reports) io.output.write('stdout', `${report.name} capabilities: ${report.capabilities.join(', ')}\n`);
    writeWarnings(io, COMMAND, warnings);
    for (const { name, failure } of failures) io.output.write('stderr', `fluxwarden doctor: ${name}: ${nodeText(failure.message, 1024)}\n`);
    return code;
  } finally {
    db.close();
  }
}
