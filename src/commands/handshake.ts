// The handshake every read command runs for a node (SPEC.md §5.2), and how a node failure maps to an exit code.
import { CapabilityUnsupported, IdentityRefusal, normalizeNetwork, type NodeProbeUpdate, type ProbeResult } from '../core/capabilities.js';
import { AuthError, ClnError, LndError, ProtocolError, TlsError, TransportError } from '../core/errors.js';
import { ExitCode } from '../core/exit-codes.js';
import { CredentialFileError, type NodeReader } from '../core/node.js';
import type { NodeConfig } from '../config/config.js';
import { PersistenceError, type Database } from '../persistence/index.js';
import { openReader, type Connection } from '../cli/connect.js';
import { StageFailure } from './stages.js';

export interface NodeFailure {
  readonly code: number;
  readonly step: string;
  readonly message: string;
}

export interface Handshake {
  readonly reader: NodeReader;
  readonly result: ProbeResult;
  readonly alias: string;
  /** The node's row id. */
  readonly rowId: string;
  /** The row stays QUARANTINED from an earlier refusal; the handshake did not lift it. */
  readonly quarantined: boolean;
  readonly connection: Connection;
}

/** The warning a read command adds for a node whose row stays quarantined. */
export const quarantineWarning = (name: string): string =>
  `node-quarantined: ${name} stays quarantined from an earlier refusal; a successful read does not lift it`;

/**
 * Runs H1 to H8 for `node` over `connection`, recording the outcome on the node's row. A stored row of another
 * name holding the same expected identity (the configuration renamed a node) is refused with exit 2.
 */
export async function handshake(db: Database, node: NodeConfig, connection: Connection, reader?: NodeReader): Promise<Handshake> {
  // Stored provenance and incompatible configured pins can be checked without presenting a credential.
  // A new name still requires its first observed identity; recordProbe repeats these checks on write.
  const existing = db.nodes.list().find(stored => stored.name === node.name);
  if (existing !== undefined) {
    db.nodes.assertIdentity(existing.id);
    if (existing.implementation !== node.implementation || existing.expectedPubkey !== node.expectedPubkey) {
      throw new PersistenceError('NODE_IDENTITY_CHANGED', 'identity: a stored node cannot be rebound; preserve its database and restore its verified connection');
    }
  }
  const session = reader ?? await openReader(node, connection);
  const recordedAs: { rowId: string | null; heldBy: string | null; quarantined: boolean } = { rowId: null, heldBy: null, quarantined: false };
  const store = {
    recordProbe: (update: NodeProbeUpdate): Promise<void> => {
      const recorded = db.nodes.recordProbe({
        name: node.name, implementation: node.implementation, expectedPubkey: node.expectedPubkey, state: update.state,
        observedVersion: update.observedVersion, capabilities: update.capabilities,
      });
      if ('id' in recorded) {
        recordedAs.rowId = recorded.id;
        recordedAs.quarantined = recorded.quarantined;
      }
      else recordedAs.heldBy = recorded.heldBy;
      return Promise.resolve();
    },
  };
  const { result, alias } = await session.probe({
    nodeId: node.name, expectedPubkey: node.expectedPubkey, expectedNetwork: node.expectedNetwork, mutating: false, store, nowMs: () => Date.now(),
  });
  const { rowId, heldBy, quarantined } = recordedAs;
  if (rowId === null) {
    throw new StageFailure(ExitCode.INVALID_INPUT, 'config', `the stored node ${heldBy ?? 'of another name'} already has the expected identity of ${node.name}`);
  }
  return { reader: session, result, alias, rowId, quarantined, connection };
}

/** The normalised network of a node that passed the handshake. */
export function networkName(node: NodeConfig, raw: string): string {
  return normalizeNetwork(node.implementation, raw) ?? raw;
}

/** The exit code, step and message of a node failure (SPEC.md §5.2, §10.2); null for anything else. */
export function nodeFailure(error: unknown): NodeFailure | null {
  if (error instanceof StageFailure) return { code: error.code, step: error.step ?? 'config', message: error.message };
  if (error instanceof PersistenceError && (error.code === 'RESTORE_PENDING' || error.code === 'RECOVERY_PENDING')) {
    return { code: ExitCode.SAFETY_REFUSAL, step: 'recovery', message: error.message };
  }
  if (error instanceof PersistenceError && (error.code === 'NODE_IDENTITY_CHANGED' || error.code === 'NODE_IDENTITY_UNVERIFIED')) {
    return { code: ExitCode.SAFETY_REFUSAL, step: 'identity', message: error.message };
  }
  if (error instanceof IdentityRefusal) return { code: ExitCode.SAFETY_REFUSAL, step: error.step, message: error.message };
  if (error instanceof CapabilityUnsupported) return { code: ExitCode.CAPABILITY_UNSUPPORTED, step: 'capability', message: error.message };
  const unreachable = (message: string): NodeFailure => ({ code: ExitCode.NODE_UNREACHABLE, step: 'connect', message });
  if (error instanceof CredentialFileError) return unreachable(error.message);
  if (error instanceof TlsError) return unreachable(`${error.message}: the node's certificate is not the configured one`);
  if (error instanceof TransportError) return unreachable(`the node could not be reached: ${error.message}`);
  if (error instanceof AuthError) {
    return unreachable(`the node refused the credential (HTTP ${String(error.httpStatus ?? 0)}${error.code === undefined ? '' : `, code ${String(error.code)}`}): ${error.message}`);
  }
  if (error instanceof LndError) {
    return unreachable(`the node answered a read with an error${error.grpcCode === undefined ? '' : ` (gRPC code ${String(error.grpcCode)})`}: ${error.message}`);
  }
  if (error instanceof ClnError) {
    return unreachable(`the node answered a read with an error${error.code === undefined ? '' : ` (code ${String(error.code)})`}: ${error.message}`);
  }
  if (error instanceof ProtocolError) return unreachable(`the node's answer could not be read: ${error.message}`);
  return null;
}

/** Which of two node failure codes decides the exit: 4 before 3 before 5 (SPEC.md §10.3 DR5), anything else last. */
export function moreUrgent(a: number, b: number): number {
  const rank = (code: number): number => [ExitCode.NODE_UNREACHABLE, ExitCode.CAPABILITY_UNSUPPORTED, ExitCode.SAFETY_REFUSAL].indexOf(code as 3 | 4 | 5);
  const ra = rank(a), rb = rank(b);
  if (ra === -1) return rb === -1 ? Math.min(a, b) : b;
  if (rb === -1) return a;
  return ra <= rb ? a : b;
}
