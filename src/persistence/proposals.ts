// Liquidity proposals and the policy versions they were planned under.
import type { DatabaseSync, SQLOutputValue } from 'node:sqlite';
import { ulid } from '../core/ulid.js';
import { PersistenceError } from './errors.js';

export type ProposalAction = 'CIRCULAR_REBALANCE' | 'NO_ACTION';
export type ProposalStatus = 'PROPOSED' | 'APPROVED' | 'REJECTED' | 'EXPIRED';
export type DemandSource = 'TARGETS' | 'EWMA';

export interface NewProposal {
  /** ULID. */
  readonly id: string;
  readonly nodeId: string;
  readonly policy: { readonly sha256: string; readonly canonicalJson: string };
  readonly actionType: ProposalAction;
  /** Channel keys of the node; null for NO_ACTION. */
  readonly sourceChannelKey: string | null;
  readonly targetChannelKey: string | null;
  readonly principalMsat: bigint | null;
  readonly maxFeeMsat: bigint;
  readonly maxFeePpm: bigint;
  readonly maxCltvDelta: number;
  readonly routeJson: string | null;
  readonly demandSource: DemandSource;
  readonly digest: string;
  readonly reasonJson: string;
  /** Unix milliseconds. */
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface StoredProposal {
  readonly id: string;
  readonly nodeId: string;
  readonly nodeName: string;
  readonly nodePubkey: string;
  readonly actionType: ProposalAction;
  readonly sourceChannelKey: string | null;
  readonly targetChannelKey: string | null;
  readonly principalMsat: bigint | null;
  readonly maxFeeMsat: bigint | null;
  readonly maxFeePpm: bigint | null;
  readonly maxCltvDelta: number | null;
  readonly routeJson: string | null;
  readonly demandSource: DemandSource;
  readonly digest: string;
  readonly status: ProposalStatus;
  readonly reasonJson: string;
  readonly policySha256: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface ProposalRepository {
  /**
   * Stores the proposal in one transaction, with a policy_versions row first when the policy digest is new.
   * Channel keys resolve to the node's channel rows; an unknown key stores nothing.
   */
  insert(proposal: NewProposal): void;
  find(id: string): StoredProposal | null;
}

export interface RepositoryTools {
  writable(what: string): void;
  run<T>(work: () => T): T;
  immediate<T>(work: () => T): T;
}

const POLICY_AUTHOR = 'cli';

function text(row: Record<string, SQLOutputValue>, key: string): string {
  const value = row[key];
  if (typeof value !== 'string') throw new Error(`column ${key} is not text`);
  return value;
}

function optionalText(row: Record<string, SQLOutputValue>, key: string): string | null {
  return row[key] === null ? null : text(row, key);
}

function optionalInteger(row: Record<string, SQLOutputValue>, key: string): bigint | null {
  const value = row[key];
  if (value === null) return null;
  if (typeof value !== 'bigint') throw new Error(`column ${key} is not an integer`);
  return value;
}

function safeNumber(value: bigint | null, key: string): number {
  if (value === null || value > BigInt(Number.MAX_SAFE_INTEGER) || value < BigInt(Number.MIN_SAFE_INTEGER)) throw new Error(`column ${key} is out of range`);
  return Number(value);
}

function oneOf<T extends string>(value: string, members: readonly T[], key: string): T {
  const found = members.find(member => member === value);
  if (found === undefined) throw new Error(`column ${key} is not a known value`);
  return found;
}

export function proposalRepository(db: DatabaseSync, tools: RepositoryTools): ProposalRepository {
  const channelId = (nodeId: string, key: string | null): string | null => {
    if (key === null) return null;
    // MySQL: same
    const row = db.prepare('SELECT id FROM channels WHERE node_id = ? AND channel_key = ?').get(nodeId, key);
    if (row === undefined) throw new PersistenceError('NOT_FOUND', 'the proposal names a channel that is not stored for its node');
    return text(row, 'id');
  };

  const policyVersion = (sha256: string, canonicalJson: string, at: number): string => {
    // MySQL: same
    const existing = db.prepare('SELECT id FROM policy_versions WHERE policy_sha256 = ?').get(sha256);
    if (existing !== undefined) return text(existing, 'id');
    const id = ulid(Date.now());
    // MySQL: same
    db.prepare(`INSERT INTO policy_versions (id, version_no, policy_sha256, policy_canonical_json, author, created_at)
      VALUES (?, (SELECT coalesce(max(version_no), 0) + 1 FROM policy_versions), ?, ?, ?, ?)`).run(id, sha256, canonicalJson, POLICY_AUTHOR, at);
    return id;
  };

  return {
    insert(proposal: NewProposal): void {
      tools.writable('proposals.insert');
      tools.immediate(() => {
        const policyId = policyVersion(proposal.policy.sha256, proposal.policy.canonicalJson, proposal.createdAt);
        const source = channelId(proposal.nodeId, proposal.sourceChannelKey);
        const target = channelId(proposal.nodeId, proposal.targetChannelKey);
        // MySQL: same
        db.prepare(`INSERT INTO liquidity_proposals (id, policy_version_id, node_id, action_type, source_channel_id, target_channel_id,
            principal_msat, max_fee_msat, max_fee_ppm, max_cltv_delta, route_json, demand_source, proposal_digest, status, reason_json,
            expires_at, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PROPOSED', ?, ?, ?)`)
          .run(proposal.id, policyId, proposal.nodeId, proposal.actionType, source, target, proposal.principalMsat, proposal.maxFeeMsat,
            proposal.maxFeePpm, proposal.maxCltvDelta, proposal.routeJson, proposal.demandSource, proposal.digest, proposal.reasonJson,
            proposal.expiresAt, proposal.createdAt);
      });
    },

    find(id: string): StoredProposal | null {
      return tools.run(() => {
        // MySQL: same
        const row = db.prepare(`SELECT p.id, p.node_id, n.name AS node_name, n.expected_pubkey AS node_pubkey, p.action_type,
            s.channel_key AS source_key, t.channel_key AS target_key, p.principal_msat, p.max_fee_msat, p.max_fee_ppm, p.max_cltv_delta,
            p.route_json, p.demand_source, p.proposal_digest, p.status, p.reason_json, v.policy_sha256, p.created_at, p.expires_at
          FROM liquidity_proposals p
            JOIN nodes n ON n.id = p.node_id
            JOIN policy_versions v ON v.id = p.policy_version_id
            LEFT JOIN channels s ON s.id = p.source_channel_id
            LEFT JOIN channels t ON t.id = p.target_channel_id
          WHERE p.id = ?`).get(id);
        if (row === undefined) return null;
        const cltv = optionalInteger(row, 'max_cltv_delta');
        return {
          id: text(row, 'id'),
          nodeId: text(row, 'node_id'),
          nodeName: text(row, 'node_name'),
          nodePubkey: text(row, 'node_pubkey'),
          actionType: oneOf(text(row, 'action_type'), ['CIRCULAR_REBALANCE', 'NO_ACTION'] as const, 'action_type'),
          sourceChannelKey: optionalText(row, 'source_key'),
          targetChannelKey: optionalText(row, 'target_key'),
          principalMsat: optionalInteger(row, 'principal_msat'),
          maxFeeMsat: optionalInteger(row, 'max_fee_msat'),
          maxFeePpm: optionalInteger(row, 'max_fee_ppm'),
          maxCltvDelta: cltv === null ? null : safeNumber(cltv, 'max_cltv_delta'),
          routeJson: optionalText(row, 'route_json'),
          demandSource: oneOf(text(row, 'demand_source'), ['TARGETS', 'EWMA'] as const, 'demand_source'),
          digest: text(row, 'proposal_digest'),
          status: oneOf(text(row, 'status'), ['PROPOSED', 'APPROVED', 'REJECTED', 'EXPIRED'] as const, 'status'),
          reasonJson: text(row, 'reason_json'),
          policySha256: text(row, 'policy_sha256'),
          createdAt: safeNumber(optionalInteger(row, 'created_at'), 'created_at'),
          expiresAt: safeNumber(optionalInteger(row, 'expires_at'), 'expires_at'),
        };
      });
    },
  };
}
