// The configuration file (SPEC.md §10.1) and the operator targets of the policy file (SPEC.md §7.1, §7.3).
// Credentials are named by path only (SECURITY.md §3.3). Messages name keys and lines, never values.
import { closeSync, fstatSync, openSync, readSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import type { Implementation } from '../core/capabilities.js';
import { parseAmount } from '../core/money.js';
import { configuredPublicKey } from '../approval/keys.js';
import type { ApprovalKey } from '../approval/types.js';
import { parseYaml, YamlError, type YamlMap, type YamlValue } from './yaml.js';

/** Configuration and policy files are at most 64 KiB (SECURITY.md §5). */
export const MAX_CONFIG_BYTES = 64 * 1024;
/** Design default of the collector interval (SPEC.md §10.4 DM4). */
export const DEFAULT_COLLECT_INTERVAL_MS = 15_000;

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

/** A configured network violates INV-15; no non-regtest configuration is returned. */
export class ConfigNetworkError extends ConfigError {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigNetworkError';
  }
}

export interface Endpoint { readonly host: string; readonly port: number }

export interface NodeConfig {
  readonly name: string;
  readonly implementation: Implementation;
  readonly endpoint: Endpoint;
  readonly tlsCertPath: string;
  /** The macaroon file (lnd) or the rune file (cln). */
  readonly credentialPath: string;
  readonly expectedPubkey: string;
  readonly expectedNetwork: 'regtest';
}

export interface Config {
  readonly database: string;
  readonly policy: string | null;
  readonly collectIntervalMs: number;
  readonly approvalKeys: readonly ApprovalKey[];
  readonly attemptDeadlineMs: number;
  readonly alertDir: string;
  readonly escalateAfterMs: number;
  readonly deltaToleranceMsat: bigint;
  /** Ordered by name. */
  readonly nodes: readonly NodeConfig[];
}

export interface ChannelTargets { readonly minInboundMsat: bigint | null; readonly minOutboundMsat: bigint | null }
/** Node name → channel key → operator targets. */
export type Targets = ReadonlyMap<string, ReadonlyMap<string, ChannelTargets>>;

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const PUBKEY = /^0[23][0-9a-f]{64}$/;
const DURATION = /^([1-9][0-9]{0,8})(s|m|h|d)$/;
const UNIT_MS: Readonly<Record<string, number>> = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };
const TOP_KEYS = new Set(['database', 'policy', 'collect_interval', 'nodes', 'approval_keys', 'escalate_after', 'delta_tolerance_msat', 'alert_dir', 'attempt_deadline']);
const NODE_KEYS = new Set(['name', 'implementation', 'url', 'tls_cert_path', 'macaroon_path', 'rune_path', 'expected_pubkey', 'expected_network']);

/** Reads a configuration or policy file of at most MAX_CONFIG_BYTES, bounded on the open descriptor. */
export function readBoundedText(path: string, what: string): string {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch (error) {
    const code = (error as { code?: unknown } | null)?.code;
    throw new ConfigError(`the ${what} file could not be read${typeof code === 'string' ? ` (${code})` : ''}`);
  }
  try {
    if (!fstatSync(fd).isFile()) throw new ConfigError(`the ${what} file is not a regular file`);
    const buffer = Buffer.alloc(MAX_CONFIG_BYTES + 1);
    let length = 0;
    for (;;) {
      const read = readSync(fd, buffer, length, buffer.length - length, length);
      if (read === 0) break;
      length += read;
      if (length > MAX_CONFIG_BYTES) throw new ConfigError(`the ${what} file is larger than ${String(MAX_CONFIG_BYTES)} bytes`);
    }
    const text = buffer.subarray(0, length).toString('utf8');
    if (text.includes('�')) throw new ConfigError(`the ${what} file is not valid UTF-8`);
    return text;
  } catch (error) {
    if (error instanceof ConfigError) throw error;
    const code = (error as { code?: unknown } | null)?.code;
    throw new ConfigError(`the ${what} file could not be read${typeof code === 'string' ? ` (${code})` : ''}`);
  } finally {
    closeSync(fd);
  }
}

function parseFile(path: string, what: string): YamlValue {
  const text = readBoundedText(path, what);
  try {
    return parseYaml(text);
  } catch (error) {
    if (error instanceof YamlError) throw new ConfigError(`the ${what} file is not in the supported YAML subset: ${error.message}`);
    throw error;
  }
}

function isMap(value: YamlValue | undefined): value is YamlMap {
  return value !== null && value !== undefined && typeof value === 'object' && !Array.isArray(value);
}

function text(map: YamlMap, key: string, where: string): string {
  const value = map[key];
  if (typeof value !== 'string' || value === '') throw new ConfigError(`${where}: ${key} must be a non-empty string`);
  return value;
}

/** An `https://host:port` address without credentials, path, query or fragment; null when it is not one. */
export function parseEndpoint(value: string): Endpoint | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' || url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '') return null;
  if (url.pathname !== '/' && url.pathname !== '') return null;
  if (url.port === '' || url.hostname === '') return null;
  if (!/^https:\/\/[^/@?#]+\/?$/i.test(value)) return null;
  const host = url.hostname.startsWith('[') && url.hostname.endsWith(']') ? url.hostname.slice(1, -1) : url.hostname;
  return { host, port: Number(url.port) };
}

/** `<int>(s|m|h|d)` in milliseconds (SPEC.md §7.1). */
export function parseDuration(value: string): number | null {
  const match = DURATION.exec(value);
  if (match === null) return null;
  return Number(match[1]) * (UNIT_MS[match[2] ?? ''] ?? 0);
}

function nodeEntry(value: YamlValue, index: number, base: string): NodeConfig {
  const where = `nodes[${String(index)}]`;
  if (!isMap(value)) throw new ConfigError(`${where} must be a mapping`);
  for (const key of Object.keys(value)) {
    if (!NODE_KEYS.has(key)) throw new ConfigError(`${where}: unknown key ${JSON.stringify(key.slice(0, 40))}`);
  }
  const name = text(value, 'name', where);
  if (!NAME.test(name)) throw new ConfigError(`${where}: name must be 1 to 64 letters, digits, '.', '_' or '-'`);
  const implementation = text(value, 'implementation', where);
  if (implementation !== 'lnd' && implementation !== 'cln') throw new ConfigError(`${where}: implementation must be lnd or cln`);
  const endpoint = parseEndpoint(text(value, 'url', where));
  if (endpoint === null) throw new ConfigError(`${where}: url must be https://<host>:<port>`);
  const [credentialKey, otherKey] = implementation === 'lnd' ? ['macaroon_path', 'rune_path'] : ['rune_path', 'macaroon_path'];
  if (value[otherKey] !== undefined) throw new ConfigError(`${where}: ${otherKey} does not apply to an ${implementation} node`);
  const expectedPubkey = text(value, 'expected_pubkey', where);
  if (!PUBKEY.test(expectedPubkey)) throw new ConfigError(`${where}: expected_pubkey must be 66 lowercase hex characters`);
  const expectedNetwork = text(value, 'expected_network', where);
  if (expectedNetwork !== 'regtest') {
    const message = `${where}: expected_network must be regtest`;
    throw new ConfigNetworkError(message);
  }
  return {
    name, implementation, endpoint,
    tlsCertPath: resolve(base, text(value, 'tls_cert_path', where)),
    credentialPath: resolve(base, text(value, credentialKey, where)),
    expectedPubkey, expectedNetwork: 'regtest',
  };
}

/** Loads and validates the configuration file (SPEC.md §10.3 G3); relative paths are relative to the file. */
export function loadConfig(path: string): Config {
  const absolute = resolve(path);
  const base = dirname(absolute);
  const root = parseFile(absolute, 'configuration');
  if (!isMap(root)) throw new ConfigError('the configuration must be a mapping');
  for (const key of Object.keys(root)) {
    if (!TOP_KEYS.has(key)) throw new ConfigError(`configuration: unknown key ${JSON.stringify(key.slice(0, 40))}`);
  }
  const database = resolve(base, text(root, 'database', 'configuration'));
  const policy = root['policy'] === undefined ? null : resolve(base, text(root, 'policy', 'configuration'));
  let collectIntervalMs = DEFAULT_COLLECT_INTERVAL_MS;
  if (root['collect_interval'] !== undefined) {
    const interval = parseDuration(text(root, 'collect_interval', 'configuration'));
    if (interval === null) throw new ConfigError('configuration: collect_interval must be <int>(s|m|h|d)');
    collectIntervalMs = interval;
  }
  const list = root['nodes'];
  if (!Array.isArray(list) || list.length === 0) throw new ConfigError('configuration: nodes must be a non-empty list');
  const nodes = list.map((value, index) => nodeEntry(value, index, base));
  const names = new Set<string>();
  for (const node of nodes) {
    if (names.has(node.name)) throw new ConfigError(`configuration: node name ${node.name} appears twice`);
    names.add(node.name);
  }
  // INV-12 pins each configured node to one identity; the nodes table is UNIQUE (expected_network, expected_pubkey).
  const identities = new Map<string, string>();
  for (const node of nodes) {
    const identity = `${node.expectedNetwork}:${node.expectedPubkey}`;
    const other = identities.get(identity);
    if (other !== undefined) throw new ConfigError(`configuration: nodes ${other} and ${node.name} have the same expected_network and expected_pubkey; each node needs its own identity`);
    identities.set(identity, node.name);
  }
  const approvalKeys: ApprovalKey[] = [];
  if (root['approval_keys'] !== undefined) {
    if (!Array.isArray(root['approval_keys'])) throw new ConfigError('configuration: approval_keys must be a list');
    for (const value of root['approval_keys']) {
      if (!isMap(value) || Object.keys(value).some(key => key !== 'key_id' && key !== 'public_key')) throw new ConfigError('configuration: invalid approval key');
      const entry = { keyId: text(value, 'key_id', 'approval_keys'), publicKey: text(value, 'public_key', 'approval_keys') };
      if (configuredPublicKey(entry) === null || approvalKeys.some(key => key.keyId === entry.keyId)) throw new ConfigError('configuration: invalid or repeated approval key');
      approvalKeys.push(entry);
    }
  }
  const attemptDeadlineMs = root['attempt_deadline'] === undefined ? 120_000 : parseDuration(text(root, 'attempt_deadline', 'configuration'));
  if (attemptDeadlineMs === null || attemptDeadlineMs > 600_000) throw new ConfigError('configuration: attempt_deadline must be a duration of at most 10m');
  const alertDir = root['alert_dir'] === undefined ? resolve(dirname(database), 'alerts') : resolve(base, text(root, 'alert_dir', 'configuration'));
  const escalateAfterMs = root['escalate_after'] === undefined ? 3_600_000 : parseDuration(text(root, 'escalate_after', 'configuration'));
  if (escalateAfterMs === null) throw new ConfigError('configuration: escalate_after must be a duration');
  const deltaToleranceMsat = root['delta_tolerance_msat'] === undefined ? 0n : target(root, 'delta_tolerance_msat', 'configuration');
  if (deltaToleranceMsat === null) throw new ConfigError('configuration: delta_tolerance_msat must be a non-negative msat string');
  return { database, policy, collectIntervalMs, approvalKeys, attemptDeadlineMs, alertDir, escalateAfterMs, deltaToleranceMsat,
    nodes: [...nodes].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) };
}

function target(map: YamlMap, key: string, where: string): bigint | null {
  const value = map[key];
  if (value === undefined) return null;
  if (typeof value !== 'string') throw new ConfigError(`${where}: ${key} must be an msat string`);
  try {
    return parseAmount(value, key);
  } catch {
    throw new ConfigError(`${where}: ${key} must be a non-negative integer msat string`);
  }
}

/** The operator targets of a policy file (`targets.<node>.<channel key>`); an absent policy has none. */
export function loadTargets(policyPath: string | null): Targets {
  const result = new Map<string, Map<string, ChannelTargets>>();
  if (policyPath === null) return result;
  const root = parseFile(policyPath, 'policy');
  if (!isMap(root)) throw new ConfigError('the policy must be a mapping');
  const targets = root['targets'];
  if (targets === undefined || targets === null) return result;
  if (!isMap(targets)) throw new ConfigError('policy: targets must be a mapping');
  for (const [node, channels] of Object.entries(targets)) {
    if (!isMap(channels)) throw new ConfigError('policy: targets.<node> must be a mapping');
    const perChannel = new Map<string, ChannelTargets>();
    for (const [key, value] of Object.entries(channels)) {
      const where = 'policy: targets.<node>.<channel>';
      if (!isMap(value)) throw new ConfigError(`${where} must be a mapping`);
      for (const field of Object.keys(value)) {
        if (field !== 'min_inbound_msat' && field !== 'min_outbound_msat') throw new ConfigError(`${where}: unknown key ${JSON.stringify(field.slice(0, 40))}`);
      }
      perChannel.set(key, { minInboundMsat: target(value, 'min_inbound_msat', where), minOutboundMsat: target(value, 'min_outbound_msat', where) });
    }
    result.set(node, perChannel);
  }
  return result;
}
