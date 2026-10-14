// One-source connection settings for the node a command selects (SECURITY.md §3.3: credentials by path,
// never by value), and construction of the concrete node readers.
import { resolve } from 'node:path';
import type { NodeReader } from '../core/node.js';
import { parseEndpoint, type Endpoint, type NodeConfig } from '../config/config.js';
import { openClnReader } from '../node-cln/reader.js';
import { openLndReader } from '../node-lnd/reader.js';
import { CONNECTION_FLAGS, type ConnectionFlags } from './args.js';
import { looksLikeCredential } from './environment.js';

export type Environment = Readonly<Record<string, string | undefined>>;

/** Environment variables of the connection settings, in the order of CONNECTION_FLAGS. */
export const CONNECTION_VARIABLES: readonly (readonly [keyof ConnectionFlags, string])[] = [
  ['url', 'FLUXWARDEN_URL'], ['tlsCertPath', 'FLUXWARDEN_TLS_CERT_PATH'], ['macaroonPath', 'FLUXWARDEN_MACAROON_PATH'], ['runePath', 'FLUXWARDEN_RUNE_PATH'],
];

export interface Connection {
  readonly endpoint: Endpoint;
  readonly tlsCertPath: string;
  readonly credentialPath: string;
}

export class ConnectionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConnectionError';
  }
}

function variables(env: Environment): ConnectionFlags {
  return Object.fromEntries(CONNECTION_VARIABLES.flatMap(([key, name]) => {
    const value = env[name];
    return value === undefined || value === '' ? [] : [[key, value]];
  }));
}

const flagName = (key: keyof ConnectionFlags): string => CONNECTION_FLAGS.find(([k]) => k === key)?.[1] ?? key;
const variableName = (key: keyof ConnectionFlags): string => CONNECTION_VARIABLES.find(([k]) => k === key)?.[1] ?? key;

/**
 * Refusals that need no configuration (before anything is read): a connection flag or variable with a command
 * that does not select exactly one node, or connection variables beside connection flags for other settings.
 * Names only, never values.
 */
export function connectionSourceRefusal(selectsOneNode: boolean, flags: ConnectionFlags, env: Environment): string | null {
  const vars = variables(env);
  const valued = CONNECTION_VARIABLES.filter(([key]) => looksLikeCredential(vars[key] ?? '')).map(([, name]) => name);
  if (valued.length > 0) return `${valued.join(', ')} looks like a credential value; connection variables hold file paths only`;
  const flagKeys = CONNECTION_FLAGS.map(([key]) => key).filter(key => flags[key] !== undefined);
  const varKeys = CONNECTION_VARIABLES.map(([key]) => key).filter(key => vars[key] !== undefined);
  if (!selectsOneNode && flagKeys.length + varKeys.length > 0) {
    const named = [...flagKeys.map(flagName), ...varKeys.map(variableName)].join(', ');
    return `${named} apply only to a command that selects one node (nodes inspect <name>, channels --node <name>); one credential is never presented to several nodes`;
  }
  if (flagKeys.length > 0) {
    const stray = varKeys.filter(key => !flagKeys.includes(key));
    if (stray.length > 0) {
      return `${stray.map(variableName).join(', ')} set beside connection flags; give every connection setting as a flag or every one as a variable`;
    }
  }
  return null;
}

/** The connection of `node`: from flags when any is given, else from the variables when any is set, else from the configuration. */
export function resolveConnection(node: NodeConfig, flags: ConnectionFlags, env: Environment): Connection {
  const vars = variables(env);
  const fromFlags = CONNECTION_FLAGS.some(([key]) => flags[key] !== undefined);
  const fromVars = !fromFlags && CONNECTION_VARIABLES.some(([key]) => vars[key] !== undefined);
  if (!fromFlags && !fromVars) return { endpoint: node.endpoint, tlsCertPath: node.tlsCertPath, credentialPath: node.credentialPath };
  const source = fromFlags ? flags : vars;
  const name = fromFlags ? flagName : variableName;
  const [credentialKey, otherKey]: [keyof ConnectionFlags, keyof ConnectionFlags] = node.implementation === 'lnd' ? ['macaroonPath', 'runePath'] : ['runePath', 'macaroonPath'];
  if (source[otherKey] !== undefined) throw new ConnectionError(`${name(otherKey)} does not apply to the ${node.implementation} node ${node.name}`);
  const missing = (['url', 'tlsCertPath', credentialKey] as const).filter(key => source[key] === undefined);
  if (missing.length > 0) throw new ConnectionError(`${missing.map(name).join(', ')} missing: give the node address, its certificate and its credential from one source`);
  const endpoint = parseEndpoint(source.url ?? '');
  if (endpoint === null) throw new ConnectionError(`${name('url')} must be https://<host>:<port>`);
  return { endpoint, tlsCertPath: resolve(source.tlsCertPath ?? ''), credentialPath: resolve(source[credentialKey] ?? '') };
}

/** Reads the certificate and credential by path and returns the node's reader; no request is sent. */
export function openReader(node: NodeConfig, connection: Connection): Promise<NodeReader> {
  const { host, port } = connection.endpoint;
  return node.implementation === 'lnd'
    ? openLndReader({ host, port, tlsCertPath: connection.tlsCertPath, macaroonPath: connection.credentialPath })
    : openClnReader({ host, port, tlsCertPath: connection.tlsCertPath, runePath: connection.credentialPath });
}
