import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { asRecord } from './cli.js';

export class LabInvalidError extends Error {
  constructor(reason: string) { super(reason); this.name = 'LabInvalidError'; }
}

export const lightningNodes = ['lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m'] as const;
export const allServices = ['bitcoind', ...lightningNodes, 'toxiproxy'];
export const edges = [['lnd-p', 'lnd-r'], ['lnd-r', 'cln-m'], ['lnd-r', 'cln-r'], ['cln-p', 'cln-r'], ['cln-r', 'cln-m']] as const;

export interface OracleOwner {
  project: string;
  composeFile: string;
  imagePins: Record<string, string>;
  pubkeys: Record<string, string>;
}

/** Independent disposable-owner declaration. This never discovers or adopts an existing lab. */
export function ownedOracle(): OracleOwner {
  const file = process.env['FLUXWARDEN_LAB_ORACLE_OWNER'];
  if (!file || !isAbsolute(file)) throw new LabInvalidError('an absolute independently declared disposable regtest owner is required');
  const owner = asRecord(JSON.parse(readFileSync(file, 'utf8')) as unknown, 'oracle owner');
  if (owner['disposable'] !== true || owner['network'] !== 'regtest' || owner['authorized'] !== true) throw new LabInvalidError('disposable regtest owner authorization is required');
  const project = owner['project'], composeFile = owner['composeFile'];
  if (typeof project !== 'string' || !/^fluxwarden-lab-[a-z0-9-]+$/.test(project) || typeof composeFile !== 'string' || !isAbsolute(composeFile)) throw new LabInvalidError('explicit isolated project and absolute compose file are required');
  const pins = asRecord(owner['imagePins'], 'independent image pins');
  const keys = asRecord(owner['pubkeys'], 'independent public keys');
  const imagePins: Record<string, string> = {}, pubkeys: Record<string, string> = {};
  for (const service of allServices) {
    const pin = pins[service];
    if (typeof pin !== 'string' || !/^[^\s$<>]+@sha256:[a-f0-9]{64}$/.test(pin)) throw new LabInvalidError('all independently measured image pins are required');
    imagePins[service] = pin;
  }
  for (const node of lightningNodes) {
    const key = keys[node];
    if (typeof key !== 'string' || !/^(?:02|03)[a-f0-9]{64}$/.test(key)) throw new LabInvalidError('independently recorded node public keys are required');
    pubkeys[node] = key;
  }
  return { project, composeFile: resolve(composeFile), imagePins, pubkeys };
}

/** Direct container commands bypass REST and proxies; no images are installed and no lab is started. */
export function dockerText(args: readonly string[]): string {
  const result = spawnSync('docker', [...args], { shell: false, windowsHide: true, encoding: 'utf8', timeout: 30_000, maxBuffer: 16 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new LabInvalidError('owned regtest oracle command did not complete successfully');
  return result.stdout.trim();
}

export function docker(args: readonly string[]): unknown {
  try { return JSON.parse(dockerText(args)) as unknown; }
  catch { throw new LabInvalidError('owned regtest oracle did not return JSON'); }
}

export function compose(owner: OracleOwner, args: readonly string[]): unknown {
  return docker(['compose', '--project-name', owner.project, '-f', owner.composeFile, ...args]);
}

export function oracle(owner: OracleOwner, node: string, method: string): Record<string, unknown> {
  const cli = node.startsWith('lnd-') ? ['lncli', '--network=regtest'] : ['lightning-cli', '--network=regtest', '-k'];
  return asRecord(compose(owner, ['exec', '-T', node, ...cli, method]), 'node oracle');
}

export function rows(value: unknown, what: string): Record<string, unknown>[] {
  if (!Array.isArray(value)) throw new LabInvalidError(`${what} must be an observed list`);
  return value.map(row => asRecord(row, what));
}

export function identity(owner: OracleOwner, node: string): Record<string, unknown> {
  const info = oracle(owner, node, 'getinfo');
  const lnd = node.startsWith('lnd-');
  const network = lnd ? rows(info['chains'], 'LND chains')[0]?.['network'] : info['network'];
  const version = info['version'];
  if (network !== 'regtest' || (lnd ? typeof version !== 'string' || !/^0\.21\.4-beta(?:$|\s|[+-])/.test(version) : version !== 'v26.06.9')) throw new LabInvalidError('owned node network or pinned version mismatch');
  if ((lnd ? info['identity_pubkey'] : info['id']) !== owner.pubkeys[node]) throw new LabInvalidError('owned node identity mismatch');
  return info;
}

export function shortId(value: unknown): string {
  if (typeof value !== 'string') throw new LabInvalidError('observed short channel identifier is required');
  if (/^\d+x\d+x\d+$/.test(value)) return value;
  if (!/^\d+$/.test(value)) throw new LabInvalidError('invalid observed short channel identifier');
  const encoded = BigInt(value);
  return `${(encoded >> 40n).toString()}x${((encoded >> 16n) & 0xffffffn).toString()}x${(encoded & 0xffffn).toString()}`;
}

export function expectedChannels(owner: OracleOwner): { scid: string; left: string; right: string }[] {
  const graph = rows(oracle(owner, 'lnd-p', 'describegraph')['edges'], 'LND graph edges');
  return edges.map(([leftNode, rightNode]) => {
    const left = owner.pubkeys[leftNode] ?? '', right = owner.pubkeys[rightNode] ?? '';
    const matching = graph.filter(row => (row['node1_pub'] === left && row['node2_pub'] === right) || (row['node1_pub'] === right && row['node2_pub'] === left));
    if (matching.length !== 1) throw new LabInvalidError('fresh owned topology does not contain exactly one expected endpoint pair');
    return { scid: shortId(matching[0]?.['channel_id']), left, right };
  });
}
