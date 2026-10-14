import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { request } from 'node:https';
import { LabInvalidError } from './chaos.js';
import { asRecord } from './cli.js';
import { docker, dockerText, identity, ownedOracle, rows, type OracleOwner } from './cp006-oracle.js';
import { client, type Client } from './cp007-toxiproxy.js';
export interface LiveOwner { project: string; ports: { lndRest: number; clnRest: number; toxiproxy: number }; credentials: { tlsCertificate: string; macaroon: string; clnCertificate: string; rune: string }; resources: { cpus: number; memoryBytes: number }; restart: boolean }
export function liveOwners(): LiveOwner[] {
  const file = process.env['FLUXWARDEN_TOXIPROXY_OWNERS'];
  if (!file || !isAbsolute(file)) throw new LabInvalidError('absolute explicit disposable Toxiproxy owner declaration required');
  const plan = asRecord(JSON.parse(readFileSync(file, 'utf8')) as unknown, 'Toxiproxy owner declaration');
  if (plan['authorized'] !== true || plan['disposable'] !== true || plan['network'] !== 'regtest') throw new LabInvalidError('explicit disposable regtest authorization required');
  const owners = rows(plan['owners'], 'explicit owners').map((raw): LiveOwner => {
    const ports = asRecord(raw['ports'], 'declared ports'), credentials = asRecord(raw['credentials'], 'declared credential files'), resources = asRecord(raw['resources'], 'declared limits');
    if (typeof raw['project'] !== 'string' || !/^fluxwarden-lab-[a-z0-9-]+$/.test(raw['project'])) throw new LabInvalidError('isolated explicit owner project required');
    for (const value of Object.values(ports)) if (typeof value !== 'number' || !Number.isInteger(value) || value < 1024 || value > 65535) throw new LabInvalidError('valid explicit loopback port required');
    for (const key of ['lndRest', 'clnRest', 'toxiproxy']) if (!ports[key]) throw new LabInvalidError('all three explicit owner ports required');
    for (const key of ['tlsCertificate', 'macaroon', 'clnCertificate', 'rune']) if (typeof credentials[key] !== 'string' || !isAbsolute(credentials[key])) throw new LabInvalidError('absolute explicit disposable credential file required');
    for (const key of ['cpus', 'memoryBytes']) if (typeof resources[key] !== 'number' || resources[key] <= 0 || !Number.isFinite(resources[key])) throw new LabInvalidError('positive explicit resource limits required');
    return { project: raw['project'], ports: ports as unknown as LiveOwner['ports'], credentials: credentials as unknown as LiveOwner['credentials'], resources: resources as unknown as LiveOwner['resources'], restart: raw['allowToxiproxyRestart'] === true };
  });
  if (owners.length === 0 || new Set(owners.map(owner => owner.project)).size !== owners.length || new Set(owners.flatMap(owner => Object.values(owner.ports))).size !== owners.length * 3) throw new LabInvalidError('nonempty disjoint disposable owners required');
  return owners;
}
export function liveClient(owner: LiveOwner): Promise<Client> { return client({ url: `http://127.0.0.1:${String(owner.ports.toxiproxy)}`, timeoutMs: 2000 }); }
export function liveOracle(owner: LiveOwner): OracleOwner {
  const oracle = ownedOracle();
  if (oracle.project !== owner.project) throw new LabInvalidError('direct node oracle declaration must match fault owner');
  identity(oracle, 'lnd-r'); identity(oracle, 'cln-m');
  return oracle;
}
// HTTPS verification is retained; no TLS bypass or credential bytes enter errors/evidence.
export function getInfo(owner: LiveOwner, timeoutMs = 3000): Promise<{ sent: boolean; status: number; body: unknown }> {
  const ca = readFileSync(owner.credentials.tlsCertificate), macaroon = readFileSync(owner.credentials.macaroon).toString('hex');
  return new Promise((resolve, reject) => {
    let sent = false;
    const call = request({ hostname: '127.0.0.1', port: owner.ports.lndRest, path: '/v1/getinfo', method: 'GET', ca, headers: { 'Grpc-Metadata-macaroon': macaroon } }, response => {
      const chunks: Buffer[] = []; response.on('data', (chunk: Buffer) => chunks.push(chunk));
      response.on('end', () => { try { resolve({ sent, status: response.statusCode ?? 0, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown }); } catch { reject(new Error('owned REST response was not JSON')); } });
    });
    const timer = setTimeout(() => { call.destroy(); reject(Object.assign(new Error('owned REST transport deadline'), { phase: sent ? 'sent' : 'unsent' })); }, timeoutMs);
    call.once('finish', () => { sent = true; });
    call.once('error', () => { reject(Object.assign(new Error('owned REST transport failed'), { phase: sent ? 'sent' : 'unsent' })); });
    call.once('close', () => { clearTimeout(timer); }); call.end();
  });
}
/** CLN C19: HTTPS, POST /v1/<method>, rune header; 3010 explicitly configured. */
export function getClnInfo(owner: LiveOwner): Promise<{ status: number; body: unknown }> {
  const ca = readFileSync(owner.credentials.clnCertificate), rune = readFileSync(owner.credentials.rune, 'utf8').trim();
  return new Promise((resolve, reject) => {
    const call = request({ hostname: '127.0.0.1', port: owner.ports.clnRest, path: '/v1/getinfo', method: 'POST', ca, headers: { rune, 'content-type': 'application/json' } }, response => {
      const chunks: Buffer[] = []; response.on('data', (chunk: Buffer) => chunks.push(chunk));
      response.on('end', () => { try { resolve({ status: response.statusCode ?? 0, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown }); } catch { reject(new Error('owned CLN REST response was not JSON')); } });
    });
    const timer = setTimeout(() => { call.destroy(); reject(new Error('owned CLN REST transport deadline')); }, 3000);
    call.once('error', () => { reject(new Error('owned CLN REST transport failed')); }); call.once('close', () => { clearTimeout(timer); }); call.end('{}');
  });
}
export function ownedContainers(owner: LiveOwner): Record<string, unknown>[] {
  const ids = dockerText(['ps', '-q', '--filter', `label=com.docker.compose.project=${owner.project}`]).split(/\s+/).filter(Boolean);
  if (ids.length !== 7) throw new LabInvalidError('explicit disposable owner must have all seven running containers');
  return rows(docker(['inspect', ...ids]), 'fresh owned container observations');
}
