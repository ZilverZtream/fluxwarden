import { createHash } from 'node:crypto';
import { isAbsolute, relative, resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import type { BindingRequest, BoundOwner, NodeName } from '../../labs/scenarios/credentials/producer-contract.d.mts';
import { asRecord } from './cli.js';
import { allServices, LabInvalidError, rows } from './cp006-oracle.js';
import type { Owner } from './cp006-lab.js';

const names: NodeName[] = ['lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m'];
const digest = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
const same = isDeepStrictEqual;
function within(root: string, value: unknown): value is string {
  if (typeof value !== 'string' || !isAbsolute(value)) return false;
  const part = relative(resolve(root), resolve(value)); return part !== '' && !part.startsWith('..') && !isAbsolute(part);
}

/** Ordinary up promises are started by Cohort, not by a synthetic producer.
 * A successful early owner never authorizes binding while its peer still starts. */
export async function afterBothFreshStarts(starts: Promise<number | null>[], bind: () => Promise<void>): Promise<void> {
  if (starts.length !== 2) throw new LabInvalidError('exact two fresh CLI starts required');
  const results = await Promise.allSettled(starts);
  for (const result of results) {
    if (result.status === 'rejected') throw result.reason instanceof Error ? result.reason : new LabInvalidError('ordinary bring-up failed');
    if (result.value !== 0) throw new LabInvalidError('ordinary fresh bring-up did not exit zero');
  }
  await bind();
}

/** Independent metadata oracle. Live callers supply fresh own Docker inspect
 * observations and descriptor-read manifest bytes, never producer permission booleans.
 * Credential/certificate byte checks and real TLS remain separate live checks. */
export function verifyFreshBinding(request: BindingRequest, owner: Owner, receipt: BoundOwner,
  declarationBytes: Uint8Array, manifestBytes: Uint8Array, observed: Record<string, unknown>[]): void {
  const manifest = asRecord(JSON.parse(Buffer.from(manifestBytes).toString('utf8')) as unknown, 'fresh actual manifest');
  const raw = asRecord(receipt, 'binding receipt');
  if (!same(Object.keys(receipt).sort(), ['version', 'ownerId', 'project', 'declarationSha256', 'manifestSha256', 'endpoints', 'credentials', 'changePasswordFile', 'containers'].sort())) {
    throw new LabInvalidError('binding receipt must contain only selected safe fields');
  }
  if (raw['version'] !== 1 || receipt.ownerId !== owner.id || receipt.project !== owner.project ||
      receipt.declarationSha256 !== digest(declarationBytes) || receipt.manifestSha256 !== digest(manifestBytes) ||
      !same(JSON.parse(Buffer.from(declarationBytes).toString('utf8')) as unknown, owner) ||
      manifest['version'] !== 1 || manifest['ownerId'] !== owner.id || manifest['project'] !== owner.project || !same(manifest['ports'], owner.ports)) {
    throw new LabInvalidError('fresh binding owner or manifest identity mismatch');
  }
  if (!same(Object.keys(receipt.endpoints).sort(), [...names].sort()) || !same(Object.keys(receipt.credentials).sort(), [...names].sort()) ||
      !within(owner.tmpRoot, receipt.changePasswordFile)) throw new LabInvalidError('fresh complete node references and owned request file required');
  if (observed.length !== 7 || receipt.containers.length !== 7 || new Set(observed.map(row => row['Id'])).size !== 7 ||
      new Set(receipt.containers.map(row => row.Id)).size !== 7) throw new LabInvalidError('exact seven independent current containers required');
  const seen = new Set<string>();
  for (const actual of observed) {
    const config = asRecord(actual['Config'], 'actual container config'), labels = asRecord(config['Labels'], 'actual compose labels');
    const service = String(labels['com.docker.compose.service']), item = receipt.containers.find(row => row.Id === actual['Id']);
    if (seen.has(service) || !allServices.includes(service) || labels['com.docker.compose.project'] !== owner.project || config['Image'] !== request.imagePins[service]) {
      throw new LabInvalidError('fresh container owner service or pinned image mismatch');
    }
    seen.add(service);
    const networks = asRecord(asRecord(actual['NetworkSettings'], 'actual networking')['Networks'], 'actual owned networks');
    const ownedNetwork = asRecord(networks[`${owner.project}_regtest`], 'actual regtest bridge');
    if (Object.keys(networks).length !== 1 || typeof ownedNetwork['NetworkID'] !== 'string' || !ownedNetwork['NetworkID']) throw new LabInvalidError('fresh exclusive owned regtest bridge required');
    const safe = { Id: actual['Id'], Image: actual['Image'], Config: { Image: config['Image'], Labels: {
      'com.docker.compose.project': labels['com.docker.compose.project'], 'com.docker.compose.service': labels['com.docker.compose.service'] } },
      NetworkSettings: { Networks: { [`${owner.project}_regtest`]: { NetworkID: ownedNetwork['NetworkID'], IPAddress: ownedNetwork['IPAddress'] } } } };
    // Exact selected-key comparison rejects returned Config.Env/Cmd/passwords.
    if (!item || !same(item, safe)) throw new LabInvalidError('sanitized receipt differs from independent current container identity');
    if (!names.includes(service as NodeName)) continue;
    const node = service as NodeName, ref = asRecord(request.endpointRefs[node], 'declared endpoint reference'), endpoint = receipt.endpoints[node];
    asRecord(endpoint, 'fresh concrete endpoint');
    if (!same(Object.keys(endpoint).sort(), ['hostname', 'servername', 'port', 'certificate', 'containerId'].sort())) throw new LabInvalidError('endpoint includes an undeclared field');
    if (ref['node'] !== node || asRecord(ref['certificate'], 'certificate reference')['node'] !== node || ref['transport'] !== 'owned-node-https' || !same(ref['roles'], ['read', 'execute'])) throw new LabInvalidError('declared node or role reference mismatch');
    if (endpoint.containerId !== actual['Id'] || endpoint.hostname !== ownedNetwork['IPAddress'] ||
        !/^\d+\.\d+\.\d+\.\d+$/.test(endpoint.hostname) || endpoint.port !== (node.startsWith('lnd-') ? 8080 : 3010) ||
        endpoint.servername !== (node.startsWith('lnd-') ? node : 'localhost')) throw new LabInvalidError('endpoint is not the independently observed owned node HTTPS binding');
    const entry = asRecord(asRecord(manifest['nodes'], 'actual nodes')[node], 'actual node');
    if (entry['network'] !== 'regtest' || !/^(02|03)[0-9a-f]{64}$/.test(String(entry['pubkey']))) throw new LabInvalidError('fresh node regtest identity unavailable');
    const cert = asRecord(entry['certificate'], 'actual copied certificate');
    if (endpoint.certificate !== cert['path'] || !within(owner.runtimeRoot, cert['path'])) throw new LabInvalidError('fresh manifest certificate reference mismatch');
    const roles = asRecord(asRecord(manifest['credentials'], 'actual credentials')[node], 'actual roles');
    if (!same(Object.keys(receipt.credentials[node]).sort(), ['execute', 'read'])) throw new LabInvalidError('exact fresh role references required');
    for (const role of ['read', 'execute'] as const) {
      const actualRole = asRecord(roles[role], 'actual role');
      if (!same(Object.keys(actualRole).sort(), ['fingerprint', 'path']) || !/^fp:[a-f0-9]{16}$/.test(String(actualRole['fingerprint'])) ||
          !same(receipt.credentials[node][role], actualRole) || !within(owner.runtimeRoot, actualRole['path'])) throw new LabInvalidError('fresh manifest role reference mismatch');
    }
  }
  // Native resource/state/image-digest assertions still run in Cohort.observe.
  rows(asRecord(manifest['topology'], 'actual owned topology')['channels'], 'actual owned topology channels');
}
