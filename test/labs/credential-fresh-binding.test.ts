import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import type { BindingProducer, BindingRequest, BoundOwner, NodeName } from '../../labs/scenarios/credentials/producer-contract.d.mts';
import { repoRoot } from '../helpers/cli.js';
import { credentialPlan } from '../helpers/cp008-live.js';
import { afterBothFreshStarts, verifyFreshBinding } from '../helpers/cp008-fresh-binding.js';
import { ownedReference } from '../helpers/owned-reference.js';
import { scratch } from '../helpers/cp016-cli.js';

const names: NodeName[] = ['lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m'];
const refs = (): BindingRequest['endpointRefs'] => Object.fromEntries(names.map(node => [node,
  { node, transport: 'owned-node-https', certificate: { node }, roles: ['read', 'execute'] }])) as BindingRequest['endpointRefs'];
const sha = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
function owner(index: number) {
  const root = scratch(`credential-fresh-${String(index)}`), original = ownedReference(root);
  const value = { ...original.owner, version: 1 as const, id: `synthetic-credential-${String(index)}`, project: `fluxwarden-lab-synthetic-credential-${String(index)}`,
    ports: { lndRest: 32100 + index * 10, clnRest: 32101 + index * 10, toxiproxy: 32102 + index * 10 },
    credentialPolicy: { maxPrincipalMsat: '100000000', callsPerMinute: '600', lndRootKeyIds: { 'lnd-p': { read: '11', execute: '12' }, 'lnd-r': { read: '21', execute: '22' } } } };
  const declaration = join(root, 'owner.json'); writeFileSync(declaration, JSON.stringify(value), { mode: 0o600 });
  const imagePins = Object.fromEntries(original.containers.map(container => [container.Config.Labels['com.docker.compose.service'], container.Config.Image])) as Record<string, string>;
  return { root, value, declaration, imagePins };
}
function nativeMetadata() {
  // These synthetic observations test the metadata oracle only. No retained
  // live receipt, native PASS, real credential or Docker operation is generated.
  const selected = owner(4), { value, declaration, imagePins } = selected;
  const request: BindingRequest = { declaration, imagePins, endpointRefs: refs(), changePassword: { kind: 'fresh-denial-control' } };
  const observed = Object.entries(imagePins).map(([service, image], index) => ({ Id: `synthetic-${service}`, Image: `sha256:${String(index).repeat(64)}`,
    Config: { Image: image, Labels: { 'com.docker.compose.project': value.project, 'com.docker.compose.service': service } },
    NetworkSettings: { Networks: { [`${value.project}_regtest`]: { NetworkID: 'synthetic-owned-network', IPAddress: `172.31.9.${String(index + 2)}` } } } }));
  const credentials = Object.fromEntries(names.map(node => [node, Object.fromEntries(['read', 'execute'].map(role => [role,
    { path: join(value.runtimeRoot, 'credentials', node, `${role}.${node.startsWith('lnd-') ? 'macaroon' : 'rune'}`), fingerprint: `fp:${'a1'.repeat(8)}` }]))])) as BoundOwner['credentials'];
  const entries = Object.fromEntries(names.map((node, index) => [node, { network: 'regtest', pubkey: `02${String(index + 1).repeat(64)}`,
    certificate: { path: join(value.runtimeRoot, `fresh-${node}.pem`), sha256: 'b2'.repeat(32) } }]));
  const manifest = { version: 1, ownerId: value.id, project: value.project, ports: value.ports, nodes: entries, credentials, topology: { channels: [] } };
  const manifestBytes = Buffer.from(JSON.stringify(manifest)), declarationBytes = Buffer.from(JSON.stringify(value));
  const receipt: BoundOwner = { version: 1, ownerId: value.id, project: value.project, declarationSha256: sha(declarationBytes), manifestSha256: sha(manifestBytes),
    endpoints: Object.fromEntries(names.map(node => {
      const container = observed.find(row => row.Config.Labels['com.docker.compose.service'] === node);
      if (!container) throw new Error('synthetic node missing');
      const network = container.NetworkSettings.Networks[`${value.project}_regtest`];
      return [node, { hostname: network?.IPAddress ?? '', servername: node.startsWith('lnd-') ? node : 'localhost',
        port: node.startsWith('lnd-') ? 8080 : 3010, containerId: container.Id, certificate: entries[node]?.certificate.path ?? '' }];
    })) as BoundOwner['endpoints'], credentials, changePasswordFile: join(value.tmpRoot, 'fresh-control.json'), containers: observed };
  return { ...selected, request, observed, receipt, declarationBytes, manifestBytes };
}
it('CP-008/LP-A v2 reads only fresh owner/node refs before startup and rejects cleanup-bound static inputs', () => {
  const a = owner(1), b = owner(2), root = scratch('credential-static'), staticRoot = join(root, 'immutable'); mkdirSync(staticRoot);
  const plan = { version: 2, authorized: true, disposable: true, network: 'regtest', staticRoot,
    sourceManifest: join(staticRoot, 'authority.json'), bindingSourceManifest: join(staticRoot, 'wire.json'),
    budget: { cpus: 4, memoryBytes: 2147483648, pids: 224, workers: 2 },
    owners: [a, b].map(item => ({ declaration: item.declaration, imagePins: item.imagePins, endpointRefs: refs(), changePassword: { kind: 'fresh-denial-control' } })) };
  const path = join(root, 'plan.json'); writeFileSync(path, JSON.stringify(plan));
  const parsed = credentialPlan(path);
  expect(parsed.owners.every(item => item.endpoints === undefined && item.changePasswordFile === undefined)).toBe(true);
  for (const item of [a, b]) expect(readdirSync(item.value.runtimeRoot)).toEqual([]);
  const stale = { ...plan, owners: plan.owners.map(item => ({ ...item, endpoints: {} })) };
  writeFileSync(path, JSON.stringify(stale)); expect(() => credentialPlan(path)).toThrow('version2');
  writeFileSync(path, JSON.stringify({ ...plan, staticRoot: a.value.tmpRoot })); expect(() => credentialPlan(path)).toThrow('survive');
});
it('CP-008/LP-A concrete binding waits for BOTH actual up completions and never runs after a failed peer', async () => {
  let finish: (code: number) => void = () => { throw new Error('missing completion barrier'); }, bindings = 0;
  const late = new Promise<number>(resolve => { finish = resolve; });
  const pending = afterBothFreshStarts([Promise.resolve(0), late], () => { bindings++; return Promise.resolve(); });
  await Promise.resolve(); expect(bindings).toBe(0); finish(0); await pending; expect(bindings).toBe(1);
  await expect(afterBothFreshStarts([Promise.resolve(0), Promise.resolve(17)], () => { bindings++; return Promise.resolve(); })).rejects.toThrow('zero');
  expect(bindings).toBe(1);
});
it('CP-008/LP-A independently observed fresh bindings reject stale owner/cert/role foreign IP and secret-bearing receipts', () => {
  const f = nativeMetadata(), verify = (receipt: BoundOwner): void => { verifyFreshBinding(f.request, f.value, receipt, f.declarationBytes, f.manifestBytes, f.observed); };
  expect(() => { verify(f.receipt); }).not.toThrow();
  const mutations: ((receipt: BoundOwner) => void)[] = [
    receipt => { receipt.ownerId = 'foreign-owner'; }, receipt => { receipt.manifestSha256 = '0'.repeat(64); },
    receipt => { receipt.endpoints['cln-m'].certificate = join(f.value.runtimeRoot, 'stale-certificate.pem'); },
    receipt => { receipt.endpoints['lnd-p'].hostname = '172.99.0.1'; },
    receipt => { receipt.credentials['cln-r'].read.fingerprint = 'fp:0000000000000000'; },
    receipt => { if (receipt.containers[0]) receipt.containers[0].Config.Labels['com.docker.compose.project'] = 'foreign-project'; },
    receipt => { Object.assign(receipt, { passwordBytes: 'synthetic-unapproved-field' }); },
    receipt => { if (receipt.containers[0]) Object.assign(receipt.containers[0].Config, { Env: ['synthetic-unapproved-env'] }); },
  ];
  for (const mutate of mutations) { const changed = structuredClone(f.receipt); mutate(changed); expect(() => { verify(changed); }).toThrow(); }
});
it('CP-008/LP-A public fresh binder rejects an absent owner before any binding artifact', async () => {
  const producer = await import(pathToFileURL(join(repoRoot, 'scripts/live-credential-binding.mjs')).href) as BindingProducer;
  const directory = scratch('credential-binding-negative');
  await expect(producer.bindFreshCredentialOwner({ declaration: join(directory, 'absent-owner.json'), imagePins: {}, endpointRefs: refs(), changePassword: { kind: 'fresh-denial-control' } })).rejects.toThrow();
  expect(readdirSync(directory)).toEqual([]);
});
