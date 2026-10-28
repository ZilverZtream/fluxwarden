import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { referencePins, referenceServices } from '../../labs/scenarios/chaos/owned-reference.mjs';

/** Synthetic Docker observations for testing reference admission, never live evidence. */
export function ownedReference(directory: string) {
  const rootNames = ['runtimeRoot', 'tmpRoot', 'sentinelRoot', 'evidenceRoot'] as const;
  const roots = Object.fromEntries(rootNames.map(key => {
    const path = join(directory, key); mkdirSync(path); return [key, path];
  })) as Record<typeof rootNames[number], string>;
  const owner = { version: 1, id: 'synthetic-reference-20261026', project: 'fluxwarden-lab-synthetic-20261026', ...roots,
    ports: { lndRest: 31210, clnRest: 31211, toxiproxy: 31212 }, resources: { cpus: 2, memoryBytes: 1073741824, pids: 112 } };
  const observed = referenceServices.map(service => ({ service, containerId: `synthetic-${service}`, cpus: 0.25, memoryBytes: 100_000_000, pids: 8 }));
  const manifest = { version: 1, ownerId: owner.id, project: owner.project, ports: owner.ports,
    nodes: Object.fromEntries(['lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m'].map((name, index) => [name, {
      network: 'regtest', pubkey: `02${String(index + 1).repeat(64)}`, version: name.startsWith('lnd-') ? '0.21.4-beta' : 'v26.06.9',
    }])),
    images: Object.fromEntries(Object.entries(referencePins).map(([name, reference]) => [name, { reference, digest: reference.split('@')[1] }])),
    resources: { declared: owner.resources, observed, effectiveWorkers: 1 } };
  const containers = referenceServices.map(service => ({ Id: `synthetic-${service}`, Name: `/${owner.project}-${service}-1`,
    Config: { Image: referencePins[service.startsWith('lnd-') ? 'lnd' : service.startsWith('cln-') ? 'cln' : service],
      Labels: { 'com.docker.compose.project': owner.project, 'com.docker.compose.service': service } },
    State: { Running: true, Paused: false, Health: { Status: 'healthy' } }, NetworkSettings: { Networks: { [`${owner.project}_regtest`]: {} } },
    HostConfig: { NanoCpus: 250_000_000, Memory: 100_000_000, PidsLimit: 8,
      PortBindings: service === 'toxiproxy' ? { '8474/tcp': [{ HostIp: '127.0.0.1', HostPort: '31212' }],
        '18080/tcp': [{ HostIp: '127.0.0.1', HostPort: '31210' }], '13010/tcp': [{ HostIp: '127.0.0.1', HostPort: '31211' }] } : {} } }));
  return { owner, manifest, containers };
}
