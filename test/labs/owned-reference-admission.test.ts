import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { qualifyNativeReference, qualifyReference } from '../../labs/scenarios/chaos/owned-reference.mjs';
import { input, proxies } from '../../labs/scenarios/chaos/live-reference.mjs';
import { ownedReference } from '../helpers/owned-reference.js';
import { scratch } from '../helpers/cp016-cli.js';
import { readCurrentBinding } from '../../labs/scenarios/live-profile.mjs';

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

it('CP-044/OPS-L1 supplied current owner is admitted while wrong owner, pins and native resource bindings refuse', () => {
  const directory = scratch('reference-owner'), fixture = ownedReference(directory);
  expect(qualifyNativeReference(fixture.owner, fixture.manifest, fixture.containers)).toEqual(fixture.containers);
  const changedOwner = { ...fixture.owner, id: 'foreign-owner' };
  expect(() => qualifyReference(changedOwner, fixture.manifest)).toThrow('LabInvalidError');
  const stale = structuredClone(fixture.manifest); stale.ports.lndRest += 1;
  expect(() => qualifyReference(fixture.owner, stale)).toThrow('LabInvalidError');
  const pins = structuredClone(fixture.manifest); const cln = pins.images['cln'];
  if (cln === undefined) throw new Error('synthetic CLN pin missing');
  cln.reference = 'foreign/image:latest';
  expect(() => qualifyReference(fixture.owner, pins)).toThrow('LabInvalidError');
  const mutations: ((containers: typeof fixture.containers) => void)[] = [
    containers => { const first = containers[0]; if (first) first.Config.Labels['com.docker.compose.project'] = 'foreign-project'; },
    containers => { const first = containers[0]; if (first) first.HostConfig.Memory = fixture.owner.resources.memoryBytes + 1; },
    containers => { const first = containers[0]; if (first) first.NetworkSettings.Networks = { 'foreign-network': {} }; },
    containers => { const proxy = containers.find(container => container.Config.Labels['com.docker.compose.service'] === 'toxiproxy');
      const port = proxy?.HostConfig.PortBindings['8474/tcp']?.[0]; if (port) port.HostIp = '0.0.0.0'; },
    containers => { const first = containers[0]; if (first) first.State.Paused = true; },
  ];
  for (const mutate of mutations) {
    const containers = structuredClone(fixture.containers); mutate(containers);
    expect(() => qualifyNativeReference(fixture.owner, fixture.manifest, containers)).toThrow('LabInvalidError');
  }
});

it('CP-044/OPS-L2 live input binds the supplied declaration and rejects a mismatched runtime before any control operation', () => {
  const directory = scratch('reference-input'), fixture = ownedReference(directory);
  const runtimeRoot = fixture.owner['runtimeRoot']; if (!runtimeRoot) throw new Error('synthetic runtime missing');
  const owner = join(directory, 'owner.json'), plan = join(directory, 'plan.json');
  writeFileSync(owner, JSON.stringify(fixture.owner));
  writeFileSync(join(runtimeRoot, 'lab.json'), JSON.stringify(fixture.manifest));
  writeFileSync(plan, JSON.stringify({ owner, binding: readCurrentBinding(owner, 'a'.repeat(40)) }));
  vi.stubEnv('FLUXWARDEN_CHAOS_REFERENCE_PLAN', plan);
  expect(input().owner.project).toBe('fluxwarden-lab-synthetic-20261026');
  writeFileSync(join(runtimeRoot, 'lab.json'), JSON.stringify({ ...fixture.manifest, ownerId: 'foreign-owner' }));
  expect(() => input()).toThrow('LabInvalidError');
});

it('CP-044/OPS-L3 foreign proxies are rejected before cleanup can change them', async () => {
  const directory = scratch('reference-proxy'), fixture = ownedReference(directory), runtimeRoot = fixture.owner['runtimeRoot'];
  if (!runtimeRoot) throw new Error('synthetic runtime missing');
  const owner = join(directory, 'owner.json'), plan = join(directory, 'plan.json');
  writeFileSync(owner, JSON.stringify(fixture.owner));
  writeFileSync(join(runtimeRoot, 'lab.json'), JSON.stringify(fixture.manifest));
  writeFileSync(plan, JSON.stringify({ owner, binding: readCurrentBinding(owner, 'a'.repeat(40)) }));
  vi.stubEnv('FLUXWARDEN_CHAOS_REFERENCE_PLAN', plan);
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
    'lnd-r-rest': { upstream: 'lnd-r:8080', enabled: true, toxics: [] },
    'cln-m-rest': { upstream: 'cln-m:3010', enabled: true, toxics: [] },
    foreign: { upstream: 'foreign:8080', enabled: false, toxics: [{ name: 'retain' }] },
  }), { status: 200 }));
  await expect(proxies()).rejects.toThrow('LabInvalidError');
  expect(fetch).toHaveBeenCalledOnce();
});
