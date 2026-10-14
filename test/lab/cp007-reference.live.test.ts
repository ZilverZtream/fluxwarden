import { expect, it } from 'vitest';
import { asRecord } from '../helpers/cli.js';
import { getInfo, getClnInfo, liveClient, liveOracle, liveOwners, ownedContainers } from '../helpers/cp007-live.js';
import { managed, required } from '../helpers/cp007-toxiproxy.js';
import { docker, oracle, rows } from '../helpers/cp006-oracle.js';
import { LabInvalidError } from '../helpers/chaos.js';

// SPEC 11.1, ARCHITECTURE 10.2; fresh API/Docker/direct CLI observations.
it('CP-007/R1 pinned daemon exposes exactly two enabled REST paths with isolated loopback publication and direct oracles', async () => {
  const owner = required(liveOwners()[0]);
  const direct = liveOracle(owner), control = await liveClient(owner), state = await control.list();
  if (Object.values(state).some(proxy => !proxy.enabled || proxy.toxics.length > 0)) throw new LabInvalidError('owned daemon is dirty before reference observation');
  expect(await control.version()).toEqual({ version: '2.12.0' });
  expect(Object.keys(state).sort()).toEqual(['cln-m-rest', 'lnd-r-rest']);
  // Toxiproxy v2.12.0 proxy.go: GET /proxies marshals the Proxy struct, whose listen is the bound
  // listener address (0.0.0.0:<port> binds dual-stack and reads back as [::]:<port>) and which also
  // carries a Logger member.
  for (const proxy of managed) {
    const observed = asRecord(state[proxy.name], proxy.name);
    expect({ name: observed['name'], upstream: observed['upstream'], enabled: observed['enabled'], toxics: observed['toxics'] }).toEqual({ name: proxy.name, upstream: proxy.upstream, enabled: true, toxics: [] });
    expect(observed['listen']).toBe(proxy.listen.replace('0.0.0.0:', '[::]:'));
  }
  const bindings: { service: unknown; host: unknown; port: number }[] = [];
  for (const container of ownedContainers(owner)) {
    const config = asRecord(container['Config'], 'container config'), service = asRecord(config['Labels'], 'labels')['com.docker.compose.service'];
    if (service === 'toxiproxy') {
      expect(config['Image']).toBe('ghcr.io/shopify/toxiproxy:2.12.0@sha256:9378ed52a28bc50edc1350f936f518f31fa95f0d15917d6eb40b8e376d1a214e');
      const image = required(rows(docker(['image', 'inspect', String(container['Image'])]), 'actual daemon image')[0]);
      expect(image['Id']).toBe(container['Image']);
      expect(Array.isArray(image['RepoDigests']) && image['RepoDigests'].some(value => typeof value === 'string' && value.endsWith('@sha256:9378ed52a28bc50edc1350f936f518f31fa95f0d15917d6eb40b8e376d1a214e')), 'actual pinned repository digest').toBe(true);
      const mounts = rows(container['Mounts'], 'actual mounts');
      expect(mounts.some(mount => mount['RW'] === false && typeof mount['Destination'] === 'string' && mount['Destination'].endsWith('.json')), 'initial config mounted read-only').toBe(true);
      expect(Array.isArray(config['Cmd']) && config['Cmd'].includes('-config'), 'daemon loads static config').toBe(true);
    }
    for (const value of Object.values(asRecord(asRecord(container['NetworkSettings'], 'network settings')['Ports'], 'published ports'))) if (value !== null) for (const binding of rows(value, 'port bindings')) bindings.push({ service, host: binding['HostIp'], port: Number(binding['HostPort']) });
  }
  expect(bindings.sort((a, b) => a.port - b.port)).toEqual(Object.values(owner.ports).sort((a, b) => a - b).map(port => ({ service: 'toxiproxy', host: '127.0.0.1', port })));
  expect(oracle(direct, 'lnd-r', 'getinfo')['synced_to_graph']).toBe(true);
  expect(oracle(direct, 'cln-m', 'getinfo')['network']).toBe('regtest');
  const lnd = await getInfo(owner), cln = await getClnInfo(owner);
  expect(lnd.status).toBe(200); expect(asRecord(lnd.body, 'proxied LND identity')['identity_pubkey']).toBe(direct.pubkeys['lnd-r']);
  // clnrest answers a successful command with 201 (plugins/rest-plugin handlers.rs; observed in the lab).
  expect(cln.status).toBe(201); expect(asRecord(cln.body, 'proxied CLN identity')['id']).toBe(direct.pubkeys['cln-m']);
});

// Public reference portion of Bowner; root separately proves exact selected union and wall phases.
it('CP-007/Rowner independent owners expose disjoint actual containers ports and bounded CPU memory', () => {
  const owners = liveOwners(); if (owners.length !== 2) throw new LabInvalidError('two explicit independent owners required');
  const ids = new Set<unknown>(); let cpu = 0, memory = 0;
  for (const owner of owners) {
    let ownCpu = 0, ownMemory = 0;
    for (const container of ownedContainers(owner)) {
      expect(ids.has(container['Id']), 'containers are disjoint').toBe(false); ids.add(container['Id']);
      const limits = asRecord(container['HostConfig'], 'actual resource limits');
      expect(limits['NanoCpus']).toBeGreaterThan(0); expect(limits['Memory']).toBeGreaterThan(0);
      ownCpu += Number(limits['NanoCpus']) / 1e9; ownMemory += Number(limits['Memory']);
    }
    expect(ownCpu).toBeLessThanOrEqual(owner.resources.cpus); expect(ownMemory).toBeLessThanOrEqual(owner.resources.memoryBytes);
    cpu += ownCpu; memory += ownMemory;
  }
  expect(cpu).toBeLessThanOrEqual(8); expect(memory).toBeLessThanOrEqual(8589934592);
});
