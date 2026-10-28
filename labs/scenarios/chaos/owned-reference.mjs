// Independent live-reference admission. Allocation names/ports may change;
// owner bindings, regtest isolation, image pins and resource budgets must hold.
import { validateOwner } from '../../docker/owner.mjs';

export const referenceServices = ['bitcoind', 'lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m', 'toxiproxy'];
// Pinned public docker-compose.yml profiles, rather than a historic demo project.
export const referencePins = Object.freeze({
  bitcoind: 'lightninglabs/bitcoin-core:31.1@sha256:86e15e4348869a86343aacbbd1aff38e96cffddd87b61644694b1e1358d737cd',
  lnd: 'lightninglabs/lnd:v0.21.4-beta@sha256:04d06edcc0f6e99a5e797ea34959f330add222226f840cd86afbc31f8f29627d',
  cln: 'elementsproject/lightningd:v26.06.9@sha256:de74289ddcccb68cd60543b08b2b8594002d819125d200492e17a95166d56577',
  toxiproxy: 'ghcr.io/shopify/toxiproxy:2.12.0@sha256:9378ed52a28bc50edc1350f936f518f31fa95f0d15917d6eb40b8e376d1a214e',
});
const invalid = () => { throw new Error('LabInvalidError: supplied owner, pins or native resource bindings do not match'); };
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const kind = service => service.startsWith('lnd-') ? 'lnd' : service.startsWith('cln-') ? 'cln' : service;

export function qualifyReference(owner, manifest) {
  try { validateOwner(owner); } catch { invalid(); }
  if (manifest?.version !== 1 || manifest.ownerId !== owner.id || manifest.project !== owner.project ||
      !equal(manifest.ports, owner.ports) || !equal(manifest.resources?.declared, owner.resources)) invalid();
  for (const [name, reference] of Object.entries(referencePins)) {
    if (manifest.images?.[name]?.reference !== reference || manifest.images[name].digest !== reference.split('@')[1]) invalid();
  }
  const observed = manifest.resources?.observed;
  if (!Array.isArray(observed) || !equal(observed.map(row => row.service).sort(), [...referenceServices].sort())) invalid();
  for (const key of ['cpus', 'memoryBytes', 'pids']) {
    if (observed.some(row => !Number.isFinite(row[key]) || row[key] <= 0) ||
        observed.reduce((sum, row) => sum + row[key], 0) > owner.resources[key]) invalid();
  }
  return owner;
}

export function qualifyNativeReference(owner, manifest, inspected) {
  qualifyReference(owner, manifest);
  if (!Array.isArray(inspected) || inspected.length !== referenceServices.length) invalid();
  const seen = new Set(), totals = { cpus: 0, memoryBytes: 0, pids: 0 };
  for (const container of inspected) {
    const labels = container.Config?.Labels, service = labels?.['com.docker.compose.service'];
    if (labels?.['com.docker.compose.project'] !== owner.project || !referenceServices.includes(service) || seen.has(service) ||
        container.Id !== manifest.resources.observed.find(row => row.service === service)?.containerId ||
        container.Name !== `/${owner.project}-${service}-1` || container.Config.Image !== referencePins[kind(service)] ||
        container.State?.Running !== true || container.State.Paused !== false || container.State.Health?.Status !== 'healthy') invalid();
    seen.add(service);
    if (!equal(Object.keys(container.NetworkSettings?.Networks ?? {}), [`${owner.project}_regtest`])) invalid();
    const host = container.HostConfig;
    const usage = { cpus: host?.NanoCpus / 1e9, memoryBytes: host?.Memory, pids: host?.PidsLimit };
    for (const key of Object.keys(totals)) {
      if (!Number.isFinite(usage[key]) || usage[key] <= 0) invalid();
      totals[key] += usage[key];
    }
    const expectedPorts = service === 'toxiproxy'
      ? { '8474/tcp': owner.ports.toxiproxy, '18080/tcp': owner.ports.lndRest, '13010/tcp': owner.ports.clnRest } : {};
    const bindings = host?.PortBindings ?? {};
    if (!equal(Object.keys(bindings).sort(), Object.keys(expectedPorts).sort())) invalid();
    for (const [port, declared] of Object.entries(expectedPorts)) {
      const actual = bindings[port];
      if (!Array.isArray(actual) || actual.length !== 1 || actual[0].HostIp !== '127.0.0.1' || Number(actual[0].HostPort) !== declared) invalid();
    }
  }
  for (const key of Object.keys(totals)) if (totals[key] > owner.resources[key]) invalid();
  return inspected;
}
