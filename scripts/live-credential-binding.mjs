// Reuses owner admission and checked file/CLI techniques from labs/docker/;
// TLS server names follow labs/docker/credential-transport.mjs and docker-compose.yml.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { isDeepStrictEqual as same } from 'node:util';
import { assertPrivateDirectories } from './private-scratch.mjs';
import { validateOwner } from '../labs/docker/owner.mjs';
import { validateCredentialPolicy } from '../labs/docker/credentials.mjs';
import { createCredentialPermissions } from '../labs/docker/credential-permissions.mjs';
import { composeEnvironment, runDocker } from '../labs/docker/compose.mjs';
import { nodes, services } from '../labs/docker/readiness.mjs';

const fail = () => new Error('credential-binding: current owner validation failed');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const keys = (value, expected) => value && same(Object.keys(value).sort(), [...expected].sort());
const within = (root, path) => {
  if (typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path) return false;
  const part = relative(root, path);
  return part !== '' && !part.startsWith('..') && !isAbsolute(part);
};

/** Called by the cohort only after both ordinary fresh owner startups settle. */
export async function bindFreshCredentialOwner({ declaration, imagePins, endpointRefs, changePassword, signal }) {
  try {
    const guard = () => { if (signal?.aborted) throw fail(); };
    guard();
    if (typeof declaration !== 'string' || !isAbsolute(declaration) || resolve(declaration) !== declaration) throw fail();
    const parent = dirname(declaration);
    const declarationIO = createCredentialPermissions({ runtimeRoot: parent, tmpRoot: parent, sentinelRoot: parent });
    const declarationBytes = Buffer.from(await declarationIO.readChecked(declaration));
    const owner = validateOwner(JSON.parse(declarationBytes.toString('utf8')));
    validateCredentialPolicy(owner.credentialPolicy);
    await assertPrivateDirectories([owner.runtimeRoot, owner.tmpRoot, owner.sentinelRoot, owner.evidenceRoot]);
    if (!same(changePassword, { kind: 'fresh-denial-control' }) || !keys(imagePins, services) || !keys(endpointRefs, nodes)) throw fail();
    for (const service of services) if (typeof imagePins[service] !== 'string' || !/^\S+@sha256:[a-f0-9]{64}$/.test(imagePins[service])) throw fail();
    for (const node of nodes) if (!same(endpointRefs[node], { node, transport: 'owned-node-https', certificate: { node }, roles: ['read', 'execute'] })) throw fail();
    const permissions = createCredentialPermissions(owner), manifestPath = join(owner.runtimeRoot, 'lab.json');
    const manifestBytes = Buffer.from(await permissions.readChecked(manifestPath));
    const manifest = JSON.parse(manifestBytes.toString('utf8'));
    if (manifest.version !== 1 || manifest.ownerId !== owner.id || manifest.project !== owner.project || !same(manifest.ports, owner.ports) ||
        !keys(manifest.nodes, nodes) || !keys(manifest.credentials, nodes) || !Array.isArray(manifest.topology?.channels)) throw fail();
    for (const service of services) {
      const image = manifest.images?.[service.split('-')[0]];
      if (image?.reference !== imagePins[service] || image.digest !== imagePins[service].split('@')[1]) throw fail();
    }
    const credentials = {};
    for (const node of nodes) {
      const entry = manifest.nodes[node], cert = entry.certificate;
      if (entry.network !== 'regtest' || !/^(02|03)[a-f0-9]{64}$/.test(entry.pubkey) || !within(owner.runtimeRoot, cert?.path) ||
          digest(await permissions.readChecked(cert.path)) !== cert.sha256 || !keys(manifest.credentials[node], ['read', 'execute'])) throw fail();
      credentials[node] = {};
      for (const role of ['read', 'execute']) {
        const actual = manifest.credentials[node][role];
        const path = join(owner.runtimeRoot, 'credentials', node, `${role}.${node.startsWith('lnd-') ? 'macaroon' : 'rune'}`);
        if (!keys(actual, ['path', 'fingerprint']) || actual.path !== path) throw fail();
        const bytes = await permissions.readChecked(path), fingerprint = `fp:${digest(bytes).slice(0, 16)}`;
        if (actual.fingerprint !== fingerprint) throw fail();
        credentials[node][role] = { path, fingerprint };
      }
    }
    const docker = async args => {
      guard();
      const result = await runDocker(['--config', owner.project, ...args], { cwd: owner.runtimeRoot, env: composeEnvironment(owner), timeoutMs: 30_000, signal });
      guard();
      if (result.exitCode !== 0) throw fail();
      return result.stdout;
    };
    const ids = (await docker(['ps', '-aq', '--no-trunc', '--filter', `label=com.docker.compose.project=${owner.project}`])).trim().split(/\s+/);
    if (ids.length !== services.length || new Set(ids).size !== ids.length || ids.some(id => !/^[a-f0-9]{64}$/.test(id))) throw fail();
    const observed = JSON.parse(await docker(['inspect', ...ids]));
    const images = JSON.parse(await docker(['image', 'inspect', ...new Set(Object.values(imagePins))]));
    if (!Array.isArray(observed) || observed.length !== services.length || !Array.isArray(images)) throw fail();
    const containers = [], endpoints = {}, seen = new Set(), addresses = new Set(), networks = new Set();
    const networkName = `${owner.project}_regtest`;
    for (const actual of observed) {
      const config = actual.Config, service = config?.Labels?.['com.docker.compose.service'];
      if (!ids.includes(actual.Id) || !services.includes(service) || seen.has(service) || config.Labels['com.docker.compose.project'] !== owner.project ||
          config.Image !== imagePins[service] || actual.State?.Running !== true || actual.State?.Paused === true || actual.State?.Health?.Status !== 'healthy') throw fail();
      seen.add(service);
      const matching = images.filter(image => Array.isArray(image.RepoDigests) && image.RepoDigests.some(pin => pin.split('@')[1] === imagePins[service].split('@')[1]));
      if (matching.length !== 1 || matching[0].Id !== actual.Image) throw fail();
      const actualNetworks = actual.NetworkSettings?.Networks, network = actualNetworks?.[networkName];
      if (!keys(actualNetworks, [networkName]) || typeof network.NetworkID !== 'string' || !network.NetworkID || isIP(network.IPAddress) !== 4 || addresses.has(network.IPAddress)) throw fail();
      addresses.add(network.IPAddress); networks.add(network.NetworkID);
      containers.push({ Id: actual.Id, Image: actual.Image, Config: { Image: config.Image, Labels: {
        'com.docker.compose.project': owner.project, 'com.docker.compose.service': service } },
      NetworkSettings: { Networks: { [networkName]: { NetworkID: network.NetworkID, IPAddress: network.IPAddress } } } });
      if (nodes.includes(service)) endpoints[service] = { hostname: network.IPAddress, servername: service.startsWith('lnd-') ? service : 'localhost',
        port: service.startsWith('lnd-') ? 8080 : 3010, certificate: manifest.nodes[service].certificate.path, containerId: actual.Id };
    }
    if (networks.size !== 1 || new Set(containers.map(container => container.Id)).size !== services.length) throw fail();
    // Recheck the current declaration and manifest after native observations.
    if (!declarationBytes.equals(Buffer.from(await declarationIO.readChecked(declaration))) ||
        !manifestBytes.equals(Buffer.from(await permissions.readChecked(manifestPath)))) throw fail();
    guard();
    const current = randomBytes(32), next = randomBytes(32);
    if (current.equals(next)) throw fail();
    const request = Buffer.from(JSON.stringify({ current_password: current.toString('base64'), new_password: next.toString('base64') }));
    // Register raw password bytes and the complete request with the existing scanner.
    for (const bytes of [current, next, request]) await permissions.writeExclusive(join(owner.sentinelRoot, `password-control-${randomUUID()}.bin`), bytes);
    const changePasswordFile = join(owner.tmpRoot, `password-control-${randomUUID()}.json`);
    await permissions.writeExclusive(changePasswordFile, request);
    if (!request.equals(Buffer.from(await permissions.readChecked(changePasswordFile)))) throw fail();
    guard();
    return { version: 1, ownerId: owner.id, project: owner.project, declarationSha256: digest(declarationBytes), manifestSha256: digest(manifestBytes),
      endpoints, credentials, changePasswordFile, containers };
  } catch { throw fail(); }
}
