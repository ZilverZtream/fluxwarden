import { readFile, writeFile, mkdir, lstat, realpath } from 'node:fs/promises';
import { join, resolve, relative, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { processOutput } from '../../dist/output/index.js';
import { createPrivateDirectory, assertPrivateDirectory, assertPrivateDirectories } from '../../scripts/private-scratch.mjs';
import { composeArguments, composeEnvironment, runDocker } from './compose.mjs';
import { bakeLabCredentials, validateCredentialPolicy } from './credentials.mjs';
import { createCredentialPermissions } from './credential-permissions.mjs';
import { createPermissionRequest } from './credential-transport.mjs';
import { provisionAuthorizationFixtures } from './credential-fixtures.mjs';
import { nodes, services, fail, record, rows, decimal, shortId, identity, synced, graphReady, layersCleared, waitFor } from './readiness.mjs';
import { validateOwner, reserveOwner, releaseOwner, checkDeclaration, clearOwnedDirectory, protectCreated, acquireWorker } from './owner.mjs';

const generalTimeout = 180000, stageTimeout = 30000;
const topology = JSON.parse(await readFile(new URL('../topology.json', import.meta.url), 'utf8'));
const proxyPlan = JSON.parse(await readFile(new URL('./toxiproxy.json', import.meta.url), 'utf8'));
export const imagePins = Object.freeze({
  bitcoind: 'lightninglabs/bitcoin-core:31.1@sha256:86e15e4348869a86343aacbbd1aff38e96cffddd87b61644694b1e1358d737cd',
  lnd: 'lightninglabs/lnd:v0.21.4-beta@sha256:04d06edcc0f6e99a5e797ea34959f330add222226f840cd86afbc31f8f29627d',
  cln: 'elementsproject/lightningd:v26.06.9@sha256:de74289ddcccb68cd60543b08b2b8594002d819125d200492e17a95166d56577',
  toxiproxy: 'ghcr.io/shopify/toxiproxy:2.12.0@sha256:9378ed52a28bc50edc1350f936f518f31fa95f0d15917d6eb40b8e376d1a214e',
});

export function createLab({ owner: declaration, run = runDocker, clock = () => performance.now(),
  delay: pause = (ms, signal) => delay(ms, undefined, { signal }),
  permissions = { create: createPrivateDirectory, assert: assertPrivateDirectory }, signal } = {}) {
  const owner = validateOwner(declaration);
  const env = composeEnvironment(owner);
  if (env.DOCKER_HOST && !/^(unix:|npipe:)/.test(env.DOCKER_HOST)) throw fail('docker-host');
  const override = join(owner.runtimeRoot, 'compose-owner.json');
  const attempt = randomBytes(8).toString('hex');
  let deadline = 0, acquired = false, reserved = false, busy = false, sequence = 0;
  let identities = {}, channelIds = {}, bootstrapSentinels = [];
  const imageProofs = new Map();
  const context = (cleanup = false) => ({ clock, delay: pause, signal: cleanup ? undefined : signal, deadline });
  const journal = async (stage, result) => {
    await writeFile(join(owner.evidenceRoot, `lab-${attempt}-command-${String(++sequence).padStart(4, '0')}.json`),
      JSON.stringify({ stage, exitCode: result.exitCode, stdoutSha256: createHash('sha256').update(result.stdout).digest('hex'), stderrSha256: createHash('sha256').update(result.stderr).digest('hex') }), { mode: 0o600 });
  };
  const execute = async (stage, argv, cleanup = false, limit = stageTimeout) => {
    if ((!cleanup && signal?.aborted) || clock() >= deadline) throw fail(`${stage} timeout`);
    let result;
    try { result = await run(argv, { cwd: owner.runtimeRoot, env, timeoutMs: Math.max(1, Math.min(limit, deadline - clock())), signal: cleanup ? undefined : signal }); }
    catch { throw fail(`${stage} subprocess`); }
    if (!result || !Number.isInteger(result.exitCode) || typeof result.stdout !== 'string' || typeof result.stderr !== 'string') throw fail(stage);
    await journal(stage, result);
    if (result.exitCode !== 0 || (!cleanup && signal?.aborted) || clock() >= deadline) throw fail(`${stage} child`);
    return result.stdout.trim();
  };
  const compose = (stage, args, cleanup = false, limit) => execute(stage, composeArguments(owner, override, args), cleanup, limit);
  const parse = (text, stage) => { try { return JSON.parse(text); } catch { throw fail(`${stage} JSON`); } };
  const rpc = async (node, method, args = []) => {
    const cli = node === 'bitcoind' ? ['bitcoin-cli', '-regtest'] : node.startsWith('lnd-') ? ['lncli', '--network=regtest'] : ['lightning-cli', '--network=regtest', '-k'];
    const text = await compose(method, ['exec', '-T', node, ...cli, method, ...args]);
    if (node === 'bitcoind' && ['getnewaddress', 'sendtoaddress'].includes(method)) return text;
    return parse(text, method);
  };
  const wait = (stage, observe) => waitFor(stage, observe, { ...context(), deadline: Math.min(deadline, clock() + stageTimeout) });
  const observeAll = async (observe, selected = nodes) => {
    const results = await Promise.allSettled(selected.map(observe));
    const rejected = results.find(result => result.status === 'rejected');
    if (rejected) throw rejected.reason;
    return results.map(result => result.value);
  };
  const info = async node => {
    const answer = record(await rpc(node, 'getinfo'), 'getinfo');
    const observed = identity(node, answer, identities[node]);
    identities[node] = { ...identities[node], ...observed };
    return answer;
  };
  const waitChain = (height, requireGraph = false) => wait('chain', async () => {
    return (await observeAll(async node => synced(node, await info(node), height, requireGraph))).every(Boolean);
  });
  const mine = async (blocks, address) => {
    const hashes = await rpc('bitcoind', 'generatetoaddress', [blocks, address]);
    if (!Array.isArray(hashes) || hashes.length !== Number(blocks)) throw fail('mine');
    return decimal(await rpc('bitcoind', 'getblockcount'), 'height');
  };
  const localChannels = async node => rows(record(await rpc(node, node.startsWith('lnd-') ? 'listchannels' : 'listpeerchannels'), 'active').channels, 'active');

  async function assertRoots() {
    const roots = [owner.runtimeRoot, owner.tmpRoot, owner.sentinelRoot, owner.evidenceRoot];
    // The ordinary validator inspects every root freshly in one Windows ACL process.
    // Supplied validators keep their one-directory interface; all independent
    // read-only inspections must settle before any Docker operation can begin.
    if (permissions.assert === assertPrivateDirectory) await assertPrivateDirectories(roots);
    else await observeAll(root => permissions.assert(root), roots);
  }
  async function configure() {
    // All seven container limits are derived from this owner's declaration, even with inherited settings.
    const cpus = Math.floor(owner.resources.cpus / 7 * 1e6) / 1e6;
    const mem_limit = Math.floor(owner.resources.memoryBytes / 7), pids_limit = Math.floor(owner.resources.pids / 7);
    const serviceConfig = Object.fromEntries(services.map(service => [service, { cpus, mem_limit, pids_limit }]));
    await writeFile(override, JSON.stringify({ services: serviceConfig }), { mode: 0o600 });
    // Isolate Docker CLI configuration as well as Compose state. Public pulls use no borrowed credentials.
    await mkdir(join(owner.runtimeRoot, owner.project), { recursive: true, mode: 0o700 });
  }
  async function observedResources() {
    const ids = (await compose('inventory', ['ps', '-aq'])).split(/\s+/).filter(Boolean);
    if (ids.length !== 7) throw fail('container-inventory');
    const raw = await execute('inspect', ['--config', owner.project, 'inspect', ...ids]);
    const inspected = rows(parse(raw, 'inspect'), 'inspect');
    if (inspected.length !== 7) throw fail('inspect');
    const wanted = new Set();
    for (const container of inspected) {
      const config = record(container.Config, 'inspect'), labels = record(config.Labels, 'inspect');
      const service = labels['com.docker.compose.service'];
      if (labels['com.docker.compose.project'] !== owner.project || !services.includes(service) || config.Image !== imagePins[service.split('-')[0]]) throw fail('image-owner');
      if (!container.RepoDigests && !imageProofs.has(config.Image)) wanted.add(config.Image);
    }
    if (wanted.size) {
      const images = rows(parse(await execute('image-inspect', ['--config', owner.project, 'image', 'inspect', ...wanted]), 'image-inspect'), 'image-inspect');
      for (const reference of wanted) {
        const matching = images.filter(image => Array.isArray(image.RepoDigests) && image.RepoDigests.some(pin => pin.split('@')[1] === reference.split('@')[1]));
        if (matching.length !== 1 || typeof matching[0].Id !== 'string') throw fail('image-digest');
        imageProofs.set(reference, matching[0].Id);
      }
    }
    const seen = new Set(), observed = [];
    for (const container of inspected) {
      const config = record(container.Config, 'inspect'), labels = record(config.Labels, 'inspect');
      const service = labels['com.docker.compose.service'], kind = service?.split('-')[0], reference = imagePins[kind];
      if (labels['com.docker.compose.project'] !== owner.project || !services.includes(service) || seen.has(service) || config.Image !== reference) throw fail('image-owner');
      seen.add(service);
      const state = record(container.State, 'inspect');
      if (state.Running !== true || record(state.Health, 'health').Status !== 'healthy') throw fail('health');
      const host = record(container.HostConfig, 'resource');
      const cpus = host.NanoCpus / 1e9, memoryBytes = host.Memory, pids = host.PidsLimit;
      if (![cpus, memoryBytes, pids].every(value => typeof value === 'number' && Number.isFinite(value) && value > 0)) throw fail('resource');
      observed.push({ service, containerId: container.Id, cpus, memoryBytes, pids });
      // Config.Image binds the exact requested digest; inspect of that reference binds the actual image ID.
      if (container.RepoDigests) {
        if (!Array.isArray(container.RepoDigests) || !container.RepoDigests.includes(reference)) throw fail('image-digest');
      } else {
        if (imageProofs.get(reference) !== container.Image) throw fail('image-digest');
      }
      for (const bindings of Object.values(host.PortBindings || {})) for (const binding of bindings || []) {
        if (binding.HostIp !== '127.0.0.1' || !Object.values(owner.ports).includes(Number(binding.HostPort))) throw fail('port-bindings');
      }
    }
    for (const key of ['cpus', 'memoryBytes', 'pids']) if (observed.reduce((sum, value) => sum + value[key], 0) > owner.resources[key]) throw fail('resource-budget');
    await writeFile(join(owner.evidenceRoot, `lab-${attempt}-container-${String(++sequence)}.json`), JSON.stringify(inspected.map(container => ({ Id: container.Id, Image: container.Image, Config: { Image: container.Config.Image, Labels: container.Config.Labels }, State: { Running: container.State.Running, Health: { Status: container.State.Health.Status } }, HostConfig: { NanoCpus: container.HostConfig.NanoCpus, Memory: container.HostConfig.Memory, PidsLimit: container.HostConfig.PidsLimit, PortBindings: container.HostConfig.PortBindings } }))), { mode: 0o600 });
    return observed;
  }
  async function copyBootstrap() {
    const directory = await permissions.create(owner.runtimeRoot, 'credentials-');
    const files = [];
    for (const node of nodes) {
      const paths = node.startsWith('lnd-') ? { certificate: '/root/.lnd/tls.cert', credential: '/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon' }
        // The clnrest CA signs the server certificate (names cln, localhost); client.pem is a client identity.
        : { certificate: '/root/.lightning/regtest/ca.pem' };
      for (const [kind, source] of Object.entries(paths)) {
        const path = join(directory, `${node}-${kind}`);
        await compose('bootstrap-copy', ['cp', `${node}:${source}`, path]);
        files.push({ node, kind, path });
      }
    }
    const copies = files.filter(file => file.kind === 'credential').map(file => ({ source: file.path,
      target: join(owner.sentinelRoot, `${file.node}-${attempt}-bootstrap.bin`) }));
    // Protect source files before copying their bytes, then protect the new sentinels in the
    // same native operation. Directory ACLs are read freshly before and after the copies.
    await protectCreated(files.map(file => file.path), { copies,
      privateDirectories: [directory, owner.sentinelRoot] });
    if (permissions.assert !== assertPrivateDirectory) await permissions.assert(directory);
    bootstrapSentinels.push(...copies.map(copy => copy.target));
    for (const file of files) {
      const actual = await realpath(file.path), inside = relative(owner.runtimeRoot, actual), stat = await lstat(file.path);
      if (!inside || inside.startsWith('..') || isAbsolute(inside) || stat.isSymbolicLink() || !stat.isFile() || stat.size === 0 || stat.size > 65536) throw fail('bootstrap-file');
      const bytes = await readFile(actual);
      identities[file.node][file.kind] = { path: actual, sha256: createHash('sha256').update(bytes).digest('hex') };
      if (file.kind === 'credential') {
        const sentinel = join(owner.sentinelRoot, `${file.node}-${attempt}-bootstrap.bin`);
        const testTmp = process.env.FLUXWARDEN_TEST_TMP;
        if (testTmp) await writeFile(join(testTmp, 'declared-out.txt'), `${actual}\n${sentinel}\n`, { flag: 'a', mode: 0o600 });
      }
    }
  }
  // Credential controls re-aim the managed proxies; a ready lab has each proxy on its own node.
  async function restoreProxies() {
    for (const proxy of proxyPlan) {
      let answer;
      try {
        const response = await fetch(`http://127.0.0.1:${owner.ports.toxiproxy}/proxies/${proxy.name}`, { method: 'POST', redirect: 'error',
          headers: { 'content-type': 'application/json' }, body: JSON.stringify({ upstream: proxy.upstream, enabled: true }), signal: AbortSignal.timeout(stageTimeout) });
        answer = response.ok ? await response.json() : undefined;
      } catch { throw fail('proxy-restore'); }
      if (!answer || answer.upstream !== proxy.upstream || answer.enabled !== true || !Array.isArray(answer.toxics) || answer.toxics.length) throw fail('proxy-restore');
    }
  }
  async function cleanup() {
    deadline = clock() + generalTimeout;
    await checkDeclaration(owner);
    await configure();
    await compose('cleanup', ['down', '--volumes', '--remove-orphans'], true);
    const containers = await compose('cleanup-inventory', ['ps', '-aq'], true);
    const volumes = await execute('cleanup-volumes', ['--config', owner.project, 'volume', 'ls', '-q', '--filter', `label=com.docker.compose.project=${owner.project}`], true);
    if (containers || volumes) throw fail('cleanup-leftovers');
    await clearOwnedDirectory(owner.tmpRoot);
    await clearOwnedDirectory(owner.runtimeRoot);
    await releaseOwner(owner, context(true));
    reserved = false; acquired = false;
    await writeFile(join(owner.evidenceRoot, `lab-${attempt}-cleanup.json`), JSON.stringify({ project: owner.project, containers: [], volumes: [], removedTemporaryState: true }), { mode: 0o600 });
  }
  async function up() {
    if (busy) throw fail('owner-busy'); busy = true; deadline = clock() + generalTimeout;
    let releaseWorker;
    try {
      // Role credentials are optional; an owner without a policy keeps only the copied bootstrap files.
      const credentialPolicy = owner.credentialPolicy === undefined ? undefined : validateCredentialPolicy(owner.credentialPolicy);
      await assertRoots();
      releaseWorker = await acquireWorker(owner);
      await configure();
      if (await compose('inventory', ['ps', '-aq'])) throw fail('existing-owner');
      await reserveOwner(owner, context()); reserved = true;
      acquired = true;
      await compose('up', ['up', '-d', '--wait', '--wait-timeout', '60'], false, 60000);
      identities = {}; channelIds = {}; bootstrapSentinels = []; imageProofs.clear();
      await observeAll(info);
      const chain = record(await rpc('bitcoind', 'getblockchaininfo'), 'bitcoin-network');
      if (chain.chain !== 'regtest') throw fail('bitcoin-network');
      const bitcoin = record(await rpc('bitcoind', 'getnetworkinfo'), 'bitcoin-version');
      if (bitcoin.version !== 310100 || bitcoin.subversion !== '/Satoshi:31.1.0/') throw fail('bitcoin-version');
      await observedResources();
      const wallets = await rpc('bitcoind', 'listwallets');
      if (!Array.isArray(wallets)) throw fail('bitcoin-wallet');
      if (!wallets.includes('lab')) await rpc('bitcoind', 'createwallet', ['lab']);
      const miningAddress = await rpc('bitcoind', 'getnewaddress');
      if (typeof miningAddress !== 'string' || !/^bcrt1[a-z0-9]+$/.test(miningAddress)) throw fail('mining-address');
      await waitChain(await mine('101', miningAddress));
      await copyBootstrap();
      for (const node of nodes) {
        const response = record(await rpc(node, node.startsWith('lnd-') ? 'newaddress' : 'newaddr', node.startsWith('lnd-') ? ['p2wkh'] : ['addresstype=bech32']), 'funding-address');
        const address = node.startsWith('lnd-') ? response.address : response.bech32;
        if (typeof address !== 'string' || !/^bcrt1[a-z0-9]+$/.test(address)) throw fail('funding-address');
        identities[node].fundingAddress = address;
        await rpc('bitcoind', 'sendtoaddress', [address, '1.00000000']);
      }
      await waitChain(await mine('6', miningAddress));
      await wait('confirmed', async () => {
        return (await observeAll(async node => {
          const balance = record(await rpc(node, node.startsWith('lnd-') ? 'walletbalance' : 'listfunds'), 'confirmed');
          return node.startsWith('lnd-') ? decimal(balance.confirmed_balance, 'confirmed') >= 100000000n
            : rows(balance.outputs, 'confirmed').some(output => output.status === 'confirmed' && decimal(output.amount_msat, 'confirmed') >= 100000000000n);
        })).every(Boolean);
      });
      for (const channel of topology.channels) await rpc(channel.from, 'connect', channel.from.startsWith('lnd-') ? [`${identities[channel.to].pubkey}@${channel.to}:9735`] : [`id=${identities[channel.to].pubkey}`, `host=${channel.to}`, 'port=9735']);
      await wait('peers', async () => {
        return (await observeAll(async node => {
          const peers = rows(record(await rpc(node, 'listpeers'), 'peers').peers, 'peers');
          return topology.channels.filter(channel => channel.from === node || channel.to === node).every(channel => {
            const remote = identities[channel.from === node ? channel.to : channel.from].pubkey;
            return peers.some(peer => node.startsWith('lnd-') ? peer.pub_key === remote : peer.id === remote && peer.connected === true);
          });
        })).every(Boolean);
      });
      const funding = [], openers = new Set();
      for (const channel of topology.channels) {
        const sat = (BigInt(channel.capacity_msat) / 1000n).toString(), push = (BigInt(channel.push_msat) / 1000n).toString();
        const result = record(await rpc(channel.from, channel.from.startsWith('lnd-') ? 'openchannel' : 'fundchannel', channel.from.startsWith('lnd-')
          ? [`--node_key=${identities[channel.to].pubkey}`, `--local_amt=${sat}`, `--push_amt=${push}`, '--sat_per_vbyte=2',
            // LND-R's next open spends change from its previous funding transaction.
            // lightningnetwork/lnd@v0.21.4-beta cmd/commands/cmd_open_channel.go:
            // min_confs=0 sets SpendUnconfirmed; the final mining still confirms every funding tx.
            ...(openers.has(channel.from) ? ['--min_confs=0'] : [])]
          : [`id=${identities[channel.to].pubkey}`, `amount=${sat}sat`, `push_msat=${channel.push_msat}msat`, 'announce=true', 'feerate=2000perkw']), 'open-channel');
        const txid = result.funding_txid || result.txid;
        if (typeof txid !== 'string' || !/^[a-f0-9]{64}$/.test(txid)) throw fail('funding-txid');
        funding.push(txid);
        openers.add(channel.from);
      }
      await wait('mempool', async () => {
        const txids = await rpc('bitcoind', 'getrawmempool');
        if (!Array.isArray(txids)) throw fail('mempool');
        return funding.every(txid => txids.includes(txid));
      });
      const height = await mine('6', miningAddress);
      await waitChain(height);
      await wait('active', async () => {
        let ready = true;
        const observed = await observeAll(localChannels);
        for (const [index, node] of nodes.entries()) {
          const channels = observed[index], expected = topology.channels.filter(channel => channel.from === node || channel.to === node);
          if (channels.length !== expected.length) { ready = false; continue; }
          for (const channel of expected) {
            const peer = identities[channel.from === node ? channel.to : channel.from].pubkey;
            const matching = channels.filter(value => node.startsWith('lnd-') ? value.remote_pubkey === peer : value.peer_id === peer);
            if (matching.length !== 1 || (node.startsWith('lnd-') ? matching[0].active !== true : matching[0].state !== 'CHANNELD_NORMAL' || matching[0].peer_connected !== true)) { ready = false; continue; }
            const scid = shortId(node.startsWith('lnd-') ? matching[0].scid || matching[0].chan_id : matching[0].short_channel_id);
            if (channelIds[channel.id] && channelIds[channel.id] !== scid) throw fail('channel-identity');
            channelIds[channel.id] = scid;
          }
        }
        return ready;
      });
      for (const node of nodes) await rpc(node, node.startsWith('lnd-') ? 'updatechanpolicy' : 'setchannel', node.startsWith('lnd-')
        ? ['--base_fee_msat=1000', '--fee_rate_ppm=1000', '--time_lock_delta=80'] : ['id=all', 'feebase=1000msat', 'feeppm=1000']);
      await wait('graph', async () => {
        return (await observeAll(async node => graphReady(node, record(await rpc(node, node.startsWith('lnd-') ? 'describegraph' : 'listchannels'), 'graph'), topology, identities, channelIds))).every(Boolean);
      });
      await wait('layers', async () => {
        return (await observeAll(async node => layersCleared(record(await rpc(node, 'askrene-listlayers'), 'layers')), nodes.filter(node => node.startsWith('cln-')))).every(Boolean);
      });
      await waitChain(height, true);
      let credentials;
      if (credentialPolicy) {
        // Credential provisioning is its own lifecycle phase with its own bounded deadline.
        deadline = clock() + generalTimeout;
        const credentialPermissions = createCredentialPermissions(owner);
        const certificates = Object.fromEntries(nodes.map(node => [node, identities[node].certificate.path]));
        const permissionRequest = createPermissionRequest({ owner, permissions: credentialPermissions, certificates });
        const ordinaryProcess = (argv, options) => run(argv.slice(1), options);
        const provisioned = await provisionAuthorizationFixtures({ owner, policy: credentialPolicy, identities, topology,
          permissions: credentialPermissions, permissionRequest, runProcess: ordinaryProcess, signal });
        try {
          ({ credentials } = await bakeLabCredentials({ owner, policy: credentialPolicy, authorizationFixtures: provisioned.fixtures,
            ports: { permissions: credentialPermissions, permissionRequest, runProcess: ordinaryProcess }, signal }));
        } finally { await provisioned.cleanup(); }
        await restoreProxies();
        // The setup admin macaroons are provisional and never part of a ready manifest.
        for (const node of ['lnd-p', 'lnd-r']) {
          await credentialPermissions.remove(identities[node].credential.path);
          delete identities[node].credential;
        }
        for (const path of bootstrapSentinels) await credentialPermissions.remove(path);
      }
      const resources = await observedResources();
      const manifest = { version: 1, ownerId: owner.id, project: owner.project, ports: owner.ports,
        ...(credentials ? { credentials } : {}),
        images: Object.fromEntries(Object.entries(imagePins).map(([kind, reference]) => [kind, { reference, digest: reference.split('@')[1] }])),
        nodes: identities, topology, resources: { declared: owner.resources, observed: resources, effectiveWorkers: 1 }, height: height.toString() };
      await writeFile(join(owner.runtimeRoot, 'lab.json'), JSON.stringify(manifest, null, 2), { mode: 0o600 });
      await writeFile(join(owner.evidenceRoot, 'lab.json'), JSON.stringify(manifest, null, 2), { mode: 0o600 });
      await writeFile(join(owner.evidenceRoot, `lab-${attempt}-manifest.json`), JSON.stringify(manifest, null, 2), { mode: 0o600 });
      return manifest;
    } catch (error) {
      if (acquired) { try { await cleanup(); } catch { throw fail('cleanup after setup failure'); } }
      else if (reserved) await releaseOwner(owner, context(true));
      throw error instanceof Error && /^lab (?:credentials )?[a-zA-Z0-9_ -]+: failed$/.test(error.message) ? error : fail('setup');
    } finally { if (releaseWorker) await releaseWorker(); busy = false; }
  }
  async function down() {
    if (busy) throw fail('owner-busy'); busy = true; deadline = clock() + generalTimeout;
    let releaseWorker;
    try { await assertRoots(); releaseWorker = await acquireWorker(owner); await cleanup(); }
    catch (error) { throw error instanceof Error && /^lab [a-zA-Z0-9 -]+: failed$/.test(error.message) ? error : fail('cleanup'); }
    finally { if (releaseWorker) await releaseWorker(); busy = false; }
  }
  // Read an already-owned running lab using the same native pin, resource and
  // readiness observations as bring-up. This neither starts nor reconfigures it.
  async function observe() {
    if (busy) throw fail('owner-busy'); busy = true; deadline = clock() + generalTimeout;
    try {
      await assertRoots();
      const manifest = record(parse(await readFile(join(owner.runtimeRoot, 'lab.json'), 'utf8'), 'manifest'), 'manifest');
      if (manifest.ownerId !== owner.id || manifest.project !== owner.project || JSON.stringify(manifest.ports) !== JSON.stringify(owner.ports) ||
          Object.entries(imagePins).some(([kind, reference]) => manifest.images?.[kind]?.reference !== reference)) throw fail('owner');
      identities = record(manifest.nodes, 'manifest');
      const resources = await observedResources();
      const chain = record(await rpc('bitcoind', 'getblockchaininfo'), 'bitcoin-network');
      if (chain.chain !== 'regtest') throw fail('bitcoin-network');
      const height = decimal(chain.blocks, 'height');
      await waitChain(height, true);
      const graph = record(await rpc('cln-m', 'listchannels'), 'graph');
      channelIds = Object.fromEntries(topology.channels.map(channel => [channel.id,
        rows(graph.channels, 'graph').find(edge => edge.source === identities[channel.from]?.pubkey && edge.destination === identities[channel.to]?.pubkey)?.short_channel_id]));
      if (!(await observeAll(async node => graphReady(node, record(await rpc(node, node.startsWith('lnd-') ? 'describegraph' : 'listchannels'), 'graph'), topology, identities, channelIds))).every(Boolean)) throw fail('graph');
      const local = await observeAll(localChannels);
      if (local.some((channels, index) => {
        const node = nodes[index], lnd = node.startsWith('lnd-');
        return channels.length !== topology.channels.filter(channel => channel.from === node || channel.to === node).length ||
          channels.some(channel => (lnd ? channel.active !== true : channel.state !== 'CHANNELD_NORMAL' || channel.peer_connected !== true) ||
            !Array.isArray(lnd ? channel.pending_htlcs : channel.htlcs) || (lnd ? channel.pending_htlcs : channel.htlcs).length !== 0);
      })) throw fail('active');
      if (!(await observeAll(async node => layersCleared(record(await rpc(node, 'askrene-listlayers'), 'layers')), nodes.filter(node => node.startsWith('cln-')))).every(Boolean)) throw fail('layers');
      return { ownerId: owner.id, project: owner.project, network: 'regtest', height: height.toString(), resources };
    } finally { busy = false; }
  }
  return { up, down, observe };
}

async function main(args) {
  const output = processOutput(), controller = new AbortController();
  const interrupt = () => controller.abort();
  process.on('SIGINT', interrupt); process.on('SIGTERM', interrupt);
  try {
    const [operation, flag, input, ...extra] = args;
    if (!['up', 'down'].includes(operation) || flag !== '--owner' || !input || !isAbsolute(input) || extra.length) {
      output.write('stderr', 'lab: up|down --owner <absolute owner declaration> is required\n');
      return 1;
    }
    if (process.env.NODE_OPTIONS?.trim() || /(?:^|[ ,])(?:http|https|net|tls)(?:$|[ ,])/i.test(process.env.NODE_DEBUG || '')) throw fail('environment');
    const owner = JSON.parse(await readFile(input, 'utf8'));
    const lab = createLab({ owner, signal: controller.signal });
    await lab[operation]();
    output.write('stdout', operation === 'up' ? 'lab ready\n' : 'lab cleaned\n');
    return 0;
  } catch (error) {
    output.write('stderr', error instanceof Error && /^lab (?:credentials )?[a-zA-Z0-9_ -]+: failed$/.test(error.message) ? `${error.message}\n` : 'lab setup: failed\n');
    return 1;
  } finally { process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', interrupt); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = await main(process.argv.slice(2));
