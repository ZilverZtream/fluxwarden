import { readFileSync, existsSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createLab, imagePins } from '../lab.mjs';
import { validateOwner, acquireWorker } from '../owner.mjs';
import { createToxiproxyClient } from '../toxiproxy.mjs';
import { identity } from '../readiness.mjs';
import { assertPrivateDirectories } from '../../../scripts/private-scratch.mjs';
import { openClnRest } from '../../../dist/node-cln/rest.js';
import { openLndRest } from '../../../dist/node-lnd/rest.js';
import { ClnReadApi } from '../../../dist/node-cln/api.js';
import { ClnExecutionAdapter } from '../../../dist/node-cln/execute.js';
import { chanIdToScid } from '../../../dist/core/scid.js';
import { minFinalCltvExpiry } from '../../../dist/core/bolt11-cltv.js';
import { ClnError, LndError } from '../../../dist/core/errors.js';
import { configStage, databaseStage } from '../../../dist/commands/stages.js';
import { workflow, controller as ordinaryController } from '../../../dist/commands/workflow.js';
import { writeOwnerOnlyFile } from '../../../dist/output/private-file.js';
import { checkReadablePath } from '../../../dist/persistence/paths.js';

const failure = () => new Error('disposable lab operation failed');
const nodes = ['lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m'];
function readJson(path) {
  const bytes = readFileSync(path);
  if (bytes.length > 1024 * 1024) throw failure();
  return JSON.parse(bytes.toString('utf8'));
}
function amount(value) {
  const text = typeof value === 'string' ? value.replace(/msat$/, '') : '';
  if (!/^(0|[1-9][0-9]*)$/.test(text)) throw failure();
  return BigInt(text);
}

// Read the ordinary owner artifacts without contacting a node or changing a run.
// The caller supplies only hashes recovered by this exact recorded reconciliation.
export async function readDemoEvidence({ planPath, configPath, recordedNodes, recovered }) {
  if (!isAbsolute(planPath)) throw failure();
  const declaration = readJson(checkReadablePath(planPath)), owner = validateOwner(declaration.owner ?? declaration);
  await assertPrivateDirectories([owner.runtimeRoot, owner.tmpRoot, owner.sentinelRoot, owner.evidenceRoot]);
  const manifest = readJson(checkReadablePath(join(owner.runtimeRoot, 'lab.json'))), config = configStage(configPath);
  if (manifest.ownerId !== owner.id || manifest.project !== owner.project || JSON.stringify(manifest.ports) !== JSON.stringify(owner.ports)) throw failure();
  if (nodes.some(node => manifest.nodes?.[node]?.network !== 'regtest' || !/^(02|03)[a-f0-9]{64}$/.test(manifest.nodes[node].pubkey))) throw failure();
  const images = {};
  for (const [kind, reference] of Object.entries(imagePins)) {
    const digest = reference.split('@')[1];
    if (manifest.images?.[kind]?.reference !== reference || manifest.images[kind].digest !== digest) throw failure();
    images[kind] = digest;
  }
  for (const recorded of recordedNodes) {
    const node = config.nodes.find(node => node.name === recorded.name), entry = manifest.nodes[recorded.name];
    const credential = manifest.credentials?.[recorded.name]?.execute;
    if (!node || !entry || node.expectedPubkey !== entry.pubkey || recorded.pubkey !== entry.pubkey || node.expectedNetwork !== 'regtest' ||
        node.implementation !== entry.kind || recorded.version !== entry.version || node.endpoint.host !== 'localhost' ||
        node.endpoint.port !== owner.ports[node.implementation === 'lnd' ? 'lndRest' : 'clnRest'] ||
        resolve(node.tlsCertPath) !== resolve(entry.certificate.path) || resolve(node.credentialPath) !== resolve(credential.path) ||
        recorded.tlsFingerprint !== entry.certificate.sha256 || credential.fingerprint !== `fp:${recorded.credentialFingerprint.slice(0, 16)}`) throw failure();
  }
  const scenarios = [];
  for (const recoveredExecution of recovered) {
    if (!recordedNodes.some(node => node.pubkey === recoveredExecution.nodePubkey) || !/^[a-f0-9]{64}$/.test(recoveredExecution.hash)) throw failure();
    if (recoveredExecution.nodePubkey !== manifest.nodes['cln-m'].pubkey) continue;
    const path = join(owner.evidenceRoot, `demo-T-05-${recoveredExecution.hash}.json`);
    if (!existsSync(path)) continue;
    const actual = readJson(checkReadablePath(path));
    if (actual.caseId !== 'T-05' || actual.injection !== 'waitsendpay downstream truncation' || actual.exit !== 7 || actual.status !== 'UNKNOWN' ||
        actual.paymentHash !== recoveredExecution.hash || actual.sendCount !== 1) throw failure();
    scenarios.push({ caseId: actual.caseId, injection: actual.injection, exit: actual.exit, status: actual.status, paymentHash: actual.paymentHash,
      sendCount: actual.sendCount, executionId: recoveredExecution.id, recoveredStatus: recoveredExecution.status,
      pass: recoveredExecution.status === 'VERIFIED_SUCCESS',
      assertions: [`observed UNKNOWN with exit ${actual.exit}`, `observed exactly one native payment record for ${actual.paymentHash}`,
        `same-hash reconciliation reached ${recoveredExecution.status}`] });
  }
  return { images, scenarios };
}

export async function createRuntimeLab({ planPath, configPath, signal }) {
  if (!isAbsolute(planPath)) throw failure();
  const declaration = readJson(planPath);
  const owner = validateOwner(declaration.owner ?? declaration);
  await assertPrivateDirectories([owner.runtimeRoot, owner.tmpRoot, owner.sentinelRoot, owner.evidenceRoot]);
  const control = createToxiproxyClient({ url: `http://127.0.0.1:${owner.ports.toxiproxy}`, signal });
  const cleanupControl = createToxiproxyClient({ url: `http://127.0.0.1:${owner.ports.toxiproxy}` });
  let manifest, release, armed = false, injected = false;
  const loadManifest = async () => {
    release ??= await acquireWorker(owner);
    const observed = readJson(join(owner.runtimeRoot, 'lab.json'));
    if (observed.ownerId !== owner.id || observed.project !== owner.project || JSON.stringify(observed.ports) !== JSON.stringify(owner.ports)) throw failure();
    manifest = observed;
  };
  const restore = async () => {
    await cleanupControl.enable('lnd-r-rest', true);
    await cleanupControl.enable('cln-m-rest', true);
    // Re-aim only these two proxies belonging to the declared project.
    await update('lnd-r-rest', 'lnd-r:8080');
    await update('cln-m-rest', 'cln-m:3010');
  };
  async function update(name, upstream) {
    // Control has no Lightning credential. This endpoint is the owner's loopback-only Toxiproxy port.
    const response = await fetch(`http://127.0.0.1:${owner.ports.toxiproxy}/proxies/${name}`, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ upstream, enabled: true }) });
    if (!response.ok) throw failure();
    const observed = await response.json();
    if (observed.name !== name || observed.upstream !== upstream || observed.enabled !== true) throw failure();
  }
  const rpc = async (node, operation) => {
    if (signal.aborted) throw failure();
    const entry = manifest.nodes[node], credential = manifest.credentials?.[node]?.execute;
    if (!entry || entry.network !== 'regtest' || !credential?.path || !entry.certificate?.path) throw failure();
    const lnd = node.startsWith('lnd-'), proxy = lnd ? 'lnd-r-rest' : 'cln-m-rest';
    await update(proxy, `${node}:${lnd ? '8080' : '3010'}`);
    const connection = { host: 'localhost', port: owner.ports[lnd ? 'lndRest' : 'clnRest'], tlsCertPath: entry.certificate.path, timeoutMs: 10000 };
    const rest = lnd ? await openLndRest({ ...connection, macaroonPath: credential.path }) : await openClnRest({ ...connection, runePath: credential.path });
    try {
      const info = lnd ? await rest.call('GET', '/v1/getinfo') : await rest.call('getinfo');
      if ((lnd ? info.chains?.[0]?.network : info.network) !== 'regtest') throw Object.assign(failure(), { networkLock: true });
      identity(node, info, entry);
      return await operation(rest, info);
    } finally { await restore(); }
  };
  const merchantChannels = () => rpc('cln-m', rest => new ClnReadApi(rest).listPeerChannels());
  const routeChannels = async () => {
    const result = await merchantChannels();
    const channel2 = result.find(channel => channel.peerId === manifest.nodes['lnd-r'].pubkey);
    const channel5 = result.find(channel => channel.peerId === manifest.nodes['cln-r'].pubkey);
    if (!channel2?.shortChannelId || !channel5?.shortChannelId) throw failure();
    return { channel2, channel5 };
  };
  const lab = {
    async status() {
      if (!existsSync(join(owner.runtimeRoot, 'lab.json'))) return { up: false, network: 'regtest' };
      await loadManifest();
      if (nodes.some(node => manifest.nodes?.[node]?.network !== 'regtest')) return { up: true, network: 'unknown' };
      const proxies = await control.list();
      for (const name of ['lnd-r-rest', 'cln-m-rest']) if (!proxies[name]?.enabled || proxies[name].toxics?.length) throw failure();
      try { for (const node of nodes) await rpc(node, () => undefined); }
      catch (error) { if (error?.networkLock) return { up: true, network: 'unknown' }; throw error; }
      return { up: true, network: 'regtest' };
    },
    async channel2ReceivableMsat() { const value = (await routeChannels()).channel2.receivableMsat; if (value === null) throw failure(); return value; },
    async checkout(request) {
      if (request.merchant !== 'cln-m' || !['lnd-p', 'cln-p'].includes(request.payer) || typeof request.amountMsat !== 'bigint' || request.amountMsat < 1n || request.amountMsat > 100000000n || (request.payer === 'cln-p' && request.amountMsat !== 10000000n) || JSON.stringify(request.channels) !== JSON.stringify(request.payer === 'lnd-p' ? [1, 2] : [4, 5])) throw failure();
      const { channel2, channel5 } = await routeChannels();
      const label = `checkout-${randomUUID()}`;
      const invoice = await rpc('cln-m', rest => rest.call('invoice', { amount_msat: request.amountMsat.toString(), label, description: 'disposable regtest checkout', expiry: 300, cltv: 18 }));
      if (!/^[a-f0-9]{64}$/.test(invoice.payment_hash) || !/^[a-f0-9]{64}$/.test(invoice.payment_secret) || !invoice.bolt11?.startsWith('lnbcrt')) throw failure();
      const finalDelta = minFinalCltvExpiry(invoice.bolt11);
      if (finalDelta === undefined || finalDelta > 144) throw failure();
      let reason = 'PAYMENT_FAILED';
      try {
        if (request.payer === 'lnd-p') {
          await rpc('lnd-p', async rest => {
            const local = await rest.call('GET', '/v1/channels');
            const channel1 = local.channels?.find(channel => channel.remote_pubkey === manifest.nodes['lnd-r'].pubkey);
            if (!channel1) throw failure();
            const answer = await rest.call('POST', `/v1/graph/routes/${manifest.nodes['cln-m'].pubkey}/0`, {
              amt_msat: request.amountMsat.toString(), final_cltv_delta: finalDelta, fee_limit: { fixed_msat: '300000' }, cltv_limit: 141,
              outgoing_chan_ids: [channel1.chan_id], last_hop_pubkey: Buffer.from(manifest.nodes['lnd-r'].pubkey, 'hex').toString('base64'), use_mission_control: false });
            const route = answer.routes?.[0];
            if (answer.routes?.length !== 1 || route.hops?.length !== 2 || route.hops[0].chan_id !== channel1.chan_id || chanIdToScid(route.hops[1].chan_id) !== channel2.shortChannelId || amount(route.total_fees_msat) > 300000n || amount(route.hops[1].amt_to_forward_msat) !== request.amountMsat) throw failure();
            route.hops[1].mpp_record = { payment_addr: Buffer.from(invoice.payment_secret, 'hex').toString('base64'), total_amt_msat: request.amountMsat.toString() };
            await rest.call('POST', '/v2/router/route/send', { payment_hash: Buffer.from(invoice.payment_hash, 'hex').toString('base64'), route });
          });
        } else {
          await rpc('cln-p', async rest => {
            const channels = await new ClnReadApi(rest).listPeerChannels();
            const channel4 = channels.find(channel => channel.peerId === manifest.nodes['cln-r'].pubkey);
            if (!channel4?.shortChannelId) throw failure();
            const forwarding = await rest.call('listchannels', { short_channel_id: channel5.shortChannelId });
            const policy = forwarding.channels?.find(channel => channel.source === manifest.nodes['cln-r'].pubkey && channel.destination === manifest.nodes['cln-m'].pubkey);
            if (!policy || !Number.isSafeInteger(policy.delay) || policy.delay + finalDelta + 1 > 144) throw failure();
            const fee = BigInt(policy.base_fee_millisatoshi) + request.amountMsat * BigInt(policy.fee_per_millionth) / 1000000n;
            if (fee > 300000n) throw failure();
            const vertices = [manifest.nodes['cln-p'].pubkey, manifest.nodes['cln-r'].pubkey, manifest.nodes['cln-m'].pubkey];
            const route = [channel4.shortChannelId, channel5.shortChannelId].map((scid, index) => ({ short_channel_id_dir: `${scid}/${vertices[index] < vertices[index + 1] ? 0 : 1}`, node_id_out: vertices[index + 1],
              amount_out_msat: (index === 0 ? request.amountMsat + fee : request.amountMsat).toString(), cltv_out: index === 0 ? finalDelta + policy.delay : finalDelta }));
            await rest.call('sendpay', { route, payment_hash: invoice.payment_hash, payment_secret: invoice.payment_secret, amount_msat: Number(request.amountMsat) });
            await rest.call('waitsendpay', { payment_hash: invoice.payment_hash, timeout: 10 });
          });
        }
      } catch (error) {
        // A transport loss is an unavailable observation, never a confirmed payment rejection.
        if (!(error instanceof LndError) && !(error instanceof ClnError && [202, 203, 204, 209].includes(error.code))) throw failure();
        reason = (request.payer === 'lnd-p' ? channel2 : channel5).receivableMsat < request.amountMsat ? 'INSUFFICIENT_INBOUND' : 'PAYMENT_REJECTED';
      }
      const observed = await rpc('cln-m', rest => new ClnReadApi(rest).listInvoices({ paymentHash: invoice.payment_hash }));
      if (observed.length !== 1) throw failure();
      const completed = observed[0].status === 'paid';
      if (!completed) await rpc('cln-m', rest => rest.call('delinvoice', { label, status: 'unpaid' }));
      return { status: completed ? 'SUCCEEDED' : 'FAILED', reason: completed ? null : reason };
    },
    async scenario(caseId) {
      if (!armed || caseId !== 'T-05') throw failure();
      await loadManifest();
      if (manifest.nodes?.['cln-m']?.network !== 'regtest') throw failure();
      const config = configStage(configPath), db = databaseStage(config.database, 'existing');
      let proposal;
      try {
        const candidates = db.executions.claim(scope => {
          const now = scope.now();
          return db.commandData.proposalIds().map(id => db.proposals.find(id)).filter(row => row?.nodeName === 'cln-m' && row.status === 'APPROVED' && row.expiresAt > now && scope.existing(row.id) === null);
        });
        if (candidates.length !== 1) throw failure();
        proposal = candidates[0];
      } finally { db.close(); }
      let sendCount = 0;
      const factory = async (node, settings, session) => {
        if (node.name !== 'cln-m' || settings.attemptDeadlineMs > 120000) throw failure();
        const normal = await ordinaryController(node, settings, session);
        const connection = session.connection;
        const rest = await openClnRest({ ...connection.endpoint, tlsCertPath: connection.tlsCertPath, runePath: connection.credentialPath, timeoutMs: 10000 });
        const transport = { call: async (method, params, options) => {
          if (method === 'sendpay') sendCount++;
          if (method === 'waitsendpay') {
            injected = true;
            await control.add('cln-m-rest', { name: 'demo-T-05', type: 'limit_data', stream: 'downstream', toxicity: 1, attributes: { bytes: 1 } });
          }
          return rest.call(method, params, options);
        } };
        const execution = new ClnExecutionAdapter(transport, { ownId: node.expectedPubkey, waitChunkSeconds: 10, attemptDeadlineMs: settings.attemptDeadlineMs });
        return { ...normal, adapter: { ...normal.adapter, sendOnRoute: (...args) => execution.sendOnRoute(...args) } };
      };
      const silent = { json: true, output: { write: () => undefined, wrote: () => false } };
      const exit = await workflow({ kind: 'actions execute', json: true, config: configPath, connection: {}, proposalId: `prop_${proposal.id}`, requireRegtest: true }, silent, {}, signal, { controller: factory });
      const fresh = databaseStage(config.database, 'existing');
      let execution;
      try { execution = fresh.executions.claim(scope => scope.existing(proposal.id)); }
      finally { fresh.close(); }
      const observed = databaseStage(config.database, 'read');
      try {
        const view = execution === null ? null : observed.executions.view(execution.executionId);
        if (!view || !injected || sendCount !== 1 || view.status !== 'UNKNOWN' || exit !== 7 || !view.paymentHash) throw failure();
        // Remove the owned fault before independently reading the payer's by-hash records.
        await cleanupControl.remove('cln-m-rest', 'demo-T-05');
        injected = false;
        const payments = await rpc('cln-m', rest => new ClnReadApi(rest).listSendPays({ paymentHash: view.paymentHash }));
        if (payments.length !== 1) throw failure();
        const result = { exit, status: view.status, paymentHash: view.paymentHash, sendCount: payments.length };
        if (writeOwnerOnlyFile(join(owner.evidenceRoot, `demo-T-05-${view.paymentHash}.json`), Buffer.from(JSON.stringify({ caseId, injection: 'waitsendpay downstream truncation', ...result }))) !== 'written') throw failure();
        return result;
      } finally { observed.close(); }
    },
  };
  return {
    lab,
    preparation: {
      async identity() {
        const status = await lab.status();
        const merchant = configStage(configPath).nodes.find(node => node.name === 'cln-m');
        if (!status.up || merchant?.expectedPubkey !== manifest.nodes['cln-m'].pubkey || merchant.implementation !== 'cln') throw failure();
        return { network: status.network };
      },
      async channels() {
        const { channel2, channel5 } = await routeChannels();
        if (channel2.receivableMsat === null || channel5.receivableMsat === null) throw failure();
        return { channel2ReceivableMsat: channel2.receivableMsat, channel5ReceivableMsat: channel5.receivableMsat };
      },
      checkout: request => lab.checkout(request),
      async channelKeys() { const { channel2, channel5 } = await routeChannels(); return { channel2: channel2.shortChannelId, channel5: channel5.shortChannelId }; },
      record(name, document) {
        if (!/^demo-preparation-(starvation|chaos)-[0-9a-f-]+\.json$/.test(name) || writeOwnerOnlyFile(join(owner.evidenceRoot, name), Buffer.from(JSON.stringify(document))) !== 'written') throw failure();
      },
    },
    faults: { async apply(caseId) { if (caseId !== 'T-05' || armed) throw failure(); armed = true; }, async clear() { try { if (injected) await cleanupControl.remove('cln-m-rest', 'demo-T-05'); } finally { armed = false; injected = false; } } },
    async up(seed) {
      const current = await lab.status();
      if (current.up) {
        if (current.network !== 'regtest') throw failure();
        const observed = await createLab({ owner, signal }).observe();
        return { ...observed, seed, reused: true };
      }
      const result = await createLab({ owner, signal }).up();
      return { ownerId: result.ownerId, project: result.project, network: 'regtest', seed };
    },
    async down() { await createLab({ owner, signal }).down(); return { project: owner.project, removed: true }; },
    async close() { try { if (release) await restore(); } finally { if (release) await release(); } },
  };
}
