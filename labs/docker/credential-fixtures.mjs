import { randomBytes, createHash } from 'node:crypto';
import { join } from 'node:path';
import { composeArguments, composeEnvironment } from './compose.mjs';

const fail = () => new Error('lab credentials provisioning: failed');

// Normal owner setup uses AddInvoice/QueryRoutes (ARCHITECTURE 4.3) and
// ElementsProject/lightning doc/schemas/{invoice,sendpay}.json. No secret CLI args.
export async function provisionAuthorizationFixtures({ owner, policy, identities, topology, permissions, permissionRequest, runProcess, signal }) {
  const provisional = [], bootstrap = [];
  const retain = async (node, kind, bytes) => {
    const path = join(owner.sentinelRoot, `${node}-${kind}-${randomBytes(8).toString('hex')}.bin`);
    await permissions.writeExclusive(path, bytes);
    return path;
  };
  const rpc = async (node, credentialPath, operation, params) => {
    const answer = await permissionRequest({ node, credentialPath, operation, params, transport: node.startsWith('lnd-') ? 'lnd-rest' : 'clnrest', signal });
    if ((answer.statusCode !== 200 && answer.statusCode !== 201) || !answer.body || typeof answer.body !== 'object' || 'error' in answer.body || 'code' in answer.body) throw fail();
    return answer.body;
  };
  const cleanup = async () => {
    let failed = false;
    for (const item of bootstrap) {
      try { await rpc(item.node, item.path, 'blacklistrune', { start: item.id, end: item.id }); } catch { failed = true; }
    }
    for (const path of provisional.reverse()) { try { await permissions.remove(path); } catch { failed = true; } }
    if (failed) throw fail();
  };
  try {
    const fixtures = {};
    await permissions.ensureDirectory(join(owner.runtimeRoot, 'provisioning'));
    for (const node of ['cln-p', 'cln-r', 'cln-m']) {
      const answer = await runProcess(['docker', ...composeArguments(owner, join(owner.runtimeRoot, 'compose-owner.json'), ['exec', '-T', node, 'lightning-cli', '--network=regtest', '-k', 'createrune'])], { cwd: owner.runtimeRoot, env: composeEnvironment(owner), timeoutMs: 30000, signal });
      if (answer.exitCode !== 0 || Buffer.byteLength(answer.stdout) > 262144) throw fail();
      const minted = JSON.parse(answer.stdout);
      if (typeof minted.rune !== 'string' || !/^[A-Za-z0-9_+/-]+={0,2}$/.test(minted.rune) || typeof minted.unique_id !== 'string' || !/^(0|[1-9][0-9]*)$/.test(minted.unique_id)) throw fail();
      const bytes = Buffer.from(minted.rune), path = join(owner.runtimeRoot, 'provisioning', `${node}.rune`);
      await permissions.writeExclusive(path, bytes); provisional.push(path);
      provisional.push(await retain(node, 'bootstrap', bytes));
      bootstrap.push({ node, path, id: minted.unique_id });
      const ownInvoice = async () => {
        const preimage = randomBytes(32); await retain(node, 'preimage', preimage);
        const label = `cp008-${randomBytes(12).toString('hex')}`;
        const invoice = await rpc(node, path, 'invoice', { amount_msat: `${policy.maxPrincipalMsat}msat`, label, description: 'disposable credential control', preimage: preimage.toString('hex') });
        if (invoice.payment_hash !== createHash('sha256').update(preimage).digest('hex') || typeof invoice.payment_secret !== 'string' || !/^[a-f0-9]{64}$/.test(invoice.payment_secret) || typeof invoice.bolt11 !== 'string' || !invoice.bolt11.startsWith('lnbcrt')) throw fail();
        await retain(node, 'payment-secret', Buffer.from(invoice.payment_secret, 'hex'));
        // Rune comparisons need an integer field: the bounded sendpay amount is a plain decimal.
        return { invoice, sendpay: { route: [], payment_hash: invoice.payment_hash, amount_msat: policy.maxPrincipalMsat, payment_secret: invoice.payment_secret } };
      };
      // Pinned sendpay supports an empty route to self. A paid invoice prepares the waitsendpay
      // control; a sendpay to an already paid invoice fails ("Already paid or expired invoice",
      // code 203), so the sendpay control pays a second, unpaid invoice.
      const { invoice, sendpay: settled } = await ownInvoice();
      await rpc(node, path, 'sendpay', settled);
      const { sendpay } = await ownInvoice();
      const nextLabel = `cp008-${randomBytes(12).toString('hex')}`;
      const nextPreimage = randomBytes(32); await retain(node, 'preimage', nextPreimage);
      const channel = topology.channels.find(channel => channel.from === node || channel.to === node);
      const channelPeer = identities[channel?.from === node ? channel.to : channel?.from]?.pubkey;
      if (!channelPeer) throw fail();
      fixtures[node] = {
        getinfo: {}, listpeerchannels: {}, listchannels: {}, listinvoices: {}, listsendpays: {}, listhtlcs: { index: 'created', limit: 500 }, 'bkpr-listaccountevents': {}, 'askrene-listlayers': {},
        getroutes: { source: identities[node].pubkey, destination: channelPeer, amount_msat: `${policy.maxPrincipalMsat}msat`, layers: ['auto.localchans', 'auto.sourcefree'], maxfee_msat: '0msat', final_cltv: 80, maxdelay: 2016, maxparts: 1 },
        sendpay, waitsendpay: { payment_hash: invoice.payment_hash, timeout: 1 },
        invoice: { amount_msat: `${policy.maxPrincipalMsat}msat`, label: nextLabel, description: 'disposable credential control', preimage: nextPreimage.toString('hex') }, delinvoice: { label: nextLabel, status: 'unpaid' },
        pay: { bolt11: invoice.bolt11 }, xpay: { invstring: invoice.bolt11 }, withdraw: { destination: identities[node].fundingAddress, satoshi: '1' },
        stop: {}, createrune: { restrictions: [] }, invokerune: { restrictions: [] }, listconfigs: {}, blacklistrune: { start: minted.unique_id, end: minted.unique_id },
      };
    }
    for (const [node, recipient] of [['lnd-p', 'lnd-r'], ['lnd-r', 'lnd-p']]) {
      const path = identities[node].credential.path, recipientPath = identities[recipient].credential.path;
      const preimage = randomBytes(32); await retain(node, 'preimage', preimage);
      const invoice = await rpc(recipient, recipientPath, 'AddInvoice', { value_msat: policy.maxPrincipalMsat, r_preimage: preimage.toString('base64'), memo: 'disposable credential control' });
      if (typeof invoice.r_hash !== 'string' || typeof invoice.payment_addr !== 'string') throw fail();
      await retain(node, 'payment-secret', Buffer.from(invoice.payment_addr, 'base64'));
      const routes = await rpc(node, path, 'QueryRoutes', { pub_key: identities[recipient].pubkey, amt_msat: policy.maxPrincipalMsat, fee_limit: { fixed_msat: '0' }, cltv_limit: 2016, use_mission_control: false });
      if (!Array.isArray(routes.routes) || routes.routes.length !== 1 || !Array.isArray(routes.routes[0].hops) || routes.routes[0].hops.length !== 1 || routes.routes[0].hops[0].pub_key !== identities[recipient].pubkey || routes.routes[0].hops[0].amt_to_forward_msat !== policy.maxPrincipalMsat || routes.routes[0].total_fees_msat !== '0') throw fail();
      const route = routes.routes[0]; route.hops[0].mpp_record = { payment_addr: invoice.payment_addr, total_amt_msat: policy.maxPrincipalMsat };
      const localPreimage = randomBytes(32); await retain(node, 'preimage', localPreimage);
      const local = await rpc(node, path, 'AddInvoice', { value_msat: policy.maxPrincipalMsat, r_preimage: localPreimage.toString('base64') });
      const password = randomBytes(32); await retain(node, 'password-control', password);
      const newPassword = randomBytes(32); await retain(node, 'password-control', newPassword);
      fixtures[node] = { ListChannels: {}, SendToRouteV2: { payment_hash: invoice.r_hash, route }, LookupInvoice: { r_hash: local.r_hash }, LookupInvoiceV2: { payment_hash: local.r_hash }, ChangePassword: { current_password: password.toString('base64'), new_password: newPassword.toString('base64') }, StopDaemon: {} };
    }
    return { fixtures, cleanup };
  } catch { try { await cleanup(); } catch { /* owner lifecycle destroys its volumes */ } throw fail(); }
}
