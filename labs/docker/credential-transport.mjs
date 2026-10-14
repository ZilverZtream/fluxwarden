import https from 'node:https';
import http from 'node:http';
import { join } from 'node:path';

const failure = () => new Error('lab credentials request: failed');
const lndRoutes = {
  GetInfo: ['GET', '/v1/getinfo'], AddInvoice: ['POST', '/v1/invoices'], QueryRoutes: ['POST', '/v1/graph/routes/'],
  ListChannels: ['GET', '/v1/channels'], SendToRouteV2: ['POST', '/v2/router/route/send'],
  ChangePassword: ['POST', '/v1/changepassword'], StopDaemon: ['POST', '/v1/stop'],
  LookupInvoice: ['GET', '/v1/invoice/'], LookupInvoiceV2: ['GET', '/v2/invoices/lookup'],
};
const clnMethods = new Set(['getinfo', 'listpeerchannels', 'listchannels', 'listinvoices', 'listhtlcs', 'getroutes', 'askrene-listlayers', 'waitsendpay', 'listsendpays', 'bkpr-listaccountevents', 'invoice', 'delinvoice', 'sendpay', 'pay', 'xpay', 'withdraw', 'stop', 'createrune', 'invokerune', 'listconfigs', 'blacklistrune', 'checkrune']);

// Rune comparisons such as pnameamount_msat< need an integer field (ElementsProject/lightning
// common/rune.c), so a plain decimal amount_msat is sent as an exact JSON integer.
function clnBody(value, key) {
  if (key === 'amount_msat' && typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value)) return value;
  if (Array.isArray(value)) return `[${value.map(item => clnBody(item)).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.entries(value).filter(([, item]) => item !== undefined).map(([name, item]) => `${JSON.stringify(name)}:${clnBody(item, name)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function wire(module, options, body, signal) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const request = module.request({ ...options, signal }, response => {
      const chunks = [];
      response.on('data', chunk => { size += chunk.length; if (size > 2 * 1024 * 1024) request.destroy(failure()); else chunks.push(chunk); });
      response.on('error', () => reject(failure()));
      response.on('end', () => { try { resolve({ statusCode: response.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); } catch { reject(failure()); } });
    });
    const timer = setTimeout(() => request.destroy(failure()), 30000);
    request.on('close', () => clearTimeout(timer));
    request.on('error', () => reject(failure()));
    request.end(body);
  });
}

// LND grpc-gateway route mapping; CLN clnrest POST /v1/<method> normal rune header.
// The clnrest server certificate names cln and localhost, never the container name.
// Proxy changes carry only fixed current-owner node names, never credential material.
export function createPermissionRequest({ owner, permissions, certificates }) {
  let previous = Promise.resolve();
  // Each owner file is read through the checked port once per request port; its bytes are
  // then reused, so a file replaced later is never picked up mid-provisioning.
  const files = new Map();
  const checked = async path => {
    if (!files.has(path)) files.set(path, Buffer.from(await permissions.readChecked(path)));
    return files.get(path);
  };
  return request => {
    const run = async () => {
      try {
        const { node, transport, operation, credentialPath, params, signal } = request;
        if (!['lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m'].includes(node) || transport !== (node.startsWith('lnd-') ? 'lnd-rest' : 'clnrest') || !params || typeof params !== 'object' || Array.isArray(params)) throw failure();
        const lnd = transport === 'lnd-rest';
        if (lnd ? !Object.hasOwn(lndRoutes, operation) : !clnMethods.has(operation)) throw failure();
        const proxy = lnd ? 'lnd-r-rest' : 'cln-m-rest';
        const changed = await wire(http, { hostname: '127.0.0.1', port: owner.ports.toxiproxy, method: 'POST', path: `/proxies/${proxy}`, headers: { 'content-type': 'application/json' } }, JSON.stringify({ upstream: `${node}:${lnd ? 8080 : 3010}`, enabled: true }), signal);
        if (changed.statusCode !== 200 || changed.body.upstream !== `${node}:${lnd ? 8080 : 3010}`) throw failure();
        // The certificate copied out of the container at bring-up pins the node.
        const cert = await checked(certificates?.[node] ?? join(owner.runtimeRoot, 'certificates', `${node}.pem`));
        const credential = Buffer.from(await checked(credentialPath));
        let [method, path] = lnd ? lndRoutes[operation] : ['POST', `/v1/${operation}`];
        if (operation === 'LookupInvoice') {
          if (typeof params.r_hash !== 'string' || Buffer.from(params.r_hash, 'base64').length !== 32) throw failure();
          path += Buffer.from(params.r_hash, 'base64').toString('hex');
        }
        // lnrpc/invoicesrpc/invoices.yaml maps LookupInvoiceV2 to GET with query parameters.
        if (operation === 'LookupInvoiceV2') {
          if (typeof params.payment_hash !== 'string' || Buffer.from(params.payment_hash, 'base64').length !== 32) throw failure();
          path += `?payment_hash=${encodeURIComponent(Buffer.from(params.payment_hash, 'base64').toString('base64'))}`;
        }
        if (operation === 'QueryRoutes') {
          if (typeof params.pub_key !== 'string' || !/^(02|03)[0-9a-f]{64}$/.test(params.pub_key) || typeof params.amt_msat !== 'string' || !/^[1-9][0-9]*$/.test(params.amt_msat)) throw failure();
          path += `${params.pub_key}/0`;
        }
        const body = method === 'GET' ? undefined : lnd ? JSON.stringify(params) : clnBody(params);
        if (body && Buffer.byteLength(body) > 2 * 1024 * 1024) throw failure();
        return await wire(https, { hostname: '127.0.0.1', port: lnd ? owner.ports.lndRest : owner.ports.clnRest, servername: lnd ? node : 'localhost', ca: cert, rejectUnauthorized: true, method, path, headers: { 'content-type': 'application/json', [lnd ? 'Grpc-Metadata-macaroon' : 'rune']: lnd ? credential.toString('hex') : credential.toString('utf8') } }, body, signal);
      } catch { throw failure(); }
    };
    const result = previous.then(run, run); previous = result.then(() => undefined, () => undefined); return result;
  };
}
