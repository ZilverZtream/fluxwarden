// Records real REST answers of one running regtest lab (LND-R through lnd-r-rest, CLN-M through
// cln-m-rest) into labs/fixtures/recordings/<impl>/<version>/ with a manifest. Preimages and
// credentials never reach a recording: they are replaced by fingerprints before anything is written.
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { mkdir, readFile, rm, rmdir, writeFile } from 'node:fs/promises';
import { request as httpsRequest } from 'node:https';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const profiles = { lnd: '0.21.4-beta', cln: 'v26.06.9' };
const recordedNode = { lnd: 'lnd-r', cln: 'cln-m' };
const deadlineMs = 150_000;

class Failure extends Error {}
const failure = stage => new Failure(stage);
const fp = bytes => createHash('sha256').update(bytes).digest('hex').slice(0, 16);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

// Every encoding of one secret that could appear in an answer, longest first so a padded form is
// replaced before the unpadded form it contains.
function forms(secret) {
  const bytes = Buffer.from(secret), base64 = bytes.toString('base64'), url = bytes.toString('base64url');
  const utf8 = bytes.toString('utf8');
  let bits = 0, accumulator = 0, base32 = '';
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte; bits += 8;
    while (bits >= 5) { bits -= 5; base32 += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[(accumulator >>> bits) & 31]; }
  }
  if (bits) base32 += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[(accumulator << (5 - bits)) & 31];
  const padded32 = `${base32}${'='.repeat((8 - base32.length % 8) % 8)}`;
  const utf16 = Buffer.from(bytes.toString('latin1'), 'utf16le');
  const values = [
    Buffer.from(utf8, 'utf8').equals(bytes) ? utf8 : '', bytes.toString('latin1'),
    bytes.toString('hex'), bytes.toString('hex').toUpperCase(),
    base64, base64.replace(/=+$/, ''), url, `${url}${'='.repeat((4 - url.length % 4) % 4)}`,
    base64.replace(/=+$/, '').toLowerCase(), url.toLowerCase(),
    base32, padded32, base32.toLowerCase(), padded32.toLowerCase(),
    utf16.toString('latin1'), Buffer.from(utf16).swap16().toString('latin1'),
    [...bytes].map(byte => `%${byte.toString(16).padStart(2, '0')}`).join(''),
    [...bytes].map(byte => `%${byte.toString(16).padStart(2, '0').toUpperCase()}`).join(''),
  ];
  return [...new Set(values.filter(value => value.length >= 8))].sort((a, b) => b.length - a.length);
}

function scrubSegments(segments, patterns) {
  for (const { pattern, marker } of patterns) {
    const combined = segments.join('');
    const matches = [...combined.matchAll(pattern)];
    let offset = 0;
    segments = segments.map(value => {
      const start = offset, end = start + value.length;
      offset = end;
      for (const match of matches.toReversed()) {
        const from = match.index, to = from + match[0].length;
        if (from >= end || to <= start) continue;
        value = value.slice(0, Math.max(0, from - start)) + (from >= start ? marker : '') + value.slice(Math.min(end, to) - start);
      }
      return value;
    });
  }
  return segments;
}

function preimageBytes(value) {
  if (/^[0-9a-fA-F]{64}$/.test(value)) return Buffer.from(value, 'hex');
  if (/^[A-Za-z0-9+/]{43}=$/.test(value)) return Buffer.from(value, 'base64');
  if (/^[A-Za-z0-9_-]{43}=?$/.test(value)) return Buffer.from(value, 'base64url');
  return undefined;
}

/** Fingerprints preimage members, then removes every registered secret in every encoding. */
export function redactText(text, secrets) {
  const token = '"(?:[^"\\\\]|\\\\.)*"';
  const patterns = secrets.flatMap(secret => forms(secret).map(form => ({
    pattern: new RegExp([...form].map(char => char.replace(/[|\\{}()[\]^$+*?.]/g, '\\$&')).join('[\\s\\u200b-\\u200d\\u2060\\ufeff]*'), 'g'),
    marker: `[redacted fp:${fp(secret)}]`,
  })));
  let redacted = text.replace(new RegExp(`(${token})(\\s*:\\s*)(${token})`, 'g'), (whole, key, separator, literal) => {
    const name = JSON.parse(key), value = JSON.parse(literal);
    if (!['payment_preimage', 'r_preimage', 'preimage'].includes(name)) return whole;
    const bytes = preimageBytes(value);
    if (!bytes || bytes.length !== 32 || bytes.every(byte => byte === 0)) return whole;
    return `${key}${separator}"fp:${fp(bytes)}"`;
  });
  const scrub = value => scrubSegments([value], patterns)[0];
  // Adjacent string fragments retain their boundaries, while their joined value is scrubbed.
  redacted = redacted.replace(new RegExp(`${token}(?:\\s*[,+]\\s*${token})+`, 'g'), run => {
    const literals = [...run.matchAll(new RegExp(token, 'g'))].map(match => match[0]);
    const values = literals.map(literal => JSON.parse(literal));
    const clean = scrubSegments(values, patterns);
    let index = 0;
    return run.replace(new RegExp(token, 'g'), literal => {
      const at = index++;
      return clean[at] === values[at] ? literal : JSON.stringify(clean[at]);
    });
  });
  // Decode string tokens only: parsing the entire document would round uint64 numbers.
  redacted = redacted.replace(new RegExp(token, 'g'), literal => {
    const value = JSON.parse(literal), clean = scrub(value);
    return clean === value ? literal : JSON.stringify(clean);
  });
  return scrub(redacted);
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index], value = argv[index + 1];
    if (!['--owner', '--out'].includes(flag) || typeof value !== 'string' || !isAbsolute(value) || Object.hasOwn(options, flag.slice(2))) return undefined;
    options[flag.slice(2)] = resolve(value);
  }
  return options.owner ? { owner: options.owner, out: options.out ?? join(repoRoot, 'labs', 'fixtures') } : undefined;
}

function json(text, stage) {
  try { return JSON.parse(text); } catch { throw failure(stage); }
}

// HTTPS through the owner's proxies, pinning the certificate copied out of each container.
function defaultTransport(lab, credential) {
  const proxy = async (method, body) => {
    const response = await fetch(`http://127.0.0.1:${lab.ports.toxiproxy}/proxies/lnd-r-rest`, { method, redirect: 'error', signal: AbortSignal.timeout(30_000),
      ...(body === undefined ? {} : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }) });
    if (!response.ok) throw failure('proxy');
    return response.json();
  };
  const setProxy = async state => {
    const answer = await proxy('POST', state);
    if (answer.upstream !== state.upstream || answer.enabled !== state.enabled) throw failure('proxy target');
  };
  return async ({ node, method, path, body, stream, onData, timeoutMs = 60_000 }) => {
    const lnd = node.startsWith('lnd-');
    const certificate = readFileSync(lab.nodes[node].certificate.path);
    const secret = await credential(node, path);
    let previous;
    if (node === 'lnd-p') {
      previous = await proxy('GET');
      if (typeof previous.upstream !== 'string' || typeof previous.enabled !== 'boolean') throw failure('proxy state');
    }
    try {
      if (previous) {
        await setProxy({ upstream: 'lnd-p:8080', enabled: true });
      }
      return await new Promise((resolvePromise, reject) => {
    let text = '', status = 0, settled = false;
    const finish = () => { if (!settled) { settled = true; clearTimeout(timer); resolvePromise({ status, body: text }); outgoing.destroy(); } };
    const timer = setTimeout(() => { settled = true; outgoing.destroy(); reject(failure('transport timeout')); }, timeoutMs);
    const outgoing = httpsRequest({ host: '127.0.0.1', port: lnd ? lab.ports.lndRest : lab.ports.clnRest, servername: lnd ? node : 'localhost',
      ca: certificate, rejectUnauthorized: true, method, path, agent: false,
      headers: { ...(lnd ? { 'Grpc-Metadata-macaroon': secret.toString('hex') } : { rune: secret.toString('utf8') }), ...(body === undefined ? {} : { 'content-type': 'application/json' }) } },
    response => {
      status = response.statusCode ?? 0;
      response.on('data', chunk => { text += chunk.toString('utf8'); if (stream && onData?.(text) === true) finish(); });
      response.on('end', finish);
      response.on('error', () => { if (!settled) { settled = true; clearTimeout(timer); reject(failure('transport')); } });
    });
    outgoing.on('error', () => { if (!settled) { settled = true; clearTimeout(timer); reject(failure('transport')); } });
    outgoing.end(body === undefined ? undefined : JSON.stringify(body));
      });
    } finally {
      if (previous) {
        await setProxy({ upstream: previous.upstream, enabled: previous.enabled });
      }
    }
  };
}

function defaultExec(project) {
  const ids = new Map();
  const run = argv => new Promise(resolvePromise => {
    const child = spawn('docker', argv, { shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 120_000);
    child.stdout.on('data', chunk => { stdout += chunk.toString('utf8'); });
    child.stderr.on('data', chunk => { stderr += chunk.toString('utf8'); });
    child.on('error', () => { clearTimeout(timer); resolvePromise({ exitCode: -1, stdout, stderr }); });
    child.on('close', code => { clearTimeout(timer); resolvePromise({ exitCode: code ?? -1, stdout, stderr }); });
  });
  return async (service, argv) => {
    if (!ids.has(service)) {
      const found = await run(['ps', '-q', '--filter', `label=com.docker.compose.project=${project}`, '--filter', `label=com.docker.compose.service=${service}`]);
      const values = found.exitCode === 0 ? found.stdout.split(/\s+/).filter(Boolean) : [];
      if (values.length !== 1) throw failure('container');
      ids.set(service, values[0]);
    }
    return run(['exec', ids.get(service), ...argv]);
  };
}

const cli = {
  'lnd-p': ['lncli', '--network=regtest'], 'lnd-r': ['lncli', '--network=regtest'],
  'cln-m': ['lightning-cli', '--network=regtest', '-k'],
};

async function record({ lab, transport, exec, register, withListpaysRune }) {
  const started = Date.now();
  const recordings = [];
  const check = () => { if (Date.now() - started > deadlineMs) throw failure('deadline'); };
  const call = async (impl, id, method, path, body, options = {}) => {
    check();
    const node = recordedNode[impl];
    const answer = await transport({ node, method, path, ...(body === undefined ? {} : { body }), ...(options.stream ? { stream: true } : {}), ...(options.onData ? { onData: options.onData } : {}), ...(options.timeoutMs ? { timeoutMs: options.timeoutMs } : {}) });
    if (!answer || !Number.isInteger(answer.status) || typeof answer.body !== 'string') throw failure(`${id} answer`);
    if (id) recordings.push({ impl, id, request: { method, path, body: body === undefined ? null : body }, answer, stream: options.stream === true });
    return answer;
  };
  const expectStatus = (answer, status, id) => { if (answer.status !== status) throw failure(`${id} status`); return json(answer.body, id); };
  const run = async (service, args) => {
    check();
    const result = await exec(service, [...cli[service], ...args]);
    if (!result || result.exitCode !== 0) throw failure(`${service} ${args[0]}`);
    return json(result.stdout.split('\n').filter(line => !line.startsWith('# ')).join('\n'), `${service} ${args[0]}`);
  };
  const until = async (stage, observe) => {
    for (;;) {
      check();
      const value = await observe();
      if (value !== undefined) return value;
      await new Promise(resolvePromise => { setTimeout(resolvePromise, 250); });
    }
  };
  // clnrest refuses a rune used again within its rate= window ("too soon"); the call is repeated.
  const clnCall = async (id, method, body) => until(`${id} rate`, async () => {
    const answer = await call('cln', undefined, 'POST', `/v1/${method}`, body);
    const parsed = (() => { try { return JSON.parse(answer.body); } catch { return undefined; } })();
    if (answer.status === 401 && parsed?.code === 1502 && parsed.message === 'Not permitted: too soon') return undefined;
    recordings.push({ impl: 'cln', id, request: { method: 'POST', path: `/v1/${method}`, body }, answer, stream: false });
    return answer;
  });

  // Guards: identity calls only, before any other request, command or file.
  const lndInfo = expectStatus(await call('lnd', 'getinfo', 'GET', '/v1/getinfo'), 200, 'lnd getinfo');
  if (!object(lndInfo) || !Array.isArray(lndInfo.chains) || lndInfo.chains[0]?.network !== 'regtest' ||
      typeof lndInfo.version !== 'string' || !/^0\.21\.4-beta(?: |$)/.test(lndInfo.version)) throw failure('lnd guard');
  const clnGuard = await call('cln', 'getinfo', 'POST', '/v1/getinfo', {});
  const clnInfo = clnGuard.status >= 200 && clnGuard.status < 300 ? json(clnGuard.body, 'cln getinfo') : undefined;
  if (!object(clnInfo) || clnInfo.network !== 'regtest' || clnInfo.version !== 'v26.06.9') throw failure('cln guard');

  // LND snapshots, route query and error envelopes (before any payment of this run).
  const channels = expectStatus(await call('lnd', 'listchannels', 'GET', '/v1/channels'), 200, 'listchannels');
  const pubkey = node => { const value = lab.nodes?.[node]?.pubkey; if (typeof value !== 'string' || !/^0[23][0-9a-f]{64}$/.test(value)) throw failure('lab pubkeys'); return value; };
  const channelTo = node => {
    const found = Array.isArray(channels?.channels) ? channels.channels.filter(channel => channel.remote_pubkey === pubkey(node)) : [];
    if (found.length !== 1 || typeof found[0].chan_id !== 'string' || !/^[1-9][0-9]*$/.test(found[0].chan_id)) throw failure('lnd channels');
    return found[0].chan_id;
  };
  const channel3 = channelTo('cln-r'), channel1 = channelTo('lnd-p');
  expectStatus(await call('lnd', 'pendingchannels', 'GET', '/v1/channels/pending'), 200, 'pendingchannels');
  expectStatus(await call('lnd', 'queryroutes', 'POST', `/v1/graph/routes/${pubkey('lnd-r')}/0`, {
    amt_msat: '100000000', outgoing_chan_ids: [channel3], last_hop_pubkey: Buffer.from(pubkey('cln-m'), 'hex').toString('base64'),
    fee_limit: { fixed_msat: '10000000' }, use_mission_control: true }), 200, 'queryroutes');
  expectStatus(await call('lnd', 'error-code-message', 'GET', `/v1/invoice/${'0'.repeat(64)}`), 404, 'error-code-message');
  expectStatus(await call('lnd', 'error-envelope', 'GET', `/v2/router/track/${Buffer.alloc(32).toString('base64url')}=`), 404, 'error-envelope');

  // CLN snapshots and route query.
  for (const method of ['listpeerchannels', 'listchannels', 'bkpr-listaccountevents']) expectStatus(await clnCall(method, method, {}), 201, method);
  expectStatus(await clnCall('getroutes', 'getroutes', { source: pubkey('lnd-r'), destination: pubkey('cln-r'), amount_msat: 100000000,
    layers: ['auto.localchans'], maxfee_msat: 10000000, final_cltv: 34, maxparts: 1 }), 201, 'getroutes');

  const height = BigInt(lndInfo.block_height);
  const preimage = async () => { const bytes = randomBytes(32); await register(bytes); return { bytes, hash: createHash('sha256').update(bytes).digest('hex') }; };
  const holdInvoice = async amountSat => {
    const secret = await preimage();
    const invoice = await run('lnd-p', ['addholdinvoice', secret.hash, '--amt', String(amountSat)]);
    if (typeof invoice.payment_addr !== 'string' || !/^[0-9a-f]{64}$/.test(invoice.payment_addr)) throw failure('hold invoice');
    return { ...secret, paymentAddr: invoice.payment_addr };
  };
  const invoiceState = (hash, state) => until(`invoice ${state}`, async () => {
    const invoice = await run('lnd-p', ['lookupinvoice', hash]);
    return invoice.state === state ? invoice : undefined;
  });
  // lnrpc/invoicesrpc/invoices.yaml: SettleInvoice is POST /v2/invoices/settle,
  // with protobuf bytes encoded as base64 in the JSON body.
  const settle = async secret => {
    check();
    expectStatus(await transport({ node: 'lnd-p', method: 'POST', path: '/v2/invoices/settle', body: { preimage: secret.bytes.toString('base64') } }), 200, 'settle invoice');
  };
  const oneHop = (hash, amountMsat, paymentAddr) => JSON.stringify({ route: { total_time_lock: Number(height + 100n), total_amt_msat: amountMsat, hops: [{
    chan_id: channel1, expiry: Number(height + 100n), amt_to_forward_msat: amountMsat, pub_key: pubkey('lnd-p'), tlv_payload: true,
    mpp_record: { payment_addr: paymentAddr, total_amt_msat: amountMsat } }] } });
  const track = hash => `/v2/router/track/${Buffer.from(hash, 'hex').toString('base64url')}=`;
  const statuses = text => text.split('\n').filter(line => line.trim()).map(line => json(line, 'track line')?.result?.status);

  // TrackPaymentV2 of a payment held at lnd-p, then settled.
  const held = await holdInvoice(50_000);
  const sending = exec('lnd-r', [...cli['lnd-r'], 'sendtoroute', '--payment_hash', held.hash, '--routes', oneHop(held.hash, '50000000', held.paymentAddr)]);
  let settledHold = false;
  try {
    await invoiceState(held.hash, 'ACCEPTED');
    const streamDeadline = performance.now() + 60_000;
    // Settlement temporarily retargets the shared proxy to LND-P. Observe and
    // close IN_FLIGHT first, then reconnect for the actual terminal update.
    const first = await call('lnd', undefined, 'GET', track(held.hash), undefined, { stream: true, onData: text => text.endsWith('\n') && statuses(text).at(-1) === 'IN_FLIGHT' });
    if (first.status !== 200 || statuses(first.body).at(-1) !== 'IN_FLIGHT') throw failure('track-in-flight');
    await settle(held); settledHold = true;
    const terminal = await call('lnd', undefined, 'GET', track(held.hash), undefined, { stream: true, timeoutMs: Math.max(1, streamDeadline - performance.now()), onData: text => text.endsWith('\n') && statuses(text).at(-1) === 'SUCCEEDED' });
    const answer = { status: terminal.status, body: first.body + terminal.body };
    recordings.push({ impl: 'lnd', id: 'track-succeeded', request: { method: 'GET', path: track(held.hash), body: null }, answer, stream: true });
    const observed = statuses(answer.body);
    if (answer.status !== 200 || !observed.includes('IN_FLIGHT') || observed.at(-1) !== 'SUCCEEDED') throw failure('track-succeeded');
  } finally {
    if (!settledHold) await exec('lnd-p', [...cli['lnd-p'], 'cancelinvoice', held.hash]);
    await sending;
  }

  // TrackPaymentV2 of a payment lnd-p cannot accept (an unknown hash).
  const unknown = await preimage();
  await exec('lnd-r', [...cli['lnd-r'], 'sendtoroute', '--payment_hash', unknown.hash, '--routes', oneHop(unknown.hash, '10000000', randomBytes(32).toString('hex'))]);
  const failedTrack = await call('lnd', 'track-failed', 'GET', track(unknown.hash), undefined, { stream: true });
  const failedLines = failedTrack.body.split('\n').filter(line => line.trim()).map(line => json(line, 'track line')?.result);
  if (failedTrack.status !== 200 || failedLines.at(-1)?.status !== 'FAILED' || failedLines.at(-1)?.failure_reason !== 'FAILURE_REASON_INCORRECT_PAYMENT_DETAILS') throw failure('track-failed');

  // A cln-m payment held at lnd-p over cln-m -> lnd-r -> lnd-p: waitsendpay reports 200 (in flight).
  const amount = 50_000_000n;
  const clnHold = await holdInvoice(Number(amount / 1000n));
  const peer = await run('cln-m', ['listpeerchannels', `id=${pubkey('lnd-r')}`]);
  const channel2 = peer.channels?.[0]?.short_channel_id;
  const decimal = BigInt(channel1), channel1Scid = `${decimal >> 40n}x${(decimal >> 16n) & 0xffffffn}x${decimal & 0xffffn}`;
  const edge = (await run('cln-m', ['listchannels', `short_channel_id=${channel1Scid}`])).channels?.find(row => row.source === pubkey('lnd-r'));
  if (typeof channel2 !== 'string' || !edge) throw failure('cln route');
  const fee = BigInt(edge.base_fee_millisatoshi) + amount * BigInt(edge.fee_per_millionth) / 1_000_000n;
  const direction = (from, to) => from < to ? 0 : 1;
  const route = [
    { short_channel_id_dir: `${channel2}/${direction(pubkey('cln-m'), pubkey('lnd-r'))}`, node_id_out: pubkey('lnd-r'), amount_out_msat: (amount + fee).toString(), cltv_out: 80 + Number(edge.delay) },
    { short_channel_id_dir: `${channel1Scid}/${direction(pubkey('lnd-r'), pubkey('lnd-p'))}`, node_id_out: pubkey('lnd-p'), amount_out_msat: amount.toString(), cltv_out: 80 },
  ];
  let settledCln = false;
  try {
    await run('cln-m', ['sendpay', `route=${JSON.stringify(route)}`, `payment_hash=${clnHold.hash}`, `payment_secret=${clnHold.paymentAddr}`, `amount_msat=${amount}`]);
    await invoiceState(clnHold.hash, 'ACCEPTED');
    const waiting = await clnCall('waitsendpay-200', 'waitsendpay', { payment_hash: clnHold.hash, timeout: 1 });
    if (waiting.status < 400 || json(waiting.body, 'waitsendpay')?.code !== 200) throw failure('waitsendpay-200');
    await settle(clnHold); settledCln = true;
    if ((await run('cln-m', ['waitsendpay', `payment_hash=${clnHold.hash}`, 'timeout=60'])).status !== 'complete') throw failure('cln payment');
  } finally { if (!settledCln) await exec('lnd-p', [...cli['lnd-p'], 'cancelinvoice', clnHold.hash]); }
  expectStatus(await clnCall('listsendpays', 'listsendpays', { payment_hash: clnHold.hash }), 201, 'listsendpays');
  await withListpaysRune(async () => expectStatus(await clnCall('listpays', 'listpays', { payment_hash: clnHold.hash }), 201, 'listpays'));
  return recordings;
}

async function writeOutput(out, files, manifest) {
  const created = [], replaced = [];
  const ensure = async directory => {
    const missing = [];
    for (let current = directory; !existsSync(current); current = dirname(current)) missing.unshift(current);
    for (const path of missing) { await mkdir(path); created.push({ path, directory: true }); }
  };
  try {
    for (const [path, text] of [...files, [join(out, 'manifest.json'), manifest]]) {
      await ensure(dirname(path));
      if (existsSync(path)) replaced.push({ path, previous: await readFile(path) });
      else created.push({ path, directory: false });
      await writeFile(path, text);
    }
  } catch (error) {
    for (const item of replaced.reverse()) await writeFile(item.path, item.previous);
    for (const item of created.reverse()) { if (item.directory) await rmdir(item.path); else await rm(item.path, { force: true }); }
    throw error;
  }
}

/** CLI entry: exit 0 recorded, 1 refused or failed, 2 usage. */
export async function main(argv, deps = {}) {
  const options = parseArguments(argv);
  if (!options) { process.stderr.write('usage: make-fixtures --owner <absolute owner.json> [--out <absolute directory>]\n'); return 2; }
  const cleanups = [];
  try {
    if (process.env.NODE_OPTIONS || /(?:^|[ ,])(?:http|https|net|tls)(?:$|[ ,])/i.test(process.env.NODE_DEBUG || '')) throw failure('environment');
    const owner = json(await readFile(options.owner, 'utf8'), 'owner');
    if (!object(owner) || typeof owner.runtimeRoot !== 'string' || typeof owner.sentinelRoot !== 'string' || typeof owner.project !== 'string' ||
        !/^fluxwarden-lab-[a-z0-9-]+$/.test(owner.project)) throw failure('owner');
    const lab = json(await readFile(join(owner.runtimeRoot, 'lab.json'), 'utf8'), 'lab.json');
    if (!object(lab) || lab.project !== owner.project) throw failure('lab.json');
    const secrets = [];
    let sequence = 0;
    const register = async bytes => {
      secrets.push(Buffer.from(bytes));
      for (;;) {
        try { await writeFile(join(owner.sentinelRoot, `recording-${++sequence}.bin`), bytes, { flag: 'wx', mode: 0o600 }); return; }
        catch (error) { if (error?.code !== 'EEXIST') throw failure('sentinel'); }
      }
    };
    // Lab role credentials allow every recorded call but listpays; it uses a temporary rune.
    const roleFiles = new Map();
    let temporaryRune;
    const credentialBytes = async (node, role) => {
      const key = `${node}/${role}`;
      if (!roleFiles.has(key)) {
        const path = lab.credentials?.[node]?.[role]?.path;
        if (typeof path !== 'string' || !isAbsolute(path)) throw failure('lab credentials');
        const bytes = await readFile(path); await register(bytes); roleFiles.set(key, bytes);
      }
      return roleFiles.get(key);
    };
    let transport = deps.transport;
    if (!transport) {
      await credentialBytes('lnd-r', 'read'); await credentialBytes('cln-m', 'read');
      transport = defaultTransport(lab, (node, path) => node === 'cln-m' && path === '/v1/listpays' && temporaryRune ? temporaryRune : credentialBytes(node, node === 'lnd-p' ? 'execute' : 'read'));
    }
    const exec = deps.exec ?? defaultExec(owner.project);
    const withListpaysRune = async operation => {
      const created = await exec('cln-m', [...cli['cln-m'], 'createrune', 'restrictions=[["method=listpays"]]']);
      const rune = created?.exitCode === 0 ? json(created.stdout, 'createrune') : undefined;
      if (!object(rune) || typeof rune.rune !== 'string' || typeof rune.unique_id !== 'string' || !/^(0|[1-9][0-9]*)$/.test(rune.unique_id)) throw failure('createrune');
      cleanups.push(async () => {
        const revoked = await exec('cln-m', [...cli['cln-m'], 'blacklistrune', `start=${rune.unique_id}`, `end=${rune.unique_id}`]);
        if (revoked?.exitCode !== 0) throw failure('blacklistrune');
      });
      const bytes = Buffer.from(rune.rune, 'utf8'); await register(bytes);
      temporaryRune = bytes;
      try { await operation(); } finally { temporaryRune = undefined; }
    };
    const recordings = await record({ lab, transport, exec, register, withListpaysRune });

    // Every answer is redacted before it is written; requests carry no secret by construction.
    const previous = existsSync(join(options.out, 'manifest.json')) ? json(await readFile(join(options.out, 'manifest.json'), 'utf8'), 'manifest') : { entries: [] };
    const kept = Array.isArray(previous.entries) ? previous.entries : [];
    const files = [], entries = [];
    for (const item of recordings) {
      const text = redactText(item.answer.body, secrets);
      const response = item.stream ? { status: item.answer.status, lines: text.split('\n').filter(line => line.trim()) } : { status: item.answer.status, body: text };
      const content = `${JSON.stringify({ id: item.id, impl: item.impl, version: profiles[item.impl], node: recordedNode[item.impl], request: item.request, response }, null, 2)}\n`;
      const file = `recordings/${item.impl}/${profiles[item.impl]}/${item.id}.json`;
      files.push([join(options.out, ...file.split('/')), content]);
      entries.push({ file, id: item.id, impl: item.impl, version: profiles[item.impl], sha256: createHash('sha256').update(content).digest('hex'),
        command: { transport: item.impl === 'lnd' ? 'lnd-rest' : 'clnrest', ...item.request }, source: 'lab' });
    }
    const manifest = `${JSON.stringify({ version: 1, entries: [...kept.filter(entry => !entries.some(added => added.file === entry.file)), ...entries] }, null, 2)}\n`;
    for (const cleanup of cleanups.splice(0)) await cleanup();
    await writeOutput(options.out, files, manifest);
    process.stdout.write(`recorded ${entries.length} answers\n`);
    return 0;
  } catch (error) {
    for (const cleanup of cleanups.splice(0)) { try { await cleanup(); } catch { /* the lab owner's teardown destroys the node */ } }
    process.stderr.write(`make-fixtures ${error instanceof Failure ? error.message : 'run'}: failed\n`);
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = await main(process.argv.slice(2));
