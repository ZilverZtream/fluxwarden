import { createHash, randomBytes } from 'node:crypto';
import { join, isAbsolute, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { composeArguments, composeEnvironment, runProcess } from './compose.mjs';
import { validateOwner } from './owner.mjs';
import { createCredentialPermissions } from './credential-permissions.mjs';
import { createPermissionRequest } from './credential-transport.mjs';

const nodes = ['lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m'];
const roles = ['read', 'execute'];
const readMethods = ['getinfo', 'listpeerchannels', 'listchannels', 'listinvoices', 'listhtlcs', 'getroutes', 'askrene-listlayers', 'waitsendpay', 'listsendpays', 'bkpr-listaccountevents'];
const executeMethods = ['getinfo', 'listpeerchannels', 'listchannels', 'invoice', 'listinvoices', 'listhtlcs', 'delinvoice', 'getroutes', 'askrene-listlayers', 'sendpay', 'waitsendpay', 'listsendpays', 'bkpr-listaccountevents'];
const forbidden = ['pay', 'xpay', 'withdraw', 'stop', 'createrune', 'invokerune', 'listconfigs', 'blacklistrune'];
const failure = stage => new Error(`lab credentials ${stage}: failed`);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const canonical = value => typeof value === 'string' && /^[1-9][0-9]*$/.test(value);
const fingerprint = bytes => `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;

export function validateCredentialPolicy(policy) {
  if (!object(policy) || !canonical(policy.maxPrincipalMsat) || BigInt(policy.maxPrincipalMsat) > 9223372036854775807n || !canonical(policy.callsPerMinute)) throw failure('policy');
  for (const node of nodes.slice(0, 2)) {
    const ids = policy.lndRootKeyIds?.[node];
    if (!object(ids) || roles.some(role => !canonical(ids[role]) || BigInt(ids[role]) > 18446744073709551615n) || ids.read === ids.execute) throw failure('policy');
  }
  return structuredClone(policy);
}

// Exact CLI output and restriction construction reuse lightningnetwork/lnd
// cmd/commands/cmd_macaroon.go and ElementsProject/lightning doc/schemas/createrune.json.
export async function bakeLabCredentials({ owner: declaration, policy: configured, authorizationFixtures, ports, signal } = {}) {
  const owned = new Set(), minted = [], lndRoots = [], credentials = {};
  let permissions, command, owner, processPort;
  const deadline = performance.now() + 180000;
  const guard = () => { if (signal?.aborted || performance.now() >= deadline) throw failure('timeout'); };
  try {
    owner = validateOwner(declaration);
    for (const key of ['runtimeRoot', 'tmpRoot', 'sentinelRoot', 'evidenceRoot']) {
      if (!isAbsolute(owner[key]) || owner[key].split(/[\\/]/).includes('..') || resolve(owner[key]) !== owner[key]) throw failure('path');
    }
    const policy = validateCredentialPolicy(configured);
    if (!object(authorizationFixtures)) throw failure('fixtures');
    const fixture = (node, operation) => {
      const value = authorizationFixtures[node]?.[operation];
      if (!object(value)) throw failure('fixtures');
      return structuredClone(value);
    };
    // Validate all normal request inputs before minting anything; caller responses are never read.
    for (const node of nodes) for (const operation of node.startsWith('lnd-') ? ['ListChannels', 'SendToRouteV2', 'ChangePassword', 'StopDaemon', 'LookupInvoice', 'LookupInvoiceV2'] : [...new Set([...readMethods, ...executeMethods, ...forbidden])]) fixture(node, operation);
    permissions = ports?.permissions ?? createCredentialPermissions(owner);
    const process = ports?.runProcess ?? runProcess; processPort = process;
    const request = ports?.permissionRequest ?? createPermissionRequest({ owner, permissions });
    const env = composeEnvironment(owner);
    command = async (node, cli) => {
      guard();
      let answer;
      try { answer = await process(['docker', ...composeArguments(owner, join(owner.runtimeRoot, 'compose-owner.json'), ['exec', '-T', node, ...cli])], { cwd: owner.runtimeRoot, env, timeoutMs: Math.max(1, Math.min(30000, deadline - performance.now())), signal }); }
      catch { throw failure('process'); }
      guard();
      if (!answer || answer.exitCode !== 0 || typeof answer.stdout !== 'string' || typeof answer.stderr !== 'string' || Buffer.byteLength(answer.stdout) > 262144 || Buffer.byteLength(answer.stderr) > 65536) throw failure('process');
      return answer.stdout;
    };
    const store = async (path, bytes) => {
      guard();
      if (bytes.length === 0 || bytes.length > 65536) throw failure('output');
      // Claim cleanup only after successful exclusive creation, never delete a borrowed collision.
      await permissions.writeExclusive(path, bytes); owned.add(path);
      guard();
      const checked = Buffer.from(await permissions.readChecked(path));
      if (!checked.equals(bytes)) throw failure('readback');
      return { path, fingerprint: fingerprint(checked) };
    };
    const register = async (node, role, bytes) => {
      const path = join(owner.sentinelRoot, `${node}-${role}-${randomBytes(8).toString('hex')}.bin`);
      await store(path, bytes);
      return path;
    };
    const mintRune = async (node, restrictions) => {
      const raw = await command(node, ['lightning-cli', '--network=regtest', '-k', 'createrune', ...(restrictions ? [`restrictions=${JSON.stringify(restrictions)}`] : [])]);
      let answer; try { answer = JSON.parse(raw); } catch { throw failure('output'); }
      if (!object(answer) || typeof answer.rune !== 'string' || !/^[A-Za-z0-9_+/-]+={0,2}$/.test(answer.rune) || typeof answer.unique_id !== 'string' || !/^(0|[1-9][0-9]*)$/.test(answer.unique_id)) throw failure('output');
      if (minted.some(item => item.node === node && item.id === answer.unique_id)) throw failure('REFERENCE_CONFLICT');
      minted.push({ node, id: answer.unique_id });
      return Buffer.from(answer.rune, 'utf8');
    };
    const control = async (node, credentialPath, operation, params, expected, check = false) => {
      for (;;) {
        guard();
        let answer; try { answer = await request({ node, credentialPath, transport: node.startsWith('lnd-') ? 'lnd-rest' : 'clnrest', operation, params, signal }); } catch { throw failure('request'); }
        guard();
        if (!answer || !Number.isInteger(answer.statusCode) || !object(answer.body)) throw failure('response');
        const body = answer.body, lnd = node.startsWith('lnd-');
        const message = typeof body.message === 'string' ? body.message : '';
        // Rate exhaustion is never evidence of missing authority. Only the observed rate
        // rejection is retried, within the same fixed deadline, without changing the rune.
        // clnrest answers a rune refusal with 401 and relays a checkrune refusal with 500.
        if (!lnd && [401, 403, 500].includes(answer.statusCode) && body.code === 1502 && /rate|per-second|per-minute|too soon/i.test(message)) {
          try { await delay(1000, undefined, { signal }); } catch { throw failure('timeout'); }
          continue;
        }
        // clnrest succeeds with 201; lnd's REST gateway with 200.
        const allowed = (answer.statusCode === 200 || (!lnd && answer.statusCode === 201)) && !('error' in body) && !('code' in body) && (!check || body.valid === true);
        // lnd macaroon refusals are plain errors (gRPC Unknown, HTTP 500 "permission denied");
        // a PermissionDenied status maps to 403 code 7. ChangePassword belongs to the
        // WalletUnlocker, which refuses every caller once the wallet is unlocked.
        const denied = lnd
          ? (answer.statusCode === 403 && body.code === 7 && /permission|not permitted|not authorized/i.test(message)) ||
            (answer.statusCode === 500 && body.code === 2 && (message === 'permission denied' ||
              (operation === 'ChangePassword' && message === 'wallet already unlocked, WalletUnlocker service is no longer available')))
          : [401, 403, ...(check ? [500] : [])].includes(answer.statusCode) && body.code === 1502 && /permission|not permitted|not authorized|restriction/i.test(message);
        if (!allowed && !denied) throw failure('response');
        if (allowed !== expected) throw failure('REFERENCE_CONFLICT');
        return;
      }
    };
    await permissions.ensureDirectory(join(owner.runtimeRoot, 'credentials'));
    await permissions.ensureDirectory(owner.sentinelRoot);
    for (const node of nodes) {
      guard();
      const directory = join(owner.runtimeRoot, 'credentials', node);
      await permissions.ensureDirectory(directory);
      credentials[node] = {};
      for (const role of roles) {
        let bytes;
        if (node.startsWith('lnd-')) {
          const rights = ['info:read', 'offchain:read', 'invoices:read', ...(role === 'execute' ? ['offchain:write', 'invoices:write'] : [])];
          const text = await command(node, ['lncli', '--network=regtest', 'bakemacaroon', `--root_key_id=${policy.lndRootKeyIds[node][role]}`, ...rights]);
          lndRoots.push({ node, id: policy.lndRootKeyIds[node][role] });
          if (!/^[a-fA-F0-9]+\r?\n?$/.test(text) || text.trim().length % 2 !== 0) throw failure('output');
          bytes = Buffer.from(text.trim(), 'hex');
        } else {
          const methods = role === 'read' ? readMethods.map(method => `method=${method}`) : executeMethods.filter(method => method !== 'askrene-listlayers').map(method => `method=${method}`).concat('method^askrene-');
          const restrictions = [methods, ...(role === 'execute' ? [['method/sendpay', `pnameamount_msat<${BigInt(policy.maxPrincipalMsat) + 1n}`]] : []), [`rate=${policy.callsPerMinute}`]];
          bytes = await mintRune(node, restrictions);
        }
        await register(node, role, bytes);
        credentials[node][role] = await store(join(directory, `${role}.${node.startsWith('lnd-') ? 'macaroon' : 'rune'}`), bytes);
      }
      if (node.startsWith('lnd-')) {
        for (const role of roles) for (const operation of ['ListChannels', 'SendToRouteV2', 'ChangePassword', 'StopDaemon', 'LookupInvoice', 'LookupInvoiceV2']) {
          await control(node, credentials[node][role].path, operation, fixture(node, operation), ['ListChannels', 'LookupInvoice'].includes(operation) || role === 'execute' && ['SendToRouteV2', 'LookupInvoiceV2'].includes(operation));
        }
      } else {
        const bytes = await mintRune(node);
        const bootstrapSentinel = await register(node, 'bootstrap', bytes);
        const path = join(directory, `bootstrap-${randomBytes(8).toString('hex')}.rune`);
        await store(path, bytes);
        for (const role of roles) {
          const methods = role === 'read' ? readMethods : executeMethods;
          for (const operation of [...new Set([...methods, 'sendpay', ...forbidden])]) await control(node, credentials[node][role].path, operation, fixture(node, operation), methods.includes(operation));
          const rune = Buffer.from(await permissions.readChecked(credentials[node][role].path)).toString('utf8');
          await control(node, path, 'checkrune', { rune, method: 'getinfo', params: fixture(node, 'getinfo') }, true, true);
          for (const operation of forbidden) await control(node, path, 'checkrune', { rune, method: operation, params: fixture(node, operation) }, false, true);
          if (role === 'execute') {
            const max = BigInt(policy.maxPrincipalMsat);
            for (const amount of [max - 1n, max, max + 1n, undefined]) {
              const params = fixture(node, 'sendpay');
              if (amount === undefined) delete params.amount_msat; else params.amount_msat = amount.toString();
              await control(node, path, 'checkrune', { rune, method: 'sendpay', params }, amount !== undefined && amount <= max, true);
            }
          }
        }
        // Revoke the permissive bootstrap ID through the trusted owner CLI using only
        // its public ID (ElementsProject/lightning doc/schemas/blacklistrune.json).
        const id = minted.at(-1).id;
        await control(node, path, 'blacklistrune', { start: id, end: id }, true);
        await permissions.remove(path); owned.delete(path);
        await permissions.remove(bootstrapSentinel); owned.delete(bootstrapSentinel);
      }
    }
    guard();
    return { credentials };
  } catch (error) {
    // Revocation uses only public IDs and runs independently of an aborted request.
    // Any cleanup error still rejects; lab.up must destroy its owner volumes afterward.
    if (owner && processPort) {
      for (const item of [...minted, ...lndRoots]) {
        const cli = item.node.startsWith('lnd-') ? ['lncli', '--network=regtest', 'deletemacaroonid', item.id]
          : ['lightning-cli', '--network=regtest', '-k', 'blacklistrune', `start=${item.id}`, `end=${item.id}`];
        try { await processPort(['docker', ...composeArguments(owner, join(owner.runtimeRoot, 'compose-owner.json'), ['exec', '-T', item.node, ...cli])], { cwd: owner.runtimeRoot, env: composeEnvironment(owner), timeoutMs: 30000 }); } catch { /* lifecycle cleanup remains mandatory */ }
      }
    }
    if (permissions) for (const path of [...owned].reverse()) { try { await permissions.remove(path); } catch { /* lifecycle must still destroy its owned volumes */ } }
    throw error instanceof Error && /^lab credentials [a-zA-Z_ -]+: failed$/.test(error.message) ? error : failure('stage');
  }
}
