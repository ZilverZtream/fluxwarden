import { appendFileSync, copyFileSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { afterEach, expect, it, vi } from 'vitest';
import { repoRoot, runCli, singleJsonDocument } from '../helpers/cli.js';
import { writeConfig } from '../helpers/cp016-cli.js';
import { testRoot } from '../helpers/env.js';
import type { AdapterErrors, ClnRest, ClnRestModule, ClnProbeModule, NodeProbeUpdate } from '../helpers/adapter-interfaces.js';
import { certificatePath } from '../fakes/https.js';
import { CLN_PUBKEY, getinfo } from '../fakes/cln/responses.js';
import { MIN_INTERVAL_MS, result, startCadenceServer, type CadenceServer, type RpcExecution } from '../fakes/cln/cadence.js';
import { syntheticCadenceRune } from '../fixtures/cln/cadence-rune.js';

// SECURITY §3.2 and SPEC §5.2 H2/H6 require this restricted credential to work.
// The golden authorization oracle is pinned in test/fakes/cln/cadence.ts.
// Only built modules are loaded; these signatures come from the accepted adapter tests.
async function built<T>(relative: string): Promise<T> {
  return await import(pathToFileURL(join(repoRoot, 'dist', relative)).href) as T;
}
const open: CadenceServer[] = [];
afterEach(async context => {
  vi.restoreAllMocks();
  for (const server of open) {
    appendFileSync(join(testRoot('FLUXWARDEN_EVIDENCE_DIR'), 'cln-cadence-timing.ndjson'), `${JSON.stringify({
      test: context.task.name,
      authorizations: server.authorizations,
      executedMethods: server.executions.map(rpc => rpc.method),
    })}\n`);
  }
  await Promise.all(open.splice(0).map(server => server.close()));
});

async function setup(execute: (rpc: RpcExecution) => void = rpc => {
  result(rpc.response, rpc.method === 'getinfo' ? getinfo() : { layers: [] });
}, authRefusal?: string): Promise<{ server: CadenceServer; runePath: string; dir: string }> {
  const dir = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'cln-cadence-'));
  const rune = syntheticCadenceRune();
  const runePath = join(dir, 'credential.rune');
  appendFileSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'declared-out.txt'), `${runePath}\n`);
  writeFileSync(runePath, `${rune}\n`, { mode: 0o600 });
  copyFileSync(runePath, join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `cln-cadence-${String(open.length)}-${String(performance.now())}.rune`));
  const server = await startCadenceServer({ rune, execute, ...(authRefusal === undefined ? {} : { authRefusal }) });
  open.push(server);
  return { server, runePath, dir };
}

async function rest(server: CadenceServer, runePath: string, timeoutMs = 1000): Promise<ClnRest> {
  const { openClnRest } = await built<ClnRestModule>('node-cln/rest.js');
  return openClnRest({ host: server.host, port: server.port, tlsCertPath: certificatePath('node'), runePath, timeoutMs });
}
function assertCadence(server: CadenceServer, methods: readonly string[]): void {
  expect(server.authorizations.map(item => [item.method, item.reason])).toEqual(methods.map(method => [method, 'accepted']));
  expect(server.executions.map(item => item.method)).toEqual(methods);
  for (let i = 1; i < server.authorizations.length; i += 1) {
    expect((server.authorizations[i]?.atMs ?? 0) - (server.authorizations[i - 1]?.atMs ?? 0)).toBeGreaterThanOrEqual(MIN_INTERVAL_MS);
  }
}
async function outcome(promise: Promise<unknown>): Promise<{ kind: 'success'; value: unknown } | { kind: 'error'; error: unknown }> {
  try { return { kind: 'success', value: await promise }; } catch (error) { return { kind: 'error', error }; }
}

it('CP-012/cadence-sequential two required reads succeed without a too-soon authorization', async () => {
  const { server, runePath } = await setup();
  const client = await rest(server, runePath);
  const first = await client.call('getinfo');
  const second = await outcome(client.call('askrene-listlayers'));
  assertCadence(server, ['getinfo', 'askrene-listlayers']);
  expect(first['id']).toBe(CLN_PUBKEY);
  expect(second).toEqual({ kind: 'success', value: { layers: [] } });
});

it('CP-012/cadence-probe the public handshake completes and records ONLINE using a rate=600 rune', async () => {
  const { server, runePath } = await setup();
  const { probeCln } = await built<ClnProbeModule>('node-cln/probe.js');
  const updates: NodeProbeUpdate[] = [];
  const probe = await outcome(probeCln(await rest(server, runePath), {
    nodeId: 'cln-cadence', expectedPubkey: CLN_PUBKEY, expectedNetwork: 'regtest', mutating: false,
    nowMs: () => 1_760_000_000_000, store: { recordProbe: update => { updates.push(update); return Promise.resolve(); } },
  }));
  assertCadence(server, ['getinfo', 'askrene-listlayers']);
  expect(probe.kind).toBe('success');
  expect(updates).toHaveLength(1);
  expect(updates[0]).toMatchObject({ state: 'ONLINE', observedVersion: 'v26.06.9' });
});

it('CP-016/cadence-doctor doctor succeeds with the documented restricted rune and two sequential reads', async () => {
  const { server, runePath, dir } = await setup();
  const config = writeConfig(dir, { database: join(dir, 'state.db'), nodes: [{
    name: 'cln-cadence', implementation: 'cln', url: `https://${server.host}:${String(server.port)}`,
    credential: runePath, tlsCert: certificatePath('node'), expectedPubkey: CLN_PUBKEY,
  }] });
  const run = await runCli(['--json', 'doctor', '--config', config]);
  assertCadence(server, ['getinfo', 'askrene-listlayers']);
  expect(run.status).toBe(0);
  expect(singleJsonDocument(run.stdout)['error']).toBeNull();
});

it('CP-012/cadence-concurrent a second call respects authorization time while the first RPC is still executing', async () => {
  let entered!: () => void;
  const firstEntered = new Promise<void>(resolve => { entered = resolve; });
  let release!: () => void;
  let released = false;
  const { server, runePath } = await setup(rpc => {
    if (rpc.method === 'getinfo') {
      // A successful second RPC and the cleanup below both release this response.
      release = () => {
        if (released) return;
        released = true;
        result(rpc.response, getinfo());
      };
      entered();
    }
    else { result(rpc.response, { layers: [] }); release(); }
  });
  const client = await rest(server, runePath);
  const first = outcome(client.call('getinfo'));
  await firstEntered;
  const second = await outcome(client.call('askrene-listlayers'));
  release();
  const firstResult = await first;
  assertCadence(server, ['getinfo', 'askrene-listlayers']);
  expect(firstResult.kind).toBe('success');
  expect(second.kind).toBe('success');
});

it('CP-012/cadence-reopen concurrent reopened clients using copies of one rune preserve its permission timing', async () => {
  const { server, runePath, dir } = await setup();
  const alias = join(dir, 'same-rune-copy.rune');
  appendFileSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'declared-out.txt'), `${alias}\n`);
  copyFileSync(runePath, alias);
  const first = await rest(server, runePath);
  await first.call('getinfo');
  const [second, third] = await Promise.all([rest(server, runePath), rest(server, alias)]);
  const results = await Promise.all([outcome(second.call('askrene-listlayers')), outcome(third.call('getinfo'))]);
  expect(server.authorizations.every(item => item.accepted)).toBe(true);
  expect(server.executions).toHaveLength(3);
  const methods = server.executions.map(item => item.method);
  assertCadence(server, methods);
  expect(results.map(item => item.kind)).toEqual(['success', 'success']);
});

it('CP-012/cadence-certificate-der reopening with LF and CRLF encodings of one X509 certificate retains the same 100 ms admission', async () => {
  const { server, runePath, dir } = await setup();
  const lf = readFileSync(certificatePath('node'), 'utf8').replace(/\r\n/g, '\n');
  const crlf = lf.replace(/\n/g, '\r\n');
  const lfPath = join(dir, 'same-certificate-lf.pem'), crlfPath = join(dir, 'same-certificate-crlf.pem');
  writeFileSync(lfPath, lf); writeFileSync(crlfPath, crlf);
  // Public Node identity oracle: raw is DER, and fingerprint256 identifies the certificate.
  // https://nodejs.org/docs/latest-v24.x/api/crypto.html#x509raw
  expect(lf === crlf, 'transport files differ').toBe(false);
  expect(new X509Certificate(lf).raw.equals(new X509Certificate(crlf).raw), 'same certificate DER').toBe(true);
  expect(new X509Certificate(lf).fingerprint256 === new X509Certificate(crlf).fingerprint256).toBe(true);
  const { openClnRest } = await built<ClnRestModule>('node-cln/rest.js');
  const clients = await Promise.all([lfPath, crlfPath].map(tlsCertPath => openClnRest({
    host: server.host, port: server.port, runePath, tlsCertPath, timeoutMs: 1000,
  })));
  const [firstClient, secondClient] = clients;
  if (!firstClient || !secondClient) throw new Error('two certificate fixture clients required');
  await firstClient.call('getinfo');
  const second = await outcome(secondClient.call('askrene-listlayers'));
  assertCadence(server, ['getinfo', 'askrene-listlayers']);
  expect(second).toEqual({ kind: 'success', value: { layers: [] } });
});

it('CP-012/cadence-certificate-anchor a prior successful context never makes a reopened distinct certificate trusted', async () => {
  const { server, runePath } = await setup();
  await (await rest(server, runePath)).call('getinfo');
  expect(new X509Certificate(readFileSync(certificatePath('node'))).raw.equals(
    new X509Certificate(readFileSync(certificatePath('other'))).raw)).toBe(false);
  const { openClnRest } = await built<ClnRestModule>('node-cln/rest.js');
  const other = await openClnRest({ host: server.host, port: server.port, runePath,
    tlsCertPath: certificatePath('other'), timeoutMs: 1000 });
  const errors = await built<AdapterErrors>('core/errors.js');
  const observed = await outcome(other.call('askrene-listlayers'));
  expect(observed.kind).toBe('error');
  if (observed.kind === 'error') expect(observed.error).toBeInstanceOf(errors.TlsError);
  expect(server.authorizations.map(item => item.method)).toEqual(['getinfo']);
  expect(server.executions.map(item => item.method)).toEqual(['getinfo']);
});

it('CP-012/cadence-deadline waiting for permission expires within the caller deadline with no request dispatched', async () => {
  const { server, runePath } = await setup();
  await (await rest(server, runePath)).call('getinfo');
  // 40 ms cannot accommodate a new authorization 100 ms after the first.
  const bounded = await rest(server, runePath, 40);
  const began = performance.now();
  const pending = await outcome(bounded.call('askrene-listlayers'));
  const elapsed = performance.now() - began;
  expect(server.authorizations.map(item => item.method)).toEqual(['getinfo']);
  expect(server.executions.map(item => item.method)).toEqual(['getinfo']);
  expect(pending.kind).toBe('error');
  if (pending.kind === 'error') {
    const errors = await built<AdapterErrors>('core/errors.js');
    expect(pending.error).toBeInstanceOf(errors.TransportError);
    expect(pending.error).toMatchObject({ notDelivered: true });
  }
  // A generous scheduling tolerance, still far below the existing 1-second default used here.
  expect(elapsed).toBeLessThan(400);
  // Reuse the same permission after expiry: an abandoned queued call must never emerge
  // later or consume the next interval. The public call supplies the timing barrier.
  const resumed = await outcome((await rest(server, runePath)).call('getinfo'));
  expect(resumed.kind).toBe('success');
  assertCadence(server, ['getinfo', 'getinfo']);
});

it('CP-012/cadence-monotonic forward and backward wall-clock jumps do not waive the 100 ms authorization rule', async () => {
  const { server, runePath } = await setup();
  const client = await rest(server, runePath);
  await client.call('getinfo');
  const wall = Date.now();
  const clock = vi.spyOn(Date, 'now').mockReturnValue(wall + 86_400_000);
  const forward = await outcome(client.call('askrene-listlayers'));
  clock.mockReturnValue(wall - 86_400_000);
  const backward = await outcome(client.call('getinfo'));
  assertCadence(server, ['getinfo', 'askrene-listlayers', 'getinfo']);
  expect([forward.kind, backward.kind]).toEqual(['success', 'success']);
});

it('CP-012/cadence-auth unrelated 1502 authentication refusals remain AuthError with one wire request', async () => {
  const { server, runePath } = await setup(undefined, 'Not authorized: Rune is not valid');
  const errors = await built<AdapterErrors>('core/errors.js');
  const refused = await outcome((await rest(server, runePath)).call('getinfo'));
  expect(refused.kind).toBe('error');
  if (refused.kind === 'error') {
    expect(refused.error).toBeInstanceOf(errors.AuthError);
    expect(refused.error).toMatchObject({ code: 1502, httpStatus: 401 });
  }
  expect(server.authorizations.map(item => item.reason)).toEqual(['auth']);
  expect(server.executions).toHaveLength(0);
});

it('CP-012/cadence-money an authorized sendpay whose response is lost is dispatched exactly once', async () => {
  const { server, runePath } = await setup(rpc => {
    if (rpc.method === 'sendpay') rpc.response.socket?.destroy();
    else result(rpc.response, getinfo());
  });
  const client = await rest(server, runePath);
  const sent = await outcome(client.call('sendpay', { route: [], payment_hash: 'ab'.repeat(32), amount_msat: 1 }));
  assertCadence(server, ['sendpay']);
  expect(server.executions.filter(item => item.method === 'sendpay')).toHaveLength(1);
  expect(sent.kind).toBe('error');
  if (sent.kind === 'error') {
    const errors = await built<AdapterErrors>('core/errors.js');
    expect(sent.error).toBeInstanceOf(errors.TransportError);
    expect(sent.error).toMatchObject({ notDelivered: false });
  }
});

it('CP-012/cadence-money-auth a dispatched sendpay refused with 1502 is never automatically retried', async () => {
  // A different rune user may have consumed the interval before this client's first request.
  const { server, runePath } = await setup(undefined, 'Not permitted: rate: too soon');
  const errors = await built<AdapterErrors>('core/errors.js');
  const sent = await outcome((await rest(server, runePath)).call('sendpay', { route: [], payment_hash: 'ab'.repeat(32), amount_msat: 1 }));
  expect(server.requests).toHaveLength(1);
  expect(server.executions).toHaveLength(0);
  expect(sent.kind).toBe('error');
  if (sent.kind === 'error') expect(sent.error).toBeInstanceOf(errors.AuthError);
});
