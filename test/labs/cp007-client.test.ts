import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { writeFileSync } from 'node:fs';
import { inspect } from 'node:util';
import { expect, it } from 'vitest';
import { client, managed, toxics, required } from '../helpers/cp007-toxiproxy.js';

interface Request { method: string; path: string; body: unknown }
async function server(reply: (request: Request, response: ServerResponse) => void): Promise<{ url: string; close: () => Promise<void> }> {
  const instance = createServer((request: IncomingMessage, response: ServerResponse) => {
    const chunks: Buffer[] = [];
    request.on('data', (data: Buffer) => chunks.push(data));
    request.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      reply({ method: request.method ?? '', path: request.url ?? '', body: text ? JSON.parse(text) as unknown : undefined }, response);
    });
  });
  await new Promise<void>(resolve => { instance.listen(0, '127.0.0.1', resolve); });
  const address = instance.address();
  if (!address || typeof address === 'string') throw new Error('loopback fake did not allocate a port');
  return { url: `http://127.0.0.1:${String(address.port)}`, close: () => new Promise<void>((resolve, reject) => { instance.closeAllConnections(); instance.close(error => { if (error) reject(error); else resolve(); }); }) };
}
function json(response: ServerResponse, value: unknown): void { response.setHeader('content-type', 'application/json'); response.end(JSON.stringify(value)); }

// API methods/body/defaults: pinned Shopify/toxiproxy v2.12.0 README HTTP API.
// Toxic attributes/units: README Toxics and toxics/{latency,timeout,slicer,...}.go.
it('CP-007/B1 wire controls preserve every implemented toxic and exact API bodies including timeout zero', async () => {
  const observed: Request[] = [];
  const local = await server((request, response) => {
    observed.push(request);
    if (request.method === 'DELETE' || request.path === '/reset') { response.statusCode = 204; response.end(); }
    else json(response, request.path === '/version' ? { version: '2.12.0' } : request.path === '/proxies' ? Object.fromEntries(managed.map(proxy => [proxy.name, { ...proxy, toxics: [] }])) : request.body);
  });
  try {
    const control = await client({ url: local.url });
    expect(await control.populate(managed)).toEqual(managed);
    expect(await control.list()).toEqual(Object.fromEntries(managed.map(proxy => [proxy.name, { ...proxy, toxics: [] }])));
    await control.enable('lnd-r-rest');
    for (const toxic of toxics) expect(await control.add('lnd-r-rest', toxic)).toEqual(toxic);
    expect(await control.remove('owner/name', 'lag name/+')).toBeUndefined();
    expect(await control.reset()).toBeUndefined();
    expect(await control.version()).toEqual({ version: '2.12.0' });
    expect(observed).toEqual([
      { method: 'POST', path: '/populate', body: managed }, { method: 'GET', path: '/proxies', body: undefined },
      { method: 'POST', path: '/proxies/lnd-r-rest', body: { enabled: true } },
      ...toxics.map(toxic => ({ method: 'POST', path: '/proxies/lnd-r-rest/toxics', body: toxic })),
      { method: 'DELETE', path: '/proxies/owner%2Fname/toxics/lag%20name%2F%2B', body: undefined },
      { method: 'POST', path: '/reset', body: undefined }, { method: 'GET', path: '/version', body: undefined },
    ]);
  } finally { await local.close(); }
});

// SPEC 11.4 / primary README "down": POST proxy enabled:false, never a toxic.
it('CP-007/B4 outage disables the owned proxy with enabled false', async () => {
  const observed: Request[] = [];
  const local = await server((request, response) => { observed.push(request); json(response, { ...managed[0], enabled: false, toxics: [] }); });
  try {
    const control = await client({ url: local.url });
    expect(await control.enable('lnd-r-rest', false)).toEqual({ ...managed[0], enabled: false, toxics: [] });
    expect(observed).toEqual([{ method: 'POST', path: '/proxies/lnd-r-rest', body: { enabled: false } }]);
  } finally { await local.close(); }
});

// Frozen public error contract and INV-11; hostile replies are injected failure controls.
it('CP-007/B2 every non-success control rejects with safe status and operation without hostile body bytes', async () => {
  const sentinelRoot = process.env['FLUXWARDEN_SENTINEL_DIR'];
  if (!sentinelRoot) throw new Error('independent sentinel directory is required');
  const secret = randomBytes(32); writeFileSync(join(sentinelRoot, 'cp007-api-preimage.bin'), secret, { mode: 0o600 });
  const forms = [secret.toString('hex'), secret.toString('hex').toUpperCase(), secret.toString('base64'), secret.toString('base64url')];
  const local = await server((_request, response) => { response.statusCode = 503; json(response, { error: forms.join(' ') }); });
  try {
    const control = await client({ url: local.url });
    const actions = [() => control.list(), () => control.populate(managed), () => control.enable('lnd-r-rest', false), () => control.add('lnd-r-rest', required(toxics[0])), () => control.remove('lnd-r-rest', 'lag'), () => control.reset(), () => control.version()];
    for (const action of actions) {
      let failure: unknown; try { await action(); } catch (error) { failure = error; }
      expect(failure instanceof Error, 'HTTP failure must reject').toBe(true);
      const metadata = failure as { status?: unknown; operation?: unknown };
      expect(metadata.status).toBe(503); expect(typeof metadata.operation === 'string' && metadata.operation.length > 0).toBe(true);
      const output = inspect(failure, { showHidden: true, depth: 8 }) + JSON.stringify(failure);
      for (const form of forms) expect(output.includes(form), 'sentinel encoding absent from error').toBe(false);
    }
  } finally { await local.close(); }
});

// D41: registry has no packet_loss; toxics/toxic.go New returns nil for unknown type.
// JSON numeric fields are int64 (timeout.go/slicer.go), not numeric strings.
it('CP-007/B5 refused unknown and malformed toxics remain errors without substitute faults or success claims', async () => {
  const observed: Request[] = [];
  const local = await server((request, response) => { observed.push(request); response.statusCode = 400; json(response, { error: 'injected pinned API refusal' }); });
  try {
    const control = await client({ url: local.url });
    for (const toxic of [{ name: 'unsupported', type: 'packet_loss', attributes: { loss: 1 } }, { name: 'malformed', type: 'timeout', attributes: { timeout: 'not-an-integer' } }]) {
      const start = observed.length;
      await expect(control.add('lnd-r-rest', toxic)).rejects.toBeInstanceOf(Error);
      const requests = observed.slice(start);
      expect(requests.length).toBeLessThanOrEqual(1);
      if (requests.length > 0) expect(requests).toEqual([{ method: 'POST', path: '/proxies/lnd-r-rest/toxics', body: toxic }]);
    }
  } finally { await local.close(); }
});

// Finite deadlines and standard AbortSignal are part of the frozen public interface.
it('CP-007/B2 pending requests honor deadline and abort while raw abort reasons stay private', async () => {
  const sentinelRoot = process.env['FLUXWARDEN_SENTINEL_DIR'];
  if (!sentinelRoot) throw new Error('independent sentinel directory is required');
  const secret = randomBytes(32); writeFileSync(join(sentinelRoot, 'cp007-abort-rune.bin'), secret, { mode: 0o600 });
  const reason = secret.toString('base64url');
  const pending: typeof fetch = (_input, init) => new Promise((_resolve, reject) => {
    const signal = init?.signal;
    if (!signal) { reject(new Error('standard fetch requires cancellation signal')); return; }
    if (signal.aborted) reject(signal.reason as Error);
    else signal.addEventListener('abort', () => { reject(signal.reason as Error); }, { once: true });
  });
  const timed = await client({ url: 'http://127.0.0.1:19999', fetch: pending, timeoutMs: 20 });
  await expect(timed.list()).rejects.toBeInstanceOf(Error);
  const abort = new AbortController();
  const canceled = await client({ url: 'http://127.0.0.1:19999', fetch: pending, timeoutMs: 5000, signal: abort.signal });
  const call = canceled.list(); abort.abort(new Error(reason));
  let failure: unknown; try { await call; } catch (error) { failure = error; }
  expect(failure instanceof Error).toBe(true);
  expect((inspect(failure, { showHidden: true }) + JSON.stringify(failure)).includes(reason), 'raw abort reason absent').toBe(false);
});
