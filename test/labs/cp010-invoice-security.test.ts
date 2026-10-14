import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { writeFileSync } from 'node:fs';
import type { RequestOptions } from 'node:https';
import { join } from 'node:path';
import { afterEach, expect, it, vi, type Mock } from 'vitest';
import { scratchDir } from '../helpers/cli.js';
import { clnInvoice, LabInvalidError, lndInvoice, settleInvoice, type Lab, type Node } from '../helpers/lab.js';

const wire = vi.hoisted((): { requests: { options: RequestOptions; body: string }[]; status: number; reply: unknown } => ({ requests: [], status: 200, reply: {} }));
vi.mock('node:https', () => ({
  request: (options: RequestOptions, callback: (response: EventEmitter & { statusCode: number }) => void) => {
    const outgoing = new EventEmitter() as EventEmitter & { destroy: () => void; end: (body: string) => void };
    outgoing.destroy = () => { outgoing.emit('close'); };
    outgoing.end = body => {
      wire.requests.push({ options, body });
      queueMicrotask(() => {
        const response = Object.assign(new EventEmitter(), { statusCode: wire.status });
        callback(response); response.emit('data', Buffer.from(JSON.stringify(wire.reply))); response.emit('end');
      });
    };
    return outgoing;
  },
}));

afterEach(() => { vi.unstubAllGlobals(); wire.requests.length = 0; wire.status = 200; wire.reply = {}; });

function owner(): { lab: Lab; certificate: Buffer; macaroon: Buffer; rune: Buffer; changes: unknown[]; commands: Mock<() => never> } {
  const root = scratchDir('invoice-https-'), certificate = Buffer.from('disposable pinned certificate'), macaroon = Buffer.alloc(32, 33), rune = Buffer.from('disposable-invoice-rune');
  const certPath = join(root, 'certificate.pem'), macPath = join(root, 'execute.macaroon'), runePath = join(root, 'execute.rune');
  writeFileSync(certPath, certificate); writeFileSync(macPath, macaroon); writeFileSync(runePath, rune);
  const changes: unknown[] = [];
  vi.stubGlobal('fetch', vi.fn((_url: string, options: { method: string; body?: string }) => {
    const value: unknown = options.method === 'GET' ? { upstream: 'lnd-r:8080', enabled: false } : JSON.parse(options.body ?? '{}') as unknown;
    if (options.method === 'POST') changes.push(value);
    return Promise.resolve(new Response(JSON.stringify(value), { status: 200 }));
  }));
  const commands = vi.fn((): never => { throw new Error('process execution must not carry a preimage'); });
  const lab: Lab = {
    declaration: { project: `fluxwarden-lab-${randomUUID()}`, ports: { lndRest: 18080, clnRest: 13010, toxiproxy: 8474 }, manifest: {
      nodes: Object.fromEntries(['lnd-p', 'lnd-r', 'cln-m'].map(node => [node, { certificate: { path: certPath } }])),
      credentials: { 'lnd-p': { execute: { path: macPath } }, 'lnd-r': { execute: { path: macPath } }, 'cln-m': { execute: { path: runePath } } },
    } },
    pubkeys: {} as Record<Node, string>, run: commands,
    ok: commands, value: commands, height: () => 113,
  };
  return { lab, certificate, macaroon, rune, changes, commands };
}

// https://github.com/lightningnetwork/lnd/blob/v0.21.4-beta/lnrpc/invoicesrpc/invoices.yaml
// SettleInvoice POST /v2/invoices/settle; protobuf bytes use base64 in grpc-gateway JSON.
it.each([200, 500])('CP-010/B2 secret-bearing LND settlement pins HTTPS and restores a disabled proxy on status %s', async status => {
  const { lab, certificate, macaroon, changes, commands } = owner(), secret = Buffer.alloc(32, 71);
  wire.status = status;
  if (status === 200) await settleInvoice(lab, 'lnd-p', secret.toString('hex'));
  else await expect(settleInvoice(lab, 'lnd-p', secret.toString('hex'))).rejects.toThrow('settlement was not accepted');
  expect(changes).toEqual([{ upstream: 'lnd-p:8080', enabled: true }, { upstream: 'lnd-r:8080', enabled: false }]);
  expect(wire.requests).toHaveLength(1);
  expect(wire.requests[0]?.options).toMatchObject({ host: '127.0.0.1', port: 18080, servername: 'lnd-p', method: 'POST', path: '/v2/invoices/settle', ca: certificate, rejectUnauthorized: true, headers: { 'Grpc-Metadata-macaroon': macaroon.toString('hex') } });
  expect(JSON.parse(wire.requests[0]?.body ?? '') as unknown).toEqual({ preimage: secret.toString('base64') });
  expect(commands).not.toHaveBeenCalled();
});

// lnrpc/lightning.yaml AddInvoice; doc/schemas/invoice.json in CLN v26.06.9.
it('CP-010/B2 invoice helpers carry supplied preimages only in pinned HTTPS bodies with exact wire encodings', async () => {
  const { lab, certificate, rune, changes, commands } = owner(), secret = Buffer.alloc(32, 93), hash = Buffer.alloc(32, 44), address = Buffer.alloc(32, 55);
  wire.reply = { r_hash: hash.toString('base64'), payment_addr: address.toString('base64'), payment_request: 'disposable-regtest-invoice' };
  expect(await lndInvoice(lab, 'lnd-r', 30_000_001n, secret.toString('hex'))).toEqual({ r_hash: hash.toString('hex'), payment_addr: address.toString('hex'), payment_request: 'disposable-regtest-invoice' });
  expect(wire.requests[0]?.options).toMatchObject({ path: '/v1/invoices', method: 'POST', ca: certificate, rejectUnauthorized: true });
  expect(JSON.parse(wire.requests[0]?.body ?? '') as unknown).toEqual({ value_msat: '30000001', r_preimage: secret.toString('base64') });
  wire.status = 201; wire.reply = { payment_hash: hash.toString('hex') };
  expect(await clnInvoice(lab, 30_000_001n, 'test-invoice', 'disposable regtest', secret.toString('hex'))).toEqual(wire.reply);
  expect(wire.requests[1]?.options).toMatchObject({ path: '/v1/invoice', method: 'POST', servername: 'localhost', ca: certificate, rejectUnauthorized: true, headers: { rune: rune.toString('utf8') } });
  expect(JSON.parse(wire.requests[1]?.body ?? '') as unknown).toEqual({ amount_msat: 30_000_001, label: 'test-invoice', description: 'disposable regtest', preimage: secret.toString('hex') });
  expect(changes).toEqual([]); expect(commands).not.toHaveBeenCalled();
});

// Exact JSON integers stop at 2^53 - 1; refusal must precede any transport or CLI effect.
it.each([9_007_199_254_740_992n, 9_007_199_254_740_993n, 18_446_744_073_709_551_615n])('CP-010/B2 CLN invoice amount %s above the exact integer range refuses before effects', async amount => {
  const { lab, changes, commands } = owner();
  wire.status = 201;
  await expect(clnInvoice(lab, amount, 'unsafe-integer', 'disposable regtest', '5d'.repeat(32))).rejects.toThrow(LabInvalidError);
  expect(wire.requests).toEqual([]);
  expect(changes).toEqual([]);
  expect(commands).not.toHaveBeenCalled();
});

it('CP-010/B2 CLN invoice accepts the greatest exact JSON integer without rounding', async () => {
  const { lab, commands } = owner();
  wire.status = 201; wire.reply = { payment_hash: '2c'.repeat(32) };
  expect(await clnInvoice(lab, 9_007_199_254_740_991n, 'safe-boundary', 'disposable regtest', '5d'.repeat(32))).toEqual(wire.reply);
  expect(wire.requests).toHaveLength(1);
  expect(wire.requests[0]?.body).toContain('"amount_msat":9007199254740991');
  expect(commands).not.toHaveBeenCalled();
});
