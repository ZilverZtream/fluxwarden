// Local HTTPS servers for adapter tests. Certificates are throwaway fixtures under
// test/fixtures/tls (self-signed with CA:TRUE, as LND's tls.cert and clnrest's generated
// certificate are), never trusted outside the test suite.
import { createServer as createHttpsServer, type Server } from 'node:https';
import { createServer as createTcpServer, type Server as TcpServer, type Socket } from 'node:net';
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { repoRoot } from '../helpers/cli.js';

export type Identity = 'node' | 'other' | 'wrong-host';
export interface TlsMaterial { readonly cert: string | Buffer; readonly key: string | Buffer; readonly certPath: string }

export function certificatePath(identity: Identity): string {
  return join(repoRoot, 'test', 'fixtures', 'tls', `test-only-${identity}.pem`);
}

function keyPath(identity: Identity): string {
  return join(repoRoot, 'test', 'fixtures', 'tls', `test-only-${identity}.key`);
}

export interface RecordedRequest { method: string; url: string; headers: IncomingHttpHeaders; body: string }

export interface FakeServer {
  readonly host: '127.0.0.1';
  readonly port: number;
  readonly requests: RecordedRequest[];
  /** TCP connections accepted, including those that never finish a TLS handshake. */
  connections: () => number;
  close: () => Promise<void>;
}

export type Handler = (request: RecordedRequest, response: ServerResponse, raw: IncomingMessage) => void;

function listen(server: Server | TcpServer): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') { reject(new Error('no port')); return; }
      resolve(address.port);
    });
  });
}

function closer(server: Server | TcpServer, sockets: Set<Socket>): () => Promise<void> {
  return () => new Promise(resolve => {
    for (const socket of sockets) socket.destroy();
    server.close(() => { resolve(); });
  });
}

export async function startHttpsFake(handler: Handler, identity: Identity = 'node', tls?: TlsMaterial): Promise<FakeServer> {
  const requests: RecordedRequest[] = [];
  const sockets = new Set<Socket>();
  let connections = 0;
  // A large header limit, so an oversized credential reaches the handler unless the client refuses it.
  const server = createHttpsServer({ cert: tls?.cert ?? readFileSync(certificatePath(identity)), key: tls?.key ?? readFileSync(keyPath(identity)), maxHeaderSize: 1 << 20 }, (raw, response) => {
    const chunks: Buffer[] = [];
    raw.on('data', (chunk: Buffer) => chunks.push(chunk));
    raw.on('end', () => {
      const request: RecordedRequest = { method: raw.method ?? '', url: raw.url ?? '', headers: raw.headers, body: Buffer.concat(chunks).toString('utf8') };
      requests.push(request);
      handler(request, response, raw);
    });
  });
  server.on('connection', (socket: Socket) => { connections += 1; sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.on('tlsClientError', () => undefined);
  const port = await listen(server);
  return { host: '127.0.0.1', port, requests, connections: () => connections, close: closer(server, sockets) };
}

/** A TCP listener that accepts and immediately resets every connection: no TLS session is ever established. */
export async function startResettingListener(): Promise<FakeServer> {
  const sockets = new Set<Socket>();
  let connections = 0;
  const server = createTcpServer(socket => { connections += 1; socket.on('error', () => undefined); socket.resetAndDestroy(); });
  const port = await listen(server);
  return { host: '127.0.0.1', port, requests: [], connections: () => connections, close: closer(server, sockets) };
}

/** A TCP listener that accepts every connection and never answers: the TLS handshake never completes. */
export async function startSilentListener(): Promise<FakeServer> {
  const sockets = new Set<Socket>();
  let connections = 0;
  const server = createTcpServer(socket => { connections += 1; sockets.add(socket); socket.on('error', () => undefined); socket.on('close', () => sockets.delete(socket)); });
  const port = await listen(server);
  return { host: '127.0.0.1', port, requests: [], connections: () => connections, close: closer(server, sockets) };
}

/** A port on which nothing listens (bound once, then released). */
export async function closedPort(): Promise<number> {
  const server = createTcpServer();
  const port = await listen(server);
  await new Promise<void>(resolve => { server.close(() => { resolve(); }); });
  return port;
}
