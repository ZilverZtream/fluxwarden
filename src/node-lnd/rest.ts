// Adapted from ZilverZtream/macwarden examples/payment-lab/src/lnd/rest.ts (25bbfa4).
import { closeSync, fstatSync, openSync, readSync } from 'node:fs';
import { request } from 'node:https';
import { createHash } from 'node:crypto';
import type { ClientRequest, IncomingMessage } from 'node:http';
import type { Socket } from 'node:net';
import { ProtocolError, transportFailure, TransportError, type TransportPhase } from '../core/errors.js';
import type { JsonObject } from '../core/json.js';
import { revealSecret, Secret } from '../core/secret.js';
import { errorFromBody, LineReader, parseJson, readFrame, type Redact } from './stream.js';

/**
 * A client for LND's REST gateway: one node, one credential, TLS verified against the
 * node's own certificate only. Every answer is size-bounded before it is parsed, because
 * the node or any path in between controls its length.
 */

export const MAX_BODY_BYTES = 16 * 1024 * 1024;
export const MAX_CREDENTIAL_FILE_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_STREAM_CONNECT_TIMEOUT_MS = 10_000;
const KEEPALIVE_MS = 15_000;
const DEFAULT_STREAM_DEADLINE_MS = 300_000;

export interface LndRestOptions {
  host: string;
  port: number;
  tlsCertPath: string;
  macaroonPath: string;
  /** Bound on a unary call, and on a stream until its answer begins (default 30000 ms). */
  timeoutMs?: number;
  /** Bound on the time to a TLS session for a stream; the stream itself is not bounded by it (default 10000 ms). */
  streamConnectTimeoutMs?: number;
  /**
   * Lifetime of one stream (default 300000 ms). There is no unbounded stream: a gateway or
   * proxy that keeps the connection alive but stops forwarding frames would otherwise hold
   * the caller forever (alexbosworth/lightning#133); at the deadline the stream fails as a
   * TransportError and the caller reopens it.
   */
  streamDeadlineMs?: number;
}

export type StreamDecision = 'continue' | 'stop';

/** How a stream ended without an error: the handler stopped it, the server ended it, or the caller's signal aborted it. */
export type StreamEnd = 'stopped' | 'ended' | 'aborted';

export interface CallOptions {
  /** Runs once, when the whole request has been handed to the connection. */
  readonly onWritten?: () => void;
}

export interface LndRest {
  readonly fingerprints?: { readonly credentialFingerprint: string; readonly tlsFingerprint: string };
  call: (method: 'GET' | 'POST', path: string, body?: unknown, options?: CallOptions) => Promise<JsonObject>;
  stream: (method: 'GET' | 'POST', path: string, body: unknown, onMessage: (result: JsonObject) => StreamDecision, signal?: AbortSignal) => Promise<StreamEnd>;
}

/** Reads a credential or certificate file of 1 to 64 KiB, bounded on the open descriptor so a growing file is never read past the limit. */
export function readBoundedFile(path: string, what: string): Buffer {
  const fd = openSync(path, 'r');
  try {
    const limit = `${what} must be between 1 and ${String(MAX_CREDENTIAL_FILE_BYTES)} bytes`;
    if (fstatSync(fd).size > MAX_CREDENTIAL_FILE_BYTES) throw new Error(limit);
    const buffer = Buffer.alloc(MAX_CREDENTIAL_FILE_BYTES + 1);
    let length = 0;
    for (;;) {
      const read = readSync(fd, buffer, length, buffer.length - length, length);
      if (read === 0) break;
      length += read;
      if (length > MAX_CREDENTIAL_FILE_BYTES) throw new Error(limit);
    }
    if (length === 0) throw new Error(limit);
    return Buffer.from(buffer.subarray(0, length));
  } finally {
    closeSync(fd);
  }
}

interface Exchange {
  req: ClientRequest;
  payload: Buffer | undefined;
  phase: () => TransportPhase;
}

/** Collects a bounded body; `done` receives the bytes, or the error that ended the read. */
function readBody(res: IncomingMessage, done: (error: Error | undefined, body?: Buffer) => void): void {
  const chunks: Buffer[] = [];
  let size = 0;
  let over = false;
  res.on('data', (chunk: Buffer) => {
    if (over) return;
    size += chunk.length;
    if (size > MAX_BODY_BYTES) { over = true; done(new ProtocolError(`answer larger than ${String(MAX_BODY_BYTES)} bytes`)); return; }
    chunks.push(chunk);
  });
  res.on('error', () => { done(new TransportError('connection failed while the answer was read', 'response')); });
  res.on('close', () => { if (!res.complete) done(new TransportError('answer ended before it was complete', 'response')); });
  res.on('end', () => { if (!over) done(undefined, Buffer.concat(chunks)); });
}

class LndRestClient implements LndRest {
  readonly fingerprints: { readonly credentialFingerprint: string; readonly tlsFingerprint: string };
  readonly #host: string;
  readonly #port: number;
  readonly #ca: Buffer;
  readonly #macaroon: Secret;
  readonly #timeoutMs: number;
  readonly #streamConnectTimeoutMs: number;
  readonly #streamDeadlineMs: number;
  readonly #redact: Redact;

  constructor(options: LndRestOptions, ca: Buffer, macaroon: Secret) {
    this.fingerprints = { credentialFingerprint: macaroon.fingerprint, tlsFingerprint: createHash('sha256').update(ca).digest('hex') };
    this.#host = options.host;
    this.#port = options.port;
    this.#ca = ca;
    this.#macaroon = macaroon;
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#streamConnectTimeoutMs = options.streamConnectTimeoutMs ?? DEFAULT_STREAM_CONNECT_TIMEOUT_MS;
    this.#streamDeadlineMs = options.streamDeadlineMs ?? DEFAULT_STREAM_DEADLINE_MS;
    this.#redact = text => macaroon.redact(text);
  }

  #open(method: string, path: string, body: unknown, onWritten?: () => void): Exchange {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), 'utf8');
    let secure = false;
    let written = false;
    const req = request({
      host: this.#host,
      port: this.#port,
      method,
      path,
      ca: this.#ca,
      // Explicit, so an inherited NODE_TLS_REJECT_UNAUTHORIZED=0 cannot turn verification off.
      rejectUnauthorized: true,
      agent: false,
      headers: {
        'Grpc-Metadata-macaroon': Buffer.from(revealSecret(this.#macaroon)).toString('hex'),
        Accept: 'application/json',
        ...(payload === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': String(payload.length) }),
      },
    });
    req.on('socket', (socket: Socket) => {
      socket.setKeepAlive(true, KEEPALIVE_MS);
      socket.once('secureConnect', () => { secure = true; });
    });
    req.on('finish', () => {
      written = true;
      onWritten?.();
    });
    return { req, payload, phase: () => (!secure ? 'connect' : written ? 'response' : 'request') };
  }

  #answer(status: number | undefined, body: Buffer): JsonObject {
    const parsed = parseJson(body);
    if (status !== 200) throw errorFromBody(parsed, status, this.#redact);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new ProtocolError('answer is not a JSON object');
    return parsed as JsonObject;
  }

  call(method: 'GET' | 'POST', path: string, body?: unknown, options: CallOptions = {}): Promise<JsonObject> {
    const exchange = this.#open(method, path, body, options.onWritten);
    const { req } = exchange;
    return new Promise<JsonObject>((resolve, reject) => {
      let settled = false;
      let responded = false;
      const finish = (error: Error | undefined, value?: JsonObject): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error !== undefined || value === undefined) { req.destroy(); reject(error ?? new ProtocolError('no answer')); } else resolve(value);
      };
      const timer = setTimeout(() => {
        finish(new TransportError(`no complete answer within ${String(this.#timeoutMs)} ms`, exchange.phase()));
      }, this.#timeoutMs);
      // Registered first: finish() destroys the request, which emits an error of its own.
      req.on('error', error => { finish(transportFailure(error, exchange.phase())); });
      req.on('response', (res: IncomingMessage) => {
        responded = true;
        readBody(res, (error, bytes) => {
          if (error !== undefined || bytes === undefined) { finish(error); return; }
          try { finish(undefined, this.#answer(res.statusCode, bytes)); } catch (failure) { finish(failure as Error); }
        });
      });
      req.on('close', () => {
        if (!responded) { finish(new TransportError('connection closed before an answer', exchange.phase())); return; }
        setImmediate(() => { finish(new TransportError('connection closed before the answer was read', 'response')); });
      });
      req.end(exchange.payload);
    });
  }

  /**
   * A server-streaming call. Resolves with how it ended: `stopped` when the handler returned
   * `stop`, `ended` when the server finished the stream first (no terminal update was seen),
   * `aborted` when the caller's signal fired. Rejects with LndError for an error frame and
   * with TransportError when the connection ends any other way or the stream deadline
   * passes. TCP keepalive notices a vanished peer; the deadline bounds a silent one.
   */
  stream(method: 'GET' | 'POST', path: string, body: unknown, onMessage: (result: JsonObject) => StreamDecision, signal?: AbortSignal): Promise<StreamEnd> {
    const exchange = this.#open(method, path, body);
    const { req } = exchange;
    return new Promise<StreamEnd>((resolve, reject) => {
      let settled = false;
      let responded = false;
      const finish = (outcome: Error | StreamEnd): void => {
        if (settled) return;
        settled = true;
        clearTimeout(connectTimer);
        clearTimeout(answerTimer);
        clearTimeout(deadline);
        signal?.removeEventListener('abort', onAbort);
        req.destroy();
        if (outcome instanceof Error) reject(outcome); else resolve(outcome);
      };
      const connectTimer = setTimeout(() => {
        if (exchange.phase() === 'connect') finish(new TransportError(`no TLS session within ${String(this.#streamConnectTimeoutMs)} ms`, 'connect'));
      }, this.#streamConnectTimeoutMs);
      const answerTimer = setTimeout(() => {
        if (!responded) finish(new TransportError(`no answer within ${String(this.#timeoutMs)} ms`, exchange.phase()));
      }, this.#timeoutMs);
      const deadline = setTimeout(() => {
        finish(new TransportError(`stream deadline of ${String(this.#streamDeadlineMs)} ms passed`, exchange.phase()));
      }, this.#streamDeadlineMs);
      const onAbort = (): void => { finish('aborted'); };
      req.on('error', error => { finish(transportFailure(error, exchange.phase())); });
      if (signal?.aborted === true) { onAbort(); return; }
      signal?.addEventListener('abort', onAbort, { once: true });
      req.on('response', (res: IncomingMessage) => {
        responded = true;
        clearTimeout(answerTimer);
        if (res.statusCode !== 200) {
          readBody(res, (error, bytes) => {
            if (error !== undefined || bytes === undefined) { finish(error ?? new ProtocolError('no answer')); return; }
            finish(errorFromBody(parseJson(bytes), res.statusCode, this.#redact));
          });
          return;
        }
        const lines = new LineReader(MAX_BODY_BYTES);
        const handle = (line: Buffer): boolean => {
          if (settled) return false;
          if (line.toString('utf8').trim() === '') return true;
          try {
            if (onMessage(readFrame(line, this.#redact)) === 'stop') { finish('stopped'); return false; }
          } catch (error) {
            finish(error instanceof Error ? error : new ProtocolError('stream handler failed'));
            return false;
          }
          return true;
        };
        res.on('data', (chunk: Buffer) => {
          if (settled) return;
          try { lines.push(chunk, handle); } catch (error) { finish(error as Error); }
        });
        res.on('error', () => { finish(new TransportError('connection failed during the stream', 'response')); });
        res.on('close', () => {
          if (settled) return;
          if (!res.complete) { finish(new TransportError('stream closed before the server ended it', 'response')); return; }
          const rest = lines.end();
          if (rest !== undefined) handle(rest);
          finish('ended');
        });
      });
      req.on('close', () => {
        if (!responded) { finish(new TransportError('connection closed before an answer', exchange.phase())); return; }
        setImmediate(() => { finish(new TransportError('connection closed before the stream settled', 'response')); });
      });
      req.end(exchange.payload);
    });
  }
}

/** Reads the certificate and the macaroon by path before any connection; the macaroon is kept only inside a Secret. */
export function openLndRest(options: LndRestOptions): Promise<LndRest> {
  try {
    for (const [name, value] of [['timeoutMs', options.timeoutMs], ['streamConnectTimeoutMs', options.streamConnectTimeoutMs], ['streamDeadlineMs', options.streamDeadlineMs]] as const) {
      if (value !== undefined && (!Number.isSafeInteger(value) || value <= 0)) throw new RangeError(`${name} must be a positive integer`);
    }
    const ca = readBoundedFile(options.tlsCertPath, 'TLS certificate');
    const macaroon = new Secret(readBoundedFile(options.macaroonPath, 'macaroon'));
    return Promise.resolve(new LndRestClient(options, ca, macaroon));
  } catch (error) {
    return Promise.reject(error instanceof Error ? error : new Error('credential files could not be read'));
  }
}

