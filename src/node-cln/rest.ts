// Adapted from src/node-lnd/rest.ts, itself adapted from ZilverZtream/macwarden examples/payment-lab/src/lnd/rest.ts (25bbfa4).
import { closeSync, fstatSync, openSync, readSync } from 'node:fs';
import { request } from 'node:https';
import { createHash, X509Certificate } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import type { IncomingMessage } from 'node:http';
import type { Socket } from 'node:net';
import { AuthError, ClnError, ProtocolError, transportFailure, TransportError, type TransportPhase } from '../core/errors.js';
import type { JsonObject } from '../core/json.js';
import { revealSecret, Secret } from '../core/secret.js';
import { admitRune, runeCadence, type CadenceAdmission, type RuneCadence } from './cadence.js';

/**
 * A client for Core Lightning's clnrest plugin (Rust, v25.02 and later): every command is
 * `POST /v1/<method>` with a JSON object body and the `rune` header, answered with 201 and
 * the result object, or with an error status and lightningd's `{code, message, data}`
 * (plugins/rest-plugin/src/handlers.rs, shared.rs at v26.06.9). TLS trusts only the
 * pinned certificate, and every answer is size-bounded before it is parsed.
 */

export const MAX_BODY_BYTES = 16 * 1024 * 1024;
export const MAX_CREDENTIAL_FILE_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
const KEEPALIVE_MS = 15_000;
const MAX_MESSAGE_CHARS = 1000;
const METHOD = /^[a-z0-9][a-z0-9_-]*$/;

export interface ClnRestOptions {
  host: string;
  port: number;
  tlsCertPath: string;
  runePath: string;
  /** The output owner registers the credential without obtaining its bytes. */
  onSecret?: (secret: Secret) => void;
  /** Bound on one call (default 30000 ms). */
  timeoutMs?: number;
}

export interface CallOptions {
  /** Runs once, when the whole request has been handed to the connection. */
  readonly onWritten?: () => void;
}

export interface ClnRest {
  readonly fingerprints?: { readonly credentialFingerprint: string; readonly tlsFingerprint: string };
  call: (method: string, params?: Record<string, unknown>, options?: CallOptions) => Promise<JsonObject>;
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

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseJson(bytes: Buffer): unknown {
  try {
    return JSON.parse(bytes.toString('utf8')) as unknown;
  } catch {
    return undefined;
  }
}

class ClnRestClient implements ClnRest {
  readonly fingerprints: { readonly credentialFingerprint: string; readonly tlsFingerprint: string };
  readonly #host: string;
  readonly #port: number;
  readonly #ca: Buffer;
  readonly #rune: Secret;
  readonly #timeoutMs: number;
  readonly #cadence: RuneCadence | undefined;

  constructor(options: ClnRestOptions, ca: Buffer, rune: Secret) {
    this.fingerprints = { credentialFingerprint: rune.fingerprint, tlsFingerprint: createHash('sha256').update(ca).digest('hex') };
    this.#host = options.host;
    this.#port = options.port;
    this.#ca = ca;
    this.#rune = rune;
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    let certificateIdentity = this.fingerprints.tlsFingerprint;
    try {
      // Node's X509Certificate fingerprint256 hashes DER, independent of PEM line endings.
      // https://nodejs.org/api/crypto.html#x509fingerprint256
      certificateIdentity = new X509Certificate(ca).fingerprint256;
    } catch { /* Keep invalid certificate handling in the unchanged TLS transport. */ }
    this.#cadence = runeCadence(revealSecret(rune), certificateIdentity);
  }

  #text(text: string): string {
    const clean = this.#rune.redact(text);
    return clean.length > MAX_MESSAGE_CHARS ? `${clean.slice(0, MAX_MESSAGE_CHARS)}...` : clean;
  }

  #answer(status: number | undefined, bytes: Buffer): JsonObject {
    const parsed = parseJson(bytes);
    if (status === 201) {
      if (!isObject(parsed)) throw new ProtocolError('answer is not a JSON object');
      return parsed;
    }
    const body = isObject(parsed) ? parsed : {};
    const message = typeof body['message'] === 'string' ? this.#text(body['message']) : `HTTP ${String(status ?? 0)}`;
    const code = typeof body['code'] === 'number' && Number.isSafeInteger(body['code']) ? body['code'] : undefined;
    if (status === 401 || status === 403) throw new AuthError(message, status, code);
    if (status !== undefined && status >= 200 && status < 300) throw new ProtocolError(`unexpected status ${String(status)}`);
    throw new ClnError(message, code, status ?? 0);
  }

  async call(method: string, params: Record<string, unknown> = {}, options: CallOptions = {}): Promise<JsonObject> {
    if (!METHOD.test(method)) return Promise.reject(new RangeError('invalid CLN method name'));
    const deadline = performance.now() + this.#timeoutMs;
    const payload = Buffer.from(JSON.stringify(params), 'utf8');
    const admission = this.#cadence === undefined ? undefined : await admitRune(this.#cadence, deadline);
    try {
      if (performance.now() >= deadline) throw new TransportError('CLN permission admission exceeded the call deadline', 'connect');
      return await this.#dispatch(method, payload, options, deadline, admission);
    } finally { admission?.done(); }
  }

  #dispatch(method: string, payload: Buffer, options: CallOptions, deadline: number, admission: CadenceAdmission | undefined): Promise<JsonObject> {
    const connectingAt = performance.now();
    let secure = false;
    let written = false;
    const phase = (): TransportPhase => (!secure ? 'connect' : written ? 'response' : 'request');
    const req = request({
      host: this.#host,
      port: this.#port,
      method: 'POST',
      path: `/v1/${method}`,
      ca: this.#ca,
      // Explicit, so an inherited NODE_TLS_REJECT_UNAUTHORIZED=0 cannot turn verification off.
      rejectUnauthorized: true,
      agent: false,
      headers: {
        rune: Buffer.from(revealSecret(this.#rune)).toString('utf8'),
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'Content-Length': String(payload.length),
      },
    });
    req.on('socket', (socket: Socket) => {
      socket.setKeepAlive(true, KEEPALIVE_MS);
      socket.once('secureConnect', () => { secure = true; });
    });
    req.on('finish', () => {
      written = true;
      admission?.written(performance.now() - connectingAt);
      options.onWritten?.();
    });
    return new Promise<JsonObject>((resolve, reject) => {
      let settled = false;
      let responded = false;
      const finish = (error: Error | undefined, value?: JsonObject): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error !== undefined || value === undefined) { req.destroy(); reject(error ?? new ProtocolError('no answer')); } else resolve(value);
      };
      const timer = setTimeout(() => { finish(new TransportError(`no complete answer within ${String(this.#timeoutMs)} ms`, phase())); }, Math.max(1, Math.ceil(deadline - performance.now())));
      // Registered first: finish() destroys the request, which emits an error of its own.
      req.on('error', error => { finish(transportFailure(error, phase())); });
      req.on('response', (res: IncomingMessage) => {
        responded = true;
        if (res.statusCode !== 401 && res.statusCode !== 403) admission?.answered();
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (chunk: Buffer) => {
          if (settled) return;
          size += chunk.length;
          if (size > MAX_BODY_BYTES) { finish(new ProtocolError(`answer larger than ${String(MAX_BODY_BYTES)} bytes`)); return; }
          chunks.push(chunk);
        });
        res.on('error', () => { finish(new TransportError('connection failed while the answer was read', 'response')); });
        res.on('close', () => { if (!res.complete) finish(new TransportError('answer ended before it was complete', 'response')); });
        res.on('end', () => {
          if (settled) return;
          try { finish(undefined, this.#answer(res.statusCode, Buffer.concat(chunks))); } catch (failure) { finish(failure as Error); }
        });
      });
      req.on('close', () => {
        if (!responded) { finish(new TransportError('connection closed before an answer', phase())); return; }
        setImmediate(() => { finish(new TransportError('connection closed before the answer was read', 'response')); });
      });
      req.end(payload);
    });
  }
}

/** Reads the certificate and the rune by path before any connection; the rune (trimmed text) is kept only inside a Secret. */
export function openClnRest(options: ClnRestOptions): Promise<ClnRest> {
  try {
    if (options.timeoutMs !== undefined && (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs <= 0)) throw new RangeError('timeoutMs must be a positive integer');
    const ca = readBoundedFile(options.tlsCertPath, 'TLS certificate');
    const rune = readBoundedFile(options.runePath, 'rune').toString('utf8').trim();
    if (rune === '' || !/^[\x21-\x7e]+$/.test(rune)) throw new Error('rune file must hold one rune');
    const secret = new Secret(Buffer.from(rune, 'utf8'));
    options.onSecret?.(secret);
    return Promise.resolve(new ClnRestClient(options, ca, secret));
  } catch (error) {
    return Promise.reject(error instanceof Error ? error : new Error('credential files could not be read'));
  }
}

/** HTTP statuses a proxy or gateway in front of clnrest produces when a call was cut off, whatever the body says. */
const AMBIGUOUS_HTTP: ReadonlySet<number> = new Set([408, 499, 502, 503, 504]);

/**
 * Whether lightningd itself answered the call with a JSON-RPC error: a ClnError carrying lightningd's error code and
 * no gateway status. Anything else (a proxy error, a 500 without a code, a cut) leaves the outcome unknown.
 */
export function lightningdRefused(error: unknown): error is ClnError {
  return error instanceof ClnError && error.code !== undefined && !AMBIGUOUS_HTTP.has(error.httpStatus);
}
