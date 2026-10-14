// Adapted from ZilverZtream/macwarden examples/payment-lab/src/lnd/rest.ts (25bbfa4): lndErrorFrom and the stream line handling.
import { AuthError, LndError, ProtocolError } from '../core/errors.js';
import type { JsonObject } from '../core/json.js';

/**
 * Envelopes of LND's REST gateway (grpc-gateway v2.16.0). A unary answer is the message
 * itself or a `google.rpc.Status` body `{code, message, details}`; a server stream is one
 * JSON object per line, `{"result": message}` or `{"error": status}` (runtime/handler.go
 * ForwardResponseStream). The send and track endpoints also answer `{code, message}` in a
 * stream (lnd#6751), so that form is read as an error frame too.
 */

/**
 * LND refuses a macaroon with plain errors that reach the gateway as gRPC 2 Unknown, HTTP 500
 * (macaroons/service.go ValidateMacaroon and CheckMacAuth, rpcperms/interceptor.go
 * checkMacaroon): "expected 1 macaroon, got 0", "verification failed: ...", "permission
 * denied", "cannot get macaroon: ...". Those answers, matched from the start of the text, are
 * credential failures, not refusals.
 */
const MACAROON_REFUSAL = /^(?:expected 1 macaroon, got 0|verification failed|permission denied|cannot get macaroon|unable to get macaroon|failed to decode macaroon|invalid macaroon)/;

/** Longest error text kept from a peer; the rest is display noise and can carry anything. */
const MAX_MESSAGE_CHARS = 1000;

export type Redact = (text: string) => string;

export function peerText(text: string, redact: Redact): string {
  const clean = redact(text);
  return clean.length > MAX_MESSAGE_CHARS ? `${clean.slice(0, MAX_MESSAGE_CHARS)}...` : clean;
}

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function integerField(body: JsonObject, key: string): number | undefined {
  const value = body[key];
  return typeof value === 'number' && Number.isSafeInteger(value) ? value : undefined;
}

/**
 * The error for an answer that is not a result. `httpStatus` is the status the transport
 * saw (undefined for a frame inside a 200 stream) and always wins over a body's
 * `http_code`: a proxy's 502 relaying LND's body is the proxy's answer, not LND's.
 */
export function errorFromBody(body: unknown, httpStatus: number | undefined, redact: Redact): LndError | AuthError {
  const inner = isObject(body) && isObject(body['error']) ? body['error'] : body;
  const fields = isObject(inner) ? inner : {};
  const text = typeof fields['message'] === 'string' ? peerText(fields['message'], redact) : undefined;
  const code = integerField(fields, 'code') ?? integerField(fields, 'grpc_code');
  if (httpStatus === 401 || httpStatus === 403) return new AuthError(text ?? `HTTP ${String(httpStatus)}`, httpStatus, code);
  const raw = typeof fields['message'] === 'string' ? fields['message'] : '';
  if (httpStatus === 500 && code === 2 && MACAROON_REFUSAL.test(raw)) return new AuthError(text ?? 'macaroon refused', httpStatus, code);
  return new LndError(text ?? `HTTP ${httpStatus === undefined ? 'error' : String(httpStatus)}`, code, httpStatus);
}

export function parseJson(bytes: Buffer): unknown {
  try {
    return JSON.parse(bytes.toString('utf8')) as unknown;
  } catch {
    return undefined;
  }
}

/** One line of a 200 stream: the message of a result frame, or the error of an error frame. */
export function readFrame(line: Buffer, redact: Redact): JsonObject {
  const parsed = parseJson(line);
  if (!isObject(parsed)) throw new ProtocolError('stream line is not a JSON object');
  if (parsed['error'] !== undefined && parsed['error'] !== null) throw errorFromBody(parsed, undefined, redact);
  if ('result' in parsed) {
    const result = parsed['result'];
    if (!isObject(result)) throw new ProtocolError('stream result is not an object');
    return result;
  }
  if (typeof parsed['code'] === 'number' && typeof parsed['message'] === 'string') throw errorFromBody(parsed, undefined, redact);
  throw new ProtocolError('stream line is neither a result nor an error');
}

/**
 * Splits a byte stream into newline-terminated lines, each at most `limit` bytes without
 * its newline. Bytes are joined before decoding, so a character split across chunks
 * survives.
 */
export class LineReader {
  readonly #limit: number;
  #parts: Buffer[] = [];
  #size = 0;

  constructor(limit: number) {
    this.#limit = limit;
  }

  #check(size: number): void {
    if (size > this.#limit) throw new ProtocolError(`stream line larger than ${String(this.#limit)} bytes`);
  }

  /** Hands every completed line to `onLine` until it returns false; throws ProtocolError for an oversized line. */
  push(chunk: Buffer, onLine: (line: Buffer) => boolean): void {
    let start = 0;
    for (let index = chunk.indexOf(0x0a); index !== -1; index = chunk.indexOf(0x0a, start)) {
      const piece = chunk.subarray(start, index);
      this.#check(this.#size + piece.length);
      const line = this.#size === 0 ? piece : Buffer.concat([...this.#parts, piece]);
      this.#parts = [];
      this.#size = 0;
      start = index + 1;
      if (!onLine(line)) return;
    }
    if (start >= chunk.length) return;
    const rest = chunk.subarray(start);
    this.#check(this.#size + rest.length);
    this.#parts.push(Buffer.from(rest));
    this.#size += rest.length;
  }

  /** The unterminated last line, if any. */
  end(): Buffer | undefined {
    if (this.#size === 0) return undefined;
    const line = Buffer.concat(this.#parts);
    this.#parts = [];
    this.#size = 0;
    return line;
  }
}
