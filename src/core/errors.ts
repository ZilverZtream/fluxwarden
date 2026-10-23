// Adapted from ZilverZtream/macwarden examples/payment-lab/src/lnd/errors.ts (25bbfa4).
/**
 * Three ways an RPC can end without a result. The distinction decides what the
 * caller may conclude:
 *
 * - LndError: LND answered. The answer is definite (for example "not found").
 * - TransportError in phase `connect`: no connection was established, so the
 *   request never reached LND.
 * - TransportError in any later phase, and ProtocolError: the request may have
 *   reached LND and the outcome is unknown. For a payment this is never a
 *   failure; the record stays unresolved until LND reports a terminal state.
 */

const NOT_FOUND = 5;

/** HTTP statuses that a gateway or proxy in front of LND produces when the call was cut off, whatever the body says. */
const AMBIGUOUS_HTTP: ReadonlySet<number> = new Set([408, 499, 502, 503, 504]);

export class LndError extends Error {
  readonly grpcCode: number | undefined;
  readonly httpStatus: number | undefined;

  constructor(message: string, grpcCode: number | undefined, httpStatus: number | undefined) {
    super(message);
    this.name = 'LndError';
    this.grpcCode = grpcCode;
    this.httpStatus = httpStatus;
  }

  /**
   * LND itself answered NotFound: gRPC code 5 with a native lookup HTTP status. LND's REST gateway
   * (grpc-gateway) always sends the gRPC code with its error body (`{"code":5,"message":...}`).
   * A 404 without a code, bodiless or with a body such as `{"message":"Not Found"}` (an API
   * gateway) or `{"message":"no Route matched with those values"}` (Kong), comes from a proxy
   * or a wrong path in front of LND and proves nothing about the payment or invoice, so it is
   * not NotFound (the caller treats it as unknown), and definiteRefusal treats it as ambiguous.
   */
  get notFound(): boolean {
    return this.grpcCode === NOT_FOUND && (this.httpStatus === undefined || this.httpStatus === 200 || this.httpStatus === 404);
  }
}

export type TransportPhase = 'connect' | 'request' | 'response';

export class TransportError extends Error {
  readonly phase: TransportPhase;

  constructor(message: string, phase: TransportPhase, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'TransportError';
    this.phase = phase;
  }

  /** True when the request bytes can not have reached LND. */
  get notDelivered(): boolean {
    return this.phase === 'connect';
  }
}

/** The node's certificate or host name failed verification against the pinned certificate; nothing was sent. */
export class TlsError extends TransportError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, 'connect', options);
    this.name = 'TlsError';
  }
}

/** The node or a proxy in front of it refused the credential (HTTP 401 or 403). */
export class AuthError extends Error {
  readonly httpStatus: number | undefined;
  /** CLN error code from the body: 1501 missing rune, 1502 invalid rune. */
  readonly code: number | undefined;

  constructor(message: string, httpStatus?: number, code?: number) {
    super(message);
    this.name = 'AuthError';
    this.httpStatus = httpStatus;
    this.code = code;
  }
}

/** lightningd answered a JSON-RPC error through clnrest. */
export class ClnError extends Error {
  readonly code: number | undefined;
  readonly httpStatus: number;

  constructor(message: string, code?: number, httpStatus = 500) {
    super(message);
    this.name = 'ClnError';
    this.code = code;
    this.httpStatus = httpStatus;
  }
}

/**
 * Error codes Node.js gives a failed certificate or host name verification: the OpenSSL
 * X509 verification results (tls.connect, `authorizationError`) and the host name check.
 */
const TLS_VERIFICATION_CODES: ReadonlySet<string> = new Set([
  'UNABLE_TO_GET_ISSUER_CERT', 'UNABLE_TO_GET_CRL', 'UNABLE_TO_DECRYPT_CERT_SIGNATURE', 'UNABLE_TO_DECRYPT_CRL_SIGNATURE',
  'UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY', 'CERT_SIGNATURE_FAILURE', 'CRL_SIGNATURE_FAILURE', 'CERT_NOT_YET_VALID', 'CERT_HAS_EXPIRED',
  'CRL_NOT_YET_VALID', 'CRL_HAS_EXPIRED', 'ERROR_IN_CERT_NOT_BEFORE_FIELD', 'ERROR_IN_CERT_NOT_AFTER_FIELD',
  'ERROR_IN_CRL_LAST_UPDATE_FIELD', 'ERROR_IN_CRL_NEXT_UPDATE_FIELD', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_CHAIN_TOO_LONG', 'CERT_REVOKED', 'INVALID_CA',
  'PATH_LENGTH_EXCEEDED', 'INVALID_PURPOSE', 'CERT_UNTRUSTED', 'CERT_REJECTED', 'HOSTNAME_MISMATCH', 'ERR_TLS_CERT_ALTNAME_INVALID',
]);

/** Whether a status is a gateway's or proxy's, which never proves what the node did. */
export function ambiguousStatus(status: number | undefined): boolean {
  return status !== undefined && AMBIGUOUS_HTTP.has(status);
}

/**
 * The error for a failed connection or request: a TLS verification failure while
 * connecting is a TlsError, anything else a TransportError in the phase reached. Only the
 * Node.js error code is kept, never the original error, so nothing of the request leaks.
 */
export function transportFailure(error: unknown, phase: TransportPhase): TransportError {
  const code = (error as { code?: unknown } | null)?.code;
  const label = typeof code === 'string' ? code : 'connection error';
  if (phase === 'connect' && isTlsFailureCode(code)) return new TlsError(`TLS verification of the node failed (${label})`);
  return new TransportError(`${label} during ${phase}`, phase);
}

/** Whether a connection error code means the TLS handshake failed rather than the network path. */
export function isTlsFailureCode(code: unknown): boolean {
  if (typeof code !== 'string' || code === 'ERR_TLS_HANDSHAKE_TIMEOUT') return false;
  return TLS_VERIFICATION_CODES.has(code) || code.startsWith('ERR_SSL_') || code.startsWith('ERR_TLS_');
}

export class ProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProtocolError';
  }
}

/**
 * gRPC status codes with which LND itself refuses a call: the request was handled
 * and nothing was created or sent. 2 Unknown is how LND returns most of its own
 * application errors (HTTP 500 from its gateway, for example "invoice with payment
 * hash already exists").
 */
const DEFINITE_REFUSAL_CODES: ReadonlySet<number> = new Set([
  2, // Unknown: an LND application error
  3, // InvalidArgument
  5, // NotFound
  6, // AlreadyExists
  7, // PermissionDenied
  8, // ResourceExhausted (request too large, rate limit inside LND)
  9, // FailedPrecondition
  11, // OutOfRange
  12, // Unimplemented
  16, // Unauthenticated
]);


/**
 * Whether an error from a call that creates something in LND (AddInvoice,
 * AddHoldInvoice, SendPaymentV2) is a definite refusal, which lets a NotFound
 * lookup decide at once that nothing was created. The classes:
 *
 * - not delivered: a TransportError in phase `connect`; the request never left
 *   (handled before this is asked, without a lookup).
 * - definite refusal: an LndError with one of DEFINITE_REFUSAL_CODES from LND's
 *   gateway, or a 400-class response (other than 404, 408 and 499) whose body carries a
 *   message, and in neither case an HTTP status from AMBIGUOUS_HTTP. A 404 without a
 *   gRPC code is a proxy's or a wrong path's answer, not LND's (see notFound).
 * - ambiguous, everything else: gRPC 1 Cancelled, 4 DeadlineExceeded, 10 Aborted,
 *   13 Internal, 14 Unavailable, 15 DataLoss (the call may have been cut off after
 *   LND began handling it); HTTP 408, 499, 502, 503 or 504 from a gateway or proxy;
 *   a 404 without a gRPC code; a 5xx without an LND body; a TransportError after the connection was
 *   established; a ProtocolError (an unreadable answer); any other error. A lookup
 *   that finds nothing then is only a point-in-time absence: the receiver keeps the
 *   invoice `creating` until its creation window has passed, the payer keeps the
 *   payment `uncertain` for reconciliation.
 */
export function definiteRefusal(error: unknown): boolean {
  if (!(error instanceof LndError)) return false;
  const status = error.httpStatus;
  if (status !== undefined && AMBIGUOUS_HTTP.has(status)) return false;
  if (error.grpcCode !== undefined) return DEFINITE_REFUSAL_CODES.has(error.grpcCode);
  // No gRPC code: only a 400-class answer with a message from the body (not the client's "HTTP <status>" stand-in),
  // and never a 404: LND's own NotFound carries code 5, so a 404 without one is a proxy's or a wrong path's.
  return status !== undefined && status >= 400 && status < 500 && status !== 404 && error.message !== `HTTP ${String(status)}`;
}

export function describeError(error: unknown): string {
  if (error instanceof LndError) return `LND error${error.grpcCode === undefined ? '' : ` (gRPC code ${String(error.grpcCode)})`}: ${error.message}`;
  if (error instanceof TransportError) return `transport error during ${error.phase}: ${error.message}`;
  if (error instanceof Error) return `${error.name}: ${error.message}`;
  return String(error);
}
