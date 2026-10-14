import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import { repoRoot } from './cli.js';

// Public interfaces of the extracted helpers. Loading inside each case preserves individual failure evidence.
export async function loadCore<T>(name: string): Promise<T> {
  return await import(pathToFileURL(join(repoRoot, 'src/core', `${name}.ts`)).href) as T;
}

export interface Money {
  parseMsat(text: string): bigint;
  msatToString(amount: bigint): string;
  hopFee(amount: bigint, base: bigint, ppm: bigint): bigint;
  routePpm(fee: bigint, principal: bigint): bigint;
  satToMsat(sat: bigint): bigint;
  formatMsat(amount: bigint): string;
  parseAmount(text: string, what: string): bigint;
  saturateInt64(amount: bigint): bigint;
}

export interface Readers {
  asObject(value: unknown, what: string): Record<string, unknown>;
  optionalObject(source: Record<string, unknown>, key: string): Record<string, unknown> | undefined;
  string(source: Record<string, unknown>, key: string): string;
  boolean(source: Record<string, unknown>, key: string): boolean;
  integer(source: Record<string, unknown>, key: string): bigint;
  checkedNonNegative(value: bigint, what: string): bigint;
  identifier(source: Record<string, unknown>, key: string): string;
  smallInteger(source: Record<string, unknown>, key: string): number;
  array(source: Record<string, unknown>, key: string): unknown[];
  enumName(source: Record<string, unknown>, key: string, names: readonly string[]): string;
}

export interface Errors {
  LndError: new (message: string, grpcCode: number | undefined, httpStatus: number | undefined) => Error & { notFound: boolean };
  TransportError: new (message: string, phase: 'connect' | 'request' | 'response', options?: { cause?: unknown }) => Error & { notDelivered: boolean };
  ProtocolError: new (message: string) => Error;
  definiteRefusal(error: unknown): boolean;
  describeError(error: unknown): string;
}

export interface Encoding {
  assertHash(value: string, what?: string): string;
  base64ToHex(value: string): string;
  hexToBase64(value: string): string;
  hexToUrlParam(value: string): string;
  sha256Hex(value: string): string;
  presentPreimage(value: string): string | undefined;
}

export interface Bolt11 {
  bolt11PaymentHash(paymentRequest: string): string | undefined;
  damagedPaymentRequest(paymentRequest: string): boolean;
}
