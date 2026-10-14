import { ProtocolError } from '../core/errors.js';
import { sha256Hex } from '../core/encoding.js';
import type { JsonObject } from '../core/json.js';

/**
 * Core Lightning v26.06 answers read into typed values, field by field after
 * doc/schemas/<method>.json. A required field that is missing or of the wrong type is a
 * ProtocolError; an optional one reads as null. Amounts are JSON safe integers or
 * "<digits>msat" strings (some interfaces render msat that way, cln#9283), always bigint.
 */

const INT64_MAX = 2n ** 63n - 1n;
const UINT64_MAX = 2n ** 64n - 1n;

function present(source: JsonObject, key: string): boolean {
  return source[key] !== undefined && source[key] !== null;
}

function missing(key: string): never {
  throw new ProtocolError(`${key} is missing`);
}

export function asObject(value: unknown, what: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ProtocolError(`${what} is not an object`);
  return value as JsonObject;
}

export function optionalString(source: JsonObject, key: string): string | null {
  if (!present(source, key)) return null;
  const value = source[key];
  if (typeof value !== 'string') throw new ProtocolError(`${key} is not a string`);
  return value;
}

export function text(source: JsonObject, key: string): string {
  return optionalString(source, key) ?? missing(key);
}

function optionalBoolean(source: JsonObject, key: string): boolean | null {
  if (!present(source, key)) return null;
  const value = source[key];
  if (typeof value !== 'boolean') throw new ProtocolError(`${key} is not a boolean`);
  return value;
}

function flag(source: JsonObject, key: string): boolean {
  return optionalBoolean(source, key) ?? missing(key);
}

/** A u16/u32/u64 count, height or time sent as a JSON number. */
function optionalNumber(source: JsonObject, key: string): number | null {
  if (!present(source, key)) return null;
  const value = source[key];
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new ProtocolError(`${key} is not a non-negative integer`);
  return value;
}

export function count(source: JsonObject, key: string): number {
  return optionalNumber(source, key) ?? missing(key);
}

/** An msat amount: a safe integer or "<digits>msat", from 0 to 2^63 - 1. */
function optionalMsat(source: JsonObject, key: string): bigint | null {
  if (!present(source, key)) return null;
  const value = source[key];
  let amount: bigint;
  if (typeof value === 'number' && Number.isSafeInteger(value)) amount = BigInt(value);
  else if (typeof value === 'string' && /^(0|[1-9][0-9]{0,18})msat$/.test(value)) amount = BigInt(value.slice(0, -4));
  else throw new ProtocolError(`${key} is not an msat amount`);
  if (amount < 0n || amount > INT64_MAX) throw new ProtocolError(`${key} is out of range`);
  return amount;
}

export function msat(source: JsonObject, key: string): bigint {
  return optionalMsat(source, key) ?? missing(key);
}

/** A u64 identifier or index as decimal text: a safe integer, or a decimal string beyond 2^53. */
function optionalIdentifier(source: JsonObject, key: string): string | null {
  if (!present(source, key)) return null;
  const value = source[key];
  let parsed: bigint;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) parsed = BigInt(value);
  else if (typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value)) parsed = BigInt(value);
  else throw new ProtocolError(`${key} is not an identifier`);
  if (parsed > UINT64_MAX) throw new ProtocolError(`${key} is out of range`);
  return parsed.toString();
}

function identifier(source: JsonObject, key: string): string {
  return optionalIdentifier(source, key) ?? missing(key);
}

function oneOf<T extends string>(source: JsonObject, key: string, values: readonly T[]): T {
  const value = text(source, key);
  const found = values.find(item => item === value);
  if (found === undefined) throw new ProtocolError(`${key} is not a known value`);
  return found;
}

function hash(source: JsonObject, key: string): string {
  const value = text(source, key);
  if (!/^[0-9a-f]{64}$/.test(value)) throw new ProtocolError(`${key} is not a 32-byte hex hash`);
  return value;
}

export function objects(source: JsonObject, key: string): JsonObject[] {
  const value = source[key];
  if (!Array.isArray(value)) throw new ProtocolError(`${key} is not an array`);
  return value.map((item, index) => asObject(item, `${key}[${String(index)}]`));
}

export function optionalObjects(source: JsonObject, key: string): JsonObject[] {
  return present(source, key) ? objects(source, key) : [];
}

function strings(source: JsonObject, key: string): string[] {
  if (!present(source, key)) return [];
  const value = source[key];
  if (!Array.isArray(value) || !value.every((item): item is string => typeof item === 'string')) throw new ProtocolError(`${key} is not a list of strings`);
  return value;
}

/** Whether a reported preimage proves the payment; the preimage itself is never kept. */
function preimageProves(source: JsonObject, key: string, paymentHash: string): boolean {
  const preimage = optionalString(source, key);
  return preimage !== null && /^[0-9a-f]{64}$/.test(preimage) && sha256Hex(preimage) === paymentHash;
}

/**
 * A lightningd version: releases are v<yy>.<mm>[.<patch>] (common/version.c); builds from
 * git add "-<commits>-g<hash>" and "-modded" (Makefile, git describe --dirty=-modded).
 * Anything else is unknown and refused by the caller.
 */
export function parseClnVersion(raw: string): { year: number; month: number; patch: number } | null {
  const match = /^v([0-9]{2})\.([0-9]{2})(?:\.([0-9]{1,4}))?(?:-[0-9]+-g[0-9a-f]{4,40})?(?:-modded)?$/.exec(raw);
  if (match === null) return null;
  const month = Number(match[2]);
  if (month < 1 || month > 12) return null;
  return { year: Number(match[1]), month, patch: match[3] === undefined ? 0 : Number(match[3]) };
}

export interface ClnInfo {
  id: string; alias: string; version: string; blockheight: number; network: string;
  warningBitcoindSync: string | null; warningLightningdSync: string | null;
}

export interface ClnHtlc {
  direction: 'in' | 'out'; id: string; amountMsat: bigint; expiry: number; paymentHash: string;
  state: string; status: string | null; localTrimmed: boolean;
}

/** listpeerchannels channel states (doc/schemas/listpeerchannels.json at v26.06.9). */
export const CHANNEL_STATES: readonly string[] = [
  'OPENINGD', 'CHANNELD_AWAITING_LOCKIN', 'CHANNELD_NORMAL', 'CHANNELD_SHUTTING_DOWN', 'CLOSINGD_SIGEXCHANGE', 'CLOSINGD_COMPLETE',
  'AWAITING_UNILATERAL', 'FUNDING_SPEND_SEEN', 'ONCHAIN', 'DUALOPEND_OPEN_INIT', 'DUALOPEND_AWAITING_LOCKIN', 'CHANNELD_AWAITING_SPLICE',
  'DUALOPEND_OPEN_COMMITTED', 'DUALOPEND_OPEN_COMMIT_READY',
];

/**
 * States in which the funding transaction is known: from lock-in waiting onward, including
 * splicing, shutdown, closing and on-chain resolution (lightningd/channel_state.h). Only
 * OPENINGD and the dual-funding negotiation states before lock-in can lack it.
 */
const FUNDED_STATES: readonly string[] = [
  'CHANNELD_AWAITING_LOCKIN', 'CHANNELD_NORMAL', 'CHANNELD_SHUTTING_DOWN', 'CLOSINGD_SIGEXCHANGE', 'CLOSINGD_COMPLETE',
  'AWAITING_UNILATERAL', 'FUNDING_SPEND_SEEN', 'ONCHAIN', 'DUALOPEND_AWAITING_LOCKIN', 'CHANNELD_AWAITING_SPLICE',
];

/**
 * Balances and reserves are null only while a channel has no funding transaction yet; a
 * funded channel without them (missing or renamed) is a ProtocolError, never 0.
 * `stateKnown` is false for a state this version does not list; such a channel is never
 * eligible.
 */
export interface ClnPeerChannel {
  peerId: string; peerConnected: boolean; state: string; stateKnown: boolean; shortChannelId: string | null; channelId: string | null;
  fundingTxid: string | null; fundingOutnum: number | null; opener: 'local' | 'remote'; private: boolean;
  totalMsat: bigint | null; toUsMsat: bigint | null; spendableMsat: bigint | null; receivableMsat: bigint | null;
  ourReserveMsat: bigint | null; theirReserveMsat: bigint | null; feeBaseMsat: bigint; feeProportionalMillionths: number;
  minimumHtlcOutMsat: bigint; maximumHtlcOutMsat: bigint; htlcs: ClnHtlc[];
}

export type ClnPaymentStatus = 'pending' | 'complete' | 'failed';
const PAYMENT_STATUSES: readonly ClnPaymentStatus[] = ['pending', 'complete', 'failed'];

export interface ClnSendPay {
  id: string; groupid: string; partid: string; paymentHash: string; status: ClnPaymentStatus;
  amountMsat: bigint | null; amountSentMsat: bigint; createdAt: number; completedAt: number | null;
  label: string | null; destination: string | null; createdIndex: string; preimageMatchesHash: boolean;
}

export interface ClnPay {
  paymentHash: string; status: ClnPaymentStatus; amountMsat: bigint | null; amountSentMsat: bigint | null;
  numberOfParts: number | null; createdAt: number; completedAt: number | null; label: string | null; preimageMatchesHash: boolean;
}

export interface ClnInvoice {
  label: string; paymentHash: string; status: 'unpaid' | 'paid' | 'expired'; amountMsat: bigint | null;
  amountReceivedMsat: bigint | null; expiresAt: number; paidAt: number | null; payIndex: string | null;
  createdIndex: string; description: string | null;
}

export interface ClnAccountEvent {
  account: string; type: 'onchain_fee' | 'chain' | 'channel'; tag: string; creditMsat: bigint; debitMsat: bigint;
  currency: string; timestamp: number; feesMsat: bigint | null; isRebalance: boolean | null; paymentId: string | null; partId: number | null;
}

export interface ClnLayer {
  layer: string; persistent: boolean; disabledNodes: string[]; disabledChannels: string[];
  channelUpdates: { shortChannelIdDir: string; enabled: boolean | null; feeBaseMsat: bigint | null; feeProportionalMillionths: number | null; cltvExpiryDelta: number | null }[];
}

export function parseInfo(body: JsonObject): ClnInfo {
  return {
    id: text(body, 'id'), alias: optionalString(body, 'alias') ?? '', version: text(body, 'version'),
    blockheight: count(body, 'blockheight'), network: text(body, 'network'),
    warningBitcoindSync: optionalString(body, 'warning_bitcoind_sync'), warningLightningdSync: optionalString(body, 'warning_lightningd_sync'),
  };
}

function parseHtlc(body: JsonObject): ClnHtlc {
  return {
    direction: oneOf(body, 'direction', ['in', 'out'] as const), id: identifier(body, 'id'), amountMsat: msat(body, 'amount_msat'),
    expiry: count(body, 'expiry'), paymentHash: hash(body, 'payment_hash'), state: text(body, 'state'),
    status: optionalString(body, 'status'), localTrimmed: optionalBoolean(body, 'local_trimmed') ?? false,
  };
}

/** A channel early in its life has no short_channel_id, channel_id or funding outpoint yet; those read as null. */
export function parsePeerChannel(body: JsonObject): ClnPeerChannel {
  const state = text(body, 'state');
  if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(state)) throw new ProtocolError('state is not a channel state name');
  const funded = present(body, 'funding_txid');
  if (FUNDED_STATES.includes(state) && !funded) throw new ProtocolError(`a channel in ${state} has no funding transaction`);
  const balance = (key: string): bigint | null => funded ? msat(body, key) : optionalMsat(body, key);
  return {
    peerId: text(body, 'peer_id'), peerConnected: flag(body, 'peer_connected'), state, stateKnown: CHANNEL_STATES.includes(state),
    shortChannelId: optionalString(body, 'short_channel_id'), channelId: optionalString(body, 'channel_id'),
    fundingTxid: optionalString(body, 'funding_txid'), fundingOutnum: optionalNumber(body, 'funding_outnum'),
    opener: oneOf(body, 'opener', ['local', 'remote'] as const), private: optionalBoolean(body, 'private') ?? false,
    totalMsat: balance('total_msat'), toUsMsat: balance('to_us_msat'),
    spendableMsat: balance('spendable_msat'), receivableMsat: balance('receivable_msat'),
    ourReserveMsat: balance('our_reserve_msat'), theirReserveMsat: balance('their_reserve_msat'),
    feeBaseMsat: optionalMsat(body, 'fee_base_msat') ?? 0n, feeProportionalMillionths: optionalNumber(body, 'fee_proportional_millionths') ?? 0,
    minimumHtlcOutMsat: optionalMsat(body, 'minimum_htlc_out_msat') ?? 0n, maximumHtlcOutMsat: optionalMsat(body, 'maximum_htlc_out_msat') ?? 0n,
    htlcs: optionalObjects(body, 'htlcs').map(parseHtlc),
  };
}

export function parseSendPay(body: JsonObject): ClnSendPay {
  const paymentHash = hash(body, 'payment_hash');
  return {
    id: identifier(body, 'id'), groupid: identifier(body, 'groupid'), partid: optionalIdentifier(body, 'partid') ?? '0', paymentHash,
    status: oneOf(body, 'status', PAYMENT_STATUSES), amountMsat: optionalMsat(body, 'amount_msat'), amountSentMsat: msat(body, 'amount_sent_msat'),
    createdAt: count(body, 'created_at'), completedAt: optionalNumber(body, 'completed_at'), label: optionalString(body, 'label'),
    destination: optionalString(body, 'destination'), createdIndex: identifier(body, 'created_index'),
    preimageMatchesHash: preimageProves(body, 'payment_preimage', paymentHash),
  };
}

export function parsePay(body: JsonObject): ClnPay {
  const paymentHash = hash(body, 'payment_hash');
  return {
    paymentHash, status: oneOf(body, 'status', PAYMENT_STATUSES), amountMsat: optionalMsat(body, 'amount_msat'),
    amountSentMsat: optionalMsat(body, 'amount_sent_msat'), numberOfParts: optionalNumber(body, 'number_of_parts'),
    createdAt: count(body, 'created_at'), completedAt: optionalNumber(body, 'completed_at'), label: optionalString(body, 'label'),
    preimageMatchesHash: preimageProves(body, 'preimage', paymentHash),
  };
}

/** An invoice without its `payment_preimage`, which is never read. */
export function parseInvoice(body: JsonObject): ClnInvoice {
  return {
    label: text(body, 'label'), paymentHash: hash(body, 'payment_hash'), status: oneOf(body, 'status', ['unpaid', 'paid', 'expired'] as const),
    amountMsat: optionalMsat(body, 'amount_msat'), amountReceivedMsat: optionalMsat(body, 'amount_received_msat'),
    expiresAt: count(body, 'expires_at'), paidAt: optionalNumber(body, 'paid_at'), payIndex: optionalIdentifier(body, 'pay_index'),
    createdIndex: identifier(body, 'created_index'), description: optionalString(body, 'description'),
  };
}

export function parseAccountEvent(body: JsonObject): ClnAccountEvent {
  return {
    account: text(body, 'account'), type: oneOf(body, 'type', ['onchain_fee', 'chain', 'channel'] as const), tag: text(body, 'tag'),
    creditMsat: msat(body, 'credit_msat'), debitMsat: msat(body, 'debit_msat'), currency: text(body, 'currency'),
    timestamp: count(body, 'timestamp'), feesMsat: optionalMsat(body, 'fees_msat'), isRebalance: optionalBoolean(body, 'is_rebalance'),
    paymentId: optionalString(body, 'payment_id'), partId: optionalNumber(body, 'part_id'),
  };
}

export function parseLayer(body: JsonObject): ClnLayer {
  return {
    layer: text(body, 'layer'), persistent: flag(body, 'persistent'), disabledNodes: strings(body, 'disabled_nodes'),
    disabledChannels: strings(body, 'disabled_channels'),
    channelUpdates: optionalObjects(body, 'channel_updates').map(update => ({
      shortChannelIdDir: text(update, 'short_channel_id_dir'), enabled: optionalBoolean(update, 'enabled'),
      feeBaseMsat: optionalMsat(update, 'fee_base_msat'), feeProportionalMillionths: optionalNumber(update, 'fee_proportional_millionths'),
      cltvExpiryDelta: optionalNumber(update, 'cltv_expiry_delta'),
    })),
  };
}
