import { ProtocolError } from '../core/errors.js';
import { sha256Hex } from '../core/encoding.js';
import {
  array, asObject, boolean, identifier, integer, smallInteger, string, type JsonObject,
} from '../core/json.js';

/**
 * LND v0.21 REST answers read into typed values. The gateway marshals with proto field
 * names, emits default values, sends 64-bit integers as decimal strings and `bytes` as
 * standard base64 (lnrpc/rpc_utils.go RESTJsonMarshalOpts). Amounts keep the unit LND
 * names (`...Sat`, `...Msat`); uint64 identifiers stay decimal text.
 */

export interface LndInfo {
  identityPubkey: string; alias: string; version: string; commitHash: string; network: string;
  blockHeight: number; blockHash: string; syncedToChain: boolean; syncedToGraph: boolean;
}

export interface LndConstraints {
  csvDelay: number; chanReserveSat: bigint; dustLimitSat: bigint; maxPendingAmtMsat: bigint; minHtlcMsat: bigint; maxAcceptedHtlcs: number;
}

export interface LndHtlc {
  incoming: boolean; amountSat: bigint; hashLock: string; expirationHeight: number;
  htlcIndex: string; forwardingChannel: string; forwardingHtlcIndex: string; lockedIn: boolean;
}

export interface LndChannel {
  active: boolean; remotePubkey: string; channelPoint: string; chanId: string;
  capacitySat: bigint; localBalanceSat: bigint; remoteBalanceSat: bigint; commitFeeSat: bigint;
  commitWeight: bigint; feePerKw: bigint; unsettledBalanceSat: bigint; initiator: boolean; private: boolean;
  pendingHtlcs: LndHtlc[]; localConstraints: LndConstraints; remoteConstraints: LndConstraints;
}

export const INITIATORS = ['INITIATOR_UNKNOWN', 'INITIATOR_LOCAL', 'INITIATOR_REMOTE', 'INITIATOR_BOTH'] as const;
export type LndInitiator = (typeof INITIATORS)[number];

export interface LndPendingChannel {
  remoteNodePub: string; channelPoint: string; capacitySat: bigint; localBalanceSat: bigint; remoteBalanceSat: bigint;
  localChanReserveSat: bigint; remoteChanReserveSat: bigint; initiator: LndInitiator;
}

export interface LndPendingChannels {
  totalLimboBalanceSat: bigint;
  pendingOpenChannels: { channel: LndPendingChannel; commitFeeSat: bigint; commitWeight: bigint; feePerKw: bigint; confirmationsUntilActive: number }[];
  waitingCloseChannels: { channel: LndPendingChannel; limboBalanceSat: bigint; closingTxid: string }[];
  pendingForceClosingChannels: { channel: LndPendingChannel; closingTxid: string; limboBalanceSat: bigint; maturityHeight: number; blocksTilMaturity: number }[];
}

/** Payment.PaymentStatus, lnrpc/lightning.proto (0 UNKNOWN is deprecated). */
export const PAYMENT_STATUSES = ['UNKNOWN', 'IN_FLIGHT', 'SUCCEEDED', 'FAILED', 'INITIATED'] as const;
const FAILURE_REASONS = [
  'FAILURE_REASON_NONE', 'FAILURE_REASON_TIMEOUT', 'FAILURE_REASON_NO_ROUTE', 'FAILURE_REASON_ERROR',
  'FAILURE_REASON_INCORRECT_PAYMENT_DETAILS', 'FAILURE_REASON_INSUFFICIENT_BALANCE', 'FAILURE_REASON_CANCELED',
] as const;
const HTLC_STATUSES = ['IN_FLIGHT', 'SUCCEEDED', 'FAILED'] as const;
const INVOICE_STATES = ['OPEN', 'SETTLED', 'CANCELED', 'ACCEPTED'] as const;

export interface LndPayment {
  paymentHash: string; valueMsat: bigint; feeMsat: bigint;
  status: (typeof PAYMENT_STATUSES)[number];
  failureReason: string; creationTimeNs: bigint; paymentIndex: bigint; preimageMatchesHash: boolean;
  htlcs: { attemptId: string; status: (typeof HTLC_STATUSES)[number] }[];
}

export interface LndPaymentsPage { payments: LndPayment[]; firstIndexOffset: bigint; lastIndexOffset: bigint }

export interface LndForwardingEvent { timestampNs: bigint; chanIdIn: string; chanIdOut: string; amtInMsat: bigint; amtOutMsat: bigint; feeMsat: bigint }

export interface LndForwardingPage { events: LndForwardingEvent[]; lastOffsetIndex: number }

export interface LndInvoice {
  rHash: string; memo: string; valueMsat: bigint; amtPaidMsat: bigint;
  state: (typeof INVOICE_STATES)[number];
  creationDate: bigint; settleDate: bigint; expiry: bigint; cltvExpiry: bigint;
  addIndex: bigint; settleIndex: bigint; paymentRequest: string;
}

/**
 * A field LND always emits (EmitUnpopulated). Balances, reserves and limits must be present:
 * a missing or renamed one would otherwise read as 0 and overstate what a channel can move.
 */
function present(source: JsonObject, key: string): JsonObject {
  if (source[key] === undefined || source[key] === null) throw new ProtocolError(`${key} is missing`);
  return source;
}

function amount(source: JsonObject, key: string): bigint {
  return integer(present(source, key), key);
}

function requiredObject(source: JsonObject, key: string): JsonObject {
  return asObject(present(source, key)[key], key);
}

/** A uint64 limit that may be 2^64 - 1 (max_pending_amt_msat, lnd#5468): never read as a signed value. */
function unsigned64(source: JsonObject, key: string): bigint {
  return BigInt(identifier(source, key));
}

/** A signed 32-bit field such as blocks_til_maturity, which turns negative once maturity has passed. */
function int32(source: JsonObject, key: string): number {
  const value = source[key];
  if (value === undefined || value === null) return 0;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < -(2 ** 31) || value >= 2 ** 31) throw new ProtocolError(`${key} is not an int32`);
  return value;
}

/** An enum by name or by proto number; a name this version does not define is refused. */
function strictEnum<T extends string>(source: JsonObject, key: string, names: readonly T[]): T {
  const value = source[key];
  const first = names[0];
  if (first === undefined) throw new ProtocolError(`${key} has no values`);
  if (value === undefined || value === null) return first;
  if (typeof value === 'string') {
    const found = names.find(name => name === value);
    if (found !== undefined) return found;
  } else if (typeof value === 'number' && Number.isInteger(value)) {
    const found = names[value];
    if (found !== undefined) return found;
  }
  throw new ProtocolError(`${key} is not a known value`);
}

function enumText(source: JsonObject, key: string, names: readonly string[]): string {
  const value = source[key];
  if (value === undefined || value === null) return names[0] ?? '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isInteger(value) && value >= 0 && value < names.length) return names[value] ?? '';
  throw new ProtocolError(`${key} is not an enum value`);
}

/** A `bytes` field: standard base64, which the gateway always emits, read as lowercase hex. */
function bytesHex(source: JsonObject, key: string): string {
  const value = string(source, key);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new ProtocolError(`${key} is not base64`);
  return Buffer.from(value, 'base64').toString('hex');
}

function hashText(source: JsonObject, key: string): string {
  const value = string(source, key);
  if (!/^[0-9a-f]{64}$/.test(value)) throw new ProtocolError(`${key} is not a 32-byte hex hash`);
  return value;
}

function objects(source: JsonObject, key: string): JsonObject[] {
  return array(source, key).map((item, index) => asObject(item, `${key}[${String(index)}]`));
}

/** Whether a reported preimage proves the payment: present, 32 bytes, and hashing to the payment hash. */
function preimageProves(preimageHex: string, paymentHash: string): boolean {
  if (!/^[0-9a-fA-F]{64}$/.test(preimageHex) || /^0+$/.test(preimageHex)) return false;
  return sha256Hex(preimageHex) === paymentHash;
}

/**
 * There is no top-level network over REST: chains[].network carries NormalizeNetwork
 * (rpcserver.go GetInfo; chains[].chain is the deprecated "bitcoin"). Every entry must be a
 * bitcoin chain and all must agree; no entry reads as no network, which is unsupported.
 */
function chainNetwork(body: JsonObject): string {
  const networks = new Set<string>();
  for (const chain of objects(body, 'chains')) {
    const name = string(chain, 'chain');
    if (name !== '' && name !== 'bitcoin') throw new ProtocolError('chains names a chain other than bitcoin');
    networks.add(string(chain, 'network'));
  }
  if (networks.size > 1) throw new ProtocolError('chains report more than one network');
  return [...networks][0] ?? '';
}

export function parseInfo(body: JsonObject): LndInfo {
  return {
    identityPubkey: string(body, 'identity_pubkey'), alias: string(body, 'alias'), version: string(body, 'version'),
    commitHash: string(body, 'commit_hash'), network: chainNetwork(body),
    blockHeight: smallInteger(body, 'block_height'), blockHash: string(body, 'block_hash'),
    syncedToChain: boolean(body, 'synced_to_chain'), syncedToGraph: boolean(body, 'synced_to_graph'),
  };
}

function parseConstraints(body: JsonObject): LndConstraints {
  return {
    csvDelay: smallInteger(present(body, 'csv_delay'), 'csv_delay'), chanReserveSat: amount(body, 'chan_reserve_sat'),
    dustLimitSat: amount(body, 'dust_limit_sat'), maxPendingAmtMsat: unsigned64(present(body, 'max_pending_amt_msat'), 'max_pending_amt_msat'),
    minHtlcMsat: unsigned64(present(body, 'min_htlc_msat'), 'min_htlc_msat'),
    maxAcceptedHtlcs: smallInteger(present(body, 'max_accepted_htlcs'), 'max_accepted_htlcs'),
  };
}

function parseHtlc(body: JsonObject): LndHtlc {
  return {
    incoming: boolean(body, 'incoming'), amountSat: amount(body, 'amount'), hashLock: bytesHex(body, 'hash_lock'),
    expirationHeight: smallInteger(body, 'expiration_height'), htlcIndex: identifier(body, 'htlc_index'),
    forwardingChannel: identifier(body, 'forwarding_channel'), forwardingHtlcIndex: identifier(body, 'forwarding_htlc_index'),
    lockedIn: boolean(body, 'locked_in'),
  };
}

export function parseChannel(body: JsonObject): LndChannel {
  return {
    active: boolean(body, 'active'), remotePubkey: string(body, 'remote_pubkey'), channelPoint: string(body, 'channel_point'),
    chanId: identifier(present(body, 'chan_id'), 'chan_id'), capacitySat: amount(body, 'capacity'), localBalanceSat: amount(body, 'local_balance'),
    remoteBalanceSat: amount(body, 'remote_balance'), commitFeeSat: amount(body, 'commit_fee'), commitWeight: amount(body, 'commit_weight'),
    feePerKw: amount(body, 'fee_per_kw'), unsettledBalanceSat: amount(body, 'unsettled_balance'), initiator: boolean(body, 'initiator'),
    private: boolean(body, 'private'), pendingHtlcs: objects(body, 'pending_htlcs').map(parseHtlc),
    localConstraints: parseConstraints(requiredObject(body, 'local_constraints')),
    remoteConstraints: parseConstraints(requiredObject(body, 'remote_constraints')),
  };
}

function parsePendingChannel(holder: JsonObject): LndPendingChannel {
  const body = requiredObject(holder, 'channel');
  return {
    remoteNodePub: string(body, 'remote_node_pub'), channelPoint: string(body, 'channel_point'), capacitySat: amount(body, 'capacity'),
    localBalanceSat: amount(body, 'local_balance'), remoteBalanceSat: amount(body, 'remote_balance'),
    localChanReserveSat: amount(body, 'local_chan_reserve_sat'), remoteChanReserveSat: amount(body, 'remote_chan_reserve_sat'),
    initiator: strictEnum(body, 'initiator', INITIATORS),
  };
}

export function parsePendingChannels(body: JsonObject): LndPendingChannels {
  return {
    totalLimboBalanceSat: amount(body, 'total_limbo_balance'),
    pendingOpenChannels: objects(body, 'pending_open_channels').map(item => ({
      channel: parsePendingChannel(item), commitFeeSat: integer(item, 'commit_fee'), commitWeight: integer(item, 'commit_weight'),
      feePerKw: integer(item, 'fee_per_kw'), confirmationsUntilActive: smallInteger(item, 'confirmations_until_active'),
    })),
    waitingCloseChannels: objects(body, 'waiting_close_channels').map(item => ({
      channel: parsePendingChannel(item), limboBalanceSat: amount(item, 'limbo_balance'), closingTxid: string(item, 'closing_txid'),
    })),
    pendingForceClosingChannels: objects(body, 'pending_force_closing_channels').map(item => ({
      channel: parsePendingChannel(item), closingTxid: string(item, 'closing_txid'), limboBalanceSat: amount(item, 'limbo_balance'),
      maturityHeight: smallInteger(item, 'maturity_height'), blocksTilMaturity: int32(item, 'blocks_til_maturity'),
    })),
  };
}

/** A payment without its preimage: only whether the preimage proves the payment is kept. */
export function parsePayment(body: JsonObject): LndPayment {
  const paymentHash = hashText(body, 'payment_hash');
  return {
    paymentHash, valueMsat: integer(body, 'value_msat'), feeMsat: integer(body, 'fee_msat'),
    status: strictEnum(body, 'status', PAYMENT_STATUSES), failureReason: enumText(body, 'failure_reason', FAILURE_REASONS),
    creationTimeNs: integer(body, 'creation_time_ns'), paymentIndex: integer(body, 'payment_index'),
    preimageMatchesHash: preimageProves(string(body, 'payment_preimage'), paymentHash),
    htlcs: objects(body, 'htlcs').map(item => ({ attemptId: identifier(item, 'attempt_id'), status: strictEnum(item, 'status', HTLC_STATUSES) })),
  };
}

export function parsePaymentsPage(body: JsonObject): LndPaymentsPage {
  const payments = objects(body, 'payments').map(parsePayment);
  const seen = new Map<bigint, LndPayment>();
  for (const payment of payments) {
    const previous = seen.get(payment.paymentIndex);
    if (previous !== undefined && (previous.paymentHash !== payment.paymentHash || previous.valueMsat !== payment.valueMsat
      || previous.feeMsat !== payment.feeMsat || previous.status !== payment.status || previous.creationTimeNs !== payment.creationTimeNs
      || previous.failureReason !== payment.failureReason || previous.preimageMatchesHash !== payment.preimageMatchesHash
      || JSON.stringify(previous.htlcs) !== JSON.stringify(payment.htlcs))) {
      throw new ProtocolError('payment list gives conflicting records for one payment index');
    }
    seen.set(payment.paymentIndex, payment);
  }
  return {
    payments,
    firstIndexOffset: integer(body, 'first_index_offset'), lastIndexOffset: integer(body, 'last_index_offset'),
  };
}

export function parseForwardingPage(body: JsonObject): LndForwardingPage {
  return {
    events: objects(body, 'forwarding_events').map(item => ({
      timestampNs: integer(item, 'timestamp_ns'), chanIdIn: identifier(item, 'chan_id_in'), chanIdOut: identifier(item, 'chan_id_out'),
      amtInMsat: integer(item, 'amt_in_msat'), amtOutMsat: integer(item, 'amt_out_msat'), feeMsat: integer(item, 'fee_msat'),
    })),
    lastOffsetIndex: smallInteger(body, 'last_offset_index'),
  };
}

/** An invoice without `r_preimage`, which invoices:read callers receive (lnd#11196) and which is never read. */
export function parseInvoice(body: JsonObject): LndInvoice {
  return {
    rHash: bytesHex(body, 'r_hash'), memo: string(body, 'memo'), valueMsat: integer(body, 'value_msat'),
    amtPaidMsat: integer(body, 'amt_paid_msat'), state: strictEnum(body, 'state', INVOICE_STATES),
    creationDate: integer(body, 'creation_date'), settleDate: integer(body, 'settle_date'), expiry: integer(body, 'expiry'),
    cltvExpiry: integer(body, 'cltv_expiry'), addIndex: integer(body, 'add_index'), settleIndex: integer(body, 'settle_index'),
    paymentRequest: string(body, 'payment_request'),
  };
}
