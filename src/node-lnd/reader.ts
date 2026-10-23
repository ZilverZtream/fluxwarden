import { ProtocolError } from '../core/errors.js';
import { array, asObject, enumName, identifier, integer } from '../core/json.js';
import { CredentialFileError, MAX_CHANNELS_PER_LISTING, type IncomingHistory, type NodeInfo, type NodeReader, type PaymentsPage } from '../core/node.js';
import { normalizeLndChannel, normalizeLndPendingChannel, type LndPendingKind, type NormalizeContext, type NormalizedChannel } from '../core/normalize.js';
import { LndReadApi } from './api.js';
import { probeLndWithAlias } from './probe.js';
import { openLndRest, type LndRest, type LndRestOptions } from './rest.js';
import { parseInvoice } from './types.js';

const PENDING_LISTS: readonly (readonly [string, LndPendingKind])[] = [
  ['pending_open_channels', 'pending_open'],
  ['waiting_close_channels', 'waiting_close'],
  ['pending_force_closing_channels', 'pending_force_closing'],
];

class LndReader implements NodeReader {
  readonly implementation = 'lnd' as const;
  readonly #rest: LndRest;
  readonly #api: LndReadApi;

  constructor(rest: LndRest) {
    this.#rest = rest;
    this.#api = new LndReadApi(rest);
  }

  probe: NodeReader['probe'] = context => probeLndWithAlias(this.#rest, context);

  async info(): Promise<NodeInfo> {
    const info = await this.#api.getInfo();
    return {
      pubkey: info.identityPubkey, alias: info.alias, network: info.network, version: info.version,
      blockHeight: info.blockHeight, syncedToChain: info.syncedToChain,
    };
  }

  /** ListChannels, then PendingChannels (lightning.proto Channel, PendingChannelsResponse), one entry per channel key. */
  async listChannels(context: NormalizeContext): Promise<NormalizedChannel[]> {
    const open = array(await this.#rest.call('GET', '/v1/channels'), 'channels');
    if (open.length > MAX_CHANNELS_PER_LISTING) throw new ProtocolError(`channel list longer than ${String(MAX_CHANNELS_PER_LISTING)} entries`);
    const pendingBody = await this.#rest.call('GET', '/v1/channels/pending');
    const pending = PENDING_LISTS.flatMap(([key, kind]) => array(pendingBody, key).map(entry => [kind, entry] as const));
    if (open.length + pending.length > MAX_CHANNELS_PER_LISTING) throw new ProtocolError(`channel list longer than ${String(MAX_CHANNELS_PER_LISTING)} entries`);
    const channels = [
      ...open.map(entry => normalizeLndChannel(entry, context)),
      ...pending.map(([kind, entry]) => normalizeLndPendingChannel(kind, entry, context)),
    ];
    if (new Set(channels.map(channel => channel.channelKey)).size !== channels.length) throw new ProtocolError('channel list names a channel twice');
    return channels;
  }

  /** ListPayments with incomplete payments, entries after index_offset (lightning.proto ListPaymentsRequest). */
  async paymentsPage(cursor: bigint, pageSize: number): Promise<PaymentsPage> {
    const page = await this.#api.listPayments({ indexOffset: cursor, maxPayments: pageSize, includeIncomplete: true });
    if (page.payments.length > pageSize) throw new ProtocolError('payment page longer than requested');
    if (page.payments.length > 0 && page.lastIndexOffset <= cursor) throw new ProtocolError('payment page does not advance past its offset');
    return { count: page.payments.length, cursor: page.payments.length === 0 ? cursor : page.lastIndexOffset };
  }

  async incomingHistory(): Promise<IncomingHistory> {
    // LND v0.21.4-beta lightning.proto ListInvoiceRequest: add-index offset is exclusive;
    // InvoiceHTLC carries the actual receiver channel and settled amount, including MPP parts.
    const receipts: IncomingHistory['receipts'][number][] = [];
    const ownPayments = new Set<string>();
    let paymentCursor = 0n;
    let paymentsComplete = false;
    for (let page = 0; page < 200; page++) {
      const payments = await this.#api.listPayments({ indexOffset: paymentCursor, maxPayments: 500, includeIncomplete: true });
      if (payments.payments.length > 500) throw new ProtocolError('incoming demand payment page longer than requested');
      if (payments.payments.length > 0 && payments.lastIndexOffset <= paymentCursor) throw new ProtocolError('incoming demand payment offset does not advance');
      for (const payment of payments.payments) ownPayments.add(payment.paymentHash);
      paymentCursor = payments.lastIndexOffset;
      if (payments.payments.length < 500) { paymentsComplete = true; break; }
    }
    if (!paymentsComplete) return { complete: false, receipts: [] };
    let cursor = 0n;
    for (let page = 0; page < 200; page++) {
      const query = new URLSearchParams({ index_offset: cursor.toString(), num_max_invoices: '500', reversed: 'false', pending_only: 'false' });
      const body = await this.#rest.call('GET', `/v1/invoices?${query.toString()}`);
      const invoices = array(body, 'invoices');
      if (invoices.length > 500) throw new ProtocolError('incoming history page longer than requested');
      for (const value of invoices) {
        const invoice = asObject(value, 'incoming invoice');
        const index = integer(invoice, 'add_index');
        if (index <= cursor) throw new ProtocolError('incoming invoice page does not advance');
        cursor = index;
        if (enumName(invoice, 'state', ['OPEN', 'SETTLED', 'CANCELED', 'ACCEPTED']) !== 'SETTLED') continue;
        // A received invoice paid by this node is a rebalance, rather than external demand.
        if (ownPayments.has(parseInvoice(invoice).rHash)) continue;
        const at = Number(integer(invoice, 'settle_date') * 1000n);
        if (!Number.isSafeInteger(at)) throw new ProtocolError('incoming settlement time is out of range');
        const htlcs = array(invoice, 'htlcs').map(value => asObject(value, 'incoming HTLC'))
          .filter(htlc => enumName(htlc, 'state', ['ACCEPTED', 'SETTLED', 'CANCELED']) === 'SETTLED');
        if (htlcs.length === 0 || htlcs.reduce((total, htlc) => total + integer(htlc, 'amt_msat'), 0n) !== integer(invoice, 'amt_paid_msat')) return { complete: false, receipts: [] };
        for (const htlc of htlcs) {
          const channelKey = identifier(htlc, 'chan_id');
          if (channelKey === '0') return { complete: false, receipts: [] };
          receipts.push({ channelKey, settledAt: at, amountMsat: integer(htlc, 'amt_msat') });
        }
      }
      if (invoices.length < 500) return { complete: true, receipts };
      if (integer(body, 'last_index_offset') !== cursor) throw new ProtocolError('incoming invoice offset is inconsistent');
    }
    return { complete: false, receipts: [] };
  }
}

/** Reads the certificate and macaroon by path (SPEC.md §5.2 H1); an unreadable file is a CredentialFileError. */
export async function openLndReader(options: LndRestOptions): Promise<NodeReader> {
  let rest: LndRest;
  try {
    rest = await openLndRest(options);
  } catch (error) {
    const code = (error as { code?: unknown } | null)?.code;
    throw new CredentialFileError(`the TLS certificate or macaroon file could not be read${typeof code === 'string' ? ` (${code})` : ''}`);
  }
  return new LndReader(rest);
}
