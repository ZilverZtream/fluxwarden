import { ProtocolError } from '../core/errors.js';
import { identifier, type JsonObject } from '../core/json.js';
import { CredentialFileError, MAX_CHANNELS_PER_LISTING, type IncomingHistory, type NodeInfo, type NodeReader, type PaymentsPage } from '../core/node.js';
import { normalizeClnChannel, type NormalizeContext, type NormalizedChannel } from '../core/normalize.js';
import { ClnReadApi } from './api.js';
import { clnSynced, probeClnWithAlias } from './probe.js';
import { openClnRest, type ClnRest, type ClnRestOptions } from './rest.js';
import { msat, objects, parseInvoice, parseSendPay, text, type ClnAccountEvent } from './types.js';

class ClnReader implements NodeReader {
  readonly implementation = 'cln' as const;
  readonly #rest: ClnRest;

  constructor(rest: ClnRest) {
    this.#rest = rest;
  }

  probe: NodeReader['probe'] = context => probeClnWithAlias(this.#rest, context);

  async info(): Promise<NodeInfo> {
    const info = await new ClnReadApi(this.#rest).getInfo();
    return { pubkey: info.id, alias: info.alias, network: info.network, version: info.version, blockHeight: info.blockheight, syncedToChain: clnSynced(info) };
  }

  /** listpeerchannels (doc/schemas/listpeerchannels.json), one entry per channel key. */
  async listChannels(context: NormalizeContext): Promise<NormalizedChannel[]> {
    const entries = objects(await this.#rest.call('listpeerchannels'), 'channels');
    if (entries.length > MAX_CHANNELS_PER_LISTING) throw new ProtocolError(`channel list longer than ${String(MAX_CHANNELS_PER_LISTING)} entries`);
    const channels = entries.map(entry => normalizeClnChannel(entry, context));
    if (new Set(channels.map(channel => channel.channelKey)).size !== channels.length) throw new ProtocolError('channel list names a channel twice');
    return channels;
  }

  /** listsendpays by created index from `cursor` (doc/schemas/listsendpays.json index, start, limit). */
  async paymentsPage(cursor: bigint, pageSize: number): Promise<PaymentsPage> {
    const start = Number(cursor);
    if (!Number.isSafeInteger(start)) throw new RangeError('the payment cursor cannot be represented exactly');
    const payments = objects(await this.#rest.call('listsendpays', { index: 'created', start, limit: pageSize }), 'payments').map(parseSendPay);
    if (payments.length > pageSize) throw new ProtocolError('payment page longer than requested');
    let next = cursor;
    for (const payment of payments) {
      const index = BigInt(payment.createdIndex);
      if (index < next) throw new ProtocolError('payment page is not in created order');
      next = index + 1n;
    }
    return { count: payments.length, cursor: next };
  }

  async incomingHistory(): Promise<IncomingHistory> {
    // CLN v26.06.9 doc/schemas/{listinvoices,listhtlcs}.json: created start is inclusive.
    // As in the collector, bound each scan to 200 pages of 500; an unfinished scan supplies no demand.
    // Project each page before retaining it: invoice descriptions, bolt11 and preimages never belong
    // to demand history. Cap retained compact evidence at the existing 16 MiB response bound as well.
    let retainedBytes = 0;
    const scan = async <T>(method: string, field: string, project: (entry: JsonObject) => T | null): Promise<T[] | null> => {
      const entries: T[] = [];
      let cursor = 0n;
      for (let page = 0; page < 200; page++) {
        const start = Number(cursor);
        if (!Number.isSafeInteger(start)) return null;
        const batch = objects(await this.#rest.call(method, { index: 'created', start, limit: 500 }), field);
        if (batch.length > 500) throw new ProtocolError('incoming history page longer than requested');
        for (const entry of batch) {
          if (entry['created_index'] === undefined) throw new ProtocolError('incoming history index is missing');
          const index = BigInt(identifier(entry, 'created_index'));
          if (index < cursor) throw new ProtocolError('incoming history page does not advance');
          cursor = index + 1n;
          const compact = project(entry);
          if (compact !== null) {
            retainedBytes += Buffer.byteLength(JSON.stringify(compact, (_key, value: unknown) => typeof value === 'bigint' ? value.toString() : value));
            if (retainedBytes > 16 * 1024 * 1024) return null;
            entries.push(compact);
          }
        }
        if (batch.length < 500) return entries;
      }
      return null;
    };
    const seen = new Set<string>();
    const invoices = await scan('listinvoices', 'invoices', entry => {
      const invoice = parseInvoice(entry);
      if (seen.has(invoice.paymentHash)) throw new ProtocolError('incoming history names an invoice twice');
      seen.add(invoice.paymentHash);
      return invoice.status === 'paid' && invoice.paidAt !== null && invoice.amountReceivedMsat !== null
        ? { paymentHash: invoice.paymentHash, paidAt: invoice.paidAt, amountReceivedMsat: invoice.amountReceivedMsat } : null;
    });
    if (invoices === null) return { complete: false, receipts: [] };
    const paidHashes = new Set(invoices.map(invoice => invoice.paymentHash));
    const htlcs = await scan('listhtlcs', 'htlcs', entry => {
      if (text(entry, 'direction') !== 'in' || text(entry, 'state') !== 'SENT_REMOVE_ACK_REVOCATION') return null;
      const paymentHash = text(entry, 'payment_hash');
      return paidHashes.has(paymentHash)
        ? { paymentHash, channelKey: text(entry, 'short_channel_id'), amountMsat: msat(entry, 'amount_msat') } : null;
    });
    if (htlcs === null) return { complete: false, receipts: [] };
    const events = await new ClnReadApi(this.#rest).listAccountEvents();
    if (events.length > 100_000) return { complete: false, receipts: [] };
    const channels = await new ClnReadApi(this.#rest).listPeerChannels();
    if (channels.length > MAX_CHANNELS_PER_LISTING) return { complete: false, receipts: [] };
    const channelKeys = new Map<string, string>();
    for (const channel of channels) {
      if (channel.channelId === null) continue;
      if (channelKeys.has(channel.channelId)) throw new ProtocolError('incoming history names a channel account twice');
      channelKeys.set(channel.channelId, channel.shortChannelId ?? channel.channelId);
    }
    const receipts: IncomingHistory['receipts'][number][] = [];
    const byHash = new Map<string, (typeof htlcs)[number][]>();
    for (const htlc of htlcs) {
      const hash = htlc.paymentHash;
      const list = byHash.get(hash) ?? [];
      list.push(htlc); byHash.set(hash, list);
    }
    const creditsByHash = new Map<string, ClnAccountEvent[]>();
    for (const event of events) {
      if (event.paymentId === null || event.type !== 'channel' || event.creditMsat <= 0n) continue;
      const list = creditsByHash.get(event.paymentId) ?? [];
      list.push(event); creditsByHash.set(event.paymentId, list);
    }
    for (const invoice of invoices) {
      const at = invoice.paidAt * 1000;
      if (!Number.isSafeInteger(at)) throw new ProtocolError('incoming settlement time is out of range');
      const matching = byHash.get(invoice.paymentHash) ?? [];
      const credits = creditsByHash.get(invoice.paymentHash) ?? [];
      if (credits.some(event => event.isRebalance === true)) continue;
      // CLN v26.06.9 lightningd/peer_htlcs.c remove_htlc_in credits only a fulfilled HTLC;
      // SENT_REMOVE_ACK_REVOCATION also retains failed attempts, so those are attribution hints only.
      // plugins/bkpr/channel_event.c exposes the credited account and amount, not a listhtlcs success flag.
      if (credits.length === 0 || credits.some(event => event.isRebalance !== false || event.tag !== 'invoice' || event.debitMsat !== 0n)
        || credits.reduce((total, event) => total + event.creditMsat, 0n) !== invoice.amountReceivedMsat) return { complete: false, receipts: [] };
      const hints = new Map<string, number>();
      for (const htlc of matching) {
        const key = `${htlc.channelKey}:${htlc.amountMsat.toString()}`;
        hints.set(key, (hints.get(key) ?? 0) + 1);
      }
      for (const credit of credits) {
        // Bookkeeper retains the full channel account after it closes, while listhtlcs need not retain its
        // HTLCs. Keep that actual identity; it cannot contribute volume to a different, current channel.
        const current = channelKeys.get(credit.account);
        if (current === undefined && !/^[0-9a-f]{64}$/.test(credit.account)) return { complete: false, receipts: [] };
        if (current !== undefined) {
          const key = `${current}:${credit.creditMsat.toString()}`;
          const available = hints.get(key) ?? 0;
          if (available === 0) return { complete: false, receipts: [] };
          hints.set(key, available - 1);
        }
        receipts.push({ channelKey: current ?? credit.account, settledAt: at, amountMsat: credit.creditMsat });
      }
    }
    return { complete: true, receipts };
  }
}

/** Reads the certificate and rune by path (SPEC.md §5.2 H1); an unreadable file is a CredentialFileError. */
export async function openClnReader(options: ClnRestOptions): Promise<NodeReader> {
  let rest: ClnRest;
  try {
    rest = await openClnRest(options);
  } catch (error) {
    const code = (error as { code?: unknown } | null)?.code;
    throw new CredentialFileError(`the TLS certificate or rune file could not be read${typeof code === 'string' ? ` (${code})` : ''}`);
  }
  return new ClnReader(rest);
}
