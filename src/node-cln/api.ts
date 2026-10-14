import { assertHash } from '../core/encoding.js';
import { ProtocolError } from '../core/errors.js';
import type { ClnRest } from './rest.js';
import {
  objects, parseAccountEvent, parseInfo, parseInvoice, parseLayer, parsePay, parsePeerChannel, parseSendPay,
  type ClnAccountEvent, type ClnInfo, type ClnInvoice, type ClnLayer, type ClnPay, type ClnPeerChannel, type ClnSendPay,
} from './types.js';

function hashFilter(filter: { paymentHash?: string } | undefined): Record<string, unknown> {
  return filter?.paymentHash === undefined ? {} : { payment_hash: assertHash(filter.paymentHash) };
}

/** Every entry of an answer to a by-hash read must name the hash asked for; another hash is a foreign answer. */
function sameHash<T extends { paymentHash: string }>(entries: T[], filter: { paymentHash?: string } | undefined): T[] {
  const wanted = filter?.paymentHash === undefined ? undefined : assertHash(filter.paymentHash);
  if (wanted !== undefined && entries.some(entry => entry.paymentHash !== wanted)) throw new ProtocolError('answer names another payment hash');
  return entries;
}

function unique<T>(entries: T[], key: (entry: T) => string | null, what: string): T[] {
  const values = entries.map(key).filter(value => value !== null);
  if (new Set(values).size !== values.length) throw new ProtocolError(`answer names a ${what} twice`);
  return entries;
}

/** The read commands FluxWarden calls through clnrest (doc/schemas/<method>.json at v26.06.9). */
export class ClnReadApi {
  readonly #rest: ClnRest;

  constructor(rest: ClnRest) {
    this.#rest = rest;
  }

  async getInfo(): Promise<ClnInfo> {
    return parseInfo(await this.#rest.call('getinfo'));
  }

  async listPeerChannels(): Promise<ClnPeerChannel[]> {
    // The short channel id is the channel key downstream; two entries under one key would be counted twice.
    const channels = objects(await this.#rest.call('listpeerchannels'), 'channels').map(parsePeerChannel);
    return unique(channels, channel => channel.shortChannelId, 'short channel id');
  }

  async listSendPays(filter?: { paymentHash?: string }): Promise<ClnSendPay[]> {
    const payments = objects(await this.#rest.call('listsendpays', hashFilter(filter)), 'payments').map(parseSendPay);
    return unique(sameHash(payments, filter), payment => payment.id, 'sendpay id');
  }

  async listPays(filter?: { paymentHash?: string }): Promise<ClnPay[]> {
    return sameHash(objects(await this.#rest.call('listpays', hashFilter(filter)), 'pays').map(parsePay), filter);
  }

  async listInvoices(filter?: { paymentHash?: string; label?: string }): Promise<ClnInvoice[]> {
    const params = { ...(filter?.label === undefined ? {} : { label: filter.label }), ...hashFilter(filter) };
    const invoices = sameHash(objects(await this.#rest.call('listinvoices', params), 'invoices').map(parseInvoice), filter);
    // lightningd answers a label filter with that exact label only (lightningd/invoice.c json_listinvoices).
    if (filter?.label !== undefined && invoices.some(invoice => invoice.label !== filter.label)) throw new ProtocolError('answer names another invoice label');
    return unique(invoices, invoice => invoice.label, 'invoice label');
  }

  async listAccountEvents(): Promise<ClnAccountEvent[]> {
    return objects(await this.#rest.call('bkpr-listaccountevents'), 'events').map(parseAccountEvent);
  }

  async listLayers(): Promise<ClnLayer[]> {
    return objects(await this.#rest.call('askrene-listlayers'), 'layers').map(parseLayer);
  }
}
