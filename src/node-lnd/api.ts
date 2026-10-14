import { ProtocolError } from '../core/errors.js';
import { assertHash, hexToUrlParam } from '../core/encoding.js';
import { array, asObject } from '../core/json.js';
import type { LndRest, StreamDecision, StreamEnd } from './rest.js';
import {
  parseChannel, parseForwardingPage, parseInfo, parseInvoice, parsePayment, parsePaymentsPage, parsePendingChannels,
  type LndChannel, type LndForwardingPage, type LndInfo, type LndInvoice, type LndPayment, type LndPaymentsPage, type LndPendingChannels,
} from './types.js';

/** The read calls of LND's REST interface (lnrpc/lightning.yaml, routerrpc/router.yaml at v0.21.4-beta). */
export class LndReadApi {
  readonly #rest: LndRest;

  constructor(rest: LndRest) {
    this.#rest = rest;
  }

  async getInfo(): Promise<LndInfo> {
    return parseInfo(await this.#rest.call('GET', '/v1/getinfo'));
  }

  async listChannels(): Promise<LndChannel[]> {
    const body = await this.#rest.call('GET', '/v1/channels');
    const channels = array(body, 'channels').map((item, index) => parseChannel(asObject(item, `channels[${String(index)}]`)));
    // The channel id is the channel key downstream; two entries under one key would be counted twice.
    if (new Set(channels.map(channel => channel.chanId)).size !== channels.length) throw new ProtocolError('channel list names a channel id twice');
    return channels;
  }

  async pendingChannels(): Promise<LndPendingChannels> {
    return parsePendingChannels(await this.#rest.call('GET', '/v1/channels/pending'));
  }

  async listPayments(request: { indexOffset: bigint; maxPayments: number; includeIncomplete: boolean }): Promise<LndPaymentsPage> {
    if (request.indexOffset < 0n || !Number.isSafeInteger(request.maxPayments) || request.maxPayments < 0) throw new RangeError('listPayments: invalid page request');
    const query = new URLSearchParams({
      include_incomplete: String(request.includeIncomplete), index_offset: request.indexOffset.toString(), max_payments: String(request.maxPayments),
    });
    return parsePaymentsPage(await this.#rest.call('GET', `/v1/payments?${query.toString()}`));
  }

  async forwardingHistory(request: { startTime: bigint; endTime: bigint; indexOffset: number; numMaxEvents: number }): Promise<LndForwardingPage> {
    // uint64 times travel as decimal strings, uint32 fields as numbers (protojson).
    const body = {
      start_time: request.startTime.toString(), end_time: request.endTime.toString(),
      index_offset: request.indexOffset, num_max_events: request.numMaxEvents,
    };
    return parseForwardingPage(await this.#rest.call('POST', '/v1/switch', body));
  }

  /** v1 LookupInvoice takes the hash as hex in the path; an answer for another hash is refused. */
  async lookupInvoice(paymentHash: string): Promise<LndInvoice> {
    const hash = assertHash(paymentHash);
    const invoice = parseInvoice(await this.#rest.call('GET', `/v1/invoice/${hash}`));
    if (invoice.rHash !== hash) throw new ProtocolError('invoice answer names another payment hash');
    return invoice;
  }

  /**
   * TrackPaymentV2 takes the hash as padded URL-safe base64: standard base64 can contain '/',
   * which splits the path, and the gateway then answers NotFound (lnd#7821). Resolves with how
   * the stream ended: `ended` means LND closed it before the handler saw what it waited for.
   */
  async trackPayment(paymentHash: string, onUpdate: (payment: LndPayment) => StreamDecision, signal?: AbortSignal): Promise<StreamEnd> {
    const hash = assertHash(paymentHash);
    return await this.#rest.stream('GET', `/v2/router/track/${hexToUrlParam(hash)}`, undefined, message => {
      const payment = parsePayment(message);
      if (payment.paymentHash !== hash) throw new ProtocolError('payment update names another payment hash');
      return onUpdate(payment);
    }, signal);
  }
}
