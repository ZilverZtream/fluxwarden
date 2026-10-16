import { ProtocolError } from '../core/errors.js';
import { CredentialFileError, MAX_CHANNELS_PER_LISTING, type NodeInfo, type NodeReader, type PaymentsPage } from '../core/node.js';
import { normalizeClnChannel, type NormalizeContext, type NormalizedChannel } from '../core/normalize.js';
import { ClnReadApi } from './api.js';
import { clnSynced, probeClnWithAlias } from './probe.js';
import { openClnRest, type ClnRest, type ClnRestOptions } from './rest.js';
import { objects, parseSendPay } from './types.js';

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
