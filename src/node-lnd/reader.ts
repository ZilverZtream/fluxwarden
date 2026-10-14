import { ProtocolError } from '../core/errors.js';
import { array } from '../core/json.js';
import { CredentialFileError, MAX_CHANNELS_PER_LISTING, type NodeInfo, type NodeReader, type PaymentsPage } from '../core/node.js';
import { normalizeLndChannel, normalizeLndPendingChannel, type LndPendingKind, type NormalizeContext, type NormalizedChannel } from '../core/normalize.js';
import { LndReadApi } from './api.js';
import { probeLndWithAlias } from './probe.js';
import { openLndRest, type LndRest, type LndRestOptions } from './rest.js';

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
