/**
 * The read side of a node as the commands and the collector use it (SPEC.md §5.1 read methods).
 * Each adapter implements it over its own transport; nothing here performs I/O.
 */
import type { Implementation, ProbeContext, ProbeResult } from './capabilities.js';
import type { NormalizeContext, NormalizedChannel } from './normalize.js';

/** The TLS certificate or the credential file named for a node could not be read (SPEC.md §5.2 H1). */
export class CredentialFileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CredentialFileError';
  }
}

/** Channels per listing; a longer listing is a protocol error, never a truncated list (SECURITY.md §5). */
export const MAX_CHANNELS_PER_LISTING = 10_000;

export interface NodeInfo {
  readonly pubkey: string;
  readonly alias: string;
  /** The node's own network string, before normalisation. */
  readonly network: string;
  readonly version: string;
  readonly blockHeight: number;
  readonly syncedToChain: boolean;
}

export interface PaymentsPage {
  /** Entries in this page. */
  readonly count: number;
  /** Where the next page starts; unchanged when the page was empty. */
  readonly cursor: bigint;
}

export interface NodeReader {
  readonly implementation: Implementation;
  /** Connect-time handshake (SPEC.md §5.2 H2 to H8), with the alias the identity call reported. */
  probe(context: ProbeContext): Promise<{ readonly result: ProbeResult; readonly alias: string }>;
  /** The identity call alone. */
  info(): Promise<NodeInfo>;
  /** Every channel the node lists, normalised; more than MAX_CHANNELS_PER_LISTING is a ProtocolError. */
  listChannels(context: NormalizeContext): Promise<NormalizedChannel[]>;
  /** One page of the payment history, oldest first, starting after `cursor`. */
  paymentsPage(cursor: bigint, pageSize: number): Promise<PaymentsPage>;
}
