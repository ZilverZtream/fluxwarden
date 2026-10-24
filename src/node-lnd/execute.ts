// The payment side of a circular rebalance over LND's REST gateway (lnd v0.21): AddInvoice with our preimage, one
// SendToRouteV2 on the validated route, TrackPaymentV2 / ListPayments for the outcome, CancelInvoice + LookupInvoice to
// close our invoice. SendPaymentV2 is never called.
import { createHash } from 'node:crypto';
import { minFinalCltvExpiry } from '../core/bolt11-cltv.js';
import { assertHash, hexToBase64 } from '../core/encoding.js';
import { definiteRefusal, LndError, ProtocolError, TransportError } from '../core/errors.js';
import type { CancelResult, CircularRoute, InvoiceResult, InvoiceState, PaymentObservation } from '../core/execution.js';
import { array, asObject, identifier, integer, string, type JsonObject } from '../core/json.js';
import { LndReadApi } from './api.js';
import type { LndRest } from './rest.js';
import type { LndPayment } from './types.js';

export interface LndExecutionOptions {
  /** Bound on one TrackPaymentV2 read; the newest record received by then decides. */
  readonly trackDeadlineMs: number;
}

/**
 * The final CLTV delta our invoices and routes ask for. Pinned lightningnetwork/lnd v0.21.4-beta
 * routing/router.go MinCLTVDelta is 24; requesting less makes AddInvoice refuse the intent.
 */
export const LND_FINAL_CLTV_DELTA = 24;
const SWEEP_PAGE = 500;
const MAX_SWEEP_PAGES = 10_000;
/** SendToRouteV2 / TrackPaymentV2 answer for a hash LND has no payment for ("payment isn't initiated"). */
const REJECTED_BEFORE_INITIATION = 'REJECTED_BEFORE_INITIATION';
const SETTLED_TEXT = 'invoice already settled';
const NOT_FOUND_TEXT = 'unable to locate invoice';

function bytesHex(source: JsonObject, key: string): string {
  const value = string(source, key);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new ProtocolError(`${key} is not base64`);
  return Buffer.from(value, 'base64').toString('hex');
}

/** SPEC §5.3 payment status mapping. `terminal` is false while LND may still change its mind. */
function observationOf(payment: LndPayment): { observation: PaymentObservation; terminal: boolean } {
  const inFlight = payment.htlcs.filter(htlc => htlc.status === 'IN_FLIGHT').length;
  switch (payment.status) {
    case 'SUCCEEDED':
      if (payment.preimageMatchesHash) {
        return {
          observation: {
            kind: 'SUCCEEDED', preimageMatchesHash: true, feeMsat: payment.feeMsat,
            htlcCount: payment.htlcs.filter(htlc => htlc.status === 'SUCCEEDED').length, settledChannelKey: null,
          },
          terminal: true,
        };
      }
      return { observation: { kind: 'SUCCEEDED', preimageMatchesHash: false, feeMsat: payment.feeMsat, htlcCount: 0, settledChannelKey: null }, terminal: true };
    case 'FAILED':
      if (inFlight > 0) return { observation: { kind: 'IN_FLIGHT' }, terminal: false };
      return { observation: { kind: 'FAILED', reason: payment.failureReason, local: false, htlcsInFlight: 0 }, terminal: true };
    case 'IN_FLIGHT':
    case 'INITIATED':
      return { observation: { kind: 'IN_FLIGHT' }, terminal: false };
    case 'UNKNOWN':
      return { observation: { kind: 'AMBIGUOUS', cause: 'LND reported the deprecated UNKNOWN status' }, terminal: false };
  }
}

/** An ambiguous outcome for any failure that is not LND's own answer. */
function ambiguous(error: unknown): PaymentObservation {
  return { kind: 'AMBIGUOUS', cause: error instanceof Error ? error.message : 'the answer could not be read' };
}

/** LND REST hop fields for the hop that reaches `route.hops[index].nodeOut` (routerrpc UnmarshallHopWithPubkey). */
function restRoute(route: CircularRoute, paymentSecret: string): JsonObject {
  const first = route.hops[0];
  if (first === undefined) throw new RangeError('route has no hops');
  const hops = route.hops.map((hop, index) => {
    const next = route.hops[index + 1] ?? hop;
    const entry: JsonObject = {
      chan_id: hop.channelKey,
      pub_key: hop.nodeOut,
      amt_to_forward_msat: next.amountOutMsat.toString(),
      fee_msat: (hop.amountOutMsat - next.amountOutMsat).toString(),
      expiry: next.expiry,
    };
    if (index === route.hops.length - 1) {
      entry['mpp_record'] = { payment_addr: hexToBase64(paymentSecret), total_amt_msat: route.principalMsat.toString() };
    }
    return entry;
  });
  return { total_time_lock: first.expiry, total_amt_msat: first.amountOutMsat.toString(), total_fees_msat: route.totalFeeMsat.toString(), hops };
}

export class LndExecutionAdapter {
  readonly #rest: LndRest;
  readonly #api: LndReadApi;
  readonly #trackDeadlineMs: number;

  constructor(rest: LndRest, options: LndExecutionOptions) {
    this.#rest = rest;
    this.#api = new LndReadApi(rest);
    this.#trackDeadlineMs = options.trackDeadlineMs;
  }

  /** AddInvoice with our preimage; an answer for another hash is a protocol error. */
  async createInvoice(amountMsat: bigint, preimage: Uint8Array, label: string, expirySeconds: number): Promise<InvoiceResult> {
    if (preimage.length !== 32) throw new RangeError('the preimage must be 32 bytes');
    const hash = createHash('sha256').update(preimage).digest('hex');
    const answer = await this.#rest.call('POST', '/v1/invoices', {
      memo: label, r_preimage: Buffer.from(preimage).toString('base64'), value_msat: amountMsat.toString(), expiry: String(expirySeconds),
      cltv_expiry: String(LND_FINAL_CLTV_DELTA),
    });
    if (bytesHex(answer, 'r_hash') !== hash) throw new ProtocolError('AddInvoice answered another payment hash');
    const paymentSecret = bytesHex(answer, 'payment_addr');
    if (!/^[0-9a-f]{64}$/.test(paymentSecret)) throw new ProtocolError('AddInvoice answered no 32-byte payment address');
    const finalCltvDelta = minFinalCltvExpiry(string(answer, 'payment_request'));
    if (finalCltvDelta === undefined) throw new ProtocolError('AddInvoice answered an unreadable payment request');
    return { paymentHash: hash, paymentSecret, finalCltvDelta };
  }

  /**
   * Exactly one SendToRouteV2. Its answer or refusal is confirmed by TrackPaymentV2 and must reach a terminal status;
   * a cut, a timeout, a gateway error or a stream that ends while the payment is in flight is AMBIGUOUS.
   */
  async sendOnRoute(route: CircularRoute, paymentHash: string, paymentSecret: string, onDispatched?: () => void): Promise<PaymentObservation> {
    const hash = assertHash(paymentHash);
    const secret = assertHash(paymentSecret, 'payment secret');
    const body = { payment_hash: hexToBase64(hash), route: restRoute(route, secret) };
    let dispatched = false;
    const written = (): void => {
      if (dispatched) return;
      dispatched = true;
      onDispatched?.();
    };
    try {
      await this.#rest.call('POST', '/v2/router/route/send', body, { onWritten: written });
    } catch (error) {
      const refused = (error instanceof TransportError && error.notDelivered) || definiteRefusal(error);
      if (!refused) return ambiguous(error);
      const tracked = await this.#track(hash);
      if (tracked.notFound) return { kind: 'FAILED', reason: REJECTED_BEFORE_INITIATION, local: true, htlcsInFlight: 0 };
      return tracked.terminal ? tracked.observation : ambiguous(new Error('the payment did not reach a terminal status'));
    }
    const tracked = await this.#track(hash);
    if (tracked.notFound) return { kind: 'AMBIGUOUS', cause: 'TrackPaymentV2 found no payment after SendToRouteV2 answered' };
    return tracked.terminal ? tracked.observation : ambiguous(new Error('the payment did not reach a terminal status'));
  }

  /** 'track': TrackPaymentV2 until a terminal record, the end of the stream or the deadline; 'sweep': ListPayments. */
  async observePayment(paymentHash: string, mode: 'track' | 'sweep' = 'track'): Promise<PaymentObservation> {
    const hash = assertHash(paymentHash);
    if (mode === 'sweep') return await this.#sweep(hash);
    const tracked = await this.#track(hash);
    return tracked.notFound ? { kind: 'NOT_FOUND' } : tracked.observation;
  }

  async invoiceState(paymentHash: string): Promise<InvoiceState> {
    try {
      const invoice = await this.#api.lookupInvoice(paymentHash);
      if (invoice.state === 'SETTLED') return 'SETTLED';
      if (invoice.state === 'CANCELED') return 'CANCELED';
      return 'OPEN';
    } catch (error) {
      if (error instanceof LndError && error.notFound) return 'NOT_FOUND';
      throw error;
    }
  }

  /**
   * CancelInvoice by hash (LND needs no label), then LookupInvoice: LND answers success without cancelling an invoice
   * that holds an accepted HTLC.
   */
  async cancelUnpaidInvoice(paymentHash: string): Promise<CancelResult> {
    const hash = assertHash(paymentHash);
    try {
      await this.#rest.call('POST', '/v2/invoices/cancel', { payment_hash: hexToBase64(hash) });
    } catch (error) {
      if (!(error instanceof LndError) || !definiteRefusal(error)) throw error;
      const text = error.message.toLowerCase();
      if (text.includes(SETTLED_TEXT)) return 'ALREADY_PAID';
      if (text.includes(NOT_FOUND_TEXT) || error.notFound) return 'NOT_FOUND';
      throw error;
    }
    const state = await this.invoiceState(hash);
    if (state === 'CANCELED') return 'CANCELED';
    if (state === 'SETTLED') return 'ALREADY_PAID';
    if (state === 'NOT_FOUND') return 'NOT_FOUND';
    throw new ProtocolError('the invoice is still open after CancelInvoice');
  }

  async #track(hash: string): Promise<{ observation: PaymentObservation; terminal: boolean; notFound: boolean }> {
    let latest: { observation: PaymentObservation; terminal: boolean } | undefined;
    let principal = 0n;
    const controller = new AbortController();
    const timer = setTimeout(() => { controller.abort(); }, this.#trackDeadlineMs);
    try {
      await this.#api.trackPayment(hash, payment => {
        latest = observationOf(payment);
        principal = payment.valueMsat;
        return latest.terminal ? 'stop' : 'continue';
      }, controller.signal);
    } catch (error) {
      if (error instanceof LndError && error.notFound && latest === undefined) return { observation: { kind: 'NOT_FOUND' }, terminal: false, notFound: true };
      if (latest === undefined || error instanceof ProtocolError || error instanceof LndError) return { observation: ambiguous(error), terminal: false, notFound: false };
    } finally {
      clearTimeout(timer);
    }
    if (latest === undefined) return { observation: { kind: 'AMBIGUOUS', cause: 'TrackPaymentV2 ended without a payment record' }, terminal: false, notFound: false };
    return { ...latest, observation: await this.#receiver(latest.observation, hash, principal), notFound: false };
  }

  /** LND lightning.proto InvoiceHTLC: only a unique settled receiver HTLC proves its actual incoming channel. */
  async #receiver(observation: PaymentObservation, hash: string, principal: bigint): Promise<PaymentObservation> {
    if (observation.kind !== 'SUCCEEDED' || !observation.preimageMatchesHash) return observation;
    let settledChannelKey: string | null = null;
    try {
      const invoice = await this.#rest.call('GET', `/v1/invoice/${hash}`);
      if (bytesHex(invoice, 'r_hash') === hash && (invoice['state'] === 'SETTLED' || invoice['state'] === 1) &&
          integer(invoice, 'amt_paid_msat') === principal && principal > 0n) {
        const settled = array(invoice, 'htlcs').map(item => asObject(item, 'invoice HTLC'))
          .filter(htlc => htlc['state'] === 'SETTLED' || htlc['state'] === 1);
        const htlc = settled.length === 1 ? settled[0] : undefined;
        if (htlc !== undefined && integer(htlc, 'amt_msat') === principal) {
          const channel = identifier(htlc, 'chan_id');
          if (channel !== '0') settledChannelKey = channel;
        }
      }
    } catch {
      // A missing or unreadable receiver receipt never replaces a proven payer outcome or invents a channel.
    }
    return { ...observation, settledChannelKey };
  }

  /** ListPayments with include_incomplete, page by page, until the hash is found or the list ends. */
  async #sweep(hash: string): Promise<PaymentObservation> {
    let offset = 0n;
    try {
      for (let page = 0; page < MAX_SWEEP_PAGES; page += 1) {
        const answer = await this.#api.listPayments({ indexOffset: offset, maxPayments: SWEEP_PAGE, includeIncomplete: true });
        const found = answer.payments.find(payment => payment.paymentHash === hash);
        if (found !== undefined) return await this.#receiver(observationOf(found).observation, hash, found.valueMsat);
        if (answer.payments.length === 0) return { kind: 'NOT_FOUND' };
        // lnd v0.21.4-beta lnrpc/lightning.proto ListPaymentsResponse: the last offset is the next
        // forward-seek cursor. A nonempty page that cannot advance leaves the history incomplete (INV-04).
        if (answer.lastIndexOffset <= offset) return { kind: 'AMBIGUOUS', cause: 'the payment list did not advance' };
        offset = answer.lastIndexOffset;
      }
    } catch (error) {
      return ambiguous(error);
    }
    return { kind: 'AMBIGUOUS', cause: 'the payment list did not end' };
  }
}
