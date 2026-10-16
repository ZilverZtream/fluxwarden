// The payment side of a circular rebalance over clnrest (Core Lightning v26.06): invoice with our preimage, the route
// from a per-execution askrene layer, one sendpay, waitsendpay in bounded chunks, listsendpays / listinvoices for the
// outcome, delinvoice ... unpaid to close our invoice. xpay and pay are never called: both settle a payment to our own
// invoice without any channel.
import { createHash, randomUUID } from 'node:crypto';
import { minFinalCltvExpiry } from '../core/bolt11-cltv.js';
import { assertHash } from '../core/encoding.js';
import { ProtocolError } from '../core/errors.js';
import type { CancelResult, CircularRoute, InvoiceResult, InvoiceState, PaymentObservation, RouteOwnership, RouteRequest, RoutingLayerClaim } from '../core/execution.js';
import type { JsonObject } from '../core/json.js';
import type { Msat } from '../core/money.js';
import { isNoRoute, type CandidateRoute } from '../core/route.js';
import { channelScid, scidToChanId } from '../core/scid.js';
import { ClnReadApi } from './api.js';
import { lightningdRefused, type ClnRest } from './rest.js';
import { ClnRouteApi } from './routes.js';
import { msat, objects, parseInfo, parsePeerChannel, parseSendPay, text, type ClnSendPay } from './types.js';

export interface ClnExecutionOptions {
  /** Our node id; askrene disables it so that getroutes runs between the two peers. */
  readonly ownId: string;
  /** Upper bound of one waitsendpay call, in seconds (SPEC §5.4 C9: at most 10). */
  readonly waitChunkSeconds: number;
  /** How long sendOnRoute waits for a final answer before it reports AMBIGUOUS. */
  readonly attemptDeadlineMs: number;
}

/** common/jsonrpc_errors.h */
const PAY_IN_PROGRESS = 200;
const PAY_NO_SUCH_PAYMENT = 208;
const INVOICE_NOT_FOUND = 905;
const INVOICE_STATUS_UNEXPECTED = 906;
/** waitsendpay answers for an attempt that failed (doc/schemas/waitsendpay.json errors). */
const PAY_FAILURES: Readonly<Record<number, string>> = {
  202: 'PAY_UNPARSEABLE_ONION',
  203: 'PAY_DESTINATION_PERM_FAIL',
  204: 'PAY_TRY_OTHER_ROUTE',
  209: 'PAY_UNSPECIFIED_ERROR',
};
/** sendpay refusals after which no HTLC is outstanding: the failures above, and parameters lightningd rejected. */
const SENDPAY_REFUSALS: Readonly<Record<number, string>> = { ...PAY_FAILURES, [-32602]: 'INVALID_PARAMS' };
/** The final CLTV delta our invoices ask for and routes are built with; dispatch checks the route against the invoice. */
const FINAL_CLTV_DELTA = 18;
const REJECTED_BEFORE_INITIATION = 'REJECTED_BEFORE_INITIATION';
/** Decision D52: lightningd sends each HTLC at network height + 1 + cltv_out, one block above the route's delta. */
const CLN_BLOCK_PADDING = 1;

function ambiguous(cause: unknown): PaymentObservation {
  return { kind: 'AMBIGUOUS', cause: cause instanceof Error ? cause.message : String(cause) };
}

/** BOLT 7: direction 0 when the sending node's id sorts below the receiving node's. */
function direction(sender: string, receiver: string): 0 | 1 {
  return sender < receiver ? 0 : 1;
}

function ppmCeil(fee: bigint, principal: bigint): bigint {
  return (fee * 1_000_000n + principal - 1n) / principal;
}

export class ClnExecutionAdapter {
  readonly #rest: ClnRest;
  readonly #api: ClnReadApi;
  readonly #routes: ClnRouteApi;
  readonly #ownId: string;
  readonly #waitChunkSeconds: number;
  readonly #attemptDeadlineMs: number;

  constructor(rest: ClnRest, options: ClnExecutionOptions) {
    if (!Number.isSafeInteger(options.waitChunkSeconds) || options.waitChunkSeconds < 1) throw new RangeError('waitChunkSeconds must be a positive integer');
    this.#rest = rest;
    this.#api = new ClnReadApi(rest);
    this.#routes = new ClnRouteApi(rest);
    this.#ownId = options.ownId;
    this.#waitChunkSeconds = options.waitChunkSeconds;
    this.#attemptDeadlineMs = options.attemptDeadlineMs;
  }

  /** invoice with our preimage; an answer for another hash is a protocol error. */
  async createInvoice(amountMsat: bigint, preimage: Uint8Array, label: string, expirySeconds: number): Promise<InvoiceResult> {
    if (preimage.length !== 32) throw new RangeError('the preimage must be 32 bytes');
    const hash = createHash('sha256').update(preimage).digest('hex');
    const answer = await this.#rest.call('invoice', {
      amount_msat: amountMsat.toString(), label, description: `fluxwarden rebalance ${label}`, expiry: expirySeconds,
      preimage: Buffer.from(preimage).toString('hex'), cltv: FINAL_CLTV_DELTA,
    });
    if (text(answer, 'payment_hash') !== hash) throw new ProtocolError('invoice answered another payment hash');
    const paymentSecret = text(answer, 'payment_secret');
    if (!/^[0-9a-f]{64}$/.test(paymentSecret)) throw new ProtocolError('invoice answered no 32-byte payment secret');
    const finalCltvDelta = minFinalCltvExpiry(text(answer, 'bolt11'));
    if (finalCltvDelta === undefined) throw new ProtocolError('invoice answered an unreadable bolt11 string');
    return { paymentHash: hash, paymentSecret, finalCltvDelta };
  }

  /**
   * getroutes between the out-peer of S and the in-peer of T under a fresh layer that is removed on every path, and the
   * circular route around it recomputed from the nodes' own policies.
   */
  async findCircularRoute(req: RouteRequest, ownership?: RouteOwnership): Promise<CircularRoute | { readonly refusal: string }> {
    const assertOwner = (): void => {
      if (ownership === undefined) return;
      const plan = ownership.db.executions.plan(ownership.executionId);
      if (plan === null || plan.status !== 'PREFLIGHT' || plan.implementation !== 'cln' || plan.nodePubkey !== this.#ownId
        || plan.sourceChannelKey !== req.sourceChannelKey || plan.targetChannelKey !== req.targetChannelKey
        || plan.principalMsat !== req.principalMsat || !ownership.db.executions.holds(ownership.executionId, ownership.fenceEpoch)) {
        throw new ProtocolError('route assessment has no current execution ownership');
      }
    };
    assertOwner();
    const info = parseInfo(await this.#rest.call('getinfo'));
    if (info.id !== this.#ownId) throw new ProtocolError('getinfo names another node');
    const channels = objects(await this.#rest.call('listpeerchannels'), 'channels').map(parsePeerChannel);
    const peerOf = (scid: string): string | null => {
      const matches = channels.filter(channel => channel.shortChannelId === scid);
      return matches.length === 1 ? matches[0]?.peerId ?? null : null;
    };
    const outPeer = peerOf(req.sourceChannelKey);
    const inPeer = peerOf(req.targetChannelKey);
    if (outPeer === null || inPeer === null) return { refusal: 'NO_FEASIBLE_ROUTE' };
    if (outPeer === inPeer) return { refusal: 'SAME_PEER' };
    const constraints = {
      selfPubkey: this.#ownId, implementation: 'cln' as const, sourceScid: req.sourceChannelKey, targetScid: req.targetChannelKey,
      outPeer, inPeer, principalMsat: req.principalMsat as Msat, maxFeeMsat: req.maxFeeMsat as Msat, maxCltvDelta: req.maxCltvDelta,
      finalCltvDelta: FINAL_CLTV_DELTA, blockHeight: info.blockheight,
    };
    const layer = `fluxwarden-${randomUUID()}`;
    let recorded: RoutingLayerClaim | undefined;
    let recordAcquired: (() => RoutingLayerClaim) | undefined;
    const answer = await this.#routes.buildCircularRoute(constraints, { layer,
      excludeScids: (req.excludeChannels ?? []).flatMap(key => { const scid = channelScid(key); return scid === null ? [] : [scid]; }),
      ...(ownership === undefined ? {} : { lifecycle: {
        beforeCreate: () => {
          assertOwner();
          recordAcquired = ownership.db.routingLayers.prepareAcquisition(ownership.executionId, ownership.fenceEpoch, this.#ownId, layer);
        },
        acquired: () => {
          if (recordAcquired === undefined) throw new ProtocolError('route acquisition has no prepared ownership receipt');
          recorded = recordAcquired();
          // Recording a successful receipt grants no authority for the next native mutation.
          assertOwner();
        },
        removed: () => { if (recorded !== undefined) ownership.db.routingLayers.removedImmediately(recorded, ownership.executionId, ownership.fenceEpoch); },
      } }),
    });
    if (isNoRoute(answer)) return { refusal: answer.code };
    const route = circularRoute(answer, req, outPeer, inPeer);
    // V5 with the CLN padding: the delta the HTLC really carries must fit the cap.
    if (!Number.isSafeInteger(route.totalTimelockDelta) || route.totalTimelockDelta + CLN_BLOCK_PADDING > req.maxCltvDelta) return { refusal: 'CLTV_DELTA_UNSAFE' };
    return route;
  }

  /** A native parameter refusal proves absence only after a successful fresh layer listing. */
  async removeRoutingLayer(layer: string): Promise<'REMOVED' | 'NOT_FOUND'> {
    try {
      await this.#rest.call('askrene-remove-layer', { layer });
      return 'REMOVED';
    } catch (error) {
      if (lightningdRefused(error) && error.code === -32602 && !(await this.#api.listLayers()).some(entry => entry.layer === layer)) return 'NOT_FOUND';
      throw error;
    }
  }

  /**
   * Exactly one sendpay, then waitsendpay in chunks of at most waitChunkSeconds until the attempt deadline. Only a
   * complete answer with our preimage and the principal delivered is a success; a failure counts only when
   * listsendpays reports it failed and our invoice is not paid; everything else is AMBIGUOUS.
   */
  async sendOnRoute(route: CircularRoute, paymentHash: string, paymentSecret: string, onDispatched?: () => void, label?: string): Promise<PaymentObservation> {
    const hash = assertHash(paymentHash);
    const secret = assertHash(paymentSecret, 'payment secret');
    const first = route.hops[0];
    if (first === undefined) throw new RangeError('route has no hops');
    const buildHeight = first.expiry - route.totalTimelockDelta;
    let sender = this.#ownId;
    const hops = route.hops.map(hop => {
      // lightningd/pay.c send_payment: each delay is added to the network height + 1, so the entries are deltas.
      const entry = {
        short_channel_id_dir: `${hop.channelKey}/${String(direction(sender, hop.nodeOut))}`,
        node_id_out: hop.nodeOut,
        amount_out_msat: hop.amountOutMsat.toString(),
        cltv_out: hop.expiry - buildHeight,
      };
      sender = hop.nodeOut;
      return entry;
    });
    if (hops.some(hop => !Number.isSafeInteger(hop.cltv_out) || hop.cltv_out <= 0)) throw new RangeError('route expiries lie below the build height');

    // CLN lightningd/runes.c check_condition compares primitive integers for numeric amount restrictions.
    // Convert only exactly representable principals; larger amounts retain their canonical decimal text.
    const amountMsat = route.principalMsat >= 0n && route.principalMsat <= BigInt(Number.MAX_SAFE_INTEGER)
      ? Number(route.principalMsat) : route.principalMsat.toString();
    let dispatched = false;
    const written = (): void => {
      if (dispatched) return;
      dispatched = true;
      onDispatched?.();
    };
    const started = performance.now();
    let answer: JsonObject;
    try {
      answer = await this.#rest.call('sendpay', { route: hops, payment_hash: hash, payment_secret: secret, amount_msat: amountMsat,
        ...(label === undefined ? {} : { label }) }, { onWritten: written });
    } catch (error) {
      // Only lightningd's own refusal with a code that leaves no HTLC behind may end in a failure; a proxy error,
      // a 500 without a code or a cut leaves the outcome unknown (INV-04).
      const reason = lightningdRefused(error) ? SENDPAY_REFUSALS[error.code ?? 0] : undefined;
      if (reason === undefined) return ambiguous(error);
      return await this.#confirmFailure(hash, reason, true);
    }
    written();
    try {
      if (parseSendPay(answer).status === 'complete') return await this.#complete(answer, hash, route.principalMsat);
    } catch (error) {
      return ambiguous(error);
    }

    for (;;) {
      const remaining = this.#attemptDeadlineMs - (performance.now() - started);
      if (remaining <= 0) return { kind: 'AMBIGUOUS', cause: 'still in flight at the attempt deadline' };
      const timeout = Math.max(1, Math.min(this.#waitChunkSeconds, Math.ceil(remaining / 1000)));
      let result: JsonObject;
      try {
        result = await this.#rest.call('waitsendpay', { payment_hash: hash, timeout });
      } catch (error) {
        if (!lightningdRefused(error)) return ambiguous(error);
        if (error.code === PAY_IN_PROGRESS) continue;
        if (error.code === PAY_NO_SUCH_PAYMENT) return { kind: 'NOT_FOUND' };
        const reason = PAY_FAILURES[error.code ?? 0];
        if (reason === undefined) return ambiguous(error);
        return await this.#confirmFailure(hash, reason, false);
      }
      try {
        return await this.#complete(result, hash, route.principalMsat);
      } catch (error) {
        return ambiguous(error);
      }
    }
  }

  /** listsendpays of the hash (the node's list in every mode): complete with our preimage, pending, failed, or no record. */
  async observePayment(paymentHash: string): Promise<PaymentObservation> {
    const hash = assertHash(paymentHash);
    let parts: ClnSendPay[];
    try {
      parts = await this.#api.listSendPays({ paymentHash: hash });
    } catch (error) {
      return ambiguous(error);
    }
    if (parts.some(part => part.paymentHash !== hash)) return { kind: 'AMBIGUOUS', cause: 'listsendpays answered another payment hash' };
    if (parts.length === 0) return { kind: 'NOT_FOUND' };
    const complete = parts.filter(part => part.status === 'complete');
    if (complete.length > 0) {
      const matches = complete.every(part => part.preimageMatchesHash);
      let fee = 0n;
      let principal = 0n;
      for (const part of complete) {
        if (part.amountMsat === null) return { kind: 'AMBIGUOUS', cause: 'a complete part has no delivered amount' };
        fee += part.amountSentMsat - part.amountMsat;
        principal += part.amountMsat;
      }
      return { kind: 'SUCCEEDED', preimageMatchesHash: matches, feeMsat: fee, htlcCount: complete.length,
        settledChannelKey: matches ? await this.#receiverChannel(hash, principal) : null };
    }
    const pending = parts.filter(part => part.status === 'pending').length;
    if (pending > 0) return { kind: 'IN_FLIGHT' };
    return await this.#attemptFailure(hash);
  }

  /**
   * listsendpays can report `failed` while a part is still pending or before it settles (cln#9036, cln#8635). The
   * failure counts only when waitsendpay, a read of the stored attempt, answers it failed.
   */
  async #attemptFailure(hash: string): Promise<PaymentObservation> {
    try {
      await this.#rest.call('waitsendpay', { payment_hash: hash, timeout: 1 });
    } catch (error) {
      if (!lightningdRefused(error)) return ambiguous(error);
      if (error.code === PAY_IN_PROGRESS) return { kind: 'IN_FLIGHT' };
      const reason = PAY_FAILURES[error.code ?? 0];
      return reason === undefined ? ambiguous(error) : { kind: 'FAILED', reason, local: false, htlcsInFlight: 0 };
    }
    return { kind: 'AMBIGUOUS', cause: 'listsendpays reported failed while waitsendpay reported the payment complete' };
  }

  async invoiceState(paymentHash: string): Promise<InvoiceState> {
    const hash = assertHash(paymentHash);
    const invoices = await this.#api.listInvoices({ paymentHash: hash });
    if (invoices.some(invoice => invoice.paymentHash !== hash)) throw new ProtocolError('listinvoices answered another payment hash');
    const invoice = invoices[0];
    if (invoice === undefined) return 'NOT_FOUND';
    if (invoice.status === 'paid') return 'SETTLED';
    return invoice.status === 'expired' ? 'CANCELED' : 'OPEN';
  }

  /** delinvoice with status unpaid only; an invoice paid meanwhile answers 906 and is reported as paid. */
  async cancelUnpaidInvoice(paymentHash: string, label: string): Promise<CancelResult> {
    const hash = assertHash(paymentHash);
    try {
      await this.#rest.call('delinvoice', { label, status: 'unpaid' });
      return 'CANCELED';
    } catch (error) {
      if (!lightningdRefused(error)) throw error;
      if (error.code === INVOICE_NOT_FOUND) return 'NOT_FOUND';
      if (error.code !== INVOICE_STATUS_UNEXPECTED) throw error;
    }
    const invoices = await this.#api.listInvoices({ label });
    const invoice = invoices[0];
    if (invoice === undefined) return 'NOT_FOUND';
    if (invoice.paymentHash !== hash) throw new ProtocolError('the invoice label names another payment hash');
    if (invoice.status === 'paid') return 'ALREADY_PAID';
    if (invoice.status === 'expired') return 'CANCELED';
    throw new ProtocolError('delinvoice refused an unpaid invoice');
  }

  /** A complete answer: success only with our preimage and exactly the principal delivered. */
  async #complete(answer: JsonObject, hash: string, principalMsat: bigint): Promise<PaymentObservation> {
    const part = parseSendPay(answer);
    if (part.paymentHash !== hash) return { kind: 'AMBIGUOUS', cause: 'the answer names another payment hash' };
    if (part.status !== 'complete') return { kind: 'AMBIGUOUS', cause: `the answer has status ${part.status}` };
    if (part.amountMsat !== principalMsat) return { kind: 'AMBIGUOUS', cause: 'the payment delivered another amount' };
    const parts = await this.#api.listSendPays({ paymentHash: hash });
    const htlcCount = parts.filter(entry => entry.paymentHash === hash && entry.status === 'complete').length;
    if (htlcCount === 0) return { kind: 'AMBIGUOUS', cause: 'listsendpays does not show the completed payment' };
    return {
      kind: 'SUCCEEDED', preimageMatchesHash: part.preimageMatchesHash, feeMsat: part.amountSentMsat - part.amountMsat, htlcCount,
      settledChannelKey: part.preimageMatchesHash ? await this.#receiverChannel(hash, principalMsat) : null,
    };
  }

  /** CLN v26.06.9 listhtlcs.json: completed incoming history correlated with our paid invoice, never the payer route. */
  async #receiverChannel(hash: string, principal: bigint): Promise<string | null> {
    try {
      const invoices = await this.#api.listInvoices({ paymentHash: hash });
      const invoice = invoices.length === 1 ? invoices[0] : undefined;
      if (invoice?.status !== 'paid' || invoice.amountReceivedMsat !== principal || principal <= 0n) return null;
      const limit = 500;
      const history = objects(await this.#rest.call('listhtlcs', { index: 'created', start: 0, limit }), 'htlcs');
      // A full page does not prove that the remaining history contains no other matching incoming HTLC.
      if (history.length >= limit) return null;
      const incoming = history.filter(htlc => text(htlc, 'payment_hash') === hash && text(htlc, 'direction') === 'in' &&
        text(htlc, 'state') === 'SENT_REMOVE_ACK_REVOCATION' && msat(htlc, 'amount_msat') === principal);
      const htlc = incoming.length === 1 ? incoming[0] : undefined;
      if (htlc === undefined) return null;
      const channel = text(htlc, 'short_channel_id');
      if (scidToChanId(channel) === '0') return null;
      return channel;
    } catch {
      return null;
    }
  }

  /**
   * A failure answer counts only when listsendpays reports every part failed and our invoice is not paid (a preimage
   * beats an error, cln#9096). A sendpay refused before any part was stored is a failure before initiation.
   */
  async #confirmFailure(hash: string, reason: string, beforeWait: boolean): Promise<PaymentObservation> {
    try {
      const parts = await this.#api.listSendPays({ paymentHash: hash });
      if (parts.some(part => part.paymentHash !== hash)) return { kind: 'AMBIGUOUS', cause: 'listsendpays answered another payment hash' };
      const invoice = await this.invoiceState(hash);
      if (invoice === 'SETTLED') return { kind: 'AMBIGUOUS', cause: 'our invoice is paid although the payment reported a failure' };
      if (parts.length === 0) {
        return beforeWait ? { kind: 'FAILED', reason: REJECTED_BEFORE_INITIATION, local: true, htlcsInFlight: 0 } : { kind: 'AMBIGUOUS', cause: 'no payment record after a failure answer' };
      }
      if (parts.every(part => part.status === 'failed')) return { kind: 'FAILED', reason, local: false, htlcsInFlight: 0 };
      return { kind: 'AMBIGUOUS', cause: 'listsendpays does not confirm the failure' };
    } catch (error) {
      return ambiguous(error);
    }
  }
}

function circularRoute(answer: CandidateRoute, req: RouteRequest, outPeer: string, inPeer: string): CircularRoute {
  const fee: bigint = answer.totalFeeMsat;
  return {
    sourceChannelKey: req.sourceChannelKey,
    targetChannelKey: req.targetChannelKey,
    outPeer,
    inPeer,
    principalMsat: req.principalMsat,
    hops: answer.hops.map(hop => ({ channelKey: hop.scid, nodeOut: hop.nodeIdOut, amountOutMsat: hop.amountOutMsat, expiry: hop.cltvOut, policy: hop.policy })),
    totalFeeMsat: fee,
    feePpmCeil: ppmCeil(fee, req.principalMsat),
    totalTimelockDelta: answer.totalTimeLock - answer.builtAtHeight,
    parts: 1,
  };
}
