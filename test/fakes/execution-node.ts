// A scripted node behind the execution port (SPEC §5.1 LightningNodeAdapter as test/helpers/cp030-execution.ts types it).
// Every call is recorded with its arguments, so tests can prove which node calls happened and in which order. Scripted
// behaviours and the node facts they stand for:
// - listChannels: NormalizedChannel values (src/core/normalize.ts); the first call answers `before`, later calls `after`,
//   as a node reports local balances before and after a settled rebalance (SPEC §8.7 step 5);
// - createInvoice: the node returns the hash of the preimage it was given (LND AddInvoice r_preimage -> r_hash,
//   lnrpc/lightning.proto Invoice; CLN invoice preimage -> payment_hash, doc/schemas/invoice.json) and a payment secret;
// - sendOnRoute: by default reports the request written (onDispatched) and answers a confirmed single-HTLC success with
//   the route's fee (LND SendToRouteV2 + TrackPaymentV2, ARCHITECTURE §5 L7/L5; CLN sendpay + waitsendpay, C7/C8);
// - observePayment, invoiceState, cancelUnpaidInvoice: the payer record, the receiver invoice and the receiver-side
//   closure (SPEC §8.4; LND CancelInvoice is idempotent and refused for a settled invoice, invoices/invoiceregistry.go;
//   CLN delinvoice ... unpaid fails with 906 for a paid invoice, doc/schemas/delinvoice.json).
import { createHash } from 'node:crypto';
import type { CircularRoute, FakeChannel } from '../helpers/cp028-executor.js';
import type { CancelResult, ExecutionAdapter, InvoiceResult, InvoiceState, PaymentObservation } from '../helpers/cp030-execution.js';

export interface Call { readonly name: string; readonly args: readonly unknown[] }

export interface SendContext {
  readonly route: CircularRoute;
  readonly paymentHash: string;
  readonly paymentSecret: string;
  readonly onDispatched: (() => void) | undefined;
}

export interface ExecutionScript {
  /** Declared receiver receipt for the fake's default one-HTLC send; null means unavailable. */
  settledChannelKey: string | null;
  before: () => FakeChannel[];
  after: () => FakeChannel[];
  invoice: (amountMsat: bigint, preimage: Uint8Array, label: string) => Promise<InvoiceResult>;
  send: (context: SendContext) => Promise<PaymentObservation>;
  observe: (paymentHash: string, mode: 'track' | 'sweep' | undefined) => Promise<PaymentObservation>;
  invoiceState: (paymentHash: string) => Promise<InvoiceState>;
  cancel: (paymentHash: string, label: string) => Promise<CancelResult>;
}

export const PAYMENT_SECRET = '5e'.repeat(32);

export const succeeded = (feeMsat: bigint, htlcCount = 1, preimageMatchesHash = true, settledChannelKey: string | null = null): PaymentObservation =>
  ({ kind: 'SUCCEEDED', preimageMatchesHash, feeMsat, htlcCount, settledChannelKey });

export const failed = (reason: string, htlcsInFlight = 0): PaymentObservation => ({ kind: 'FAILED', reason, local: false, htlcsInFlight });

/** Never settles (a node or network that holds the answer). */
export const never = <T>(): Promise<T> => new Promise<T>(() => undefined);

export class ScriptedExecutionNode implements ExecutionAdapter {
  readonly calls: Call[] = [];
  readonly script: ExecutionScript;
  #listed = 0;

  constructor(over: Partial<ExecutionScript> = {}) {
    this.script = {
      settledChannelKey: null,
      before: () => [],
      after: () => [],
      invoice: (_amount, preimage) => Promise.resolve({ paymentHash: createHash('sha256').update(preimage).digest('hex'), paymentSecret: PAYMENT_SECRET, finalCltvDelta: 18 }),
      send: context => { context.onDispatched?.(); return Promise.resolve(succeeded(context.route.totalFeeMsat, 1, true, this.script.settledChannelKey)); },
      observe: () => Promise.resolve({ kind: 'IN_FLIGHT' }),
      invoiceState: () => Promise.resolve('OPEN'),
      cancel: () => Promise.resolve('CANCELED'),
      ...over,
    };
  }

  named(name: string): Call[] { return this.calls.filter(call => call.name === name); }
  count(name: string): number { return this.named(name).length; }
  names(): string[] { return this.calls.map(call => call.name); }

  listChannels(): Promise<readonly FakeChannel[]> {
    this.calls.push({ name: 'listChannels', args: [] });
    this.#listed += 1;
    return Promise.resolve(this.#listed === 1 ? this.script.before() : this.script.after());
  }

  createInvoice(amountMsat: bigint, preimage: Uint8Array, label: string, expirySeconds: number): Promise<InvoiceResult> {
    this.calls.push({ name: 'createInvoice', args: [amountMsat, Buffer.from(preimage), label, expirySeconds] });
    return this.script.invoice(amountMsat, preimage, label);
  }

  sendOnRoute(route: CircularRoute, paymentHash: string, paymentSecret: string, onDispatched?: () => void): Promise<PaymentObservation> {
    this.calls.push({ name: 'sendOnRoute', args: [route, paymentHash, paymentSecret] });
    return this.script.send({ route, paymentHash, paymentSecret, onDispatched });
  }

  observePayment(paymentHash: string, mode?: 'track' | 'sweep'): Promise<PaymentObservation> {
    this.calls.push({ name: 'observePayment', args: [paymentHash, mode] });
    return this.script.observe(paymentHash, mode);
  }

  invoiceState(paymentHash: string): Promise<InvoiceState> {
    this.calls.push({ name: 'invoiceState', args: [paymentHash] });
    return this.script.invoiceState(paymentHash);
  }

  cancelUnpaidInvoice(paymentHash: string, label: string): Promise<CancelResult> {
    this.calls.push({ name: 'cancelUnpaidInvoice', args: [paymentHash, label] });
    return this.script.cancel(paymentHash, label);
  }

  /** Mutating calls that move funds (SPEC §5.1: reachable only from the executor). */
  fundMovingCalls(): string[] {
    return this.names().filter(name => name === 'createInvoice' || name === 'sendOnRoute');
  }
}
