/*
Interface: labs/scenarios/demo/prepare.mjs exports prepareStarvation(port, options).
The port observes merchant identity/channels and makes ordinary LND-P→LND-R→CLN-M invoice payments.
It never authorizes a rebalance. An operator sets channel 2's inbound target to observed receivable+100,000,000 msat;
channel 5's target is zero, retaining spare inbound for the approved 100,000,000 msat rebalance (SPEC §14.1).
The reproduce script runs this preparation before the starvation phase and again before the fresh chaos plan.
*/
import { expect, it } from 'vitest';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { repoRoot } from '../helpers/cli.js';

interface PreparationModule {
  prepareStarvation(port: ReturnType<typeof merchant>['port'], options?: { maxPayments?: number }): Promise<{
    before: { channel2ReceivableMsat: bigint; channel5ReceivableMsat: bigint };
    after: { channel2ReceivableMsat: bigint; channel5ReceivableMsat: bigint }; payments: number; targetInboundMsat: bigint;
  }>;
}
const prepareStarvation = async (port: ReturnType<typeof merchant>['port'], options?: { maxPayments?: number }) => {
  const module = await import(pathToFileURL(join(repoRoot, 'labs/scenarios/demo/prepare.mjs')).href) as PreparationModule;
  return await module.prepareStarvation(port, options);
};

function merchant(network = 'regtest') {
  let two = 1_250_000_000n;
  const five = 1_250_000_000n, calls: { merchant: string; payer: string; channels: number[]; amountMsat: bigint }[] = [];
  return {
    port: { identity: () => Promise.resolve({ network }), channels: () => Promise.resolve({ channel2ReceivableMsat: two, channel5ReceivableMsat: five }),
      checkout: (request: { merchant: string; payer: string; channels: number[]; amountMsat: bigint }) => { calls.push(request); two -= request.amountMsat; return Promise.resolve({ status: 'SUCCEEDED' }); } },
    calls, two: () => two,
  };
}

it('CP-043/B3 controlled preparation starves channel 2 while preserving channel 5 and a 100000000 msat principal', async () => {
  const m = merchant(), result = await prepareStarvation(m.port);
  expect(m.calls).toHaveLength(13);
  expect(m.calls.every(c => c.merchant === 'cln-m' && c.payer === 'lnd-p' && c.channels.join(',') === '1,2')).toBe(true);
  expect(m.calls.slice(0, 12).map(c => c.amountMsat)).toEqual(new Array<bigint>(12).fill(100_000_000n));
  expect(m.calls[12]?.amountMsat).toBe(45_000_000n); expect(m.two()).toBe(5_000_000n);
  expect(result).toEqual({ before: { channel2ReceivableMsat: 1_250_000_000n, channel5ReceivableMsat: 1_250_000_000n },
    after: { channel2ReceivableMsat: 5_000_000n, channel5ReceivableMsat: 1_250_000_000n }, payments: 13, targetInboundMsat: 105_000_000n });
});

it('CP-043/B3 preparation fails if a payment changes channel 5 or produces no measured channel 2 drain', async () => {
  const m = merchant(); m.port.checkout = () => Promise.resolve({ status: 'SUCCEEDED' });
  await expect(prepareStarvation(m.port)).rejects.toThrow('demo preparation channel 2 delta');
});

it('CP-043/B3 preparation fails if the independent snapshot shows channel 5 was consumed', async () => {
  const m = merchant(), channels = m.port.channels; let reads = 0;
  m.port.channels = async () => { const snapshot = await channels(); return { ...snapshot, channel5ReceivableMsat: snapshot.channel5ReceivableMsat - (reads++ === 0 ? 0n : 1n) }; };
  await expect(prepareStarvation(m.port)).rejects.toThrow('demo preparation channel 5 changed');
});

it('CP-043/B3 preparation refuses a non-regtest merchant before any invoice', async () => {
  const m = merchant('mainnet'); await expect(prepareStarvation(m.port)).rejects.toThrow('demo network-lock'); expect(m.calls).toEqual([]);
});

it('CP-043/B3 preparation is bounded when a dirty lab needs more payments', async () => {
  const m = merchant(); await expect(prepareStarvation(m.port, { maxPayments: 1 })).rejects.toThrow('demo preparation payment bound'); expect(m.calls).toHaveLength(1);
});
