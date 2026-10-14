/* Interface: labs/docker/demo/driver.mjs exports prepareDemoStarvation(port, options),
 * with prepareStarvation's identity/channels/checkout port and options. The demo wrapper
 * bounds invoice principal and payment count before checkout and preserves observed deltas (SPEC §14.1).
 */
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';

interface Options { targetReceivableMsat?: bigint; maxInvoiceMsat?: bigint; maxPayments?: number }
interface Snapshot { channel2ReceivableMsat: bigint; channel5ReceivableMsat: bigint }
interface Payment { merchant: string; payer: string; channels: number[]; amountMsat: bigint }
interface Driver {
  prepareDemoStarvation: (port: ReturnType<typeof merchant>['port'], options?: Options) => Promise<{
    before: Snapshot; after: Snapshot; payments: number; targetInboundMsat: bigint;
  }>;
}
const wrapper = async () => (await import(pathToFileURL(join(repoRoot, 'labs/docker/demo/driver.mjs')).href) as Driver).prepareDemoStarvation;

function merchant(two = 1_250_000_000n, five = 1_250_000_000n) {
  const calls: Payment[] = [];
  return {
    calls,
    port: {
      identity: () => Promise.resolve({ network: 'regtest' }),
      channels: () => Promise.resolve({ channel2ReceivableMsat: two, channel5ReceivableMsat: five }),
      checkout: (payment: Payment) => { calls.push(payment); two -= payment.amountMsat; return Promise.resolve({ status: 'SUCCEEDED' }); },
    },
  };
}

it.each([
  { options: { maxInvoiceMsat: 100_000_001n }, label: 'invoice above 100000000 msat' },
  { options: { maxPayments: 51 }, label: 'payment count above 50' },
])('CP-043/B3 demo preparation refuses $label before any invoice or send', async ({ options }) => {
  const prepare = await wrapper(), m = merchant();
  await expect(prepare(m.port, options)).rejects.toThrow('demo preparation input');
  expect(m.calls).toEqual([]);
});

it('CP-043/B3 demo preparation refuses observed channel 5 below 100000000 msat before any invoice or send', async () => {
  const prepare = await wrapper(), m = merchant(1_250_000_000n, 99_999_999n);
  await expect(prepare(m.port)).rejects.toThrow('demo preparation channel 5 insufficient');
  expect(m.calls).toEqual([]);
});

it('CP-043/B3 demo preparation refuses observed channel 2 below the requested target before any invoice or send', async () => {
  const prepare = await wrapper(), m = merchant(4_999_999n);
  await expect(prepare(m.port, { targetReceivableMsat: 5_000_000n })).rejects.toThrow('demo preparation channel 2 below target');
  expect(m.calls).toEqual([]);
});

it('CP-043/B3 valid demo preparation delegates exact payments and preserves the observed custom target and channel deltas', async () => {
  const prepare = await wrapper(), m = merchant();
  const result = await prepare(m.port, { targetReceivableMsat: 10_000_000n, maxInvoiceMsat: 100_000_000n, maxPayments: 50 });
  expect(m.calls).toEqual([
    ...Array.from({ length: 12 }, () => ({ merchant: 'cln-m', payer: 'lnd-p', channels: [1, 2], amountMsat: 100_000_000n })),
    { merchant: 'cln-m', payer: 'lnd-p', channels: [1, 2], amountMsat: 40_000_000n },
  ]);
  expect(result).toEqual({ before: { channel2ReceivableMsat: 1_250_000_000n, channel5ReceivableMsat: 1_250_000_000n },
    after: { channel2ReceivableMsat: 10_000_000n, channel5ReceivableMsat: 1_250_000_000n }, payments: 13, targetInboundMsat: 110_000_000n });
});
