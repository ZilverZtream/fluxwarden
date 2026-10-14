// Ordinary incoming checkout payments prepare a disposable merchant; snapshots decide when to stop.
// SPEC §14.1 requires channel 2 starved while channel 5 has spare receivable capacity.
export async function prepareStarvation(port, { targetReceivableMsat = 5_000_000n, maxInvoiceMsat = 100_000_000n, maxPayments = 50 } = {}) {
  const identity = await port.identity();
  if (identity.network !== 'regtest') throw new Error('demo network-lock');
  if (targetReceivableMsat < 0n || maxInvoiceMsat < 1n || !Number.isSafeInteger(maxPayments) || maxPayments < 1) throw new Error('demo preparation input');
  const before = await port.channels();
  let observed = before;
  let payments = 0;
  while (observed.channel2ReceivableMsat > targetReceivableMsat) {
    if (payments >= maxPayments) throw new Error('demo preparation payment bound');
    const amountMsat = observed.channel2ReceivableMsat - targetReceivableMsat < maxInvoiceMsat
      ? observed.channel2ReceivableMsat - targetReceivableMsat : maxInvoiceMsat;
    const receipt = await port.checkout({ merchant: 'cln-m', payer: 'lnd-p', channels: [1, 2], amountMsat });
    if (receipt.status !== 'SUCCEEDED') throw new Error('demo preparation checkout refused');
    const next = await port.channels();
    if (next.channel2ReceivableMsat !== observed.channel2ReceivableMsat - amountMsat) throw new Error('demo preparation channel 2 delta');
    if (next.channel5ReceivableMsat !== before.channel5ReceivableMsat) throw new Error('demo preparation channel 5 changed');
    observed = next;
    payments += 1;
  }
  if (observed.channel5ReceivableMsat < 100_000_000n) throw new Error('demo preparation channel 5 insufficient');
  return { before, after: observed, payments, targetInboundMsat: observed.channel2ReceivableMsat + 100_000_000n };
}
