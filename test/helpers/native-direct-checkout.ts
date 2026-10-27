import { randomBytes, randomUUID } from 'node:crypto';
import { appendFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';
import { input, oracle, register, retain } from '../../labs/scenarios/chaos/live-reference.mjs';

// Same native one-channel checkout used by the T-18 CLI case, through the
// actual compiled public adapters and the supplied owner's ports/credentials.
// A conclusive settled callback records custody before assertions can fail.
export async function nativeDirectCheckout(amount: bigint, reverse: boolean, settled: () => void): Promise<void> {
  if (amount <= 0n || amount > 100000000n || amount % 1000n !== 0n) throw new Error('GAP T-18 bounded whole-satoshi checkout required');
  const p = input(), owner = p.owner as typeof p.owner & { ports: { lndRest: number; clnRest: number } };
  const manifest = p.manifest as { nodes: Record<string, { pubkey: string; certificate: { path: string } }>;
    credentials: Record<string, { execute: { path: string } }> };
  const lnd = manifest.nodes['lnd-r'], cln = manifest.nodes['cln-m'], lc = manifest.credentials['lnd-r'], cc = manifest.credentials['cln-m'];
  if (!lnd || !cln || !lc || !cc) throw new Error('GAP T-18 owned checkout identity unavailable');
  const channel = (oracle('lnd-r', 'listchannels')['channels'] as Record<string, unknown>[]).find(v => v['remote_pubkey'] === cln.pubkey);
  if (!channel || (channel['pending_htlcs'] as unknown[]).length) throw new Error('GAP T-18 clean direct channel unavailable');
  const url = (path: string): string => pathToFileURL(resolve('dist', path)).href;
  const [{ openLndRest }, { openClnRest }, { LndExecutionAdapter }, { ClnExecutionAdapter }] = await Promise.all([
    import(url('node-lnd/rest.js')) as Promise<typeof import('../../src/node-lnd/rest.js')>,
    import(url('node-cln/rest.js')) as Promise<typeof import('../../src/node-cln/rest.js')>,
    import(url('node-lnd/execute.js')) as Promise<typeof import('../../src/node-lnd/execute.js')>,
    import(url('node-cln/execute.js')) as Promise<typeof import('../../src/node-cln/execute.js')>,
  ]);
  const lndAdapter = new LndExecutionAdapter(await openLndRest({ host: 'localhost', port: owner.ports.lndRest,
    tlsCertPath: lnd.certificate.path, macaroonPath: lc.execute.path }), { trackDeadlineMs: 10000 });
  const clnRest = await openClnRest({ host: 'localhost', port: owner.ports.clnRest, tlsCertPath: cln.certificate.path, runePath: cc.execute.path });
  let queue = Promise.resolve();
  const clnAdapter = new ClnExecutionAdapter({ call: (method, params) => {
    const next = queue.then(async () => { await delay(150); return clnRest.call(method, params); });
    queue = next.then(() => undefined, () => undefined); return next;
  } }, { ownId: cln.pubkey, waitChunkSeconds: 2, attemptDeadlineMs: 10000 });
  const payer = reverse ? clnAdapter : lndAdapter, payee = reverse ? lndAdapter : clnAdapter;
  const label = `owned-t18-worker-${randomUUID()}`, preimage = randomBytes(32), path = join(p.tmp, `${label}.preimage.bin`);
  writeFileSync(path, preimage, { mode: 0o600 }); appendFileSync(join(p.tmp, 'declared-out.txt'), `${path}\n`); register(path, `${label}.preimage.bin`);
  let hash: string | undefined;
  try {
    const invoice = await payee.createInvoice(amount, preimage, label, 120); hash = invoice.paymentHash;
    const secret = join(p.tmp, `${label}.payment-secret.bin`);
    writeFileSync(secret, Buffer.from(invoice.paymentSecret, 'hex'), { mode: 0o600 }); appendFileSync(join(p.tmp, 'declared-out.txt'), `${secret}\n`); register(secret, `${label}.payment-secret.bin`);
    const height = Number(oracle('lnd-r', 'getinfo')['block_height']), delta = Math.max(24, invoice.finalCltvDelta);
    if (delta + 3 > 144) throw new Error('GAP T-18 direct checkout CLTV bound');
    const key = String(channel[reverse ? 'scid_str' : 'scid']), destination = reverse ? lnd.pubkey : cln.pubkey;
    let payment = await payer.sendOnRoute({ sourceChannelKey: key, targetChannelKey: key, outPeer: destination, inPeer: destination,
      principalMsat: amount, hops: [{ channelKey: key, nodeOut: destination, amountOutMsat: amount, expiry: height + delta }],
      totalFeeMsat: 0n, feePpmCeil: 0n, totalTimelockDelta: delta, parts: 1 }, hash, invoice.paymentSecret);
    if (payment.kind !== 'SUCCEEDED') payment = await payer.observePayment(hash, 'sweep');
    const proven = payment.kind === 'SUCCEEDED' && payment.preimageMatchesHash && payment.feeMsat === 0n && payment.htlcCount === 1;
    if (proven) settled();
    retain(`${label}-payment`, { amountMsat: amount.toString(), reverse, hash, payment, conclusiveZeroFeeSettlement: proven });
    if (!proven) throw new Error('LabInvalidError: T-18 checkout not conclusively settled; no payment retry');
  } finally {
    if (hash !== undefined) retain(`${label}-cleanup`, { hash, invoiceState: await payee.cancelUnpaidInvoice(hash, label) });
  }
}
