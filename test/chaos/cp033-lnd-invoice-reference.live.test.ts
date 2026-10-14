// Pinned native reference: lnd v0.21.4-beta routing/router.go:35-54,
// https://github.com/lightningnetwork/lnd/blob/v0.21.4-beta/routing/router.go#L35
// MinCLTVDelta=24. Owned native controls reject 23 and accept 24; both controls
// use fresh preimages and cancel unpaid invoices by hash. SPEC T-05 requires an
// executable quote and invoice under the existing total CLTV cap of 144.
import { expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadLndRest } from '../helpers/adapter-interfaces.js';
import { loadLndExecute, sha256 } from '../helpers/cp030-execution.js';
import { clean, history, initializeRegistry, input, oracle, preflight, register, retain, setRunner, unchangedOld } from '../../labs/scenarios/chaos/live-reference.mjs';
setRunner((file,args,options) => spawnSync(file,args,options));

it('CP-033/B1 T-05 pinned LND public invoice port accepts its final delta 24 without sending a payment', async () => {
  initializeRegistry(); await preflight('t05-lnd-invoice-before'); const original=history(), p=input();
  const manifest=p.manifest as {nodes:Record<string,{certificate:{path:string}}> ; credentials:Record<string,{execute:{path:string}}>};
  const label=`owned-invoice-gold-${randomUUID()}`, preimagePath=join(p.tmp,`${label}.preimage.bin`);
  writeFileSync(preimagePath,randomBytes(32),{mode:0o600}); appendFileSync(join(p.tmp,'declared-out.txt'),`${preimagePath}\n`); register(preimagePath,`${label}.preimage.bin`);
  const hash=sha256(readFileSync(preimagePath));
  const {openLndRest}=await loadLndRest(), {LndExecutionAdapter}=await loadLndExecute();
  const node=manifest.nodes['lnd-r'], credential=manifest.credentials['lnd-r'];
  if(!node||!credential)throw new Error('GAP pinned owned LND credential paths unavailable');
  const rest=await openLndRest({host:'localhost',port:29210,tlsCertPath:node.certificate.path,macaroonPath:credential.execute.path});
  const adapter=new LndExecutionAdapter(rest,{trackDeadlineMs:3000});
  try {
    const invoice=await adapter.createInvoice(100000000n,readFileSync(preimagePath),label,120);
    retain('t05-lnd-invoice-gold',{paymentHash:invoice.paymentHash,finalCltvDelta:invoice.finalCltvDelta});
    expect(invoice.paymentHash).toBe(hash); expect(invoice.finalCltvDelta).toBe(24);
    expect((oracle('lnd-r','listpayments',['--include_incomplete'])['payments'] as Record<string,unknown>[]).filter(v=>v['payment_hash']===hash)).toEqual([]);
    unchangedOld(original,history());
  } finally {
    retain('t05-lnd-invoice-gold-cancel',{hash,state:await adapter.cancelUnpaidInvoice(hash,label)});
    await clean(); await preflight('t05-lnd-invoice-after');
  }
});
