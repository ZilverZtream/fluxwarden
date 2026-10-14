import { spawnSync } from 'node:child_process';
import { expect,it } from 'vitest';
import { cli,clean,feeConfig,history,initializeRegistry,oracle,preflight,retain,setRunner,unchangedOld } from '../../labs/scenarios/chaos/live-reference.mjs';
setRunner((file,args,options)=>spawnSync(file,args,options));

// Pinned CLN v26.06.9 getroutes error206; SPEC11.6 T03 requires the public
// planner to produce NO_ACTION/FEE_CEILING_EXCEEDED without a payment.
it('CP-033/B1 T-03 owned pinned CLN over-cap quote produces NO_ACTION with unchanged invoices and payments',async()=>{
  initializeRegistry();await preflight('t03-before');const original=history(),fixture=feeConfig();
  const payments=oracle('cln-m','listsendpays'),invoices=oracle('cln-m','listinvoices');retain('t03-node-before',{payments,invoices});
  try {
    expect(cli(['doctor'],'t03-doctor',fixture.config).exit).toBe(0);
    const plan=cli(['liquidity','plan','--refresh'],'t03-plan',fixture.config);
    expect(plan.exit).toBe(0);expect(plan.body.result).toMatchObject({action:'NO_ACTION',route:null});
    expect(plan.body.result['candidates']).toEqual(expect.arrayContaining([expect.objectContaining({code:'FEE_CEILING_EXCEEDED'})]));
    const after={payments:oracle('cln-m','listsendpays'),invoices:oracle('cln-m','listinvoices')};retain('t03-node-after',after);
    expect(after).toEqual({payments,invoices});unchangedOld(original,history());
  }finally{await clean();await preflight('t03-after');}
});
