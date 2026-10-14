import { spawnSync } from 'node:child_process';
import { expect,it } from 'vitest';
import { setTimeout as delay } from 'node:timers/promises';
import { loadLndRest } from '../helpers/adapter-interfaces.js';
import type { LndRest } from '../helpers/adapter-interfaces.js';
import { cli,clean,history,initializeRegistry,input,lndConfig,nodeControl,oracle,preflight,retain,setRunner,unchangedOld } from '../../labs/scenarios/chaos/live-reference.mjs';
setRunner((file,args,options)=>spawnSync(file,args,options));
async function recover(rest:LndRest){const start=Date.now();for(;;){try{const info=await rest.call('GET','/v1/getinfo');if(info['synced_to_chain']===true)return;}catch{/* The owned restart can temporarily refuse the read port. */}if(Date.now()-start>30000)throw new Error('GAP T-25 owned LND recovery unavailable');await delay(200);}}
it('CP-034/B1 T-25 owned bitcoind pause must expose an unsynced pinned node before asserting chain-sync refusal',async()=>{
  initializeRegistry();await preflight('t25-before');const original=history(),p=input(),fixture=lndConfig();
  try{
    expect(cli(['doctor'],'t25-doctor',fixture.config).exit).toBe(0);
    const plan=cli(['liquidity','plan','--refresh'],'t25-plan',fixture.config);expect(plan.exit).toBe(0);expect(plan.body.result).toMatchObject({action:'CIRCULAR_REBALANCE',principal_msat:'100000000'});
    const proposal=String(plan.body.result['proposal_id']);expect(cli(['liquidity','approve',proposal,'--key',p.key],'t25-approval',fixture.config).exit).toBe(0);
    nodeControl('bitcoind','pause');const observations=[];const start=Date.now();let unsynced=false;
    do{const info=oracle('lnd-r','getinfo');observations.push(info);unsynced=info['synced_to_chain']===false;}while(!unsynced&&Date.now()-start<10000);
    retain('t25-paused-chain-observations',{observations,unsynced});
    if(!unsynced)throw new Error('GAP T-25 chain-sync: owned bitcoind pause did not make the pinned node report unsynced within the bounded stimulus');
    expect(cli(['actions','execute',proposal,'--require-regtest'],'t25-execute',fixture.config)).toMatchObject({exit:5,body:{error:{step:'chain-sync'}}});unchangedOld(original,history());
  }finally{await clean();await preflight('t25-after');}
});

it('CP-034/B1 T-25 owned persistent LND restart requires a real native unsynced answer before chain-sync refusal',async()=>{
  initializeRegistry();await preflight('t25-restart-before');const original=history(),p=input(),fixture=lndConfig();
  const manifest=p.manifest as {nodes:Record<string,{certificate:{path:string}}> ;credentials:Record<string,{execute:{path:string}}>};
  const node=manifest.nodes['lnd-r'],credential=manifest.credentials['lnd-r'];if(!node||!credential)throw new Error('GAP T-25 owned native credential paths unavailable');
  const {openLndRest}=await loadLndRest(),rest=await openLndRest({host:'localhost',port:29210,tlsCertPath:node.certificate.path,macaroonPath:credential.execute.path,timeoutMs:1000});
  try {
    expect(cli(['doctor'],'t25-restart-doctor',fixture.config).exit).toBe(0);
    const plan=cli(['liquidity','plan','--refresh'],'t25-restart-plan',fixture.config);expect(plan.exit).toBe(0);expect(plan.body.result).toMatchObject({action:'CIRCULAR_REBALANCE',principal_msat:'100000000'});
    const proposal=String(plan.body.result['proposal_id']);expect(cli(['liquidity','approve',proposal,'--key',p.key],'t25-restart-approval',fixture.config).exit).toBe(0);
    const before=oracle('lnd-r','listpayments',['--include_incomplete']);retain('t25-restart-payments-before',before);
    const restarted=spawnSync('docker',['restart',`${p.owner.project}-lnd-r-1`],{encoding:'utf8',shell:false,windowsHide:true,timeout:30000});expect(restarted.status).toBe(0);
    const observations:Record<string,unknown>[]=[],start=Date.now();let unsynced=false;
    do{try{const info=await rest.call('GET','/v1/getinfo');observations.push({at:Date.now(),network:info['chains'],height:info['block_height'],syncedToChain:info['synced_to_chain']});unsynced=info['synced_to_chain']===false;}catch(error){observations.push({at:Date.now(),error:error instanceof Error?error.name:'unknown'});}if(!unsynced)await delay(25);}while(!unsynced&&Date.now()-start<20000);
    retain('t25-restart-native-observations',{observations,unsynced});
    if(!unsynced)throw new Error('GAP T-25 chain-sync: persistent pinned LND restart exposed no valid native synced_to_chain=false answer');
    const immediatelyBefore=await rest.call('GET','/v1/getinfo');retain('t25-restart-native-immediately-before',immediatelyBefore);
    if(immediatelyBefore['synced_to_chain']!==false)throw new Error('GAP T-25 chain-sync: genuine startup false recovered before the public CLI invocation');
    const result=cli(['actions','execute',proposal,'--require-regtest'],'t25-restart-execute',fixture.config);
    if(result.exit!==5||result.body.error?.['step']!=='chain-sync')throw new Error('GAP T-25 chain-sync: startup false did not persist through the actual CLI handshake; retained result is not chain-sync proof');
    expect(result).toMatchObject({exit:5,body:{error:{step:'chain-sync'}}});
    expect(oracle('lnd-r','listpayments',['--include_incomplete'])).toEqual(before);unchangedOld(original,history());
  }finally{await clean();await recover(rest);await preflight('t25-restart-after');}
});
