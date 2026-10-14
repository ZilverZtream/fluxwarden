import { spawnSync } from 'node:child_process';
import { randomBytes,randomUUID } from 'node:crypto';
import { appendFileSync,readFileSync,writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { expect,it } from 'vitest';
import { loadClnRest,loadLndRest } from '../helpers/adapter-interfaces.js';
import { loadClnExecute,loadLndExecute,sha256 } from '../helpers/cp030-execution.js';
import { isCandidate,loadLndRoutes,loadRoute,type RouteChannel,type RouteConstraints } from '../helpers/route-interfaces.js';
import { cli,clnConfig,clean,history,initializeRegistry,input,lndConfig,oracle,preflight,query,register,retain,setRunner,unchangedOld } from '../../labs/scenarios/chaos/live-reference.mjs';
setRunner((file,args,options)=>spawnSync(file,args,options));
function receivable(){const p=input(),nodes=p.manifest['nodes'] as Record<string,{pubkey:string}>,peer=nodes['lnd-r'];if(!peer)throw new Error('GAP owned native LND peer unavailable');const channel=(oracle('cln-m','listpeerchannels')['channels'] as Record<string,unknown>[]).find(v=>v['peer_id']===peer.pubkey);if(!channel)throw new Error('GAP owned native target channel unavailable');return BigInt(String(channel['receivable_msat']));}

// An ordinary one-channel payment avoids the unrelated LND-P payer reserve.
// Native ListPeerChannels receivable includes this channel's constraints; no
// amount exceeds that observation or the original 100m/300k/2500ppm/144 caps.
async function directCheckout(amount:bigint,index:number,reverse=false) {
  const p=input(), manifest=p.manifest as {nodes:Record<string,{pubkey:string;certificate:{path:string}}> ;credentials:Record<string,{execute:{path:string}}>};
  const lnd=manifest.nodes['lnd-r'], cln=manifest.nodes['cln-m'], lc=manifest.credentials['lnd-r'],cc=manifest.credentials['cln-m'];
  if(!lnd||!cln||!lc||!cc)throw new Error('GAP T-18 owned direct credential paths unavailable');
  expect(amount>0n&&amount<=100000000n).toBe(true);
  const before=oracle('lnd-r','listchannels'),channel=(before['channels'] as Record<string,unknown>[]).find(v=>v['remote_pubkey']===cln.pubkey);
  if(!channel)throw new Error('GAP T-18 owned direct channel unavailable');
  const spendable=(BigInt(String(channel['local_balance']))-BigInt(String(channel['local_chan_reserve_sat']))-BigInt(String(channel['commit_fee'])))*1000n;
  if(!reverse)expect(spendable>=amount).toBe(true);
  const {openLndRest}=await loadLndRest(),{openClnRest}=await loadClnRest(),{LndExecutionAdapter}=await loadLndExecute(),{ClnExecutionAdapter}=await loadClnExecute();
  const sender=new LndExecutionAdapter(await openLndRest({host:'localhost',port:29210,tlsCertPath:lnd.certificate.path,macaroonPath:lc.execute.path}),{trackDeadlineMs:10000});
  const receiverRest=await openClnRest({host:'localhost',port:29211,tlsCertPath:cln.certificate.path,runePath:cc.execute.path});
  let queue=Promise.resolve();
  const receiver=new ClnExecutionAdapter({call:(method,params)=>{const next=queue.then(async()=>{await delay(150);return receiverRest.call(method,params);});queue=next.then(()=>undefined,()=>undefined);return next;}}, {ownId:cln.pubkey,waitChunkSeconds:2,attemptDeadlineMs:10000});
  const payee=reverse?sender:receiver,payer=reverse?receiver:sender;
  const label=`owned-t18-direct-${randomUUID()}`, path=join(p.tmp,`${label}.preimage.bin`);
  writeFileSync(path,randomBytes(32),{mode:0o600});appendFileSync(join(p.tmp,'declared-out.txt'),`${path}\n`);register(path,`${label}.preimage.bin`);const hash=sha256(readFileSync(path));
  try {
    const invoice=await payee.createInvoice(amount,readFileSync(path),label,120),height=Number(oracle('lnd-r','getinfo')['block_height']),delta=Math.max(24,invoice.finalCltvDelta),key=reverse?String(channel['scid_str']):String(channel['scid']),destination=reverse?lnd.pubkey:cln.pubkey;
    const secretPath=join(p.tmp,`${label}.payment-secret.bin`);writeFileSync(secretPath,Buffer.from(invoice.paymentSecret,'hex'),{mode:0o600});appendFileSync(join(p.tmp,'declared-out.txt'),`${secretPath}\n`);register(secretPath,`${label}.payment-secret.bin`);
    expect(delta+3<=144).toBe(true);
    const payment=await payer.sendOnRoute({sourceChannelKey:key,targetChannelKey:key,outPeer:destination,inPeer:destination,principalMsat:amount,hops:[{channelKey:key,nodeOut:destination,amountOutMsat:amount,expiry:height+delta}],totalFeeMsat:0n,feePpmCeil:0n,totalTimelockDelta:delta,parts:1},hash,invoice.paymentSecret);
    retain(`t18-direct-${String(index)}`,{hash,amountMsat:amount.toString(),before,payment});expect(payment).toMatchObject({kind:'SUCCEEDED',preimageMatchesHash:true,feeMsat:0n,htlcCount:1});
  }finally{retain(`t18-direct-${String(index)}-invoice-cleanup`,{hash,state:await payee.cancelUnpaidInvoice(hash,label)});}
}

it('CP-034/B1 T-18 ordinary reverse payment restores only the owned tested channel to a feasible fresh-plan baseline',async()=>{
  initializeRegistry();await preflight('t18-restore-before');const before=history();
  try{const initial=receivable();retain('t18-restore-baseline',{initial});
    // A fresh proposal must be feasible before starvation: restore to 120m,
    // then fresh own approvals will be prepared before reducing it to 60m.
    if(initial<120000000n){let remaining=120000000n-initial;for(let i=0;remaining>0n;i+=1){const amount=remaining<100000000n?remaining:100000000n;await directCheckout(amount,100+i,true);remaining-=amount;}}
    retain('t18-restore-result',{receivable:receivable()});unchangedOld(before,history());
  }finally{await clean();await preflight('t18-restore-after');}
});

it('CP-034/B1 T-18 public validator refuses an actual approved native LND route against fresh observed spendable balance',async()=>{
  initializeRegistry();await preflight('t18-v8-before');const original=history(),p=input();
  try{
    const initial=receivable();if(initial<120000000n)await directCheckout(120000000n-initial,200,true);
    const fixture=lndConfig(true);expect(cli(['doctor'],'t18-v8-doctor',fixture.config).exit).toBe(0);
    const plan=cli(['liquidity','plan','--refresh'],'t18-v8-plan',fixture.config);expect(plan.exit).toBe(0);const proposal=plan.body.result;expect(proposal).toMatchObject({action:'CIRCULAR_REBALANCE',principal_msat:'100000000'});
    const id=String(proposal['proposal_id']);expect(cli(['liquidity','approve',id,'--key',p.key],'t18-v8-approval',fixture.config).exit).toBe(0);
    const manifest=p.manifest as {nodes:Record<string,{pubkey:string;certificate:{path:string}}> ;credentials:Record<string,{execute:{path:string}}>},node=manifest.nodes['lnd-r'],credential=manifest.credentials['lnd-r'];if(!node||!credential)throw new Error('GAP T18 native public route credentials unavailable');
    const native=oracle('lnd-r','listchannels'),channels=native['channels'] as Record<string,unknown>[],source=channels.find(v=>v['scid']===proposal['source_channel']),target=channels.find(v=>v['scid']===proposal['target_channel']);if(!source||!target)throw new Error('GAP T18 native circular endpoints missing');
    const height=Number(oracle('lnd-r','getinfo')['block_height']),constraints:RouteConstraints={selfPubkey:node.pubkey,implementation:'lnd',sourceScid:String(source['scid_str']),targetScid:String(target['scid_str']),outPeer:String(source['remote_pubkey']),inPeer:String(target['remote_pubkey']),principalMsat:100000000n,maxFeeMsat:250000n,maxCltvDelta:144,finalCltvDelta:24,blockHeight:height};
    const {openLndRest}=await loadLndRest(),{LndRouteApi}=await loadLndRoutes(),rest=await openLndRest({host:'localhost',port:29210,tlsCertPath:node.certificate.path,macaroonPath:credential.execute.path});
    const candidate=await new LndRouteApi(rest).buildCircularRoute(constraints);if(!isCandidate(candidate))throw new Error('GAP T18 actual pre-drain native approved route unavailable');
    const approved=proposal['route'] as {hops:Record<string,unknown>[];fee_msat:string;cltv_delta:number;padding:number};
    expect(candidate.hops.map(v=>({channel:v.scid,node_out:v.nodeIdOut,amount_msat:v.amountOutMsat.toString(),cltv:v.cltvOut}))).toEqual(approved.hops);
    expect(candidate.totalFeeMsat).toBe(BigInt(approved.fee_msat));expect(candidate.totalTimeLock-height+approved.padding<=144).toBe(true);retain('t18-v8-native-approved-route',{candidate,constraints,approved,source,target});
    await directCheckout(receivable()-60000000n,201);
    const snapshot=cli(['channels','--node','lnd-r'],'t18-v8-current-native-snapshot',fixture.config);expect(snapshot.exit).toBe(0);
    const nodeRows=snapshot.body.result['nodes'] as {channels:Record<string,unknown>[]}[],observed=nodeRows[0]?.channels;if(!observed)throw new Error('GAP T18 native snapshot missing');
    const normalized:RouteChannel[]=observed.map(v=>{const nativeChannel=channels.find(n=>n['scid']===v['channel']);if(!nativeChannel||v['state']!=='ACTIVE')throw new Error('GAP T18 native active channel identity changed');expect(Date.now()-Date.parse(String(v['observed_at']))).toBeLessThan(60000);return{channelKey:String(v['channel']),scid:String(nativeChannel['scid_str']),peerPubkey:String(v['peer']),state:'ACTIVE',spendableMsat:BigInt(String(v['spendable_msat'])),receivableMsat:BigInt(String(v['receivable_msat']))};});
    expect(Number(oracle('lnd-r','getinfo')['block_height'])).toBe(height);expect(receivable()).toBe(60000000n);
    const counts={payments:oracle('lnd-r','listpayments',['--include_incomplete']),invoices:oracle('lnd-r','listinvoices')};
    const verdict=(await loadRoute()).validateRoute(candidate,constraints,normalized,{maxFeeMsat:300000n,maxFeePpm:2500n,exemptFeeMsat:0n,maxCltvDelta:144,minChannelReserveMsat:10000000n});retain('t18-v8-native-verdict',{label:'public validator against actual native observations',verdict,candidate,normalized});
    expect(verdict).toEqual({ok:false,code:'FIRST_HOP_SPENDABLE',check:'V8'});
    const actual=cli(['actions','execute',id,'--require-regtest'],'t18-v8-cli-earlier-guard',fixture.config);expect(actual).toMatchObject({exit:5,body:{error:{step:'RESERVE_FLOOR'}}});
    expect({payments:oracle('lnd-r','listpayments',['--include_incomplete']),invoices:oracle('lnd-r','listinvoices')}).toEqual(counts);unchangedOld(original,history());
  }finally{await clean();await preflight('t18-v8-after');}
});

// SPEC T-18 / INV-14: a quote based on graph capacity is not authority to
// dispatch after a real last-hop/first-hop available balance has fallen.
it('CP-034/B1 T-18 real bounded direct drain refuses last-hop availability and earlier first-hop reserve protection',async()=>{
  initializeRegistry();await preflight('t18-before');const original=history(),p=input(),cln=clnConfig('t18-balance',true),lnd=lndConfig(true);
  try{
    const proposals:Record<string,string>={};
    for(const[name,fixture]of[['cln',cln],['lnd',lnd]]as const){
      expect(cli(['doctor'],`t18-${name}-doctor`,fixture.config).exit).toBe(0);
      expect(cli(['channels','--node',name==='cln'?'cln-m':'lnd-r'],`t18-${name}-channels`,fixture.config).exit).toBe(0);
      const plan=cli(['liquidity','plan','--refresh'],`t18-${name}-plan`,fixture.config);expect(plan.exit).toBe(0);expect(plan.body.result).toMatchObject({action:'CIRCULAR_REBALANCE',principal_msat:'100000000'});
      proposals[name]=String(plan.body.result['proposal_id']);expect(cli(['liquidity','approve',proposals[name]??'','--key',p.key],`t18-${name}-approval`,fixture.config).exit).toBe(0);
    }
    const snapshots=[];
    for(let count=0;count<20;count+=1){
      await delay(1000);
      const before=receivable();snapshots.push({receivable:before.toString()});
      if(before<=60000000n)break;
      const amount=before-60000000n<100000000n?before-60000000n:100000000n;
      await directCheckout(amount,count);
    }
    const after=receivable();retain('t18-drain-observations',{snapshots,afterReceivableMsat:after.toString()});expect(after).toBe(60000000n);
    const nodeBefore={clnPayments:oracle('cln-m','listsendpays'),clnInvoices:oracle('cln-m','listinvoices'),lndPayments:oracle('lnd-r','listpayments',['--include_incomplete'])};retain('t18-node-before-refusals',nodeBefore);
    const clnResult=cli(['actions','execute',proposals['cln']??'','--require-regtest'],'t18-cln-execute',cln.config);
    const lndResult=cli(['actions','execute',proposals['lnd']??'','--require-regtest'],'t18-lnd-execute',lnd.config);
    const nodeAfter={clnPayments:oracle('cln-m','listsendpays'),clnInvoices:oracle('cln-m','listinvoices'),lndPayments:oracle('lnd-r','listpayments',['--include_incomplete'])};retain('t18-node-after-refusals',nodeAfter);
    expect(nodeAfter).toEqual(nodeBefore);
    for(const[name,fixture]of[['cln',cln],['lnd',lnd]]as const)expect(query(fixture.database,'SELECT status,payment_hash FROM executions WHERE proposal_id = ?',(proposals[name]??'').replace(/^prop_/,''))).toEqual([{status:'CANCELLED',payment_hash:null}]);
    expect(clnResult).toMatchObject({exit:5,body:{error:{step:'LAST_HOP_RECEIVABLE'}}});
    expect(lndResult).toMatchObject({exit:5,body:{error:{step:'RESERVE_FLOOR'}}});unchangedOld(original,history());
    retain('t18-first-hop-specific-gap',{status:'GAP',reason:'SPEC P3 reserve protection precedes V8 on the same native spendable snapshot; this live refusal does not prove FIRST_HOP_SPENDABLE.'});
  }finally{await clean();await preflight('t18-after');}
});
