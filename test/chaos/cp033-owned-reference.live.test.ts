import { expect, it } from 'vitest';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { cli, clean, clnConfig, enable, history, initializeRegistry, input, latency, lndConfig, networkConfig, nodeControl, oracle, preflight, proxies, query, readConfig, retain, rows, setRunner, unchangedOld } from '../../labs/scenarios/chaos/live-reference.mjs';
setRunner((file,args,options) => spawnSync(file,args,options));

// SPEC §11.6 T-01 / SECURITY INV-15: config network guard precedes credentials.
for (const network of ['mainnet', 'testnet4', 'signet']) {
  it(`CP-033/B1 T-01 owned pinned lab refuses configured ${network} before unreadable execution credentials`, async () => {
    initializeRegistry(); await preflight(`t01-${network}-before`); const before = history();
    try {
      const config = networkConfig(network);
      const result = cli(['actions','execute','prop_00000000000000000000000000','--require-regtest'], `t01-${network}-execute`, config);
      expect(result).toMatchObject({ exit:5, body:{ error:{ step:'network-lock' } } });
      unchangedOld(before,history());
    } finally { await clean(); await preflight(`t01-${network}-after`); }
  });
}

it('CP-033/B1 T-01 daemon DM1 rejects configured mainnet before the pinned node handshake',async()=>{
  initializeRegistry();await preflight('t01-daemon-before');const original=history(),fixture=lndConfig();
  try{expect(cli(['doctor'],'t01-daemon-doctor',fixture.config).exit).toBe(0);const config=join(dirname(fixture.config),'network-mismatch.yaml');writeFileSync(config,readFileSync(fixture.config,'utf8').replace('expected_network: regtest','expected_network: mainnet'));
    const before={payments:oracle('lnd-r','listpayments',['--include_incomplete']),invoices:oracle('lnd-r','listinvoices')};retain('t01-daemon-native-before',before);
    // SPEC DM1 loads the same read configuration as doctor/channels; daemon
    // never executes proposals. Known off-network read config is invalid2.
    const result=cli(['daemon'],'t01-daemon-refusal',config);expect(result).toMatchObject({exit:2,body:{error:{step:'config'}}});
    const after={payments:oracle('lnd-r','listpayments',['--include_incomplete']),invoices:oracle('lnd-r','listinvoices')};retain('t01-daemon-native-after',after);expect(after).toEqual(before);unchangedOld(original,history());
  }finally{await clean();await preflight('t01-daemon-after');}
});

// T-05 CLN primary reference: lightningd/pay.c sendpay/waitsendpay and SPEC §8.4
// require resolving the one stored hash. Runtime is the public CLI, not a fake node.
it('CP-033/B1 T-05 CLN response cut preserves one hash and reconciles exactly one real node payment', async () => {
  initializeRegistry(); await preflight('t05-cln-before'); const before = history();
  try {
    const plan = cli(['liquidity','plan','--refresh'],'t05-cln-plan');
    expect(plan.exit).toBe(0);
    const proposal = plan.body.result;
    expect(proposal, 'fresh eligible intent from public planner').toMatchObject({ action:'CIRCULAR_REBALANCE', principal_msat:'100000000', policy_sha256:'baaae43179d69c79ee0fe9a16410463ec403eed1aa78f4d740481c6b25184287' });
    const p = input();
    expect(cli(['liquidity','approve',String(proposal['proposal_id']),'--key',p.key], 't05-cln-approve').exit).toBe(0);
    const chaos = cli(['lab','chaos','--case','T-05'],'t05-cln-chaos');
    expect(chaos).toMatchObject({ exit:7, body:{ result:{ status:'UNKNOWN', sendCount:1 } } });
    const hash = String(chaos.body.result['paymentHash']);
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
    const observed = oracle('cln-m','listsendpays',[`payment_hash=${hash}`]); retain('t05-cln-node-payment-before-reconcile',observed);
    expect(observed['payments']).toHaveLength(1);
    const executed = rows('SELECT id, proposal_id, status, payment_hash FROM executions WHERE payment_hash = ?',hash);
    expect(executed).toHaveLength(1); expect(executed[0]?.['status']).toBe('UNKNOWN');
    expect(cli(['reconcile','--node','cln-m','--since','1h'],'t05-cln-reconcile').exit).toBe(0);
    expect(rows('SELECT status,payment_hash FROM executions WHERE payment_hash = ?',hash)).toEqual([{ status:'VERIFIED_SUCCESS', payment_hash:hash }]);
    expect(rows('SELECT event_type FROM ledger_journals WHERE execution_id = ? ORDER BY occurred_at,id',executed[0]?.['id']).map(v => v['event_type'])).toEqual(['REBALANCE_SENT','REBALANCE_SETTLED']);
    const again = oracle('cln-m','listsendpays',[`payment_hash=${hash}`]); retain('t05-cln-node-payment-after-reconcile',again);
    expect(again['payments']).toHaveLength(1);
    unchangedOld(before,history());
  } finally { await clean(); expect(Object.values(await proxies()).every((p: { enabled:boolean; toxics:unknown[] }) => p.enabled && p.toxics.length === 0)).toBe(true); await preflight('t05-cln-after'); }
});

async function until(predicate:()=>boolean,deadline=30000) {
  const start=Date.now(); for (;;) { try { if(predicate())return; }catch(e){ if(!(e instanceof Error)||!e.message.includes('database is locked'))throw e; } if (Date.now()-start > deadline) throw new Error('LabInvalidError: observable interleaving point unavailable'); await new Promise<void>(r => setImmediate(r)); }
}
function worker(args:string[],config:string) {
  const p=input(), child=spawn(process.execPath,[resolve('dist/cli/bin.js'),'--json',...args,'--config',config],{ cwd:resolve('.'),env:process.env,shell:false,windowsHide:true,stdio:['ignore','pipe','pipe'] });
  let stdout='',stderr=''; child.stdout.on('data',(v:Buffer)=>{stdout+=v.toString();});child.stderr.on('data',(v:Buffer)=>{stderr+=v.toString();});
  const done=new Promise<{exit:number|null;stdout:string;stderr:string}>(r => child.on('exit',exit=>{let body:unknown;try{body=JSON.parse(stdout) as unknown;}catch{try{body={documents:stdout.trim().split('\n').filter(Boolean).map(line=>JSON.parse(line) as unknown)};}catch{body={malformed:true};}}retain(`worker-${String(child.pid)}`,{exit,body,stderr});r({exit,stdout,stderr});}));
  return {child,done,p};
}

// LND SendToRouteV2 must lose a sent response, retain the persisted hash, then use
// node evidence after the owned forwarding node resumes (SPEC T-05, INV-04/05).
it('CP-033/B1 T-05 LND sent response loss resolves one pinned node HTLC by the persisted hash',async()=>{
  initializeRegistry();await preflight('t05-lnd-before');const original=history(),p=input(),fixture=lndConfig();
  let active:ReturnType<typeof worker>|undefined;
  try {
    expect(cli(['doctor'],'t05-lnd-doctor',fixture.config).exit).toBe(0);
    expect(cli(['channels','--node','lnd-r'],'t05-lnd-channels',fixture.config).exit).toBe(0);
    const planned=cli(['liquidity','plan','--refresh'],'t05-lnd-plan',fixture.config);
    expect(planned.exit).toBe(0);const proposal=planned.body.result;
    expect(proposal).toMatchObject({ action:'CIRCULAR_REBALANCE',principal_msat:'100000000' });
    expect(cli(['liquidity','approve',String(proposal['proposal_id']),'--key',p.key],'t05-lnd-approval',fixture.config).exit).toBe(0);
    const nativeBefore=oracle('lnd-r','listchannels');retain('t05-lnd-native-balance-before',nativeBefore);
    await latency('lnd-r-rest','t05-response-barrier',500);
    active=worker(['actions','execute',String(proposal['proposal_id']),'--require-regtest'],fixture.config);
    const id=String(proposal['proposal_id']).replace(/^prop_/,'');
    await until(()=>query(fixture.database,'SELECT status FROM executions WHERE proposal_id = ?',id).some(v=>v['status']==='IN_FLIGHT'));
    const submitted=query(fixture.database,'SELECT id,status,payment_hash FROM executions WHERE proposal_id = ?',id)[0];
    retain('t05-lnd-submitted',submitted);await enable('lnd-r-rest',false);
    const result=await active.done;retain('t05-lnd-execute',{ exit:result.exit,body:JSON.parse(result.stdout) as unknown,stderr:result.stderr });
    expect(result.exit).toBe(7);expect(query(fixture.database,'SELECT status FROM executions WHERE proposal_id = ?',id)).toEqual([{status:'UNKNOWN'}]);
    await clean();
    const hash=String(submitted?.['payment_hash']);
    const payment=oracle('lnd-r','listpayments',['--include_incomplete']);retain('t05-lnd-node-payment',payment);
    const matching=(payment['payments'] as Record<string,unknown>[]).filter(v=>v['payment_hash']===hash);expect(matching).toHaveLength(1);
    // lnrpc/lightning.proto Payment.htlcs contains all attempts: one hash alone
    // does not exclude duplicate SendToRouteV2 calls under that same hash.
    expect(matching[0]?.['htlcs']).toHaveLength(1);retain('t05-lnd-attempts',matching[0]?.['htlcs']);
    // SPEC 8.7 step 5 / A30: original tolerance remains zero. Native LND
    // balances are integer sat, while the receipt fee has msat precision.
    const reconciled=cli(['reconcile','--node','lnd-r','--since','1h'],'t05-lnd-reconcile',fixture.config);
    const nativeAfter=oracle('lnd-r','listchannels'),finalPayment=oracle('lnd-r','listpayments',['--include_incomplete']);retain('t05-lnd-native-balance-after',nativeAfter);retain('t05-lnd-terminal-payment',finalPayment);
    const terminal=(finalPayment['payments'] as Record<string,unknown>[]).filter(v=>v['payment_hash']===hash);expect(terminal).toHaveLength(1);expect(terminal[0]?.['htlcs']).toHaveLength(1);expect(terminal[0]?.['status']).toBe('SUCCEEDED');
    const balance=(record:Record<string,unknown>,key:string)=>{const channel=(record['channels'] as Record<string,unknown>[]).find(v=>v['scid']===key);if(!channel)throw new Error('GAP native LND balance missing');return BigInt(String(channel['local_balance']))*1000n;};
    const source=String(proposal['source_channel']),target=String(proposal['target_channel']),principal=BigInt(String(terminal[0]?.['value_msat'])),fee=BigInt(String(terminal[0]?.['fee_msat']));
    const sourceResidual=balance(nativeAfter,source)-balance(nativeBefore,source)+principal+fee,targetResidual=balance(nativeAfter,target)-balance(nativeBefore,target)-principal,absolute=(v:bigint)=>v<0n?-v:v;
    retain('t05-lnd-zero-tolerance-native-residual',{sourceResidual,targetResidual,principal,fee,nativeQuantumMsat:'1000',configuredToleranceMsat:'0'});
    expect(absolute(sourceResidual)>0n&&absolute(sourceResidual)<1000n).toBe(true);expect(targetResidual).toBe(0n);expect(fee).toBe(BigInt(String(proposal['route'] && (proposal['route'] as Record<string,unknown>)['fee_msat'])));
    expect(reconciled).toMatchObject({exit:9,body:{error:{code:9}}});expect(query(fixture.database,'SELECT delta_status FROM executions WHERE proposal_id = ?',id)).toEqual([{delta_status:'MISMATCH'}]);
    expect(query(fixture.database,'SELECT status,payment_hash FROM executions WHERE proposal_id = ?',id)).toEqual([{status:'VERIFIED_SUCCESS',payment_hash:hash}]);
    expect(query(fixture.database,'SELECT event_type FROM ledger_journals WHERE execution_id = ? ORDER BY occurred_at,id',submitted?.['id']).map(v=>v['event_type'])).toEqual(['REBALANCE_SENT','REBALANCE_SETTLED']);
    const afterAgain=oracle('lnd-r','listpayments',['--include_incomplete']);const finalMatches=(afterAgain['payments'] as Record<string,unknown>[]).filter(v=>v['payment_hash']===hash);expect(finalMatches).toHaveLength(1);expect(finalMatches[0]?.['htlcs']).toHaveLength(1);retain('t05-lnd-no-duplicate-final',finalMatches);unchangedOld(original,history());
  } finally { if(active?.child.exitCode===null) active.child.kill('SIGKILL');await clean();await preflight('t05-lnd-after'); }
});

it('CP-033/B1 T-06 two live CLI processes claim one fresh approved intent and dispatch one node payment',async()=>{
  initializeRegistry();await preflight('t06-before');const original=history(),p=input(),fixture=clnConfig('t06-race');
  const workers:ReturnType<typeof worker>[]=[];
  try{
    expect(cli(['doctor'],'t06-doctor',fixture.config).exit).toBe(0);
    const planned=cli(['liquidity','plan','--refresh'],'t06-plan',fixture.config);expect(planned.exit).toBe(0);expect(planned.body.result).toMatchObject({action:'CIRCULAR_REBALANCE',principal_msat:'100000000'});
    const proposal=String(planned.body.result['proposal_id']),id=proposal.replace(/^prop_/,'');
    expect(cli(['liquidity','approve',proposal,'--key',p.key],'t06-approval',fixture.config).exit).toBe(0);
    // Both OS processes start before either is awaited; a real database claim arbitrates.
    await latency('cln-m-rest','t06-claim-barrier',500);
    workers.push(worker(['actions','execute',proposal,'--require-regtest'],fixture.config));
    await until(()=>query(fixture.database,'SELECT status FROM executions WHERE proposal_id = ?',id).some(v=>v['status']==='PREFLIGHT'));
    // An independent existing read rune avoids cln's per-rune rate= spacing race.
    // It cannot dispatch; the held claim must refuse this process first.
    workers.push(worker(['actions','execute',proposal,'--require-regtest'],readConfig(fixture.config)));
    const outcomes=await Promise.all(workers.map(w=>w.done));expect(outcomes.map(v=>v.exit).sort()).toEqual([0,5]);
    const loser=outcomes.find(v=>v.exit===5);expect(JSON.parse(loser?.stdout??'{}') as unknown).toMatchObject({error:{step:'claimed-elsewhere'}});
    const executed=query(fixture.database,'SELECT id,status,payment_hash FROM executions WHERE proposal_id = ?',id);expect(executed).toHaveLength(1);expect(executed[0]?.['status']).toBe('VERIFIED_SUCCESS');
    const payment=oracle('cln-m','listsendpays',[`payment_hash=${String(executed[0]?.['payment_hash'])}`]);retain('t06-node-payment',payment);expect(payment['payments']).toHaveLength(1);
    expect(query(fixture.database,'SELECT event_type FROM ledger_journals WHERE execution_id = ? ORDER BY occurred_at,id',executed[0]?.['id']).map(v=>v['event_type'])).toEqual(['REBALANCE_SENT','REBALANCE_SETTLED']);unchangedOld(original,history());
  }finally{for(const w of workers)if(w.child.exitCode===null)w.child.kill('SIGKILL');await clean();await preflight('t06-after');}
});

let killed: { fixture:ReturnType<typeof clnConfig>;proposal:string;id:string;fence:unknown }|undefined;
it('CP-033/B1 T-07 killing the owned worker during real preflight sends no invoice or payment',async()=>{
  initializeRegistry();await preflight('t07-before');const original=history(),p=input(),fixture=clnConfig('t07-kill');
  let active:ReturnType<typeof worker>|undefined;
  try{
    expect(cli(['doctor'],'t07-doctor',fixture.config).exit).toBe(0);
    const plan=cli(['liquidity','plan','--refresh'],'t07-plan',fixture.config);expect(plan.exit).toBe(0);expect(plan.body.result).toMatchObject({action:'CIRCULAR_REBALANCE',principal_msat:'100000000'});
    const proposal=String(plan.body.result['proposal_id']),id=proposal.replace(/^prop_/,'');expect(cli(['liquidity','approve',proposal,'--key',p.key],'t07-approval',fixture.config).exit).toBe(0);
    const before={payments:oracle('cln-m','listsendpays'),invoices:oracle('cln-m','listinvoices')};retain('t07-node-before',before);
    await latency('cln-m-rest','t07-preflight-barrier',1500);active=worker(['actions','execute',proposal,'--require-regtest'],fixture.config);
    await until(()=>query(fixture.database,'SELECT status,payment_hash FROM executions WHERE proposal_id = ?',id).some(v=>v['status']==='PREFLIGHT'&&v['payment_hash']===null));
    const dead=query(fixture.database,'SELECT id,status,payment_hash,fence_epoch,lease_expires_at FROM executions WHERE proposal_id = ?',id)[0];retain('t07-dead-claim',dead);active.child.kill('SIGKILL');await active.done;await clean();
    const after={payments:oracle('cln-m','listsendpays'),invoices:oracle('cln-m','listinvoices')};retain('t07-node-after-kill',after);expect(after).toEqual(before);
    killed={fixture,proposal,id,fence:dead?.['fence_epoch']};retain('t07-reclaim-input',killed);unchangedOld(original,history());
  }finally{if(active?.child.exitCode===null)active.child.kill('SIGKILL');await clean();await preflight('t07-after');}
});

it('CP-033/B1 T-07 reclaim after the observed database-clock lease expires increments the fence and sends once',async()=>{
  if(!killed)throw new Error('GAP T-07 reclaim: no independently observed killed claim');
  const{fixture,proposal,id,fence}=killed;await preflight('t07-reclaim-before');
  try{
    // Public CLI lease is 180 seconds. This is a separate assertion case so the
    // natural lease wait remains inside the approved 180-second live test bound.
    await until(()=>query(fixture.database,"SELECT id FROM executions WHERE proposal_id = ? AND lease_expires_at < CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",id).length===1,170000);
    expect(cli(['actions','execute',proposal,'--require-regtest'],'t07-reclaim',fixture.config).exit).toBe(0);
    const completed=query(fixture.database,'SELECT status,payment_hash,fence_epoch FROM executions WHERE proposal_id = ?',id)[0];expect(completed?.['status']).toBe('VERIFIED_SUCCESS');expect(Number(completed?.['fence_epoch'])).toBeGreaterThan(Number(fence));
    const payment=oracle('cln-m','listsendpays',[`payment_hash=${String(completed?.['payment_hash'])}`]);retain('t07-node-reclaimed-payment',payment);expect(payment['payments']).toHaveLength(1);
  }finally{await clean();await preflight('t07-reclaim-after');}
});

let restart: {fixture:ReturnType<typeof clnConfig>;id:string;hash:string}|undefined;
it('CP-034/B1 T-16 restarted daemon observes a real stuck payment, retains its reservation and alerts on repeated passes',async()=>{
  initializeRegistry();await preflight('t16-stuck-before');const original=history(),p=input(),fixture=clnConfig('t16-stuck');
  let active:ReturnType<typeof worker>|undefined,daemon:ReturnType<typeof worker>|undefined;
  try{
    expect(cli(['doctor'],'t16-doctor',fixture.config).exit).toBe(0);
    const plan=cli(['liquidity','plan','--refresh'],'t16-plan',fixture.config);expect(plan.exit).toBe(0);expect(plan.body.result).toMatchObject({action:'CIRCULAR_REBALANCE',principal_msat:'100000000'});
    const proposal=String(plan.body.result['proposal_id']),proposalId=proposal.replace(/^prop_/,'');expect(cli(['liquidity','approve',proposal,'--key',p.key],'t16-approval',fixture.config).exit).toBe(0);
    nodeControl('cln-r','pause');active=worker(['actions','execute',proposal,'--require-regtest'],fixture.config);
    await until(()=>query(fixture.database,'SELECT status FROM executions WHERE proposal_id = ?',proposalId).some(v=>v['status']==='IN_FLIGHT'));
    const row=query(fixture.database,'SELECT id,status,payment_hash,lease_expires_at FROM executions WHERE proposal_id = ?',proposalId)[0],id=String(row?.['id']),hash=String(row?.['payment_hash']);retain('t16-worker-death',row);active.child.kill('SIGKILL');await active.done;
    const pending=oracle('cln-m','listsendpays',[`payment_hash=${hash}`]);retain('t16-pending-node',pending);expect(pending['payments']).toEqual([expect.objectContaining({status:'pending'})]);restart={fixture,id,hash};
    await until(()=>query(fixture.database,"SELECT id FROM executions WHERE id = ? AND lease_expires_at < CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",id).length===1,100000);
    daemon=worker(['daemon'],fixture.config);
    const alerts=join(dirname(fixture.config),'alerts'),stuck=()=>existsSync(alerts)?readdirSync(alerts).filter(name=>name.endsWith('.json')&&readFileSync(join(alerts,name),'utf8').includes('stuck-in-flight')):[];
    await until(()=>stuck().length===1,40000);
    // CP-041/B2: same execution/state on repeated passes is one idempotent
    // alert file, while every public reconciler pass still reports UNKNOWN7.
    const passes=[cli(['reconcile','--node','cln-m','--since','1h'],'t16-stuck-pass1',fixture.config),cli(['reconcile','--node','cln-m','--since','1h'],'t16-stuck-pass2',fixture.config)];expect(passes.map(v=>v.exit)).toEqual([7,7]);
    retain('t16-repeated-alerts',{files:stuck(),passes});expect(stuck()).toHaveLength(1);expect(query(fixture.database,'SELECT state FROM budget_reservations WHERE execution_id = ?',id)).toEqual([{state:'HELD'}]);
    expect(query(fixture.database,'SELECT actual_fee_msat FROM executions WHERE id = ?',id)).toEqual([{actual_fee_msat:null}]);daemon.child.kill('SIGKILL');await daemon.done;
    expect(cli(['reconcile','--node','cln-m','--since','1h'],'t16-stuck-reconcile',fixture.config).exit).toBe(7);unchangedOld(original,history());
  }finally{if(active?.child.exitCode===null)active.child.kill('SIGKILL');if(daemon?.child.exitCode===null)daemon.child.kill('SIGKILL');await clean();if(restart?.fixture===fixture)await until(()=>((oracle('cln-m','listsendpays',[`payment_hash=${restart?.hash??''}`])['payments']) as Record<string,unknown>[]).some(v=>v['status']==='complete'),60000);await preflight('t16-stuck-after');}
});

it('CP-034/B1 T-16 node settlement while daemon is down is swept by the same hash on startup with one journal pair',async()=>{
  if(!restart)throw new Error('GAP T-16 terminal startup: no observed real in-flight worker death');const{fixture,id,hash}=restart;
  await preflight('t16-terminal-before');let daemon:ReturnType<typeof worker>|undefined;
  try{
    const terminal=oracle('cln-m','listsendpays',[`payment_hash=${hash}`]);retain('t16-terminal-node-before',terminal);expect(terminal['payments']).toEqual([expect.objectContaining({status:'complete'})]);
    await until(()=>query(fixture.database,"SELECT id FROM executions WHERE id = ? AND lease_expires_at < CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",id).length===1,100000);
    daemon=worker(['daemon'],fixture.config);await until(()=>query(fixture.database,'SELECT status FROM executions WHERE id = ?',id).some(v=>v['status']==='VERIFIED_SUCCESS'));
    expect(query(fixture.database,'SELECT payment_hash FROM executions WHERE id = ?',id)).toEqual([{payment_hash:hash}]);expect(query(fixture.database,'SELECT event_type FROM ledger_journals WHERE execution_id = ? ORDER BY occurred_at,id',id).map(v=>v['event_type'])).toEqual(['REBALANCE_SENT','REBALANCE_SETTLED']);
    const after=oracle('cln-m','listsendpays',[`payment_hash=${hash}`]);retain('t16-terminal-node-after',after);expect(after['payments']).toHaveLength(1);
  }finally{if(daemon?.child.exitCode===null)daemon.child.kill('SIGKILL');await clean();await preflight('t16-terminal-after');}
});
