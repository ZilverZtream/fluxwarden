// Public filesystem and Worker transports only. The 100ms clock model starts
// at the provider after genuine verification; it is not a real 600-second run.
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { expect } from 'vitest';
import { ownedCaptureToolArgs } from './capture-fixture.js';
import { composedFixture, type ComposedFixture } from './composed-seal.js';

const transport = String.raw`
import fs from 'node:fs';import fsp from 'node:fs/promises';import timers from 'node:timers';
import promiseTimers from 'node:timers/promises';import workers from 'node:worker_threads';
import {performance} from 'node:perf_hooks';import {resolve,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {syncBuiltinESMExports} from 'node:module';import {jobs as ordinaryJobs} from './composition-transport.mjs';
const mode=process.env.CONTROL_LIFECYCLE,output=resolve(process.env.FLUXWARDEN_RELEASE_OUTPUT);
const report=join(output,'report.json'),control=dirname(process.env.CONTROL_COMPOSITION_LOG);
const recordPath=join(control,'lifecycle.jsonl');
const write=fs.writeFileSync,writeFd=fs.writeSync,read=fs.readFileSync,append=fs.appendFileSync;
const open=fs.openSync,close=fs.closeSync,rename=fs.renameSync,stat=fs.lstatSync;
const asyncOpen=fsp.open,asyncWrite=fsp.writeFile;
const rawTimeout=timers.setTimeout,rawClear=timers.clearTimeout,rawWall=Date.now.bind(Date);
const rawNow=performance.now.bind(performance),rawHr=process.hrtime.bigint.bind(process.hrtime);
const owned=new Set(),descriptors=new Map(),writtenDescriptors=new Set();let faulted=false,replaced=false,inside=0;
const log=(event,fields={})=>append(recordPath,JSON.stringify({event,wallMs:rawWall(),...fields})+'\n');
const identity=path=>{const s=stat(path,{bigint:true});return{dev:String(s.dev),ino:String(s.ino),size:Number(s.size)};};
const exclusive=flags=>typeof flags==='string'?flags.includes('x'):Boolean(flags&fs.constants.O_EXCL);
const descriptor=file=>typeof file==='number'?file:file&&Number.isInteger(file.fd)?file.fd:null;
const target=file=>descriptor(file)!==null?descriptors.get(descriptor(file)):resolve(file instanceof URL?fileURLToPath(file):String(file));
function remember(path,flags,fd){const resolved=resolve(String(path));descriptors.set(fd,resolved);if(exclusive(flags)&&resolved===report)owned.add(report);}
function fault(file,data,options){
 const path=target(file);if(path!==report)return;
 if(mode==='partial'&&path===report&&!faulted&&owned.has(path)){
  faulted=true;const bytes=typeof data==='string'?Buffer.from(data,typeof options==='string'?options:options?.encoding??'utf8'):Buffer.from(data);
  inside++;try{if(descriptor(file)!==null)writeFd(descriptor(file),bytes.subarray(0,9));else write(file,bytes.subarray(0,9),options);}finally{inside--;}
  log('partial-created',{...identity(path),bytes:9});throw Object.assign(new Error('owned synthetic partial write'),{code:'ENOSPC'});
 }
}
function after(file){const path=target(file);if(mode!=='replacement'||path!==report||replaced||!owned.has(path))return;
 const fd=descriptor(file);if(fd!==null){writtenDescriptors.add(fd);log('replacement-awaiting-close');return;}
 const replacement=join(control,'operator-replacement.bin');write(replacement,'operator-owned replacement\n',{flag:'wx',mode:0o600});
 const original=identity(replacement);rename(replacement,report);replaced=true;log('replacement-installed',original);
}
function closed(fd){const path=descriptors.get(fd);descriptors.delete(fd);if(writtenDescriptors.delete(fd)){
 log('report-descriptor-closed');after(path);
}}
fs.openSync=function(path,flags,...args){const fd=open.call(this,path,flags,...args);remember(path,flags,fd);return fd;};
fs.closeSync=function(fd,...args){const value=close.call(this,fd,...args);closed(fd);return value;};
fs.writeFileSync=function(file,data,options){
 if(inside)return write.call(this,file,data,options);
 if(typeof file!=='number'&&exclusive(typeof options==='object'?options?.flag:undefined)&&target(file)===report)owned.add(report);
 fault(file,data,options);inside++;let value;try{value=write.call(this,file,data,options);}finally{inside--;}after(file);return value;
};
fs.writeSync=function(fd,data,...args){if(inside)return writeFd.call(this,fd,data,...args);fault(fd,data);const value=writeFd.call(this,fd,data,...args);after(fd);return value;};
fsp.writeFile=async function(file,data,options){
 if(typeof file!=='number'&&exclusive(typeof options==='object'?options?.flag:undefined)&&target(file)===report)owned.add(report);
 fault(file,data,options);const value=await asyncWrite.call(this,file,data,options);after(file);return value;
};
fsp.open=async function(path,flags,...args){const handle=await asyncOpen.call(this,path,flags,...args);remember(path,flags,handle.fd);
 for(const name of ['writeFile','write']){const original=handle[name].bind(handle);handle[name]=async function(data,...rest){fault(handle.fd,data,rest[0]);const value=await original(data,...rest);after(handle.fd);return value;};}
 const finish=handle.close.bind(handle),fd=handle.fd;handle.close=async function(){const value=await finish();closed(fd);return value;};return handle;
};
// A later distinct output write is the EIO interleaving point, including fd APIs.
const outputPath=file=>{const path=target(file);return path&&path.startsWith(output+(/\\/.test(output)?'\\':'/'));};
function later(file){if(mode==='replacement'&&replaced&&target(file)!==report&&outputPath(file)&&!faulted){faulted=true;log('injected-EIO');throw Object.assign(new Error('owned synthetic later write'),{code:'EIO'});}}
for(const [owner,name] of [[fs,'writeFileSync'],[fs,'writeSync']]){const original=owner[name];owner[name]=function(file,...args){if(!inside)later(file);return original.call(this,file,...args);};}
const promiseWrite=fsp.writeFile;fsp.writeFile=async function(file,...args){later(file);return promiseWrite.call(this,file,...args);};
const promiseOpen=fsp.open;fsp.open=async function(...args){const handle=await promiseOpen.apply(this,args);for(const name of ['writeFile','write']){const original=handle[name].bind(handle);handle[name]=async function(...values){later(handle.fd);return original(...values);};}return handle;};
let activate=()=>{};
if(mode==='pending'){
 const shared=new SharedArrayBuffer(32),state=new Int32Array(shared),wide=new BigInt64Array(shared);
 const baseNow=rawNow(),baseHr=rawHr(),baseWall=rawWall(),longTimers=new Map();let active=false;
 const elapsed=()=>active?Number(rawHr()-wide[2])/1e6*6000:0;
 Object.defineProperty(performance,'now',{value:()=>baseNow+elapsed(),configurable:true});Date.now=()=>baseWall+elapsed();
 const clock=previous=>{let value=baseHr+BigInt(Math.floor(elapsed()*1e6));if(previous)value-=BigInt(previous[0])*1000000000n+BigInt(previous[1]);return[Number(value/1000000000n),Number(value%1000000000n)];};
 clock.bigint=()=>baseHr+BigInt(Math.floor(elapsed()*1e6));process.hrtime=clock;
 function timeout(callback,delay,...args){if(!(delay>=180000))return rawTimeout(callback,delay,...args);
  log('long-timer-registered',{delay,active});
  const entry={callback,delay,args,timer:null,cancelled:false};const handle=rawTimeout(()=>{if(active)log('main-deadline-delivered');callback(...args);},active?delay/6000:delay);entry.timer=handle;longTimers.set(handle,entry);return handle;
 }
 function clear(handle){const entry=longTimers.get(handle);if(entry){entry.cancelled=true;rawClear(entry.timer);}else rawClear(handle);}
 timers.setTimeout=globalThis.setTimeout=timeout;timers.clearTimeout=globalThis.clearTimeout=clear;
 const ordinaryPromiseTimeout=promiseTimers.setTimeout;promiseTimers.setTimeout=(delay,value,options={})=>delay<180000?ordinaryPromiseTimeout(delay,value,options):new Promise((accept,reject)=>{
  const handle=timeout(()=>accept(value),delay);if(options.ref===false)handle.unref();
  if(options.signal){const abort=()=>{clear(handle);reject(Object.assign(new Error('synthetic timer aborted'),{name:'AbortError',code:'ABORT_ERR'}));};if(options.signal.aborted)abort();else options.signal.addEventListener('abort',abort,{once:true});}
 });
 const RealWorker=workers.Worker;
 const workerSource="const {workerData}=require('node:worker_threads');const fs=require('node:fs');const state=new Int32Array(workerData.shared),wide=new BigInt64Array(workerData.shared);Atomics.store(state,1,1);Atomics.notify(state,1);Atomics.wait(state,0,0);const poll=setInterval(()=>{if(Number(process.hrtime.bigint()-wide[2])/1e6>=100){fs.appendFileSync(workerData.log,JSON.stringify({event:'watchdog-expired',wallMs:Date.now()})+'\\n');process.kill(process.pid,'SIGKILL');}},40);";
 workers.Worker=class extends RealWorker{
  constructor(){super(workerSource,{eval:true,execArgv:[],workerData:{shared,log:recordPath}});Atomics.wait(state,1,0,5000);if(Atomics.load(state,1)!==1)throw Error('real model watchdog did not start');log('watchdog-ready');}
  terminate(){log('watchdog-terminated',{pending:Atomics.load(state,3)===1});return super.terminate();}
 };
 activate=()=>{active=true;wide[2]=rawHr();Atomics.store(state,3,1);Atomics.store(state,0,1);Atomics.notify(state,0);
  for(const [handle,entry]of longTimers){if(entry.cancelled)continue;const ref=handle.hasRef();rawClear(entry.timer);entry.timer=rawTimeout(()=>{log('main-deadline-delivered');entry.callback(...entry.args);},entry.delay/6000);if(!ref)entry.timer.unref();}
  log('provider-start',{modelDeadlineMs:100,watchdogPollMs:40});
 };
}
syncBuiltinESMExports();
export async function jobs(){if(mode!=='pending')return ordinaryJobs();activate();for(let tick=1;tick<=80;tick++){
 await new Promise(accept=>rawTimeout(accept,10));log('provider-tick',{tick});
}log('provider-completed');return ordinaryJobs();}
export function rejected(){log('main-rejected');}
`;

export function lifecycleFixture(): ComposedFixture {
  return composedFixture(source => {
    // Local verification can execute an explicitly supplied opaque candidate.
    // Portable committed tests default to their own checkout's genuine scripts.
    const candidate = process.env['FLUXWARDEN_TEST_OPAQUE_TOOLS_ROOT'];
    if (candidate) for (const entry of readdirSync(join(candidate, 'scripts'), { withFileTypes: true })) {
      if (entry.isFile() && entry.name.endsWith('.mjs')) copyFileSync(join(candidate, 'scripts', entry.name), join(source, 'scripts', entry.name));
    }
    writeFileSync(join(source, 'lifecycle-transport.mjs'), transport);
    writeFileSync(join(source, 'seal-driver.mjs'), `import {jobs,rejected} from './lifecycle-transport.mjs';
const {sealReport}=await import('./scripts/release-ci.mjs');
try{await sealReport({listJobs:jobs},'live/chaos');}catch{rejected();process.exitCode=7;}
`);
  });
}

export function lifecycleEvents(f: ComposedFixture): Record<string, unknown>[] {
  const path = join(dirname(f.transportLog), 'lifecycle.jsonl');
  return existsSync(path) ? readFileSync(path, 'utf8').trim().split('\n').map(line => JSON.parse(line) as Record<string, unknown>) : [];
}

export function runLifecycle(f: ComposedFixture, mode: 'replacement' | 'partial' | 'pending') {
  const result = spawnSync(process.execPath, [...ownedCaptureToolArgs([join(f.source, 'seal-driver.mjs')])], {
    cwd: f.source, env: { ...f.env, CONTROL_LIFECYCLE: mode }, windowsHide: true, encoding: 'utf8', timeout: 30_000,
  });
  expect(result.error, 'the original 30-second child completion bound is unchanged').toBeUndefined();
  return result;
}
