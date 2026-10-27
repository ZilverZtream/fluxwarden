// CP-044 D29 composed-phase reference. Production scripts are copied opaquely
// by the existing genuine-capture fixture; only IO/clock transports are injected.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect } from 'vitest';
import { ownedCaptureToolArgs } from './capture-fixture.js';
import { capturedSealFixture, type SealFixture } from './oct26-seal-fixture.js';

export interface ComposedFixture extends SealFixture { transportLog: string }
export function composedFixture(prepareSource?: (source: string) => void): ComposedFixture {
  let transportLog = '';
  const fixture = capturedSealFixture(0, {}, source => {
    writeFileSync(join(source, 'composition-transport.mjs'), `import cp from 'node:child_process';
import fs from 'node:fs';import fsp from 'node:fs/promises';import {performance} from 'node:perf_hooks';
import {resolve,sep,join} from 'node:path';import {syncBuiltinESMExports} from 'node:module';
const mode=process.env.CONTROL_COMPOSITION??'ordinary',originalSpawn=cp.spawnSync;
const originalRead=fs.readFileSync,originalWrite=fs.writeFileSync,originalCopy=fs.copyFileSync;
const originalOpen=fs.openSync,originalClose=fs.closeSync,originalWriteSync=fs.writeSync,descriptors=new Map();
const asyncWrite=fsp.writeFile,asyncCopy=fsp.copyFile,originalAppend=fs.appendFileSync;
const output=resolve(process.env.FLUXWARDEN_RELEASE_OUTPUT),capture=resolve(process.env.FLUXWARDEN_CI_CAPTURE_DIR);
let elapsed=0,readAdvanced=false,writeAdvanced=false;
const now=performance.now.bind(performance),hr=process.hrtime.bigint.bind(process.hrtime),wall=Date.now();
Object.defineProperty(performance,'now',{value:()=>now()+elapsed,configurable:true});
const alteredHr=previous=>{let value=hr()+BigInt(elapsed)*1000000n;if(previous)value-=BigInt(previous[0])*1000000000n+BigInt(previous[1]);return[Number(value/1000000000n),Number(value%1000000000n)];};
alteredHr.bigint=()=>hr()+BigInt(elapsed)*1000000n;process.hrtime=alteredHr;
if(mode.startsWith('clock-'))Date.now=()=>wall;
const log=event=>originalAppend(process.env.CONTROL_COMPOSITION_LOG,JSON.stringify({event,elapsed})+'\\n');
const filePath=path=>typeof path==='number'?descriptors.get(path):resolve(String(path));
fs.openSync=function(path,...args){const fd=originalOpen.call(this,path,...args);descriptors.set(fd,resolve(String(path)));return fd;};
fs.closeSync=function(fd,...args){const value=originalClose.call(this,fd,...args);descriptors.delete(fd);return value;};
cp.spawnSync=function(command,args,options){
 if(options?.timeout>180000)log('subordinate-cap-raised');
 if(Array.isArray(args)&&args.some(value=>String(value).replaceAll('\\\\','/').endsWith('/ci-capture.mjs'))&&args.includes('verify')){
  log('public-verifier-child');
  if(mode==='deny-child')return {status:71,signal:null,stdout:Buffer.alloc(0),stderr:Buffer.alloc(0),pid:0,output:[null,Buffer.alloc(0),Buffer.alloc(0)]};
 }
 return originalSpawn.call(this,command,args,options);
};
fs.readFileSync=function(path,...args){const value=originalRead.call(this,path,...args);
 if(mode==='clock-spanning'&&!readAdvanced&&filePath(path)===join(capture,'receipt.json')){readAdvanced=true;elapsed=420000;log('verification-input-read');}
 return value;
};
function beforeWrite(path){const target=filePath(path);if(target!==undefined&&(target===output||target.startsWith(output+sep))){
 if(mode==='clock-spanning'&&!writeAdvanced){writeAdvanced=true;elapsed=610001;log('final-write-clock');}
 log('report-write');
}}
fs.writeFileSync=function(path,...args){beforeWrite(path);return originalWrite.call(this,path,...args);};
fs.writeSync=function(fd,...args){beforeWrite(fd);return originalWriteSync.call(this,fd,...args);};
fs.copyFileSync=function(from,to,...args){beforeWrite(to);return originalCopy.call(this,from,to,...args);};
fsp.writeFile=async function(path,...args){beforeWrite(path);return asyncWrite.call(this,path,...args);};
fsp.copyFile=async function(from,to,...args){beforeWrite(to);return asyncCopy.call(this,from,to,...args);};
syncBuiltinESMExports();
export async function jobs(){log('provider');
 if(mode==='provider-failure')throw Object.assign(new Error('synthetic provider transport failure'),{code:'EIO'});
 if(mode==='mutate-at-provider'){
  const path=join(process.env.FLUXWARDEN_EVIDENCE_DIR,'vitest-chaos.json'),bytes=originalRead(path,'utf8');
  originalWrite(path,bytes.replace('CP-044','CP-045'));log('provider-mutated-report');
 }
 if(mode==='clock-provider'){elapsed=600001;log('provider-clock-expired');}
 if(mode==='clock-spanning'){elapsed=520000;log('provider-clock');}
 return [{id:4242,name:'live/chaos',head_sha:process.env.GITHUB_SHA,run_id:Number(process.env.GITHUB_RUN_ID)}];
}
globalThis.fetch=async input=>{
 const url=new URL(String(input));
 if(url.origin!=='https://api.github.com'||url.pathname!=='/repos/ZilverZtream/fluxwarden/actions/runs/777/attempts/1/jobs'||url.search!=='?per_page=100&page=1')throw new Error('unrecognized synthetic provider endpoint');
 return new Response(JSON.stringify({total_count:1,jobs:await jobs()}),{status:200,headers:{'content-type':'application/json'}});
};
`);
    writeFileSync(join(source, 'seal-driver.mjs'), `import {jobs} from './composition-transport.mjs';
const {sealReport}=await import('./scripts/release-ci.mjs');
await sealReport({listJobs:jobs},'live/chaos',{verified:true,skipVerification:true});
`);
    prepareSource?.(source);
  }, ({ source, env }) => {
    const controls = join(dirname(source), 'composition-control'); mkdirSync(controls, { mode: 0o700 });
    transportLog = join(controls, 'transport.jsonl'); env['CONTROL_COMPOSITION_LOG'] = transportLog;
    // Already registered genuine synthetic SOURCE; the fake fetch never emits
    // headers or connects externally. CLI provider keeps its existing interface.
    env['GITHUB_TOKEN'] = readFileSync(join(source, 'test/sentinels/source.bin')).toString('hex');
  });
  return { ...fixture, transportLog };
}

export function runComposed(f: ComposedFixture, mode = 'ordinary', cli = false) {
  const result = spawnSync(process.execPath, [...ownedCaptureToolArgs(cli
    ? ['--import', pathToFileURL(join(f.source, 'composition-transport.mjs')).href, join(f.source, 'scripts/release-ci.mjs'), 'seal', '--key', 'live/chaos']
    : [join(f.source, 'seal-driver.mjs')])], {
    cwd: f.source, env: { ...f.env, CONTROL_COMPOSITION: mode }, windowsHide: true, encoding: 'utf8', timeout: 30_000,
  });
  expect(result.error, 'original 30-second fixture child bound remains unchanged').toBeUndefined(); expect(result.signal).toBeNull();
  return result;
}
export function events(f: ComposedFixture): string[] {
  return existsSync(f.transportLog) ? readFileSync(f.transportLog, 'utf8').trim().split('\n').map(line => {
    const row = JSON.parse(line) as { event: string }; return row.event;
  }) : [];
}
export function refused(f: ComposedFixture, result: ReturnType<typeof runComposed>): void {
  expect(result.status).not.toBeNull(); expect(result.status).not.toBe(0);
  expect(readdirSync(f.output), 'refusal cannot leave uploadable report outputs').toEqual([]);
}
