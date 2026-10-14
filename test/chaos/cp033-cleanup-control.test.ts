import { mkdirSync,writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach,expect,it,vi } from 'vitest';
import { clean,nodeControl,setRunner } from '../../labs/scenarios/chaos/live-reference.mjs';
import { scratch } from '../helpers/cp016-cli.js';
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();});
it('CP-033/B1 cleanup attempts every owned unpause even when proxy discovery fails and retains the original failure',async()=>{
  const directory=scratch('chaos-cleanup-control'),runtime=join(directory,'runtime');mkdirSync(runtime);
  const owner=join(directory,'owner.json'),plan=join(directory,'plan.json');
  writeFileSync(owner,JSON.stringify({project:'fluxwarden-lab-demo-fixed-20261013',runtimeRoot:runtime,ports:{lndRest:29210,clnRest:29211,toxiproxy:29212}}));
  writeFileSync(join(runtime,'lab.json'),'{}');writeFileSync(plan,JSON.stringify({owner}));vi.stubEnv('FLUXWARDEN_CHAOS_REFERENCE_PLAN',plan);
  const calls:string[]=[];setRunner((_file,args)=>{calls.push(args[0]??'');return{status:0,signal:null,output:[null,'',''],pid:1,stdout:'',stderr:''};});
  nodeControl('cln-m','pause');nodeControl('cln-r','pause');
  const failure=new Error('synthetic control-plane outage');vi.spyOn(globalThis,'fetch').mockRejectedValue(failure);
  await expect(clean()).rejects.toBe(failure);expect(calls).toEqual(['pause','pause','unpause','unpause']);
  await expect(clean()).rejects.toBe(failure);expect(calls).toEqual(['pause','pause','unpause','unpause']);
});
