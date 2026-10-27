/* SPEC 14.1-14.2; CP-039/B1 public bundle contract; CP-043/B3 public T-05
 * Observation {caseId,injection,exit,status,paymentHash,sendCount}.
 * Read-only retained-artifact gold. No node, Docker, CLI, credential or producer
 * source access. Known owner pins and actual T-05 facts cannot be unavailable.
 * Seed and compiled/runtime commit provenance are deliberately separate facts.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect,it } from 'vitest';
import { qualifyReference } from '../../labs/scenarios/chaos/owned-reference.mjs';
import { readRetainedDemoRuntime } from '../../labs/scenarios/live-profile.mjs';

type Row=Record<string,unknown>;
function row(value:unknown):Row{if(!value||typeof value!=='object'||Array.isArray(value))throw new Error('GAP CP-043 artifact object unavailable');return value as Row;}
function records(value:unknown):Row[]{if(!Array.isArray(value))throw new Error('GAP CP-043 artifact records unavailable');return value.map(row);}
function json(path:string):Row{return row(JSON.parse(readFileSync(path,'utf8')) as unknown);}

it('CP-043/B1 actual full-demo export binds known owner image pins and observed T-05 recovery into its bundle',()=>{
  const handoffPath=process.env['FLUXWARDEN_DEMO_HANDOFF'];if(!handoffPath)throw new Error('GAP CP-043 explicit retained demo handoff required');
  const handoff=json(handoffPath),{owner,runtime}=readRetainedDemoRuntime(handoff);
  const bundle=process.env['FLUXWARDEN_DEMO_BUNDLE']??String(handoff['bundle']),manifest=json(join(bundle,'manifest.json'));
  const actual=json(String(handoff['actualT05Path'])),native=json(String(handoff['nativeHistoryPath'])),verification=json(String(handoff['verificationPath']));
  // D29: a new exclusively owned allocation has new names/ports. Historical
  // project literals are provenance of older runs, not the current oracle.
  qualifyReference(owner,runtime);
  const project=String(owner['project']);expect(project).toMatch(/^fluxwarden-lab-[a-z0-9-]+$/);expect(runtime['project']).toBe(project);expect(native['project']).toBe(project);
  const resources=records(native['resources']),services=['bitcoind','lnd-p','lnd-r','cln-p','cln-r','cln-m','toxiproxy'];
  expect(resources.map(v=>String(v['service'])).sort()).toEqual([...services].sort());
  const pins=row(runtime['images']),expectedDigests=new Set<string>();
  for(const service of services){const kind=service.startsWith('lnd-')?'lnd':service.startsWith('cln-')?'cln':service,pin=row(pins[kind]),observed=resources.find(v=>v['service']===service);
    expect(observed?.['project']).toBe(project);expect(observed?.['image']).toBe(pin['reference']);expect(String(pin['digest'])).toMatch(/^sha256:[a-f0-9]{64}$/);expectedDigests.add(String(pin['digest']));}
  // Verify the supplied successful bundle, without invoking an exporter or
  // accepting new fixture facts. Checksums cover eight existing payloads.
  const checksums=readFileSync(join(bundle,'checksums.sha256'),'utf8').trim().split('\n');expect(checksums).toHaveLength(8);
  for(const line of checksums){const match=/^([a-f0-9]{64}) {2}([a-z][a-z.-]+)$/.exec(line);if(!match?.[1]||!match[2])throw new Error('GAP CP-043 malformed retained checksum');expect(createHash('sha256').update(readFileSync(join(bundle,match[2]))).digest('hex')).toBe(match[1]);}
  expect(actual['caseId']).toBe('T-05');expect(actual['exit']).toBe(7);expect(actual['status']).toBe('UNKNOWN');expect(actual['sendCount']).toBe(1);
  const hash=String(actual['paymentHash']);expect(hash).toMatch(/^[a-f0-9]{64}$/);
  const merchant=records(native['records']).find(v=>v['node']==='cln-m');if(!merchant)throw new Error('GAP CP-043 retained native merchant missing');
  // Project only non-secret payment fields into diagnostics.
  const matching=records(merchant['payments']).filter(v=>v['paymentHash']===hash).map(v=>({status:v['status'],preimageMatchesHash:v['preimageMatchesHash']}));
  expect(matching).toEqual([{status:'complete',preimageMatchesHash:true}]);
  const executions=records(verification['executions']).filter(v=>v['hash']===hash);expect(executions.length).toBe(1);const execution=executions[0];if(!execution)throw new Error('GAP CP-043 retained execution missing');
  expect(execution['status']).toBe('VERIFIED_SUCCESS');expect(execution['nativeRecords']).toBe(1);
  const trace=readFileSync(join(bundle,'execution-trace.ndjson'),'utf8').trim().split('\n').map(line=>row(JSON.parse(line) as unknown)).filter(v=>v['execution_id']===execution['id']);
  expect(trace.some(v=>v['to']==='UNKNOWN')).toBe(true);expect(trace.some(v=>v['from']==='UNKNOWN'&&v['to']==='VERIFIED_SUCCESS')).toBe(true);
  const exportedDigests=Object.values(row(manifest['image_digests']));for(const digest of expectedDigests)expect.soft(exportedDigests.includes(digest),'known native owner image digest retained').toBe(true);
  expect.soft(manifest['chaos_scenario_ids'],'known observed T-05 scenario ID retained').toEqual(['T-05']);
  const unavailable=row(manifest['unavailable_evidence']??{});expect.soft(unavailable['image_digests'],'known owner images cannot be unavailable').toBeUndefined();expect.soft(unavailable['chaos_scenario_ids'],'observed scenario cannot be unavailable').toBeUndefined();
  const chaos=records(JSON.parse(readFileSync(join(bundle,'chaos-results.json'),'utf8')) as unknown),scenario=chaos.filter(v=>(v['scenario']??v['caseId'])==='T-05');
  expect.soft(scenario.length,'actual T-05 has one per-scenario exported result').toBe(1);
  if(scenario.length===1){const result=scenario[0];expect.soft(result?.['injection']).toBe(actual['injection']);expect.soft(result?.['pass']).toBe(true);
    const assertions=result?.['assertions'];expect.soft(Array.isArray(assertions)&&assertions.length>0,'scenario carries explicit assertions').toBe(true);
    // These are already public CP-043 Observation fields, not new API flags.
    for(const field of ['exit','status','paymentHash','sendCount'])expect.soft(result?.[field],`scenario retains actual ${field}`).toBe(actual[field]);
    const assertionText=JSON.stringify(assertions??[]);expect.soft(assertionText.includes('UNKNOWN'),'assertions identify sent unknown outcome').toBe(true);expect.soft(assertionText.includes('VERIFIED_SUCCESS'),'assertions identify actual terminal recovery').toBe(true);
    expect.soft(/one payment|payment.*(?:count|records).*1|exactly.*(?:one|1)/i.test(assertionText),'assertions record observed no-duplicate native payment').toBe(true);}
});
