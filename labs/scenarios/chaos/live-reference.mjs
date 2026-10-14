// Owned pinned regtest oracle. Inputs are paths; retained answers omit secret fields.
import { createHash } from 'node:crypto';
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export const requiredLiveRows = ['T-01','T-03','T-05','T-06','T-07','T-16','T-18','T-25'];
export const allFakeRows = Array.from({ length: 25 }, (_, i) => `T-${String(i + 1).padStart(2, '0')}`);
let runner;
const paused = new Set();
export function setRunner(value) { runner = value; }
export function input() {
  if (!process.env.FLUXWARDEN_CHAOS_REFERENCE_PLAN) throw new Error('LabInvalidError: explicit owned reference plan required');
  const p = JSON.parse(readFileSync(process.env.FLUXWARDEN_CHAOS_REFERENCE_PLAN, 'utf8'));
  const owner = JSON.parse(readFileSync(p.owner, 'utf8'));
  if (owner.project !== 'fluxwarden-lab-demo-fixed-20261013' || owner.ports.lndRest !== 29210 || owner.ports.clnRest !== 29211 || owner.ports.toxiproxy !== 29212)
    throw new Error('LabInvalidError: authorized owner mismatch');
  return { ...p, ownerPath:p.owner, owner, manifest: JSON.parse(readFileSync(join(owner.runtimeRoot, 'lab.json'), 'utf8')) };
}
function hash(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
export function register(path, name) {
  const p = input(), bytes = readFileSync(path), destination = join(p.sentinels, name);
  writeFileSync(destination, bytes, { mode: 0o600 });
  appendFileSync(join(p.tmp, 'declared-out.txt'), `${destination}\n`);
  appendFileSync(join(p.evidence, 'sources.ndjson'), `${JSON.stringify({ path, sha256: hash(bytes) })}\n`);
}
function safe(value) {
  if(typeof value === 'bigint')return value.toString();
  if (Array.isArray(value)) return value.map(safe);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, v]) => {
    if (/preimage|r_preimage|payment_secret|paymentSecret|payment_addr|rune|macaroon|private_key/i.test(key) && typeof v === 'string' && v && v !== '[redacted]') {
      const binary = /preimage|payment_secret|paymentSecret|payment_addr/i.test(key);
      const p = input(), bytes = /^[a-f0-9]{64}$/i.test(v) ? Buffer.from(v, 'hex') : binary && /^[A-Za-z0-9+/]{43}=$/.test(v) ? Buffer.from(v, 'base64') : Buffer.from(v);
      // Native lncli Payment uses a zero-filled payment_preimage when the
      // FAILED/IN_FLIGHT/INITIATED payment has no revealed preimage. This
      // typed absent value is still redacted. Explicit inputs and successful
      // receipt preimages, including all-zero bytes, remain registered.
      if(key === 'payment_preimage' && ['FAILED','IN_FLIGHT','INITIATED'].includes(value.status) && bytes.length === 32 && bytes.every(byte=>byte===0))return[key,'[redacted]'];
      writeFileSync(join(p.sentinels, `observed-${hash(bytes)}.bin`), bytes, { mode: 0o600 });
      return [key, '[redacted]'];
    }
    return [key, safe(v)];
  }));
  return value;
}
export function retain(name, value) { const p = input(); writeFileSync(join(p.evidence, `${name}.json`), JSON.stringify(safe(value), null, 2)); }
function command(executable, args) {
  const r = runner(executable, args, { encoding: 'utf8', shell: false, windowsHide: true, timeout: 30000, maxBuffer: 16 * 1024 * 1024 });
  if (r.status !== 0) throw new Error('LabInvalidError: owned direct oracle failed');
  return JSON.parse(r.stdout);
}
export function oracle(node, method, parameters = []) {
  const p = input();
  return safe(command('docker', ['exec', `${p.owner.project}-${node}-1`, ...(node.startsWith('lnd-') ? ['lncli', '--network=regtest'] : ['lightning-cli','--network=regtest','-k']), method, ...parameters]));
}
export async function proxies() { const p = input(); return await (await fetch(`http://127.0.0.1:${p.owner.ports.toxiproxy}/proxies`)).json(); }
export async function clean() {
  const p = input(), base = `http://127.0.0.1:${p.owner.ports.toxiproxy}/proxies`;
  const failures=[];let observed={};
  try{observed=await proxies();}catch(error){failures.push(error);}
  for (const [name, proxy] of Object.entries(observed)) {
    for (const toxic of proxy.toxics) try{const response=await fetch(`${base}/${name}/toxics/${toxic.name}`, { method:'DELETE' });if(!response.ok)throw new Error('owned toxic cleanup refused');}catch(error){failures.push(error);}
    try{const response=await fetch(`${base}/${name}`, { method:'POST', headers:{ 'content-type':'application/json' }, body:JSON.stringify({ enabled:true }) });if(!response.ok)throw new Error('owned proxy cleanup refused');}catch(error){failures.push(error);}
  }
  for (const node of [...paused]) try{nodeControl(node,'unpause');}catch(error){failures.push(error);}
  if(failures.length)throw failures[0];
}
export function nodeControl(node, operation) {
  if (!['bitcoind','lnd-r','cln-r','cln-m'].includes(node) || !['pause','unpause'].includes(operation)) throw new Error('owned pause only');
  const p = input(), r = runner('docker',[operation,`${p.owner.project}-${node}-1`],{ encoding:'utf8', shell:false, windowsHide:true, timeout:30000 });
  if (r.status !== 0) throw new Error('LabInvalidError: owned pause operation failed');
  if (operation === 'pause') paused.add(node); else paused.delete(node);
}
export async function enable(proxy,enabled) {
  if (!['lnd-r-rest','cln-m-rest'].includes(proxy)) throw new Error('owned proxy only');
  const p = input(); const response = await fetch(`http://127.0.0.1:${p.owner.ports.toxiproxy}/proxies/${proxy}`,{ method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({ enabled }) });
  if (!response.ok) throw new Error('LabInvalidError: owned proxy control failed');
}
export async function latency(proxy,name,milliseconds) {
  if (!['lnd-r-rest','cln-m-rest'].includes(proxy)) throw new Error('owned proxy only');
  const p=input(),response=await fetch(`http://127.0.0.1:${p.owner.ports.toxiproxy}/proxies/${proxy}/toxics`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name,type:'latency',stream:'downstream',toxicity:1,attributes:{latency:milliseconds,jitter:0}})});
  if(!response.ok)throw new Error('LabInvalidError: owned latency control failed');
}
export function clnConfig(caseId,reverse=false) {
  if(!/^t\d\d-[a-z]+$/.test(caseId))throw new Error('fixed owned scenario name required');
  const p=input(),directory=mkdtempSync(join(p.tmp,`${caseId}-`));
  const channels=oracle('cln-m','listpeerchannels').channels,ordered=[...channels].sort((a,b)=>Number(a.receivable_msat)-Number(b.receivable_msat));if(reverse)ordered.reverse();
  const config=join(directory,'config.yaml'),policy=join(directory,'policy.yaml'),database=join(directory,'case.db');
  writeFileSync(policy,readFileSync(p.policy,'utf8').split('"targets":')[0]+`"targets":\n  "cln-m":\n    "${ordered[0].short_channel_id}":\n      "min_inbound_msat": "${BigInt(ordered[0].receivable_msat)+100000000n}"\n    "${ordered[1].short_channel_id}":\n      "min_inbound_msat": "0"\n`);
  let configText=readFileSync(p.config,'utf8').replace('database: ./state/fluxwarden.db',`database: "${database.replaceAll('\\','/')}"`).replace('policy: ./policy.yaml',`policy: "${policy.replaceAll('\\','/')}"`);
  if(caseId.startsWith('t07-')||caseId.startsWith('t16-'))configText=configText.replace('attempt_deadline: 120s','attempt_deadline: 15s');
  if(caseId.startsWith('t16-'))configText=configText.replace('escalate_after: 1h','escalate_after: 1s').replace('collect_interval: 15s','collect_interval: 1s');
  writeFileSync(config,configText+`alert_dir: "${join(directory,'alerts').replaceAll('\\','/')}"\n`);
  retain(`${caseId}-fixture`,{database,policy,originalChannels:channels,policyFileSha256:hash(readFileSync(policy))});return{config,policy,database};
}
export async function preflight(name) {
  const p = input(), ids = command('docker', ['inspect', ...['bitcoind','lnd-p','lnd-r','cln-p','cln-r','cln-m','toxiproxy'].map(n => `${p.owner.project}-${n}-1`)]);
  const nodes = ['lnd-p','lnd-r','cln-p','cln-r','cln-m'].map(node => {
    const info = oracle(node,'getinfo'), expected = p.manifest.nodes[node], lnd = node.startsWith('lnd-');
    const network = lnd ? info.chains[0].network : info.network;
    if (network !== 'regtest' || (lnd ? info.identity_pubkey : info.id) !== expected.pubkey || (lnd ? !info.version.startsWith('0.21.4-beta') : info.version !== 'v26.06.9')) throw new Error('LabInvalidError: pinned node identity mismatch');
    const channels = oracle(node,lnd ? 'listchannels':'listpeerchannels');
    const list = channels.channels;
    if (list.some(c => (lnd ? c.pending_htlcs : c.htlcs)?.length)) throw new Error('LabInvalidError: leftover HTLCs');
    return { node, info, channels };
  });
  const proxy = await proxies();
  if (Object.values(proxy).some(v => !v.enabled || v.toxics.length)) throw new Error('LabInvalidError: dirty owned proxy');
  const facts = { nodes, proxies:proxy, containers:ids.map(v => ({ name:v.Name, image:v.Config.Image, running:v.State.Running, paused:v.State.Paused })) };
  retain(name,facts); return facts;
}
export function query(database, sql, ...params) {
  const db = new DatabaseSync(database, { readOnly:true });
  try { db.exec('PRAGMA busy_timeout = 100'); return db.prepare(sql).all(...params); } finally { db.close(); }
}
export function rows(sql,...params) { return query(input().database,sql,...params); }
export function history() {
  return Object.fromEntries(['liquidity_proposals','approvals','executions','execution_events','ledger_journals','ledger_lines','budget_reservations'].map(t => [t, rows(`SELECT * FROM ${t}`)]));
}
export function unchangedOld(before, after) {
  for (const [table, old] of Object.entries(before)) for (const row of old) {
    const match = after[table].find(candidate => table === 'ledger_lines' ? candidate.journal_id === row.journal_id && candidate.sequence_no === row.sequence_no : candidate.id === row.id);
    if (JSON.stringify(match) !== JSON.stringify(row)) throw new Error(`historical ${table} row changed`);
  }
}
export function cli(args, name, config) {
  const p = input(), r = runner(process.execPath, [resolve('dist/cli/bin.js'), '--json', ...args, '--config', config ?? p.config], {
    cwd:p.cwd, env:{ ...process.env, FLUXWARDEN_LAB_PLAN:p.ownerPath ?? p.owner }, shell:false, windowsHide:true, encoding:'utf8', timeout:180000, maxBuffer:16 * 1024 * 1024,
  });
  let body; try { body = JSON.parse(r.stdout); } catch { body = { malformed:true }; }
  const result = { exit:r.status, signal:r.signal, body, stderr:r.stderr }; retain(name,result); return result;
}
export function networkConfig(network) {
  const p = input(), target = join(p.tmp,`network-${network}.yaml`);
  // Missing execution credential proves the network guard happens before credential reading.
  writeFileSync(target, readFileSync(p.config,'utf8').replace('expected_network: regtest',`expected_network: ${network}`).replace(/rune_path: .*/,`rune_path: "${join(p.tmp,'unreadable-never-created.rune').replaceAll('\\','/')}"`).replace('database: ./state/fluxwarden.db',`database: "${p.database.replaceAll('\\','/')}"`).replace('policy: ./policy.yaml',`policy: "${p.policy.replaceAll('\\','/')}"`));
  return target;
}
export function initializeRegistry() {
  const p = input();
  for (const node of Object.values(p.manifest.nodes)) register(node.certificate.path, `${node.pubkey}-certificate`);
  for (const [node, credentials] of Object.entries(p.manifest.credentials)) for (const [kind,c] of Object.entries(credentials)) register(c.path, `${node}-${kind}-credential`);
  register(p.key,'operator-private.pem');
  // Existing owner registry also includes TLS private material and preimages.
  const current=readdirSync(p.owner.sentinelRoot,{withFileTypes:true}).filter(entry=>entry.isFile()).map(entry=>join(p.owner.sentinelRoot,entry.name));
  for (const name of new Set([...(p.extraSentinels??[]),...current])) register(name,`source-${hash(Buffer.from(name))}`);
}
export function lndConfig(reverse=false) {
  const p = input(), directory = mkdtempSync(join(p.tmp,'lnd-owned-'));
  const info = oracle('lnd-r','listchannels');let target = info.channels.find(c => c.remote_pubkey === p.manifest.nodes['cln-m'].pubkey), source = info.channels.find(c => c.remote_pubkey === p.manifest.nodes['cln-r'].pubkey);if(reverse)[target,source]=[source,target];
  if (!source || !target) throw new Error('LabInvalidError: owned LND circular endpoints unavailable');
  const principal = 100000000n, inbound = BigInt(source.remote_balance) * 1000n + principal;
  const policy = join(directory,'policy.yaml'), config = join(directory,'config.yaml'), database = join(directory,'lnd.db');
  // REST ListChannels channel keys are decimal scids; lncli adds scid_str as a display field.
  writeFileSync(policy,readFileSync(p.policy,'utf8').split('"targets":')[0]+`"targets":\n  "lnd-r":\n    "${source.scid}":\n      "min_inbound_msat": "${inbound}"\n    "${target.scid}":\n      "min_inbound_msat": "0"\n`);
  const head = readFileSync(p.config,'utf8').split('nodes:')[0].replace('database: ./state/fluxwarden.db',`database: "${database.replaceAll('\\','/')}"`).replace('policy: ./policy.yaml',`policy: "${policy.replaceAll('\\','/')}"`);
  writeFileSync(config,head+`nodes:\n  - name: lnd-r\n    implementation: lnd\n    url: https://localhost:29210\n    tls_cert_path: "${p.manifest.nodes['lnd-r'].certificate.path.replaceAll('\\','/')}"\n    macaroon_path: "${p.manifest.credentials['lnd-r'].execute.path.replaceAll('\\','/')}"\n    expected_pubkey: "${p.manifest.nodes['lnd-r'].pubkey}"\n    expected_network: regtest\n`);
  retain('lnd-owned-policy-source',{ originalPolicySha256:'baaae43179d69c79ee0fe9a16410463ec403eed1aa78f4d740481c6b25184287', fileSha256:hash(readFileSync(policy)), sourceChannel:source.scid_str,targetChannel:target.scid_str,principalMsat:principal.toString(), originalChannels:info.channels });
  return {config,policy,database};
}
export function feeConfig() {
  const p = input(), directory = join(p.tmp,'cln-fee-quote');mkdirSync(directory,{recursive:true,mode:0o700});
  const channels = oracle('cln-m','listpeerchannels').channels, ordered = [...channels].sort((a,b)=>Number(a.receivable_msat)-Number(b.receivable_msat));
  const desired = BigInt(ordered[0].receivable_msat)+100000000n;
  const config=join(directory,'config.yaml'),policy=join(directory,'policy.yaml'),database=join(directory,'quote.db');
  writeFileSync(policy,readFileSync(p.policy,'utf8').split('"targets":')[0].replace('"max_fee_msat": "300000"','"max_fee_msat": "100"')+`"targets":\n  "cln-m":\n    "${ordered[0].short_channel_id}":\n      "min_inbound_msat": "${desired}"\n    "${ordered[1].short_channel_id}":\n      "min_inbound_msat": "0"\n`);
  writeFileSync(config,readFileSync(p.config,'utf8').replace('database: ./state/fluxwarden.db',`database: "${database.replaceAll('\\','/')}"`).replace('policy: ./policy.yaml',`policy: "${policy.replaceAll('\\','/')}"`));
  return {config,policy,database};
}
export function readConfig(config) {
  const p=input(),destination=config.replace(/\.yaml$/,'-read.yaml');
  writeFileSync(destination,readFileSync(config,'utf8').replace(p.manifest.credentials['cln-m'].execute.path.replaceAll('\\','/'),p.manifest.credentials['cln-m'].read.path.replaceAll('\\','/')));
  return destination;
}
