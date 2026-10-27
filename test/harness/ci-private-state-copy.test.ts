// Private state copies: raw32 original outbox copies are SECRET_OUTPUT,
// never INPUT. Exact real product manifests/admission and full source scans
// remain independent of prospective typed policy acceptance.
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { copyFileSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { expect, it } from 'vitest';
import { asRecord, binPath, childEnv, repoRoot } from '../helpers/cli.js';
import { declareFixtureCapture, declareFixturePaths, ownedCaptureToolArgs } from '../helpers/capture-fixture.js';
import { expectOwnerOnly } from '../helpers/cp015-persistence.js';
import { testRoot } from '../helpers/env.js';

const sha = (bytes: Uint8Array | string): string => createHash('sha256').update(bytes).digest('hex');
const captureCli = join(repoRoot, 'scripts/ci-capture.mjs');
const sourceId = '01ARZ3NDEKTSV4RRFFQ69G5FAV', pubkey = `02${'ab'.repeat(32)}`;
function runtimeFiles(root: string): string[] {
  return readdirSync(root, { withFileTypes: true }).flatMap(entry => {
    const path = join(root, entry.name);
    return entry.isDirectory() ? entry.name === 'node_modules' ? [] : runtimeFiles(path) : entry.isFile() && /\.(js|json)$/.test(entry.name) ? [path] : [];
  });
}
function payloadFiles(root: string): string[] {
  return readdirSync(root, { withFileTypes: true }).flatMap(entry => {
    const path = join(root, entry.name);
    if (entry.isSymbolicLink()) throw new Error('bundle payload is linked');
    return entry.isDirectory() ? payloadFiles(path) : entry.isFile() ? [path] : [];
  });
}
async function fixture(mode: string) {
  const parent = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'private-copy-'));
  const root = join(parent, 'root'), capture = join(parent, 'capture'), temp = join(parent, 'temp'), tmp = join(parent, 'tmp'),
    testTmp = join(parent, 'test-tmp'), sentinels = join(parent, 'sentinels'), evidence = join(parent, 'evidence');
  for (const path of [root, capture, temp, tmp, testTmp, sentinels, evidence]) mkdirSync(path, { mode: 0o700 });
  const permissions = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as { assertPrivateDirectories: (paths: string[]) => Promise<void> };
  await permissions.assertPrivateDirectories([root, capture, temp, tmp, testTmp, sentinels, evidence]);
  const env = { ...childEnv(), TEMP: temp, TMP: tmp, FLUXWARDEN_TEST_TMP: testTmp, FLUXWARDEN_SENTINEL_DIR: sentinels, FLUXWARDEN_EVIDENCE_DIR: evidence };
  const test = join(root, 'test'); mkdirSync(test); mkdirSync(join(root, 'scripts'));
  for (const name of ['leak-check.mjs', 'private-scratch.mjs']) copyFileSync(join(repoRoot, 'scripts', name), join(root, 'scripts', name));
  const built = runtimeFiles(join(repoRoot, 'dist'));
  for (const path of built) { const destination = join(root, relative(repoRoot, path)); mkdirSync(dirname(destination), { recursive: true }); copyFileSync(path, destination); }
  const binary = join(root, relative(repoRoot, binPath()));
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'owned-private-copy-fixture', version: '1.0.0', type: 'module', bin: { fluxwarden: relative(root, binary).replace(/\\/g, '/') } }));
  const sourceState = join(test, 'original-state'), database = join(sourceState, 'original.db'), source = join(sourceState, 'outbox.key'), unrelated = join(test, 'unrelated.bin');
  const { openDatabase } = await import(pathToFileURL(join(root, 'dist/persistence/index.js')).href) as {
    openDatabase: (path: string, options: { readOnly: boolean }) => { close: () => void; nodes: { insert: (value: Record<string, string>) => void } };
  };
  const db = openDatabase(database, { readOnly: false });
  db.nodes.insert({ id: sourceId, name: 'alpha', implementation: 'cln', expectedNetwork: 'regtest', expectedPubkey: pubkey }); db.close();
  mkdirSync(join(sourceState, 'alerts'), { mode: 0o700 });
  const bytes = randomBytes(32), other = randomBytes(32);
  declareFixturePaths([source, unrelated]); declareFixtureCapture(capture, [bytes, other], []);
  writeFileSync(source, '', { flag: 'wx', mode: 0o600 });
  if (process.platform === 'win32') expect(spawnSync(join(process.env['SystemRoot'] ?? 'C:/Windows', 'System32/icacls.exe'), [source, '/inheritance:d'], { windowsHide: true, timeout: 10000 }).status).toBe(0);
  writeFileSync(source, bytes); writeFileSync(unrelated, other, { mode: 0o600 });
  writeFileSync(join(test, 'sentinels.json'), JSON.stringify(['test/original-state/outbox.key', 'test/unrelated.bin']));
  const bundle = join(testTmp, 'bundle'), restored = join(testTmp, 'restored-state'), restoredDb = join(restored, 'restored.db');
  const config = join(testTmp, 'source.yaml'), restoreConfig = join(testTmp, 'restore.yaml');
  function configText(path: string, alerts: string): string {
    const yaml = (path: string): string => path.replace(/\\/g, '/');
    return `database: "${yaml(path)}"\nalert_dir: "${yaml(alerts)}"\nnodes:\n  - name: alpha\n    implementation: cln\n    url: https://127.0.0.1:1\n    tls_cert_path: "${yaml(join(test, 'unused.pem'))}"\n    rune_path: "${yaml(join(test, 'unused.rune'))}"\n    expected_pubkey: "${pubkey}"\n    expected_network: regtest\n`;
  }
  writeFileSync(config, configText(database, join(sourceState, 'alerts'))); writeFileSync(restoreConfig, configText(restoredDb, join(restored, 'alerts')));
  const git = (args: string[]) => spawnSync('git', args, { cwd: root, env, windowsHide: true, encoding: 'utf8', timeout: 30000 });
  for (const args of [['init', '--quiet'], ['config', 'core.longpaths', 'true'], ['add', '--', '.'],
    ['-c', 'user.name=Private copy fixture', '-c', 'user.email=fixture@invalid', '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'immutable built private-copy fixture']]) expect(git(args).status).toBe(0);
  const control = join(evidence, 'control.json'), driver = join(temp, 'driver.mjs');
  const helper = pathToFileURL(join(repoRoot, 'scripts/ci-secret-output.mjs')).href;
  writeFileSync(driver, `
import {spawnSync} from 'node:child_process';import {readFileSync,writeFileSync,appendFileSync,lstatSync,renameSync,copyFileSync,linkSync,chmodSync} from 'node:fs';import {createHash} from 'node:crypto';import {join} from 'node:path';
const mode=${JSON.stringify(mode)},source=${JSON.stringify(source)},unrelated=${JSON.stringify(unrelated)},bundle=${JSON.stringify(bundle)},restored=${JSON.stringify(restored)},config=${JSON.stringify(config)},restoreConfig=${JSON.stringify(restoreConfig)},binary=${JSON.stringify(binary)};
const hash=b=>createHash('sha256').update(b).digest('hex');
const env=Object.fromEntries(Object.entries(process.env).filter(([name])=>!/^FLUXWARDEN_|^NODE_OPTIONS$|^NODE_DEBUG$/i.test(name)||name.toUpperCase()==='FLUXWARDEN_TEST_TMP'));
const sourceBefore={sha256:hash(readFileSync(source)),ino:String(lstatSync(source).ino),dev:String(lstatSync(source).dev)};
const facts={mode,sourceBefore,authorizations:[],children:[]};
const {authorizeSecretOutput}=await import(${JSON.stringify(helper)});
async function invoke(operation){
 const path=join(operation==='backup'?bundle:restored,'outbox.key'),sourcePath=operation==='backup'?source:join(bundle,'outbox.key');
 const args=[binary,'--json','state',operation,operation==='backup'?'--out':'--from',bundle,'--config',operation==='backup'?config:restoreConfig];
 const intent={kind:mode==='unknown-kind'?'unrelated-copy':'state-outbox-copy',path,sourcePath:(mode==='wrong-source'&&operation==='backup'||mode==='wrong-restore-source'&&operation==='restore')?unrelated:sourcePath,command:process.execPath,args:[...args],env:{...env}};
 async function authorize(){let accepted=true;try{await authorizeSecretOutput(intent);}catch{accepted=false;}facts.authorizations.push({operation,accepted});}
 if(mode!=='missing'&&mode!=='late')await authorize();
 const actualEnv={...env};
 if(operation==='backup'&&mode==='config-change')appendFileSync(config,'# changed after intent\\n');
 if(operation==='backup'&&mode==='environment-change')actualEnv.PRIVATE_COPY_CONTROL='changed';
 if(operation==='backup'&&mode==='argv-change'){const replacement=config+'.same-bytes';copyFileSync(config,replacement);args[args.length-1]=replacement;}
 const result=spawnSync(process.execPath,args,{env:actualEnv,encoding:'utf8',windowsHide:true,timeout:30000});
 facts.children.push({operation,status:result.status,signal:result.signal,errorCode:result.error?.code??null});
 process.stdout.write(result.stdout??'');process.stderr.write(result.stderr??'');
 if(result.error||result.signal||result.status!==0)throw Error('ordinary state-copy child failed');
 if(mode==='late')await authorize();
 return path;
}
const backupKey=await invoke('backup');
if(mode==='roundtrip'||mode==='wrong-restore-source')await invoke('restore');
if(mode==='source-change'){const old=readFileSync(source),next=Buffer.from(old);next[0]^=1;writeFileSync(source,next);}
if(mode==='added-bytes')appendFileSync(backupKey,Buffer.from('extra payload'));
if(mode==='manifest-change'){const path=join(bundle,'manifest.json'),manifest=JSON.parse(readFileSync(path));manifest.nodes[0].pubkey='02'+'cd'.repeat(32);writeFileSync(path,JSON.stringify(manifest));}
if(mode==='hard-linked'){linkSync(backupKey,backupKey+'.alias');facts.multipleLinks=lstatSync(backupKey).nlink>1;}
if(mode==='insecure'){if(process.platform==='win32'){if(spawnSync('C:/Windows/System32/icacls.exe',[backupKey,'/grant','*S-1-1-0:(R)'],{windowsHide:true}).status!==0)throw Error('ACL control failed');}else chmodSync(backupKey,0o644);}
if(mode==='replaced'){const before=lstatSync(backupKey),next=backupKey+'.replacement';copyFileSync(backupKey,next);if(process.platform==='win32'&&spawnSync('C:/Windows/System32/icacls.exe',[next,'/inheritance:d'],{windowsHide:true}).status!==0)throw Error('protect replacement');renameSync(next,backupKey);facts.replaced=before.ino!==lstatSync(backupKey).ino;}
if(mode==='extra-sink')writeFileSync(join(process.env.FLUXWARDEN_EVIDENCE_DIR,'unexpected-key.bin'),readFileSync(source));
if(mode==='cross-source')writeFileSync(join(process.env.FLUXWARDEN_EVIDENCE_DIR,'unrelated-source.bin'),readFileSync(unrelated));
if(mode==='stdout')process.stdout.write(readFileSync(source));
facts.sourceAfter={sha256:hash(readFileSync(source)),ino:String(lstatSync(source).ino),dev:String(lstatSync(source).dev)};
writeFileSync(${JSON.stringify(control)},JSON.stringify(facts));
`);
  const invoke = (verify = false) => {
    const result = spawnSync(process.execPath, [...ownedCaptureToolArgs([captureCli, ...(verify ? ['verify'] : []), '--root', root, '--capture-dir', capture,
      ...(verify ? [] : ['--', process.execPath, driver])])], { cwd: root, env, encoding: 'utf8', windowsHide: true, timeout: verify ? 30000 : 60000 });
    if (verify) {
      expect(result.error, 'independent verifier completes without transport failure or deadline').toBeUndefined();
      expect(result.signal, 'a killed verifier is not a refusal proof').toBeNull();
      expect(result.status, 'refusal must be an actual verifier exit').not.toBeNull();
    }
    return result;
  };
  return { root, capture, bundle, restored, restoredDb, source, database, control, invoke,
    receipt: () => asRecord(JSON.parse(readFileSync(join(capture, 'receipt.json'), 'utf8')) as unknown, 'capture receipt') };
}

it('CP-044/PRIVATE-COPY exact prospective original32 backup and restore remain scanned OUTPUT with manifest and admission integrity', async () => {
  const f = await fixture('roundtrip'), result = f.invoke();
  expect(result.error).toBeUndefined(); expect(result.signal).toBeNull();
  const facts = asRecord(JSON.parse(readFileSync(f.control, 'utf8')) as unknown, 'actual product observations');
  expect(facts['children']).toMatchObject([{ operation: 'backup', status: 0 }, { operation: 'restore', status: 0 }]);
  expect(facts['sourceAfter']).toEqual(facts['sourceBefore']);
  const manifest = asRecord(JSON.parse(readFileSync(join(f.bundle, 'manifest.json'), 'utf8')) as unknown, 'complete backup manifest');
  expect(manifest['format']).toBe(1); expect(manifest['nodes']).toEqual([{ id: sourceId, name: 'alpha', implementation: 'cln', pubkey }]);
  const entries = manifest['files'] as { path: string; sha256: string; bytes: number }[];
  expect(entries.map(row => row.path).sort()).toEqual(payloadFiles(f.bundle).filter(path => path !== join(f.bundle, 'manifest.json')).map(path => relative(f.bundle, path).replace(/\\/g, '/')).sort());
  for (const entry of entries) { const path = join(f.bundle, entry.path); expect(sha(readFileSync(path))).toBe(entry.sha256); expect(lstatSync(path).size).toBe(entry.bytes); }
  const source = readFileSync(f.source); expect(source).toHaveLength(32);
  for (const directory of [f.bundle, f.restored]) expectOwnerOnly(directory, 'directory');
  for (const key of [join(f.bundle, 'outbox.key'), join(f.restored, 'outbox.key')]) { expect(readFileSync(key).equals(source)).toBe(true); expect(lstatSync(key).nlink).toBe(1); expectOwnerOnly(key, 'file'); }
  // Read the sealed tracked source without SQLite creating WAL/SHM sidefiles.
  const originalUri = pathToFileURL(f.database); originalUri.searchParams.set('immutable', '1');
  const original = new DatabaseSync(originalUri.href, { readOnly: true }), restored = new DatabaseSync(f.restoredDb, { readOnly: true });
  try {
    expect(manifest['schema']).toBe(original.prepare('PRAGMA user_version').get()?.['user_version']);
    expect(restored.prepare('PRAGMA integrity_check').get()?.['integrity_check']).toBe('ok');
    for (const table of ['nodes', 'approvals', 'executions', 'execution_events', 'budget_reservations', 'ledger_journals', 'ledger_lines']) {
      expect(restored.prepare(`SELECT * FROM ${table}`).all()).toEqual(original.prepare(`SELECT * FROM ${table}`).all());
    }
  } finally { original.close(); restored.close(); }
  const { openDatabase } = await import(pathToFileURL(join(f.root, 'dist/persistence/index.js')).href) as {
    openDatabase: (path: string, options: { readOnly: boolean; mustExist: boolean }) => { close: () => void; state: { assertAdmitted: () => void } };
  };
  const admission = openDatabase(f.restoredDb, { readOnly: false, mustExist: true });
  try { let code: unknown; try { admission.state.assertAdmitted(); } catch (error) { code = (error as { code?: unknown }).code; } expect(code).toBe('RESTORE_PENDING'); }
  finally { admission.close(); }
  const receipt = f.receipt();
  expect(receipt['result']).toMatchObject({ exitCode: 0, complete: true, leakFree: false, policySatisfied: true });
  const artifacts = receipt['artifacts'] as Record<string, unknown>[];
  for (const path of [join(f.bundle, 'outbox.key'), join(f.restored, 'outbox.key')]) expect(artifacts.filter(row => row['path'] === path && row['purpose'] === 'SECRET_OUTPUT' && row['sha256'] === sha(source))).toHaveLength(1);
  expect((receipt['sources'] as Record<string, unknown>[]).some(row => row['sha256'] === sha(source))).toBe(true);
  expect(result.status).toBe(0); expect(f.invoke(true).status).toBe(0);
}, 360000);

it('CP-044/PRIVATE-COPY exact32 intent cannot authorize changed source destination config environment or argv', async () => {
  for (const mode of ['wrong-source', 'source-change', 'added-bytes', 'replaced', 'config-change', 'environment-change', 'argv-change', 'unknown-kind']) {
    const f = await fixture(mode), result = f.invoke(); expect(result.error).toBeUndefined(); expect(result.signal).toBeNull();
    const facts = asRecord(JSON.parse(readFileSync(f.control, 'utf8')) as unknown, 'actual copy control');
    expect(facts['children']).toMatchObject([{ operation: 'backup', status: 0 }]);
    if (mode === 'replaced') expect(facts['replaced']).toBe(true);
    expect(result.status !== null && result.status !== 0).toBe(true); expect(asRecord(f.receipt()['result'], 'policy')['policySatisfied']).not.toBe(true);
    expect(f.invoke(true).status !== 0).toBe(true);
  }
}, 360000);

it('CP-044/PRIVATE-COPY closing checks reject changed manifest hard links broad ACL and wrong restore source', async () => {
  for (const mode of ['manifest-change', 'hard-linked', 'insecure', 'wrong-restore-source']) {
    const f = await fixture(mode), result = f.invoke(); expect(result.error).toBeUndefined(); expect(result.signal).toBeNull();
    const facts = asRecord(JSON.parse(readFileSync(f.control, 'utf8')) as unknown, 'actual closing control');
    expect(facts['children']).toMatchObject(mode === 'wrong-restore-source'
      ? [{ operation: 'backup', status: 0 }, { operation: 'restore', status: 0 }] : [{ operation: 'backup', status: 0 }]);
    if (mode === 'hard-linked') expect(facts['multipleLinks']).toBe(true);
    expect(result.status !== null && result.status !== 0).toBe(true);
    expect(asRecord(f.receipt()['result'], 'policy')['policySatisfied']).not.toBe(true);
    expect(f.invoke(true).status !== 0).toBe(true);
  }
}, 360000);

it('CP-044/PRIVATE-COPY full source census rejects missing late extra-sink cross-source and stream disclosures', async () => {
  for (const mode of ['missing', 'late', 'extra-sink', 'cross-source', 'stdout']) {
    const f = await fixture(mode), result = f.invoke(); expect(result.error).toBeUndefined(); expect(result.signal).toBeNull();
    expect(asRecord(JSON.parse(readFileSync(f.control, 'utf8')) as unknown, 'actual copy control')['children']).toMatchObject([{ operation: 'backup', status: 0 }]);
    expect(result.status !== null && result.status !== 0).toBe(true);
    expect(f.receipt()['result']).toMatchObject({ leakFree: false, policySatisfied: false });
    expect(f.invoke(true).status !== 0).toBe(true);
  }
}, 360000);
