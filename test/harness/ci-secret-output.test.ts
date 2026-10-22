// SPEC 10.3 command13 and SECURITY5: generated private keys stay OUTPUT and
// fully scanned. Prospective intent may accept only the exact genuine producer's
// canonical owner-only key, with its actual successful public response bound.
// Public helper: ci-secret-output.mjs authorizeSecretOutput({path,command,args}).
import { spawnSync } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import { appendFileSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { asRecord, binPath, childEnv, repoRoot } from '../helpers/cli.js';
import { declareFixtureCapture, declareFixturePaths, ownedCaptureToolArgs } from '../helpers/capture-fixture.js';
import { testRoot } from '../helpers/env.js';
import { scanner } from '../helpers/leak-scan.js';
import { assertStrictWindowsOwnerOnly, readWindowsSecurity } from '../helpers/windows-security.js';

const sha = (bytes: Buffer | string): string => createHash('sha256').update(bytes).digest('hex');
const captureCli = join(repoRoot, 'scripts/ci-capture.mjs');
const outputHelper = pathToFileURL(join(repoRoot, 'scripts/ci-secret-output.mjs')).href;
const records = (value: unknown): Record<string, unknown>[] => {
  if (!Array.isArray(value)) throw new Error('retained census must be an array');
  return value.map(row => asRecord(row, 'census row'));
};

function runtimeFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return entry.name === 'node_modules' ? [] : runtimeFiles(path);
    return entry.isFile() && /\.(?:js|json)$/.test(entry.name) ? [path] : [];
  });
}

async function fixture(mode: string, registerKey = true) {
  const parent = mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'ko-'));
  const root = join(parent, 'r'), capture = join(parent, 'c');
  const roots = ['t', 'u', 's', 'src', 'ev'].map(name => join(parent, name));
  for (const path of [root, capture, ...roots]) mkdirSync(path, { mode: 0o700 });
  const { assertPrivateDirectories } = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as {
    assertPrivateDirectories: (paths: string[]) => Promise<void>;
  };
  await assertPrivateDirectories(roots);
  const env = { ...childEnv(), TEMP: roots[0], TMP: roots[1], FLUXWARDEN_TEST_TMP: roots[2],
    FLUXWARDEN_SENTINEL_DIR: roots[3], FLUXWARDEN_EVIDENCE_DIR: roots[4] };
  mkdirSync(join(root, 'test')); mkdirSync(join(root, 'scripts'));
  const seed = randomBytes(32), source = join(root, 'test/control.bin');
  declareFixturePaths([source]);
  declareFixtureCapture(capture, [seed], []);
  writeFileSync(source, seed, { mode: 0o600 });
  writeFileSync(join(root, 'test/sentinels.json'), JSON.stringify(['test/control.bin']));
  const support = ['leak-check.mjs', 'private-scratch.mjs'];
  for (const name of support) copyFileSync(join(repoRoot, 'scripts', name), join(root, 'scripts', name));
  const built = runtimeFiles(join(repoRoot, 'dist'));
  for (const path of built) {
    const destination = join(root, relative(repoRoot, path));
    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(path, destination);
  }
  const binary = join(root, relative(repoRoot, binPath()));
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'owned-key-output-fixture', version: '1.0.0', type: 'module',
    bin: { fluxwarden: relative(root, binary).replace(/\\/g, '/') } }));
  const git = (...args: string[]) => {
    const result = spawnSync('git', args, { cwd: root, env, encoding: 'utf8', windowsHide: true, timeout: 10_000 });
    appendFileSync(join(parent, 'git-setup.jsonl'), JSON.stringify({ stage: args[0], status: result.status, signal: result.signal,
      errorCode: (result.error as NodeJS.ErrnoException | undefined)?.code ?? null }) + '\n');
    return result;
  };
  const inputs = ['package.json', 'test/control.bin', 'test/sentinels.json', ...support.map(name => `scripts/${name}`),
    ...built.map(path => relative(repoRoot, path).replace(/\\/g, '/'))];
  for (const args of [['init', '--quiet'], ['config', 'core.longpaths', 'true'], ['add', '--', ...inputs],
    ['-c', 'user.name=Key output fixture', '-c', 'user.email=fixture@invalid', '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'owned key output fixture']]) {
    expect(git(...args).status, 'genuine built CLI fixture has original immutable Git identity').toBe(0);
  }
  const key = join(roots[2] ?? '', 'operator.key'), response = join(roots[4] ?? '', 'producer.json');
  const control = join(roots[4] ?? '', 'control.json'), child = join(roots[0] ?? '', 'command.mjs');
  // Deliberate response faults are substituted producers, never a general
  // permission to preload arbitrary programs into the genuine key command.
  const transport = join(root, 'transport.mjs');
  writeFileSync(transport, `
const original=process.stdout.write.bind(process.stdout);
process.stdout.write=function(chunk,...rest){
 let value;try{value=JSON.parse(String(chunk));}catch{return original(chunk,...rest);}
 if(value.result){if(${JSON.stringify(mode)}==='wrong-public-key')value.result.public_key=Buffer.alloc(32,7).toString('base64');
 if(${JSON.stringify(mode)}==='wrong-key-id')value.result.key_id='0'.repeat(32);}
 return original(JSON.stringify(value)+'\\n',...rest);
};
`);
  const fake = join(root, 'wrong-producer.mjs');
  writeFileSync(fake, `
import {generateKeyPairSync,createHash} from 'node:crypto';import {writeFileSync} from 'node:fs';import {spawnSync} from 'node:child_process';
const out=process.argv[process.argv.indexOf('--out')+1],pair=generateKeyPairSync('ed25519');
writeFileSync(out,pair.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});
if(process.platform==='win32'&&spawnSync('C:/Windows/System32/icacls.exe',[out,'/inheritance:d'],{windowsHide:true}).status!==0)throw Error('owned key protection failed');
const raw=pair.publicKey.export({format:'der',type:'spki'}).subarray(-32);
process.stdout.write(JSON.stringify({schema:1,command:'keys generate',ok:true,result:{public_key:raw.toString('base64'),key_id:createHash('sha256').update(raw).digest('hex').slice(0,32)},error:null})+'\\n');
process.exitCode=${mode === 'failed-producer' ? '7' : '0'};
`);
  const environmentProducer = join(root, 'environment-producer.mjs');
  writeFileSync(environmentProducer, `
import {spawnSync} from 'node:child_process';
const env=Object.fromEntries(Object.entries(process.env).filter(([name])=>!/^NODE_OPTIONS$/i.test(name)));
const actual=spawnSync(process.execPath,process.argv.slice(1),{env,windowsHide:true,timeout:30000});
if(actual.error||actual.signal||actual.status!==0)throw Error('actual nested genuine producer did not succeed');
process.stdout.write(actual.stdout);process.stderr.write(actual.stderr);process.exit(actual.status);
`);
  expect(git('add', '--', 'transport.mjs').status).toBe(0);
  expect(git('add', '--', 'wrong-producer.mjs').status).toBe(0);
  expect(git('add', '--', 'environment-producer.mjs').status).toBe(0);
  expect(git('-c', 'user.name=Key output fixture', '-c', 'user.email=fixture@invalid', '-c', 'commit.gpgsign=false',
    'commit', '--quiet', '-m', 'owned transport control').status).toBe(0);
  writeFileSync(child, `
import {spawnSync} from 'node:child_process';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {readFileSync,writeFileSync,appendFileSync,copyFileSync,renameSync,chmodSync,lstatSync,linkSync} from 'node:fs';
import {join} from 'node:path';
const mode=${JSON.stringify(mode)}, key=${JSON.stringify(key)}, response=${JSON.stringify(response)};
const substituted=['wrong-producer','failed-producer'].includes(mode);
const args=[...(['wrong-public-key','wrong-key-id'].includes(mode)?['--import',${JSON.stringify(pathToFileURL(transport).href)}]:[]),
 substituted?${JSON.stringify(fake)}:${JSON.stringify(binary)},'--json','keys','generate','--out',key];
function protect(path){if(process.platform==='win32'){if(spawnSync('C:/Windows/System32/icacls.exe',[path,'/inheritance:d'],{windowsHide:true}).status!==0)throw Error('owned fixture protection failed');}else chmodSync(path,0o600);}
if(mode==='existing'){writeFileSync(key,generateKeyPairSync('ed25519').privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});protect(key);}
let authorize, helperAvailable=false, authorizationRejected=false;
try { ({authorizeSecretOutput:authorize}=await import(${JSON.stringify(outputHelper)})); helperAvailable=typeof authorize==='function'; }
catch(error) { if(error.code!=='ERR_MODULE_NOT_FOUND') throw error; }
async function intent(){ if(authorize)try { await authorize({path:mode==='unbound'?key+'.other':key,command:process.execPath,args}); }catch{ authorizationRejected=true; } }
if(mode!=='missing'&&mode!=='late')await intent();
const producerEnv=Object.fromEntries(Object.entries(process.env).filter(([name])=>!/^FLUXWARDEN_|^NODE_OPTIONS$|^NODE_DEBUG$/i.test(name)||name.toUpperCase()==='FLUXWARDEN_TEST_TMP'));
if(mode==='environment-preload')producerEnv.NODE_OPTIONS='--import='+${JSON.stringify(pathToFileURL(environmentProducer).href)};
const produced=spawnSync(process.execPath,args,{env:producerEnv,encoding:'utf8',windowsHide:true,timeout:30000});
if(produced.error)throw produced.error;
writeFileSync(response,produced.stdout);
process.stdout.write(produced.stdout);process.stderr.write(produced.stderr);
if(produced.status!==0&&!['failed-producer','existing'].includes(mode))throw new Error('genuine key producer did not succeed');
const bytes=readFileSync(key);
if(${JSON.stringify(registerKey)})writeFileSync(join(process.env.FLUXWARDEN_SENTINEL_DIR,'generated-key.pem'),bytes,{mode:0o600});
if(mode==='late')await intent();
if(mode==='elsewhere')writeFileSync(join(process.env.FLUXWARDEN_EVIDENCE_DIR,'unexpected-key.log'),bytes);
if(mode==='stdout')process.stdout.write(bytes);
let identityChanged=false;
if(mode==='replaced'){const before=lstatSync(key);const next=key+'.replacement';copyFileSync(key,next);protect(next);renameSync(next,key);const after=lstatSync(key);identityChanged=before.ino!==after.ino||before.dev!==after.dev;}
if(mode==='insecure'){if(process.platform==='win32'){if(spawnSync('C:/Windows/System32/icacls.exe',[key,'/grant','*S-1-1-0:(R)'],{windowsHide:true}).status!==0)throw Error('permission control failed');}else chmodSync(key,0o644);}
if(mode==='additional-payload')appendFileSync(key,'\\nordinary additional payload\\n');
if(mode==='unrelated-source')writeFileSync(join(process.env.FLUXWARDEN_EVIDENCE_DIR,'unrelated-source.log'),readFileSync(${JSON.stringify(source)}));
let linked=false;
if(mode==='hard-linked'){linkSync(key,key+'.alias');linked=lstatSync(key).nlink>1;}
writeFileSync(${JSON.stringify(control)},JSON.stringify({helperAvailable,authorizationRejected,producerStatus:produced.status,identityChanged,linked,
 originalSha256:createHash('sha256').update(bytes).digest('hex')}));
`);
  // These nested custody operations must finish; an infrastructure deadline is
  // not an authorization rejection. Allow each its own bounded completion time.
  const invoke = (verify = false) => {
    const result = spawnSync(process.execPath, [...ownedCaptureToolArgs([captureCli, ...(verify ? ['verify'] : []),
      '--root', root, '--capture-dir', capture, ...(verify ? [] : ['--', process.execPath, child])])], {
      cwd: root, env, encoding: 'utf8', windowsHide: true, timeout: verify ? 30_000 : 60_000,
    });
    if (verify) {
      expect(result.error, 'independent verifier completes without a spawn error or deadline').toBeUndefined();
      expect(result.signal, 'a killed verifier cannot establish rejection').toBeNull();
      expect(result.status, 'verification reports an actual process exit').not.toBeNull();
    }
    return result;
  };
  return { root, capture, sourceRoot: roots[3] ?? '', key, response, control, invoke,
    receipt: () => asRecord(JSON.parse(readFileSync(join(capture, 'receipt.json'), 'utf8')) as unknown, 'safe receipt') };
}

for (const mode of ['unbound', 'existing', 'replaced', 'hard-linked', 'insecure', 'wrong-producer', 'failed-producer',
  'wrong-public-key', 'wrong-key-id', 'additional-payload', 'unrelated-source', 'stdout', 'environment-preload']) {
  it(`CP-044/SECRET-OUTPUT rejects ${mode} despite an exact key-shaped output`, async () => {
    const f = await fixture(mode), result = f.invoke();
    expect(result.error).toBeUndefined();
    const control = asRecord(JSON.parse(readFileSync(f.control, 'utf8')) as unknown, 'private producer observation');
    expect(control['producerStatus'], 'actual producer status is retained without a substituted return value').toBe(
      mode === 'failed-producer' ? 7 : mode === 'existing' ? 2 : 0);
    if (mode === 'replaced') expect(control['identityChanged'], 'same-byte replacement has a distinct physical identity').toBe(true);
    if (mode === 'hard-linked') expect(control['linked'], 'real multiple-link destination exists during Closing').toBe(true);
    expect(result.status !== null && result.status !== 0, 'typed intent cannot excuse an unbound or unsafe secret disclosure').toBe(true);
    const receipt = f.receipt();
    expect(asRecord(receipt['result'], 'result')['policySatisfied']).not.toBe(true);
    expect(records(receipt['sources']).some(row => row['sha256'] === control['originalSha256']), 'failed boundary retains original generated SOURCE membership').toBe(true);
    expect(f.invoke(true).status !== 0, 'independent verification preserves rejection').toBe(true);
  }, 120_000);
}

it('CP-044/SECRET-OUTPUT genuine prospective generated key stays SOURCE-scanned output with truthful expected-match acceptance', async () => {
  const f = await fixture('clean'), result = f.invoke();
  expect(result.error).toBeUndefined();
  expect(result.status, 'only the admitted genuine key match permits successful policy acceptance').toBe(0);
  const receipt = f.receipt(), bytes = readFileSync(f.key), key = createPrivateKey(bytes);
  expect(key.asymmetricKeyType).toBe('ed25519');
  expect(Buffer.from(key.export({ type: 'pkcs8', format: 'pem' })).equals(bytes), 'one canonical key and no extra payload').toBe(true);
  const jwk = createPublicKey(key).export({ format: 'jwk' });
  if (typeof jwk.x !== 'string') throw new Error('Ed25519 response binding unavailable');
  const raw = Buffer.from(jwk.x, 'base64url');
  const response = asRecord(asRecord(JSON.parse(readFileSync(f.response, 'utf8')) as unknown, 'producer response')['result'], 'public key response');
  expect(response['public_key']).toBe(raw.toString('base64'));
  expect(response['key_id']).toBe(sha(raw).slice(0, 32));
  if (process.platform === 'win32') assertStrictWindowsOwnerOnly(readWindowsSecurity(f.key), 'file');
  else expect(statSync(f.key).mode & 0o777).toBe(0o600);
  expect(receipt['result']).toMatchObject({ exitCode: 0, complete: true, leakFree: false, policySatisfied: true });
  expect(records(receipt['sources']).some(row => row['sha256'] === sha(bytes)), 'actual generated key remains in original recognition union').toBe(true);
  expect(records(receipt['artifacts']).filter(row => row['purpose'] === 'SECRET_OUTPUT' && row['path'] === f.key
    && row['sha256'] === sha(bytes)), 'exactly one accepted output identity remains inventoried').toHaveLength(1);
  const engine = await scanner();
  expect(engine.findLeaks({ root: f.root, sentinels: join(f.root, 'test/sentinels.json'), sentinelDir: f.sourceRoot, paths: [f.key] }),
    'unchanged original engine still detects the generated private key').not.toBeNull();
  expect(JSON.stringify(receipt).includes(bytes.toString('utf8')), 'public receipt never publishes private key bytes').toBe(false);
  expect(f.invoke(true).status, 'fresh independent recheck retains truthful policy acceptance').toBe(0);
}, 120_000);

for (const mode of ['missing', 'late', 'elsewhere']) {
  it(`CP-044/SECRET-OUTPUT rejects ${mode} authorization or an additional credential disclosure`, async () => {
    const f = await fixture(mode), result = f.invoke();
    expect(result.error).toBeUndefined();
    expect(asRecord(JSON.parse(readFileSync(f.control, 'utf8')) as unknown, 'producer control')['producerStatus'], 'real producer executed successfully').toBe(0);
    expect(result.status !== null && result.status !== 0, 'intent cannot hide an unauthorized credential output').toBe(true);
    const receipt = f.receipt();
    expect(asRecord(receipt['result'], 'result')['leakFree']).toBe(false);
    expect(asRecord(receipt['result'], 'result')['policySatisfied']).not.toBe(true);
    expect(records(receipt['sources']).some(row => row['sha256'] === sha(readFileSync(f.key))), 'failed evidence retains generated original SOURCE').toBe(true);
    expect(f.invoke(true).status !== 0, 'recheck cannot retroactively accept the failed boundary').toBe(true);
  }, 120_000);
}

it('CP-044/SECRET-OUTPUT automatic SOURCE custody accepts the genuine key without caller registration', async () => {
  const f = await fixture('clean', false), result = f.invoke();
  expect(result.error).toBeUndefined();
  expect(asRecord(JSON.parse(readFileSync(f.control, 'utf8')) as unknown, 'producer observation')['producerStatus']).toBe(0);
  expect(existsSync(join(f.sourceRoot, 'generated-key.pem')), 'caller did not register the generated private key').toBe(false);
  const receipt = f.receipt(), bytes = readFileSync(f.key), fingerprint = sha(bytes);
  expect(records(receipt['sources']).some(row => row['sha256'] === fingerprint),
    'genuine authorized output automatically joins the retained SOURCE union').toBe(true);
  const retained = join(f.capture, 'private/sources', fingerprint);
  expect(readFileSync(retained).equals(bytes), 'original generated SOURCE bytes remain available through completion').toBe(true);
  const engine = await scanner();
  expect(engine.findLeaks({ root: f.root, sentinels: join(f.root, 'test/sentinels.json'),
    sentinelDir: join(f.capture, 'private/sources'), paths: [f.key] }),
  'unchanged engine detects the key using only the actually retained SOURCE population').not.toBeNull();
  expect(records(receipt['artifacts']).filter(row => row['path'] === f.key && row['purpose'] === 'SECRET_OUTPUT'
    && row['sha256'] === fingerprint), 'generated key stays exactly one inventoried SECRET_OUTPUT').toHaveLength(1);
  expect(result.status, 'automatic recognition permits only the prospective own-key match').toBe(0);
  expect(receipt['result']).toMatchObject({ exitCode: 0, complete: true, leakFree: false, policySatisfied: true });
  expect(f.invoke(true).status, 'independent verification retains automatic SOURCE custody and acceptance').toBe(0);
}, 120_000);

for (const mode of ['elsewhere', 'stdout']) {
  it(`CP-044/SECRET-OUTPUT automatic SOURCE custody rejects ${mode} disclosure without caller registration`, async () => {
    const f = await fixture(mode, false), result = f.invoke();
    expect(result.error).toBeUndefined();
    expect(asRecord(JSON.parse(readFileSync(f.control, 'utf8')) as unknown, 'producer observation')['producerStatus']).toBe(0);
    expect(existsSync(join(f.sourceRoot, 'generated-key.pem')), 'caller did not register the generated private key').toBe(false);
    expect(result.status !== null && result.status !== 0,
      'automatic SOURCE recognition rejects the generated key outside its authorized destination').toBe(true);
    const receipt = f.receipt(), bytes = readFileSync(f.key), fingerprint = sha(bytes);
    expect(records(receipt['sources']).some(row => row['sha256'] === fingerprint),
      'rejected disclosure retains the automatically registered original key').toBe(true);
    expect(readFileSync(join(f.capture, 'private/sources', fingerprint)).equals(bytes)).toBe(true);
    expect(records(receipt['artifacts']).filter(row => row['path'] === f.key && row['purpose'] === 'SECRET_OUTPUT'
      && row['sha256'] === fingerprint), 'own key retains OUTPUT purpose despite the additional leak').toHaveLength(1);
    expect(asRecord(receipt['result'], 'result')).toMatchObject({ leakFree: false, policySatisfied: false });
    expect(f.invoke(true).status !== 0, 'independent verification preserves the additional-disclosure rejection').toBe(true);
  }, 120_000);
}

for (const mode of ['missing', 'late']) {
  it(`CP-044/SECRET-OUTPUT rejects ${mode} authorization without caller SOURCE registration`, async () => {
    const f = await fixture(mode, false), result = f.invoke();
    expect(result.error).toBeUndefined();
    expect(asRecord(JSON.parse(readFileSync(f.control, 'utf8')) as unknown, 'producer observation')['producerStatus'],
      'the actual canonical key producer succeeded').toBe(0);
    expect(existsSync(join(f.sourceRoot, 'generated-key.pem')), 'caller did not register the generated private key').toBe(false);
    expect(result.status !== null && result.status !== 0,
      'genuine key generation still requires exact prospective authorization').toBe(true);
    expect(asRecord(f.receipt()['result'], 'result')['policySatisfied']).not.toBe(true);
    expect(f.invoke(true).status !== 0, 'independent verification cannot accept missing or late authorization').toBe(true);
  }, 120_000);
}
