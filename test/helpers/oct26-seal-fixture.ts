// A real unchanged capture over a small committed synthetic producer. Reports
// and native-observation-shaped files are UNIT INPUTS, never lab/CI PASS proof.
// The separate public-chaos regression executes real failed Vitest assertions.
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { copyFileSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect } from 'vitest';
import { asRecord, childEnv, repoRoot, scratchDir } from './cli.js';
import { declareFixtureCapture, declareFixturePaths, ownedCaptureToolArgs } from './capture-fixture.js';

export const REQUIRED_ROWS = ['T-01', 'T-03', 'T-05', 'T-06', 'T-07', 'T-16', 'T-18', 'T-25'];
export interface SealFixture {
  source: string; capture: string; evidence: string; output: string; tarball: string;
  sourceCommit: string; exitCode: number; env: NodeJS.ProcessEnv; originalReport: Buffer; seed: Buffer; leakPath: string;
  plantObserved?: boolean;
}

export function capturedSealFixture(exitCode: 0 | 7, extraObservations: Record<string, unknown> = {}, prepareSource?: (source: string) => void,
  beforeCapture?: (fixture: Pick<SealFixture, 'source' | 'env' | 'sourceCommit'>) => void): SealFixture {
  const root = scratchDir('seal-contract'), source = join(root, 'source');
  const capture = join(root, 'capture'), evidence = join(root, 'evidence'), output = join(root, 'bounded');
  const sentinels = join(root, 'sentinels'), tests = join(root, 'tests'), temp = join(root, 'temp'), tmp = join(root, 'tmp'), packages = join(root, 'packages');
  for (const path of [source, capture, evidence, output, sentinels, tests, temp, tmp, packages]) mkdirSync(path, { mode: 0o700 });
  for (const path of ['scripts', 'test/sentinels', 'test/chaos', 'src/cli', 'dist/cli', 'dist/evidence']) mkdirSync(join(source, path), { recursive: true, mode: 0o700 });
  for (const entry of readdirSync(join(repoRoot, 'scripts'), { withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith('.mjs')) copyFileSync(join(repoRoot, 'scripts', entry.name), join(source, 'scripts', entry.name));
  }
  const seed = randomBytes(32), seedPath = join(source, 'test/sentinels/source.bin'), registry = join(sentinels, 'source.bin'), leakPath = join(output, 'planted-leak.json');
  declareFixturePaths([seedPath, registry]);
  declareFixtureCapture(capture, [seed], [{ path: leakPath, bytes: seed }]);
  writeFileSync(seedPath, seed, { mode: 0o600 }); writeFileSync(registry, seed, { mode: 0o600 });
  writeFileSync(join(source, 'test/sentinels.json'), JSON.stringify(['test/sentinels/source.bin']));
  writeFileSync(join(source, '.gitignore'), 'dist/\nnode_modules/\n*.tgz\n');
  writeFileSync(join(source, 'package.json'), JSON.stringify({ name: 'fluxwarden', version: '1.0.0', type: 'module', bin: { fluxwarden: 'dist/cli/bin.js' },
    files: ['dist', 'README.md', 'LICENSE', 'SECURITY.md', 'CHANGELOG.md', 'NOTICE-SOURCE-REUSE.md'] }));
  writeFileSync(join(source, 'package-lock.json'), JSON.stringify({ name: 'fluxwarden', version: '1.0.0', lockfileVersion: 3,
    packages: { '': { name: 'fluxwarden', version: '1.0.0' } } }));
  for (const name of ['README.md', 'LICENSE', 'SECURITY.md', 'CHANGELOG.md', 'NOTICE-SOURCE-REUSE.md']) copyFileSync(join(repoRoot, name), join(source, name));
  writeFileSync(join(source, 'src/cli/bin.ts'), 'export {};\n');
  writeFileSync(join(source, 'dist/cli/bin.js'), 'export {};\n');
  writeFileSync(join(source, 'test/chaos/contract.live.test.ts'), '// Synthetic format controls only; no node reference execution.\n');
  writeFileSync(join(source, 'produce.mjs'), `import {writeFileSync} from 'node:fs';import {join} from 'node:path';
const ids=${JSON.stringify(REQUIRED_ROWS)},failed=Number(process.env.CONTROL_EXIT)!==0;
const assertionResults=ids.map((id,index)=>({ancestorTitles:[],title:'CP-044/SEAL synthetic '+id+' contract input',fullName:'CP-044/SEAL synthetic '+id+' contract input',status:failed&&index===ids.length-1?'failed':'passed'}));
const report={success:!failed,numTotalTests:ids.length,numPassedTests:ids.length-(failed?1:0),numFailedTests:failed?1:0,numPendingTests:0,numTodoTests:0,
testResults:[{name:join(process.cwd(),'test/chaos/contract.live.test.ts'),status:failed?'failed':'passed',assertionResults}]};
writeFileSync(join(process.env.FLUXWARDEN_EVIDENCE_DIR,'vitest-chaos.json'),JSON.stringify(report)+'\\n');
for(const id of ids.filter(id=>id!=='T-18'))writeFileSync(join(process.env.FLUXWARDEN_EVIDENCE_DIR,id.toLowerCase().replace('-','')+'-contract-observation.json'),JSON.stringify({syntheticUnitFixture:true,observation:'nonempty format control; no native result claimed'}));
for(const variant of ['LAST_HOP_RECEIVABLE','FIRST_HOP_SPENDABLE'])writeFileSync(join(process.env.FLUXWARDEN_EVIDENCE_DIR,'t18-'+variant.toLowerCase()+'.json'),JSON.stringify({scenario:'T-18',variant,status:'PASS',sourceCommit:process.env.GITHUB_SHA,ownerId:'synthetic-seal-owner',syntheticUnitFixture:true,
facts:{principalMsat:'100000000',observedAvailableMsat:'60000000',refusalCode:variant,exitCode:5,nodePaymentsBefore:0,nodePaymentsAfter:0}}));
for(const [name,observation] of Object.entries(${JSON.stringify(extraObservations)}))writeFileSync(join(process.env.FLUXWARDEN_EVIDENCE_DIR,name),JSON.stringify(observation));
process.exitCode=Number(process.env.CONTROL_EXIT);
`);
  writeFileSync(join(source, 'seal-driver.mjs'), `import {sealReport} from './scripts/release-ci.mjs';
await sealReport({listJobs:()=>Promise.resolve([{id:4242,name:'live/chaos',head_sha:process.env.GITHUB_SHA,run_id:Number(process.env.GITHUB_RUN_ID)}])},'live/chaos');
`);
  // Inject only the output transport, after the real report is materialized.
  // Clearing an old output directory cannot accidentally satisfy this control.
  writeFileSync(join(source, 'seal-output-transport.mjs'), `import fs from 'node:fs';import fsp from 'node:fs/promises';import {join,resolve} from 'node:path';import {syncBuiltinESMExports} from 'node:module';
const write=fs.writeFileSync,copy=fs.copyFileSync,asyncWrite=fsp.writeFile,asyncCopy=fsp.copyFile;let planted=false;
function plant(path){if(planted||resolve(String(path))!==join(process.env.FLUXWARDEN_RELEASE_OUTPUT,'report.json'))return;planted=true;
write(join(process.env.FLUXWARDEN_RELEASE_OUTPUT,'planted-leak.json'),JSON.stringify({value:fs.readFileSync(process.env.CONTROL_SEAL_SOURCE).toString('hex')}));process.stdout.write('fixture-output-plant\\n');}
fs.writeFileSync=function(path,...args){const result=write.call(this,path,...args);plant(path);return result;};
fs.copyFileSync=function(from,to,...args){const result=copy.call(this,from,to,...args);plant(to);return result;};
fsp.writeFile=async function(path,...args){const result=await asyncWrite.call(this,path,...args);plant(path);return result;};
fsp.copyFile=async function(from,to,...args){const result=await asyncCopy.call(this,from,to,...args);plant(to);return result;};syncBuiltinESMExports();
`);
  // Public aggregate fixtures may need a real independently collectable source.
  // Materialize it before the immutable Git identity, package and capture.
  prepareSource?.(source);
  const env: NodeJS.ProcessEnv = { ...childEnv(), TEMP: temp, TMP: tmp, FLUXWARDEN_TEST_TMP: tests,
    FLUXWARDEN_SENTINEL_DIR: sentinels, FLUXWARDEN_EVIDENCE_DIR: evidence, FLUXWARDEN_CI_CAPTURE_DIR: capture,
    FLUXWARDEN_RELEASE_OUTPUT: output, CONTROL_EXIT: String(exitCode), GITHUB_RUN_ID: '777', GITHUB_RUN_ATTEMPT: '1', NPM_CONFIG_OFFLINE: 'true',
    NPM_CONFIG_CACHE: join(temp, 'npm-cache'), NPM_CONFIG_LOGS_DIR: join(evidence, 'npm-logs'), NPM_CONFIG_UPDATE_NOTIFIER: 'false',
    NPM_CONFIG_USERCONFIG: join(temp, 'npm-user.npmrc'), NPM_CONFIG_GLOBALCONFIG: join(temp, 'npm-global.npmrc') };
  writeFileSync(env['NPM_CONFIG_USERCONFIG'] ?? '', '', { mode: 0o600 }); writeFileSync(env['NPM_CONFIG_GLOBALCONFIG'] ?? '', '', { mode: 0o600 });
  const git = (args: string[]) => spawnSync('git', args, { cwd: source, env, windowsHide: true, encoding: 'utf8', timeout: 10_000 });
  for (const args of [['init', '--quiet'], ['add', '--', '.'], ['-c', 'user.name=Seal contract fixture', '-c', 'user.email=fixture@invalid', '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'synthetic seal source']]) {
    expect(git(args).status, 'fixture source has an actual immutable Git identity').toBe(0);
  }
  const sourceCommit = git(['rev-parse', 'HEAD']).stdout.trim();
  expect(sourceCommit).toMatch(/^[a-f0-9]{40}$/); env['GITHUB_SHA'] = sourceCommit;
  writeFileSync(join(source, 'dist/evidence/build-info.json'), JSON.stringify({ gitCommit: sourceCommit }));
  const plan = join(root, 'owner-plan.json'); env['FLUXWARDEN_LAB_PLAN'] = plan;
  writeFileSync(plan, JSON.stringify({ sourceCommit, exclusive: true, network: 'regtest', ownerId: 'synthetic-seal-owner', owner: { evidenceRoot: evidence } }));
  const npm = process.env['npm_execpath'] ?? join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js');
  const packed = spawnSync(process.execPath, [npm, 'pack', '--offline', '--ignore-scripts', '--json', '--pack-destination', packages], {
    cwd: source, env, windowsHide: true, encoding: 'utf8', timeout: 10_000,
  });
  expect(packed.error).toBeUndefined(); expect(packed.status, 'actual synthetic package pack completes').toBe(0);
  const tarball = join(packages, 'fluxwarden-1.0.0.tgz'); env['FLUXWARDEN_FINAL_TARBALL'] = tarball;
  // Inventory collection is a fixture producer too. Complete it before the
  // capture closes TEMP and retains every file in that independently scanned scope.
  beforeCapture?.({ source, env, sourceCommit });
  const captured = spawnSync(process.execPath, [...ownedCaptureToolArgs([join(source, 'scripts/ci-capture.mjs'), '--root', source, '--capture-dir', capture, '--',
    'node', 'scripts/ci-job.mjs', '--commands-only', '--', 'node', 'produce.mjs', '--next', 'node', 'scripts/no-pending.mjs', join(evidence, 'vitest-chaos.json'),
    '--finally', 'node', 'scripts/leak-check.mjs', '--sentinels', 'test/sentinels.json', '--sentinel-dir', sentinels, evidence])], {
    cwd: source, env, windowsHide: true, timeout: 30_000,
  });
  expect(captured.error).toBeUndefined(); expect(captured.signal).toBeNull(); expect(captured.status, 'real captured command preserves the actual producer exit').toBe(exitCode);
  const receipt = asRecord(JSON.parse(readFileSync(join(capture, 'receipt.json'), 'utf8')), 'original receipt');
  expect(asRecord(receipt['result'], 'original result')['exitCode']).toBe(exitCode);
  expect(asRecord(receipt['result'], 'original result')['complete']).toBe(true);
  const verified = spawnSync(process.execPath, [...ownedCaptureToolArgs([join(source, 'scripts/ci-capture.mjs'), 'verify', '--root', source, '--capture-dir', capture])], {
    cwd: source, env, windowsHide: true, timeout: 30_000,
  });
  expect(verified.error).toBeUndefined(); expect(verified.status, 'independent unchanged verifier accepts truthful completed capture even on a failed command').toBe(0);
  return { source, capture, evidence, output, tarball, sourceCommit, exitCode, env, originalReport: readFileSync(join(evidence, 'vitest-chaos.json')), seed, leakPath };
}

export function runPublicSeal(fixture: SealFixture, injectLeak = false): number | null {
  const result = spawnSync(process.execPath, [...ownedCaptureToolArgs([
    ...(injectLeak ? ['--import', pathToFileURL(join(fixture.source, 'seal-output-transport.mjs')).href] : []),
    join(fixture.source, 'seal-driver.mjs')])], {
    cwd: fixture.source, env: { ...fixture.env, CONTROL_SEAL_SOURCE: join(fixture.source, 'test/sentinels/source.bin') }, windowsHide: true, timeout: 30_000,
  });
  expect(result.error).toBeUndefined(); expect(result.signal).toBeNull();
  fixture.plantObserved = result.stdout.includes(Buffer.from('fixture-output-plant\n'));
  return result.status;
}

export async function loadPublicSeal(): Promise<void> {
  // Ordinary API loading before mutation cases prevents an absent API from
  // accidentally counting as a successful integrity/leak refusal control.
  await import(pathToFileURL(join(repoRoot, 'scripts/release-ci.mjs')).href);
}
