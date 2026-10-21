import fs from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createPrivateDirectory, assertPrivateDirectories } from './private-scratch.mjs';
import { findLeaks, sentinelRedactor } from './leak-check.mjs';
import { variables, hash, inside, files, directories, registered, equivalents, retain, anchor, ancestry, binding, namespace } from './ci-capture-files.mjs';

const script = fileURLToPath(import.meta.url);
const write = (path, value) => fs.writeFileSync(path, JSON.stringify(value), { mode: 0o600, flag: 'wx' });
const read = path => JSON.parse(fs.readFileSync(path, 'utf8'));
const digest = path => hash(fs.readFileSync(path));
function git(root, args, env = process.env, input) {
  const result = spawnSync('git', ['-C', root, ...args], { env, input, encoding: 'utf8', windowsHide: true });
  if (result.status !== 0) throw new Error('capture checkout identity failed');
  return result.stdout.trim();
}
function identity(root, capture) {
  const index = join(capture, 'private', 'checkout.index');
  const env = { ...process.env, GIT_INDEX_FILE: index };
  try {
    git(root, ['read-tree', 'HEAD'], env);
    git(root, ['add', '-A', '--', '.'], env);
    const sourcePaths = git(root, ['ls-files', '--cached', '--others', '--exclude-standard', '-z']).split('\0').filter(Boolean).map(path => resolve(root, path));
    const sourceBindings = sourcePaths.sort().map(path => ({ file: binding(path), parents: ancestry(dirname(path)) }));
    return { commit: git(root, ['rev-parse', 'HEAD']), tree: git(root, ['write-tree'], env), readSetSha256: hash(JSON.stringify(sourceBindings)), rootIdentitySha256: hash(JSON.stringify(ancestry(root))) };
  } finally { fs.rmSync(index, { force: true }); }
}
function inventory(paths) {
  return [...new Set(paths.flatMap(files))].sort().map(path => ({ ...binding(path), parents: ancestry(dirname(path)) }));
}
function same(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
function records(capture, config) {
  return files(join(capture, 'private', 'records')).map(path => {
    const row = read(path);
    if (!same(Object.keys(row), ['path', 'sha256', 'purpose']) || typeof row.path !== 'string' || resolve(row.path) !== row.path || !/^[0-9a-f]{64}$/.test(row.sha256) || !['INPUT', 'EGRESS'].includes(row.purpose) ||
        path !== join(capture, 'private', 'records', hash(JSON.stringify(row)) + '.json') ||
        row.purpose === 'INPUT' && !config.registered.includes(row.path) && !inside(config.sentinelDir, row.path)) throw new Error('capture invalid original context');
    return row;
  }).sort((a, b) => a.path.localeCompare(b.path) || a.sha256.localeCompare(b.sha256));
}
function retainedSourceIdentities(capture) {
  for (const path of files(join(capture, 'private', 'identities'))) for (const line of fs.readFileSync(path, 'utf8').trim().split('\n')) {
    const observed = JSON.parse(line);
    if (!same(observed.storage, anchor(join(capture, 'private', 'bytes', observed.sha256)))) throw new Error('capture private source replaced');
  }
}
function metadataPaths(capture) {
  return ['config.json', 'sentinels.json', 'records', 'identities', 'authorizations'].flatMap(name => files(join(capture, 'private', name))).concat(['custody.json', 'receipt.json', 'receipt.sha256'].map(name => join(capture, name)));
}
function captureEgress(capture, retained) {
  const metadata = new Set(metadataPaths(capture));
  const typedCopies = new Map();
  for (const row of retained) {
    typedCopies.set(join(capture, 'private', 'bytes', row.sha256), row.sha256);
    if (row.purpose === 'INPUT') typedCopies.set(join(capture, 'private', 'sources', row.sha256), row.sha256);
  }
  return files(capture).filter(path => {
    if (typedCopies.has(path)) {
      if (digest(path) !== typedCopies.get(path)) throw new Error('capture typed copy changed');
      return false;
    }
    // Metadata is separately scanned after Closing. Every other retained file,
    // including unknown files inside private directories, keeps EGRESS purpose.
    return !metadata.has(path);
  });
}
function declarationSet(testTmp) {
  const path = join(testTmp, 'declared-out.txt');
  const result = new Set();
  if (fs.existsSync(path)) for (const line of fs.readFileSync(path, 'utf8').split(/\r?\n/)) {
    const entry = line.trim();
    if (entry) result.add(/^sha256:[0-9a-f]{64}$/.test(entry) ? entry : resolve(testTmp, entry));
  }
  return result;
}
function authorizedDeclaration(capture, config, declared, path) {
  if (path === join(config.testTmp, 'declared-out.txt') || inside(config.evidenceDir, path)) return false;
  const key = hash(path);
  const has = entries => entries.has(path) || entries.has('sha256:' + key);
  if (!has(declared)) return false;
  if (has(new Set(config.initialDeclarations))) return true;
  const ledger = join(capture, 'private', 'authorizations', key + '.json');
  if (!fs.existsSync(ledger)) return false;
  const observed = read(ledger);
  return observed.pathSha256 === key && observed.purpose === 'INPUT' && /^[0-9a-f]{64}$/.test(observed.declarationSha256);
}
function scan(capture, config, retained) {
  const options = { root: config.root, sentinels: join(capture, 'private', 'sentinels.json'), sentinelDir: join(capture, 'private', 'sources') };
  // Keep the scanner's exact declaration and evidence-priority semantics on the
  // original paths. Private byte copies provide custody, never source credit.
  const paths = [...new Set([...retained.filter(record => record.purpose !== 'INPUT').map(record => record.path), ...captureEgress(capture, retained)])];
  if (findLeaks({ ...options, paths, testTmp: config.testTmp, evidenceDir: config.evidenceDir })) return false;
  const declared = declarationSet(config.testTmp);
  const unproven = paths.filter(path => (declared.has(path) || declared.has('sha256:' + hash(path))) && !authorizedDeclaration(capture, config, declared, path));
  // The unchanged engine gets every unproved declaration target as EGRESS too;
  // a later append cannot retroactively suppress bytes already written there.
  if (unproven.length && findLeaks({ ...options, paths: unproven })) return false;
  const roots = [...config.roots, ...config.outputs.filter(path => fs.existsSync(path)), capture];
  const names = new Set([...retained.map(record => record.path), ...roots.flatMap(directories), ...roots.flatMap(path => ancestry(dirname(path)).map(row => row.path))]);
  for (const path of names) {
    if (authorizedDeclaration(capture, config, declared, path)) continue;
    // Includes empty directories and all ancestor names; a directory's location
    // in an INPUT registry alone never grants its namespace source purpose.
    if (findLeaks({ ...options, commandOutput: path })) return false;
  }
  return true;
}
function custody(capture, config) {
  const metadata = ['receipt.json', 'receipt.sha256', 'custody.json'].map(name => join(capture, name));
  const paths = [...config.roots, ...config.outputs.filter(path => fs.existsSync(path)), ...registered(config.root), join(config.root, 'test/sentinels.json'), capture];
  return { parents: [...config.roots, ...config.outputs.filter(path => fs.existsSync(path)), capture, config.root].map(path => ancestry(dirname(path))), namespace: namespace(paths, new Set(metadata)) };
}
async function verify(root, capture) {
  await assertPrivateDirectories([capture]);
  const receipt = read(join(capture, 'receipt.json'));
  const config = read(join(capture, 'private', 'config.json'));
  if (config.root !== root || config.capture !== capture) throw new Error('capture context changed');
  await assertPrivateDirectories(config.roots);
  const seal = read(join(capture, 'receipt.sha256'));
  if (digest(join(capture, 'receipt.json')) !== seal.receiptSha256 || !same(seal.metadata, ['receipt.json', 'receipt.sha256', 'custody.json'].map(name => ({ name, ...anchor(join(capture, name)) })))) throw new Error('capture receipt changed');
  if (!same(identity(root, capture), receipt.identity.after)) throw new Error('capture checkout changed');
  const expected = read(join(capture, 'custody.json'));
  if (digest(join(capture, 'custody.json')) !== receipt.custodySha256) throw new Error('capture custody record changed');
  if (!same(custody(capture, config), expected)) throw new Error('capture custody changed');
  retainedSourceIdentities(capture);
  if (!receipt.result.complete || !receipt.result.leakFree || !scan(capture, config, records(capture, config)) || findLeaks({ root, sentinels: join(capture, 'private', 'sentinels.json'), sentinelDir: join(capture, 'private', 'sources'), paths: metadataPaths(capture) })) return 1;
  return 0;
}
async function captureCommand(root, capture, command) {
  if (!fs.existsSync(capture)) {
    const created = await createPrivateDirectory(dirname(capture), 'capture-');
    fs.renameSync(created, capture);
  }
  await assertPrivateDirectories([capture]);
  if (fs.readdirSync(capture).length) throw new Error('capture directory must be empty');
  if (command[0] === 'node') command[0] = process.execPath;
  if (command[0] === 'npm') {
    const candidates = [join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js'), resolve(dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js')];
    const npm = candidates.find(path => fs.existsSync(path));
    if (!npm) throw new Error('capture npm driver unavailable');
    command = [process.execPath, npm, ...command.slice(1)];
  }
  if (!command.length || resolve(command[0]) !== resolve(process.execPath)) throw new Error('capture requires an owned Node driver');
  const privateDir = await createPrivateDirectory(capture, 'private-');
  fs.renameSync(privateDir, join(capture, 'private'));
  for (const name of ['bytes', 'records', 'sources', 'identities', 'authorizations']) fs.mkdirSync(join(capture, 'private', name), { mode: 0o700 });
  for (const name of ['receipt.json', 'receipt.sha256', 'custody.json']) fs.writeFileSync(join(capture, name), '', { flag: 'wx', mode: 0o600 });
  const env = { ...process.env };
  for (const name of variables) {
    if (!env[name]) env[name] = await createPrivateDirectory(capture, name.toLowerCase() + '-');
  }
  const roots = [...new Set(variables.map(name => resolve(env[name])))];
  await assertPrivateDirectories(roots);
  if (roots.some(path => inside(path, capture))) throw new Error('capture root overlaps owned roots');
  const sourcePaths = registered(root);
  const outputs = ['dist', 'reports', 'coverage', 'chaos-evidence'].map(name => join(root, name));
  const anchoredRoots = [...roots, capture, join(capture, 'private'), ...['bytes', 'records', 'sources', 'identities', 'authorizations'].map(name => join(capture, 'private', name))];
  const rootIdentities = anchoredRoots.map(path => ({ path, parents: ancestry(path) }));
  const config = { root, capture, roots, outputs, rootIdentities, initialDeclarations: [...declarationSet(resolve(env.FLUXWARDEN_TEST_TMP))], registered: sourcePaths, sentinelDir: resolve(env.FLUXWARDEN_SENTINEL_DIR), testTmp: resolve(env.FLUXWARDEN_TEST_TMP), evidenceDir: resolve(env.FLUXWARDEN_EVIDENCE_DIR) };
  write(join(capture, 'private', 'config.json'), config);
  write(join(capture, 'private', 'sentinels.json'), []);
  const before = identity(root, capture);
  const initialSources = inventory([...sourcePaths, config.sentinelDir]);
  for (const row of initialSources) retain(capture, row.path, 'INPUT');
  const stdout = fs.openSync(join(capture, 'stdout.log'), 'wx', 0o600);
  const stderr = fs.openSync(join(capture, 'stderr.log'), 'wx', 0o600);
  let exitCode, complete = true;
  try {
    const child = spawn(command[0], ['--import', pathToFileURL(join(dirname(script), 'ci-capture-preload.mjs')).href, ...command.slice(1)], {
      cwd: root, env: { ...env, FLUXWARDEN_CI_CAPTURE: capture }, stdio: ['ignore', stdout, stderr], windowsHide: true,
    });
    exitCode = await new Promise(resolveExit => {
      child.once('error', () => { complete = false; resolveExit(1); });
      child.once('close', code => resolveExit(code ?? 1));
    });
  } finally { fs.closeSync(stdout); fs.closeSync(stderr); }
  let after = before;
  try {
    after = identity(root, capture);
    if (!same(before, after)) complete = false;
    if (!same(config.rootIdentities, anchoredRoots.map(path => ({ path, parents: ancestry(path) })))) complete = false;
    if (!same(initialSources, inventory(initialSources.map(row => row.path)))) complete = false;
    if (!same(sourcePaths, registered(root))) complete = false;
    for (const path of files(config.sentinelDir)) retain(capture, path, 'INPUT');
    for (const path of [...roots.flatMap(files), ...outputs.filter(path => fs.existsSync(path)).flatMap(files), join(capture, 'stdout.log'), join(capture, 'stderr.log')]) {
      if (!inside(config.sentinelDir, path)) retain(capture, path, 'EGRESS');
    }
    for (const path of captureEgress(capture, records(capture, config))) retain(capture, path, 'EGRESS');
    if (fs.existsSync(join(capture, 'private', 'incomplete'))) complete = false;
    retainedSourceIdentities(capture);
  } catch { complete = false; }
  const retained = records(capture, config);
  for (const record of retained.filter(row => row.purpose === 'INPUT')) {
    const source = fs.readFileSync(join(capture, 'private', 'bytes', record.sha256));
    const destination = join(capture, 'private', 'sources', record.sha256);
    if (!fs.existsSync(destination)) fs.writeFileSync(destination, source, { mode: 0o600, flag: 'wx' });
  }
  let leakFree = false;
  try { leakFree = scan(capture, config, retained); } catch { complete = false; }
  const redact = sentinelRedactor({ root, sentinels: join(capture, 'private', 'sentinels.json'), sentinelDir: join(capture, 'private', 'sources') });
  const context = row => ({ path: redact(row.path), ...(redact(row.path) !== row.path ? { pathSha256: hash(row.path) } : {}), sha256: row.sha256 });
  const declared = declarationSet(config.testTmp);
  const sources = retained.filter(row => row.purpose === 'INPUT').flatMap(row => equivalents(fs.readFileSync(join(capture, 'private', 'bytes', row.sha256))).map(bytes => ({ ...context(row), sha256: hash(bytes), purpose: 'INPUT' })));
  const artifacts = retained.filter(row => row.purpose !== 'INPUT').map(row => ({ ...context(row), purpose: row.path === join(config.testTmp, 'declared-out.txt') ? 'DECLARATION' : authorizedDeclaration(capture, config, declared, row.path) ? 'INPUT' : 'EGRESS' }));
  let census;
  try { census = custody(capture, config); }
  catch { complete = false; census = []; }
  fs.writeFileSync(join(capture, 'custody.json'), JSON.stringify(census), { mode: 0o600 });
  const receipt = { scope: 'observed retained closing artifacts, full command streams and registered source lifetime; no universal temporary-file history claim', boundarySha256: '42784be10c0f54af383eb8005f0195db59f371081d504c9971fbb78dff6f9489', identity: { before, after }, result: { exitCode, complete, leakFree }, sources, artifacts, custodySha256: digest(join(capture, 'custody.json')) };
  fs.writeFileSync(join(capture, 'receipt.json'), JSON.stringify(receipt), { mode: 0o600 });
  const metadata = ['receipt.json', 'receipt.sha256', 'custody.json'].map(name => ({ name, ...anchor(join(capture, name)) }));
  fs.writeFileSync(join(capture, 'receipt.sha256'), JSON.stringify({ receiptSha256: digest(join(capture, 'receipt.json')), metadata }), { mode: 0o600 });
  try {
    if (findLeaks({ root, sentinels: join(capture, 'private', 'sentinels.json'), sentinelDir: join(capture, 'private', 'sources'), paths: metadataPaths(capture) })) leakFree = false;
  } catch { complete = false; }
  receipt.result = { exitCode, complete, leakFree };
  fs.writeFileSync(join(capture, 'receipt.json'), JSON.stringify(receipt), { mode: 0o600 });
  fs.writeFileSync(join(capture, 'receipt.sha256'), JSON.stringify({ receiptSha256: digest(join(capture, 'receipt.json')), metadata }), { mode: 0o600 });
  return exitCode || (complete && leakFree ? 0 : 1);
}
async function main(args) {
  const verification = args[0] === 'verify';
  if (verification) args = args.slice(1);
  if (args[0] !== '--root' || !args[1] || args[2] !== '--capture-dir' || !args[3] || (verification ? args.length !== 4 : args[4] !== '--')) return 2;
  const root = resolve(args[1]), capture = resolve(args[3]);
  return verification ? verify(root, capture) : captureCommand(root, capture, args.slice(5));
}
if (process.argv[1] && resolve(process.argv[1]) === script) {
  try { process.exitCode = await main(process.argv.slice(2)); }
  catch { process.stderr.write('ci-capture failed\n'); process.exitCode = 1; }
}
