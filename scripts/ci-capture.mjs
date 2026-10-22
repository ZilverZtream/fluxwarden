import fs from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { resolve, join, dirname, relative, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createPrivateDirectory, assertPrivateDirectories } from './private-scratch.mjs';
import { findLeaks, sentinelRedactor } from './leak-check.mjs';
import { variables, hash, inside, files, directories, registered, equivalents, retain, anchor, ancestry, binding, namespace } from './ci-capture-files.mjs';
import { secretOutputs, unexpectedSecretMatches } from './ci-secret-output.mjs';

const script = fileURLToPath(import.meta.url);
const write = (path, value) => fs.writeFileSync(path, JSON.stringify(value), { mode: 0o600, flag: 'wx' });
const read = path => JSON.parse(fs.readFileSync(path, 'utf8'));
const digest = path => hash(fs.readFileSync(path));
const secretContext = (row, redact) => ({ path: redact(row.path), ...(redact(row.path) !== row.path ? { pathSha256: hash(row.path) } : {}), sha256: row.sha256, keyId: row.keyId, authorizationSha256: row.authorizationSha256 });
let diagnosticContext;
const diagnosticClasses = new Set(['Error', 'TypeError', 'RangeError', 'SyntaxError']);
const diagnosticCodes = new Set(['ENOENT', 'EACCES', 'EPERM', 'EEXIST', 'ENOTDIR', 'EISDIR', 'ENAMETOOLONG', 'ELOOP', 'ENOSPC', 'EIO', 'ENOBUFS', 'ENOMEM', 'ETIMEDOUT', 'ERR_ASSERTION', 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER']);
const diagnosticInteger = value => Number.isSafeInteger(value) && value >= 0;
const diagnosticLocation = value => diagnosticInteger(value) && value > 0 && value <= 10_000_000;
function diagnosticFrame(text, file, root) {
  if (typeof text !== 'string' || text.length > 1_048_576) return undefined;
  const absolute = resolve(root, file);
  for (const name of [absolute, absolute.split(sep).join('/'), pathToFileURL(absolute).href, file]) {
    const at = text.indexOf(name + ':');
    if (at < 0) continue;
    const match = /^(\d{1,7})(?::(\d{1,7}))?(?!\d)/.exec(text.slice(at + name.length + 1));
    if (match && diagnosticLocation(Number(match[1]))) return { file, line: Number(match[1]), column: diagnosticLocation(Number(match[2])) ? Number(match[2]) : null };
  }
}
function diagnosticError(error) {
  try {
    const frame = diagnosticFrame(error?.stack, 'scripts/ci-capture.mjs', dirname(dirname(script)));
    return { name: diagnosticClasses.has(error?.name) ? error.name : 'UNKNOWN', code: diagnosticCodes.has(error?.code) ? error.code : null,
      messageSha256: hash(typeof error?.message === 'string' ? error.message : typeof error === 'string' ? error : ''),
      pathSha256: typeof error?.path === 'string' ? hash(error.path) : null,
      frame: frame ?? null };
  } catch { return { name: 'UNKNOWN', code: null, messageSha256: hash(''), pathSha256: null, frame: null }; }
}
function diagnosticReport(kind) {
  const context = diagnosticContext;
  const reportName = 'vitest-' + kind + '.json';
  let reportSha256 = null;
  const unavailable = status => ({ report: reportName, status, sha256: reportSha256, failures: [] });
  if (typeof context?.evidenceDir !== 'string' || !context.tests) return unavailable('UNREADABLE');
  const path = join(context.evidenceDir, reportName);
  let fd;
  try {
    // Reports are untrusted data. Bound the read even if the file grows, and
    // refuse links or a redirected evidence directory before reading bytes.
    const canonical = value => process.platform === 'win32' ? value.toLowerCase() : value;
    if (canonical(fs.realpathSync.native(path)) !== canonical(resolve(path))) return unavailable('UNREADABLE');
    const before = fs.lstatSync(path);
    if (!before.isFile() || before.isSymbolicLink()) return unavailable('UNREADABLE');
    if (before.size > 16_777_216) return unavailable('OVERSIZE');
    fd = fs.openSync(path, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const opened = fs.fstatSync(fd);
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) return unavailable('UNREADABLE');
    const bytes = Buffer.alloc(before.size + 1);
    let length = 0, count;
    while (length < bytes.length && (count = fs.readSync(fd, bytes, length, bytes.length - length, null))) length += count;
    const after = fs.fstatSync(fd);
    if (length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) return unavailable('UNREADABLE');
    reportSha256 = hash(bytes.subarray(0, length));
    const report = JSON.parse(bytes.subarray(0, length).toString('utf8'));
    const totals = {};
    for (const key of ['numPassedTests', 'numFailedTests', 'numPendingTests']) {
      if (!diagnosticInteger(report?.[key])) return unavailable('INVALID');
      totals[key] = report[key];
    }
    if (report.numTotalTests !== undefined && (!diagnosticInteger(report.numTotalTests) || report.numPassedTests + report.numFailedTests + report.numPendingTests > report.numTotalTests)) return unavailable('INVALID');
    if (!Array.isArray(report.testResults) || report.testResults.length > 20_000) return unavailable('INVALID');
    const failed = [];
    let assertions = 0;
    for (const suite of report.testResults) {
      if (typeof suite?.name !== 'string' || suite.name.length > 4096 || !Array.isArray(suite.assertionResults)) return unavailable('INVALID');
      const claimedFile = relative(context.root, resolve(context.root, suite.name)).split(sep).join('/');
      const file = context.tests.has(claimedFile) ? claimedFile : null;
      assertions += suite.assertionResults.length;
      if (assertions > 20_000) return unavailable('INVALID');
      for (const test of suite.assertionResults) {
        if (!['passed', 'failed', 'pending', 'skipped', 'todo', 'disabled'].includes(test?.status)) return unavailable('INVALID');
        if (test.status !== 'failed') continue;
        if (typeof test.fullName !== 'string' || !Array.isArray(test.failureMessages) || test.failureMessages.some(message => typeof message !== 'string')) return unavailable('INVALID');
        if (failed.length >= 16) continue;
        const frame = file ? test.failureMessages.map(message => diagnosticFrame(message, file, context.root)).find(Boolean)
          ?? (diagnosticLocation(test.location?.line) ? { file, line: test.location.line, column: diagnosticLocation(test.location.column) ? test.location.column : null } : undefined) : undefined;
        const codes = test.failureMessages.flatMap(message => {
          const code = /^\w*Error \[([A-Z0-9_]+)\]:/.exec(message)?.[1] ?? /^\w*Error: ([A-Z0-9_]+):/.exec(message)?.[1];
          return diagnosticCodes.has(code) ? [code] : [];
        });
        failed.push({ titleSha256: hash(test.fullName), messageSha256: hash(test.failureMessages.join('\n')), file, line: frame?.line ?? null, column: frame?.column ?? null, codes: [...new Set(codes)] });
      }
    }
    if (Object.values(totals).some(count => count > assertions)) return unavailable('INVALID');
    return { report: reportName, status: 'OK', passed: totals.numPassedTests, failed: totals.numFailedTests, pending: totals.numPendingTests, sha256: reportSha256, failures: failed };
  } catch (error) { return unavailable(error?.code === 'ENOENT' ? 'MISSING' : error?.code ? 'UNREADABLE' : 'INVALID'); }
  finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* Diagnostics never replace the original failure. */ } } }
}
function safeDiagnostic(value) {
  try {
    const context = diagnosticContext, text = JSON.stringify(value);
    const options = { root: context.root, sentinels: join(context.root, 'test/sentinels.json') };
    // A config under verification must never replace the caller's actual union.
    if (findLeaks({ ...options, sentinelDir: context.environment.sentinelDir, commandOutput: text })) return null;
    if (context.sentinelDir !== context.environment.sentinelDir && findLeaks({ ...options, sentinelDir: context.sentinelDir, commandOutput: text })) return null;
    const retained = join(context.capture, 'private', 'sources');
    if (fs.existsSync(retained) && findLeaks({ ...options, sentinelDir: retained, commandOutput: text })) return null;
    return text;
  } catch { return null; }
}
function diagnostic(phase, result, reasons, errors = []) {
  const base = { stage: 'ci-capture', phase, exitCode: Number.isInteger(result.exitCode) ? result.exitCode : 1,
    complete: result.complete === true, leakFree: result.leakFree === true, policySatisfied: result.policySatisfied === true, reasons };
  // Public-looking paths and numeric metadata can themselves be literal sources.
  // Guard the complete JSON, including keys and hashes, before any emission.
  const safe = safeDiagnostic({ ...base, details: { reports: ['harness', 'product'].map(diagnosticReport), errors } }) ?? safeDiagnostic(base);
  if (safe !== null) process.stderr.write(safe + '\n');
}
function git(root, args, env = process.env, input) {
  const result = spawnSync('git', ['-C', root, ...args], { env, input, encoding: 'utf8', windowsHide: true });
  if (result.status !== 0) throw new Error('capture checkout identity failed');
  return result.stdout.trim();
}
function dependencyTree(root, env, capture) {
  const dependencies = join(root, 'node_modules'), generated = ['.vite', '.vite-temp'].map(name => join(dependencies, name));
  git(root, ['read-tree', '--empty'], env);
  if (!fs.existsSync(dependencies)) return { dependencyTree: git(root, ['write-tree'], env), dependencyNamespaceSha256: hash('[]') };
  if (fs.lstatSync(dependencies).isSymbolicLink() || !fs.lstatSync(dependencies).isDirectory()) throw new Error('capture dependency root');
  const links = [], directories = [];
  const visit = directory => {
    directories.push(relative(root, directory).split(sep).join('/'));
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (generated.some(directory => inside(directory, path))) continue;
      if (entry.isSymbolicLink()) {
        const original = fs.readlinkSync(path), originalTarget = resolve(dirname(path), original), target = fs.realpathSync.native(path);
        if (!inside(dependencies, originalTarget) || generated.some(directory => inside(directory, originalTarget)) || !inside(dependencies, target) || generated.some(directory => inside(directory, target))) throw new Error('capture unauthenticated dependency link');
        links.push({ path, original, target });
      } else if (entry.isDirectory()) visit(path);
      else if (!entry.isFile()) throw new Error('capture dependency entry');
    }
  };
  visit(dependencies);
  // Git's attribute source and raw-byte settings prevent checkout/global text
  // filters from making different installed bytes share an input identity.
  const emptyTree = git(root, ['write-tree'], env), attributes = join(capture, 'private', 'dependency-attributes');
  if (!fs.existsSync(attributes)) fs.writeFileSync(attributes, '', { flag: 'wx', mode: 0o600 });
  const rawGit = (args, input) => git(root, ['--attr-source=' + emptyTree, '-c', 'core.autocrlf=false', '-c', 'core.attributesfile=' + attributes, ...args], { ...env, GIT_ATTR_NOSYSTEM: '1' }, input);
  // Windows Git follows directory junctions. Exclude every observed link from
  // traversal and stage its original target bytes explicitly as a Git symlink.
  rawGit(['add', '-f', '-A', '--', 'node_modules', ...generated.map(directory => ':(literal,exclude)' + relative(root, directory).split(sep).join('/')), ...links.map(link => ':(literal,exclude)' + relative(root, link.path).split(sep).join('/'))]);
  const entries = git(root, ['ls-files', '--stage', '-z'], env).split('\0').filter(Boolean).map(row => ({ mode: row.slice(0, 6), path: resolve(root, row.slice(row.indexOf('\t') + 1)) }));
  if (entries.length && rawGit(['check-attr', '--all', '-z', '--stdin'], entries.map(entry => entry.path).join('\0') + '\0')) throw new Error('capture dependency attributes');
  if (entries.some(entry => !['100644', '100755'].includes(entry.mode))) throw new Error('capture dependency entry');
  for (const link of links) {
    const directory = fs.statSync(link.target).isDirectory();
    if (!entries.some(entry => directory ? inside(link.target, entry.path) : inside(link.target, entry.path) && inside(entry.path, link.target))) throw new Error('capture unauthenticated dependency target');
    const object = rawGit(['hash-object', '-w', '--stdin'], link.original);
    rawGit(['update-index', '--add', '--cacheinfo', '120000,' + object + ',' + relative(root, link.path).split(sep).join('/')]);
  }
  return { dependencyTree: git(root, ['write-tree'], env), dependencyNamespaceSha256: hash(JSON.stringify(directories.sort())) };
}
function identity(root, capture) {
  const index = join(capture, 'private', 'checkout.index');
  const env = { ...process.env, GIT_INDEX_FILE: index };
  try {
    const sourceNames = git(root, ['ls-files', '--cached', '--others', '--exclude-standard', '-z']).split('\0').filter(Boolean).filter(path => !inside(join(root, 'node_modules'), resolve(root, path)));
    const stagedDeletions = git(root, ['diff', '--cached', '--diff-filter=D', '--name-only', '-z', 'HEAD']);
    git(root, ['read-tree', 'HEAD'], env);
    // Restoring HEAD must not resurrect names already removed from the real
    // index. Keep a fresh private index so Git rereads current checkout bytes.
    if (stagedDeletions) git(root, ['update-index', '--force-remove', '-z', '--stdin'], env, stagedDeletions);
    // An explicit excluded ignored directory makes Git add fail. Stage the
    // ordinary index/read-set names literally instead, without traversing deps.
    if (sourceNames.length) git(root, ['--literal-pathspecs', 'add', '-A', '--pathspec-from-file=-', '--pathspec-file-nul'], env, sourceNames.join('\0') + '\0');
    git(root, ['rm', '--cached', '-r', '--ignore-unmatch', '--', 'node_modules'], env);
    const tree = git(root, ['write-tree'], env);
    const sourcePaths = git(root, ['ls-files', '--cached', '-z'], env).split('\0').filter(Boolean).map(path => resolve(root, path));
    const parents = new Map();
    const sourceBindings = sourcePaths.sort().map(path => {
      const directory = dirname(path);
      if (!parents.has(directory)) parents.set(directory, ancestry(directory));
      return { file: binding(path), parents: parents.get(directory) };
    });
    let dependencies;
    try { dependencies = { ...dependencyTree(root, env, capture), dependencyValid: true }; }
    catch { dependencies = { dependencyTree: null, dependencyNamespaceSha256: null, dependencyValid: false }; }
    return { commit: git(root, ['rev-parse', 'HEAD']), tree, ...dependencies, readSetSha256: hash(JSON.stringify(sourceBindings)), rootIdentitySha256: hash(JSON.stringify(ancestry(root))) };
  } finally { fs.rmSync(index, { force: true }); }
}
function inventory(paths) {
  return [...new Set(paths.flatMap(files))].sort().map(path => ({ ...binding(path), parents: ancestry(dirname(path)) }));
}
function same(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
function parentBindings(paths) {
  // Shared ancestors have one physical identity per observation. Keep every
  // original path/dev/ino/realpath once, rather than repeating the same tree.
  return [...new Map(paths.flatMap(ancestry).map(row => [row.path, row])).values()].sort((a, b) => a.path.localeCompare(b.path));
}
function records(capture, config) {
  return files(join(capture, 'private', 'records')).map(path => {
    const row = read(path);
    if (!same(Object.keys(row), ['path', 'sha256', 'purpose']) || typeof row.path !== 'string' || resolve(row.path) !== row.path || !/^[0-9a-f]{64}$/.test(row.sha256) || !['INPUT', 'EGRESS', 'SECRET_OUTPUT'].includes(row.purpose) ||
        path !== join(capture, 'private', 'records', hash(JSON.stringify(row)) + '.json') ||
        row.purpose === 'INPUT' && !config.registered.includes(row.path) && !inside(config.sentinelDir, row.path)) throw new Error('capture invalid original context');
    if (row.purpose === 'SECRET_OUTPUT') {
      const producer = read(join(capture, 'private', 'authorizations', 'secret-output-' + hash(row.path) + '.json'));
      if (producer.purpose !== 'SECRET_OUTPUT' || producer.file?.sha256 !== row.sha256 || producer.environment?.codeLoadingValidated !== true) throw new Error('capture invalid generated source');
    }
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
    if (row.purpose === 'INPUT' || row.purpose === 'SECRET_OUTPUT') {
      typedCopies.set(join(capture, 'private', 'sources', row.sha256), row.sha256);
      for (const bytes of equivalents(fs.readFileSync(join(capture, 'private', 'bytes', row.sha256)))) typedCopies.set(join(capture, 'private', 'bytes', hash(bytes)), hash(bytes));
    }
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
function scan(capture, config, retained, approved = []) {
  const options = { root: config.root, sentinels: join(capture, 'private', 'sentinels.json'), sentinelDir: join(capture, 'private', 'sources') };
  // Keep the scanner's exact declaration and evidence-priority semantics on the
  // original paths. Private byte copies provide custody, never source credit.
  const paths = [...new Set([...retained.filter(record => record.purpose !== 'INPUT').map(record => record.path), ...captureEgress(capture, retained)])];
  const authorized = new Set(approved.map(row => row.path));
  let leakFree = !findLeaks({ ...options, paths, testTmp: config.testTmp, evidenceDir: config.evidenceDir });
  let noUnexpectedLeaks = authorized.size ? !findLeaks({ ...options, paths: paths.filter(path => !authorized.has(path)), testTmp: config.testTmp, evidenceDir: config.evidenceDir }) : Boolean(leakFree);
  const declared = declarationSet(config.testTmp);
  const unproven = paths.filter(path => (declared.has(path) || declared.has('sha256:' + hash(path))) && !authorizedDeclaration(capture, config, declared, path));
  // The unchanged engine gets every unproved declaration target as EGRESS too;
  // a later append cannot retroactively suppress bytes already written there.
  if (unproven.length && findLeaks({ ...options, paths: unproven })) { leakFree = false; if (!authorized.size) noUnexpectedLeaks = false; }
  if (authorized.size && unproven.some(path => !authorized.has(path)) && findLeaks({ ...options, paths: unproven.filter(path => !authorized.has(path)) })) noUnexpectedLeaks = false;
  const secretOutputMatches = [];
  for (const row of approved) {
    const match = findLeaks({ ...options, paths: [row.path] });
    if (match) { leakFree = false; secretOutputMatches.push({ pathSha256: hash(row.path), sha256: row.sha256, encoding: match.encoding }); }
  }
  if (unexpectedSecretMatches(capture, retained, approved, findLeaks)) noUnexpectedLeaks = false;
  const roots = [...config.roots, ...config.outputs.filter(path => fs.existsSync(path)), capture];
  const names = new Set([...retained.map(record => record.path), ...roots.flatMap(directories), ...roots.flatMap(path => ancestry(dirname(path)).map(row => row.path))]);
  // Includes empty directories and all ancestor names. NUL cannot occur in a
  // filename, so one unchanged-engine pass retains every original name without
  // rebuilding source recognition for each directory and retained artifact.
  const outputNames = [...names].filter(path => !authorizedDeclaration(capture, config, declared, path));
  if (findLeaks({ ...options, commandOutput: outputNames.join('\0') })) { leakFree = false; noUnexpectedLeaks = false; }
  return { leakFree: Boolean(leakFree), noUnexpectedLeaks, authorizedMatches: secretOutputMatches.length, secretOutputMatches };
}
function custody(capture, config) {
  const metadata = ['receipt.json', 'receipt.sha256', 'custody.json'].map(name => join(capture, name));
  const paths = [...config.roots, ...config.outputs.filter(path => fs.existsSync(path)), ...registered(config.root), join(config.root, 'test/sentinels.json'), capture];
  return { parents: parentBindings([...config.roots, ...config.outputs.filter(path => fs.existsSync(path)), capture, config.root].map(dirname)), namespace: namespace(paths, new Set(metadata)) };
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
  diagnosticContext.evidenceDir = config.evidenceDir;
  diagnosticContext.sentinelDir = config.sentinelDir;
  if (!receipt.result.complete || !receipt.result.policySatisfied) {
    diagnostic('verify', receipt.result, [!receipt.result.complete ? 'recorded_incomplete' : 'recorded_policy_failure']);
    return 1;
  }
  const outputs = await secretOutputs(capture, config);
  const checked = scan(capture, config, records(capture, config), outputs.approved);
  const redact = sentinelRedactor({ root, sentinels: join(capture, 'private', 'sentinels.json'), sentinelDir: join(capture, 'private', 'sources') });
  if (!outputs.valid || !checked.noUnexpectedLeaks || checked.leakFree !== receipt.result.leakFree || checked.authorizedMatches !== receipt.result.authorizedMatches
    || !same(checked.secretOutputMatches, receipt.secretOutputMatches)
    || !same(outputs.approved.map(row => secretContext(row, redact)), receipt.secretOutputs)
    || findLeaks({ root, sentinels: join(capture, 'private', 'sentinels.json'), sentinelDir: join(capture, 'private', 'sources'), paths: metadataPaths(capture) })) {
    diagnostic('verify', receipt.result, ['verification_scan']);
    return 1;
  }
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
  const outputs = ['dist', 'reports', 'coverage', 'chaos-evidence', 'node_modules/.vite', 'node_modules/.vite-temp'].map(name => join(root, name));
  const anchoredRoots = [...roots, capture, join(capture, 'private'), ...['bytes', 'records', 'sources', 'identities', 'authorizations'].map(name => join(capture, 'private', name))];
  const rootIdentities = parentBindings(anchoredRoots);
  const config = { root, capture, roots, outputs, rootIdentities, initialDeclarations: [...declarationSet(resolve(env.FLUXWARDEN_TEST_TMP))], registered: sourcePaths, sentinelDir: resolve(env.FLUXWARDEN_SENTINEL_DIR), testTmp: resolve(env.FLUXWARDEN_TEST_TMP), evidenceDir: resolve(env.FLUXWARDEN_EVIDENCE_DIR) };
  diagnosticContext.evidenceDir = config.evidenceDir;
  diagnosticContext.sentinelDir = config.sentinelDir;
  write(join(capture, 'private', 'config.json'), config);
  write(join(capture, 'private', 'sentinels.json'), []);
  const before = identity(root, capture);
  let complete = before.dependencyValid;
  const reasons = new Set(complete ? [] : ['dependency_identity']);
  const errors = [];
  const initialSources = inventory([...sourcePaths, config.sentinelDir]);
  for (const row of initialSources) retain(capture, row.path, 'INPUT');
  const setupPaths = ['npm-install.stdout.log', 'npm-install.stderr.log', 'npm-install.json', 'npm-install-logs'].map(name => join(config.evidenceDir, name)).filter(path => fs.existsSync(path));
  const setupEvidence = namespace(setupPaths);
  for (const path of setupPaths.flatMap(files)) retain(capture, path, 'EGRESS');
  const stdout = fs.openSync(join(capture, 'stdout.log'), 'wx', 0o600);
  const stderr = fs.openSync(join(capture, 'stderr.log'), 'wx', 0o600);
  let exitCode;
  try {
    if (!complete) exitCode = 1;
    else {
    const child = spawn(command[0], ['--import', pathToFileURL(join(dirname(script), 'ci-capture-preload.mjs')).href, ...command.slice(1)], {
      cwd: root, env: { ...env, FLUXWARDEN_CI_CAPTURE: capture }, stdio: ['ignore', stdout, stderr], windowsHide: true,
    });
    exitCode = await new Promise(resolveExit => {
      child.once('error', error => { complete = false; reasons.add('child_spawn'); errors.push({ stage: 'child_spawn', ...diagnosticError(error) }); resolveExit(1); });
      child.once('close', code => resolveExit(code ?? 1));
    });
    }
  } finally { fs.closeSync(stdout); fs.closeSync(stderr); }
  let after = before;
  try {
    after = identity(root, capture);
    if (!same(before, after)) { complete = false; reasons.add('checkout_identity'); }
    if (before.dependencyTree !== after.dependencyTree || before.dependencyNamespaceSha256 !== after.dependencyNamespaceSha256) reasons.add('dependency_identity');
    if (!same(setupEvidence, namespace(setupPaths))) { complete = false; reasons.add('setup_evidence'); }
    if (!same(config.rootIdentities, parentBindings(anchoredRoots))) { complete = false; reasons.add('root_identity'); }
    if (!same(initialSources, inventory(initialSources.map(row => row.path)))) { complete = false; reasons.add('source_identity'); }
    if (!same(sourcePaths, registered(root))) { complete = false; reasons.add('source_membership'); }
    for (const path of files(config.sentinelDir)) retain(capture, path, 'INPUT');
    for (const path of [...roots.flatMap(files), ...outputs.filter(path => fs.existsSync(path)).flatMap(files), join(capture, 'stdout.log'), join(capture, 'stderr.log')]) {
      if (!inside(config.sentinelDir, path)) retain(capture, path, 'EGRESS');
    }
    for (const path of captureEgress(capture, records(capture, config))) retain(capture, path, 'EGRESS');
    if (fs.existsSync(join(capture, 'private', 'incomplete'))) { complete = false; reasons.add('source_lifecycle'); }
    retainedSourceIdentities(capture);
  } catch (error) { complete = false; reasons.add('closing_inventory'); errors.push({ stage: 'closing_inventory', ...diagnosticError(error) }); }
  const retained = records(capture, config);
  for (const record of retained.filter(row => row.purpose === 'INPUT' || row.purpose === 'SECRET_OUTPUT')) {
    const source = fs.readFileSync(join(capture, 'private', 'bytes', record.sha256));
    const destination = join(capture, 'private', 'sources', record.sha256);
    if (!fs.existsSync(destination)) fs.writeFileSync(destination, source, { mode: 0o600, flag: 'wx' });
  }
  let leakFree = false, policySatisfied = false, authorizedMatches = 0, secretOutputMatches = [];
  const outputsPolicy = await secretOutputs(capture, config);
  try {
    const checked = scan(capture, config, retained, outputsPolicy.approved);
    ({ leakFree, authorizedMatches, secretOutputMatches } = checked);
    policySatisfied = outputsPolicy.valid && checked.noUnexpectedLeaks;
    if (!policySatisfied) reasons.add('output_leak');
  }
  catch (error) { complete = false; reasons.add('output_scan'); errors.push({ stage: 'output_scan', ...diagnosticError(error) }); }
  const redact = sentinelRedactor({ root, sentinels: join(capture, 'private', 'sentinels.json'), sentinelDir: join(capture, 'private', 'sources') });
  const context = row => ({ path: redact(row.path), ...(redact(row.path) !== row.path ? { pathSha256: hash(row.path) } : {}), sha256: row.sha256 });
  const declared = declarationSet(config.testTmp);
  const sources = retained.filter(row => row.purpose === 'INPUT' || row.purpose === 'SECRET_OUTPUT').flatMap(row => equivalents(fs.readFileSync(join(capture, 'private', 'bytes', row.sha256))).map(bytes => ({ ...context(row), sha256: hash(bytes), purpose: row.purpose })));
  const artifacts = retained.filter(row => row.purpose !== 'INPUT').map(row => ({ ...context(row), purpose: row.purpose === 'SECRET_OUTPUT' || outputsPolicy.approved.some(output => output.path === row.path && output.sha256 === row.sha256) ? 'SECRET_OUTPUT' : row.path === join(config.testTmp, 'declared-out.txt') ? 'DECLARATION' : authorizedDeclaration(capture, config, declared, row.path) ? 'INPUT' : 'EGRESS' }));
  let census;
  try { census = custody(capture, config); }
  catch (error) { complete = false; census = []; reasons.add('custody_inventory'); errors.push({ stage: 'custody_inventory', ...diagnosticError(error) }); }
  fs.writeFileSync(join(capture, 'custody.json'), JSON.stringify(census), { mode: 0o600 });
  const receipt = { scope: 'observed retained closing artifacts, full command streams, registered source lifetime and authenticated dependency inputs; prospectively authorized canonical operator-key outputs retain literal matches with separate policy acceptance; no universal temporary-file history claim', boundarySha256: '8f4e83b62bad4940be142239352e443788d778d2ad10a24e76400bdf40f7bc27', parentBoundarySha256: '42784be10c0f54af383eb8005f0195db59f371081d504c9971fbb78dff6f9489', identity: { before, after }, result: { exitCode, complete, leakFree, policySatisfied, authorizedMatches }, sources, artifacts, secretOutputs: outputsPolicy.approved.map(row => secretContext(row, redact)), secretOutputMatches, custodySha256: digest(join(capture, 'custody.json')) };
  fs.writeFileSync(join(capture, 'receipt.json'), JSON.stringify(receipt), { mode: 0o600 });
  const metadata = ['receipt.json', 'receipt.sha256', 'custody.json'].map(name => ({ name, ...anchor(join(capture, name)) }));
  fs.writeFileSync(join(capture, 'receipt.sha256'), JSON.stringify({ receiptSha256: digest(join(capture, 'receipt.json')), metadata }), { mode: 0o600 });
  try {
    if (findLeaks({ root, sentinels: join(capture, 'private', 'sentinels.json'), sentinelDir: join(capture, 'private', 'sources'), paths: metadataPaths(capture) })) { leakFree = false; policySatisfied = false; reasons.add('metadata_leak'); }
  } catch (error) { complete = false; reasons.add('metadata_scan'); errors.push({ stage: 'metadata_scan', ...diagnosticError(error) }); }
  policySatisfied = complete && policySatisfied;
  receipt.result = { exitCode, complete, leakFree, policySatisfied, authorizedMatches };
  fs.writeFileSync(join(capture, 'receipt.json'), JSON.stringify(receipt), { mode: 0o600 });
  fs.writeFileSync(join(capture, 'receipt.sha256'), JSON.stringify({ receiptSha256: digest(join(capture, 'receipt.json')), metadata }), { mode: 0o600 });
  if (exitCode || !complete || !policySatisfied) diagnostic('capture', receipt.result, [...reasons, ...(exitCode ? ['child_failure'] : [])], errors);
  return exitCode || (complete && policySatisfied ? 0 : 1);
}
async function main(args) {
  const verification = args[0] === 'verify';
  if (verification) args = args.slice(1);
  if (args[0] !== '--root' || !args[1] || args[2] !== '--capture-dir' || !args[3] || (verification ? args.length !== 4 : args[4] !== '--')) return 2;
  const root = resolve(args[1]), capture = resolve(args[3]);
  let tests;
  try { tests = new Set(git(root, ['ls-tree', '-r', '--name-only', '-z', 'HEAD', '--', 'test']).split('\0').filter(path => path.length <= 512 && /^test\/[A-Za-z0-9_./-]+\.test\.[cm]?[jt]sx?$/.test(path))); }
  catch { /* A diagnostic without a trusted tracked-file allowlist emits no report fields. */ }
  const environment = Object.freeze({ evidenceDir: process.env.FLUXWARDEN_EVIDENCE_DIR, sentinelDir: process.env.FLUXWARDEN_SENTINEL_DIR });
  diagnosticContext = { root, capture, tests, environment, ...environment };
  return verification ? verify(root, capture) : captureCommand(root, capture, args.slice(5));
}
if (process.argv[1] && resolve(process.argv[1]) === script) {
  try { process.exitCode = await main(process.argv.slice(2)); }
  catch (error) { diagnostic(process.argv[2] === 'verify' ? 'verify' : 'capture', {}, ['operation_failed'], [{ stage: 'operation_failed', ...diagnosticError(error) }]); process.exitCode = 1; }
}
