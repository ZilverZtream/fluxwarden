// Loaded only by the explicitly owned Node test driver (and its fork workers),
// never injected via NODE_OPTIONS into product CLI subprocesses.
// Node.js/node doc/api/module.md: syncBuiltinESMExports updates named fs imports.
import fs from 'node:fs';
import { AsyncLocalStorage } from 'node:async_hooks';
import promises from 'node:fs/promises';
import childProcess from 'node:child_process';
import { createHash } from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { fileURLToPath } from 'node:url';
import { resolve, join, dirname, basename } from 'node:path';
import { files, inside, retain, hash, binding, ancestry } from './ci-capture-files.mjs';
import { secretProducer, producerEnvironment, stateCopyProducer, verifyStateCopy } from './ci-secret-output.mjs';
import { beginSecretRemovals, finishSecretRemovals, secretOutputMutation } from './ci-secret-removal.mjs';

const capture = process.env.FLUXWARDEN_CI_CAPTURE;
let authorizeOutput;
export async function authorizeOwnedSecretOutput(options) {
  if (capture) return authorizeOutput(options);
}
if (capture) {
  const config = JSON.parse(fs.readFileSync(join(capture, 'private', 'config.json'), 'utf8'));
  const originals = { readFileSync: fs.readFileSync, writeFileSync: fs.writeFileSync, readdirSync: fs.readdirSync, lstatSync: fs.lstatSync, fstatSync: fs.fstatSync, realpathSync: fs.realpathSync };
  const descriptors = new Map();
  // Node.js/node doc/api/async_context.md: scope native recursive cleanup,
  // retaining independent mutation observation across overlapping async calls.
  const removalContext = new AsyncLocalStorage();
  const nestedRemoval = (path, operation) => {
    const current = removalContext.getStore();
    return current?.active && current.capture === capture && current.root === config.root &&
      current.proofs.length > 0 && current.proofs.every(proof => proof.state === 'pending') &&
      ['unlink', 'rm', 'rmdir'].includes(current.operation) && ['unlink', 'rm', 'rmdir'].includes(operation) && inside(current.target, path);
  };
  const closedDescriptor = Symbol('closed descriptor');
  let busy = false;
  const incomplete = () => {
    const previous = busy;
    busy = true;
    try { originals.writeFileSync(join(capture, 'private', 'incomplete'), 'capture lifecycle failed', { mode: 0o600 }); }
    finally { busy = previous; }
  };
  const intents = new Map();
  const saveIntent = row => {
    const previous = busy;
    busy = true;
    try { originals.writeFileSync(join(capture, 'private', 'authorizations', 'secret-output-' + hash(row.path) + '.json'), JSON.stringify(row), { mode: 0o600 }); }
    finally { busy = previous; }
  };
  const absent = path => {
    try { originals.lstatSync(path); throw new Error('secret output already exists'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  };
  const producerFor = row => row.kind === 'state-outbox-copy' ? stateCopyProducer(config, row.command, row.args, row.path, row.sourcePath) : secretProducer(config, row.command, row.args, row.path);
  authorizeOutput = ({ path, command, args, kind, sourcePath, env }) => {
    try {
      if (kind !== undefined && kind !== 'state-outbox-copy') throw new Error('secret output kind');
      if (typeof path !== 'string' || path !== resolve(path) || intents.has(path)
        || ![...config.roots, ...config.outputs].some(root => inside(root, path))
        || inside(config.evidenceDir, path) || inside(config.sentinelDir, path) || config.registered.includes(path)) throw new Error('secret output destination');
      absent(path);
      const row = { purpose: 'SECRET_OUTPUT', prospective: true, path, command, args: [...args], ...(kind ? { kind, sourcePath } : {}), state: 'authorized' };
      row.producer = producerFor(row);
      if (kind) {
        if (!env || typeof env !== 'object') throw new Error('state output explicit environment');
        absent(row.producer.root);
        row.intendedEnvironment = producerEnvironment({ env }).identity;
        row.parents = ancestry(dirname(row.producer.root));
      } else row.parents = ancestry(dirname(path));
      const ledger = join(capture, 'private', 'authorizations', 'secret-output-' + hash(path) + '.json');
      absent(ledger);
      saveIntent(row);
      intents.set(path, row);
    } catch { incomplete(); throw new Error('secret output authorization rejected'); }
  };
  const startProducer = (command, args, options) => {
    let row = [...intents.values()].find(row => row.command === command && JSON.stringify(row.args) === JSON.stringify(args));
    let environment;
    if (!row) {
      // The existing canonical producer is observable independently of intent.
      // Observation retains SOURCE; it never supplies prospective authorization.
      let recognized = false;
      try {
        const path = args?.at(-1), producer = secretProducer(config, command, args, path);
        recognized = true;
        environment = producerEnvironment(options);
        if (path !== resolve(path) || ![...config.roots, ...config.outputs].some(root => inside(root, path))) throw new Error('secret output destination');
        try { originals.lstatSync(path); return; }
        catch (error) { if (error.code !== 'ENOENT') throw error; }
        row = { purpose: 'SECRET_OUTPUT', prospective: false, path, command, args: [...args], producer, parents: [], state: 'authorized' };
        saveIntent(row); intents.set(path, row);
      } catch { if (recognized) incomplete(); return; }
    }
    try {
      if (row.state !== 'authorized' || options?.shell || options?.windowsVerbatimArguments || options?.input != null) throw new Error('secret output execution');
      absent(row.path);
      if (row.kind) absent(row.producer.root);
      if (JSON.stringify(row.producer) !== JSON.stringify(producerFor(row))
        || row.prospective && JSON.stringify(row.parents) !== JSON.stringify(ancestry(dirname(row.kind ? row.producer.root : row.path)))) throw new Error('secret output producer changed');
      environment ??= producerEnvironment(options);
      if (row.kind && JSON.stringify(row.intendedEnvironment) !== JSON.stringify(environment.identity)) throw new Error('state output environment changed');
      row.environment = environment.identity;
      row.state = 'started'; saveIntent(row);
      return { row, env: environment.env };
    } catch { row.state = 'invalid'; saveIntent(row); incomplete(); }
  };
  const finishProducer = (row, result, stdout, stderr, stored) => {
    const previous = busy;
    busy = true;
    try {
      const out = Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout ?? '');
      const err = Buffer.isBuffer(stderr) ? stderr : Buffer.from(stderr ?? '');
      if (!stored) {
        originals.writeFileSync(join(capture, 'secret-output-' + hash(row.path) + '.stdout.log'), out, { flag: 'wx', mode: 0o600 });
        originals.writeFileSync(join(capture, 'secret-output-' + hash(row.path) + '.stderr.log'), err, { flag: 'wx', mode: 0o600 });
      }
      row.result = { exitCode: result.status, signal: result.signal ?? null, errorCode: result.error?.code ?? null };
      row.stdoutSha256 = stored?.stdoutSha256 ?? hash(out); row.stderrSha256 = stored?.stderrSha256 ?? hash(err);
      if (!row.prospective && result.status !== 0 && !fs.existsSync(row.path)) {
        row.state = 'not-produced'; saveIntent(row); return;
      }
      if (!row.prospective || row.kind) row.parents = ancestry(dirname(row.path));
      row.file = binding(row.path); row.state = 'closed';
      if (result.status === 0 && !result.signal && !result.error) {
        if (fs.statSync(row.path).size > 65_536) throw new Error('secret output source bound');
        if (row.kind) {
          row.closedNamespace = verifyStateCopy(config, row).contents;
          if (row.producer.operation === 'restore') {
            // Preserve the actual independently validated result before the
            // caller can reconcile it. Later database evolution is ordinary;
            // the original signing-key output remains immutable.
            const snapshot = retain(capture, row.producer.database, 'EGRESS');
            row.restoreSnapshot = binding(join(capture, 'private', 'bytes', snapshot.sha256));
          }
        }
        // Observe the original before returning control to the caller: it is a
        // SOURCE identity without changing its original SECRET_OUTPUT purpose.
        retain(capture, row.path, 'SECRET_OUTPUT');
      }
      saveIntent(row);
    } catch { row.state = 'invalid'; saveIntent(row); incomplete(); }
    finally { busy = previous; }
  };
  const spawnSync = childProcess.spawnSync;
  childProcess.spawnSync = function (command, args, options) {
    const execution = { ...options }, observed = startProducer(command, args, execution);
    if (!observed) return spawnSync.apply(this, arguments);
    const { row, env } = observed;
    const result = spawnSync.call(this, command, args, { ...execution, env, encoding: 'buffer' });
    finishProducer(row, result, result.stdout, result.stderr);
    if (options?.encoding && options.encoding !== 'buffer') {
      result.output = result.output?.map(value => Buffer.isBuffer(value) ? value.toString(options.encoding) : value);
      result.stdout = result.output?.[1]; result.stderr = result.output?.[2];
    }
    return result;
  };
  const spawn = childProcess.spawn;
  childProcess.spawn = function (command, args, options) {
    const execution = { ...options }, observed = startProducer(command, args, execution);
    const child = observed ? spawn.call(this, command, args, { ...execution, env: observed.env }) : spawn.apply(this, arguments);
    const row = observed?.row;
    if (row) {
      let error;
      if (!child.stdout || !child.stderr) { row.state = 'invalid'; saveIntent(row); incomplete(); }
      else {
        const streams = [child.stdout, child.stderr].map((stream, index) => {
          const path = join(capture, 'secret-output-' + hash(row.path) + (index ? '.stderr.log' : '.stdout.log'));
          const fd = fs.openSync(path, 'wx', 0o600), digest = createHash('sha256');
          stream.on('data', bytes => {
            const value = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
            for (let at = 0; at < value.length;) at += fs.writeSync(fd, value, at, value.length - at);
            digest.update(value);
          });
          return { fd, digest };
        });
        child.once('error', value => { error = value; });
        child.once('close', (status, signal) => {
          for (const { fd } of streams) fs.closeSync(fd);
          finishProducer(row, { status, signal, error }, null, null, { stdoutSha256: streams[0].digest.digest('hex'), stderrSha256: streams[1].digest.digest('hex') });
        });
      }
    }
    return child;
  };
  // All recorder-owned inputs, snapshots and custody records share the same
  // private namespace. Only the guarded internal recorder may mutate it.
  const protectedPaths = [join(capture, 'private')];
  const guardMutation = path => {
    const candidates = [path];
    try { candidates.push(originals.realpathSync(path)); }
    catch {
      try { candidates.push(join(originals.realpathSync(dirname(path)), basename(path))); }
      catch { /* Nonexistent parents are guarded when their namespace is created. */ }
    }
    if (candidates.some(candidate => protectedPaths.some(protectedPath => inside(protectedPath, candidate) || inside(candidate, protectedPath)))) {
      incomplete();
      throw new Error('capture private recorder mutation');
    }
  };
  const inputPath = path => inside(config.sentinelDir, path) || config.registered.includes(path);
  const declared = (entries, path) => entries.includes(path) || entries.includes('sha256:' + hash(path));
  const authorizeWrite = path => {
    if (inputPath(path) || ![...config.roots, ...config.outputs, capture].some(root => inside(root, path))) return;
    const ledger = join(capture, 'private', 'authorizations', hash(path) + '.json');
    try { originals.lstatSync(ledger); return; }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    let bytes = Buffer.alloc(0);
    try { bytes = originals.readFileSync(join(config.testTmp, 'declared-out.txt')); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    const entries = bytes.toString('utf8').split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(entry => /^sha256:[0-9a-f]{64}$/.test(entry) ? entry : resolve(config.testTmp, entry));
    let exists = true;
    try { originals.lstatSync(path); } catch (error) { if (error.code !== 'ENOENT') throw error; exists = false; }
    // An existing unobserved file cannot acquire INPUT purpose after its write.
    // Initial supplied declarations are distinct from runtime prospective ones.
    const input = declared(entries, path) && (!exists || declared(config.initialDeclarations, path));
    try { originals.writeFileSync(ledger, JSON.stringify({ pathSha256: hash(path), purpose: input ? 'INPUT' : 'EGRESS', declarationSha256: hash(bytes) }), { flag: 'wx', mode: 0o600 }); }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
  };
  const pathOf = value => {
    if (typeof value === 'string' || value instanceof URL || Buffer.isBuffer(value)) return resolve(value instanceof URL ? fileURLToPath(value) : String(value));
    const fd = typeof value === 'number' ? value : value?.fd;
    return descriptors.get(fd)?.path;
  };
  const observe = (value, mutation = false, operation = 'write', removalCompletion = false) => {
    if (busy) return;
    const fd = typeof value === 'number' ? value : value?.fd;
    if (mutation && typeof fd === 'number') {
      if (descriptors.has(fd)) descriptors.get(fd).writing = true;
      else if (fd > 2) {
        // Reject a definitely closed descriptor before any write is attempted.
        // A valid inherited/unmapped descriptor still cannot prove source lifetime.
        try { originals.fstatSync(fd); }
        catch (error) {
          if (error.code === 'EBADF') {
            // Preserve the public operation's native error fields. The fstat
            // only establishes that no write can safely be attempted.
            error.syscall = operation;
            error.message = error.message.replace(/, fstat$/, ', ' + operation);
            Object.defineProperty(error, closedDescriptor, { value: true });
            throw error;
          }
        }
        incomplete();
      }
    }
    const path = pathOf(value);
    if (!path) return;
    if (mutation) {
      guardMutation(path);
      busy = true;
      try { if (!nestedRemoval(path, operation)) secretOutputMutation(capture, path, operation); authorizeWrite(path); } catch { incomplete(); }
      finally { busy = false; }
    }
    if (!mutation && !removalCompletion) {
      busy = true;
      try { secretOutputMutation(capture, path, operation); } catch { incomplete(); }
      finally { busy = false; }
    }
    if (!inside(config.sentinelDir, path) && !inside(path, config.sentinelDir) && !config.registered.some(source => source === path || inside(path, source))) return;
    busy = true;
    try {
      let candidates;
      try { candidates = files(path); }
      catch (error) {
        if (error.code === 'ENOENT') {
          if (mutation && typeof fd === 'number') incomplete();
          return;
        }
        throw error;
      }
      for (const file of candidates) {
        const input = inside(config.sentinelDir, file) || config.registered.includes(file);
        if (input) retain(capture, file, 'INPUT');
      }
    } catch {
      incomplete();
    } finally { busy = false; }
  };
  const removalOperations = new Set(['unlink', 'rm', 'rmdir']);
  const prepareRemoval = (value, operation) => {
    if (busy || !removalOperations.has(operation)) return [];
    const path = pathOf(value);
    if (!path || nestedRemoval(path, operation)) return [];
    busy = true;
    try { return beginSecretRemovals(capture, config, path, operation, [...descriptors.values()].filter(row => row.writing).map(row => row.path)); }
    catch { incomplete(); return []; }
    finally { busy = false; }
  };
  const completeRemoval = (prepared, error) => {
    if (!prepared.length) return;
    busy = true;
    try { if (!finishSecretRemovals(capture, prepared, error)) incomplete(); }
    catch { incomplete(); }
    finally { busy = false; }
  };
  const syscall = name => ['writeFile', 'appendFile', 'write', 'writev'].includes(name) ? 'write' : name === 'futimes' ? 'futime' : name;
  const callbackFailure = (error, name, args) => {
    if (!error[closedDescriptor] || typeof args.at(-1) !== 'function') throw error;
    const callback = args.at(-1);
    // Node's callback APIs return before delivering descriptor errors. No
    // actual write is issued for the descriptor rejected by the native stat.
    const rest = ['write', 'writev'].includes(name) ? [0, args[1]] : [];
    process.nextTick(() => callback(error, ...rest));
  };
  // A hard link publishes existing bytes at its destination, including the
  // Windows owner-only writer's staged file. Observe it before publication.
  const operations = ['writeFile', 'appendFile', 'copyFile', 'link', 'rename', 'unlink', 'rm', 'rmdir', 'truncate', 'mkdir'];
  for (const name of operations) {
    const target = name === 'copyFile' || name === 'link' || name === 'rename' ? 1 : 0;
    const originalSync = fs[name + 'Sync'];
    if (originalSync) fs[name + 'Sync'] = function (...args) {
      observe(args[0], true, syscall(name)); if (target) observe(args[target], true);
      const prepared = prepareRemoval(args[0], name), scope = prepared.length ? { capture, root: config.root, operation: name, target: pathOf(args[0]), proofs: prepared, active: true } : null;
      let result;
      try { result = scope ? removalContext.run(scope, () => originalSync.apply(this, args)) : originalSync.apply(this, args); }
      catch (error) { if (scope) scope.active = false; completeRemoval(prepared, error); observe(args[target], false, name, removalOperations.has(name)); throw error; }
      if (scope) scope.active = false;
      completeRemoval(prepared);
      observe(args[target], false, name, removalOperations.has(name));
      if (target) observe(args[0]);
      return result;
    };
    const original = fs[name];
    if (original) fs[name] = function (...args) {
      if (typeof args.at(-1) !== 'function') return original.apply(this, args);
      try { observe(args[0], true, syscall(name)); if (target) observe(args[target], true); }
      catch (error) { return callbackFailure(error, name, args); }
      const prepared = prepareRemoval(args[0], name), scope = prepared.length ? { capture, root: config.root, operation: name, target: pathOf(args[0]), proofs: prepared, active: true } : null;
      const callback = args.at(-1);
      if (typeof callback === 'function') args[args.length - 1] = function (...result) {
        if (scope) scope.active = false;
        completeRemoval(prepared, result[0]);
        observe(args[target], false, name, removalOperations.has(name));
        if (target) observe(args[0]);
        return callback.apply(this, result);
      };
      try { return scope ? removalContext.run(scope, () => original.apply(this, args)) : original.apply(this, args); }
      catch (error) { if (scope) scope.active = false; completeRemoval(prepared, error); throw error; }
    };
    const originalPromise = promises[name];
    if (originalPromise) promises[name] = async function (...args) {
      observe(args[0], true, syscall(name)); if (target) observe(args[target], true);
      const prepared = prepareRemoval(args[0], name), scope = prepared.length ? { capture, root: config.root, operation: name, target: pathOf(args[0]), proofs: prepared, active: true } : null;
      let result;
      try { result = await (scope ? removalContext.run(scope, () => originalPromise.apply(this, args)) : originalPromise.apply(this, args)); }
      catch (error) { if (scope) scope.active = false; completeRemoval(prepared, error); observe(args[target], false, name, removalOperations.has(name)); throw error; }
      if (scope) scope.active = false;
      completeRemoval(prepared);
      observe(args[target], false, name, removalOperations.has(name));
      if (target) observe(args[0]);
      return result;
    };
  }
  // These public APIs do not establish source writes, but must not bypass the
  // recorder's private namespace through metadata or link changes.
  for (const name of ['chmod', 'chown', 'utimes', 'lutimes', 'lchown', 'symlink', 'cp', 'mkdtemp']) {
    const guarded = args => {
      if (busy) return;
      for (const value of args.slice(0, ['symlink', 'cp'].includes(name) ? 2 : 1)) {
        const path = pathOf(value);
        if (path) { guardMutation(path); observe(path, true, name); }
      }
    };
    const originalSync = fs[name + 'Sync'];
    if (originalSync) fs[name + 'Sync'] = function (...args) { guarded(args); try { return originalSync.apply(this, args); } finally { for (const value of args.slice(0, ['symlink', 'cp'].includes(name) ? 2 : 1)) observe(value); } };
    const original = fs[name];
    if (original) fs[name] = function (...args) {
      guarded(args);
      const callback = args.at(-1);
      if (typeof callback === 'function') args[args.length - 1] = function (...result) {
        for (const value of args.slice(0, ['symlink', 'cp'].includes(name) ? 2 : 1)) observe(value);
        return callback.apply(this, result);
      };
      return original.apply(this, args);
    };
    const originalPromise = promises[name];
    if (originalPromise) promises[name] = async function (...args) { guarded(args); try { return await originalPromise.apply(this, args); } finally { for (const value of args.slice(0, ['symlink', 'cp'].includes(name) ? 2 : 1)) observe(value); } };
  }
  const writable = flags => typeof flags === 'number'
    ? (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_TRUNC | fs.constants.O_APPEND)) !== 0
    : /[wa+]/.test(String(flags));
  const remember = (fd, path, flags) => {
    const resolved = pathOf(path);
    if (resolved) descriptors.set(fd, { path: resolved, writing: writable(flags) });
  };
  const openSync = fs.openSync;
  fs.openSync = function (path, flags, ...args) {
    if (writable(flags)) observe(path, true);
    try {
      const fd = openSync.call(this, path, flags, ...args);
      remember(fd, path, flags);
      return fd;
    } finally { if (writable(flags)) observe(path); }
  };
  const open = fs.open;
  fs.open = function (...args) {
    if (writable(args[1])) observe(args[0], true);
    const callback = args.at(-1);
    if (typeof callback !== 'function') return open.apply(this, args);
    args[args.length - 1] = function (error, fd) {
      if (!error) remember(fd, args[0], args[1]);
      if (writable(args[1])) observe(args[0]);
      return callback.call(this, error, fd);
    };
    return open.apply(this, args);
  };
  for (const name of ['write', 'writev', 'ftruncate', 'fchmod', 'fchown', 'futimes']) {
    const originalSync = fs[name + 'Sync'];
    fs[name + 'Sync'] = function (...args) {
      try { observe(args[0], true, syscall(name)); }
      catch (error) {
        // Windows implements chown as a native no-op, including closed FDs.
        if (!(error[closedDescriptor] && name === 'fchown' && process.platform === 'win32')) throw error;
      }
      const result = originalSync.apply(this, args);
      observe(args[0]);
      return result;
    };
    const original = fs[name];
    fs[name] = function (...args) {
      if (typeof args.at(-1) !== 'function') return original.apply(this, args);
      const mutationPath = pathOf(args[0]);
      try { observe(args[0], true, syscall(name)); }
      catch (error) {
        if (!(error[closedDescriptor] && name === 'fchown' && process.platform === 'win32')) return callbackFailure(error, name, args);
      }
      const callback = args.at(-1);
      if (typeof callback !== 'function') return original.apply(this, args);
      args[args.length - 1] = function (...result) {
        observe(mutationPath ?? args[0]);
        return callback.apply(this, result);
      };
      return original.apply(this, args);
    };
  }
  const closeSync = fs.closeSync;
  fs.closeSync = function (fd) {
    const descriptor = descriptors.get(fd);
    if (descriptor?.writing) observe(fd);
    const result = closeSync.call(this, fd);
    if (descriptor?.writing) observe(descriptor.path);
    descriptors.delete(fd);
    return result;
  };
  const close = fs.close;
  fs.close = function (fd, callback) {
    if (typeof callback !== 'function') return close.call(this, fd, callback);
    const descriptor = descriptors.get(fd);
    if (descriptors.get(fd)?.writing) observe(fd);
    return close.call(this, fd, function (error) {
      if (descriptor?.writing) observe(descriptor.path);
      if (!error && descriptors.get(fd) === descriptor) descriptors.delete(fd);
      return callback.call(this, error);
    });
  };
  const watchStream = (stream, path, existingFd) => {
    let openedFd = existingFd;
    let descriptor = descriptors.get(existingFd);
    if (typeof existingFd === 'number') {
      try { observe(existingFd, true); }
      catch (error) {
        if (!error[closedDescriptor]) throw error;
        process.nextTick(() => stream.destroy(error));
      }
    }
    stream.on('open', fd => { openedFd = fd; remember(fd, path, 'w'); descriptor = descriptors.get(fd); });
    stream.on('finish', () => observe(path));
    stream.on('close', () => { observe(path); if (typeof openedFd === 'number' && descriptors.get(openedFd) === descriptor) descriptors.delete(openedFd); });
    return stream;
  };
  const createWriteStream = fs.createWriteStream;
  fs.createWriteStream = function (path, options) {
    observe(path, true);
    const resolved = pathOf(path);
    if (options?.fs && resolved && (inside(config.sentinelDir, resolved) || config.registered.includes(resolved))) incomplete();
    return watchStream(createWriteStream.call(this, path, options), path, options?.fd);
  };
  const openPromise = promises.open;
  promises.open = async function (path, flags, ...args) {
    if (writable(flags)) observe(path, true);
    let handle;
    try { handle = await openPromise.call(this, path, flags, ...args); }
    finally { if (writable(flags)) observe(path); }
    const fd = handle.fd;
    remember(fd, path, flags);
    for (const name of ['write', 'writev', 'writeFile', 'appendFile', 'truncate', 'chmod', 'chown', 'utimes']) {
      const original = handle[name];
      handle[name] = async function (...args) {
        // FileHandle performs its own closed-state rejection, with method-
        // specific fields, before any native write. Keep that rejection intact.
        if (handle.fd === -1) return original.apply(this, args);
        observe(fd, true);
        try { return await original.apply(this, args); }
        finally { observe(path); }
      };
    }
    const close = handle.close;
    handle.close = async function (...args) {
      const descriptor = descriptors.get(fd);
      if (descriptors.get(fd)?.writing) observe(fd);
      const result = await close.apply(this, args);
      if (descriptor?.writing) observe(descriptor.path);
      if (descriptors.get(fd) === descriptor) descriptors.delete(fd);
      return result;
    };
    const stream = handle.createWriteStream;
    handle.createWriteStream = function (...args) {
      if (handle.fd === -1) return stream.apply(this, args);
      observe(fd, true);
      return watchStream(stream.apply(this, args), path, fd);
    };
    return handle;
  };
  syncBuiltinESMExports();
}
