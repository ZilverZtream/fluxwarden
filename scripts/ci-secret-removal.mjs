// Closed operator-key removal preserves observed output purpose and payload.
import fs from 'node:fs';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { join, dirname, resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { hash, inside, binding, ancestry, anchor } from './ci-capture-files.mjs';
import { secretProducer } from './ci-secret-output.mjs';

const directory = capture => join(capture, 'private', 'authorizations', 'secret-removals');
const recordPath = (capture, path) => join(directory(capture), hash(path) + '.json');
const read = path => JSON.parse(fs.readFileSync(path, 'utf8'));
const absent = path => {
  try { fs.lstatSync(path); return false; }
  catch (error) { if (error.code !== 'ENOENT') throw error; return true; }
};
function removalRecords(capture) {
  let names;
  try { names = fs.readdirSync(directory(capture)); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  return names.filter(name => /^[a-f0-9]{64}\.json$/.test(name)).map(name => {
    const row = read(join(directory(capture), name));
    if (typeof row.path !== 'string' || row.path !== resolve(row.path) || name !== hash(row.path) + '.json') throw new Error('secret removal identity');
    return row;
  });
}
function store(capture, row, exclusive = false) {
  const target = recordPath(capture, row.path), temporary = target + '.' + randomUUID() + '.tmp';
  fs.writeFileSync(temporary, JSON.stringify(row), { flag: 'wx', mode: 0o600 });
  try {
    // Node.js/node doc/api/fs.md: link publishes an exclusive complete record;
    // rename replaces an existing record atomically on this same filesystem.
    if (exclusive) fs.linkSync(temporary, target);
    else fs.renameSync(temporary, target);
  } finally { if (!absent(temporary)) fs.unlinkSync(temporary); }
}
function authorization(capture, config, path, row) {
  if (row.purpose !== 'SECRET_OUTPUT' || row.prospective !== true || row.state !== 'closed' || row.kind !== undefined ||
    row.path !== resolve(row.path) || path !== join(capture, 'private', 'authorizations', 'secret-output-' + hash(row.path) + '.json') ||
    row.result?.exitCode !== 0 || row.result.signal !== null || row.result.errorCode !== null ||
    row.environment?.codeLoadingValidated !== true || !/^[a-f0-9]{64}$/.test(row.environment.sha256) ||
    !Array.isArray(row.environment.variables) || row.environment.variables.some(value => typeof value.name !== 'string' || !/^[a-f0-9]{64}$/.test(value.valueSha256)) ||
    !isDeepStrictEqual(row.producer, secretProducer(config, row.command, row.args, row.path)) ||
    row.file?.path !== row.path || row.file.type !== 'file' || !/^[a-f0-9]{64}$/.test(row.file.sha256) ||
    ![...config.roots, ...config.outputs].some(root => inside(root, row.path))) throw new Error('secret removal authorization');
  const record = { path: row.path, sha256: row.file.sha256, purpose: 'SECRET_OUTPUT' };
  const name = hash(JSON.stringify(record));
  if (!isDeepStrictEqual(read(join(capture, 'private', 'records', name + '.json')), record)) throw new Error('secret removal original purpose');
  const storagePath = join(capture, 'private', 'bytes', row.file.sha256), storage = binding(storagePath);
  const identities = fs.readFileSync(join(capture, 'private', 'identities', name + '.jsonl'), 'utf8').trim().split('\n').map(line => JSON.parse(line));
  if (!identities.length || identities.some(observed => {
    const { parents, storage: retained, ...file } = observed;
    return !isDeepStrictEqual(file, row.file) || !isDeepStrictEqual(parents, row.parents) || !isDeepStrictEqual(retained, anchor(storagePath));
  })) throw new Error('secret removal original identity');
  const bytes = fs.readFileSync(storagePath);
  if (hash(bytes) !== row.file.sha256 || !isDeepStrictEqual(storage, binding(storagePath))) throw new Error('secret removal retained payload');
  return { storagePath, storage, bytes, authorizationSha256: hash(fs.readFileSync(path)) };
}
function privateBytes(config, path) {
  const permission = createRequire(import.meta.url)(join(config.root, 'dist/platform/owner-only.js'));
  const info = fs.lstatSync(path);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > 65_536) throw new Error('secret removal object');
  if (process.platform === 'win32') {
    const descriptor = permission.readSecurityDescriptors([path])[0];
    if (!descriptor || !permission.isOwnerOnlySecurityDescriptor(descriptor.sddl, descriptor.ownerSid, permission.currentUserSid(), 'file')) throw new Error('secret removal permissions');
  }
  return Buffer.from(permission.readOwnerOnlyFile(path, 65_536));
}
export function secretOutputMutation(capture, path, operation = 'write') {
  for (const row of removalRecords(capture)) {
    if (!inside(path, row.path) && !inside(row.path, path)) continue;
    // Repeated cleanup cannot recreate an already removed key or refresh proof.
    if (row.state === 'closed' && ['unlink', 'rm', 'rmdir'].includes(operation) && absent(row.path)) continue;
    row.state = 'invalid'; store(capture, row);
    throw new Error('secret removal overlapping mutation');
  }
}
export function beginSecretRemovals(capture, config, target, operation, writingPaths = []) {
  if (!target || !['unlink', 'rm', 'rmdir'].includes(operation)) return [];
  const prepared = [];
  for (const name of fs.readdirSync(join(capture, 'private', 'authorizations')).filter(name => /^secret-output-[a-f0-9]{64}\.json$/.test(name))) {
    const path = join(capture, 'private', 'authorizations', name), row = read(path);
    if (row.kind !== undefined || typeof row.path !== 'string' || !inside(target, row.path)) continue;
    const existing = removalRecords(capture).find(proof => proof.path === row.path);
    if (existing?.state === 'closed' && absent(row.path)) continue;
    if (existing || row.prospective !== true || row.state !== 'closed') throw new Error('secret removal unproved output');
    fs.mkdirSync(directory(capture), { recursive: true, mode: 0o700 });
    const proof = { version: 1, purpose: 'SECRET_OUTPUT_REMOVAL', state: 'pending', path: row.path,
      authorizationSha256: hash(fs.readFileSync(path)), file: row.file, parents: row.parents,
      operation: { name: operation, target }, permissionsValidated: false };
    store(capture, proof, true);
    try {
      const retained = authorization(capture, config, path, row);
      if (!isDeepStrictEqual(row.file, binding(row.path)) || !isDeepStrictEqual(row.parents, ancestry(dirname(row.path))) ||
        writingPaths.some(writable => inside(writable, row.path) || inside(row.path, writable))) throw new Error('secret removal changed output');
      if (!privateBytes(config, row.path).equals(retained.bytes) || !isDeepStrictEqual(row.file, binding(row.path)) ||
        read(recordPath(capture, row.path)).state !== 'pending') throw new Error('secret removal changed payload');
      proof.storage = retained.storage; proof.permissionsValidated = true;
      store(capture, proof); prepared.push(proof);
    } catch (error) { proof.state = 'invalid'; store(capture, proof); throw error; }
  }
  return prepared;
}
export function finishSecretRemovals(capture, prepared, error) {
  let valid = true;
  for (const proof of prepared) {
    try {
      if (error || !isDeepStrictEqual(read(recordPath(capture, proof.path)), proof) || !absent(proof.path) ||
        hash(fs.readFileSync(join(capture, 'private', 'authorizations', 'secret-output-' + hash(proof.path) + '.json'))) !== proof.authorizationSha256 ||
        !isDeepStrictEqual(binding(join(capture, 'private', 'bytes', proof.file.sha256)), proof.storage) ||
        proof.parents.some(parent => !inside(proof.operation.target, parent.path) && !isDeepStrictEqual(anchor(parent.path),
          Object.fromEntries(Object.entries(parent).filter(([key]) => key !== 'path'))))) throw new Error('secret removal incomplete');
      proof.state = 'closed'; proof.result = { success: true, absent: true };
      store(capture, proof);
    } catch {
      proof.state = 'invalid'; store(capture, proof); valid = false;
    }
  }
  return valid;
}
export function removedSecretOutput(capture, config, path, row) {
  const retained = authorization(capture, config, path, row), proof = read(recordPath(capture, row.path));
  if (proof.version !== 1 || proof.purpose !== 'SECRET_OUTPUT_REMOVAL' || proof.state !== 'closed' || proof.path !== row.path ||
    proof.authorizationSha256 !== retained.authorizationSha256 || !isDeepStrictEqual(proof.file, row.file) ||
    !isDeepStrictEqual(proof.parents, row.parents) || !isDeepStrictEqual(proof.storage, retained.storage) || proof.permissionsValidated !== true ||
    !['unlink', 'rm', 'rmdir'].includes(proof.operation?.name) || proof.operation.target !== resolve(proof.operation.target) ||
    !inside(proof.operation.target, row.path) || proof.result?.success !== true || proof.result.absent !== true || !absent(row.path) ||
    hash(privateBytes(config, retained.storagePath)) !== row.file.sha256) throw new Error('secret removal proof');
  return { path: retained.storagePath, storage: retained.storage, names: proof.parents.map(parent => parent.path) };
}