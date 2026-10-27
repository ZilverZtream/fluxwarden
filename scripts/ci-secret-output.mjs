// Typed authorization for the specified operator-key producer, never an INPUT declaration.
import fs from 'node:fs';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { createRequire } from 'node:module';
import { resolve, join, dirname, relative, sep } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { hash, inside, binding, ancestry, namespace, equivalents, files } from './ci-capture-files.mjs';

export async function authorizeSecretOutput(options) {
  if (!process.env.FLUXWARDEN_CI_CAPTURE) return;
  // Node.js/node doc/api/modules.md: require(esm) shares the native ESM module
  // instance. The test runner's transformed import would install a second recorder.
  const { authorizeOwnedSecretOutput } = createRequire(import.meta.url)('./ci-capture-preload.mjs');
  return authorizeOwnedSecretOutput(options);
}

export function secretProducer(config, command, args, path) {
  if (command !== process.execPath || !Array.isArray(args) || args.some(arg => typeof arg !== 'string')) throw new Error('secret output producer');
  const pkg = JSON.parse(fs.readFileSync(join(config.root, 'package.json'), 'utf8'));
  const binary = resolve(config.root, typeof pkg.bin === 'string' ? pkg.bin : pkg.bin?.fluxwarden ?? '');
  const expected = [binary, '--json', 'keys', 'generate', '--out', path];
  if (!inside(join(config.root, 'dist'), binary) || JSON.stringify(args) !== JSON.stringify(expected)) throw new Error('secret output invocation');
  return { binary: binding(binary), parents: ancestry(dirname(binary)), package: binding(join(config.root, 'package.json')), builtSha256: hash(JSON.stringify(namespace([join(config.root, 'dist')]))) };
}

// The pinned archive producer (src/persistence/state-archive.ts copyPrivate)
// creates and verifies private directories/empty files before copying bytes.
// Compare its complete compiled tree to this owned tool's build, then bind the
// actual invocation/tree/config/source and existing exclusive parent namespace.
export function stateCopyProducer(config, command, args, path, sourcePath) {
  if (command !== process.execPath || !Array.isArray(args) || args.length !== 8 || args.some(arg => typeof arg !== 'string')) throw new Error('state output invocation');
  const pkgPath = join(config.root, 'package.json'), pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  const binary = resolve(config.root, typeof pkg.bin === 'string' ? pkg.bin : pkg.bin?.fluxwarden ?? '');
  const operation = args[3], bundle = args[5], configPath = args[7];
  if (!inside(join(config.root, 'dist'), binary) || args[0] !== binary || args[1] !== '--json' || args[2] !== 'state'
    || !['backup', 'restore'].includes(operation) || args[4] !== (operation === 'backup' ? '--out' : '--from') || args[6] !== '--config'
    || bundle !== resolve(bundle) || configPath !== resolve(configPath) || sourcePath !== resolve(sourcePath)) throw new Error('state output invocation');
  const tree = root => files(root).filter(path => /\.(?:js|json)$/.test(path)).map(path => [relative(root, path).split(sep).join('/'), hash(fs.readFileSync(path))]).sort((a, b) => a[0].localeCompare(b[0]));
  if (!isDeepStrictEqual(tree(join(config.root, 'dist')), tree(fileURLToPath(new URL('../dist', import.meta.url))))) throw new Error('state output creation ordering');
  const require = createRequire(import.meta.url);
  const { loadConfig } = require(join(config.root, 'dist/config/config.js'));
  const { checkPrivateDirectory } = require(join(config.root, 'dist/persistence/paths.js'));
  const permission = require(join(config.root, 'dist/platform/owner-only.js'));
  const loaded = loadConfig(configPath), root = operation === 'backup' ? bundle : dirname(loaded.database);
  const expectedSource = operation === 'backup' ? join(dirname(loaded.database), 'outbox.key') : join(bundle, 'outbox.key');
  if (path !== join(root, 'outbox.key') || sourcePath !== expectedSource || sourcePath === path
    || operation === 'restore' && resolve(loaded.alertDir) !== join(root, 'alerts')) throw new Error('state output source');
  checkPrivateDirectory(dirname(root)); checkPrivateDirectory(dirname(sourcePath));
  const before = binding(sourcePath), bytes = Buffer.from(permission.readOwnerOnlyFile(sourcePath, 32));
  if (bytes.length !== 32 || !isDeepStrictEqual(before, binding(sourcePath))) throw new Error('state output exact source');
  return { executable: binding(command), binary: binding(binary), package: binding(pkgPath), builtSha256: hash(JSON.stringify(namespace([join(config.root, 'dist')]))),
    config: binding(configPath), source: before, sourceParents: ancestry(dirname(sourcePath)), operation, root, bundle,
    database: loaded.database, alertDir: loaded.alertDir, ancestor: ancestry(dirname(root)),
    ...(operation === 'restore' ? { input: namespace([bundle]), manifest: verifyStateBundle(config, bundle) } : {}) };
}

function immutableDatabase(path, work) {
  // As in src/persistence/db.ts, acquire SQLite only when it is used: Node22
  // otherwise emits its experimental warning in unrelated captured children.
  const { DatabaseSync } = process.getBuiltinModule('node:sqlite');
  const before = binding(path), url = pathToFileURL(path);
  url.searchParams.set('mode', 'ro'); url.searchParams.set('immutable', '1');
  const db = new DatabaseSync(url, { readOnly: true });
  let result;
  try {
    if (db.prepare('PRAGMA integrity_check').get().integrity_check !== 'ok') throw new Error('state output database integrity');
    result = work(db);
  } finally { db.close(); }
  if (!isDeepStrictEqual(before, binding(path))) throw new Error('state output database changed');
  return result;
}

function verifyStateBundle(config, root) {
  const require = createRequire(import.meta.url);
  const { checkPrivateFiles } = require(join(config.root, 'dist/persistence/paths.js'));
  const { SCHEMA_VERSION } = require(join(config.root, 'dist/persistence/schema.js'));
  const { readEffect } = require(join(config.root, 'dist/output/effects.js'));
  const all = namespace([root]), manifestPath = join(root, 'manifest.json');
  checkPrivateFiles(all.filter(row => row.type === 'file').map(row => row.path), all.filter(row => row.type === 'directory').map(row => row.path));
  if (!isDeepStrictEqual(all.filter(row => row.type === 'directory').map(row => row.path).sort(), [root, join(root, 'runs'), join(root, 'alerts')].sort())) throw new Error('state output bundle directories');
  if (fs.statSync(manifestPath).size > 16 * 1024 * 1024) throw new Error('state output manifest bound');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  if (manifest.format !== 1 || manifest.schema !== SCHEMA_VERSION || !Array.isArray(manifest.files) || !Array.isArray(manifest.nodes)
    || !isDeepStrictEqual(Object.keys(manifest).sort(), ['files', 'format', 'nodes', 'schema'])) throw new Error('state output manifest');
  const names = new Set(), key = fs.readFileSync(join(root, 'outbox.key'));
  if (key.length !== 32) throw new Error('state output key');
  for (const item of manifest.files) {
    if (typeof item.path !== 'string' || names.has(item.path) || !isDeepStrictEqual(Object.keys(item).sort(), ['bytes', 'path', 'sha256'])
      || !(item.path === 'state.sqlite3' || item.path === 'outbox.key' || /^runs\/run_[0-9A-HJKMNP-TV-Z]{26}\.json$/.test(item.path)
        || /^alerts\/(?!\.)[a-zA-Z0-9_%=.-]+\.json$/.test(item.path))
      || !Number.isSafeInteger(item.bytes) || item.bytes < 0 || !/^[0-9a-f]{64}$/.test(item.sha256)) throw new Error('state output payload identity');
    names.add(item.path);
    const path = join(root, item.path), info = fs.lstatSync(path);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size !== item.bytes || hash(fs.readFileSync(path)) !== item.sha256
      || item.path.startsWith('alerts/') && readEffect(path, key).state !== 'valid') throw new Error('state output payload');
  }
  if (!names.has('state.sqlite3') || !names.has('outbox.key') || !isDeepStrictEqual([...names, 'manifest.json'].sort(),
    all.filter(row => row.type === 'file').map(row => relative(root, row.path).split(sep).join('/')).sort())) throw new Error('state output complete inventory');
  immutableDatabase(join(root, 'state.sqlite3'), db => {
    if (db.prepare('PRAGMA user_version').get().user_version !== manifest.schema || !isDeepStrictEqual(
      JSON.parse(JSON.stringify(db.prepare('SELECT id,name,implementation,expected_pubkey AS pubkey FROM nodes ORDER BY id').all())), [...manifest.nodes].sort((a, b) => a.id.localeCompare(b.id)))) throw new Error('state output node identities');
  });
  return manifest;
}

export function verifyStateCopy(config, row, snapshotPath) {
  const expected = stateCopyProducer(config, row.command, row.args, row.path, row.sourcePath);
  if (!isDeepStrictEqual(row.producer, expected)) throw new Error('state output source or producer changed');
  const require = createRequire(import.meta.url), permission = require(join(config.root, 'dist/platform/owner-only.js'));
  const { checkPrivateFiles } = require(join(config.root, 'dist/persistence/paths.js'));
  // Only the immediate child result is compared as financial state. Closing
  // verification rechecks that immutable snapshot, never the later live DB.
  const contents = snapshotPath ? row.closedNamespace : namespace([expected.root]);
  if (!snapshotPath) checkPrivateFiles(contents.filter(row => row.type === 'file').map(row => row.path), contents.filter(row => row.type === 'directory').map(row => row.path));
  else checkPrivateFiles([row.path, snapshotPath], [expected.root]);
  if (expected.operation === 'restore' && !isDeepStrictEqual(contents.filter(row => row.type === 'directory').map(row => row.path).sort(),
    [expected.root, expected.alertDir].sort())) throw new Error('state output restored directories');
  const bytes = Buffer.from(permission.readOwnerOnlyFile(row.path, 32));
  if (bytes.length !== 32 || !bytes.equals(Buffer.from(permission.readOwnerOnlyFile(row.sourcePath, 32)))) throw new Error('state output bytes');
  const manifest = verifyStateBundle(config, expected.bundle);
  if (expected.operation === 'restore') {
    immutableDatabase(join(expected.bundle, 'state.sqlite3'), source => immutableDatabase(snapshotPath ?? expected.database, target => {
      if (target.prepare('PRAGMA user_version').get().user_version !== manifest.schema || target.prepare('SELECT pending FROM restore_barrier WHERE id=1').get()?.pending !== 1) throw new Error('state output admission');
      const required = target.prepare('SELECT node_id AS id,implementation,pubkey FROM restore_required_nodes ORDER BY node_id').all();
      const identities = manifest.nodes.map(({ id, implementation, pubkey }) => ({ id, implementation, pubkey })).sort((a, b) => a.id.localeCompare(b.id));
      if (!isDeepStrictEqual(JSON.parse(JSON.stringify(required)), identities)) throw new Error('state output required admission');
      for (const { name } of source.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('restore_barrier','restore_required_nodes') ORDER BY name").all()) {
        const sql = 'SELECT * FROM "' + name.replace(/"/g, '""') + '"';
        const before = source.prepare(sql), after = target.prepare(sql);
        before.setReadBigInts(true); after.setReadBigInts(true);
        if (!isDeepStrictEqual(before.all(), after.all())) throw new Error('state output restored rows');
      }
    }));
    const expectedFiles = [expected.database];
    for (const item of manifest.files.filter(item => item.path !== 'state.sqlite3')) {
      const path = item.path === 'outbox.key' ? row.path : item.path.startsWith('alerts/') ? join(expected.alertDir, item.path.slice(7)) : `${expected.database}.${item.path.slice(5)}`;
      expectedFiles.push(path);
      const actual = contents.find(row => row.path === path);
      if (!actual || actual.sha256 !== item.sha256 || actual.size !== String(item.bytes)) throw new Error('state output restored payload');
    }
    if (!isDeepStrictEqual(contents.filter(row => row.type === 'file').map(row => row.path).sort(), expectedFiles.sort())) throw new Error('state output restored inventory');
  }
  return { bytes, contents };
}

export function producerEnvironment(options) {
  const env = {};
  for (const name in options?.env ?? process.env) {
    const value = (options?.env ?? process.env)[name];
    if (value !== undefined) env[name] = String(value);
  }
  if (Object.entries(env).some(([name, value]) => /^(?:NODE_OPTIONS|NODE_PATH)$/i.test(name) && value.trim() !== '')) throw new Error('secret output code-loading environment');
  // Match Node's Windows case-alias selection while retaining the exact snapshot
  // passed to spawn. Values stay private fingerprints, never public environment text.
  const seen = new Set();
  const entries = Object.keys(env).sort().filter(name => {
    const key = process.platform === 'win32' ? name.toUpperCase() : name;
    if (seen.has(key)) return false;
    seen.add(key); return true;
  }).map(name => [name, env[name]]);
  return { env, identity: { origin: options?.env ? 'explicit' : 'inherited', codeLoadingValidated: true,
    sha256: hash(JSON.stringify(entries)), variables: entries.map(([name, value]) => ({ name, valueSha256: hash(value) })) } };
}

export async function secretOutputs(capture, config) {
  const approved = [];
  let valid = true;
  for (const path of files(join(capture, 'private', 'authorizations')).filter(path => /secret-output-[0-9a-f]{64}\.json$/.test(path))) {
    try {
      const row = JSON.parse(fs.readFileSync(path, 'utf8'));
      if (row.purpose === 'SECRET_OUTPUT' && row.prospective === false && row.state === 'not-produced' && row.result.exitCode !== 0) continue;
      if (row.purpose !== 'SECRET_OUTPUT' || row.prospective !== true || row.state !== 'closed' || row.path !== resolve(row.path)
        || path !== join(capture, 'private', 'authorizations', 'secret-output-' + hash(row.path) + '.json')
        || row.result.exitCode !== 0 || row.result.signal !== null || row.result.errorCode !== null
        || row.environment?.codeLoadingValidated !== true || !/^[0-9a-f]{64}$/.test(row.environment.sha256)
        || !Array.isArray(row.environment.variables) || row.environment.variables.some(value => typeof value.name !== 'string' || !/^[0-9a-f]{64}$/.test(value.valueSha256))
        || row.kind !== undefined && row.kind !== 'state-outbox-copy'
        || JSON.stringify(row.producer) !== JSON.stringify(row.kind ? stateCopyProducer(config, row.command, row.args, row.path, row.sourcePath) : secretProducer(config, row.command, row.args, row.path))
        || JSON.stringify(row.file) !== JSON.stringify(binding(row.path))
        || JSON.stringify(row.parents) !== JSON.stringify(ancestry(dirname(row.path)))) throw new Error('secret output custody');
      const info = fs.lstatSync(row.path);
      if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) throw new Error('secret output object');
      const permission = await import(pathToFileURL(join(config.root, 'dist/platform/owner-only.js')).href);
      if (process.platform === 'win32') {
        const descriptor = permission.readSecurityDescriptors([row.path])[0];
        if (!descriptor || !permission.isOwnerOnlySecurityDescriptor(descriptor.sddl, descriptor.ownerSid, permission.currentUserSid(), 'file')) throw new Error('secret output permissions');
      }
      const bytes = Buffer.from(permission.readOwnerOnlyFile(row.path, 65_536));
      if (row.kind === 'state-outbox-copy') {
        if (!isDeepStrictEqual(row.environment, row.intendedEnvironment)) throw new Error('state output environment custody');
        let snapshotPath;
        if (row.producer.operation === 'restore') {
          snapshotPath = join(capture, 'private', 'bytes', row.restoreSnapshot?.sha256 ?? '');
          const original = row.closedNamespace.find(item => item.path === row.producer.database);
          if (!original || original.sha256 !== row.restoreSnapshot?.sha256 || !isDeepStrictEqual(row.restoreSnapshot, binding(snapshotPath))) throw new Error('state output restore snapshot custody');
        }
        const closed = verifyStateCopy(config, row, snapshotPath);
        if (!snapshotPath && !isDeepStrictEqual(closed.contents, row.closedNamespace)) throw new Error('state output namespace changed');
        const responsePath = join(capture, 'secret-output-' + hash(row.path) + '.stdout.log');
        const stderrPath = join(capture, 'secret-output-' + hash(row.path) + '.stderr.log');
        if (fs.statSync(responsePath).size > 65_536 || fs.statSync(stderrPath).size > 65_536) throw new Error('state output response bound');
        const responseBytes = fs.readFileSync(responsePath), stderrBytes = fs.readFileSync(stderrPath);
        if (hash(responseBytes) !== row.stdoutSha256 || hash(stderrBytes) !== row.stderrSha256) throw new Error('state output response custody');
        const response = JSON.parse(responseBytes.toString('utf8'));
        if (response.command !== `state ${row.producer.operation}` || response.error !== null || !isDeepStrictEqual(response.result,
          row.producer.operation === 'backup' ? { backed_up: true } : { restored: true, reconciliation_required: true })) throw new Error('state output response');
        approved.push({ path: row.path, sha256: hash(bytes), authorizationSha256: hash(fs.readFileSync(path)), fingerprints: equivalents(bytes).map(hash) });
        continue;
      }
      const key = createPrivateKey(bytes);
      if (key.asymmetricKeyType !== 'ed25519' || !Buffer.from(key.export({ type: 'pkcs8', format: 'pem' })).equals(bytes)) throw new Error('secret output key');
      const raw = Buffer.from(createPublicKey(key).export({ format: 'jwk' }).x, 'base64url');
      const responsePath = join(capture, 'secret-output-' + hash(row.path) + '.stdout.log');
      const stderrPath = join(capture, 'secret-output-' + hash(row.path) + '.stderr.log');
      if (fs.statSync(responsePath).size > 65_536 || fs.statSync(stderrPath).size > 65_536) throw new Error('secret output response bound');
      const responseBytes = fs.readFileSync(responsePath);
      if (hash(responseBytes) !== row.stdoutSha256 || hash(fs.readFileSync(stderrPath)) !== row.stderrSha256) throw new Error('secret output response custody');
      const response = JSON.parse(responseBytes.toString('utf8'));
      if (response.command !== 'keys generate' || response.error !== null
        || response.result?.public_key !== raw.toString('base64') || response.result?.key_id !== hash(raw).slice(0, 32)
        || JSON.stringify(Object.keys(response.result).sort()) !== JSON.stringify(['key_id', 'public_key'])) throw new Error('secret output response');
      approved.push({ path: row.path, sha256: hash(bytes), keyId: hash(raw).slice(0, 32), authorizationSha256: hash(fs.readFileSync(path)), fingerprints: equivalents(bytes).map(hash) });
    } catch { valid = false; }
  }
  return { valid, approved };
}

// Supplemental attribution retains only existing SOURCE equivalents. The mandatory
// full-union pass is separate. One common recognizer excludes all admitted keys;
// small cross-key passes then prevent one admitted output from disclosing another.
export function unexpectedSecretMatches(capture, retained, approved, findLeaks) {
  if (!approved.length) return false;
  const population = new Map();
  for (const row of retained.filter(row => row.purpose === 'INPUT' || row.purpose === 'SECRET_OUTPUT')) for (const bytes of equivalents(fs.readFileSync(join(capture, 'private', 'bytes', row.sha256)))) population.set(hash(bytes), bytes);
  const expected = new Set(approved.flatMap(row => row.fingerprints));
  const scan = (fingerprints, paths) => {
    if (!fingerprints.length) return false;
    const sources = fingerprints.map(fingerprint => {
      const path = join(capture, 'private', 'bytes', fingerprint), bytes = population.get(fingerprint);
      if (!fs.existsSync(path)) fs.writeFileSync(path, bytes, { flag: 'wx', mode: 0o600 });
      if (!fs.readFileSync(path).equals(bytes)) throw new Error('secret output equivalent custody');
      return path;
    });
    const sentinels = join(capture, 'private', 'authorizations', 'secret-scan-' + hash(JSON.stringify(sources)) + '.json');
    const value = JSON.stringify(sources.map(path => relative(capture, path).split(sep).join('/')));
    if (!fs.existsSync(sentinels)) fs.writeFileSync(sentinels, value, { flag: 'wx', mode: 0o600 });
    if (fs.readFileSync(sentinels, 'utf8') !== value) throw new Error('secret output source context');
    return Boolean(findLeaks({ root: capture, sentinels, paths }));
  };
  if (scan([...population.keys()].filter(key => !expected.has(key)), approved.map(row => row.path))) return true;
  for (const row of approved) if (scan([...population.keys()].filter(key => expected.has(key) && !row.fingerprints.includes(key)), [row.path])) return true;
  return false;
}
