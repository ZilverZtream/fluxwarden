// Typed authorization for the specified operator-key producer, never an INPUT declaration.
import fs from 'node:fs';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { createRequire } from 'node:module';
import { resolve, join, dirname, relative, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
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
        || JSON.stringify(row.producer) !== JSON.stringify(secretProducer(config, row.command, row.args, row.path))
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
