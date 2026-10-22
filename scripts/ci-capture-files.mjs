// Finite custody for the CI driver's five explicitly owned directories.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, join, relative, isAbsolute, sep, dirname } from 'node:path';

export const variables = ['TEMP', 'TMP', 'FLUXWARDEN_TEST_TMP', 'FLUXWARDEN_SENTINEL_DIR', 'FLUXWARDEN_EVIDENCE_DIR'];
export const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export const inside = (parent, path) => {
  const rel = relative(parent, path);
  return rel === '' || (!isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`));
};
// Node.js/node doc/api/fs.md: bigint file IDs plus realpath bind the observed
// object, while directory names bind its namespace independently of content.
export function anchor(path) {
  const info = fs.lstatSync(path, { bigint: true });
  if (info.isSymbolicLink() || (!info.isFile() && !info.isDirectory())) throw new Error('capture unsupported identity');
  return { realpath: fs.realpathSync.native(path), dev: String(info.dev), ino: String(info.ino), birthtimeNs: String(info.birthtimeNs), type: info.isDirectory() ? 'directory' : 'file' };
}
export function binding(path, stable = false) {
  const result = { path: resolve(path), ...anchor(path) };
  if (result.type === 'directory') result.entries = fs.readdirSync(path).sort();
  else if (!stable) {
    const info = fs.lstatSync(path, { bigint: true });
    result.size = String(info.size); result.mtimeNs = String(info.mtimeNs); result.ctimeNs = String(info.ctimeNs);
    result.sha256 = hash(fs.readFileSync(path));
  }
  return result;
}
export function ancestry(path) {
  const result = [];
  for (let current = resolve(path); ; current = dirname(current)) {
    result.push({ path: current, ...anchor(current) });
    if (dirname(current) === current) return result;
  }
}
export function namespace(paths, stable = new Set()) {
  const result = new Map();
  const visit = path => {
    const value = binding(path, stable.has(resolve(path)));
    if (result.has(value.path)) return;
    result.set(value.path, value);
    if (value.type === 'directory') for (const name of value.entries) visit(join(path, name));
  };
  for (const path of paths) visit(path);
  return [...result.values()].sort((a, b) => a.path.localeCompare(b.path));
}
export function files(path) {
  const stat = fs.lstatSync(path);
  if (stat.isSymbolicLink()) throw new Error('capture linked path');
  if (stat.isFile()) return [resolve(path)];
  if (!stat.isDirectory()) throw new Error('capture unsupported path');
  return fs.readdirSync(path).flatMap(name => files(join(path, name)));
}
export function directories(path) {
  const info = fs.lstatSync(path);
  if (info.isSymbolicLink()) throw new Error('capture linked namespace');
  if (!info.isDirectory()) return [];
  return [resolve(path), ...fs.readdirSync(path).flatMap(name => directories(join(path, name)))];
}
export function registered(root) {
  const globs = JSON.parse(fs.readFileSync(join(root, 'test/sentinels.json'), 'utf8'));
  if (!Array.isArray(globs) || !globs.length || globs.some(glob => typeof glob !== 'string')) throw new Error('capture source list');
  return [...new Set(globs.flatMap(glob => {
    const prefix = glob.split(/[?*]/, 1)[0];
    const base = resolve(root, prefix.endsWith('/') ? prefix : dirname(prefix));
    if (!inside(root, base)) throw new Error('capture source boundary');
    // Same finite glob grammar as scripts/leak-check.mjs.
    let expression = '';
    for (let i = 0; i < glob.length; i++) {
      const c = glob[i];
      if (c === '*' && glob[i + 1] === '*') {
        if (glob[i + 2] === '/') { expression += '(?:.*/)?'; i += 2; }
        else { expression += '.*'; i++; }
      } else if (c === '*') expression += '[^/]*';
      else if (c === '?') expression += '[^/]';
      else expression += c.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
    }
    const pattern = new RegExp(`^${expression}$`);
    const found = files(base).filter(path => pattern.test(relative(root, path).split(sep).join('/')));
    if (!found.length) throw new Error('capture missing source');
    return found;
  }))];
}

// Fingerprints only: these are the existing scanner's PEM, macaroon and NWC
// equivalences (scripts/leak-check.mjs sentinelSources). Recognition stays there.
export function equivalents(bytes) {
  const result = [bytes];
  for (const match of bytes.toString('latin1').matchAll(/-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----([\s\S]*?)-----END \1-----/g)) {
    const body = match[2].replace(/\s/g, '');
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(body)) result.push(Buffer.from(body, 'base64'));
  }
  if (bytes[0] === 2 && bytes.length > 35) {
    result.push(bytes.subarray(1));
    const at = bytes.lastIndexOf(Buffer.from([0, 6, 32]));
    const signature = at >= 0 && at + 35 <= bytes.length ? bytes.subarray(at + 3, at + 35) : null;
    if (signature && new Set(signature).size >= 16) result.push(signature);
  }
  for (const match of bytes.toString('latin1').matchAll(/(?:nostr\+walletconnect|nostrwalletconnect):[^\s"'<>]*?[?&]secret=([0-9a-f]{64})(?![0-9a-f])/gi)) result.push(Buffer.from(match[1], 'hex'));
  return result.filter(value => value.length);
}

export function retain(capture, path, purpose) {
  const observed = binding(path);
  const bytes = fs.readFileSync(path);
  const sha256 = hash(bytes);
  const stored = join(capture, 'private', 'bytes', sha256);
  try { fs.writeFileSync(stored, bytes, { flag: 'wx', mode: 0o600 }); }
  catch (error) { if (error.code !== 'EEXIST') throw error; }
  if (!fs.readFileSync(stored).equals(bytes) || observed.sha256 !== sha256 || JSON.stringify(observed) !== JSON.stringify(binding(path))) throw new Error('capture unstable retained file');
  const record = { path: resolve(path), sha256, purpose };
  if (purpose === 'EGRESS') {
    const output = { ...record, purpose: 'SECRET_OUTPUT' };
    const original = join(capture, 'private', 'records', hash(JSON.stringify(output)) + '.json');
    if (fs.existsSync(original) && fs.readFileSync(original, 'utf8') === JSON.stringify(output)) return output;
  }
  // One immutable record per original context and byte identity, shared safely by workers.
  const name = hash(JSON.stringify(record));
  try { fs.writeFileSync(join(capture, 'private', 'records', name + '.json'), JSON.stringify(record), { flag: 'wx', mode: 0o600 }); }
  catch (error) { if (error.code !== 'EEXIST') throw error; }
  if (purpose === 'INPUT' || purpose === 'SECRET_OUTPUT') {
    // Stable record names retain the original context; the observation stream
    // distinguishes source replacement during the owned lifetime from Closing.
    fs.appendFileSync(join(capture, 'private', 'identities', name + '.jsonl'), JSON.stringify({ ...observed, parents: ancestry(dirname(path)), storage: anchor(stored) }) + '\n', { mode: 0o600 });
  }
  return record;
}
