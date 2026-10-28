// Pinned-object verification follows test/helpers/cp008-source-contract.ts;
// private directory checks reuse MacWarden scripts/private-scratch.mjs.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { assertPrivateDirectory, realDirectory } from './private-scratch.mjs';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = () => new Error('credential-sources: pinned source validation failed');
function absolute(path) {
  if (typeof path !== 'string' || !isAbsolute(path)) throw fail();
  return resolve(path);
}
function overlaps(a, b) {
  const inside = (root, path) => {
    const part = relative(root, path);
    return part === '' || (!part.startsWith('..') && !isAbsolute(part));
  };
  return inside(a, b) || inside(b, a);
}
function git(root, args, input) {
  // No shell, checkout, hooks, upstream programs, or network transport.
  const run = spawnSync('git', ['-c', 'core.hooksPath=', ...args], {
    cwd: root, input, shell: false, windowsHide: true, timeout: 15_000, maxBuffer: 16 * 1024 * 1024,
    env: { ...process.env, GIT_NO_LAZY_FETCH: '1', GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null' },
  });
  if (run.error || run.status !== 0) throw fail();
  return run.stdout;
}
async function identity(root, pin) {
  await realDirectory(root);
  const revision = git(root, ['rev-parse', '--verify', `${pin.revision}^{commit}`]).toString('utf8').trim();
  const origin = git(root, ['remote', 'get-url', 'origin']).toString('utf8').trim().replace(/\.git$/, '');
  if (revision !== pin.commit || origin !== pin.url) throw fail();
}

/** Materialize only verified immutable Git inputs in a fresh static directory. */
export async function preparePinnedCredentialSources({ directory, checkouts }) {
  directory = absolute(directory);
  // Absence is checked before input work and mkdir itself is exclusive.
  try { await lstat(directory); throw fail(); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const contract = JSON.parse(await readFile(new URL('../labs/fixtures/credential-reference-contract.json', import.meta.url), 'utf8'));
  const roots = {};
  for (const id of ['macwarden', 'lnd', 'cln']) {
    roots[id] = absolute(checkouts?.[id]);
    if (overlaps(directory, roots[id])) throw fail();
    await identity(roots[id], contract.repositories[id]);
  }
  const inputs = [...contract.cp004, ...Object.values(contract.profiles).flat()];
  const bytes = new Map();
  const objects = {};
  for (const id of Object.keys(roots)) {
    const pin = contract.repositories[id];
    const names = new Set([pin.commit, `${pin.commit}^{tree}`]);
    for (const source of inputs.filter(source => source.repository === id)) {
      names.add(`${pin.commit}:${source.path}`);
      for (let parent = dirname(source.path); parent !== '.'; parent = dirname(parent)) {
        names.add(`${pin.commit}:${parent.replace(/\\/g, '/')}`);
      }
    }
    objects[id] = new Map();
    for (const name of names) {
      const oid = git(roots[id], ['rev-parse', '--verify', name]).toString('utf8').trim();
      const type = git(roots[id], ['cat-file', '-t', oid]).toString('utf8').trim();
      if (!/^[a-f0-9]{40}$/.test(oid) || !['commit', 'tree', 'blob'].includes(type)) throw fail();
      objects[id].set(oid, { type, content: git(roots[id], ['cat-file', type, oid]) });
    }
  }
  // Every identity and all 52 pinned file hashes are verified before any output.
  for (const source of inputs) {
    const pin = contract.repositories[source.repository];
    const content = git(roots[source.repository], ['show', `${pin.commit}:${source.path}`]);
    if (digest(content) !== source.sha256) throw fail();
    bytes.set(`${source.repository}:${source.path}`, content);
  }
  await assertPrivateDirectory(dirname(directory));
  await mkdir(directory, { mode: 0o700 });
  await assertPrivateDirectory(directory);
  const repositories = {};
  for (const id of ['macwarden', 'lnd', 'cln']) {
    const gitRoot = join(directory, id);
    // Copy exact objects for the selected paths. A partial upstream checkout can
    // lack unrelated blobs, so cloning its entire reachable graph is incorrect.
    git(directory, ['init', '--bare', '--', gitRoot]);
    for (const [oid, object] of objects[id]) {
      const written = git(gitRoot, ['hash-object', '-t', object.type, '-w', '--stdin'], object.content).toString('utf8').trim();
      if (written !== oid) throw fail();
    }
    const pin = contract.repositories[id];
    git(gitRoot, ['update-ref', 'refs/heads/pinned', pin.commit]);
    git(gitRoot, ['symbolic-ref', 'HEAD', 'refs/heads/pinned']);
    if (!/^[a-f0-9]+$/.test(pin.revision)) git(gitRoot, ['update-ref', `refs/tags/${pin.revision}`, pin.commit]);
    await writeFile(join(gitRoot, 'shallow'), `${pin.commit}\n`, { flag: 'wx', mode: 0o600 });
    git(gitRoot, ['remote', 'add', 'origin', pin.url]);
    await identity(gitRoot, pin);
    repositories[id] = { id, ...pin, gitRoot };
  }
  const files = new Map();
  for (const source of inputs) {
    const key = `${source.repository}:${source.path}`;
    if (files.has(key)) continue;
    const file = join(directory, 'sources', source.repository, source.path);
    await mkdir(dirname(file), { recursive: true, mode: 0o700 });
    await writeFile(file, bytes.get(key), { flag: 'wx', mode: 0o600 });
    files.set(key, file);
  }
  const paths = {};
  for (const [profile, sources] of Object.entries(contract.profiles)) {
    const manifest = {
      version: 2, profile, repositories: ['lnd', 'cln'].map(id => repositories[id]),
      sources: sources.map(source => ({ ...source, file: files.get(`${source.repository}:${source.path}`) })),
      aliases: profile === 'credential-wire-v1' ? contract.wireAliases : [],
    };
    paths[profile] = join(directory, `${profile}.json`);
    await writeFile(paths[profile], `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  }
  return { referenceRoot: repositories.macwarden.gitRoot, sourceManifest: paths['credential-primary-v1'], bindingSourceManifest: paths['credential-wire-v1'] };
}
