import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, realpathSync } from 'node:fs';
import { isAbsolute, relative, resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import Ajv2020 from 'ajv/dist/2020.js';
import { asRecord, readJson } from './cli.js';
import { LabInvalidError, rows } from './cp006-oracle.js';

export type SourceProfile = 'credential-primary-v1' | 'credential-wire-v1';
interface Source { repository: string; path: string; file: string; sha256: string }
interface Repository { id: string; url: string; revision: string; commit: string; gitRoot: string }
const contract = asRecord(readJson('labs/fixtures/credential-reference-contract.json'), 'canonical credential source contract');
const validateManifest = new Ajv2020.default({ strict: true }).compile(readJson('labs/fixtures/credential-source-manifest.schema.json') as object);
const digest = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
const same = isDeepStrictEqual;
function absolute(value: unknown): string {
  if (typeof value !== 'string' || !isAbsolute(value)) throw new LabInvalidError('canonical source requires an absolute path'); return resolve(value);
}
function inside(root: string, path: string): boolean {
  const part = relative(root, path); return part !== '' && !part.startsWith('..') && !isAbsolute(part);
}

/** Semantic identity checks precede every file/Git read. Counts are a consequence
 * of the exact approved path set, never evidence of permission/wire coverage. */
export function sourceManifestIdentity(raw: unknown, profile: SourceProfile): { repositories: Repository[]; sources: Source[] } {
  if (!validateManifest(raw)) throw new LabInvalidError('canonical credential source manifest schema mismatch');
  const value = asRecord(raw, 'pinned source manifest'), profiles = asRecord(contract['profiles'], 'canonical source profiles');
  if (value['version'] !== 2 || value['profile'] !== profile) throw new LabInvalidError('exact version2 credential source profile required');
  const expected = rows(profiles[profile], 'canonical source identities');
  const sources = rows(value['sources'], 'source identities'), repositories = rows(value['repositories'], 'source repositories');
  const identities = sources.map(source => `${String(source['repository'])}:${String(source['path'])}`);
  if (new Set(identities).size !== identities.length || !same([...identities].sort(), expected.map(source => `${String(source['repository'])}:${String(source['path'])}`).sort())) {
    throw new LabInvalidError('canonical credential source identities missing duplicated substituted or extra');
  }
  const pins = asRecord(contract['repositories'], 'canonical repository pins');
  if (repositories.length !== 2 || !same(repositories.map(repo => repo['id']).sort(), ['cln', 'lnd'])) throw new LabInvalidError('exact two pinned source repositories required');
  for (const repo of repositories) {
    const pin = asRecord(pins[String(repo['id'])], 'canonical repository');
    for (const field of ['url', 'revision', 'commit']) if (repo[field] !== pin[field]) throw new LabInvalidError('canonical upstream repository pin mismatch');
    absolute(repo['gitRoot']);
  }
  for (const source of sources) {
    const gold = expected.find(gold => gold['repository'] === source['repository'] && gold['path'] === source['path']);
    if (source['sha256'] !== gold?.['sha256']) throw new LabInvalidError('canonical upstream source hash mismatch');
    absolute(source['file']);
  }
  if (!same(value['aliases'], profile === 'credential-wire-v1' ? contract['wireAliases'] : [])) throw new LabInvalidError('explicit pinned invokerune alias required only in wire profile');
  return { repositories: repositories as unknown as Repository[], sources: sources as unknown as Source[] };
}

function git(root: string, args: string[]): Buffer {
  const run = spawnSync('git', args, { cwd: root, shell: false, windowsHide: true, timeout: 15000, maxBuffer: 16 * 1024 * 1024 });
  if (run.error || run.status !== 0) throw new LabInvalidError('pinned upstream Git object unavailable'); return run.stdout;
}
function checkedSource(path: string): Buffer {
  const before = lstatSync(path), canonical = realpathSync(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size < 1 || before.size > 16 * 1024 * 1024 ||
      (process.platform === 'win32' ? canonical.toLowerCase() !== resolve(path).toLowerCase() : canonical !== resolve(path))) {
    throw new LabInvalidError('pinned source requires a bounded canonical nonlink file');
  }
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const after = fstatSync(fd);
    if (before.ino !== after.ino || before.dev !== after.dev || before.size !== after.size) throw new LabInvalidError('pinned source changed during descriptor read');
    return readFileSync(fd);
  } finally { closeSync(fd); }
}
export function verifySourceManifest(path: string, profile: SourceProfile, staticRoot: string): void {
  const manifest = sourceManifestIdentity(JSON.parse(checkedSource(path).toString('utf8')) as unknown, profile);
  for (const file of [path, ...manifest.sources.map(source => source.file), ...manifest.repositories.map(repo => repo.gitRoot)]) {
    if (!inside(resolve(staticRoot), resolve(file))) throw new LabInvalidError('immutable source input escaped its declared static root');
  }
  for (const repo of manifest.repositories) {
    const revision = git(repo.gitRoot, ['rev-parse', `${repo.revision}^{commit}`]).toString('utf8').trim();
    const origin = git(repo.gitRoot, ['remote', 'get-url', 'origin']).toString('utf8').trim().replace(/\.git$/, '');
    if (revision !== repo.commit || origin !== repo.url) throw new LabInvalidError('actual Git revision or repository identity mismatch');
  }
  for (const source of manifest.sources) {
    const repo = manifest.repositories.find(repo => repo.id === source.repository);
    if (!repo || digest(checkedSource(source.file)) !== source.sha256 || digest(git(repo.gitRoot, ['show', `${repo.commit}:${source.path}`])) !== source.sha256) {
      throw new LabInvalidError('local source bytes or pinned Git object hash mismatch');
    }
  }
}
