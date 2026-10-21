// Release packaging: the npm tarball, its installed command, the release and chaos workflows, the
// version and the changelog. Expected values follow the public specification (package identity,
// documentation set, exit codes) and the release plan (0.1.0, 0.2.0, 0.3.0, 1.0.0).
//
// Interface:
// - `npm run build` then `npm pack` (scripts allowed, so a `prepack` clean build is honoured) yields
//   `fluxwarden-<version>.tgz` holding only package.json, README.md, LICENSE, SECURITY.md,
//   CHANGELOG.md and compiled files under dist/ (`.js`, `.d.ts`, and their `.map` files), each
//   compiled from a file under src/ of the same relative path, plus dist/evidence/build-info.json
//   containing only the build's git commit; the installed package.json supplies its version.
// - `npm install --global --prefix <dir> --ignore-scripts --offline <tgz>` installs a working
//   `fluxwarden` command (Windows: `<dir>/fluxwarden.cmd`; elsewhere: `<dir>/bin/fluxwarden`).
// - `.github/workflows/release.yml`: triggered only by pushed `v*` tags; one job runs, in order,
//   `npm ci --ignore-scripts`, `npm run lint`, `npm run build`, `npm test`, `npm run test:harness`,
//   a tag/version comparison (GITHUB_REF_NAME or github.ref_name against package.json), `npm pack`,
//   `node scripts/leak-check.mjs` over the packed tarball, and `npm publish <file>.tgz`.
// - `.github/workflows/ci.yml` job `chaos`: dispatch only; runs `npm run test:chaos`, then
//   `node scripts/leak-check.mjs` over the evidence directory, then uploads that directory with a
//   pinned `actions/upload-artifact` step under `if: always()`; it reads no secret.
// - README.md has an `## Install` section with `npm install --global fluxwarden` (or `-g`).
import { spawn, spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { asRecord, childEnv, isRecord, readJson, readText, repoRoot } from '../helpers/cli.js';
import { testRoot } from '../helpers/env.js';
import { parseYaml, type Yaml } from '../helpers/yaml.js';
import { unlinkFixture } from '../helpers/fixture-links.js';
import { count, demo, rows, storedId } from '../helpers/cpw-cli.js';
import { channel, loadPersistence } from '../helpers/cp015-persistence.js';
import { CH3, CLN_R, HEIGHT, LND_R, MUTATING, S, SELF, T, methodsOf } from '../fakes/cln/rebalance-node.js';
import type { FakeServer } from '../fakes/https.js';

// Release plan: private validation releases 0.1.0, 0.2.0 and 0.3.0, then the public 1.0.0.
const RELEASES = ['0.1.0', '0.2.0', '0.3.0', '1.0.0'] as const;
const ENGINES = '^22.23.2 || ^24.18.1 || >=26.5.1';
const TOP_LEVEL = ['CHANGELOG.md', 'LICENSE', 'README.md', 'SECURITY.md', 'package.json'];
const RUNTIME_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'bundledDependencies'];
const INSTALL_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare'];
const BUILD_METADATA = 'dist/evidence/build-info.json';

function isBuildMetadata(path: string): boolean {
  return path === BUILD_METADATA;
}

function validBuildMetadata(value: unknown, commit: string): boolean {
  return isRecord(value) && Object.keys(value).length === 1 && /^[0-9a-f]{40}$/.test(commit) && value['gitCommit'] === commit;
}

function isForbiddenReleaseArtifact(path: string): boolean {
  if (isBuildMetadata(path)) return false;
  if (/(?:^|\/)(?:test|tests|labs|\.runtime|fixtures|recordings|sentinels)(?:\/|$)/.test(path)) return true;
  if (!/(?:^|\/)evidence(?:\/|$)/.test(path)) return false;
  // Evidence artifacts never ship; the compiled evidence runtime follows the same source provenance rule as other modules.
  if (!/^dist\/.+\.(?:js|d\.ts|js\.map|d\.ts\.map)$/.test(path)) return true;
  const source = path.slice('dist/'.length).replace(/\.(?:js|d\.ts)(?:\.map)?$/, '.ts');
  return !existsSync(join(repoRoot, 'src', source));
}

interface Packed { tarball: string; files: string[]; installedDir: string; prefix: string; manifest: Record<string, unknown> }
let packed: Packed | undefined;
let installedLink: string | undefined;

afterAll(() => {
  if (installedLink !== undefined) unlinkFixture(installedLink);
});

function npmCli(): string {
  const fromEnv = process.env['npm_execpath'];
  if (fromEnv !== undefined && /npm-cli\.js$/.test(fromEnv)) return fromEnv;
  return process.platform === 'win32'
    ? join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
    : join(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js');
}

function npm(args: readonly string[], cwd: string): SpawnSyncReturns<string> {
  const result = spawnSync(process.execPath, [npmCli(), ...args], { cwd, env: childEnv(), encoding: 'utf8', windowsHide: true, timeout: 240_000 });
  if (result.error !== undefined) throw result.error;
  return result;
}

function scratch(prefix: string): string {
  return mkdtempSync(join(testRoot('FLUXWARDEN_TEST_TMP'), `fw-release-${prefix}-`));
}

function filesUnder(directory: string): string[] {
  return readdirSync(directory).flatMap(name => {
    const path = join(directory, name);
    return statSync(path).isDirectory() ? filesUnder(path) : [path];
  });
}

function containsPrivatePath(text: string, roots: readonly string[]): boolean {
  return roots.some(root => {
    if (/^(?:[\\/]+|[A-Za-z]:[\\/]*)$/.test(root) || root.length === 0) return false;
    const clean = root.replace(/[\\/]+$/, '');
    const forms = new Set([clean, clean.replace(/\\/g, '/'), clean.replace(/\\/g, '\\\\')]);
    return [...forms].some(form => {
      const escaped = form.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      return new RegExp(`(?:^|[^A-Za-z0-9_./\\\\:~-]|\\bfile:\\/\\/\\/?)${escaped}(?=$|[\\\\/]|[^A-Za-z0-9_.~-])`).test(text);
    });
  });
}

function pkg(): Record<string, unknown> {
  return asRecord(readJson('package.json'), 'package.json');
}

function release(): Packed {
  if (packed === undefined) throw new Error('the release tarball was not produced');
  return packed;
}

beforeAll(() => {
  const build = npm(['run', '--silent', 'build'], repoRoot);
  if (build.status !== 0) throw new Error(`npm run build failed: ${build.stdout}${build.stderr}`);
  const destination = scratch('pack');
  const pack = npm(['pack', '--json', '--pack-destination', destination], repoRoot);
  if (pack.status !== 0) throw new Error(`npm pack failed: ${pack.stderr}`);
  const report: unknown = JSON.parse(pack.stdout);
  if (!Array.isArray(report) || report.length !== 1 || !isRecord(report[0])) throw new Error('npm pack reported no single package');
  const entry = report[0];
  const filename = entry['filename'];
  const files = entry['files'];
  if (typeof filename !== 'string' || !Array.isArray(files)) throw new Error('npm pack report lacks filename or files');
  const tarball = join(destination, filename);
  const prefix = scratch('prefix');
  if (process.platform !== 'win32') installedLink = join(prefix, 'bin', 'fluxwarden');
  const install = npm(['install', '--global', '--prefix', prefix, '--ignore-scripts', '--no-audit', '--no-fund', '--offline', tarball], scratch('install-cwd'));
  if (install.status !== 0) throw new Error(`installing the tarball failed: ${install.stderr}`);
  const installedDir = process.platform === 'win32' ? join(prefix, 'node_modules', 'fluxwarden') : join(prefix, 'lib', 'node_modules', 'fluxwarden');
  packed = {
    tarball,
    files: files.map(file => String(asRecord(file, 'packed file')['path']).replace(/\\/g, '/')),
    installedDir,
    prefix,
    manifest: asRecord(JSON.parse(readFileSync(join(installedDir, 'package.json'), 'utf8')), 'installed package.json'),
  };
}, 300_000);

function installed(args: readonly string[]): { status: number | null; stdout: string; stderr: string } {
  const { prefix } = release();
  const cwd = scratch('cwd');
  const options = { cwd, env: childEnv(), encoding: 'utf8' as const, windowsHide: true, timeout: 30_000 };
  // Windows runs the npm command shim through cmd.exe, as a user's shell does.
  const result = process.platform === 'win32'
    ? spawnSync(process.env['ComSpec'] ?? 'cmd.exe', ['/d', '/s', '/c', `"${join(prefix, 'fluxwarden.cmd')}" ${args.join(' ')}`], { ...options, windowsVerbatimArguments: true })
    : spawnSync(join(prefix, 'bin', 'fluxwarden'), [...args], options);
  if (result.error !== undefined) throw result.error;
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function installedAsync(args: readonly string[]): Promise<{ status: number | null; stdout: string; stderr: string }> {
  const { installedDir, manifest } = release();
  const binary = String(asRecord(manifest['bin'], 'installed bin')['fluxwarden']);
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(installedDir, binary), ...args], { cwd: scratch('cwd'), env: childEnv(), windowsHide: true, timeout: 10_000 });
    let stdout = '', stderr = '';
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stdout.on('data', (text: string) => { stdout += text; });
    child.stderr.on('data', (text: string) => { stderr += text; });
    child.on('error', reject);
    child.on('close', status => { resolve({ status, stdout, stderr }); });
  });
}

function envelopeOf(stdout: string): Record<string, unknown> {
  const text = stdout.endsWith('\n') ? stdout.slice(0, -1) : stdout;
  expect(text.includes('\n'), 'exactly one JSON document').toBe(false);
  return asRecord(JSON.parse(text), 'envelope');
}

it('CP-018/B1 the packed tarball holds exactly the allow-listed files: built dist, README, LICENSE, SECURITY.md, CHANGELOG.md and package.json', () => {
  const { files } = release();
  const outside = files.filter(path => !TOP_LEVEL.includes(path) && !isBuildMetadata(path) && !/^dist\/.+\.(?:js|d\.ts|js\.map|d\.ts\.map)$/.test(path));
  expect(outside, 'files outside the allow-list').toEqual([]);
  for (const name of TOP_LEVEL) expect(files, name).toContain(name);
  // Test sources, lab runtime state, recordings, fixtures and evidence artifacts never ship, even under dist/.
  expect(files.filter(isForbiddenReleaseArtifact)).toEqual([]);
  // Every compiled file comes from a current source file: no stale output from a removed module.
  const stale = files.filter(path => path.startsWith('dist/') && !isBuildMetadata(path)).filter(path => {
    const source = path.slice('dist/'.length).replace(/\.(?:js|d\.ts)(?:\.map)?$/, '.ts');
    return !existsSync(join(repoRoot, 'src', source));
  });
  expect(stale, 'compiled files without a source').toEqual([]);
  const bin = asRecord(pkg()['bin'], 'bin');
  expect(files).toContain(String(bin['fluxwarden']).replace(/^\.\//, ''));
  // SPEC evidence manifest provenance requires both the release version and git commit.
  expect(files).toContain(BUILD_METADATA);
  const current = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: repoRoot, encoding: 'utf8', windowsHide: true, timeout: 10_000 });
  expect(current.status, 'current checkout commit').toBe(0);
  const metadata: unknown = JSON.parse(readFileSync(join(release().installedDir, BUILD_METADATA), 'utf8'));
  expect(validBuildMetadata(metadata, current.stdout.trim()), 'exact current build metadata').toBe(true);
  expect(release().manifest['version'], 'installed release version').toBe(pkg()['version']);
});

it('CP-018/B1 compiled evidence code is permitted while evidence artifacts and stale modules remain prohibited', () => {
  expect(isForbiddenReleaseArtifact('dist/evidence/bundle.js')).toBe(false);
  expect(isForbiddenReleaseArtifact(BUILD_METADATA)).toBe(false);
  for (const path of ['evidence/bundle.js', 'dist/evidence/bundle.json', 'dist/evidence/manifest.json', 'dist/evidence/build-info.json.bak', 'dist/nested/evidence/build-info.json', 'dist/evidence/stale-private-fixture.js', 'dist/fixtures/bundle.js', 'dist/recordings/bundle.js', 'dist/sentinels/bundle.js']) {
    expect(isForbiddenReleaseArtifact(path), path).toBe(true);
  }
});

it('CP-018/B1 build metadata rejects missing stale malformed or extra fields and counterfeit metadata paths', () => {
  const commit = 'a'.repeat(40);
  expect(validBuildMetadata({ gitCommit: commit }, commit)).toBe(true);
  for (const value of [null, [], {}, { gitCommit: null }, { gitCommit: 'b'.repeat(40) }, { gitCommit: commit.toUpperCase() }, { gitCommit: commit, bundle: [] }, { gitCommit: commit, version: '1.0.0' }]) {
    expect(validBuildMetadata(value, commit)).toBe(false);
  }
  expect(validBuildMetadata({ gitCommit: 'invalid' }, 'invalid')).toBe(false);
  for (const path of ['evidence/build-info.json', 'dist/evidence/build-info.JSON', 'dist/evidence/../evidence/build-info.json', 'dist/evidence/build-info.json/manifest.json']) expect(isBuildMetadata(path), path).toBe(false);
});

it('CP-018/B1 a fresh tarball and its installed copy contain no registered sentinel in any encoding and no local path', async () => {
  const { tarball, installedDir } = release();
  const scanner = await import(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href) as {
    findLeaks(options: { sentinels: string; sentinelDir?: string; root: string; paths: string[] }): { path: string; encoding: string } | null;
  };
  const sentinelDir = testRoot('FLUXWARDEN_SENTINEL_DIR');
  const work = scratch('leak');
  // The tar stream (headers and contents uncompressed) and the installed tree are both scanned.
  const tar = gunzipSync(readFileSync(tarball));
  const tarPath = join(work, 'package.tar');
  writeFileSync(tarPath, tar);
  const sentinels = join(repoRoot, 'test', 'sentinels.json');
  expect(scanner.findLeaks({ sentinels, sentinelDir, root: repoRoot, paths: [tarPath, installedDir] })).toBeNull();

  // Control: the same scan finds a registered sentinel planted in a copy of the tarball.
  const registered: unknown = JSON.parse(readText('test/sentinels.json'));
  if (!Array.isArray(registered) || typeof registered[0] !== 'string') throw new Error('no registered sentinel');
  const planted = join(work, 'planted', 'package.tar');
  mkdirSync(dirname(planted));
  const plantedBytes = Buffer.concat([tar, Buffer.from(readFileSync(join(repoRoot, registered[0])).toString('base64'))]);
  let detectedEncoding: string | null = null;
  try {
    writeFileSync(planted, plantedBytes);
    const hit = scanner.findLeaks({ sentinels, sentinelDir, root: repoRoot, paths: [planted] });
    detectedEncoding = hit?.encoding ?? null;
    expect(hit, 'planted control is detected').not.toBeNull();
  } finally {
    try {
      writeFileSync(`${planted}.control.json`, `${JSON.stringify({ sha256: createHash('sha256').update(plantedBytes).digest('hex'), detectedEncoding })}\n`, { flag: 'wx', mode: 0o600 });
    } finally { if (existsSync(planted)) unlinkSync(planted); }
  }

  // Build machine paths (source maps, embedded file names) do not ship.
  const text = [tar.toString('latin1'), ...filesUnder(installedDir).map(path => readFileSync(path, 'latin1'))].join('\n');
  expect(containsPrivatePath(text, [repoRoot, homedir(), testRoot('FLUXWARDEN_EVIDENCE_DIR'), sentinelDir]), 'a local path ships').toBe(false);
});

it('CP-018/B1 private path checks reject full workspace evidence and sentinel components in every path spelling', () => {
  const roots = ['/work', '/private/evidence', '/private/sentinels', 'C:\\private\\workspace'];
  for (const root of roots) {
    for (const form of [root, root.replace(/\\/g, '/'), root.replace(/\\/g, '\\\\')]) {
      for (const text of [form, `"${form}"`, `${form}/private-file`, `path=${form}\\private-file`, `file://${form}/private-file`, `\0${form}\0`]) expect(containsPrivatePath(text, roots), text).toBe(true);
      for (const text of [`${form}flow`, `${form}-public`, `${form}.public`, `/prefix${form}/file`]) expect(containsPrivatePath(text, roots), text).toBe(false);
    }
  }
  for (const text of ['/workflow.js', '/workspace/file', 'ordinary /private/evidence-public/file', 'ordinary /private/sentinels2/file']) expect(containsPrivatePath(text, roots), text).toBe(false);
  for (const system of ['/', '\\', 'C:\\', 'C:/']) expect(containsPrivatePath('/ordinary/file C:\\ordinary\\file', [system])).toBe(false);
});

it('CP-018/B2 the installed tarball answers --version with the package version and --help with usage, both exit 0', () => {
  const { manifest, installedDir } = release();
  expect(manifest['version']).toBe(pkg()['version']);
  for (const field of RUNTIME_FIELDS) expect(manifest[field], field).toBeUndefined();
  expect(existsSync(join(installedDir, 'node_modules')), 'nothing installed beside the package').toBe(false);
  const bin = asRecord(manifest['bin'], 'installed bin');
  expect(readFileSync(join(installedDir, String(bin['fluxwarden'])), 'utf8').split('\n')[0]?.trim()).toBe('#!/usr/bin/env node');

  const version = installed(['--version']);
  expect(version.status).toBe(0);
  expect(version.stdout).toBe(`${String(pkg()['version'])}\n`);
  const help = installed(['--help']);
  expect(help.status).toBe(0);
  expect(help.stdout).toMatch(/fluxwarden/);
  expect(help.stdout).toMatch(/\bdoctor\b/);
});

it('CP-018/B2 the installed doctor and channels without a configuration exit 2 with one INVALID_INPUT document naming the command', () => {
  // SPEC §10.3 G3: an unreadable configuration (default ./fluxwarden.yaml, absent here) is exit 2.
  for (const command of [['doctor'], ['channels']]) {
    const run = installed([...command, '--json']);
    expect(run.status, command.join(' ')).toBe(2);
    const document = envelopeOf(run.stdout);
    expect(document['schema']).toBe(1);
    expect(document['command']).toBe(command.join(' '));
    expect(document['ok']).toBe(false);
    expect(document['result']).toBeNull();
    expect(asRecord(document['error'], 'error')['code']).toBe(2);
  }
});

it('CP-027/B2 the installed tarball dispatches liquidity plan and liquidity explain, refusing a missing configuration with exit 2', () => {
  for (const command of [['liquidity', 'plan'], ['liquidity', 'explain', 'proposal-1']]) {
    const run = installed([...command, '--json']);
    expect(run.status, command.join(' ')).toBe(2);
    const document = envelopeOf(run.stdout);
    expect(document['command']).toBe(command.slice(0, 2).join(' '));
    expect(asRecord(document['error'], 'error')['code']).toBe(2);
  }
});

it('CP-018/B2 the public release smoke command accepts the tested tarball and reports its source version', () => {
  const result = spawnSync(process.execPath, [join(repoRoot, 'scripts', 'release-smoke.mjs'), release().tarball], {
    cwd: repoRoot, env: childEnv(), encoding: 'utf8', windowsHide: true, timeout: 15_000,
  });
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
  expect(result.stdout).toContain(String(pkg()['version']));
  expect(installed(['--version'])).toEqual({ status: 0, stdout: `${String(pkg()['version'])}\n`, stderr: '' });
  expect(installed(['--help']).status).toBe(0);
});

it('CP-027/B2 the installed tarball plans from recorded CLN snapshot balances and stores the exact proposal and digest', async () => {
  const open: FakeServer[] = [];
  try {
    const d = await demo(open, { withKey: false, targets: { 'cln-m': { [S]: '3995709000', [T]: '50000000' } } });
    expect((await installedAsync(['--json', 'channels', '--node', 'cln-m', '--config', d.config])).status).toBe(0);
    const recording = asRecord(readJson('labs/fixtures/recordings/cln/v26.06.9/listpeerchannels.json'), 'recording');
    const recorded = asRecord(JSON.parse(String(asRecord(recording['response'], 'response')['body'])), 'recorded result')['channels'];
    if (!Array.isArray(recorded) || recorded.length !== 2) throw new Error('two recorded CLN channels required');
    const p = await loadPersistence();
    const db = p.openDatabase(d.database, { readOnly: false });
    try {
      const nodeId = String(rows(d.database, "SELECT id FROM nodes WHERE name = 'cln-m'")[0]?.['id']);
      // Replay recorded monetary balances on the existing deterministic SPEC route identities.
      for (const [index, key, peer] of [[0, S, LND_R], [1, T, CLN_R]] as const) {
        const r = asRecord(recorded[index], 'recorded channel');
        const amount = (field: string): bigint => BigInt(String(r[field]));
        const snapshot = channel({ nodeId, channelKey: key, scid: key, peerPubkey: peer,
          fundingOutpoint: `${String(r['funding_txid'])}:${String(r['funding_outnum'])}`,
          capacityMsat: amount('total_msat'), localBalanceMsat: amount('to_us_msat'), remoteBalanceMsat: amount('total_msat') - amount('to_us_msat'),
          spendableMsat: amount('spendable_msat'), receivableMsat: amount('receivable_msat'), confidence: 'NODE_REPORTED',
          observedAt: Date.now(), blockHeight: HEIGHT, pendingOutMsat: 0n, pendingInMsat: 0n, pendingHtlcCount: 0,
          provenance: { recording: 'cln/v26.06.9/listpeerchannels' },
        });
        db.snapshots.record(db.channels.upsert(snapshot), snapshot);
      }
    } finally { db.close(); }
    expect(count(d.database, 'channel_snapshots')).toBe(4);
    const run = await installedAsync(['--json', 'liquidity', 'plan', '--node', 'cln-m', '--config', d.config]);
    expect(run.status, run.stderr + run.stdout).toBe(0);
    const envelope = envelopeOf(run.stdout);
    expect(envelope['ok']).toBe(true); expect(envelope['error']).toBeNull();
    const proposal = asRecord(envelope['result'], 'proposal');
    // SPEC §7.4: min(300m deficit, 3642.166m surplus, 1149.7m after reserves/fee cap, 100m cap).
    expect(proposal).toMatchObject({ action: 'CIRCULAR_REBALANCE', status: 'PROPOSED', source_channel: S, target_channel: T, principal_msat: '100000000' });
    const route = asRecord(proposal['route'], 'route');
    expect(route).toMatchObject({ fee_msat: '202101', fee_ppm: 2022, cltv_delta: 132 });
    expect((route['hops'] as Record<string, unknown>[]).map(hop => [hop['channel'], hop['node_out'], hop['amount_msat']])).toEqual([
      [S, LND_R, '100202101'], [CH3, CLN_R, '100101000'], [T, SELF, '100000000'],
    ]);
    expect((proposal['inputs'] as Record<string, unknown>[]).map(input => [input['channel'], input['spendable_msat'], input['receivable_msat']])).toEqual([
      [S, '1200000000', '3695709000'], [T, '1200000000', '3692166000'],
    ]);
    const fields = [storedId(String(proposal['proposal_id'])), SELF, S, T, '100000000', '300000', '2500', '5000', '144', String(proposal['policy_sha256']), String(proposal['expires_at'])];
    const hash = createHash('sha256').update('FluxWarden-proposal-v1\0');
    for (const field of fields) { const bytes = Buffer.from(field); const length = Buffer.alloc(4); length.writeUInt32BE(bytes.length); hash.update(length).update(bytes); }
    expect(proposal['digest']).toBe(hash.digest('hex'));
    expect(rows(d.database, 'SELECT id, action_type, proposal_digest, status, principal_msat FROM liquidity_proposals')).toEqual([
      { id: storedId(String(proposal['proposal_id'])), action_type: 'CIRCULAR_REBALANCE', proposal_digest: proposal['digest'], status: 'PROPOSED', principal_msat: 100000000 },
    ]);
    expect(count(d.database, 'channel_snapshots')).toBe(4);
    expect(methodsOf(d.cln.fake).filter(method => MUTATING.includes(method))).toEqual([]);
    expect(count(d.database, 'executions')).toBe(0);
  } finally { await Promise.all(open.map(server => server.close())); }
});

it('CP-018/B2 package.json carries the identity, engines, a dist bin, no runtime dependency and no install-time script', () => {
  const manifest = pkg();
  expect(manifest['name']).toBe('fluxwarden');
  expect(manifest['license']).toBe('MIT');
  expect(manifest['type']).toBe('module');
  expect(asRecord(manifest['engines'], 'engines')).toEqual({ node: ENGINES });
  const bin = asRecord(manifest['bin'], 'bin');
  expect(Object.keys(bin)).toEqual(['fluxwarden']);
  expect(String(bin['fluxwarden'])).toMatch(/^(?:\.\/)?dist\/.+\.js$/);
  for (const field of RUNTIME_FIELDS) {
    const value = manifest[field];
    expect(value === undefined || (isRecord(value) && Object.keys(value).length === 0) || (Array.isArray(value) && value.length === 0), field).toBe(true);
  }
  const scripts = isRecord(manifest['scripts']) ? manifest['scripts'] : {};
  for (const name of INSTALL_SCRIPTS) expect(scripts[name], name).toBeUndefined();
});

function map(value: Yaml | undefined, what: string): { [key: string]: Yaml } {
  if (value === undefined || value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${what} is not a mapping`);
  return value;
}
function list(value: Yaml | undefined, what: string): Yaml[] {
  if (!Array.isArray(value)) throw new Error(`${what} is not a sequence`);
  return value;
}
function steps(job: { [key: string]: Yaml }, what: string): { [key: string]: Yaml }[] {
  return list(job['steps'], `${what}.steps`).map(step => map(step, `${what} step`));
}
function runText(step: { [key: string]: Yaml } | undefined): string {
  const run = step?.['run'];
  return typeof run === 'string' ? run : '';
}
function firstIndex(all: { [key: string]: Yaml }[], pattern: RegExp): number {
  return all.findIndex(step => pattern.test(runText(step)));
}

it('CP-018/B3 the release workflow runs only for pushed version tags, pins every action and publishes only the tarball it tested and scanned', () => {
  const path = '.github/workflows/release.yml';
  expect(existsSync(join(repoRoot, path)), path).toBe(true);
  const wf = map(parseYaml(readText(path)), 'release workflow');
  const on = map(wf['on'], 'on');
  expect(Object.keys(on)).toEqual(['push']);
  const push = map(on['push'], 'on.push');
  expect(Object.keys(push)).toEqual(['tags']);
  const tags = list(push['tags'], 'tags');
  expect(tags.length).toBeGreaterThan(0);
  for (const tag of tags) expect(String(tag)).toMatch(/^v/);
  const permissions = map(wf['permissions'], 'permissions');
  expect(permissions['contents']).toBe('read');
  for (const key of Object.keys(permissions)) expect(['contents', 'id-token'], key).toContain(key);

  const jobs = map(wf['jobs'], 'jobs');
  const publishing = Object.entries(jobs).filter(([name, job]) => steps(map(job, name), name).some(step => /\bnpm publish\b/.test(runText(step))));
  expect(publishing.length, 'exactly one publishing job').toBe(1);
  for (const [name, jobValue] of Object.entries(jobs)) {
    for (const step of steps(map(jobValue, name), name)) {
      const uses = step['uses'];
      if (typeof uses === 'string') expect(uses, `${name} uses`).toMatch(/^[^@\s]+@[0-9a-f]{40}$/);
      if (typeof uses === 'string' && uses.startsWith('actions/checkout@')) expect(map(step['with'], 'checkout.with')['persist-credentials']).toBe(false);
      if (/\bnpm publish\b/.test(runText(step))) expect(runText(step), 'publish names a tarball').toMatch(/\bnpm publish\s+(?:--\S+\s+)*\S+\.tgz\b/);
    }
  }
  const [name, jobValue] = publishing[0] ?? ['', null];
  const all = steps(map(jobValue, name), name);
  const order = [/\bnpm ci --ignore-scripts\b/, /\bnpm run lint\b/, /\bnpm run build\b/, /\bnpm test\b/, /\bnpm run test:harness\b/, /(?:GITHUB_REF_NAME|github\.ref_name)/, /\bnpm pack\b/, /\bscripts\/leak-check\.mjs\b/, /\bnpm publish\b/];
  const indexes = order.map(pattern => firstIndex(all, pattern));
  for (const [at, index] of indexes.entries()) expect(index, String(order[at])).toBeGreaterThanOrEqual(0);
  expect([...indexes].sort((a, b) => a - b), 'step order').toEqual(indexes);
  expect(runText(all[indexes[5] ?? -1]), 'the tag is compared with the package version').toMatch(/package\.json|npm pkg get version|\.version\b/);
});

it('CP-036/B5 the chaos job runs only on dispatch, scans its evidence for leaks and uploads it on every outcome without reading a secret', () => {
  const wf = map(parseYaml(readText('.github/workflows/ci.yml')), 'ci workflow');
  expect(Object.keys(map(wf['on'], 'on'))).toContain('workflow_dispatch');
  const chaos = map(map(wf['jobs'], 'jobs')['chaos'], 'chaos');
  expect(String(chaos['if'])).toMatch(/github\.event_name\s*==\s*'workflow_dispatch'/);
  if (chaos['permissions'] !== undefined) expect(chaos['permissions']).toEqual({ contents: 'read' });
  expect(JSON.stringify(chaos)).not.toMatch(/secrets\./);
  const all = steps(chaos, 'chaos');
  const run = firstIndex(all, /\bnpm run test:chaos\b/);
  const scan = firstIndex(all, /\bscripts\/leak-check\.mjs\b/);
  const upload = all.findIndex(step => typeof step['uses'] === 'string' && step['uses'].startsWith('actions/upload-artifact@'));
  expect(run, 'chaos run').toBeGreaterThanOrEqual(0);
  if (scan === run) {
    const command = runText(all[run]);
    const chaosCommand = command.indexOf('npm run test:chaos');
    const finalStage = command.indexOf('--finally');
    const scannerCommand = command.indexOf('scripts/leak-check.mjs');
    expect(command, 'one finite capture contains the actual ordered job commands').toMatch(/scripts\/ci-capture\.mjs\b.*\s--\s+node scripts\/ci-job\.mjs\b/);
    expect(finalStage, 'scanner is an unconditional final command after chaos, including a failed chaos exit').toBeGreaterThan(chaosCommand);
    expect(scannerCommand, 'the actual unchanged scanner follows the final-stage delimiter').toBeGreaterThan(finalStage);
    expect(command.slice(finalStage), 'final stage executes the unchanged scanner directly').toMatch(/^--finally node scripts\/leak-check\.mjs\b/);
  } else expect(scan, 'separate leak scan step follows the run').toBeGreaterThan(run);
  expect(upload, 'upload after the scan').toBeGreaterThan(scan);
  const uploadStep = all[upload] ?? {};
  expect(String(uploadStep['uses'])).toMatch(/^actions\/upload-artifact@[0-9a-f]{40}$/);
  expect(String(uploadStep['if'])).toMatch(/\balways\(\)/);
  const uploaded = String(map(uploadStep['with'], 'upload.with')['path']).trim();
  expect(uploaded.length).toBeGreaterThan(0);
  // Lab runtime state holds credential paths and node material; it is never uploaded.
  expect(uploaded).not.toMatch(/\.runtime|labs\/?$|\bsentinels?\b/);
  const evidenceVariable = (value: string): string => value.replace(/\$\{\{\s*env\.FLUXWARDEN_EVIDENCE_DIR\s*\}\}/g, '$FLUXWARDEN_EVIDENCE_DIR');
  expect(evidenceVariable(runText(all[scan])), 'the scan covers the uploaded path').toContain(evidenceVariable(uploaded.split(/\r?\n/)[0] ?? ''));
});

function releaseSections(text: string): { version: string; date: string; body: string }[] {
  const headings = [...text.matchAll(/^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})\r?$/gm)];
  return headings.map((match, index) => {
    const start = match.index + match[0].length;
    const rest = text.slice(start, headings[index + 1]?.index ?? text.length);
    const next = /^## /m.exec(rest);
    return { version: match[1] ?? '', date: match[2] ?? '', body: next === null ? rest : rest.slice(0, next.index) };
  });
}

function semverCompare(a: string, b: string): number {
  const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i += 1) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  return 0;
}

function expectReleaseEntry(version: string): void {
  const sections = releaseSections(readText('CHANGELOG.md'));
  const entry = sections.find(section => section.version === version);
  expect(entry, `CHANGELOG entry for ${version}`).toBeDefined();
  expect(entry?.body.split(/\r?\n/).filter(line => /^\s*[-*] \S/.test(line)).length ?? 0, `${version} lists its changes`).toBeGreaterThan(0);
  // Newest first: versions strictly descending, dates never increasing.
  for (let i = 1; i < sections.length; i += 1) {
    const newer = sections[i - 1], older = sections[i];
    if (newer === undefined || older === undefined) continue;
    expect(semverCompare(newer.version, older.version), `${newer.version} above ${older.version}`).toBeGreaterThan(0);
    expect(newer.date >= older.date, `${newer.version} dated no earlier than ${older.version}`).toBe(true);
  }
  expect(semverCompare(String(pkg()['version']), version), `package version reaches ${version}`).toBeGreaterThanOrEqual(0);
  expect(RELEASES as readonly string[], 'package version is a planned release').toContain(String(pkg()['version']));
}

it('CP-018/B4 the changelog has a dated 0.1.0 entry and the README an install section', () => {
  expectReleaseEntry('0.1.0');
  const install = /^## Install\s*\r?\n([\s\S]*?)(?=^## |(?![\s\S]))/m.exec(readText('README.md'))?.[1] ?? '';
  expect(install, 'README install section').toMatch(/\bnpm install (?:--global|-g) fluxwarden\b/);
});

it('CP-027/B4 the changelog has a dated 0.2.0 entry above 0.1.0', () => {
  expectReleaseEntry('0.2.0');
});

it('CP-036/B4 the changelog has a dated 0.3.0 entry above 0.2.0', () => {
  expectReleaseEntry('0.3.0');
});

it('CP-044/B4 the package is version 1.0.0 with a changelog entry for every release', () => {
  for (const version of RELEASES) expectReleaseEntry(version);
  expect(pkg()['version']).toBe('1.0.0');
  expect(release().manifest['version']).toBe('1.0.0');
});
