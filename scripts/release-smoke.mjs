import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { createPrivateDirectory } from './private-scratch.mjs';
import { findLeaks } from './leak-check.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const topLevel = new Set(['package.json', 'README.md', 'LICENSE', 'SECURITY.md', 'CHANGELOG.md', 'NOTICE-SOURCE-REUSE.md']);
const buildMetadata = 'dist/evidence/build-info.json';

export function inspectTarball(path) {
  const tar = gunzipSync(readFileSync(path), { maxOutputLength: 128 * 1024 * 1024 });
  const files = new Set();
  for (let at = 0; at + 512 <= tar.length;) {
    const header = tar.subarray(at, at + 512);
    if (header.every(byte => byte === 0)) break;
    const text = (start, end) => header.subarray(start, end).toString('utf8').replace(/\0.*$/s, '');
    const name = text(0, 100), prefix = text(345, 500);
    const path = prefix ? `${prefix}/${name}` : name;
    const sizeText = text(124, 136).trim();
    if (!/^[0-7]+$/.test(sizeText)) throw new Error('invalid tar member size');
    const size = parseInt(sizeText, 8);
    if (at + 512 + size > tar.length) throw new Error('truncated tar member');
    const relative = path.replace(/^package\//, '');
    if (!path.startsWith('package/') || relative.includes('..') || relative.includes('\\') || files.has(relative)) throw new Error('unsafe tar member');
    if (![0, 48].includes(header[156])) throw new Error('non-file tar member');
    const data = tar.subarray(at + 512, at + 512 + size);
    if (relative === buildMetadata) {
      let metadata;
      try { metadata = JSON.parse(data.toString('utf8')); } catch { throw new Error('invalid build metadata'); }
      if (metadata === null || typeof metadata !== 'object' || Array.isArray(metadata) ||
          Object.keys(metadata).join() !== 'gitCommit' || typeof metadata.gitCommit !== 'string' ||
          !/^[0-9a-f]{40}$/.test(metadata.gitCommit)) throw new Error('invalid build metadata');
    } else if (!topLevel.has(relative)) {
      if (!/^dist\/.+\.(?:js|d\.ts|js\.map|d\.ts\.map)$/.test(relative)) throw new Error('tar member outside allow-list');
      const source = relative.slice(5).replace(/\.(?:js|d\.ts)(?:\.map)?$/, '.ts');
      if (!existsSync(join(root, 'src', source))) throw new Error('stale compiled tar member');
    }
    for (const local of [root, process.env.USERPROFILE, process.env.HOME].filter(Boolean)) {
      for (const form of [local, local.replaceAll('\\', '/'), local.replaceAll('\\', '\\\\')]) {
        if (data.includes(Buffer.from(form))) throw new Error('local build path in tar member');
      }
    }
    files.add(relative);
    at += 512 + Math.ceil(size / 512) * 512;
  }
  for (const required of topLevel) if (!files.has(required)) throw new Error('required tar member absent');
  if (!files.has('dist/cli/bin.js')) throw new Error('installed command absent');
  if (!files.has(buildMetadata)) throw new Error('build metadata absent');
  return files;
}

function run(executable, args, cwd, env, options = {}) {
  const result = spawnSync(executable, args, { cwd, env, windowsHide: true, timeout: 120_000, ...options });
  // Preserve complete observed child streams before validation or scratch cleanup.
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  process.stderr.write('\n' + JSON.stringify({ stage: 'release-smoke-child', status: result.status, signal: result.signal,
    errorCode: result.error?.code ?? null }) + '\n');
  if (result.error) throw result.error;
  return { ...result, stdout: result.stdout?.toString('utf8') ?? '', stderr: result.stderr?.toString('utf8') ?? '' };
}

async function smoke(tarball) {
  inspectTarball(tarball);
  const work = await createPrivateDirectory(process.env.FLUXWARDEN_TEST_TMP ?? tmpdir(), 'fw-installed-');
  try {
    const env = { ...process.env };
    delete env.NODE_OPTIONS;
    delete env.NODE_DEBUG;
    const prefix = join(work, 'prefix'), cwd = join(work, 'cwd');
    mkdirSync(cwd);
    const npm = process.env.npm_execpath ?? (process.platform === 'win32'
      ? join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js')
      : join(dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js'));
    const installed = run(process.execPath, [npm, 'install', '--global', '--prefix', prefix, '--ignore-scripts', '--offline', '--no-audit', '--no-fund', tarball], cwd, env);
    if (installed.status !== 0) throw new Error('offline tarball installation failed');
    const packageDir = process.platform === 'win32' ? join(prefix, 'node_modules/fluxwarden') : join(prefix, 'lib/node_modules/fluxwarden');
    const manifest = JSON.parse(readFileSync(join(packageDir, 'package.json'), 'utf8'));
    if (manifest.name !== 'fluxwarden' || Object.keys(manifest.bin).join() !== 'fluxwarden') throw new Error('installed identity mismatch');
    for (const key of ['dependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'bundledDependencies']) {
      if (manifest[key] !== undefined && Object.keys(manifest[key]).length !== 0) throw new Error('runtime dependency in tarball');
    }
    if (existsSync(join(packageDir, 'node_modules'))) throw new Error('unexpected installed dependency');
    const scan = findLeaks({ root, sentinels: join(root, 'test/sentinels.json'), sentinelDir: process.env.FLUXWARDEN_SENTINEL_DIR,
      paths: [tarball, packageDir] });
    if (scan !== null) throw new Error('credential in release artifact');
    const command = args => {
      if (process.platform !== 'win32') return run(join(prefix, 'bin/fluxwarden'), args, cwd, env);
      // Only fixed smoke arguments and a newly created path reach the Windows shim.
      if (!/^[A-Za-z]:[\\\w .:-]+$/.test(prefix)) throw new Error('unsafe shim path');
      return run(process.env.ComSpec ?? 'C:\\Windows\\System32\\cmd.exe', ['/d', '/s', '/c', `"${join(prefix, 'fluxwarden.cmd')}" ${args.join(' ')}`], cwd, env, { windowsVerbatimArguments: true });
    };
    const version = command(['--version']);
    if (version.status !== 0 || version.stdout !== `${manifest.version}\n`) throw new Error('installed version failed');
    const help = command(['--help']);
    if (help.status !== 0 || !help.stdout.includes('doctor')) throw new Error('installed help failed');
    for (const args of [['doctor'], ['channels'], ['liquidity', 'plan'], ['liquidity', 'explain', 'proposal-1']]) {
      const answer = command([...args, '--json']);
      const document = JSON.parse(answer.stdout);
      if (answer.status !== 2 || document.schema !== 1 || document.ok !== false || document.result !== null || document.error?.code !== 2 ||
          document.command !== args.slice(0, args[0] === 'liquidity' ? 2 : 1).join(' ')) throw new Error('installed configuration refusal failed');
    }
    process.stdout.write(`FluxWarden ${manifest.version}: release tarball allow-list, leak scan, offline installation and command smoke passed.\n`);
  } finally {
    // work is created by this invocation and stays beneath its selected scratch root.
    rmSync(work, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3) throw new Error('one tarball path required');
    await smoke(resolve(process.argv[2]));
  } catch {
    process.stderr.write('Release tarball validation failed.\n');
    process.exitCode = 1;
  }
}
