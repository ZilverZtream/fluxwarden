// Trusted frozen-lock setup precedes candidate validation; all diagnostics stay
// in owned evidence, while only this invocation's disposable cache is removed.
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { createPrivateDirectory, assertPrivateDirectories } from './private-scratch.mjs';

const digest = path => createHash('sha256').update(fs.readFileSync(path)).digest('hex');
const names = ['TEMP', 'TMP', 'FLUXWARDEN_TEST_TMP', 'FLUXWARDEN_SENTINEL_DIR', 'FLUXWARDEN_EVIDENCE_DIR'];
const statusPath = () => join(process.env.FLUXWARDEN_EVIDENCE_DIR, 'npm-install.json');
const provenance = root => ({ lockSha256: digest(join(root, 'package-lock.json')), packageSha256: digest(join(root, 'package.json')) });
async function install(root) {
  if (names.some(name => !process.env[name])) throw new Error('private setup roots required');
  await assertPrivateDirectories(names.map(name => resolve(process.env[name])));
  const evidence = process.env.FLUXWARDEN_EVIDENCE_DIR;
  const logs = join(evidence, 'npm-install-logs');
  fs.mkdirSync(logs, { mode: 0o700 });
  const cache = await createPrivateDirectory(process.env.TEMP, 'npm-install-cache-');
  const stdout = fs.openSync(join(evidence, 'npm-install.stdout.log'), 'wx', 0o600);
  const stderr = fs.openSync(join(evidence, 'npm-install.stderr.log'), 'wx', 0o600);
  const record = { status: null, signal: null, errorCode: null, complete: false, cacheRemoved: false };
  try {
    const before = provenance(root);
    Object.assign(record, before);
    const userconfig = join(cache, 'empty-user.npmrc'), globalconfig = join(cache, 'empty-global.npmrc');
    for (const path of [userconfig, globalconfig]) fs.writeFileSync(path, '', { mode: 0o600, flag: 'wx' });
    const npm = [join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js'), resolve(dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js')].find(fs.existsSync);
    if (!npm) throw new Error('setup npm unavailable');
    record.npmCliSha256 = digest(npm);
    record.nodeVersion = process.version;
    const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^npm_config_(?:userconfig|globalconfig|cache|logs_dir|update_notifier)$/i.test(name)));
    const result = spawnSync(process.execPath, [npm, 'ci', '--ignore-scripts'], {
      cwd: root, windowsHide: true, timeout: 180_000, stdio: ['ignore', stdout, stderr],
      env: { ...env, NPM_CONFIG_USERCONFIG: userconfig, NPM_CONFIG_GLOBALCONFIG: globalconfig,
        NPM_CONFIG_CACHE: cache, NPM_CONFIG_LOGS_DIR: logs, NPM_CONFIG_UPDATE_NOTIFIER: 'false',
        NODE_COMPILE_CACHE: join(cache, 'node-compile-cache') },
    });
    record.status = result.status;
    record.signal = result.signal;
    record.errorCode = result.error?.code ?? null;
    record.complete = !result.error && !result.signal && JSON.stringify(before) === JSON.stringify(provenance(root));
  } catch { record.complete = false; }
  finally {
    fs.closeSync(stdout); fs.closeSync(stderr);
    try {
      await assertPrivateDirectories([cache]);
      fs.rmSync(cache, { recursive: true, force: true });
      record.cacheRemoved = true;
    } catch { record.complete = false; }
    fs.writeFileSync(statusPath(), JSON.stringify(record), { mode: 0o600, flag: 'wx' });
  }
  return !record.complete || !record.cacheRemoved ? record.status || 1 : record.status ?? 1;
}
function verify(root) {
  const record = JSON.parse(fs.readFileSync(statusPath(), 'utf8'));
  const current = provenance(root);
  if (!record.complete || !record.cacheRemoved || record.lockSha256 !== current.lockSha256 || record.packageSha256 !== current.packageSha256 ||
      record.signal !== null || record.errorCode !== null || !Number.isInteger(record.status) || record.status < 0) return 1;
  for (const name of ['npm-install.stdout.log', 'npm-install.stderr.log', 'npm-install-logs']) fs.lstatSync(join(process.env.FLUXWARDEN_EVIDENCE_DIR, name));
  return record.status;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2), verification = args[0] === 'verify';
    if (verification) args.shift();
    if (args.length !== 2 || args[0] !== '--root') throw new Error('setup checkout required');
    process.exitCode = verification ? verify(resolve(args[1])) : await install(resolve(args[1]));
  } catch { process.stderr.write('CI dependency setup failed\n'); process.exitCode = 1; }
}
