import { appendFile, writeFile } from 'node:fs/promises';
import { win32, join } from 'node:path';
import { createPrivateDirectory, assertPrivateDirectories, realDirectory } from './private-scratch.mjs';
let parent = process.env.FLUXWARDEN_CI_TMP_PARENT;
if (process.platform === 'win32') {
  // Hosted temp drives and runner profiles can have mutable or foreign-owned ancestors.
  // Avoid both: restrict only a unique directory we create directly on the OS drive.
  const systemRoot = process.env.SystemRoot;
  if (!systemRoot || !/^[A-Za-z]:\\Windows$/i.test(systemRoot)) throw new Error('a Windows system directory on an absolute drive is required');
  const drive = win32.parse(systemRoot).root;
  await realDirectory(systemRoot);
  await realDirectory(drive);
  parent = await createPrivateDirectory(drive, 'fluxwarden-ci-');
}
const roots = [];
for (const [name, prefix] of [['TEMP', 'ci-temp-'], ['TMP', 'ci-tmp-'], ['FLUXWARDEN_TEST_TMP', 'ci-tests-'], ['FLUXWARDEN_SENTINEL_DIR', 'ci-sentinels-'], ['FLUXWARDEN_EVIDENCE_DIR', 'ci-evidence-'], ['FLUXWARDEN_CI_CAPTURE_DIR', 'ci-capture-']]) {
  roots.push([name, await createPrivateDirectory(parent, prefix)]);
}
await assertPrivateDirectories([...(process.platform === 'win32' ? [parent] : []), ...roots.map(([, directory]) => directory)]);
const temp = roots.find(([name]) => name === 'TEMP')[1], evidence = roots.find(([name]) => name === 'FLUXWARDEN_EVIDENCE_DIR')[1];
for (const [name, filename] of [['NPM_CONFIG_USERCONFIG', 'npm-user.npmrc'], ['NPM_CONFIG_GLOBALCONFIG', 'npm-global.npmrc']]) {
  const path = join(temp, filename); await writeFile(path, '', { flag: 'wx', mode: 0o600 }); roots.push([name, path]);
}
roots.push(['NPM_CONFIG_CACHE', await createPrivateDirectory(temp, 'npm-validation-cache-')], ['NPM_CONFIG_LOGS_DIR', await createPrivateDirectory(evidence, 'npm-validation-logs-')], ['NPM_CONFIG_UPDATE_NOTIFIER', 'false']);
await appendFile(process.env.GITHUB_ENV, [
  ...(process.platform === 'win32' ? [['FLUXWARDEN_CI_OWNED_ROOT', parent]] : []), ...roots,
].map(([name, directory]) => `${name}=${directory}\n`).join(''));

const releaseOutput = await createPrivateDirectory(parent, 'ci-release-');
await assertPrivateDirectories([releaseOutput]);
const manifest = JSON.parse(await (await import('node:fs/promises')).readFile(new URL('../package.json', import.meta.url), 'utf8'));
await appendFile(process.env.GITHUB_ENV, 'FLUXWARDEN_RELEASE_OUTPUT=' + releaseOutput + '\nFLUXWARDEN_FINAL_TARBALL=' + join(releaseOutput, 'fluxwarden-' + manifest.version + '.tgz') + '\n');
