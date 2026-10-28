// Source purpose follows the prospectively selected private namespace. Runtime,
// evidence and metadata stay ordinary outputs, including equal-byte copies.
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { lstatSync, readFileSync, readdirSync, realpathSync, unlinkSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { childEnv, repoRoot } from '../helpers/cli.js';
import { declareFixturePaths } from '../helpers/capture-fixture.js';
import { testRoot } from '../helpers/env.js';
import { scanner } from '../helpers/leak-scan.js';
import { assertCp012SourceNamespaces } from '../helpers/cp012-reference-authority.js';

it('CP-044/OWNED-SOURCE every original owned source joins the full global pool while matching evidence remains a leak', async () => {
  const scratch = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as {
    createPrivateDirectory(parent: string, prefix: string): Promise<string>;
  };
  const root = await scratch.createPrivateDirectory(testRoot('FLUXWARDEN_TEST_TMP'), 'source-layout-');
  const global = testRoot('FLUXWARDEN_SENTINEL_DIR');
  const originals: { path: string; bytes: Buffer; dev: bigint; ino: bigint }[] = [];
  const evidence = await scratch.createPrivateDirectory(root, 'evidence-');
  for (let owner = 0; owner < 2; owner += 1) {
    const runtime = await scratch.createPrivateDirectory(root, 'runtime-');
    const temporary = await scratch.createPrivateDirectory(root, 'temporary-');
    const owned = await scratch.createPrivateDirectory(global, 'owned-source-');
    const part = relative(realpathSync(global), realpathSync(owned));
    expect(part !== '' && part !== '..' && !part.startsWith(`..${sep}`) && !isAbsolute(part)).toBe(true);
    assertCp012SourceNamespaces(runtime, temporary, owned, evidence, global);
    for (let source = 0; source < 6; source += 1) {
      const path = join(owned, `original-${String(source)}.bin`), bytes = randomBytes(32);
      writeFileSync(path, bytes, { flag: 'wx', mode: 0o600 });
      const info = lstatSync(path, { bigint: true });
      originals.push({ path, bytes, dev: info.dev, ino: info.ino });
    }
  }
  // A global-only source must remain visible too; owner scoping cannot narrow it.
  const path = join(global, `global-only-${randomBytes(8).toString('hex')}.bin`), bytes = randomBytes(32);
  writeFileSync(path, bytes, { flag: 'wx', mode: 0o600 });
  const info = lstatSync(path, { bigint: true }); originals.push({ path, bytes, dev: info.dev, ino: info.ino });
  const output = join(evidence, 'ordinary-output.log');
  declareFixturePaths([output]);
  const engine = await scanner();
  const options = { root: repoRoot, sentinelDir: global, sentinels: join(repoRoot, 'test/sentinels.json'),
    testTmp: root, evidenceDir: evidence, paths: [output] };
  try {
    writeFileSync(output, 'ordinary noncredential evidence', { mode: 0o600 });
    expect(engine.findLeaks(options)).toBeNull();
    for (const original of originals) {
      writeFileSync(output, `ordinary output ${original.bytes.toString('hex')} end`, { mode: 0o600 });
      const hit = engine.findLeaks(options);
      expect(hit, 'every original owner/global source detects an equal-byte egress copy').not.toBeNull();
      expect(resolve(hit?.path ?? '')).toBe(resolve(output));
    }
  } finally { unlinkSync(output); }
  for (const original of originals) {
    const current = lstatSync(original.path, { bigint: true });
    expect(current.dev).toBe(original.dev); expect(current.ino).toBe(original.ino);
    expect(readFileSync(original.path).equals(original.bytes)).toBe(true);
  }
});
const operationalRoots = ['FLUXWARDEN_TEST_TMP', 'TEMP', 'TMP', 'FLUXWARDEN_EVIDENCE_DIR',
  'FLUXWARDEN_CI_CAPTURE_DIR', 'FLUXWARDEN_CI_CAPTURE'] as const;
for (const selected of operationalRoots) {
  it(`CP-044/SOURCE-BOUNDARY ${selected} rejects equal and symmetric source overlap before owned allocation`, async () => {
    const scratch = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as {
      createPrivateDirectory(parent: string, prefix: string): Promise<string>;
    };
    for (const geometry of ['equal', 'source-parent', 'source-child']) {
      const root = await scratch.createPrivateDirectory(testRoot('FLUXWARDEN_TEST_TMP'), 'source-boundary-');
      const parent = await scratch.createPrivateDirectory(root, 'allocation-');
      const env: NodeJS.ProcessEnv = Object.fromEntries(Object.entries(childEnv())
        .filter(([name]) => !/^FLUXWARDEN_|^NODE_OPTIONS$|^NODE_DEBUG$/i.test(name)));
      for (const name of operationalRoots) env[name] = await scratch.createPrivateDirectory(root, 'operational-');
      let global = await scratch.createPrivateDirectory(root, 'source-');
      if (geometry === 'equal') env[selected] = global;
      else if (geometry === 'source-parent') env[selected] = await scratch.createPrivateDirectory(global, 'operational-');
      else global = await scratch.createPrivateDirectory(env[selected] ?? root, 'source-');
      env['FLUXWARDEN_SENTINEL_DIR'] = global;
      env['FLUXWARDEN_LAB_SOURCE_CHECKOUTS'] = join(root, 'intentionally-missing-pinned-mapping.json');
      const child = join(root, 'allocation.mjs');
      writeFileSync(child, `import {prepareOwnedLive} from ${JSON.stringify(pathToFileURL(join(repoRoot, 'scripts/release-live.mjs')).href)};
try {await prepareOwnedLive(${JSON.stringify(parent)},${JSON.stringify('a'.repeat(40))});process.stdout.write(JSON.stringify({refused:false}));}
catch(error){process.stdout.write(JSON.stringify({refused:true,message:error instanceof Error?error.message:'unknown'}));}`, { mode: 0o600 });
      const before = readdirSync(parent).sort();
      const result = spawnSync(process.execPath, [child], { cwd: repoRoot, env, encoding: 'utf8', windowsHide: true, timeout: 10_000 });
      expect(result.error, `${selected}/${geometry} child completed`).toBeUndefined();
      expect(result.status, `${selected}/${geometry} child completed`).toBe(0);
      const observed = JSON.parse(result.stdout) as { refused: boolean; message?: string };
      expect(observed.refused, `${selected}/${geometry} overlap refused`).toBe(true);
      // The namespace refusal must precede any pinned-input read or allocation.
      expect(observed.message, `${selected}/${geometry} namespace prerequisite`).toMatch(/separate canonical sentinel root required/);
      expect(readdirSync(parent).sort(), `${selected}/${geometry} no owned allocation`).toEqual(before);
    }
  });
}