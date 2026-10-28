// CP008 Rleak requires independent nonempty TLS/approval key format sources;
// these controls never become node credentials or execution approval authority.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { prepareCp008LeakSources, proveCp008ArtifactLeaks } from '../helpers/cp008-live.js';
import { repoRoot } from '../helpers/cli.js';
import { declareFixturePaths } from '../helpers/capture-fixture.js';
import { testRoot } from '../helpers/env.js';
import { scanner } from '../helpers/leak-scan.js';
import { sentinels } from '../helpers/output.js';
import { assertStrictWindowsOwnerOnly, readWindowsSecurity } from '../helpers/windows-security.js';

it('CP-008/RLEAK-SOURCES fresh valid private key sources detect every required encoding without granting execution authority', async () => {
  const permissions = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as {
    assertPrivateDirectory(path: string): Promise<void>;
    createPrivateDirectory(parent: string, prefix: string): Promise<string>;
  };
  const root = await permissions.createPrivateDirectory(testRoot('FLUXWARDEN_TEST_TMP'), 'cp008-sources-');
  const global = testRoot('FLUXWARDEN_SENTINEL_DIR');
  const foreign = await permissions.createPrivateDirectory(root, 'not-source-');
  await expect(prepareCp008LeakSources(foreign, permissions)).rejects.toThrow(/actual global source namespace before creation/);
  expect(readdirSync(foreign)).toEqual([]);
  const engine = await scanner(), seen = new Set<string>();
  for (let owner = 0; owner < 2; owner += 1) {
    const sourceRoot = await permissions.createPrivateDirectory(global, 'cp008-owner-');
    const paths = await prepareCp008LeakSources(sourceRoot, permissions);
    expect(paths).toHaveLength(2);
    expect(paths.some(path => path.includes('tls-key-'))).toBe(true);
    expect(paths.some(path => path.includes('approval-key-'))).toBe(true);
    const planted = join(root, `ordinary-evidence-${String(owner)}.bin`);
    declareFixturePaths([planted]);
    const options = { root: repoRoot, sentinels: join(repoRoot, 'test/sentinels.json'), sentinelDir: global,
      testTmp: root, evidenceDir: root, paths: [planted] };
    try {
      writeFileSync(planted, 'ordinary noncredential evidence', { mode: 0o600 });
      expect(engine.findLeaks(options)).toBeNull();
      for (const path of paths) {
        const bytes = readFileSync(path), key = createPrivateKey(bytes), info = lstatSync(path);
        expect(info.isFile() && !info.isSymbolicLink()).toBe(true);
        if (process.platform === 'win32') assertStrictWindowsOwnerOnly(readWindowsSecurity(path), 'file');
        else { expect(info.uid).toBe(process.getuid?.()); expect(info.mode & 0o777).toBe(0o600); }
        const fingerprint = createHash('sha256').update(bytes).digest('hex');
        expect(seen.has(fingerprint), 'each owner has fresh independent source bytes').toBe(false); seen.add(fingerprint);
        const tls = path.includes('tls-key-');
        expect(key.asymmetricKeyType).toBe(tls ? 'ec' : 'ed25519');
        if (tls) expect(key.asymmetricKeyDetails?.namedCurve).toBe('prime256v1');
        const message = Buffer.from('independent disposable format control');
        expect(verify(tls ? 'sha256' : null, message, createPublicKey(key), sign(tls ? 'sha256' : null, message, key))).toBe(true);
        const b64 = bytes.toString('base64'), url = bytes.toString('base64url');
        for (const encoded of [bytes.toString('utf8'), bytes.toString('latin1'), bytes.toString('hex'), bytes.toString('hex').toUpperCase(),
          b64, b64.replace(/=+$/, ''), url + '='.repeat((4 - url.length % 4) % 4), url]) {
          writeFileSync(planted, encoded, { mode: 0o600 });
          const hit = engine.findLeaks(options);
          expect(hit !== null, 'all eight required source encodings remain detectable').toBe(true);
          expect(resolve(hit?.path ?? '')).toBe(resolve(planted));
        }
        expect(readFileSync(path).equals(bytes), 'complete original source remains unchanged').toBe(true);
      }
    } finally { unlinkSync(planted); }
  }
});
it('CP-008/RLEAK-ARTIFACTS actual artifact scan requires every kind and retains official static global and owned source coverage', async () => {
  const permissions = await import(pathToFileURL(join(repoRoot, 'scripts/private-scratch.mjs')).href) as {
    assertPrivateDirectory(path: string): Promise<void>;
    createPrivateDirectory(parent: string, prefix: string): Promise<string>;
  };
  const owners = [];
  for (let index = 0; index < 2; index += 1) {
    const root = await permissions.createPrivateDirectory(testRoot('FLUXWARDEN_TEST_TMP'), 'cp008-artifacts-');
    const owner = { runtimeRoot: await permissions.createPrivateDirectory(root, 'runtime-'),
      tmpRoot: await permissions.createPrivateDirectory(root, 'temporary-'),
      evidenceRoot: await permissions.createPrivateDirectory(root, 'evidence-'),
      sentinelRoot: await permissions.createPrivateDirectory(testRoot('FLUXWARDEN_SENTINEL_DIR'), 'cp008-owner-') };
    for (const kind of ['preimage', 'macaroon', 'rune']) {
      const source = sentinels().find(row => row.kind === kind);
      if (!source) throw new Error('official static kind source missing');
      writeFileSync(join(owner.sentinelRoot, `${kind}.bin`), source.bytes, { mode: 0o600, flag: 'wx' });
    }
    owners.push({ owner });
  }
  const fixture = { privateIO: permissions, plan: { owners } };
  await expect(proveCp008ArtifactLeaks(fixture)).rejects.toThrow(/independent required nonempty sentinel kind/);
  for (const { owner } of owners) await prepareCp008LeakSources(owner.sentinelRoot, permissions);
  await proveCp008ArtifactLeaks(fixture);
}, 180_000);