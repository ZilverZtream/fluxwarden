// Pinned native fixture controls. No Docker or native PASS evidence is produced.
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { expectNoSentinelLeak, lncliShortChannelId } from '../helpers/adapter-lab.js';
import { repoRoot, scratchDir } from '../helpers/cli.js';
import { declareFixturePaths } from '../helpers/capture-fixture.js';
import { ownedReference } from '../helpers/owned-reference.js';
import { certificatePath } from '../fakes/https.js';

const hash = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');
const fingerprint = (bytes: Buffer): string => `fp:${hash(bytes).slice(0, 16)}`;

/** Original controlled INPUT production precedes every recognition attempt. */
function sourceFixture() {
  const root = scratchDir('adapter-scan-roots'), sentinelDir = join(root, 'sentinels'), testTmp = join(root, 'tests'), evidenceDir = join(root, 'evidence');
  for (const path of [sentinelDir, testTmp, evidenceDir]) mkdirSync(path, { mode: 0o700 });
  const reference = ownedReference(root), ownerPath = join(root, 'owner.json'), adapterPath = join(root, 'adapter.json');
  const macaroon = randomBytes(32), rune = Buffer.from(randomBytes(32).toString('base64url'));
  const sources = [macaroon, rune, ...Array.from({ length: 4 }, () => randomBytes(32))].map((bytes, index) => ({
    path: join(reference.owner.sentinelRoot, `registered-${String(index)}.bin`), bytes,
  }));
  const lndCredential = join(reference.owner.runtimeRoot, 'read.macaroon'), clnCredential = join(reference.owner.runtimeRoot, 'read.rune');
  const lndCertificate = join(reference.owner.runtimeRoot, 'lnd-certificate.pem'), clnCertificate = join(reference.owner.runtimeRoot, 'cln-certificate.pem');
  const foreignCertificate = join(root, 'foreign-certificate.pem'), foreignCredential = join(root, 'foreign-credential.bin'), foreignBytes = randomBytes(32);
  const plant = join(evidenceDir, 'deliberate-control.txt'), globalPath = join(sentinelDir, 'global-source.bin'), globalBytes = randomBytes(32);
  declareFixturePaths([...sources.map(source => source.path), lndCredential, clnCredential, foreignCredential, plant, globalPath]);
  for (const source of sources) writeFileSync(source.path, source.bytes, { mode: 0o600 });
  writeFileSync(lndCredential, macaroon, { mode: 0o600 });
  // CP012/B1: the active rune is the complete printable token after trimming.
  writeFileSync(clnCredential, Buffer.concat([rune, Buffer.from('\n')]), { mode: 0o600 });
  writeFileSync(foreignCredential, foreignBytes, { mode: 0o600 });
  const certificate = readFileSync(certificatePath('node'));
  for (const path of [lndCertificate, clnCertificate, foreignCertificate]) writeFileSync(path, certificate, { mode: 0o600 });
  const credentials: Record<string, Record<string, { path: string; fingerprint: string }>> = {
    'lnd-r': { read: { path: lndCredential, fingerprint: fingerprint(macaroon) } },
    'cln-m': { read: { path: clnCredential, fingerprint: fingerprint(rune) } },
  };
  const nodes: Record<string, Record<string, unknown>> = {
    ...reference.manifest.nodes,
    'lnd-r': { ...reference.manifest.nodes['lnd-r'], kind: 'lnd', certificate: { path: lndCertificate, sha256: hash(certificate) } },
    'cln-m': { ...reference.manifest.nodes['cln-m'], kind: 'cln', certificate: { path: clnCertificate, sha256: hash(certificate) } },
  };
  const manifest = { ...reference.manifest, nodes, credentials };
  const adapter = { version: 1, network: 'regtest', disposable: true, project: reference.owner.project, composeFile: join(root, 'compose.yml'),
    lnd: { service: 'lnd-r', host: '127.0.0.1', port: reference.owner.ports.lndRest, pubkey: reference.manifest.nodes['lnd-r']?.pubkey ?? '', tlsCert: lndCertificate, macaroon: lndCredential },
    cln: { service: 'cln-m', host: '127.0.0.1', port: reference.owner.ports.clnRest, pubkey: reference.manifest.nodes['cln-m']?.pubkey ?? '', tlsCert: clnCertificate, rune: clnCredential }, wrongCert: join(root, 'wrong.pem') };
  writeFileSync(ownerPath, JSON.stringify(reference.owner));
  const writeManifest = () => { writeFileSync(join(reference.owner.runtimeRoot, 'lab.json'), JSON.stringify(manifest)); };
  const writeAdapter = () => { writeFileSync(adapterPath, JSON.stringify(adapter)); };
  writeManifest(); writeAdapter();
  const roots = { FLUXWARDEN_SENTINEL_DIR: sentinelDir, FLUXWARDEN_TEST_TMP: testTmp, FLUXWARDEN_EVIDENCE_DIR: evidenceDir, FLUXWARDEN_LAB_OWNER: ownerPath, FLUXWARDEN_LAB_ADAPTER_PLAN: adapterPath };
  const saved = Object.fromEntries(Object.keys(roots).map(name => [name, process.env[name]]));
  Object.assign(process.env, roots);
  const restore = () => { for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) Reflect.deleteProperty(process.env, name); else process.env[name] = value;
  } };
  return { root, reference, ownerPath, manifest, adapter, sources, plant, globalPath, globalBytes, testTmp, macaroon, rune,
    lndCredential, foreignCredential, foreignBytes, foreignCertificate, writeManifest, writeAdapter, restore };
}

it('CP-023/R1 pinned lncli short channel IDs remain decimal when chan_id carries the 32-byte identifier', () => {
  // CP011/R2 records replaceAndAppendScid/appendChanID: scid is the short ID,
  // chan_id is the 32-byte identifier. Legacy output contains decimal chan_id.
  expect(lncliShortChannelId({ chan_id: 'a'.repeat(64), scid: '1099511758848' })).toBe('1099511758848');
  expect(lncliShortChannelId({ chan_id: '1099511758848' })).toBe('1099511758848');
  for (const value of [{ chan_id: 'a'.repeat(64) }, { scid: 'malformed', chan_id: '1099511758848' }, {}]) {
    expect(() => { lncliShortChannelId(value); }).toThrow(/short channel/);
  }
});

it('CP-011/Rleak official static sources and every runtime registration scan without a scratch manifest', async () => {
  const f = sourceFixture(), registry = JSON.parse(readFileSync(join(repoRoot, 'test/sentinels.json'), 'utf8')) as string[];
  const official = registry[0], last = f.sources.at(-1);
  if (!official || !last) throw new Error('complete official/runtime source controls required');
  try {
    expect(existsSync(join(f.testTmp, 'sentinels.json')), 'the official scanner must not require an invented scratch source list').toBe(false);
    await expect(expectNoSentinelLeak()).resolves.toBeUndefined();
    // Isolated native runs have global0/owner35. Never fill coverage with static
    // fixtures; every original owned registration must still participate.
    writeFileSync(f.globalPath, f.globalBytes, { mode: 0o600 });
    for (const bytes of [readFileSync(join(repoRoot, official)), last.bytes, f.globalBytes]) {
      try {
        writeFileSync(f.plant, bytes.toString('hex'));
        await expect(expectNoSentinelLeak()).rejects.toThrow();
      } finally { if (existsSync(f.plant)) unlinkSync(f.plant); }
    }
    const manifestPath = join(f.reference.owner.runtimeRoot, 'lab.json'), originalManifest = readFileSync(manifestPath);
    try {
      writeFileSync(manifestPath, JSON.stringify({ ...f.manifest, ownerId: 'wrong-owner' }));
      await expect(expectNoSentinelLeak()).rejects.toThrow(/runtime does not belong/);
    } finally { writeFileSync(manifestPath, originalManifest); }
  } finally { f.restore(); }
}, 120_000);

it('CP-044/ARC-044-001 active endpoint TLS and complete credential must bind the original registered authority', async () => {
  const f = sourceFixture(), adapter = structuredClone(f.adapter), manifest = structuredClone(f.manifest);
  const mutations: (() => void)[] = [
    () => { f.adapter.lnd.macaroon = f.foreignCredential; writeFileSync(f.plant, f.foreignBytes.toString('hex')); },
    () => {
      writeFileSync(f.lndCredential, f.foreignBytes);
      const role = f.manifest.credentials['lnd-r']?.['read']; if (!role) throw new Error('original role absent');
      role.fingerprint = fingerprint(f.foreignBytes); writeFileSync(f.plant, f.foreignBytes.toString('hex'));
    },
    () => {
      // A recognizer hit on a registered prefix cannot cover this whole value.
      const partial = Buffer.concat([f.macaroon, f.foreignBytes]);
      writeFileSync(f.lndCredential, partial);
      const role = f.manifest.credentials['lnd-r']?.['read']; if (!role) throw new Error('original role absent');
      role.fingerprint = fingerprint(partial);
    },
    () => {
      // The engine has no trimmed alias for an original rune-plus-newline source.
      const originalRune = f.sources[1]; if (!originalRune) throw new Error('original rune registration absent');
      writeFileSync(originalRune.path, Buffer.concat([f.rune, Buffer.from('\n')]));
      writeFileSync(f.plant, f.rune.toString('hex'));
    },
    () => { f.adapter.lnd.tlsCert = f.foreignCertificate; },
    () => { f.adapter.lnd.port += 1; },
    () => { f.adapter.lnd.host = 'localhost'; },
    () => {
      f.adapter.lnd.service = 'lnd-p'; f.adapter.lnd.pubkey = f.reference.manifest.nodes['lnd-p']?.pubkey ?? '';
      f.manifest.nodes['lnd-p'] = { ...f.manifest.nodes['lnd-p'], kind: 'lnd', certificate: structuredClone(f.manifest.nodes['lnd-r']?.['certificate']) };
      f.manifest.credentials['lnd-p'] = structuredClone(f.manifest.credentials['lnd-r'] ?? {});
    },
  ];
  try {
    for (const mutate of mutations) {
      try {
        mutate(); f.writeManifest(); f.writeAdapter();
        await expect(expectNoSentinelLeak()).rejects.toThrow();
      } finally {
        Object.assign(f.adapter, structuredClone(adapter)); Object.assign(f.manifest, structuredClone(manifest));
        writeFileSync(f.lndCredential, f.macaroon);
        const originalRune = f.sources[1];
        if (originalRune) writeFileSync(originalRune.path, f.rune);
        f.writeManifest(); f.writeAdapter();
        if (existsSync(f.plant)) unlinkSync(f.plant);
      }
    }
  } finally { f.restore(); }
}, 120_000);
