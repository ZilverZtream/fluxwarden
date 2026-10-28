import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import type { SourceProducer } from '../../labs/scenarios/credentials/producer-contract.d.mts';
import { asRecord, readJson, repoRoot } from '../helpers/cli.js';
import { sourceManifestIdentity } from '../helpers/cp008-source-contract.js';
import { scratch } from '../helpers/cp016-cli.js';

const contract = asRecord(readJson('labs/fixtures/credential-reference-contract.json'), 'approved contract');
function manifest(profile: 'credential-primary-v1' | 'credential-wire-v1') {
  const profiles = asRecord(contract['profiles'], 'profiles'), repos = asRecord(contract['repositories'], 'repositories');
  const repositories: Record<string, unknown>[] = ['lnd', 'cln'].map(id => ({ id, ...asRecord(repos[id], 'pin'), gitRoot: join(repoRoot, 'unused-synthetic-git', id) }));
  const sources: Record<string, unknown>[] = (profiles[profile] as Record<string, unknown>[]).map(source => ({ ...source, file: join(repoRoot, 'unused-synthetic-source', String(source['repository']), String(source['path'])) }));
  return { version: 2, profile, repositories, sources,
    aliases: profile === 'credential-wire-v1' ? contract['wireAliases'] : [] };
}
it('CP-008/LP-A exact authority identities reject same-count substitution duplicate paths and forged pins', () => {
  const gold = manifest('credential-primary-v1'); expect(gold.sources).toHaveLength(13);
  expect(sourceManifestIdentity(gold, gold.profile).sources).toHaveLength(13);
  const substituted = structuredClone(gold); substituted.sources[0] = { ...substituted.sources[0], path: 'arbitrary-file.go' };
  expect(() => sourceManifestIdentity(substituted, gold.profile)).toThrow('identities');
  const duplicate = structuredClone(gold); duplicate.sources[0] = { ...duplicate.sources[1] };
  expect(() => sourceManifestIdentity(duplicate, gold.profile)).toThrow('identities');
  const pin = structuredClone(gold); if (pin.repositories[0]) pin.repositories[0]['commit'] = '0'.repeat(40);
  expect(() => sourceManifestIdentity(pin, gold.profile)).toThrow('pin');
});
it('CP-008/LP-A complete wire identities require actual method schemas and explicit invokerune alias', () => {
  const gold = manifest('credential-wire-v1'); expect(sourceManifestIdentity(gold, gold.profile).sources).toHaveLength(31);
  expect(() => sourceManifestIdentity({ ...gold, aliases: [] }, gold.profile)).toThrow('alias');
  const missing = structuredClone(gold); missing.sources.pop(); expect(() => sourceManifestIdentity(missing, gold.profile)).toThrow('identities');
  const tampered = structuredClone(gold); if (tampered.sources[0]) tampered.sources[0]['sha256'] = '0'.repeat(64);
  expect(() => sourceManifestIdentity(tampered, gold.profile)).toThrow('hash');
});
it('CP-008/LP-A public source producer rejects unpinned checkouts before creating an output', async () => {
  // The missing implementation is deliberately outside expect.rejects: module
  // absence cannot masquerade as a successful source-identity refusal control.
  const producer = await import(pathToFileURL(join(repoRoot, 'scripts/live-credential-sources.mjs')).href) as SourceProducer;
  const root = scratch('credential-source-negative'), directory = join(root, 'uncreated-output');
  await expect(producer.preparePinnedCredentialSources({ directory, checkouts: { lnd: root, cln: root, macwarden: root } })).rejects.toThrow();
  expect(existsSync(directory)).toBe(false);
});
