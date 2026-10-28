// Docker29.5.2 native reference: Config.Image retains repository:tag@digest,
// while image inspect RepoDigests retains canonical repository@digest.
import { expect, it } from 'vitest';
import { hasPinnedRepoDigest } from '../helpers/cp008-live.js';
import { asRecord, readJson } from '../helpers/cli.js';

it('CP-008/IMAGE-PIN canonical repository digest retains exact repository SHA and registry port', () => {
  const pins = asRecord(asRecord(readJson('test/fixtures/cp006-expectations.json'), 'pinned native fixture')['imagePins'], 'image pins');
  const reference = String(pins['cln']);
  const digest = 'sha256:de74289ddcccb68cd60543b08b2b8594002d819125d200492e17a95166d56577';
  const repository = 'elementsproject/lightningd';
  expect(hasPinnedRepoDigest([`${repository}@${digest}`], reference), 'actual pinned native canonical form').toBe(true);
  for (const observed of [undefined, null, [], [digest], [`${repository}:v26.06.9`], [reference],
    [`foreign/lightningd@${digest}`], [`${repository}@sha256:${'0'.repeat(64)}`]]) {
    expect(hasPinnedRepoDigest(observed, reference), 'missing, tag-only, wrong repository or changed digest never proves the pin').toBe(false);
  }
  const registryReference = `registry.example:5000/team/lightningd:v26.06.9@${digest}`;
  expect(hasPinnedRepoDigest([`registry.example:5000/team/lightningd@${digest}`], registryReference)).toBe(true);
  expect(hasPinnedRepoDigest([`registry.example/team/lightningd@${digest}`], registryReference), 'registry port cannot be discarded').toBe(false);
  expect(hasPinnedRepoDigest([`registry.example:5001/team/lightningd@${digest}`], registryReference)).toBe(false);
  expect(hasPinnedRepoDigest([`registry.example:5000/team/lightningd@${digest}`], `registry.example:5000/team/lightningd@${digest}`)).toBe(true);
  for (const malformed of [repository, `${repository}:tag`, `${repository}:@${digest}`, `${repository}@sha256:bad`]) {
    expect(hasPinnedRepoDigest([`${repository}@${digest}`], malformed), 'absence of an exact pinned digest cannot grant authority').toBe(false);
  }
});