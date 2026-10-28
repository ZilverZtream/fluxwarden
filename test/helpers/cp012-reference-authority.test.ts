// CP012 separate nonspending observation authority; pinned CLN rune wire
// encoding is ccan/rune/coding.c76-108,307-375 at v26.06.9. No native claim.
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { testRoot } from './env.js';
import { expect, it } from 'vitest';
import { assertCp012ReferenceScope, assertCp012SourceNamespaces, CP012_REFERENCE_METHODS, CP012_SCOPE_FILTER, type Cp012ReferenceAuthority } from './cp012-reference-authority.js';

function fixture() {
  const record: Cp012ReferenceAuthority = {
    version: 1, purpose: 'cp012-reference-read-only',
    binding: { version: 1, sourceCommit: 'a'.repeat(40), ownerPath: '/synthetic/owner.json', ownerSha256: 'b'.repeat(64),
      ownerId: 'synthetic', project: 'fluxwarden-lab-synthetic', manifestSha256: 'c'.repeat(64) },
    endpoint: { service: 'cln-m', host: 'localhost', port: 31002, pubkey: `02${'ab'.repeat(32)}`, tlsCert: '/synthetic/cert.pem', tlsSha256: 'd'.repeat(64) },
    credential: { path: '/synthetic/reference/cln-m-cp012-read.rune', sha256: 'e'.repeat(64), fingerprint: `fp:${'e'.repeat(16)}`, uniqueId: '27' },
    methods: CP012_REFERENCE_METHODS, ratePerMinute: '600',
  };
  const alternatives = CP012_REFERENCE_METHODS.map(method => ({ fieldname: 'method', condition: '=', value: method }));
  const row = { unique_id: '27', restrictions: [{ alternatives }, { alternatives: [{ fieldname: 'rate', condition: '=', value: '600' }] }] };
  const auth = randomBytes(32);
  const token = (tail = `=27&${CP012_REFERENCE_METHODS.map(method => `method=${method}`).join('|')}&rate=600`) =>
    Buffer.concat([auth, Buffer.from(tail)]).toString('base64url');
  return { record, row, token };
}

it('CP-012/REFERENCE-AUTH exact original token scope agrees with projected native metadata without raw rune output', () => {
  const f = fixture();
  expect(() => { assertCp012ReferenceScope({ runes: [f.row] }, f.token(), f.record); }).not.toThrow();
  expect(CP012_SCOPE_FILTER.includes('"rune"'), 'native projection never requests a raw credential').toBe(false);
  const mutations = [
    { name: 'daemon-extra-spending-method', apply: () => { f.row.restrictions[0]?.alternatives.push({ fieldname: 'method', condition: '=', value: 'sendpay' }); } },
    { name: 'daemon-wrong-rate', apply: () => { const r = f.row.restrictions[1]?.alternatives[0]; if (r) r.value = '601'; } },
    { name: 'foreign-native-id', apply: () => { f.row.unique_id = '28'; } },
  ];
  for (const mutation of mutations) {
    const saved = structuredClone(f.row); mutation.apply();
    expect(() => { assertCp012ReferenceScope({ runes: [f.row] }, f.token(), f.record); }, mutation.name).toThrow(/reference authority/);
    Object.assign(f.row, saved);
  }
  for (const flag of ['blacklisted', 'our_rune', 'stored'] as const) {
    expect(() => { assertCp012ReferenceScope({ runes: [{ ...f.row, [flag]: flag === 'blacklisted' }] }, f.token(), f.record); }, flag).toThrow(/reference authority/);
  }
  for (const tail of [
    '=27&method^list&rate=600',
    `=27&${CP012_REFERENCE_METHODS.map(method => `method=${method}`).join('|')}|method=sendpay&rate=600`,
    `=28&${CP012_REFERENCE_METHODS.map(method => `method=${method}`).join('|')}&rate=600`,
    `=27&${CP012_REFERENCE_METHODS.map(method => `method=${method}`).join('|')}&rate=601`,
  ]) expect(() => { assertCp012ReferenceScope({ runes: [f.row] }, f.token(tail), f.record); }, 'declared metadata cannot narrow actual token bytes').toThrow(/reference authority/);
  expect(() => { assertCp012ReferenceScope({ runes: [{ ...f.row, rune: 'forbidden raw field' }] }, f.token(), f.record); }).toThrow(/reference authority/);
  expect(() => { assertCp012ReferenceScope({ runes: [f.row], rune: 'forbidden raw root field' }, f.token(), f.record); }).toThrow(/reference authority/);
  expect(() => { assertCp012ReferenceScope({ runes: [{ ...f.row, blacklisted: 'false' }] }, f.token(), f.record); }).toThrow(/reference authority/);
  expect(() => { assertCp012ReferenceScope({ runes: [f.row, f.row] }, f.token(), f.record); }, 'duplicate native identity').toThrow(/reference authority/);
  expect(() => { assertCp012ReferenceScope({ runes: [f.row] }, `${f.token()}\n`, f.record); }, 'noncanonical original token').toThrow(/reference authority/);
});
it('CP-012/REFERENCE-SOURCE only declared owner sources may nest in the global source population', () => {
  const root = testRoot('FLUXWARDEN_TEST_TMP'), runtime = join(root, 'runtime'), temporary = join(root, 'temporary');
  const global = join(root, 'sources'), owned = join(global, 'owner-a'), evidence = join(root, 'evidence');
  expect(() => { assertCp012SourceNamespaces(runtime, temporary, owned, evidence, global); }).not.toThrow();
  for (const [ownerSource, globalSource] of [[global, global], [global, owned], [owned, root],
    [evidence, global], [join(evidence, 'owner-a'), evidence], [runtime, global], [temporary, global]]) {
    if (!ownerSource || !globalSource) throw new Error('source geometry fixture missing');
    expect(() => { assertCp012SourceNamespaces(runtime, temporary, ownerSource, evidence, globalSource); }).toThrow(/reference authority/);
  }
});