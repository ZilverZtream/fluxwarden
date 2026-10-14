import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it, vi } from 'vitest';
import { asRecord, repoRoot, scratchDir } from '../helpers/cli.js';
import { secretForms } from '../helpers/output.js';

interface Request { node: string; method: string; path: string; body?: Record<string, unknown>; stream?: boolean; onData?: (text: string) => void }
interface Tool {
  redactText(text: string, secrets: Uint8Array[]): string;
  main(argv: string[], deps?: { transport?: (request: Request) => Promise<{ status: number; body: string }>; exec?: (node: string, argv: string[]) => Promise<{ exitCode: number; stdout: string; stderr: string }> }): Promise<number>;
}
const tool = async (): Promise<Tool> => await import(pathToFileURL(join(repoRoot, 'scripts/make-fixtures.mjs')).href) as Tool;
const fingerprint = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex').slice(0, 16);
const escape = (value: string, mixed: boolean): string => value.replace(/[\s\S]/g, (char, index: number) => mixed && index % 2 ? char : `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);

// SPEC §12.2 / INV-11: alternate encodings and split values must not recover a credential.
const alternateSecret = Buffer.from('disposable-review-credential-1234');
const base32 = 'MRUXG4DPONQWE3DFFVZGK5TJMV3S2Y3SMVSGK3TUNFQWYLJRGIZTI';
const alternateForms = [
  ['base32', base32], ['base32 padded', `${base32}===`], ['base32 lowercase', base32.toLowerCase()],
  ['UTF-16LE', Buffer.from(alternateSecret.toString(), 'utf16le').toString('latin1')],
  ['UTF-16BE', Buffer.from(alternateSecret.toString(), 'utf16le').swap16().toString('latin1')],
  ['wrapped base64', 'ZGlzcG9zYWJsZS1y\nZXZpZXctY3JlZGVu\ndGlhbC0xMjM0'],
  ['split hex', '646973706f7361626c652d7265766965772d63726564656e7469616c2d31323334'.replace(/.{8}/g, '$&\u200b')],
] as const;
it.each(alternateForms)('CP-009/B3 %s credential is removed with an exact fingerprint and uint64 retained', async (_name, encoded) => {
  const marker = `[redacted fp:${fingerprint(alternateSecret)}]`;
  const input = `{"note":${JSON.stringify(`before ${encoded} after`)},"n":18446744073709551615,"unchanged":"\\u0061"}`;
  expect((await tool()).redactText(input, [alternateSecret])).toBe(`{"note":${JSON.stringify(`before ${marker} after`)},"n":18446744073709551615,"unchanged":"\\u0061"}`);
});

it('CP-009/B3 adjacent literal fragments are scrubbed without changing array structure or uint64', async () => {
  const input = '{"note":["before ZGlzcG9zYWJsZS1y", "ZXZpZXctY3JlZGVu", "dGlhbC0xMjM0 after"],"n":18446744073709551615}';
  expect((await tool()).redactText(input, [alternateSecret])).toBe(`{"note":["before [redacted fp:${fingerprint(alternateSecret)}]", "", " after"],"n":18446744073709551615}`);
});

it('CP-009/B3 a single escaped credential member is scrubbed independently and an adjacent uint64 record stays exact', async () => {
  const secret = Buffer.from('synthetic-single-string-secret-12');
  const encoded = secret.toString().replace(/./g, char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
  // Each NDJSON record has one member, so no adjacent string literals can scrub the value.
  const input = `{"note":"${encoded}"}\n{"n":18446744073709551615}`;
  const result = (await tool()).redactText(input, [secret]);
  expect(result).toBe('{"note":"[redacted fp:2118c95a8a186d5b]"}\n{"n":18446744073709551615}');
  const decoded = asRecord(JSON.parse(result.split('\n')[0] ?? '') as unknown, 'redacted record');
  expect(decoded['note']).toBe('[redacted fp:2118c95a8a186d5b]');
  for (const [, form] of secretForms(secret)) expect(result.includes(form)).toBe(false);
});

// INV-11: JSON decoding must not recover preimages or credentials. Token-level editing
// must also retain exact uint64 literals (JSON.parse of the whole answer loses precision).
it.each([false, true])('CP-009/B3 JSON escaped and interleaved preimage members become fingerprints (mixed=%s)', async mixed => {
  const bytes = Buffer.alloc(32, 71), other = Buffer.alloc(32, 93);
  const input = `{"payment_\\u0070reimage":"${escape(bytes.toString('hex'), mixed)}","r_preimage":"${escape(other.toString('base64'), mixed)}","n":18446744073709551615}`;
  const result = (await tool()).redactText(input, [bytes]);
  expect(JSON.parse(result) as unknown).toEqual({ payment_preimage: `fp:${fingerprint(bytes)}`, r_preimage: `fp:${fingerprint(other)}`, n: Number('18446744073709551615') });
  expect(result).toContain('"n":18446744073709551615');
});

it('CP-009/B3 registered secret forms inside escaped JSON values are removed after decoding', async () => {
  const bytes = Buffer.from('disposable-fixture-secret-1234567');
  for (const [, form] of secretForms(bytes)) for (const mixed of [false, true]) {
    const result = (await tool()).redactText(`{"note":"prefix ${escape(form, mixed)} suffix","unchanged":"\\u0061"}`, [bytes]);
    expect(JSON.parse(result) as unknown).toEqual({ note: `prefix [redacted fp:${fingerprint(bytes)}] suffix`, unchanged: 'a' });
    expect(result).toContain('"unchanged":"\\u0061"');
  }
});

it.each([['NODE_OPTIONS', '--trace-warnings'], ['NODE_OPTIONS', ' '], ['NODE_DEBUG', 'HTTP'], ['NODE_DEBUG', 'fs,https'], ['NODE_DEBUG', 'net tls']])(
  'CP-009/B4 unsafe %s=%s refuses before owner reads or requests', async (name, value) => {
    vi.stubEnv(name, value);
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    const transport = vi.fn(), exec = vi.fn();
    try {
      const out = join(scratchDir('recording-env-'), 'out');
      expect(await (await tool()).main(['--owner', join(out, 'absent-owner.json'), '--out', out], { transport, exec })).toBe(1);
      expect(stderr.mock.calls.map(call => String(call[0])).join('')).toBe('make-fixtures environment: failed\n');
      expect([transport.mock.calls.length, exec.mock.calls.length, existsSync(out)]).toEqual([0, 0, false]);
    } finally { stderr.mockRestore(); vi.unstubAllEnvs(); }
  },
);

it.each([0, 1])('CP-009/B1 refresh retains historical profiles and publishes only after temporary rune cleanup succeeds (exit %i)', async cleanupExit => {
  const root = scratchDir('recording-transport-'), runtimeRoot = join(root, 'runtime'), sentinelRoot = join(root, 'sentinels'), out = join(root, 'out');
  mkdirSync(runtimeRoot); mkdirSync(sentinelRoot);
  const owner = join(root, 'owner.json'), project = 'fluxwarden-lab-recording-security';
  writeFileSync(owner, JSON.stringify({ project, runtimeRoot, sentinelRoot }));
  const keys = { 'lnd-r': `02${'11'.repeat(32)}`, 'lnd-p': `03${'22'.repeat(32)}`, 'cln-m': `02${'33'.repeat(32)}`, 'cln-r': `03${'44'.repeat(32)}` };
  writeFileSync(join(runtimeRoot, 'lab.json'), JSON.stringify({ project, nodes: Object.fromEntries(Object.entries(keys).map(([node, pubkey]) => [node, { pubkey }])) }));
  const calls: Request[] = [], commands: string[][] = [];
  let settled = false;
  const transport = (req: Request): Promise<{ status: number; body: string }> => {
    calls.push(req);
    const answer = (status: number, body: unknown): Promise<{ status: number; body: string }> => Promise.resolve({ status, body: JSON.stringify(body) });
    if (req.path === '/v1/getinfo') return req.node === 'lnd-r' ? answer(200, { chains: [{ network: 'regtest' }], version: '0.21.4-beta', block_height: 113 }) : answer(201, { network: 'regtest', version: 'v26.06.9' });
    if (req.path === '/v1/channels') return answer(200, { channels: [{ remote_pubkey: keys['cln-r'], chan_id: '1099511758848' }, { remote_pubkey: keys['lnd-p'], chan_id: '1099511758849' }] });
    if (req.path === `/v1/invoice/${'0'.repeat(64)}`) return answer(404, {});
    if (req.path.startsWith('/v2/router/track/')) {
      if (req.path.includes(Buffer.alloc(32).toString('base64url'))) return answer(404, {});
      const body = req.stream && req.onData ? `{"result":{"status":"${settled ? 'SUCCEEDED' : 'IN_FLIGHT'}"}}\n` : '{"result":{"status":"FAILED","failure_reason":"FAILURE_REASON_INCORRECT_PAYMENT_DETAILS"}}\n';
      req.onData?.(body); return Promise.resolve({ status: 200, body });
    }
    if (req.path === '/v2/invoices/settle') settled = true;
    if (req.path === '/v1/waitsendpay') return answer(500, { code: 200 });
    return answer(req.node.startsWith('lnd') ? 200 : 201, {});
  };
  const exec = (node: string, argv: string[]): Promise<{ exitCode: number; stdout: string; stderr: string }> => {
    commands.push([node, ...argv]);
    const method = argv[node.startsWith('lnd') ? 2 : 3];
    if (method === 'blacklistrune') return Promise.resolve({ exitCode: cleanupExit, stdout: '', stderr: '' });
    const value = method === 'addholdinvoice' ? { payment_addr: '11'.repeat(32) } : method === 'lookupinvoice' ? { state: 'ACCEPTED' } :
      method === 'listpeerchannels' ? { channels: [{ short_channel_id: '100x1x0' }] } : method === 'listchannels' ? { channels: [{ source: keys['lnd-r'], base_fee_millisatoshi: 1000, fee_per_millionth: 1000, delay: 80 }] } :
        method === 'waitsendpay' ? { status: 'complete' } : method === 'createrune' ? { rune: 'disposable-recorder-rune', unique_id: '1' } : {};
    return Promise.resolve({ exitCode: 0, stdout: JSON.stringify(value), stderr: '' });
  };
  if (cleanupExit === 0) cpSync(join(repoRoot, 'labs/fixtures'), out, { recursive: true });
  const before = JSON.parse(readFileSync(join(repoRoot, 'labs/fixtures/manifest.json'), 'utf8')) as { entries: { file: string; version: string; sha256: string; source: string }[] };
  const historical = before.entries.filter(entry => entry.version === '0.20.1-beta' || entry.version === 'v26.04.2');
  expect(historical).toHaveLength(2);
  const historicalBytes = historical.map(entry => readFileSync(join(repoRoot, 'labs/fixtures', entry.file)));
  const savedFile = 'recordings/lnd/0.21.4-beta/getinfo-previous.json';
  const savedSource = before.entries.find(entry => entry.file === 'recordings/lnd/0.21.4-beta/getinfo.json');
  if (!savedSource) throw new Error('current getinfo recording is required');
  const savedEntry = { ...savedSource, file: savedFile };
  const savedBytes = readFileSync(join(repoRoot, 'labs/fixtures', savedSource.file));
  if (cleanupExit === 0) {
    // A copy of a real observation under a distinct path is not refreshed by this run.
    writeFileSync(join(out, savedFile), savedBytes);
    before.entries.push(savedEntry);
    writeFileSync(join(out, 'manifest.json'), JSON.stringify(before));
  }
  const code = await (await tool()).main(['--owner', owner, '--out', out], { transport, exec });
  expect(commands.filter(command => command.includes('blacklistrune'))).toHaveLength(1);
  expect(code).toBe(cleanupExit === 0 ? 0 : 1);
  if (cleanupExit !== 0) { expect(existsSync(out)).toBe(false); return; }
  const after = JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8')) as typeof before;
  expect(after.entries).toHaveLength(before.entries.length);
  expect(after.entries.find(entry => entry.file === savedFile)).toEqual(savedEntry);
  expect(readFileSync(join(out, savedFile))).toEqual(savedBytes);
  for (const [index, entry] of historical.entries()) {
    expect(after.entries.find(now => now.file === entry.file)).toEqual(entry);
    expect(readFileSync(join(out, entry.file))).toEqual(historicalBytes[index]);
  }
  const current = after.entries.find(entry => entry.file === 'recordings/lnd/0.21.4-beta/getinfo.json');
  expect(current).toBeDefined();
  expect(current?.sha256).not.toBe(before.entries.find(entry => entry.file === current?.file)?.sha256);
  for (const entry of after.entries) expect(entry.sha256).toBe(createHash('sha256').update(readFileSync(join(out, entry.file))).digest('hex'));
  expect(new Set(after.entries.map(entry => entry.file)).size).toBe(after.entries.length);
  const settlements = calls.filter(call => call.path === '/v2/invoices/settle');
  expect(settlements.map(call => [call.node, call.method])).toEqual([['lnd-p', 'POST'], ['lnd-p', 'POST']]);
  const subscriptions = calls.filter(call => call.path.startsWith('/v2/router/track/') && call.onData);
  expect(subscriptions).toHaveLength(2);
  const [first, terminal] = subscriptions, settlement = settlements[0];
  if (!first || !terminal || !settlement) throw new Error('both observed subscriptions and settlement are required');
  expect(subscriptions.map(call => call.path)).toEqual([first.path, first.path]);
  expect(calls.indexOf(first)).toBeLessThan(calls.indexOf(settlement));
  expect(calls.indexOf(terminal)).toBeGreaterThan(calls.indexOf(settlement));
  const succeeded = JSON.parse(readFileSync(join(out, 'recordings/lnd/0.21.4-beta/track-succeeded.json'), 'utf8')) as { response: { lines: string[] } };
  expect(succeeded.response.lines.map(line => (JSON.parse(line) as { result: { status: string } }).result.status)).toEqual(['IN_FLIGHT', 'SUCCEEDED']);
  const registered = readdirSync(sentinelRoot).map(file => readFileSync(join(sentinelRoot, file)));
  for (const call of settlements) {
    const preimage = Buffer.from(String(call.body?.['preimage']), 'base64');
    expect(preimage.length).toBe(32);
    expect(registered.some(bytes => bytes.equals(preimage))).toBe(true);
  }
  for (const secret of registered) for (const [, form] of secretForms(secret)) expect(JSON.stringify(commands).includes(form)).toBe(false);
});

it.each([['lnd', /^0\.20(?:\.|$)/], ['cln', /^v?26\.04(?:\.|$)/]] as const)('CP-009/B2 authenticated historical %s profile has a versioned getinfo recording', (impl, version) => {
  // ARCHITECTURE §10.6: older profiles prove CAPABILITY_UNSUPPORTED from real observations.
  const value = JSON.parse(readFileSync(join(repoRoot, 'labs/fixtures/manifest.json'), 'utf8')) as { entries: { impl: string; version: string; id: string; file: string; sha256: string; source: string; provenance?: unknown }[] };
  const entry = value.entries.find(entry => entry.impl === impl && version.test(entry.version) && entry.id === 'getinfo');
  expect(entry, `${impl} ${String(version)} authenticated getinfo recording missing`).toBeDefined();
  if (!entry) throw new Error('historical recording unavailable');
  const bytes = readFileSync(join(repoRoot, 'labs/fixtures', entry.file));
  expect(createHash('sha256').update(bytes).digest('hex')).toBe(entry.sha256);
  const recording = JSON.parse(bytes.toString('utf8')) as { response: { status: number; body: string } };
  const info = JSON.parse(recording.response.body) as { version: string; commit_hash?: string; network?: string; chains?: { network: string }[] };
  expect(info.version).toMatch(version);
  expect(impl === 'lnd' ? info.chains?.[0]?.network : info.network).toBe('regtest');
  expect(recording.response.status).toBe(impl === 'lnd' ? 200 : 201);
  expect(entry.source).toBe('lab');
  const provenance = asRecord(entry.provenance, 'historical capture provenance');
  // Official release/image provenance:
  // github.com/lightningnetwork/lnd/releases/tag/v0.20.1-beta (signed binary verification)
  // github.com/ElementsProject/lightning/blob/ee6d4c4553d8989a289ca8848022197757ff98f5/doc/getting-started/getting-started/installation.md#docker
  const expected = impl === 'lnd' ? {
    release: 'https://github.com/lightningnetwork/lnd/releases/tag/v0.20.1-beta',
    sourceCommit: '848b72ce96eb68fa90fd4336523ca4c59bddcd4c',
    image: 'lightninglabs/lnd:v0.20.1-beta@sha256:f0a2bdc4b8bc89cb3b31b6e12d6b16ac5145defd916d8152cf0c1c07d8697cff',
    binarySha256: 'c532d7f2a5722c266ae58a74cedbd628144626043730f020a6c96476529ab6d6',
    cliBinarySha256: '49d8a3037419753cfc6e91919eac0a2587bcc098ed42a6e452483efebcf9e259',
    oracle: 'lncli --network=regtest getinfo',
  } : {
    release: 'https://github.com/ElementsProject/lightning/releases/tag/v26.04.2',
    sourceCommit: 'ee6d4c4553d8989a289ca8848022197757ff98f5',
    image: 'elementsproject/lightningd:v26.04.2@sha256:bed87dd031f087d368a4594cd243b8a3771a92dc9cb7d40be57c8d6d85cd54e8',
    binarySha256: '620a80ad7db6f366c5b4df74d4520453919032c6ae186871d9ba66b065b595cd',
    cliBinarySha256: '0382a6e57ebc3d8342e6743b11c89ea855665d1734e90308e936705bf69568af',
    oracle: 'lightning-cli --network=regtest getinfo',
  };
  expect(provenance).toMatchObject({ ...expected, observedNetwork: 'regtest', observedVersion: info.version });
  expect(provenance['imageId']).toMatch(/^sha256:[0-9a-f]{64}$/);
  expect(provenance['oracleSha256']).toMatch(/^[0-9a-f]{64}$/);
  expect(provenance['capture']).toEqual(expect.arrayContaining(['curl', '--cacert', '--header', `@/tmp/${impl}-header`]));
  expect(typeof provenance['capturedAt'] === 'string' && Number.isFinite(Date.parse(provenance['capturedAt']))).toBe(true);
  const credentials = asRecord(provenance['credentials'], 'credential fingerprints');
  expect(credentials['macaroon']).toMatch(/^fp:[0-9a-f]{16}$/);
  expect(credentials['rune']).toMatch(/^fp:[0-9a-f]{16}$/);
  if (impl === 'lnd') expect(info.commit_hash).toBe(expected.sourceCommit);
});
