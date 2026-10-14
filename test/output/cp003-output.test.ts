import { spawn, spawnSync } from 'node:child_process';
import { Console } from 'node:console';
import { createHash, createPrivateKey } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { pathToFileURL } from 'node:url';
import { inspect, format } from 'node:util';
import { ESLint } from 'eslint';
import ts from 'typescript';
import tseslint from 'typescript-eslint';
import { clearCaches } from '@typescript-eslint/parser';
import { beforeAll, expect, it, onTestFinished } from 'vitest';
import { childEnv, repoRoot } from '../helpers/cli.js';
import { capturedSink, declareDeliberateOutputs, discardSink, marker, outputModule, registerSentinels, registryIsNonempty, scratchRoot, secretForms, secretType, sentinelRoot, sentinels } from '../helpers/output.js';

beforeAll(() => { registerSentinels(); });

it('CP-003/B1 every Secret formatting surface emits only the independently computed fingerprint marker', async () => {
  const Secret = await secretType();
  const original = sentinels()[0]?.bytes;
  if (!original) throw new Error('preimage fixture is missing');
  const supplied = Buffer.from(original);
  const secret = new Secret(supplied);
  // SHA-256 of the original fixture bytes supplies the oracle; mutating the caller's
  // buffer catches accidental aliasing of credential storage.
  const expected = `[redacted fp:${createHash('sha256').update(original).digest('hex').slice(0, 16)}]`;
  supplied.fill(0);
  const capture = capturedSink();
  new Console({ stdout: capture.sink, stderr: capture.sink }).log(secret);
  // Template coercion is itself one of the required public formatting surfaces.
  // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
  const template = `${secret}`;
  const forms = [String(secret), template, JSON.parse(JSON.stringify(secret)) as unknown, inspect(secret), capture.text().replace(/\r?\n$/, ''), format('%s', secret), format('%O', secret)];
  for (const value of forms) expect(value === expected, 'format is exactly the fingerprint marker').toBe(true);
  for (const value of forms) {
    if (typeof value !== 'string') throw new Error('format did not return text');
    for (const [, encoded] of secretForms(original)) expect(!value.includes(encoded), 'credential representation is absent').toBe(true);
  }
  expect(Object.entries(secret).length, 'no enumerable credential property').toBe(0);
  expect(Object.keys({ ...secret }).length, 'spread exposes no credential property').toBe(0);
  const clone: unknown = structuredClone(secret);
  expect(JSON.stringify(clone).includes(expected) || JSON.stringify(clone) === '{}', 'structured clone contains no credential properties').toBe(true);
});

it('CP-003/B2 every registered credential kind and encoding is removed while ordinary bytes are preserved', async () => {
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  const fixtures = sentinels();
  const output = createOutput({ stdout: discardSink(), stderr: discardSink(), secrets: fixtures.map(row => new Secret(row.bytes)) });
  for (const row of fixtures) {
    for (const [encoding, value] of secretForms(row.bytes)) {
      const input = `before / ${value} / between / ${value} / after é`;
      const redacted = output.redact(input);
      const parts = redacted.split(' / ');
      expect(parts.length === 5 && parts[0] === 'before' && marker(parts[1] ?? '') && parts[2] === 'between' && marker(parts[3] ?? '') && parts[4] === 'after é', `${row.kind}/${encoding}: redaction and byte preservation`).toBe(true);
    }
  }
});

it('CP-003/B3 all five payment request prefixes retain their original case and redact only their payload', async () => {
  const { createOutput } = await outputModule();
  const output = createOutput({ stdout: discardSink(), stderr: discardSink(), secrets: [] });
  // The reference defines prefix recognition plus at least twenty payload characters;
  // invoice decoding and checksum validation are outside this output property.
  for (const prefix of ['lnbcrt', 'lnbc', 'lntb', 'lntbs', 'lnsb']) {
    for (const hrp of [prefix, prefix.toUpperCase()]) {
      const payload = `${hrp}100n1${'q'.repeat(96)}`;
      const expected = `left (${hrp}[redacted]), right é`;
      expect(output.redact(`left (${payload}), right é`) === expected, `${hrp}: exact prefix and surrounding text`).toBe(true);
    }
  }
  expect(output.redact('ordinary lnbc text, lntbs, café'), 'ordinary prefix fragments remain').toBe('ordinary lnbc text, lntbs, café');
});

it('CP-003/B4 node controls bidi and invisible characters become printable escapes in text and one UTF-8 JSON document', async () => {
  const { createOutput } = await outputModule();
  const points = [0x1b, 0x07, 0x7f, ...Array.from({ length: 32 }, (_, i) => 0x80 + i), ...Array.from({ length: 4 }, (_, i) => 0x2066 + i), ...Array.from({ length: 5 }, (_, i) => 0x200b + i)];
  const hostile = `alias é:${points.map(point => String.fromCharCode(point)).join('|')}:done`;
  function escaped(text: string): boolean {
    if (!text.startsWith('alias é:') || !text.endsWith(':done')) return false;
    const parts = text.slice('alias é:'.length, -':done'.length).split('|');
    return parts.length === points.length && points.every((point, index) => new RegExp(`^(?:\\\\x${point.toString(16).padStart(2, '0')}|\\\\u${point.toString(16).padStart(4, '0')})$`, 'i').test(parts[index] ?? ''));
  }
  const text = capturedSink(), json = capturedSink();
  const output = createOutput({ stdout: text.sink, stderr: discardSink(), secrets: [] });
  const jsonOutput = createOutput({ stdout: json.sink, stderr: discardSink(), secrets: [] });
  await output.write(hostile, { stream: 'stdout', exitCode: 0 });
  await jsonOutput.json({ schema: 1, command: 'status', ok: true, warnings: [], result: { alias: hostile }, error: null }, { exitCode: 0 });
  expect(escaped(text.text()), 'text preserves accented letters and escapes each hostile character').toBe(true);
  const envelope: unknown = JSON.parse(json.text());
  const result = envelope as { schema: number; command: string; ok: boolean; warnings: unknown[]; result: { alias: string }; error: unknown };
  expect(result.schema).toBe(1);
  expect(result.command).toBe('status');
  expect(result.ok).toBe(true);
  expect(result.warnings).toEqual([]);
  expect(result.error).toBeNull();
  expect(escaped(result.result.alias), 'JSON strings contain printable escapes after parsing').toBe(true);
  expect(Buffer.from(text.text()).includes(Buffer.from('é')), 'UTF-8 accent encoding').toBe(true);
});

it('CP-003/B5 a 100 MiB result streams bounded complete UTF-8 chunks with cross-boundary secrets redacted', async () => {
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  const fixture = sentinels()[0]?.bytes;
  if (!fixture) throw new Error('preimage fixture missing');
  const hex = fixture.toString('hex');
  const size = 100 * 1024 * 1024;
  // Both features straddle successive 64 KiB boundaries in the original UTF-8.
  const prefix = 'a'.repeat(65536 - 13);
  const middle = 'b'.repeat(65536 - (Buffer.byteLength(prefix) + hex.length) % 65536 - 2);
  const head = `${prefix}${hex}${middle}🛰`;
  const text = `${head}${'c'.repeat(size - Buffer.byteLength(head))}`;
  const fingerprint = `[redacted fp:${createHash('sha256').update(fixture).digest('hex').slice(0, 16)}]`;
  const expectedHashes = ['[redacted]', fingerprint].map(replacement => createHash('sha256').update(`${prefix}${replacement}${middle}🛰${'c'.repeat(size - Buffer.byteLength(head))}`).digest('hex'));
  const hash = createHash('sha256');
  let count = 0, maximum = 0, invalid = false, leaked = false, bytesWritten = 0;
  const sink = new Writable({ highWaterMark: 1024, write(chunk: Buffer, _encoding, callback) {
    const bytes = Buffer.from(chunk);
    count++; maximum = Math.max(maximum, bytes.byteLength); bytesWritten += bytes.byteLength;
    try { new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { invalid = true; }
    leaked ||= bytes.includes(Buffer.from(hex));
    hash.update(bytes);
    // Async transport callback forces real backpressure without sleep-based timing.
    setImmediate(callback);
  } });
  const output = createOutput({ stdout: sink, stderr: discardSink(), secrets: [new Secret(fixture)] });
  await output.write(text, { exitCode: 0 });
  expect(count >= 1600, 'a do-nothing or one-shot writer cannot satisfy the chunk count').toBe(true);
  expect(maximum).toBeLessThanOrEqual(65536);
  expect(bytesWritten > 99 * 1024 * 1024, 'the complete large result was written').toBe(true);
  expect(invalid, 'each write independently decodes as UTF-8').toBe(false);
  expect(leaked, 'registered secret is absent from chunks').toBe(false);
  expect(expectedHashes.includes(hash.digest('hex')), 'complete result differs only by the secret marker').toBe(true);
});

it('CP-003/B5 early-closed real stdout and stderr pipes preserve the command exit code and finish promptly', async () => {
  for (const target of ['stdout', 'stderr']) {
    const result = await new Promise<{ code: number | null; signal: string | null; diagnostic: string; sawBytes: boolean }>((resolve, reject) => {
      const child = spawn(process.execPath, [join(repoRoot, 'test/fixtures/output/pipe.mjs'), target], { cwd: scratchRoot(), env: { ...childEnv(), LANG: 'C', LC_ALL: 'C' }, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
      const reader = target === 'stdout' ? child.stdout : child.stderr;
      const other = target === 'stdout' ? child.stderr : child.stdout;
      let diagnostic = '', sawBytes = false;
      reader.once('data', () => { sawBytes = true; reader.destroy(); });
      other.on('data', (chunk: Buffer) => { diagnostic += chunk.toString('utf8'); });
      const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('closed pipe did not complete within 10000 ms')); }, 10000);
      child.on('error', error => { clearTimeout(timer); reject(error); });
      child.on('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, diagnostic, sawBytes }); });
    });
    expect(result.sawBytes, 'the writer actually reached the real pipe').toBe(true);
    expect(result.code, target).toBe(7);
    expect(result.signal, target).toBeNull();
    expect(result.diagnostic, target).toBe('completed\n');
  }
});

it('CP-003/B6 reveal capability imports are confined to adapters and approval and indirect bypasses are diagnosed', async () => {
  const eslint = new ESLint({ cwd: repoRoot, overrideConfig: { languageOptions: { parserOptions: { projectService: false, project: null } }, rules: { ...tseslint.configs.disableTypeChecked.rules } } });
  const direct = 'import { revealSecret } from "../core/secret.js"; export const capability = revealSecret;';
  const allowedDirect = 'import { revealSecret } from "../core/secret.js"; void revealSecret;';
  async function errors(source: string, path: string): Promise<number> {
    const rows = await eslint.lintText(source, { filePath: join(repoRoot, path) });
    expect(rows.some(row => row.messages.some(message => message.fatal)), `${path}: source parses`).toBe(false);
    return rows.reduce((total, row) => total + row.errorCount, 0);
  }
  // Only the node adapters and the approval signer may reveal credential bytes.
  const allowedModules = ['node-lnd/credential', 'node-cln/credential', 'approval/sign'];
  for (const module of allowedModules) expect(await errors(allowedDirect, `src/${module}.ts`), `${module}: direct capability is allowed`).toBe(0);
  // Allowed modules (the adapters and the approval signer) may call the capability internally only;
  // exporting it in any form is an error everywhere (the CP-026 confinement).
  const internal = 'import { createHash } from "node:crypto"; import { revealSecret, type Secret } from "../core/secret.js"; '
    + 'function fingerprint(s: Secret): string { const hash = createHash("sha256"); hash.update(revealSecret(s)); return hash.digest("hex").slice(0, 16); } '
    + 'export const present = (s: Secret): boolean => fingerprint(s).length === 16;';
  const exportForms = [
    direct,
    'import { revealSecret } from "../core/secret.js"; export default revealSecret;',
    'import { revealSecret } from "../core/secret.js"; export { revealSecret };',
    'import { revealSecret } from "../core/secret.js"; export { revealSecret as capability };',
    'export { revealSecret } from "../core/secret.js";',
    'export * from "../core/secret.js";',
  ];
  for (const path of ['src/node-lnd/credential.ts', 'src/node-cln/credential.ts', 'src/approval/sign.ts']) {
    expect(await errors(internal, path), `${path}: internal use is allowed`).toBe(0);
    for (const source of exportForms) expect(await errors(source, path) > 0, `${path}: exported capability is reported: ${source}`).toBe(true);
  }
  for (const directory of ['cli', 'planner', 'output', 'core', 'executor', 'reconciler', 'policy', 'ledger', 'persistence', 'daemon', 'other', 'approval']) {
    expect(await errors(direct, `src/${directory}/credential.ts`) > 0, `${directory}: forbidden direct capability`).toBe(true);
    expect(await errors(internal, `src/${directory}/credential.ts`) > 0, `${directory}: forbidden internal use`).toBe(true);
  }
  const bypasses = [
    'export const extract = (s: {reveal(): unknown}) => s["reveal"]();',
    'export const extract = (s: {reveal(): unknown}) => { const {reveal} = s; return reveal(); };',
    'export const extract = (s: {reveal(): unknown}) => s.reveal.call(s);',
    'export {revealSecret as capability} from "../core/secret.js";',
    'export const extract = async () => (await import("../core/secret.js")).revealSecret;',
    'import * as secrets from "../core/secret.js"; export const extract = secrets["revealSecret"];',
    'import {revealSecret as extract} from "../core/secret.js"; export {extract};',
  ];
  for (const [index, source] of bypasses.entries()) expect(await errors(source, `src/cli/bypass-${String(index)}.ts`) > 0, `bypass ${String(index)} is reported`).toBe(true);

  // The capability stays confined even when an allowed
  // module gives it an ordinary export name. Either end of the sequence may
  // diagnose the crossing; unrelated lint errors cannot prove this boundary.
  async function capabilityErrors(source: string, path: string): Promise<number> {
    const rows = await eslint.lintText(source, { filePath: join(repoRoot, path) });
    expect(rows.some(row => row.messages.some(message => message.fatal)), `${path}: source parses`).toBe(false);
    return rows.reduce((total, row) => total + row.messages.filter(message => message.severity === 2 && /credential|restricted[- /]?capability|reveal(?:Secret)?/i.test(`${message.ruleId ?? ''} ${message.message}`)).length, 0);
  }
  const exports = [
    { syntax: 'export-from', source: 'export { revealSecret as credentialBytes } from "../core/secret.js";' },
    { syntax: 'imported-local export', source: 'import { revealSecret as extract } from "../core/secret.js"; export { extract as credentialBytes };' },
  ];
  for (const module of allowedModules) {
    for (const exporter of exports) {
      const exporterErrors = await capabilityErrors(exporter.source, `src/${module}.ts`);
      for (const consumer of ['cli', 'output', 'planner']) {
        const source = `import { credentialBytes } from "../${module}.js"; export const extract = credentialBytes;`;
        const consumerErrors = await capabilityErrors(source, `src/${consumer}/credential.ts`);
        expect.soft(exporterErrors + consumerErrors, `${module} ${exporter.syntax} -> ${consumer}: capability crossing is diagnosed`).toBeGreaterThan(0);
      }
    }
  }
});

it('CP-003/B7 hostile near-matches stay unchanged under the redaction time and growth bounds', async () => {
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  const output = createOutput({ stdout: discardSink(), stderr: discardSink(), secrets: sentinels().map(row => new Secret(row.bytes)) });
  const fragment = 'abcdef0123456789 QWxhZGRpbjpvcGVu lnbc_ lntbs_ lnsb_ ';
  const small = fragment.repeat(Math.ceil(1024 * 1024 / fragment.length)).slice(0, 1024 * 1024);
  const large = small + small;
  output.redact(fragment.repeat(100));
  function measure(text: string, timings: number[]): void {
    const start = performance.now();
    const result = output.redact(text);
    timings.push(performance.now() - start);
    expect(result === text, 'almost-matches are preserved').toBe(true);
  }
  const smallTimings: number[] = [], largeTimings: number[] = [];
  // Alternate sizes so their five samples span the same measurement period.
  for (let i = 0; i < 5; i++) {
    measure(small, smallTimings);
    measure(large, largeTimings);
  }
  const median = (timings: number[]): number => [...timings].sort((a, b) => a - b)[2] ?? Infinity;
  const one = median(smallTimings), two = median(largeTimings);
  console.info(JSON.stringify({ case: 'CP-003/B7', oneMiBSamplesMs: smallTimings, twoMiBSamplesMs: largeTimings,
    oneMiBMedianMs: one, twoMiBMedianMs: two }));
  expect(one, 'one MiB median redaction duration').toBeLessThan(200);
  expect(two <= one * 2.5 + 5, 'doubling stays within approximately linear growth and timer noise').toBe(true);
});

it('CP-003/B8 the committed sentinel set is valid and its clean and planted leak checks have safe exact outcomes', () => {
  const fixtures = sentinels();
  expect(fixtures.map(row => row.kind).sort()).toEqual(['ed25519-key', 'macaroon', 'preimage', 'rune', 'tls-key']);
  expect(fixtures.every(row => row.bytes.byteLength > 0), 'every original kind is nonempty').toBe(true);
  const preimage = fixtures.find(row => row.kind === 'preimage');
  expect(preimage?.bytes.byteLength).toBe(32);
  const macaroon = fixtures.find(row => row.kind === 'macaroon')?.bytes;
  if (!macaroon) throw new Error('macaroon fixture is missing');
  // Macaroon v2 packet framing: version, optional location, identifier, two EOS
  // markers (header and caveat list), signature tag and 32-byte signature.
  let offset = 0;
  expect(macaroon[offset++]).toBe(2);
  expect(macaroon[offset++]).toBe(1);
  const locationLength = macaroon[offset++] ?? 0;
  offset += locationLength;
  expect(macaroon[offset++]).toBe(2);
  const identifierLength = macaroon[offset++] ?? 0;
  expect(identifierLength > 0).toBe(true);
  offset += identifierLength;
  expect(macaroon[offset++]).toBe(0);
  expect(macaroon[offset++]).toBe(0);
  expect(macaroon[offset++]).toBe(6);
  expect(macaroon[offset++]).toBe(32);
  expect(macaroon.length - offset).toBe(32);
  const rune = fixtures.find(row => row.kind === 'rune')?.bytes.toString('utf8') ?? '';
  expect(/^[A-Za-z0-9_-]+={0,2}$/.test(rune) && Buffer.from(rune, 'base64url').byteLength > 32, 'rune has signature and restriction bytes').toBe(true);
  for (const kind of ['tls-key', 'ed25519-key']) {
    const key = fixtures.find(row => row.kind === kind);
    if (!key) throw new Error('key fixture missing');
    expect(key.bytes.toString('utf8').startsWith('-----BEGIN PRIVATE KEY-----\n'), `${kind}: PEM header`).toBe(true);
    expect(createPrivateKey(key.bytes).asymmetricKeyType).toBe(kind === 'ed25519-key' ? 'ed25519' : 'rsa');
  }
  expect(registryIsNonempty(sentinelRoot()), 'committed fixtures are registered for the outer suite scan').toBe(true);
  const root = mkdtempSync(join(scratchRoot(), 'sentinel-check-'));
  const evidence = join(root, 'retained');
  mkdirSync(evidence);
  const registry = join(repoRoot, 'test/sentinels.json');
  // A sentinel directory private to this case, so sentinels other suites register and
  // remove concurrently cannot change its verdicts or diagnostics.
  const privateSentinels = mkdtempSync(join(sentinelRoot(), 'b8-'));
  registerSentinels(privateSentinels);
  const args = [join(repoRoot, 'scripts/leak-check.mjs'), '--sentinels', registry, '--sentinel-dir', privateSentinels];
  const clean = join(root, 'clean.log');
  writeFileSync(clean, 'ordinary UTF-8 output é\n');
  const result = spawnSync(process.execPath, [...args, clean], { cwd: repoRoot, encoding: 'utf8', windowsHide: true, timeout: 10000 });
  if (result.error) throw result.error;
  expect(result.status).toBe(0);
  const planted = join(evidence, 'planted.log');
  const value = preimage?.bytes;
  if (!value) throw new Error('preimage missing');
  // Deliberate leak: declared by exact path for concurrent suite-wide scans; the checker
  // below runs with this test's own root, where nothing is declared.
  declareDeliberateOutputs([planted]);
  try {
    writeFileSync(planted, value.toString('hex'));
    const leak = spawnSync(process.execPath, [...args, planted], { cwd: repoRoot, env: { ...process.env, FLUXWARDEN_TEST_TMP: root }, encoding: 'utf8', windowsHide: true, timeout: 10000 });
    if (leak.error) throw leak.error;
    expect(leak.status).toBe(1);
    const diagnostic = leak.stdout + leak.stderr;
    expect(diagnostic.includes(planted), 'leak diagnostic names the planted path').toBe(true);
    expect(/hex/i.test(diagnostic), 'leak diagnostic names the encoding').toBe(true);
    for (const [, encoded] of secretForms(value)) expect(!diagnostic.includes(encoded), 'leak diagnostic never prints the value').toBe(true);
  } finally { rmSync(planted, { force: true }); }
});

it('CP-003/B9 preimages redact only in named JSON and text fields unless the value is separately registered', async () => {
  const { createOutput } = await outputModule();
  const unregistered = createHash('sha256').update('disposable unregistered field value').digest('hex');
  const output = createOutput({ stdout: discardSink(), stderr: discardSink(), secrets: [] });
  for (const field of ['preimage', 'r_preimage', 'payment_preimage']) {
    const json = output.redact(JSON.stringify({ [field]: unregistered, channel_id: unregistered }));
    const decoded = JSON.parse(json) as Record<string, unknown>;
    const rendered = decoded[field];
    expect(typeof rendered === 'string' && marker(rendered), `${field}: JSON preimage is redacted`).toBe(true);
    expect(decoded['channel_id'] === unregistered, `${field}: unrelated JSON value survives`).toBe(true);
    const text = output.redact(`${field}=${unregistered}; channel_id=${unregistered}`);
    const expectedTail = `; channel_id=${unregistered}`;
    expect(text.startsWith(`${field}=`) && text.endsWith(expectedTail) && marker(text.slice(field.length + 1, -expectedTail.length)), `${field}: text redacts only the named value`).toBe(true);
  }
  const Secret = await secretType();
  const registered = createOutput({ stdout: discardSink(), stderr: discardSink(), secrets: [new Secret(Buffer.from(unregistered, 'hex'))] });
  expect(marker(registered.redact(unregistered)), 'registration redacts an otherwise unrelated value').toBe(true);
});

it('CP-003/B1 credential bytes revealed through the approved capability are a private copy unaffected by caller buffer mutation', async () => {
  // Credential bytes live only in Secret storage. Expected bytes come
  // from an independent copy of the fixture, never from the Secret under test.
  const module = await import(pathToFileURL(join(repoRoot, 'dist/core/secret.js')).href) as { Secret: new (bytes: Uint8Array) => object; revealSecret: (secret: object) => Uint8Array };
  const fixture = sentinels().find(row => row.kind === 'preimage')?.bytes;
  if (!fixture) throw new Error('preimage fixture is missing');
  const expected = Buffer.from(fixture);
  const supplied = Buffer.from(fixture);
  const secret = new module.Secret(supplied);
  supplied.fill(0);
  supplied[0] = 0xff;
  expect(Buffer.from(module.revealSecret(secret)).equals(expected), 'revealed bytes equal the original credential after caller mutation').toBe(true);
  module.revealSecret(secret).fill(0);
  expect(Buffer.from(module.revealSecret(secret)).equals(expected), 'mutating a revealed copy leaves the stored credential intact').toBe(true);
});

it('CP-003/B2 base64 and base64url of a registered credential hex text are removed padded and unpadded while ordinary bytes are preserved', async () => {
  // Credentials must not appear in any encoding; LND carries macaroons as hex text in a
  // request header, so base64 or base64url of that hex text is the same credential.
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  const fixtures = sentinels();
  const output = createOutput({ stdout: discardSink(), stderr: discardSink(), secrets: fixtures.map(row => new Secret(row.bytes)) });
  function nested(bytes: Buffer): [string, string][] {
    const rows: [string, string][] = [];
    for (const [hexCase, hex] of [['lower', bytes.toString('hex')], ['upper', bytes.toString('hex').toUpperCase()]] as const) {
      const base64 = Buffer.from(hex).toString('base64');
      const url = base64.replace(/\+/g, '-').replace(/\//g, '_');
      rows.push([`base64-of-hex-${hexCase}`, base64], [`base64-of-hex-${hexCase}-unpadded`, base64.replace(/=+$/, '')], [`base64url-of-hex-${hexCase}-padded`, url], [`base64url-of-hex-${hexCase}-unpadded`, url.replace(/=+$/, '')]);
    }
    return rows;
  }
  const preimage = fixtures.find(row => row.kind === 'preimage')?.bytes;
  if (!preimage) throw new Error('preimage fixture is missing');
  // A 32-byte preimage has 64 hex characters, whose base64 ends in "=="; the unpadded
  // form is therefore a distinct string that must be covered on its own.
  expect(Buffer.from(preimage.toString('hex')).toString('base64').endsWith('=='), 'fixture exercises distinct unpadded forms').toBe(true);
  for (const row of fixtures) {
    for (const [encoding, value] of nested(row.bytes)) {
      const redacted = output.redact(`before / ${value} / between / ${value} / after é`);
      const parts = redacted.split(' / ');
      expect(parts.length === 5 && parts[0] === 'before' && marker(parts[1] ?? '') && parts[2] === 'between' && marker(parts[3] ?? '') && parts[4] === 'after é', `${row.kind}/${encoding}: redaction and byte preservation`).toBe(true);
    }
  }
  for (const [encoding, value] of nested(preimage)) {
    const captured = capturedSink();
    const writer = createOutput({ stdout: captured.sink, stderr: discardSink(), secrets: [new Secret(preimage)] });
    await writer.write(`left / ${value} / right`, { stream: 'stdout', exitCode: 0 });
    const emitted = captured.text();
    expect(emitted.includes(value), `${encoding}: emitted bytes omit the credential`).toBe(false);
    const match = /^left \/ (.*) \/ right\r?\n?$/.exec(emitted);
    expect(match !== null && marker(match[1] ?? ''), `${encoding}: emitted bytes keep the surrounding text around one marker`).toBe(true);
  }
});

it('CP-003/B3 a payment request prefix followed by fewer than twenty payload characters stays intact even when a shorter prefix would reach the threshold', async () => {
  const { createOutput } = await outputModule();
  const output = createOutput({ stdout: discardSink(), stderr: discardSink(), secrets: [] });
  // Recognition needs the prefix and at least 20 payload
  // characters. The longest supported prefix decides, so "lntbs" + 19 is not "lntb" + 20.
  for (const [prefix, shorter] of [['lntbs', 'lntb'], ['lnbcrt', 'lnbc']] as const) {
    for (const hrp of [prefix, prefix.toUpperCase()]) {
      const short = `${hrp}${'q'.repeat(19)}`;
      expect(output.redact(`left (${short}), right`), `${hrp}+19: ordinary fragment is preserved, not read as ${shorter}`).toBe(`left (${short}), right`);
      expect(output.redact(`left (${hrp}${'q'.repeat(20)}), right`), `${hrp}+20: redacted after the full prefix`).toBe(`left (${hrp}[redacted]), right`);
    }
  }
});

it('CP-003/B6 statically computable module specifiers and member names reaching the reveal capability are diagnosed in forbidden locations', async () => {
  const eslint = new ESLint({ cwd: repoRoot, overrideConfig: { languageOptions: { parserOptions: { projectService: false, project: null } }, rules: { ...tseslint.configs.disableTypeChecked.rules } } });
  const shapes = [
    'export const capability = async (): Promise<unknown> => { const module = await import("../core/" + "secret.js") as Record<string, unknown>; return module["reve" + "alSecret"]; };',
    'export const capability = async (): Promise<unknown> => { const module = await import(`../core/${"secret"}.js`) as Record<string, unknown>; return module[`reveal${"Secret"}`]; };',
    'import * as secrets from "../core/secret.js"; export const capability: unknown = (secrets as Record<string, unknown>)["reveal" + "Secret"];',
    'export const extract = (s: Record<string, (() => unknown) | undefined>): unknown => s["rev" + "eal"]?.();',
  ];
  // Every shape is ordinary type-correct code under the repository's strict compiler
  // options, so the boundary cannot rely on the type checker rejecting it.
  const config: unknown = ts.readConfigFile(join(repoRoot, 'tsconfig.json'), path => ts.sys.readFile(path)).config;
  const options = { ...ts.parseJsonConfigFileContent(config, ts.sys, repoRoot).options, noEmit: true };
  const normal = (path: string): string => path.replace(/\\/g, '/');
  for (const [index, source] of shapes.entries()) {
    const file = normal(join(repoRoot, `src/cli/computed-${String(index)}.ts`));
    const host = ts.createCompilerHost(options);
    const read = host.readFile.bind(host), exists = host.fileExists.bind(host), get = host.getSourceFile.bind(host);
    host.readFile = path => normal(path) === file ? source : read(path);
    host.fileExists = path => normal(path) === file || exists(path);
    host.getSourceFile = (path, language, ...rest) => normal(path) === file ? ts.createSourceFile(path, source, language, true) : get(path, language, ...rest);
    const program = ts.createProgram({ rootNames: [file], options, host });
    const diagnostics = ts.getPreEmitDiagnostics(program).filter(item => item.file !== undefined && normal(item.file.fileName) === file).map(item => ts.flattenDiagnosticMessageText(item.messageText, ' '));
    expect(diagnostics, `shape ${String(index)}: strict type-correct`).toEqual([]);
    for (const directory of ['cli', 'output', 'planner']) {
      const rows = await eslint.lintText(source, { filePath: join(repoRoot, `src/${directory}/computed-${String(index)}.ts`) });
      expect(rows.some(row => row.messages.some(message => message.fatal)), `shape ${String(index)}: source parses`).toBe(false);
      const capability = rows.reduce((total, row) => total + row.messages.filter(message => message.severity === 2 && message.ruleId === 'credentials/restricted-capability').length, 0);
      expect.soft(capability, `shape ${String(index)} in src/${directory}: capability boundary diagnosed`).toBeGreaterThan(0);
    }
  }
});

it('CP-003/B4 embedding bidi controls, the byte order mark and other invisible format characters become printable escapes', async () => {
  const { createOutput } = await outputModule();
  // Unicode Bidi_Control U+061C and U+202A..U+202E; invisible format characters U+00AD,
  // U+180E, U+2060..U+2064 and U+FEFF (zero width no-break space / byte order mark).
  const points = [0x061c, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x00ad, 0x180e, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xfeff];
  const hostile = `alias é:${points.map(point => String.fromCharCode(point)).join('|')}:done`;
  const capture = capturedSink();
  const output = createOutput({ stdout: capture.sink, stderr: discardSink(), secrets: [] });
  await output.write(hostile, { stream: 'stdout', exitCode: 0 });
  const text = capture.text().replace(/\r?\n$/, '');
  expect(text.startsWith('alias é:') && text.endsWith(':done'), 'surrounding text and accented letters are unchanged').toBe(true);
  const parts = text.slice('alias é:'.length, -':done'.length).split('|');
  expect(parts.length, 'one rendering per hostile character').toBe(points.length);
  for (const [index, point] of points.entries()) {
    const hex = point.toString(16);
    expect.soft(new RegExp(`^(?:\\\\x${hex.padStart(2, '0')}|\\\\u${hex.padStart(4, '0')})$`, 'i').test(parts[index] ?? ''), `U+${hex.padStart(4, '0').toUpperCase()} is a printable escape`).toBe(true);
  }
});

it('CP-003/B2 a registered PEM key is removed in CRLF, armor-less body, JSON-escaped and DER base64 and hex forms', async () => {
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  const fixtures = sentinels();
  const output = createOutput({ stdout: discardSink(), stderr: discardSink(), secrets: fixtures.map(row => new Secret(row.bytes)) });
  for (const kind of ['tls-key', 'ed25519-key']) {
    const bytes = fixtures.find(row => row.kind === kind)?.bytes;
    if (!bytes) throw new Error(`${kind} fixture is missing`);
    const pem = bytes.toString('utf8');
    const body = pem.split('\n').filter(line => line.length > 0 && !line.startsWith('-----'));
    // The PKCS #8 DER comes from node:crypto, independently of the PEM text handling.
    const der = createPrivateKey(bytes).export({ format: 'der', type: 'pkcs8' });
    const forms: [string, string][] = [
      ['pem-crlf', pem.replace(/\n/g, '\r\n')],
      ['body-lf', body.join('\n')],
      ['body-crlf', body.join('\r\n')],
      ['json-escaped', JSON.stringify(pem).slice(1, -1)],
      ['der-base64', der.toString('base64')],
      ['der-base64url', der.toString('base64url')],
      ['der-hex-lower', der.toString('hex')],
      ['der-hex-upper', der.toString('hex').toUpperCase()],
    ];
    for (const [encoding, value] of forms) {
      const redacted = output.redact(`before / ${value} / after é`);
      const label = `${kind}/${encoding}`;
      expect.soft(redacted.startsWith('before / ') && redacted.endsWith(' / after é'), `${label}: surrounding text is preserved`).toBe(true);
      const middle = redacted.slice('before / '.length, -' / after é'.length);
      expect.soft(middle.replace(/\[redacted(?: fp:[0-9a-f]{16})?\]/g, '').replace(/\r|\n|\\r|\\n/g, '') === '', `${label}: only markers and line breaks remain`).toBe(true);
      expect.soft(marker(middle.split(/\r?\n|\\r\\n|\\n/)[0] ?? ''), `${label}: at least one marker`).toBe(true);
    }
  }
  // A base64 credential in a query string is commonly URL-encoded (+ / = as %2B %2F %3D).
  const macaroon = fixtures.find(row => row.kind === 'macaroon')?.bytes;
  if (!macaroon) throw new Error('macaroon fixture is missing');
  const encoded = encodeURIComponent(macaroon.toString('base64'));
  expect(encoded === macaroon.toString('base64'), 'fixture exercises percent-encoded base64 characters').toBe(false);
  for (const value of [encoded, encoded.replace(/%[0-9A-F]{2}/g, escape => escape.toLowerCase())]) {
    const parts = output.redact(`before / ${value} / after`).split(' / ');
    expect.soft(parts.length === 3 && parts[0] === 'before' && marker(parts[1] ?? '') && parts[2] === 'after', 'URL-encoded base64 macaroon is redacted').toBe(true);
  }
});

it('CP-003/B9 named preimage fields redact exactly 64 hex characters and leave longer or shorter hex runs intact', async () => {
  const { createOutput } = await outputModule();
  const output = createOutput({ stdout: discardSink(), stderr: discardSink(), secrets: [] });
  // A preimage is 32 bytes; a 63- or 65-character hex run is some other value and stays whole.
  const run = createHash('sha256').update('disposable field length value').digest('hex');
  for (const field of ['preimage', 'r_preimage', 'payment_preimage']) {
    for (const value of [run.slice(0, 63), `${run}a`, `${run}${run}`]) {
      const text = `${field}=${value}; next`;
      expect(output.redact(text), `${field}: ${String(value.length)} hex characters stay`).toBe(text);
      const json = JSON.stringify({ [field]: value });
      expect(output.redact(json), `${field}: JSON ${String(value.length)} hex characters stay`).toBe(json);
    }
    const parts = output.redact(`${field}=${run}; next`).split('; ');
    expect(parts[1] === 'next' && marker(parts[0]?.slice(field.length + 1) ?? ''), `${field}: exactly 64 hex characters are redacted`).toBe(true);
  }
});

it('CP-003/B3 a payment request after a word character or split across writes is still redacted after its prefix', async () => {
  const { createOutput } = await outputModule();
  // BOLT #11 example invoice (lightning/bolts 11-payment-encoding.md, "donation" example).
  const invoice = 'lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql';
  const output = createOutput({ stdout: discardSink(), stderr: discardSink(), secrets: [] });
  for (const lead of ['invoice_', 'x', 'id9']) expect(output.redact(`${lead}${invoice} end`), `after "${lead}"`).toBe(`${lead}lnbc[redacted] end`);
  for (const split of [10, 30, 200]) {
    const capture = capturedSink();
    const writer = createOutput({ stdout: capture.sink, stderr: discardSink(), secrets: [] });
    await writer.write(`pay ${invoice.slice(0, split)}`, { stream: 'stdout', exitCode: 0 });
    await writer.write(`${invoice.slice(split)} done`, { stream: 'stdout', exitCode: 0 });
    const joined = capture.text();
    const tail = invoice.slice(Math.max(split, 24));
    expect(joined.startsWith('pay lnbc') && joined.endsWith(' done'), `split ${String(split)}: surrounding text is preserved`).toBe(true);
    expect(joined.includes(tail), `split ${String(split)}: the payload continuation is not emitted`).toBe(false);
  }
});

it('CP-003/B6 an allowed module cannot hand the reveal capability on under another name, inside an object or through a wrapper', async () => {
  const eslint = new ESLint({ cwd: repoRoot, overrideConfig: { languageOptions: { parserOptions: { projectService: false, project: null } }, rules: { ...tseslint.configs.disableTypeChecked.rules } } });
  async function capability(source: string, path: string): Promise<number> {
    const rows = await eslint.lintText(source, { filePath: join(repoRoot, path) });
    expect(rows.some(row => row.messages.some(message => message.fatal)), `${path}: source parses`).toBe(false);
    return rows.reduce((total, row) => total + row.messages.filter(message => message.severity === 2 && message.ruleId === 'credentials/restricted-capability').length, 0);
  }
  const handed = [
    ['alias', 'import { revealSecret } from "../core/secret.js"; export const credentialBytes = revealSecret;'],
    ['object property', 'import { revealSecret } from "../core/secret.js"; export const capabilities = { bytes: revealSecret };'],
    ['class property', 'import { revealSecret } from "../core/secret.js"; export class Capabilities { static bytes = revealSecret; }'],
    ['wrapper function', 'import { revealSecret, type Secret } from "../core/secret.js"; export function credentialBytes(secret: Secret): Uint8Array { return revealSecret(secret); }'],
    ['wrapper arrow', 'import { revealSecret, type Secret } from "../core/secret.js"; export const credentialBytes = (secret: Secret): Uint8Array => revealSecret(secret);'],
    ['wrapper returning text of the bytes', 'import { revealSecret, type Secret } from "../core/secret.js"; export function credentialText(secret: Secret): string { return revealSecret(secret).toString(); }'],
    ['local wrapper exported in an object', 'import { revealSecret, type Secret } from "../core/secret.js"; const bytes = (secret: Secret): Uint8Array => revealSecret(secret); export const api = { bytes };'],
    ['local wrapper as default export object', 'import { revealSecret, type Secret } from "../core/secret.js"; function bytes(secret: Secret): Uint8Array { return revealSecret(secret); } export default { bytes };'],
    ['class field holding revealed bytes', 'import { revealSecret, type Secret } from "../core/secret.js"; declare const secret: Secret; export class Holder { readonly bytes = revealSecret(secret); }'],
    ['default export of revealed bytes', 'import { revealSecret, type Secret } from "../core/secret.js"; declare const secret: Secret; export default revealSecret(secret);'],
    ['wrapper reached through two literals', 'import { revealSecret, type Secret } from "../core/secret.js"; function f(secret: Secret): Uint8Array { return revealSecret(secret); } const inner = { f }; export const api = { inner };'],
  ] as const;
  const internal = 'import { revealSecret, type Secret } from "../core/secret.js"; export function credentialLength(secret: Secret): number { return revealSecret(secret).length; }';
  for (const module of ['node-lnd/credential', 'node-cln/credential', 'approval/sign']) {
    for (const [shape, source] of handed) expect.soft(await capability(source, `src/${module}.ts`), `${module} ${shape}: capability hand-off is diagnosed`).toBeGreaterThan(0);
    expect.soft(await capability(internal, `src/${module}.ts`), `${module}: internal use that returns no credential bytes is allowed`).toBe(0);
  }
  // Any other approval module is a forbidden location, even for internal use.
  expect.soft(await capability(internal, 'src/approval/credential.ts'), 'approval/credential: reveal is forbidden outside the signer').toBeGreaterThan(0);
});

// Reverses the printable escapes, so a check sees the characters an output stream conveys.
function unescapeOutput(text: string): string {
  return text.replace(/\\u\{([0-9a-f]+)\}|\\u([0-9a-f]{4})|\\x([0-9a-f]{2})/gi, (_match, astral: string | undefined, unit: string | undefined, byte: string | undefined) =>
    astral !== undefined ? String.fromCodePoint(parseInt(astral, 16)) : String.fromCharCode(parseInt(unit ?? byte ?? '0', 16)));
}

function keyMaterial(kind: string): { pem: string; body: string[]; der: Buffer } {
  const bytes = sentinels().find(row => row.kind === kind)?.bytes;
  if (!bytes) throw new Error(`${kind} fixture is missing`);
  const pem = bytes.toString('utf8');
  return { pem, body: pem.split('\n').filter(line => line.length > 0 && !line.startsWith('-----')), der: createPrivateKey(bytes).export({ format: 'der', type: 'pkcs8' }) };
}

// Only markers, whitespace, escaped line breaks and PEM armor may remain where a key was.
function onlyMarkersRemain(text: string): boolean {
  return text.replace(/\[redacted(?: fp:[0-9a-f]{16})?\]/g, '').replace(/-----(?:BEGIN|END) PRIVATE KEY-----/g, '').replace(/\s|\\r|\\n/g, '') === '';
}

it('CP-003/B2 a registered PEM key is removed when indented, re-wrapped at other columns, as MIME base64 of its DER and with escaped slashes', async () => {
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  const output = createOutput({ stdout: discardSink(), stderr: discardSink(), secrets: sentinels().map(row => new Secret(row.bytes)) });
  for (const kind of ['tls-key', 'ed25519-key']) {
    const { pem, der } = keyMaterial(kind);
    const base64 = der.toString('base64');
    const wrap = (width: number, newline: string): string => (base64.match(new RegExp(`.{1,${String(width)}}`, 'g')) ?? []).join(newline);
    const forms: [string, string][] = [
      // A YAML block scalar indents every line of the value.
      ['yaml-indented', pem.trimEnd().split('\n').map(line => `  ${line}`).join('\n')],
      ['tab-indented', pem.trimEnd().split('\n').map(line => `\t${line}`).join('\n')],
      ...[76, 72, 40, 17].map((width): [string, string] => [`rewrapped-${String(width)}`, `-----BEGIN PRIVATE KEY-----\n${wrap(width, '\n')}\n-----END PRIVATE KEY-----`]),
      // MIME base64 (RFC 2045): 76-character lines separated by CRLF.
      ['mime-der', wrap(76, '\r\n')],
      // Some JSON writers escape "/" as "\/".
      ['json-escaped-slash', JSON.stringify(pem).slice(1, -1).replace(/\//g, '\\/')],
    ];
    expect(pem.includes('/'), `${kind}: fixture exercises the escaped-slash form`).toBe(true);
    for (const [encoding, value] of forms) {
      // The registered raw PEM ends in a line break, so a marker may absorb the one before "after".
      const redacted = output.redact(`before:\n${value}\nafter é`);
      const label = `${kind}/${encoding}`;
      expect.soft(redacted.startsWith('before:') && redacted.endsWith('after é'), `${label}: surrounding text is preserved`).toBe(true);
      expect.soft(onlyMarkersRemain(redacted.slice('before:'.length, -'after é'.length)) && redacted.includes('[redacted'), `${label}: only markers and layout remain`).toBe(true);
    }
  }
});

it('CP-003/B2 a form-encoded credential with spaces as plus signs is redacted', async () => {
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  // application/x-www-form-urlencoded writes a space byte as "+" and other bytes as %XX.
  const bytes = Buffer.from(createHash('sha256').update('disposable form encoded credential').digest().map((byte, index) => index % 5 === 0 ? 0x20 : byte));
  const output = createOutput({ stdout: discardSink(), stderr: discardSink(), secrets: [new Secret(bytes)] });
  const form = [...bytes].map(byte => byte === 0x20 ? '+' : `%${byte.toString(16).padStart(2, '0').toUpperCase()}`).join('');
  const parts = output.redact(`token=${form}&next=1`).split('&');
  expect(parts.length === 2 && parts[1] === 'next=1' && marker(parts[0]?.slice('token='.length) ?? ''), 'form-encoded credential is redacted and the next field kept').toBe(true);
});

it('CP-003/B10 credentials with line breaks or control bytes split across two writes never complete in the joined output', async () => {
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  const fixtures = sentinels();
  const secrets = fixtures.map(row => new Secret(row.bytes));
  // A CRLF PEM key split at 40%: the emitted prefix stays, the remaining key lines must not.
  // The RSA key has many body lines; the Ed25519 key's body is a single line.
  for (const kind of ['tls-key']) {
    const { pem, body } = keyMaterial(kind);
    const crlf = pem.replace(/\n/g, '\r\n');
    const split = Math.floor(crlf.length * 0.4);
    const capture = capturedSink();
    const writer = createOutput({ stdout: capture.sink, stderr: discardSink(), secrets });
    await writer.write(`key:\r\n${crlf.slice(0, split)}`, { stream: 'stdout', exitCode: 0 });
    await writer.write(`${crlf.slice(split)}after`, { stream: 'stdout', exitCode: 0 });
    const conveyed = unescapeOutput(capture.text());
    const later = body.filter(line => crlf.indexOf(line) >= split);
    expect(later.length > 1, `${kind}: lines follow the split`).toBe(true);
    expect.soft(later.some(line => conveyed.includes(line)), `${kind}: no key line after the split is conveyed`).toBe(false);
    expect.soft(capture.text().endsWith('after'), `${kind}: following text is preserved`).toBe(true);
  }
  // A binary credential written as latin1 text carries control bytes that are escaped on output.
  const binary = Buffer.from(Array.from({ length: 32 }, (_unused, index) => (index * 37 + 3) % 256));
  const latin = binary.toString('latin1');
  const half = latin.slice(16);
  expect([...binary.subarray(16)].some(code => { return code < 0x20 || (code >= 0x7f && code <= 0x9f); }), 'the continuation carries control bytes').toBe(true);
  const capture = capturedSink();
  const writer = createOutput({ stdout: capture.sink, stderr: discardSink(), secrets: [new Secret(binary)] });
  await writer.write(`raw ${latin.slice(0, 16)}`, { stream: 'stdout', exitCode: 0 });
  await writer.write(`${half} end`, { stream: 'stdout', exitCode: 0 });
  expect(unescapeOutput(capture.text()).includes(half), 'latin1 continuation is not conveyed as escapes').toBe(false);
  expect(capture.text().endsWith(' end'), 'following text is preserved').toBe(true);
});

it('CP-003/B3 an invoice continuation is withheld whatever the registered secrets and the next ordinary word is kept', async () => {
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  // Only a one-byte credential is registered, so the credential overlap alone is tiny.
  const split = capturedSink();
  const small = createOutput({ stdout: split.sink, stderr: discardSink(), secrets: [new Secret(Uint8Array.of(0x7f))] });
  await small.write(`pay lnbcrt1${'q'.repeat(12)}`, { stream: 'stdout', exitCode: 0 });
  await small.write(`${'p'.repeat(300)}\n`, { stream: 'stdout', exitCode: 0 });
  expect(split.text().includes('ppppp'), 'the invoice continuation is not emitted').toBe(false);
  // A run containing characters outside the bech32 data alphabet ("o", "1", upper case)
  // cannot continue an invoice, and hex text after a 64-hex preimage makes it no preimage:
  // neither may be removed.
  const invoice = `lnbcrt1${'q'.repeat(40)}`;
  for (const next of ['done', 'Done\n', '1500000 msat']) {
    const capture = capturedSink();
    const writer = createOutput({ stdout: capture.sink, stderr: discardSink(), secrets: [] });
    await writer.write(`pay ${invoice}`, { stream: 'stdout', exitCode: 0 });
    await writer.write(next, { stream: 'stdout', exitCode: 0 });
    expect.soft(capture.text(), `invoice then ${JSON.stringify(next)}`).toBe(`pay lnbcrt[redacted]${next}`);
  }
  for (const next of ['deadline passed', 'deadbeef is the next field']) {
    const capture = capturedSink();
    const writer = createOutput({ stdout: capture.sink, stderr: discardSink(), secrets: [] });
    await writer.write(`preimage=${'ab'.repeat(32)}`, { stream: 'stdout', exitCode: 0 });
    await writer.write(next, { stream: 'stdout', exitCode: 0 });
    expect.soft(capture.text(), `preimage then ${JSON.stringify(next)}`).toBe(`preimage=[redacted]${next}`);
  }
});

it('CP-003/B4 astral format characters and supplementary variation selectors render as one unambiguous escape', async () => {
  const { createOutput } = await outputModule();
  // U+E0041 (tag), U+E0001 (language tag), U+E0100 and U+E01EF (variation selectors 17 and 256).
  for (const point of [0xe0041, 0xe0001, 0xe0100, 0xe01ef]) {
    const capture = capturedSink();
    const output = createOutput({ stdout: capture.sink, stderr: discardSink(), secrets: [] });
    await output.write(`a${String.fromCodePoint(point)}b`, { stream: 'stdout', exitCode: 0 });
    const text = capture.text();
    const hex = point.toString(16);
    const high = (0xd800 + ((point - 0x10000) >> 10)).toString(16), low = (0xdc00 + ((point - 0x10000) & 0x3ff)).toString(16);
    expect.soft(new RegExp(`^a(?:\\\\u\\{0*${hex}\\}|\\\\u${high}\\\\u${low})b$`, 'i').test(text), `U+${hex.toUpperCase()} escape`).toBe(true);
    expect.soft(unescapeOutput(text), `U+${hex.toUpperCase()} escape names exactly that character`).toBe(`a${String.fromCodePoint(point)}b`);
  }
});

it('CP-003/B2 binary values in JSON documents are never rendered as their bytes', async () => {
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  const preimage = sentinels().find(row => row.kind === 'preimage')?.bytes;
  if (!preimage) throw new Error('preimage fixture is missing');
  const unregistered = createHash('sha256').update('disposable unregistered binary value').digest();
  function numbers(value: unknown): number[] {
    if (typeof value === 'number') return [value];
    if (value !== null && typeof value === 'object') return Object.values(value).flatMap(numbers);
    return [];
  }
  for (const [name, bytes] of [['registered', preimage], ['unregistered', unregistered]] as const) {
    const values: Record<string, unknown> = {
      buffer: Buffer.from(bytes),
      view: new Uint8Array(bytes),
      data: new DataView(Uint8Array.from(bytes).buffer),
      wrapped: { toJSON: () => Buffer.from(bytes) },
    };
    for (const [kind, value] of Object.entries(values)) {
      const capture = capturedSink();
      const output = createOutput({ stdout: capture.sink, stderr: discardSink(), secrets: [new Secret(preimage)] });
      await output.json({ schema: 1, command: 'status', ok: true, warnings: [], result: { value, count: 7 }, error: null }, { exitCode: 0 });
      const text = capture.text();
      const parsed = JSON.parse(text) as { result: { value: unknown; count: number } };
      expect.soft(parsed.result.count, `${name}/${kind}: ordinary values are kept`).toBe(7);
      expect.soft(numbers(parsed.result.value).length, `${name}/${kind}: no byte values are rendered`).toBe(0);
      expect.soft(secretForms(Buffer.from(bytes)).filter(([encoding]) => !encoding.startsWith('raw')).some(([, encoded]) => text.includes(encoded)), `${name}/${kind}: no encoding of the bytes`).toBe(false);
    }
  }
});

// Deterministic pseudo-random bytes (mulberry32), so every generated credential is reproducible from its seed.
function generator(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = Math.imul(state ^ (state >>> 15), state | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

// Random credential bytes with the byte values and sequences that collide with escape syntax.
function hostileCredential(seed: number, size: number): Buffer {
  const random = generator(seed);
  const bytes = Buffer.from(Array.from({ length: size }, () => Math.floor(random() * 256)));
  const inserts = [[seed % 32], [0x22], [0x5c], [0x7f], [0x80 + Math.floor(random() * 128)], [0x5c, 0x6e], [0x25, 0x34, 0x31], [0x5c, 0x75, 0x30, 0x30, 0x34, 0x31]];
  for (const insert of inserts) if (random() < 0.5) Buffer.from(insert).copy(bytes, Math.floor(random() * (size - insert.length)));
  return bytes;
}

// Decodes JSON string escapes and printable output escapes in one left-to-right pass.
function decodeJsonText(text: string): string {
  const simple: Record<string, string> = { b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
  return text.replace(/\\(?:u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|(["\\/bfnrt]))/g, (_match, astral: string | undefined, unit: string | undefined, byte: string | undefined, other: string | undefined) =>
    astral !== undefined ? String.fromCodePoint(parseInt(astral, 16)) : unit !== undefined || byte !== undefined ? String.fromCharCode(parseInt(unit ?? byte ?? '0', 16)) : simple[other ?? ''] ?? other ?? '');
}

function decodePercentText(text: string): Buffer {
  return Buffer.from(unescapeOutput(text).replace(/\+/g, ' ').replace(/%([0-9a-fA-F]{2})/g, (_match, byte: string) => String.fromCharCode(parseInt(byte, 16))), 'latin1');
}

// True when the secret, or any 16-byte window of it, is present in the decoded output.
function conveys(decoded: Buffer, secret: Buffer): boolean {
  if (decoded.includes(secret)) return true;
  for (let start = 0; start + 16 <= secret.length; start += 8) if (decoded.includes(secret.subarray(start, start + 16))) return true;
  return false;
}

const formSafe = new Set(Array.from('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789*-._', character => character.charCodeAt(0)));

it('CP-003/B2 seeded random credentials never reach output JSON-escaped or percent-encoded, judged by decoding the output', async () => {
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  const failures: string[] = [];
  const credentials = [...Array.from({ length: 48 }, (_unused, seed) => ({ seed, size: 32 })), ...Array.from({ length: 16 }, (_unused, seed) => ({ seed: 1000 + seed, size: 300 }))];
  for (const { seed, size } of credentials) {
    const bytes = hostileCredential(seed, size);
    const latin = bytes.toString('latin1');
    const utf8 = bytes.toString('utf8');
    const forms: [string, string, (text: string) => Buffer, Buffer][] = [
      ['json-latin1', JSON.stringify(latin), text => Buffer.from(decodeJsonText(text), 'latin1'), bytes],
      ['json-utf8', JSON.stringify(utf8), text => Buffer.from(decodeJsonText(text), 'utf8'), Buffer.from(utf8, 'utf8')],
      ['json-base64', JSON.stringify(bytes.toString('base64')), text => Buffer.from(decodeJsonText(text), 'latin1'), Buffer.from(bytes.toString('base64'))],
      ['json-hex', JSON.stringify(bytes.toString('hex')), text => Buffer.from(decodeJsonText(text), 'latin1'), Buffer.from(bytes.toString('hex'))],
      ['percent-lower', [...bytes].map(byte => `%${byte.toString(16).padStart(2, '0')}`).join(''), decodePercentText, bytes],
      ['percent-upper', [...bytes].map(byte => `%${byte.toString(16).padStart(2, '0').toUpperCase()}`).join(''), decodePercentText, bytes],
      ['form-encoded', [...bytes].map(byte => byte === 0x20 ? '+' : formSafe.has(byte) ? String.fromCharCode(byte) : `%${byte.toString(16).padStart(2, '0').toUpperCase()}`).join(''), decodePercentText, bytes],
      ['uri-component-base64', encodeURIComponent(bytes.toString('base64')), decodePercentText, Buffer.from(bytes.toString('base64'))],
    ];
    for (const [encoding, form, decode, needle] of forms) {
      const capture = capturedSink();
      const output = createOutput({ stdout: capture.sink, stderr: discardSink(), secrets: [new Secret(bytes)] });
      await output.write(`value=${form};\n`, { stream: 'stdout', exitCode: 0 });
      if (conveys(decode(capture.text()), needle)) failures.push(`seed ${String(seed)}/${String(size)} bytes/${encoding}`);
    }
  }
  const perEncoding = new Map<string, number>();
  for (const failure of failures) { const encoding = failure.split('/').at(-1) ?? ''; perEncoding.set(encoding, (perEncoding.get(encoding) ?? 0) + 1); }
  expect(failures.slice(0, 12), `${String(failures.length)} credential forms conveyed: ${[...perEncoding].map(([encoding, count]) => `${encoding} ${String(count)}`).join(', ')}`).toEqual([]);
});

it('CP-003/B2 hex after a near-miss prefix, JSON escapes of a binary macaroon and escapes ending the text are redacted', async () => {
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  const fixtures = sentinels();
  const secrets = fixtures.map(row => new Secret(row.bytes));
  const output = createOutput({ stdout: discardSink(), stderr: discardSink(), secrets });
  const macaroon = fixtures.find(row => row.kind === 'macaroon')?.bytes;
  const preimage = fixtures.find(row => row.kind === 'preimage')?.bytes;
  if (!macaroon || !preimage) throw new Error('fixtures are missing');
  // A hex dump whose length byte equals the credential's first byte starts a partial match first.
  const hex = macaroon.toString('hex');
  const dump = output.redact(`dump ${hex.slice(0, 2)}${hex} end`);
  expect(dump.startsWith('dump ') && dump.endsWith(' end') && dump.includes('[redacted'), 'hex dump keeps its frame').toBe(true);
  expect(conveys(Buffer.from(dump), Buffer.from(hex)), 'macaroon hex after a near-miss prefix is not conveyed').toBe(false);
  // A credential whose hex starts "aab" written after one more "a".
  const overlapping = Buffer.from(Array.from({ length: 32 }, (_unused, index) => (index * 53 + 7) & 0xff));
  overlapping[0] = 0xaa; overlapping[1] = 0xb1;
  const selfOverlap = createOutput({ stdout: discardSink(), stderr: discardSink(), secrets: [new Secret(overlapping)] }).redact(`fp=a${overlapping.toString('hex')}`);
  expect(selfOverlap.startsWith('fp=a') && marker(selfOverlap.slice(4)), 'match starting inside an abandoned partial match').toBe(true);
  // JSON renders the binary macaroon's control bytes as \u00XX escapes.
  const json = capturedSink();
  await createOutput({ stdout: json.sink, stderr: discardSink(), secrets }).json({ token: macaroon.toString('latin1') }, { exitCode: 0 });
  expect(conveys(Buffer.from(decodeJsonText(json.text()), 'latin1'), macaroon), 'JSON-escaped binary macaroon is not conveyed').toBe(false);
  // Every byte as a \u00XX escape, with the escape ending the text.
  const escaped = [...preimage].map(byte => `\\u00${byte.toString(16).padStart(2, '0')}`).join('');
  expect(marker(output.redact(escaped)), 'escaped credential ending the text is redacted').toBe(true);
  // Colon-separated hex, the fingerprint layout, in both cases.
  for (const text of [preimage.toString('hex'), preimage.toString('hex').toUpperCase()]) {
    const colon = (text.match(/../g) ?? []).join(':');
    const redacted = output.redact(`fp=${colon} next`);
    expect(redacted.startsWith('fp=') && redacted.endsWith(' next') && marker(redacted.slice(3, -5)), 'colon-separated hex is redacted').toBe(true);
  }
  // Whitespace anywhere inside a credential: spaced hex and base64 with inserted line breaks.
  for (const value of [(preimage.toString('hex').match(/../g) ?? []).join(' '), (preimage.toString('hex').match(/.{1,8}/g) ?? []).join(' '), (preimage.toString('base64').match(/.{1,10}/g) ?? []).join('\n')]) {
    const redacted = output.redact(`before / ${value} / after`);
    expect.soft(redacted.startsWith('before / ') && redacted.endsWith(' / after') && onlyMarkersRemain(redacted.slice(9, -8)) && redacted.includes('[redacted'), 'credential with interleaved whitespace is redacted').toBe(true);
  }
});

it('CP-003/B10 long escape-dense credential forms split across writes never convey the continuation', async () => {
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  const fixtures = sentinels();
  const pem = fixtures.find(row => row.kind === 'tls-key')?.bytes;
  const preimage = fixtures.find(row => row.kind === 'preimage')?.bytes;
  if (!pem || !preimage) throw new Error('fixtures are missing');
  async function secondWrite(secret: Buffer, form: string, split: number): Promise<string> {
    const capture = capturedSink();
    const writer = createOutput({ stdout: capture.sink, stderr: discardSink(), secrets: [new Secret(secret)] });
    await writer.write(`x ${form.slice(0, split)}`, { stream: 'stdout', exitCode: 0 });
    const first = capture.text().length;
    await writer.write(`${form.slice(split)} y\n`, { stream: 'stdout', exitCode: 0 });
    return capture.text().slice(first);
  }
  // Percent-encoded hex text of the TLS key: more than 8192 characters, split at 90%.
  const hexText = pem.toString('hex');
  const percent = Buffer.from(hexText).toString('hex').replace(/../g, pair => `%${pair}`);
  expect(percent.length > 8192, 'form exceeds 8192 characters').toBe(true);
  const tail = decodePercentText(await secondWrite(pem, percent, Math.floor(percent.length * 0.9))).toString('latin1');
  let leaked = false;
  for (let start = 0; start + 32 <= hexText.length; start += 16) leaked ||= tail.includes(hexText.slice(start, start + 32));
  expect(leaked, 'percent-encoded hex continuation is not conveyed').toBe(false);
  // Every key byte as a six-character \u00XX escape, split early and late.
  const escape = (bytes: Buffer): string => [...bytes].map(byte => `\\u00${byte.toString(16).padStart(2, '0')}`).join('');
  const escapedKey = escape(pem);
  const body = pem.toString('utf8').split('\n').filter(line => line.length > 0 && !line.startsWith('-----'));
  for (const split of [30, 1200, escapedKey.length - 1200, escapedKey.length - 400]) {
    const second = decodeJsonText(await secondWrite(pem, escapedKey, split));
    let found = false;
    for (const line of body) for (let start = 0; start + 16 <= line.length; start += 8) found ||= second.includes(line.slice(start, start + 16));
    expect.soft(found, `escaped key split at ${String(split)}: no key text after the split`).toBe(false);
  }
  // Every split of an escaped preimage: the second write never carries two escaped bytes of it.
  const escapedPreimage = escape(preimage);
  const leaks: number[] = [];
  for (let split = 1; split < escapedPreimage.length; split++) {
    const second = await secondWrite(preimage, escapedPreimage, split);
    for (let start = 0; start + 12 <= second.length; start++) if (escapedPreimage.includes(second.slice(start, start + 12))) { leaks.push(split); break; }
  }
  expect(leaks.slice(0, 8), 'splits that convey part of the escaped preimage').toEqual([]);
});

it('CP-003/B2 text after a credential marker is kept across writes and layouts are treated alike', async () => {
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  const preimage = sentinels().find(row => row.kind === 'preimage')?.bytes;
  const pem = sentinels().find(row => row.kind === 'tls-key')?.bytes;
  if (!preimage || !pem) throw new Error('fixtures are missing');
  const fingerprint = `[redacted fp:${createHash('sha256').update(preimage).digest('hex').slice(0, 16)}]`;
  const capture = capturedSink();
  const writer = createOutput({ stdout: capture.sink, stderr: discardSink(), secrets: [new Secret(preimage)] });
  await writer.write(`x ${preimage.toString('hex')}`, { stream: 'stdout', exitCode: 0 });
  await writer.write('next', { stream: 'stdout', exitCode: 0 });
  expect(capture.text(), 'the following write is unchanged').toBe(`x ${fingerprint}next`);
  // A form-encoded credential completed in one write adds nothing to a later write bringing "%".
  const formCapture = capturedSink();
  const formWriter = createOutput({ stdout: formCapture.sink, stderr: discardSink(), secrets: [new Secret(Buffer.from('correct horse battery staple'))] });
  await formWriter.write('pw=correct+horse+battery+staple', { stream: 'stdout', exitCode: 0 });
  const first = formCapture.text().length;
  await formWriter.write('%41 done\n', { stream: 'stdout', exitCode: 0 });
  expect(formCapture.text().slice(first), 'the later write is unchanged').toBe('%41 done\n');
  // A key stored with CRLF and printed with LF is redacted exactly like the same key stored with LF.
  const lf = pem.toString('utf8');
  const fromCrlf = new Secret(Buffer.from(lf.replace(/\n/g, '\r\n'))).toString();
  const fromLf = new Secret(Buffer.from(lf)).toString();
  const crlfOutput = createOutput({ stdout: discardSink(), stderr: discardSink(), secrets: [new Secret(Buffer.from(lf.replace(/\n/g, '\r\n')))] }).redact(`${lf}next`);
  const lfOutput = createOutput({ stdout: discardSink(), stderr: discardSink(), secrets: [new Secret(Buffer.from(lf))] }).redact(`${lf}next`);
  expect(crlfOutput.split(fromCrlf).join('M') === lfOutput.split(fromLf).join('M'), 'CRLF-stored and LF-stored keys give the same layout').toBe(true);
});

it('CP-003/B2 a Buffer already in its JSON shape is not rendered as bytes', async () => {
  const { createOutput } = await outputModule();
  const preimage = sentinels().find(row => row.kind === 'preimage')?.bytes;
  if (!preimage) throw new Error('preimage fixture is missing');
  function numbers(value: unknown): number[] {
    if (typeof value === 'number') return [value];
    if (value !== null && typeof value === 'object') return Object.values(value).flatMap(numbers);
    return [];
  }
  for (const [kind, value] of [['Buffer.toJSON()', Buffer.from(preimage).toJSON()], ['toJSON returning the Buffer shape', { toJSON: () => Buffer.from(preimage).toJSON() }]] as const) {
    const capture = capturedSink();
    await createOutput({ stdout: capture.sink, stderr: discardSink(), secrets: [] }).json({ value, count: 7 }, { exitCode: 0 });
    const parsed = JSON.parse(capture.text()) as { value: unknown; count: number };
    expect.soft(parsed.count, `${kind}: ordinary values are kept`).toBe(7);
    expect.soft(numbers(parsed.value).length, `${kind}: no byte values are rendered`).toBe(0);
  }
});

it('CP-003/B6 reveal confinement covers every source extension under src', async () => {
  const eslint = new ESLint({ cwd: repoRoot, overrideConfig: { languageOptions: { parserOptions: { projectService: false, project: null } }, rules: { ...tseslint.configs.disableTypeChecked.rules } } });
  for (const file of ['src/cli/capability.mts', 'src/cli/capability.cts', 'src/cli/capability.js', 'src/cli/capability.mjs']) {
    const [report] = await eslint.lintText('import { revealSecret } from "../core/secret.js"; export const bytes = revealSecret;', { filePath: join(repoRoot, file) });
    expect.soft(report?.fatalErrorCount, `${file}: parses`).toBe(0);
    expect.soft(report?.messages.some(message => message.ruleId === 'credentials/restricted-capability'), `${file}: reveal is diagnosed`).toBe(true);
  }
});

it('CP-003/B6 an allowed reveal module exports nothing that returns revealed bytes, whatever the export shape, while an allow-listed fingerprint export passes', async () => {
  // Type-aware lint of a probe in an adapter directory; the probe resolves the real Secret types.
  const probe = 'src/node-lnd/export-probe.ts';
  const eslint = new ESLint({ cwd: repoRoot, overrideConfig: { languageOptions: { parserOptions: { projectService: { allowDefaultProject: [probe], defaultProject: 'tsconfig.json' } } } } });
  async function capability(source: string): Promise<number> {
    const [report] = await eslint.lintText(source, { filePath: join(repoRoot, probe) });
    expect(report?.fatalErrorCount, 'probe parses').toBe(0);
    return report?.messages.filter(message => message.ruleId === 'credentials/restricted-capability').length ?? 0;
  }
  const header = 'import { revealSecret, type Secret } from "../core/secret.js"; function f(secret: Secret): Uint8Array { return revealSecret(secret); }';
  const escapes = [
    ['const alias', 'export const g = f;'],
    ['literal as const', 'export const api = { f } as const;'],
    ['static class field', 'export class Api { static f = f; }'],
    ['nested object literal', 'export const api = { v1: { f } };'],
    ['frozen literal', 'export const api = Object.freeze({ f });'],
    ['re-export alias', 'export { f as g };'],
  ] as const;
  for (const [shape, tail] of escapes) expect.soft(await capability(`${header} ${tail}`), `${shape}: export of a byte-returning function is diagnosed`).toBeGreaterThan(0);
  const capabilityExports = [
    ['named', 'import { revealSecret } from "../core/secret.js"; export { revealSecret };'],
    ['renamed re-export', 'export { revealSecret as bytes } from "../core/secret.js";'],
    ['object property', 'import { revealSecret } from "../core/secret.js"; export const api = { revealSecret };'],
    ['default', 'import { revealSecret } from "../core/secret.js"; export default revealSecret;'],
  ] as const;
  for (const [shape, source] of capabilityExports) expect.soft(await capability(source), `${shape}: export of the capability is diagnosed`).toBeGreaterThan(0);
  const fingerprint = 'import { createHash } from "node:crypto"; import { revealSecret, type Secret } from "../core/secret.js"; export function fingerprint(secret: Secret): string { return createHash("sha256").update(revealSecret(secret)).digest("hex").slice(0, 16); }';
  // An export that carries text needs an allow-list entry with its reason; without one it is flagged.
  expect.soft(await capability(fingerprint), 'a text export without an allow-list entry is diagnosed').toBeGreaterThan(0);
  const listed = new ESLint({ cwd: repoRoot, overrideConfig: {
    languageOptions: { parserOptions: { projectService: { allowDefaultProject: [probe], defaultProject: 'tsconfig.json' } } },
    rules: { 'credentials/restricted-capability': ['error', { allow: [{ file: probe, export: 'fingerprint', reason: 'first 16 hex digits of a SHA-256, not credential bytes' }] }] },
  } });
  const [report] = await listed.lintText(fingerprint, { filePath: join(repoRoot, probe) });
  expect.soft(report?.fatalErrorCount, 'probe parses').toBe(0);
  expect.soft(report?.messages.filter(message => message.ruleId === 'credentials/restricted-capability').length, 'an allow-listed fingerprint export passes').toBe(0);
});

// Seeded credential population for the leak property: binary, printable ASCII (sometimes with an
// invoice-like run), escape look-alike ASCII, base64-alphabet text, and credentials whose base64
// rendering contains a payment-request look-alike ("lnbc", "lnsb", ... followed by 20+ letters).
const base64Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const lookalikeAlphabet = '\\%+"nrtbfu0123456789abcdefABCDEF/: ';
const invoicePrefixes = ['lnbc', 'lntb', 'lnsb', 'lnbcrt', 'LnBc', 'LNSB'];
function populationMember(seed: number): { bytes: Buffer; kind: string; cut?: number } {
  const random = generator(seed);
  const pick = (alphabet: string): number => alphabet.charCodeAt(Math.floor(random() * alphabet.length));
  const kind = seed % 5;
  if (kind === 4) {
    const prefix = invoicePrefixes[Math.floor(random() * invoicePrefixes.length)] ?? 'lnbc';
    const run = prefix + Array.from({ length: 24 }, () => String.fromCharCode(pick(base64Alphabet.slice(0, 62)))).join('');
    const before = Array.from({ length: 4 * Math.floor(random() * 20) }, () => String.fromCharCode(pick(base64Alphabet))).join('');
    let text = before + run;
    text += Array.from({ length: 48 + ((4 - (text.length % 4)) % 4) + 4 * Math.floor(random() * 30) }, () => String.fromCharCode(pick(base64Alphabet))).join('');
    // Bytes whose canonical base64 is exactly this text, with the look-alike ending at the cut.
    return { bytes: Buffer.from(text, 'base64'), kind: 'base64-invoice-lookalike', cut: before.length + run.length };
  }
  const size = 1 + Math.floor(random() * 400);
  const bytes = Buffer.from(Array.from({ length: size }, () => kind === 0 ? Math.floor(random() * 256) : kind === 1 ? 0x20 + Math.floor(random() * 95) : kind === 2 ? pick(lookalikeAlphabet) : pick(base64Alphabet)));
  if (kind === 1 && size > 40 && random() < 0.5) Buffer.from(`${invoicePrefixes[Math.floor(random() * invoicePrefixes.length)] ?? 'lnbc'}${'q'.repeat(24)}`).copy(bytes, Math.floor(random() * (size - 30)));
  return { bytes, kind: ['binary', 'printable', 'escape-lookalike', 'base64-alphabet'][kind] ?? 'binary' };
}

function stripMarkers(text: string): string {
  return text.replace(/\[redacted(?: fp:[0-9a-f]{16})?\]/g, '');
}

// Every view of a credential, with the decoder that recovers characters from output and the needle to look for.
function leakViews(bytes: Buffer): [string, string, (text: string) => Buffer, Buffer][] {
  const latin = bytes.toString('latin1');
  const textual = (text: string): Buffer => Buffer.from(unescapeOutput(text), 'latin1');
  return [
    ['raw', latin, textual, bytes],
    ['hex', bytes.toString('hex'), text => Buffer.from(unescapeOutput(text).toLowerCase(), 'latin1'), Buffer.from(bytes.toString('hex'))],
    ['HEX', bytes.toString('hex').toUpperCase(), text => Buffer.from(unescapeOutput(text).toLowerCase(), 'latin1'), Buffer.from(bytes.toString('hex'))],
    ['base64', bytes.toString('base64'), textual, Buffer.from(bytes.toString('base64'))],
    ['base64url', bytes.toString('base64url'), textual, Buffer.from(bytes.toString('base64url'))],
    ['json', JSON.stringify(latin).slice(1, -1), text => Buffer.from(decodeJsonText(text), 'latin1'), bytes],
    ['percent', [...bytes].map(byte => `%${byte.toString(16).padStart(2, '0').toUpperCase()}`).join(''), decodePercentText, bytes],
    ['form', [...bytes].map(byte => byte === 0x20 ? '+' : formSafe.has(byte) ? String.fromCharCode(byte) : `%${byte.toString(16).padStart(2, '0').toUpperCase()}`).join(''), decodePercentText, bytes],
  ];
}

async function leakProperty(first: number, count: number): Promise<string[]> {
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  const failures: string[] = [];
  for (let seed = first; seed < first + count; seed++) {
    const { bytes, kind, cut } = populationMember(seed);
    const secret = new Secret(bytes);
    const random = generator(seed ^ 0x5bd1e995);
    for (const [view, form, decode, needle] of leakViews(bytes)) {
      const label = `seed ${String(seed)} ${kind} ${String(bytes.length)} bytes/${view}`;
      // One write: after markers are removed, the decoded output holds no part of the credential.
      const single = capturedSink();
      await createOutput({ stdout: single.sink, stderr: discardSink(), secrets: [secret] }).write(form, { stream: 'stdout', exitCode: 0 });
      if (conveys(decode(stripMarkers(single.text())), needle)) failures.push(`${label}/one write`);
      if (form.length < 2) continue;
      // Two or three writes: bytes already written stay, the final write conveys nothing of the credential.
      const cuts = new Set<number>();
      if (cut !== undefined && (view === 'base64' || view === 'base64url')) cuts.add(cut);
      const pieces = Math.min(form.length - 1, 1 + Math.floor(random() * 2));
      while (cuts.size < pieces) cuts.add(1 + Math.floor(random() * (form.length - 1)));
      const offsets = [0, ...[...cuts].sort((a, b) => a - b), form.length];
      const split = capturedSink();
      const writer = createOutput({ stdout: split.sink, stderr: discardSink(), secrets: [secret] });
      let before = 0;
      for (let index = 0; index + 1 < offsets.length; index++) {
        before = split.text().length;
        await writer.write(form.slice(offsets[index], offsets[index + 1]), { stream: 'stdout', exitCode: 0 });
      }
      const final = stripMarkers(split.text().slice(before));
      if (needle.length >= 16 ? conveys(decode(final), needle) : decode(stripMarkers(split.text())).includes(needle)) failures.push(`${label}/split at ${offsets.slice(1, -1).join(',')}`);
    }
  }
  return failures;
}

for (const [first, count] of [[0, 100], [100, 100], [200, 100], [300, 100], [400, 100]] as const) {
  it(`CP-003/B10 seeded credentials ${String(first)}-${String(first + count - 1)} never reach output in any view, in one write or split across writes, judged by decoding`, async () => {
    const failures = await leakProperty(first, count);
    const classes = new Map<string, number>();
    for (const failure of failures) {
      const [head = '', view = '', mode = ''] = failure.split('/');
      const key = `${head.split(' ')[2] ?? ''}/${view}/${mode.startsWith('split') ? 'split' : 'one write'}`;
      classes.set(key, (classes.get(key) ?? 0) + 1);
    }
    expect(failures.slice(0, 10), `${String(failures.length)} leaking cases: ${[...classes].map(([key, count]) => `${key} ${String(count)}`).join(', ')}`).toEqual([]);
  });
}

it('CP-003/B2 form encoding without other escapes, a YAML block key, a form feed and following lines keep the expected layout', async () => {
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  const redactWith = (bytes: Buffer, text: string): string => createOutput({ stdout: discardSink(), stderr: discardSink(), secrets: [new Secret(bytes)] }).redact(text);
  const fingerprintOf = (bytes: Buffer): string => `[redacted fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}]`;
  // Spaces sent as "+" with no "%" anywhere in the text.
  const phrase = Buffer.from('correct horse battery staple');
  expect(redactWith(phrase, 'pw=correct+horse+battery+staple&x=1'), 'form encoding with "+" only').toBe(`pw=${fingerprintOf(phrase)}&x=1`);
  // A YAML block scalar holding a key: the next key stays on its own line after the marker.
  const pem = sentinels().find(row => row.kind === 'tls-key')?.bytes;
  if (!pem) throw new Error('tls-key fixture is missing');
  const text = pem.toString('utf8');
  const block = text.split('\n').filter(line => line.length > 0).map(line => `  ${line}`).join('\n');
  const yaml = redactWith(pem, `a: |\n${block}\nb: 2`);
  expect(yaml.startsWith('a: |\n') && yaml.endsWith(`${fingerprintOf(pem)}\nb: 2`), 'YAML block keeps the next key on its own line').toBe(true);
  // A credential ending in a form feed, JSON-escaped as "\f": nothing of it is left beside the marker.
  const feed = Buffer.from(`abcdefghijklmnopqrstuvwxyz0123456789${String.fromCharCode(12)}`);
  expect(redactWith(feed, `{"k":${JSON.stringify(feed.toString('latin1'))}}`), 'JSON "\\f" escape is part of the credential').toBe(`{"k":"${fingerprintOf(feed)}"}`);
  // Keys stored with CRLF or LF and printed with LF give the same layout before non-word lines.
  const crlf = Buffer.from(text.replace(/\n/g, '\r\n'));
  const lf = Buffer.from(text);
  for (const after of ['- item', '}', '\n']) {
    expect.soft(redactWith(crlf, `${text}${after}`).split(fingerprintOf(crlf)).join('M'), `layout before ${JSON.stringify(after)}`).toBe(redactWith(lf, `${text}${after}`).split(fingerprintOf(lf)).join('M'));
  }
});

it('CP-003/B4 private-use, unassigned and noncharacter code points become printable escapes', async () => {
  const { createOutput } = await outputModule();
  for (const point of [0xe000, 0xf8ff, 0xf0000, 0x0378, 0xfdd0, 0xfffe]) {
    const capture = capturedSink();
    await createOutput({ stdout: capture.sink, stderr: discardSink(), secrets: [] }).write(`a${String.fromCodePoint(point)}b`, { stream: 'stdout', exitCode: 0 });
    const text = capture.text();
    expect.soft(!text.includes(String.fromCodePoint(point)) && unescapeOutput(text) === `a${String.fromCodePoint(point)}b`, `U+${point.toString(16).toUpperCase()} is escaped exactly`).toBe(true);
  }
});

it('CP-003/B6 every export of a reveal module that can carry text or bytes needs an allow-list entry, and none can permit a reveal-shaped export', async () => {
  clearCaches();
  onTestFinished(clearCaches);
  const probe = 'src/approval/sign.ts';
  async function flagged(source: string, allow: string[] = []): Promise<boolean> {
    const eslint = new ESLint({ cwd: repoRoot, overrideConfig: {
      languageOptions: { parserOptions: { projectService: { defaultProject: 'tsconfig.json' } } },
      rules: { 'credentials/restricted-capability': ['error', { allow: allow.map(name => ({ file: probe, export: name, reason: 'probe' })) }] },
    } });
    const [report] = await eslint.lintText(source, { filePath: join(repoRoot, probe) });
    expect(report?.fatalErrorCount, 'probe parses').toBe(0);
    return report?.messages.some(message => message.ruleId === 'credentials/restricted-capability') ?? false;
  }
  const carriers = [
    ['function returning a Buffer', 'export function load(): Buffer { return Buffer.alloc(1); }'],
    ['deeply nested text', 'export const settings = { a: { b: { c: { d: "text" } } } };'],
    ['generic container of text', 'export const cache = new Map<string, string>();'],
    ['class constructed with text', 'export class Holder { constructor(readonly label: string) {} }'],
    ['optional text', 'export function find(key: number): string | undefined { return key > 0 ? "x" : undefined; }'],
    ['unknown result', 'export function parse(value: number): unknown { return value; }'],
  ] as const;
  for (const [shape, source] of carriers) {
    expect.soft(await flagged(source), `${shape}: flagged without an entry`).toBe(true);
  }
  expect.soft(await flagged('export function load(): Buffer { return Buffer.alloc(1); }', ['load']), 'an entry permits a data export').toBe(false);
  expect.soft(await flagged('export const retries = 3;'), 'a numeric export needs no entry').toBe(false);
  const revealing = 'import { revealSecret, type Secret } from "../core/secret.js"; export function g(secret: Secret): Uint8Array { const bytes = revealSecret(secret); return bytes; }';
  expect.soft(await flagged(revealing, ['g']), 'an entry cannot permit a function shaped like the capability').toBe(true);
  expect.soft(await flagged('import { revealSecret } from "../core/secret.js"; export { revealSecret };', ['revealSecret']), 'an entry cannot permit exporting the capability').toBe(true);
});
