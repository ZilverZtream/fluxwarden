import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { appendFileSync, closeSync, createReadStream, createWriteStream, mkdirSync, mkdtempSync, openSync, rmSync, writeFileSync, writeSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createGzip } from 'node:zlib';
import { expect, it } from 'vitest';
import { childEnv, repoRoot } from '../helpers/cli.js';
import { testRoot } from '../helpers/env.js';

// SECURITY INV-11 and accepted D50: all retained files and all registered forms,
// including interleaved whitespace, remain covered. The 100 MiB ordinary-output
// requirement is exercised as real bytes, without sampling or file-size exclusions.
// 128 MiB is the smaller proposed fixed V8 budget: Node plus five short synthetic
// registrations needs far less than it. The corpus must not consume heap in proportion
// to its size. This is a black-box resource requirement, independent of read sizes.
const MiB = 1024 * 1024;
const LARGE = 100 * MiB;
const HEAP = 128;
// Docker-free artifact references use vitest.lab.config.ts's existing 180 s budget.
const WATCHDOG = 175_000; // Independent child watchdog within that reference budget.
type Task = { label: string; paths: string[] };
type Source = { kind: string; bytes: Buffer; body?: Buffer };
type Hit = { path: string; encoding: string } | null;
type Observation = { results: { label: string; hit?: Hit; failed?: boolean }[]; elapsedMs: number; memory: { heapUsed: number; rss: number } };

function forms(bytes: Buffer): [string, Buffer][] {
  const hex = bytes.toString('hex'), b64 = bytes.toString('base64');
  const utf16 = Buffer.from(bytes.toString('latin1'), 'utf16le');
  return [
    ['raw', bytes], ['hex-lower', Buffer.from(hex)], ['hex-upper', Buffer.from(hex.toUpperCase())],
    ['base64-padded', Buffer.from(b64)], ['base64-unpadded', Buffer.from(b64.replace(/=+$/, ''))],
    ['base64url-padded', Buffer.from(b64.replace(/\+/g, '-').replace(/\//g, '_'))],
    ['base64url-unpadded', Buffer.from(bytes.toString('base64url'))],
    ['utf16le', utf16], ['utf16be', Buffer.from(utf16).swap16()],
    ['wrapped-base64', Buffer.from(b64.match(/.{1,11}/g)?.join('\r\n  \t') ?? '')],
    ['interleaved-hex', Buffer.from(hex.match(/.{1,3}/g)?.join(' \r\n\t') ?? '')],
    ['percent', Buffer.from([...bytes].map(byte => `%${byte.toString(16).padStart(2, '0')}`).join(''))],
    ['json-escaped', Buffer.from([...bytes].map(byte => `\\u00${byte.toString(16).padStart(2, '0')}`).join(''))],
  ];
}

function fixture() {
  const deadline = performance.now() + WATCHDOG;
  const parent = testRoot('FLUXWARDEN_TEST_TMP');
  const root = mkdtempSync(join(parent, 'bounded-scanner-'));
  const sentinelDir = mkdtempSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), 'bounded-scanner-'));
  const scratch = join(root, 'scratch'), evidence = join(root, 'retained');
  mkdirSync(scratch); mkdirSync(evidence);
  const sentinels = join(root, 'registry.json');
  writeFileSync(sentinels, '[]');
  const tls = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
  const approval = generateKeyPairSync('ed25519').privateKey;
  const sources: Source[] = [
    { kind: 'preimage', bytes: randomBytes(32) },
    { kind: 'macaroon', bytes: randomBytes(48) },
    { kind: 'rune', bytes: Buffer.from(randomBytes(32).toString('base64url')) },
    { kind: 'tls-key', bytes: Buffer.from(tls.export({ type: 'pkcs8', format: 'pem' })), body: tls.export({ type: 'pkcs8', format: 'der' }) },
    { kind: 'approval-key', bytes: Buffer.from(approval.export({ type: 'pkcs8', format: 'pem' })), body: approval.export({ type: 'pkcs8', format: 'der' }) },
  ];
  for (const source of sources) writeFileSync(join(sentinelDir, `${source.kind}.bin`), source.bytes, { mode: 0o600 });
  const options = { root, sentinels, sentinelDir, testTmp: scratch, evidenceDir: evidence };
  function source(kind: string): Source {
    const found = sources.find(candidate => candidate.kind === kind);
    if (!found) throw new Error('synthetic kind is absent');
    return found;
  }
  function cleanup() {
    const directories: [string, string][] = [[parent, root], [testRoot('FLUXWARDEN_SENTINEL_DIR'), sentinelDir]];
    for (const [base, owned] of directories) {
      const local = relative(resolve(base), resolve(owned));
      if (!local || local.startsWith('..') || isAbsolute(local)) throw new Error('fixture cleanup escaped its private owner');
      rmSync(owned, { recursive: true, force: true });
    }
  }
  return { root, scratch, evidence, sentinelDir, sources, source, options, deadline, cleanup };
}

function ordinaryFile(file: string, size: number) {
  const block = Buffer.alloc(MiB, 'ordinary ledger status ok; retained output 0123456789\n');
  const fd = openSync(file, 'w', 0o600);
  try {
    for (let position = 0; position < size; position += block.length) writeSync(fd, block, 0, Math.min(block.length, size - position));
  } finally { closeSync(fd); }
}

function plant(file: string, value: Buffer, boundary: number) {
  // Exact deliberate outputs are declared to the outer validation scan; this
  // child uses its own scratch root and must still detect every planted file.
  appendFileSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'declared-out.txt'), `${file}\n`);
  const fd = openSync(file, 'r+');
  // Two independent writes straddle a public fixture position. Neither this position
  // nor the write lengths depend on any scanner implementation or chunk size.
  const split = Math.max(1, Math.floor(value.length / 3));
  try {
    writeSync(fd, value, 0, split, boundary - split);
    writeSync(fd, value, split, value.length - split, boundary);
  } finally { closeSync(fd); }
}

function bounded(f: ReturnType<typeof fixture>, tasks: Task[], cli = false) {
  const config = join(f.root, 'scan-input.json');
  writeFileSync(config, JSON.stringify({ module: join(repoRoot, 'scripts/leak-check.mjs'), options: f.options, tasks }));
  const args = cli
    ? ['--max-old-space-size=128', join(repoRoot, 'scripts/leak-check.mjs'), '--sentinels', f.options.sentinels, '--sentinel-dir', f.sentinelDir, ...tasks.flatMap(task => task.paths)]
    : [`--max-old-space-size=${String(HEAP)}`, join(repoRoot, 'test/helpers/bounded-leak-child.mjs'), config];
  const start = performance.now();
  const timeout = Math.max(1, Math.floor(f.deadline - performance.now()));
  const result = spawnSync(process.execPath, args, { cwd: f.root, env: childEnv(), windowsHide: true, encoding: 'utf8', timeout, maxBuffer: MiB });
  // Emit only performance/process facts; raw scanner diagnostics are never logged.
  const lines = result.stdout.trim().split(/\r?\n/);
  const startup = !cli && lines[0]?.startsWith('{') ? JSON.parse(lines[0]) as { event?: string; heapUsed?: number } : undefined;
  console.info(JSON.stringify({ heapMiB: HEAP, startupHeapUsed: startup?.heapUsed, cli, tasks: tasks.length, status: result.status, signal: result.signal, errorCode: (result.error as NodeJS.ErrnoException | undefined)?.code, elapsedMs: Math.round(performance.now() - start), heapOutOfMemory: /heap out of memory/i.test(result.stderr), stdoutBytes: result.stdout.length, stderrBytes: result.stderr.length }));
  const diagnostic = `${result.stdout}\n${result.stderr}`;
  const confidential = f.sources.flatMap(source => [...forms(source.bytes), ...(source.body ? forms(source.body) : [])]);
  expect(confidential.every(([, value]) => !Buffer.from(diagnostic).includes(value)), 'process diagnostics contain no registered value').toBe(true);
  expect(result.error === undefined, 'bounded subprocess completed without a watchdog or output-buffer error').toBe(true);
  expect(result.signal, 'bounded subprocess did not crash').toBeNull();
  expect(result.status, 'bounded scan completed successfully').toBe(0);
  expect(result.stderr.length, 'bounded scan has no error diagnostics').toBe(0);
  if (cli) return;
  expect(startup?.event, 'public module loaded within the fixed heap budget').toBe('ready');
  expect(lines.length, 'startup and complete scan observations are present').toBe(2);
  const observation = JSON.parse(lines[1] ?? 'null') as Observation;
  console.info(JSON.stringify({ scanMs: Math.round(observation.elapsedMs), heapUsed: observation.memory.heapUsed, rss: observation.memory.rss, observations: observation.results.length }));
  expect(observation.results.length, 'every requested scan returned a result').toBe(tasks.length);
  return observation;
}

it('CP-002/B8 a clean 100 MiB ordinary retained file returns null under a 128 MiB heap', () => {
  const f = fixture();
  try {
    const file = join(f.evidence, 'ordinary.log'); ordinaryFile(file, LARGE);
    const observation = bounded(f, [{ label: 'large-clean', paths: [file] }]);
    expect(observation?.results[0]?.failed, 'ordinary file scanning must not refuse').not.toBe(true);
    expect(observation?.results[0]?.hit).toBeNull();
  } finally { f.cleanup(); }
});

it('CP-002/B8 CLI scans a clean 100 MiB ordinary retained file with exit zero under a 128 MiB heap', () => {
  const f = fixture();
  try {
    const file = join(f.evidence, 'ordinary.log'); ordinaryFile(file, LARGE);
    bounded(f, [{ label: 'large-clean-cli', paths: [file] }], true);
  } finally { f.cleanup(); }
});

it('CP-002/B8 many retained files and SQLite are clean and the last large file is never omitted under a 128 MiB heap', () => {
  const f = fixture();
  try {
    for (let index = 0; index < 128; index++) ordinaryFile(join(index % 2 ? f.scratch : f.evidence, `${String(index).padStart(3, '0')}.log`), MiB / 2);
    const db = new DatabaseSync(join(f.scratch, 'state.sqlite'));
    try { db.exec('CREATE TABLE retained (payload BLOB); INSERT INTO retained VALUES (zeroblob(16777216))'); } finally { db.close(); }
    const file = join(f.evidence, 'zz-last-large.log'); ordinaryFile(file, LARGE);
    const clean = bounded(f, [{ label: 'retained-clean', paths: [f.scratch, f.evidence] }]);
    expect(clean?.results[0]?.failed).not.toBe(true); expect(clean?.results[0]?.hit).toBeNull();
    plant(file, Buffer.from(f.source('rune').bytes.toString('base64')), LARGE - 37);
    const planted = bounded(f, [{ label: 'last-retained-file', paths: [f.scratch, f.evidence] }]);
    expect(planted?.results[0]?.failed).not.toBe(true);
    expect(planted?.results[0]?.hit?.path).toBe(file);
    expect(typeof planted?.results[0]?.hit?.encoding).toBe('string');
  } finally { f.cleanup(); }
});

it('CP-002/B8 five independent kinds and PEM bodies remain detectable in late and boundary-spanning registered forms under a 128 MiB heap', () => {
  const f = fixture();
  try {
    const tasks: Task[] = [];
    for (const source of f.sources) {
      const candidates: [string, Buffer][] = [[source.kind, source.bytes], ...(source.body ? [[`${source.kind}-DER`, source.body] as [string, Buffer]] : [])];
      for (const [kind, bytes] of candidates) {
        for (const [index, [encoding, value]] of forms(bytes).entries()) {
          const label = `${kind}/${encoding}`;
          const file = join(f.evidence, `${kind}-${encoding}.bin`);
          ordinaryFile(file, 2 * MiB);
          plant(file, value, index % 2 ? 2 * MiB - 31 : MiB + 13);
          tasks.push({ label, paths: [file] });
        }
      }
    }
    const observation = bounded(f, tasks);
    for (const [index, task] of tasks.entries()) {
      const row = observation?.results[index];
      expect.soft(row?.label === task.label, `${task.label}: result accounted for`).toBe(true);
      expect.soft(row?.failed !== true, `${task.label}: scan completed`).toBe(true);
      expect.soft(row?.hit?.path === task.paths[0], `${task.label}: planted file detected`).toBe(true);
      expect.soft(typeof row?.hit?.encoding === 'string' && row.hit.encoding.length > 0, `${task.label}: encoding metadata present`).toBe(true);
      expect.soft(row?.hit !== null && Object.keys(row?.hit ?? {}).every(key => key === 'path' || key === 'encoding'), `${task.label}: metadata only`).toBe(true);
    }
  } finally { f.cleanup(); }
});

it('CP-002/B8 raw base64 hex UTF16 wrapped and escaped forms near the end of 100 MiB files are detected under a 128 MiB heap', () => {
  const f = fixture();
  try {
    const tasks: Task[] = [];
    const lateControls: [string, string][] = [
      ['preimage', 'raw'], ['macaroon', 'base64-padded'], ['rune', 'hex-upper'],
      ['tls-key', 'utf16le'], ['approval-key', 'wrapped-base64'], ['preimage', 'json-escaped'],
    ];
    for (const [kind, encoding] of lateControls) {
      const encoded = forms(f.source(kind).bytes).find(([name]) => name === encoding);
      if (!encoded) throw new Error('required independent encoding is absent');
      const file = join(f.evidence, `large-${kind}-${encoding}.bin`);
      ordinaryFile(file, LARGE); plant(file, encoded[1], LARGE - 4093);
      tasks.push({ label: `large-tail/${kind}/${encoding}`, paths: [file] });
    }
    const observation = bounded(f, tasks);
    for (const [index, task] of tasks.entries()) {
      const row = observation?.results[index];
      expect.soft(row?.failed !== true, `${task.label}: scan completed`).toBe(true);
      expect.soft(row?.hit?.path === task.paths[0], `${task.label}: late file detected`).toBe(true);
      expect.soft(typeof row?.hit?.encoding === 'string', `${task.label}: encoding metadata present`).toBe(true);
    }
  } finally { f.cleanup(); }
});

// Independent POSIX ustar construction, not a production archive helper. The member
// plus headers is below the existing 128 MiB inflated archive limit.
async function archive(member: string, size: number, target: string) {
  const header = Buffer.alloc(512);
  header.write('retained/ordinary.log'); header.write('0000600\0', 100); header.write('0000000\0', 108); header.write('0000000\0', 116);
  header.write(`${size.toString(8).padStart(11, '0')}\0`, 124); header.write('00000000000\0', 136);
  header.fill(32, 148, 156); header[156] = 48; header.write('ustar\0', 257); header.write('00', 263);
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148);
  async function* contents() { yield header; for await (const block of createReadStream(member)) yield block; yield Buffer.alloc((512 - size % 512) % 512 + 1024); }
  await pipeline(Readable.from(contents()), createGzip(), createWriteStream(target, { mode: 0o600 }));
}

it('CP-002/B8 compressed tar members below the existing inflated limit are scanned clean and late leaks are found under a 128 MiB heap', async () => {
  const f = fixture();
  try {
    const member = join(f.scratch, 'ordinary.log'), tar = join(f.evidence, 'retained.tgz');
    ordinaryFile(member, LARGE); await archive(member, LARGE, tar);
    const clean = bounded(f, [{ label: 'compressed-clean', paths: [tar] }]);
    expect(clean?.results[0]?.failed).not.toBe(true); expect(clean?.results[0]?.hit).toBeNull();
    plant(member, Buffer.from(f.source('preimage').bytes.toString('hex')), LARGE - 41);
    appendFileSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'declared-out.txt'), `${tar}\n`);
    await archive(member, LARGE, tar);
    const planted = bounded(f, [{ label: 'compressed-late', paths: [tar] }]);
    expect(planted?.results[0]?.failed).not.toBe(true);
    expect(planted?.results[0]?.hit !== null, 'compressed member late leak detected').toBe(true);
    expect(typeof planted?.results[0]?.hit?.encoding).toBe('string');
  } finally { f.cleanup(); }
});
