// Interface: findLeaks({ sentinels, sentinelDir, root, paths, commandOutput,
// testTmp, evidenceDir }) returns null or { path, encoding }.
// SECURITY INV-11 and docs/security-model.md: complete registered bytes remain
// detectable in ordinary encoding runs, with legal grouping and line wrapping.
import { appendFileSync, mkdtempSync, rmdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { repoRoot } from '../helpers/cli.js';
import { testRoot } from '../helpers/env.js';

type Hit = { path: string; encoding: string } | null;
interface Scanner {
  findLeaks(options: { sentinels: string; sentinelDir: string; root: string; paths: string[];
    testTmp: string; evidenceDir: string; commandOutput?: string }): Hit;
}
type Alphabet = 'base64' | 'base64url';
const loadScanner = async (): Promise<Scanner> =>
  await import(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href) as Scanner;

function sample(length: number, salt = 19): Buffer {
  return Buffer.from(Array.from({ length }, (_, index) => (index * 53 + salt) & 255));
}

function base32(bytes: Buffer): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bits = [...bytes].map(byte => byte.toString(2).padStart(8, '0')).join('');
  let result = '';
  for (let offset = 0; offset < bits.length; offset += 5) {
    result += alphabet.charAt(Number.parseInt(bits.slice(offset, offset + 5).padEnd(5, '0'), 2));
  }
  return result;
}

function retainedForms(bytes: Buffer): [string, Buffer][] {
  const hex = bytes.toString('hex'), b64 = bytes.toString('base64');
  const utf16 = Buffer.from(bytes.toString('latin1'), 'utf16le');
  const text: [string, string][] = [
    ['hex-lower', hex], ['hex-upper', hex.toUpperCase()],
    ['base64-padded', b64], ['base64-unpadded', b64.replace(/=+$/, '')],
    ['base64url-padded', b64.replace(/\+/g, '-').replace(/\//g, '_')],
    ['base64url-unpadded', bytes.toString('base64url')],
    ['base32', base32(bytes)], ['base32-lower', base32(bytes).toLowerCase()],
    ['percent', [...bytes].map(byte => `%${byte.toString(16).padStart(2, '0')}`).join('')],
    ['escaped-hex', [...bytes].map(byte => `\\x${byte.toString(16).padStart(2, '0')}`).join('')],
    ['escaped-json', [...bytes].map(byte => `\\u00${byte.toString(16).padStart(2, '0')}`).join('')],
    ['decimal', `[${[...bytes].join(',')}]`],
    ['nested-base64', Buffer.from(hex).toString('base64')],
    ['nested-hex', Buffer.from(b64).toString('hex')],
  ];
  return [['raw', bytes], ['utf16le', utf16], ['utf16be', Buffer.from(utf16).swap16()],
    ...text.map(([name, value]): [string, Buffer] => [name, Buffer.from(value)])];
}

async function fixture() {
  const scanner = await loadScanner();
  const parent = testRoot('FLUXWARDEN_TEST_TMP');
  const root = mkdtempSync(join(parent, 'encoding-'));
  const sentinelDir = mkdtempSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), 'encoding-'));
  const sentinels = join(root, 'registry.json'), target = join(root, 'payload.bin');
  const sourceFiles: string[] = [];
  const sources: Buffer[] = [];
  writeFileSync(sentinels, '[]');
  // The surrounding scan may exclude this deliberate artifact; this scan's
  // own temporary root contains no declaration that could suppress a hit.
  appendFileSync(join(parent, 'declared-out.txt'), `${target}\n`);
  const options = { root, sentinels, sentinelDir, testTmp: root, evidenceDir: root };
  return {
    target,
    register(bytes: Buffer) {
      const path = join(sentinelDir, `${String(sourceFiles.length)}.bin`);
      sourceFiles.push(path);
      sources.push(bytes);
      writeFileSync(path, bytes, { mode: 0o600 });
    },
    clean(value: Buffer, label: string) {
      writeFileSync(target, value);
      expect(scanner.findLeaks({ ...options, paths: [target] }) === null, label).toBe(true);
    },
    detect(value: Buffer, label: string, output = false) {
      this.clean(Buffer.from('ordinary output ~!?'), `${label}: clean before planting`);
      writeFileSync(target, value);
      this.detectFile(label);
      if (output) {
        expect(Buffer.from(value.toString('utf8')).equals(value), `${label}: valid captured text`).toBe(true);
        const hit = scanner.findLeaks({ ...options, paths: [], commandOutput: value.toString('utf8') });
        expect(hit !== null, `${label}: captured output detected`).toBe(true);
      }
    },
    detectFile(label: string) {
      const hit = scanner.findLeaks({ ...options, paths: [target] });
      expect(hit !== null, `${label}: complete source detected`).toBe(true);
      // Only this artifact is selected. Paired clean observations establish its
      // identity even when a registered value inside its path must be redacted.
      const diagnostic = hit?.path;
      const maxDiagnosticBytes = Buffer.byteLength(target) * '[redacted fp:0000000000000000]'.length;
      expect(typeof diagnostic === 'string' && diagnostic.length > 0 && Buffer.byteLength(diagnostic) <= maxDiagnosticBytes,
        `${label}: bounded diagnostic path present`).toBe(true);
      expect(typeof diagnostic === 'string' && !/\p{Cc}/u.test(diagnostic) &&
        sources.every(source => !Buffer.from(diagnostic).includes(source)), `${label}: safe diagnostic path`).toBe(true);
      expect(typeof hit?.encoding === 'string' && hit.encoding.length > 0, `${label}: encoding named`).toBe(true);
      this.clean(Buffer.from('ordinary output ~!?'), `${label}: clean after planting`);
    },
    cleanup() {
      // Remove only the exact files and empty directories allocated here.
      for (const path of [target, sentinels, ...sourceFiles]) rmSync(path, { force: true });
      rmdirSync(root); rmdirSync(sentinelDir);
    },
  };
}

function encodedRun(source: Buffer, phase: number, alphabet: Alphabet): string {
  // Base64 represents three bytes per four symbols. Encode the entire ordinary
  // container so an interior source can begin at each of the three byte phases.
  const before = Buffer.concat([Buffer.from([251, 239, 248, 17, 34, 51, 68, 85, 102]), Buffer.alloc(phase, 177)]);
  const after = Buffer.from([161, 113, 129, 145, 161, 81, 97]);
  expect(!before.includes(source) && !after.includes(source), 'container margins contain no complete source').toBe(true);
  const bytes = Buffer.concat([before, source, after]);
  const encoded = bytes.toString('base64');
  const token = alphabet === 'base64' ? encoded : encoded.replace(/\+/g, '-').replace(/\//g, '_');
  expect(before.length % 3 === phase && Buffer.from(token, alphabet).subarray(before.length, before.length + source.length).equals(source),
    'complete source occurs at the requested byte phase').toBe(true);
  return token;
}

for (const alphabet of ['base64', 'base64url'] as const) {
  it(`CP-002/B8 ${alphabet} containers preserve complete interior sources at every byte phase`, async () => {
    const f = await fixture(), source = sample(35);
    try {
      f.register(source);
      f.clean(Buffer.from('ordinary output ~!?'), 'ordinary text is clean');
      for (const phase of [0, 1, 2]) {
        const token = encodedRun(source, phase, alphabet);
        for (const padded of [true, false]) {
          const value = padded ? token : token.replace(/=+$/, '');
          f.detect(Buffer.from(`!${value}?`), `${alphabet}/phase-${String(phase)}/padded-${String(padded)}`, true);
        }
      }
    } finally { f.cleanup(); }
  });
}

it('CP-002/B8 legal grouped hex and wrapped base64 preserve bytes across digit and quartet splits', async () => {
  const f = await fixture(), source = sample(38);
  try {
    f.register(source);
    f.clean(Buffer.from('ordinary output ~!?'), 'ordinary text is clean');
    for (const width of [1, 3]) {
      const grouped = source.toString('hex').match(new RegExp(`.{1,${String(width)}}`, 'g'))?.join(' \r\n\t') ?? '';
      f.detect(Buffer.from(`!${grouped}?`), `hex/group-${String(width)}`, true);
    }
    f.detect(Buffer.from(source.toString('hex').match(/../g)?.join(':') ?? ''), 'hex/colon-bytes', true);
    for (const alphabet of ['base64', 'base64url'] as const) {
      for (const phase of [0, 1, 2]) {
        for (const width of [5, 13]) {
          const token = encodedRun(source, phase, alphabet);
          const wrapped = token.match(new RegExp(`.{1,${String(width)}}`, 'g'))?.join('\r\n  \t') ?? '';
          f.detect(Buffer.from(`!${wrapped}?`), `${alphabet}/phase-${String(phase)}/wrap-${String(width)}`, true);
        }
      }
    }
  } finally { f.cleanup(); }
});

for (const length of [1, 2, 5]) {
  it(`CP-002/B8 a ${String(length)}-byte registration remains complete inside encoded containers`, async () => {
    const f = await fixture();
    // Avoid incidental standalone encodings in path text; a complete source
    // encoded inside a larger path container may still require redaction.
    const source = [255, 254, 253, 252, 250, 249]
      .map(first => Buffer.from(Array.from({ length }, (_, index) => first - index)))
      .find(bytes => retainedForms(bytes).every(([, value]) => !f.target.toLowerCase().includes(value.toString('utf8').toLowerCase())));
    try {
      if (!source) throw new Error('no collision-free synthetic source');
      f.register(source);
      f.clean(Buffer.from('ordinary output ~!?'), 'short registration does not reject ordinary text');
      for (const alphabet of ['base64', 'base64url'] as const) {
        for (const phase of [0, 1, 2]) {
          f.detect(Buffer.from(`!${encodedRun(source, phase, alphabet)}?`), `${alphabet}/phase-${String(phase)}`, true);
        }
      }
    } finally { f.cleanup(); }
  });
}

it('CP-002/B8 complete binary and retained textual encodings identify the planted file', async () => {
  const f = await fixture(), source = sample(41, 31);
  try {
    f.register(source);
    f.clean(Buffer.from('ordinary output ~!?'), 'ordinary artifact is clean');
    for (const [name, value] of retainedForms(source)) {
      f.detect(Buffer.concat([Buffer.from('!'), value, Buffer.from('?')]), name);
    }
  } finally { f.cleanup(); }
});

it('CP-002/B8 distinct longer registrations share a prefix without making that prefix a leak', async () => {
  const f = await fixture(), prefix = sample(24, 43);
  const sources = [Buffer.concat([prefix, sample(13, 91)]), Buffer.concat([prefix, sample(17, 137)])];
  const ordinary = Buffer.concat([prefix, Buffer.alloc(19, 238)]);
  try {
    for (const source of sources) f.register(source);
    expect(sources.every(source => !ordinary.includes(source)), 'negative fixture contains neither complete source').toBe(true);
    f.clean(ordinary, 'incomplete shared binary prefix is clean');
    for (const alphabet of ['base64', 'base64url'] as const) {
      for (const phase of [0, 1, 2]) {
        f.clean(Buffer.from(`!${encodedRun(ordinary, phase, alphabet)}?`), `${alphabet}/phase-${String(phase)}: incomplete prefix is clean`);
        for (const [index, source] of sources.entries()) {
          f.detect(Buffer.from(`!${encodedRun(source, phase, alphabet)}?`), `${alphabet}/phase-${String(phase)}/source-${String(index)}`, true);
        }
      }
    }
  } finally { f.cleanup(); }
});

it('CP-002/B8 complete encodings remain detectable across independent artifact write boundaries', async () => {
  const f = await fixture(), source = sample(35, 67);
  try {
    f.register(source);
    const forms = retainedForms(source).filter(([name]) => ['raw', 'hex-lower', 'base64-padded', 'base64url-padded', 'utf16le'].includes(name));
    for (const boundary of [4096, 65536]) {
      for (const [name, value] of forms) {
        f.clean(Buffer.alloc(boundary + value.length, '.'), `${name}/${String(boundary)}: ordinary file is clean`);
        const split = Math.floor(value.length / 2);
        writeFileSync(f.target, Buffer.concat([Buffer.alloc(boundary - split, '.'), value.subarray(0, split)]));
        appendFileSync(f.target, Buffer.concat([value.subarray(split), Buffer.from('!?')]));
        f.detectFile(`${name}/${String(boundary)}`);
      }
    }
  } finally { f.cleanup(); }
});
