// Adapted from ZilverZtream/macwarden scripts/leak-check.mjs (25bbfa4).
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, lstatSync, statSync, existsSync, openSync, readSync, closeSync, createReadStream } from 'node:fs';
import { resolve, relative, dirname, basename, join, sep, isAbsolute } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { createGunzip, deflateSync, inflateSync } from 'node:zlib';
import { serialize, deserialize } from 'node:v8';
import { pipeline } from 'node:stream/promises';
import { Worker, isMainThread, workerData } from 'node:worker_threads';

const INFLATED_LIMIT = 128 * 1024 * 1024;
const SCAN_CHUNK_BYTES = 256 * 1024;
const INFLATION_HEARTBEAT_MS = 100;
const INFLATION_STALL_MS = 2_000;

// Node.js/node doc/api/worker_threads.md: shared bytes plus Atomics preserve a
// synchronous caller while public stream APIs bound the compressed-input reads.
// Validate the complete gzip before recognition, retaining the existing cap and
// corrupt/truncated-archive refusal, even when an early member contains a leak.
if (!isMainThread && workerData?.leakInflation === true) {
  const control = new Int32Array(workerData.control);
  const bytes = new Uint8Array(workerData.bytes);
  const heartbeat = () => {
    Atomics.add(control, 2, 1);
    Atomics.notify(control, 0);
  };
  heartbeat();
  const pulse = setInterval(heartbeat, INFLATION_HEARTBEAT_MS);
  let size = 0;
  try {
    await pipeline(createReadStream(workerData.path), createGunzip(), async chunks => {
      for await (const chunk of chunks) {
        if (size + chunk.length > INFLATED_LIMIT) throw new Error('inflated artifact limit');
        bytes.set(chunk, size);
        size += chunk.length;
      }
    });
    Atomics.store(control, 1, size);
    Atomics.store(control, 0, 1);
  } catch {
    Atomics.store(control, 0, 2);
  } finally {
    clearInterval(pulse);
    Atomics.notify(control, 0);
  }
}

function inflatedArtifact(path) {
  const bytes = new SharedArrayBuffer(INFLATED_LIMIT);
  const control = new Int32Array(new SharedArrayBuffer(12));
  // A file entry cannot inherit --input-type from an inline/stdin caller. This
  // trusted bootstrap is valid in both CommonJS and ESM and retains inherited
  // heap/security options. Capture module-startup errors before shared status
  // initialization; parent 'error' listeners cannot run during Atomics.wait.
  const bootstrap = `import('node:worker_threads').then(({ workerData }) => {
    const control = new Int32Array(workerData.control);
    return import(workerData.module).catch(() => {
      Atomics.store(control, 0, 2);
      Atomics.notify(control, 0);
    });
  }).catch(() => {});`;
  const worker = new Worker(bootstrap, {
    eval: true,
    workerData: { leakInflation: true, module: import.meta.url, path, bytes, control: control.buffer },
  });
  // All stream errors become a fixed category in the shared control block.
  worker.on('error', () => {});
  try {
    let beat = Atomics.load(control, 2), lastProgress = performance.now();
    while (Atomics.load(control, 0) === 0) {
      Atomics.wait(control, 0, 0, INFLATION_HEARTBEAT_MS);
      const next = Atomics.load(control, 2);
      if (next !== beat) {
        beat = next;
        lastProgress = performance.now();
      }
      // This bounds lost-worker/startup failures, not gzip input or duration.
      // Healthy asynchronous reads continue to report liveness while pending.
      if (Atomics.load(control, 0) === 0 && performance.now() - lastProgress >= INFLATION_STALL_MS)
        throw new Error('compressed artifact worker unavailable');
    }
    if (Atomics.load(control, 0) !== 1) throw new Error('compressed artifact failed');
    return Buffer.from(bytes, 0, Atomics.load(control, 1));
  } finally {
    void worker.terminate();
  }
}

// Same leftmost-greedy matches as /W+(?:SW+)+={0,2}/g for the three grouped base64
// shapes, in linear time (the regular expressions backtrack quadratically over long
// unseparated runs).
// Classify every UTF-16 code unit with the original JavaScript whitespace
// recognizer once. The fixed 64 KiB table also covers non-byte code units.
const base64Classes = Uint8Array.from({ length: 65536 }, (_, code) => {
  const digit = code >= 65 && code <= 90 || code >= 97 && code <= 122 ||
    code >= 48 && code <= 57 || code === 43 || code === 47;
  const space = /\s/.test(String.fromCharCode(code));
  return (digit || code === 95 ? 1 : 0) | (digit ? 2 : 0) |
    (digit || code === 95 || code === 45 ? 4 : 0) |
    (!digit && ![95, 61, 92, 45].includes(code) && !space ? 8 : 0) |
    (code === 45 ? 16 : 0) | (code === 95 ? 32 : 0) | (space ? 64 : 0);
});
function lastToken(line) {
  let end = line.length;
  while (end > 0 && (base64Classes[line.charCodeAt(end - 1)] & 64)) end--;
  let start = end;
  while (start > 0 && !(base64Classes[line.charCodeAt(start - 1)] & 64)) start--;
  return line.slice(start, end);
}
// The same last token from every LF-delimited line, without allocating the
// complete split lines. Empty tokens contribute nothing to the joined view.
function lineTails(text) {
  const tails = [];
  let from = 0;
  for (;;) {
    const newline = text.indexOf('\n', from);
    const lineEnd = newline < 0 ? text.length : newline;
    let end = lineEnd;
    while (end > from && (base64Classes[text.charCodeAt(end - 1)] & 64)) end--;
    let start = end;
    while (start > from && !(base64Classes[text.charCodeAt(start - 1)] & 64)) start--;
    if (start < end) tails.push(text.slice(start, end));
    if (newline < 0) break;
    from = newline + 1;
  }
  return tails.join('');
}
export function groupedBase64Runs(text, shape, minimumLength = 0) {
  const runs = [];
  visitGroupedBase64(text, shape, minimumLength, (start, end) => runs.push(text.slice(start, end)));
  return runs;
}

function visitGroupedBase64(text, shape, minimumLength, visit) {
  // A grouped run requires an actual separator immediately followed by a word.
  // This native syntax check avoids walking every ordinary ungrouped character.
  const pair = shape === 'dash' ? /-[A-Za-z0-9+/_]/
    : shape === 'underscore' ? /_[A-Za-z0-9+/]/
      : /[^A-Za-z0-9+/_=\s\\-][A-Za-z0-9+/_-]/;
  if (!pair.test(text)) return;
  const wordMask = shape === 'dash' ? 1 : shape === 'underscore' ? 2 : 4;
  const separatorMask = shape === 'dash' ? 16 : shape === 'underscore' ? 32 : 8;
  const word = at => (base64Classes[text.charCodeAt(at)] & wordMask) !== 0;
  const separator = at => (base64Classes[text.charCodeAt(at)] & separatorMask) !== 0;
  let at = 0;
  while (at < text.length) {
    if (!word(at)) { at++; continue; }
    const start = at;
    while (at < text.length && word(at)) at++;
    const firstLength = at - start;
    let end = at, groups = 1, lastLength = firstLength, regular = firstLength % 4 === 0;
    while (end + 1 < text.length && separator(end) && word(end + 1)) {
      if (lastLength !== firstLength) regular = false;
      end++;
      const groupStart = end;
      while (end < text.length && word(end)) end++;
      lastLength = end - groupStart;
      groups++;
    }
    if (groups === 1) continue;
    let padding = 0;
    while (padding < 2 && text[end + padding] === '=') padding++;
    // Each consumed separator is removed before decoding. The remaining
    // character count bounds even the largest phase-zero decode; shorter
    // runs cannot hold any complete literal from the current source set.
    // Traverse the same greedy run and padding before deciding to emit it.
    const length = end - start - (groups - 1) + padding;
    if (Math.floor(length * 3 / 4) >= minimumLength)
      visit(start, end + padding, length, regular && lastLength <= firstLength);
    at = end + padding;
  }
}

function filesUnder(path, rejectLinks = false) {
  let stat;
  try { stat = lstatSync(path); }
  catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
  if (stat.isSymbolicLink()) {
    if (rejectLinks) throw new Error('linked artifact path');
    return [];
  }
  if (!stat.isDirectory()) return stat.isFile() ? [path] : [];
  return readdirSync(path).flatMap(name => filesUnder(join(path, name), rejectLinks));
}

function globPattern(glob) {
  let pattern = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*' && glob[i + 1] === '*') {
      if (glob[i + 2] === '/') { pattern += '(?:.*/)?'; i += 2; }
      else { pattern += '.*'; i++; }
    }
    else if (c === '*') pattern += '[^/]*';
    else if (c === '?') pattern += '[^/]';
    else pattern += c.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
  }
  return new RegExp(`^${pattern}$`);
}

function variants(bytes) {
  const base64 = bytes.toString('base64');
  const base64url = bytes.toString('base64url');
  return [
    ['utf8', bytes.toString('utf8')], ['latin1', bytes.toString('latin1')],
    ['hex-lower', bytes.toString('hex')], ['hex-upper', bytes.toString('hex').toUpperCase()],
    ['base64-padded', base64], ['base64-unpadded', base64.replace(/=+$/, '')],
    ['base64url-padded', base64.replace(/\+/g, '-').replace(/\//g, '_')],
    ['base64url-unpadded', base64url],
    // Case folding (for example a URL hostname) keeps most of a base64 value's bits.
    ['base64-case-folded', base64.replace(/=+$/, '').toLowerCase()],
    ['base64url-case-folded', base64url.toLowerCase()],
    ['base32', base32(bytes)],
    ['base32-lower', base32(bytes).toLowerCase()],
  ].filter(([, value]) => value.length > 0);
}

function base32(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let accumulator = 0, bits = 0, text = '';
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte; bits += 8;
    while (bits >= 5) { bits -= 5; text += alphabet[(accumulator >>> bits) & 31]; }
  }
  if (bits) text += alphabet[(accumulator << (5 - bits)) & 31];
  return text;
}

const hexNibbles = Int8Array.from({ length: 128 }, (_, code) =>
  code >= 48 && code <= 57 ? code - 48 : code >= 65 && code <= 70 ? code - 55
    : code >= 97 && code <= 102 ? code - 87 : -1);
function hexStreams(text) {
  text = text.replace(/0x(?=[0-9a-f]{2})/gi, '');
  const nibble = code => code >= 0 && code < 128 ? hexNibbles[code] : -1;
  const separatorEnd = at => {
    const char = text[at];
    const code = text.charCodeAt(at);
    if (char !== undefined && char !== '\\' && !(code >= 48 && code <= 57 ||
        code >= 65 && code <= 90 || code >= 97 && code <= 122)) return at + 1;
    if (char !== '\\') return at;
    if (text[at + 1] !== undefined && 'trnfv'.includes(text[at + 1])) return at + 2;
    if (text[at + 1] === 'u' &&
        ['0009', '000a', '000b', '000c', '000d', '0020'].includes(
          text.slice(at + 2, at + 6).toLowerCase())) return at + 6;
    return at;
  };

  const stream = capacity => ({ bytes: Buffer.allocUnsafe(capacity),
    length: 0, start: 0, ends: [] });
  const ordinary = stream(Math.floor(text.length / 2));
  // Odd groups contribute both their ordinary and shifted pairs here.
  const shifted = stream(text.length);
  const finish = stream => {
    // The separated-hex recognizer has always required at least two bytes.
    // Short segments cannot match; dropping them retains the same boundaries.
    if (stream.length - stream.start >= 2) stream.ends.push(stream.length);
    else stream.length = stream.start;
    stream.start = stream.length;
  };
  let shiftedActive = false;
  for (let at = 0; at < text.length;) {
    if (nibble(text.charCodeAt(at)) < 0) {
      at++;
      continue;
    }

    const start = at;
    while (at < text.length && nibble(text.charCodeAt(at)) >= 0) at++;
    // Keep the ordinary pairs through an odd final group. A shifted stream
    // starts one nibble into an odd group and continues through later groups;
    // another odd group ends that stream only after its ordinary pairs.
    const odd = (at - start) % 2 !== 0;
    for (let pair = start; pair + 1 < at; pair += 2) {
      const byte = nibble(text.charCodeAt(pair)) * 16 + nibble(text.charCodeAt(pair + 1));
      ordinary.bytes[ordinary.length++] = byte;
      if (shiftedActive) shifted.bytes[shifted.length++] = byte;
    }
    if (odd) {
      finish(shifted);
      shiftedActive = true;
      for (let pair = start + 1; pair + 1 < at; pair += 2) {
        const byte = nibble(text.charCodeAt(pair)) * 16 + nibble(text.charCodeAt(pair + 1));
        shifted.bytes[shifted.length++] = byte;
      }
      finish(ordinary);
    }

    const beforeSeparator = at;
    while (at < text.length) {
      const end = separatorEnd(at);
      if (end === at) break;
      at = end;
    }
    if (at === beforeSeparator || at >= text.length || nibble(text.charCodeAt(at)) < 0) {
      finish(ordinary);
      finish(shifted);
      shiftedActive = false;
    }
  }
  finish(ordinary);
  finish(shifted);
  return [ordinary, shifted].map(({ bytes, length, ends }) =>
    ({ bytes: bytes.subarray(0, length), ends: Uint32Array.from(ends) }));
}

function streamIncludes(streams, source) {
  for (const { bytes, ends, starts, finishes } of streams) {
    for (let at = bytes.indexOf(source); at !== -1; at = bytes.indexOf(source, at + 1)) {
      // Concatenating segments lets each source use native search. Reject any
      // match crossing a reset; no delimiter byte can safely stand for a reset.
      let low = 0, high = ends.length;
      while (low < high) {
        const mid = Math.floor((low + high) / 2);
        if (ends[mid] <= at) low = mid + 1;
        else high = mid;
      }
      if (at + source.length <= ends[low] &&
          (!starts || starts[at]) && (!finishes || finishes[at + source.length - 1])) return true;
    }
  }
  return false;
}

function decimalStream(text) {
  const streams = [];
  const runs = /\d{1,3}(?:[^0-9A-Za-z\\]{1,3}\d{1,3})+|\[\s*\d{1,3}\s*\]/g;
  for (let run; (run = runs.exec(text)) !== null;) {
    const values = run[0].match(/\d+/g).map(Number);
    for (let segmentStart = 0; segmentStart < values.length;) {
      let segmentEnd = segmentStart;
      while (segmentEnd < values.length && values[segmentEnd] <= 255) segmentEnd++;
      if (segmentEnd > segmentStart) {
        const bytes = Buffer.from(values.slice(segmentStart, segmentEnd));
        streams.push({ bytes, ends: Uint32Array.of(bytes.length) });
      }
      segmentStart = segmentEnd + 1;
    }
  }
  return streams;
}

function recoveredText(text, unique = true) {
  // A decoded credential can itself contain escape-like bytes. Keep every
  // depth so a later decoding pass cannot erase an earlier exact match.
  const views = [text];
  for (let round = 0; round < 2; round++) {
    text = text.replace(/%u([0-9a-f]{4})|&#(?:x([0-9a-f]{1,4})|([0-9]{1,5}));/gi,
      (match, unicode, hex, decimal) => {
        const value = parseInt(unicode ?? hex ?? decimal, decimal ? 10 : 16);
        return value <= 255 ? String.fromCharCode(value) : match;
      });
    text = text.replace(/\\(?:u([0-9a-f]{4})|x([0-9a-f]{2})|([0-7]{1,3})|([\\"/bfnrt]))/gi,
      (_match, unicode, hex, octal, simple) => unicode || hex || octal
        ? String.fromCharCode(parseInt(unicode ?? hex ?? octal, octal ? 8 : 16))
        : ({ b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }[simple] ?? simple));
    views.push(text);
  }
  return unique ? [...new Set(views)] : views;
}

function preparedSource(source) {
  const hex = source.toString('hex');
  const latin1 = source.toString('latin1');
  const utf16le = Buffer.from(latin1, 'utf16le');
  const base64 = source.toString('base64');
  const base64url = source.toString('base64url');
  const base64Forms = [...new Set([base64, base64.replace(/=+$/, ''),
    base64.replace(/\+/g, '-').replace(/\//g, '_'), base64url])];
  const textForms = [...new Set([hex, hex.toUpperCase(), ...base64Forms])].map(form => Buffer.from(form));
  return {
    source, hex, latin1, base64, base64url, base64Forms,
    // Text encodings as bytes, for a second layer: base64 or hex of this text.
    textForms,
    // Canonical short nested values do not reach the maximal-run decoder's floor.
    shortBase64TextForms: textForms.filter(form => form.length <= 9).map(form => Buffer.from(form.toString('base64'))),
    utf16le, utf16be: Buffer.from(utf16le).swap16(),
    percentBytes: hex.replace(/../g, byte => `%${byte}`),
    escapedBytes: hex.replace(/../g, byte => `\\x${byte}`),
    decimalMinLength: [...source].reduce((length, byte) => length + String(byte).length, source.length + 1),
  };
}

function preparedBase64Runs(text, joined, tails, minimumLength, base64MayMatch) {
  const runs = new Set();
  const decisions = new Map();
  let decisionBytes = 0;
  let workspace;
  const kept = (code, shape) => shape === 'dash' ? code !== 45 : shape === 'underscore' ? code !== 95
    : shape !== 'other' || (base64Classes[code] & 4) !== 0 || code === 61;
  const canonical = code => code === 45 ? 43 : code === 95 ? 47 : code;
  const normalize = (view, start, end, shape) => {
    const run = view.slice(start, end);
    return shape === 'dash' ? run.replaceAll('-', '') : shape === 'underscore' ? run.replaceAll('_', '')
      : shape === 'other' ? run.replace(/[^A-Za-z0-9+/_=-]/g, '') : run;
  };
  const allows = (view, start, end, shape, length) => {
    if (base64MayMatch.maximumLength === 0) return true;
    // Canonical ASCII spans use one reusable buffer, not one encoded string
    // per predicate miss. Long spans keep every boundary through prefix overlap.
    if (base64MayMatch.bytes) {
      workspace ??= Buffer.allocUnsafe(SCAN_CHUNK_BYTES);
      if (length > workspace.length) {
        const overlap = base64MayMatch.maximumLength - 1;
        let used = 0;
        for (let at = start; at < end; at++) {
          const code = view.charCodeAt(at);
          if (!kept(code, shape)) continue;
          workspace[used++] = canonical(code);
          if (used === workspace.length) {
            if (base64MayMatch.bytes(workspace.subarray(0, used))) return true;
            workspace.copy(workspace, 0, used - overlap, used);
            used = overlap;
          }
        }
        return base64MayMatch.bytes(workspace.subarray(0, used));
      }
      let hash = 2166136261, used = 0;
      for (let at = start; at < end; at++) {
        const code = view.charCodeAt(at);
        if (!kept(code, shape)) continue;
        const byte = canonical(code);
        workspace[used++] = byte;
        hash = Math.imul(hash ^ byte, 16777619) >>> 0;
      }
      const value = workspace.subarray(0, used), cached = decisions.get(hash);
      if (Buffer.isBuffer(cached?.value) && cached.value.equals(value)) return cached.allowed;
      const allowed = base64MayMatch.bytes(value);
      // Hash collisions only select a complete logical-value comparison. Keep
      // the existing conservative quota; collisions and full quotas stay uncached.
      const size = used * 2 + 128;
      if (!cached && decisionBytes + size <= SCAN_CHUNK_BYTES) {
        decisions.set(hash, { value: Buffer.from(value), allowed });
        decisionBytes += size;
      }
      return allowed;
    }
    let hash = 2166136261;
    for (let at = start; at < end; at++) {
      const code = view.charCodeAt(at);
      if (kept(code, shape)) hash = Math.imul(hash ^ canonical(code), 16777619) >>> 0;
    }
    const cached = decisions.get(hash);
    if (cached?.value.length === length) {
      let index = 0, equal = true;
      for (let at = start; at < end; at++) {
        const code = view.charCodeAt(at);
        if (kept(code, shape) && canonical(code) !== cached.value.charCodeAt(index++)) { equal = false; break; }
      }
      if (equal && index === length) return cached.allowed;
    }
    const value = normalize(view, start, end, shape).replaceAll('-', '+').replaceAll('_', '/');
    const allowed = base64MayMatch(value);
    const size = value.length * 2 + 128;
    // Hashes only select a complete-string comparison. A collision or a full
    // per-window budget receives the original uncached predicate instead.
    if (!cached && decisionBytes + size <= SCAN_CHUNK_BYTES) {
      decisions.set(hash, { value, allowed });
      decisionBytes += size;
    }
    return allowed;
  };
  const admit = (view, start, end, shape, length, regular = true) => {
    if (!regular || !(Math.floor(length * 3 / 4) >= minimumLength) || !allows(view, start, end, shape, length)) return;
    // Group regularity never changes a cached source-predicate decision.
    runs.add(normalize(view, start, end, shape));
  };
  for (const view of new Set([text, joined, tails])) {
    const pattern = /[A-Za-z0-9+/_-]{16,}={0,2}/g;
    for (let match; (match = pattern.exec(view)) !== null;) admit(view, match.index, pattern.lastIndex, 'raw', match[0].length);
  }
  for (const shape of ['dash', 'underscore', 'other']) {
    visitGroupedBase64(text, shape, minimumLength, (start, end, length, regular) =>
      admit(text, start, end, shape, length, shape !== 'other' || regular));
  }
  return [...runs].flatMap(run => [0, 1, 2, 3].map(phase => Buffer.from(run.slice(phase), 'base64url')));
}

function preparedData(data, minimumLength = 0, base64MayMatch = () => true, literalWorkspace) {
  // Exact duplicate views share immutable buffers within this decoded window.
  const buffers = new Map();
  const buffer = text => {
    if (!buffers.has(text)) buffers.set(text, Buffer.from(text));
    return buffers.get(text);
  };
  // A valid UTF-8 view is the exact input bytes, so let the matcher's WeakMap
  // reuse that complete comparison. Invalid UTF-8 keeps its original bytes
  // and its independently encoded replacement-character view.
  const utf8 = data.toString('utf8'), utf8Bytes = Buffer.from(utf8);
  buffers.set(utf8, utf8Bytes.equals(data) ? data : utf8Bytes);
  const utf16 = Buffer.from(data.subarray(0, data.length - data.length % 2));
  const recovered = [utf8, utf16.toString('utf16le'),
    Buffer.from(utf16).swap16().toString('utf16le')].flatMap(recoveredText);
  const text = recovered.join('\n');
  // Zero-width characters split a value as invisibly as whitespace does.
  const compact = text.replace(/[\s\u200b-\u200d\u2060\ufeff]/g, '');
  // Two more views of split values, each one linear pass: adjacent string literals
  // joined ("ab" + "cd", ["ab", "cd"]), and the last token of every line joined
  // (wrapped output behind a per-line log prefix such as a timestamp).
  const literals = text.replace(/(["'`])(?=([\s\u200b-\u200d\u2060\ufeff]*))\2[,+]?(?=([\s\u200b-\u200d\u2060\ufeff]*))\3\1/g, '');
  const joined = literals === text ? compact : literals.replace(/[\s\u200b-\u200d\u2060\ufeff]/g, '');
  const tails = lineTails(text);
  const percent = text.replace(/%([0-9a-f]{2})/gi, (_, digits) => String.fromCharCode(parseInt(digits, 16)));
  const lower = text.toLowerCase();
  const compactLower = compact === text ? lower : compact.toLowerCase();
  const percentLower = percent === text ? lower
    : percent === compact ? compactLower : percent.toLowerCase();
  let separated, decimal, base64Runs;
  // Stream literal views through the same byte matcher. Detailed checks can
  // still materialize every original UTF-8 buffer after a candidate is admitted.
  return { data, text, literalWorkspace,
    literalTexts: () => [...recovered, lower, compact, compactLower, percent, percentLower, joined, tails],
    get recovered() { return recovered.map(buffer); },
    get lower() { return buffer(lower); },
    get compact() { return buffer(compact); },
    get compactLower() { return buffer(compactLower); },
    get percent() { return buffer(percent); },
    get percentLower() { return buffer(percentLower); },
    get splitViews() { return [buffer(joined), buffer(tails)]; },
    hexStreams: () => separated ??= hexStreams(text),
    decimalStream: () => decimal ??= decimalStream(text),
    get base64Runs() { return base64Runs ??= preparedBase64Runs(text, joined, tails, minimumLength, base64MayMatch); } };
}

function alternateEncoding(data, source, state = preparedSource(source), input = preparedData(data)) {
  const { recovered, text, lower, compact, compactLower, percent, percentLower, base64Runs } = input;
  const { hex, base64, base64url, latin1 } = state;
  if (recovered.some(text => text.includes(latin1))) return 'recovered escaped bytes';
  if (lower.includes(hex)) return 'mixed-case hex';
  if (text.length >= state.decimalMinLength && streamIncludes(input.decimalStream(), source)) return 'decimal byte array';
  if (source.length >= 2 && text.length >= source.length * 2 &&
      streamIncludes(input.hexStreams(), source)) return 'separated hex';
  if (compactLower.includes(hex)) return 'wrapped hex';
  if (state.base64Forms.some(form => compact.includes(form))) return 'wrapped base64';
  if (percentLower.includes(hex)) return 'percent-encoded hex';
  if (percent.includes(base64) || percent.includes(base64url)) return 'percent-encoded base64';
  if (state.base64Forms.some(form => compactLower.includes(form.replace(/=+$/, '').toLowerCase()) ||
    percentLower.includes(form.replace(/=+$/, '').toLowerCase()))) return 'case-folded base64';
  if (lower.includes(state.percentBytes)) return 'percent-encoded bytes';
  if (lower.includes(state.escapedBytes)) return 'escaped bytes';
  if (data.includes(state.utf16le) || data.includes(state.utf16be)) return 'utf-16 bytes';
  // Decode each maximal base64 run once, preserving offset recognition.
  if (base64Runs.some(run => run.includes(source))) return 'offset base64';
  if (input.splitViews.some(view => state.textForms.some(form => view.includes(form)))) return 'split literals';
  // A second layer: base64 of the hex or base64 text, or hex of the base64 text.
  if (state.shortBase64TextForms.some(form => data.includes(form))) return 'base64 of a text encoding';
  if (base64Runs.some(run => state.textForms.some(form => run.includes(form)))) return 'base64 of a text encoding';
  if (text.length >= source.length * 2 && state.textForms.some(form => streamIncludes(input.hexStreams(), form)))
    return 'hex of a text encoding';
  return null;
}

const MATCHER_SHIFT_BYTES = 1 << 20;
function preparedLiteralMatcher(values, minimumWidth = 8) {
  const literals = [...new Map(values.map(bytes => [bytes.toString('hex'), bytes])).values()];
  const minimumLength = literals.reduce((size, bytes) => Math.min(size, bytes.length), Infinity);
  const maximumLength = literals.reduce((size, bytes) => Math.max(size, bytes.length), 0);
  const width = Math.min(32, Math.max(minimumWidth, minimumLength));
  const short = literals.filter(bytes => bytes.length < width);
  const blockKey = word => Math.imul(word, 0x9e3779b1) >>> 12;
  // A rare final block permits long conservative skips. Frequency is only
  // an anchor-selection heuristic; hash collisions cannot suppress a match.
  const prefixes = new Map();
  const selectAnchors = () => {
    const frequency = new Uint16Array(MATCHER_SHIFT_BYTES);
    for (const bytes of literals) {
      for (let at = width - 4; at + 4 <= bytes.length; at++) {
        const key = blockKey(bytes.readUInt32LE(at));
        if (frequency[key] < 65535) frequency[key]++;
      }
    }
    for (const bytes of literals.filter(bytes => bytes.length >= width)) {
      let offset = 0, best = Infinity;
      for (let at = 0; at + width <= bytes.length; at++) {
        const score = frequency[blockKey(bytes.readUInt32LE(at + width - 4))];
        if (score < best) { best = score; offset = at; }
        if (score === 1) break;
      }
      const key = bytes.readUInt32LE(offset);
      if (!prefixes.has(key)) prefixes.set(key, []);
      prefixes.get(key).push({ bytes, offset });
    }
  };
  selectAnchors();
  // Wu-Manber's conservative block shifts (bubiche/wu_manber,
  // wu_manber.hpp preProcess/scan), with anchors bounded by the shortest
  // literal. Four-byte hash collisions only reduce shifts; every admitted
  // position still receives exact complete-literal validation.
  const shifts = new Uint8Array(MATCHER_SHIFT_BYTES).fill(width - 3);
  for (const candidates of prefixes.values()) for (const { bytes, offset } of candidates) {
    for (let at = 0; at <= width - 4; at++) {
      const block = blockKey(bytes.readUInt32LE(offset + at));
      shifts[block] = Math.min(shifts[block], width - 4 - at);
    }
  }
  // Only freshly prepared, immutable view buffers reach this matcher.
  const checked = new WeakMap();
  const check = bytes => {
    for (const value of short) if (bytes.includes(value)) return true;
    // Recover each possible literal start from its interior anchor, then
    // compare the complete bytes. Short values were searched independently.
    for (let at = 0; at + width <= bytes.length;) {
      const shift = shifts[blockKey(bytes.readUInt32LE(at + width - 4))];
      if (shift) { at += shift; continue; }
      const key = bytes.readUInt32LE(at);
      const candidates = prefixes.get(key);
      if (candidates) for (const { bytes: value, offset } of candidates) {
        if (bytes.readUInt32LE(at + width - 4) !== value.readUInt32LE(offset + width - 4)) continue;
        const start = at - offset;
        if (start >= 0 && start + value.length <= bytes.length &&
            bytes.compare(value, 0, value.length, start, start + value.length) === 0) return true;
      }
      // A zero shift admits a candidate and advances just one byte, keeping
      // overlapping anchors and their original literal starts reachable.
      at++;
    }
    return false;
  };
  const match = bytes => {
    // No full literal can fit in a shorter buffer. In particular, avoid
    // retaining WeakMap entries for the many tiny decoded grouping runs.
    if (bytes.length < minimumLength) return false;
    if (!checked.has(bytes)) checked.set(bytes, check(bytes));
    return checked.get(bytes);
  };
  // Mutable invocation-owned workspaces must bypass immutable-buffer memoization.
  match.mutable = bytes => bytes.length >= minimumLength && check(bytes);
  match.minimumLength = minimumLength;
  match.text = (text, workspace) => {
    // Search the identical UTF-8 byte sequence without retaining a complete
    // encoded view. Small views and very long literals keep the direct path.
    if (!workspace || !maximumLength || text.length <= maximumLength || maximumLength >= SCAN_CHUNK_BYTES / 2)
      return match(Buffer.from(text));
    const bytes = workspace();
    let from = 0, retained = 0;
    while (from < text.length) {
      // Three bytes per UTF-16 code unit bounds UTF-8, including replacement
      // bytes for unpaired surrogates. Keep valid pairs together so slicing
      // cannot introduce replacement bytes absent from Buffer.from(text).
      let end = Math.min(text.length, from + Math.floor((bytes.length - retained) / 3));
      if (end < text.length && text.charCodeAt(end - 1) >= 0xd800 && text.charCodeAt(end - 1) <= 0xdbff &&
          text.charCodeAt(end) >= 0xdc00 && text.charCodeAt(end) <= 0xdfff) end--;
      const length = retained + bytes.write(text.slice(from, end), retained, bytes.length - retained, 'utf8');
      // The reusable workspace is mutable: bypass the immutable-buffer cache.
      if (check(bytes.subarray(0, length))) return true;
      retained = Math.min(maximumLength - 1, length);
      bytes.copy(bytes, 0, length - retained, length);
      from = end;
    }
    return false;
  };
  return match;
}

function preparedMatcherGroup(states) {
  const encoded = preparedLiteralMatcher(states.flatMap(state => [
    state.source,
    ...state.variants.map(variant => variant.bytes), state.utf16le, state.utf16be,
    ...state.shortBase64TextForms,
    Buffer.from(state.percentBytes), Buffer.from(state.escapedBytes),
  ]));
  const match = input => {
    // These literal alternatives contain every full registered credential.
    // This filter may admit a match across parser boundaries; the detailed
    // checks below still enforce all boundaries and choose the encoding.
    if (encoded(input.data)) return true;
    const checkedTexts = new Set();
    for (const text of input.literalTexts()) {
      if (checkedTexts.has(text)) continue;
      checkedTexts.add(text);
      if (encoded.text(text, input.literalWorkspace)) return true;
    }
    if (input.hexStreams().some(stream => encoded(stream.bytes)) ||
        input.decimalStream().some(stream => encoded(stream.bytes))) return true;
    return input.base64Runs.some(encoded);
  };
  match.minimumLength = encoded.minimumLength;
  return match;
}

function preparedMatcher(states) {
  return preparedMatcherGroup(states);
}

function preparedBase64Filter(states) {
  const admitAll = () => true;
  admitAll.bytes = admitAll;
  admitAll.maximumLength = 0;
  if (!states.length) return admitAll;
  const patterns = new Set();
  for (const state of states) for (const bytes of [state.source, ...state.textForms]) {
    const prefix = bytes.subarray(0, 24);
    for (let phase = 0; phase < 3; phase++) {
      const encoded = Buffer.concat([Buffer.alloc(phase), prefix]).toString('base64');
      const from = Math.ceil(phase * 8 / 6), to = Math.floor((phase + prefix.length) * 8 / 6);
      const anchor = encoded.slice(from, to);
      // A short source might provide no complete, independently determined
      // sextet. In that case every run still receives all four decoding passes.
      if (!anchor) return admitAll;
      patterns.add(anchor);
    }
  }
  // Any decoded occurrence contains these interior sextets of its first bytes,
  // regardless of the enclosing byte phase or the decoder's starting offset.
  // Group separators were already removed. Each sextet accepts either alphabet;
  // full decoding and exact complete-source checks still decide every match.
  const prefixes = preparedLiteralMatcher([...patterns].map(pattern => Buffer.from(pattern)), 4);
  const matches = run => prefixes(Buffer.from(run.replaceAll('-', '+').replaceAll('_', '/')));
  matches.bytes = prefixes.mutable;
  matches.maximumLength = [...patterns].reduce((length, pattern) => Math.max(length, pattern.length), 0);
  return matches;
}

function preparedSyntaxFilter(states) {
  if (!states.length) return () => true;
  const patterns = new Set();
  for (const state of states) {
    for (const bytes of [state.source, ...state.variants.map(form => form.bytes), state.utf16le, state.utf16be,
      ...state.shortBase64TextForms]) patterns.add(bytes.subarray(0, 32).toString('latin1'));
    for (const bytes of [state.source, ...state.textForms]) {
      const prefix = bytes.subarray(0, 24);
      patterns.add(prefix.toString('hex'));
      patterns.add([...prefix].map(byte => String(byte)).join(''));
      // Drop the leading sextets influenced by an unknown enclosing prefix.
      // Every remaining sextet depends solely on registered bytes. Include all
      // three byte phases and grouped/wrapped forms, then verify full values.
      for (let phase = 0; phase < 3; phase++) {
        const encoded = Buffer.concat([Buffer.alloc(phase), prefix]).toString('base64');
        const from = Math.ceil(phase * 8 / 6), to = Math.floor((phase + prefix.length) * 8 / 6);
        patterns.add(encoded.slice(from, to));
      }
    }
  }
  // Escape syntaxes are decoded by the authoritative recognizers. A marker
  // admits the entire window rather than trying to enumerate their depths.
  const marker = /[\\%]|&#/;
  if (patterns.has('')) return () => true;
  // Every case-insensitive Latin-1 literal match also survives uppercasing both
  // strings. Expanding characters can admit extra prefixes; complete parsers
  // still decide hits. Every complete value contains its full chosen prefix;
  // longer prefixes permit larger conservative byte-search skips.
  const prefixes = preparedLiteralMatcher([...patterns].map(pattern => Buffer.from(pattern.toUpperCase())), 4);
  const matches = text => prefixes(Buffer.from(text.toUpperCase()));
  return bytes => {
    const text = bytes.toString('latin1');
    // These are deliberately permissive prefix views: removing even invalid
    // separators can only admit extra candidates. Full parsers decide matches.
    return marker.test(text) || matches(text) || matches(text.replace(/[^A-Za-z0-9+/]/g, '')) ||
      matches(text.replace(/[^A-Za-z0-9+/_-]/g, '').replaceAll('-', '+').replaceAll('_', '/')) ||
      matches(text.replace(/0x/gi, '').replace(/[^0-9a-f]/gi, '')) ||
      matches(text.replace(/[^0-9]/g, ''));
  };
}

function replaceCredential(text, value, foldedHex) {
  if (!value) return text;
  // UTF-8 replaces each lone surrogate with one replacement character. Compare
  // that view, whose code-unit positions are unchanged, but copy ordinary spans
  // from the original string. Hex folding also preserves every position.
  const comparable = foldedHex ? text.replace(/[A-F]/g, letter => letter.toLowerCase()) : text.toWellFormed();
  const needle = foldedHex ? value.toLowerCase() : value;
  let at = comparable.indexOf(needle);
  if (at < 0) return text;
  const parts = [];
  let from = 0;
  do {
    parts.push(text.slice(from, at), '[redacted]');
    from = at + needle.length;
    at = comparable.indexOf(needle, from);
  } while (at >= 0);
  parts.push(text.slice(from));
  return parts.join('');
}

function safePath(path, sources, state = preparedRedactor(sources)) {
  if (path === 'command output') return path;
  if (state.possibleLeak) {
    const input = preparedData(Buffer.from(path), state.possibleLeak.minimumLength);
    const name = basename(path);
    if (!state.possibleLeak(input) &&
        (name === path || !state.possibleLeak(preparedData(Buffer.from(name), state.possibleLeak.minimumLength)))) return path;
  }
  let safe = path;
  for (const { value, foldedHex } of state.encoded) {
    safe = replaceCredential(safe, value, foldedHex);
  }
  // Recognize the filename independently: hex-looking directory prefixes can
  // share separators with its encoding and change the byte alignment.
  const data = Buffer.from(safe);
  const input = preparedData(data);
  const nameData = Buffer.from(basename(safe));
  const nameInput = basename(safe) === safe ? input : preparedData(nameData);
  if (state.sources.some(source => alternateEncoding(data, source.source, source, input) ||
    alternateEncoding(nameData, source.source, source, nameInput))) return '[redacted path]';
  return safe;
}

function preparedRedactor(sources) {
  const states = sources.map(preparedCredential);
  return { sources: states, possibleLeak: sources.length ? preparedMatcher(states) : null,
    encoded: states.flatMap(state => state.redactions).sort((a, b) => b.value.length - a.value.length) };
}

const preparedCredentials = new Map();
let credentialBytes = 0;
function preparedCredential(source) {
  const key = source.toString('hex');
  const found = preparedCredentials.get(key);
  if (found) return found;
  const forms = variants(source);
  const state = { ...preparedSource(source),
    variants: forms.map(([encoding, value]) => ({ encoding, value,
      lower: value.toLowerCase(), bytes: Buffer.from(value, 'utf8') })),
    redactions: forms.map(([encoding, value]) => ({ value, foldedHex: encoding.startsWith('hex-') })),
    size: source.length * 256 + 4096 };
  const limit = 64 * 1_048_576;
  if (state.size <= limit) {
    while (preparedCredentials.size >= 4096 || credentialBytes + state.size > limit) {
      const oldest = preparedCredentials.keys().next().value;
      credentialBytes -= preparedCredentials.get(oldest).size;
      preparedCredentials.delete(oldest);
    }
    preparedCredentials.set(key, state);
    credentialBytes += state.size;
  }
  return state;
}

// Keys contain the complete bytes in their current order, never paths or file
// metadata. Callers must enumerate and read the sources before consulting this
// cache, so replacement, late registration and unreadable sources stay visible.
const sourceSnapshots = new Map();
let snapshotBytes = 0;
function preparedSnapshot(sources) {
  const key = sources.map(source => source.toString('hex')).join(':');
  const found = sourceSnapshots.get(key);
  if (found) return found;
  const states = sources.map(preparedCredential);
  const state = { states, possibleLeak: sources.length ? preparedMatcher(states) : null,
    syntax: preparedSyntaxFilter(states),
    base64MayMatch: preparedBase64Filter(states),
    redactor: preparedRedactor(sources),
    cleanInputs: new Map(), cleanInputBytes: 0,
    // Include buffers, string encodings, regex alternatives and per-source
    // overhead conservatively, plus both full and both prefix matchers' fixed
    // byte-shift tables.
    // Oversized snapshots receive uncached checks.
    size: (sources.length ? 4 * MATCHER_SHIFT_BYTES : 0) +
      sources.reduce((size, source) => size + source.length * 256 + 4096, key.length * 2) };
  const limit = 64 * 1_048_576;
  if (state.size <= limit) {
    while (sourceSnapshots.size >= 4 || snapshotBytes + state.size > limit) {
      const oldest = sourceSnapshots.keys().next().value;
      snapshotBytes -= sourceSnapshots.get(oldest).size;
      sourceSnapshots.delete(oldest);
    }
    sourceSnapshots.set(key, state);
    snapshotBytes += state.size;
  }
  return state;
}

/**
 * @typedef {object} SentinelOptions
 * @property {string} sentinels Path to the registered source-glob JSON list.
 * @property {string} [sentinelDir] Directory of runtime sentinel source files.
 * @property {string} [root] Project root for registered source globs.
 */

// Fewer distinct byte values than this in 32 bytes is not a random signature
// (a uniform random one falls below 16 with negligible probability).
const SIGNATURE_MIN_DISTINCT_BYTES = 16;

// Another test worker's bake or rotate holds a freshly staged runtime sentinel open exclusively
// while it sets its permissions (Windows reports EBUSY, EPERM or EACCES). Such a file is retried
// with backoff for up to this long, then the check fails; it is never skipped.
const BUSY_RETRY_MS = 5_000;
const BUSY_CODES = new Set(['EBUSY', 'EPERM', 'EACCES']);
const pause = ms => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

// Sentinel bytes by file identity (resolved path, size, mtime in ns, inode), so an unchanged
// runtime buffer can be reused only after rereading and comparing its complete
// current bytes. Metadata alone cannot prove freshness or continued readability.
// Cache only stable before/after identities; bound both entries and bytes.
const SOURCE_CACHE_ENTRIES = 8192;
const SOURCE_CACHE_BYTES = 64 * 1_048_576;
const sourceCache = new Map();
let sourceCacheBytes = 0;
function identity(path) {
  const stat = statSync(path, { bigint: true });
  return `${resolve(path)}\0${stat.size}\0${stat.mtimeNs}\0${stat.ino}`;
}
function cachedRead(path) {
  const before = identity(path);
  const bytes = readFileSync(path);
  const stable = identity(path) === before;
  const found = sourceCache.get(before);
  if (stable && found?.equals(bytes)) return found;
  if (stable && bytes.length <= SOURCE_CACHE_BYTES) {
    if (found) {
      sourceCache.delete(before);
      sourceCacheBytes -= found.length;
    }
    while (sourceCache.size >= SOURCE_CACHE_ENTRIES || sourceCacheBytes + bytes.length > SOURCE_CACHE_BYTES) {
      const oldest = sourceCache.keys().next().value;
      sourceCacheBytes -= sourceCache.get(oldest).length;
      sourceCache.delete(oldest);
    }
    sourceCache.set(before, bytes);
    sourceCacheBytes += bytes.length;
  }
  return bytes;
}
function readRuntimeSource(path) {
  const deadline = performance.now() + BUSY_RETRY_MS;
  for (let delay = 25; ; delay = Math.min(delay * 2, 1_000)) {
    try { return cachedRead(path); }
    catch (error) {
      if (!BUSY_CODES.has(error?.code) || performance.now() >= deadline) throw error;
      pause(Math.min(delay, Math.max(1, deadline - performance.now())));
    }
  }
}

/** @param {SentinelOptions} options */
function sentinelSources({ sentinels, sentinelDir, root }) {
  const projectRoot = root ? resolve(root) : resolve(dirname(sentinels), '..');
  // The registered list fails closed: a missing or invalid list, a glob outside the
  // project or a glob that matches no file is an error, never an empty population.
  const globs = JSON.parse(readFileSync(sentinels, 'utf8'));
  if (!Array.isArray(globs) || !globs.every(item => typeof item === 'string')) throw new Error('invalid sentinels list');
  const sourcePaths = globs.flatMap(glob => {
    const prefix = glob.split(/[?*]/, 1)[0];
    const base = resolve(projectRoot, prefix.endsWith('/') ? prefix : dirname(prefix));
    if (base !== projectRoot && !base.startsWith(projectRoot + sep)) throw new Error('sentinel glob outside the project');
    const pattern = globPattern(glob);
    const matched = filesUnder(base).filter(path => pattern.test(relative(projectRoot, path).split(sep).join('/')));
    if (!matched.length) throw new Error('sentinel glob matches no file');
    return matched;
  });
  // Runtime sentinels are written and removed by tests in other workers while this check runs.
  // filesUnder already skips one removed while the directory is listed; one removed between the
  // listing and its read is skipped the same way (it holds no credential any more). A registered
  // source that cannot be read still fails.
  const runtime = new Set(sentinelDir ? filesUnder(sentinelDir) : []);
  sourcePaths.push(...runtime);
  // Read every declared path, including duplicates, so unreadable sources
  // still fail validation. Recognition needs each exact credential only once;
  // source paths remain intact for independent artifact accounting.
  const distinct = new Map();
  for (const path of sourcePaths) {
    let bytes;
    try { bytes = runtime.has(path) ? readRuntimeSource(path) : readFileSync(path); }
    catch (error) {
      if (error?.code === 'ENOENT' && runtime.has(path)) continue;
      throw error;
    }
    if (bytes.length) distinct.set(bytes.toString('hex'), bytes);
    // PEM wrapping is presentation, not credential identity. Register its full
    // decoded body too, so rewrapping and every encoding of DER are covered.
    for (const match of bytes.toString('latin1').matchAll(/-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----([\s\S]*?)-----END \1-----/g)) {
      const body = match[2].replace(/\s/g, '');
      if (/^[A-Za-z0-9+/]+={0,2}$/.test(body)) {
        const der = Buffer.from(body, 'base64');
        if (der.length) distinct.set(der.toString('hex'), der);
      }
    }
    // A v2 macaroon sentinel also registers what is equivalent to it: everything after
    // the constant version byte, and its 32-byte signature (the field after the caveats'
    // end marker: 00 06 20), which with the identifier is the credential.
    if (bytes[0] === 0x02 && bytes.length > 35) {
      const rest = bytes.subarray(1);
      distinct.set(rest.toString('hex'), rest);
      const field = bytes.lastIndexOf(Buffer.from([0x00, 0x06, 0x20]));
      const signature = field >= 0 && field + 35 <= bytes.length ? bytes.subarray(field + 3, field + 35) : null;
      // A real HMAC-SHA256 signature has about 30 distinct byte values; a synthetic
      // placeholder (all zero bytes) would match ordinary data, so it is not registered.
      if (signature && new Set(signature).size >= SIGNATURE_MIN_DISTINCT_BYTES) distinct.set(signature.toString('hex'), signature);
    }
    // An NWC URI sentinel also registers its 32-byte connection secret, so the
    // secret is found in every encoding even when it leaks without the URI.
    for (const match of bytes.toString('latin1').matchAll(/(?:nostr\+walletconnect|nostrwalletconnect):[^\s"'<>]*?[?&]secret=([0-9a-f]{64})(?![0-9a-f])/gi)) {
      const secret = Buffer.from(match[1], 'hex');
      distinct.set(secret.toString('hex'), secret);
    }
  }
  return [...distinct.values()];
}

/** @param {SentinelOptions} options */
export function sentinelRedactor(options) {
  const sources = sentinelSources(options);
  const state = preparedSnapshot(sources).redactor;
  // Cache belongs to this source snapshot only. Bound both retained characters
  // and entry count; oversized strings still receive complete recognition.
  const cache = new Map();
  let retained = 0;
  return text => {
    if (cache.has(text)) return cache.get(text);
    const safe = safePath(text, sources, state);
    const size = text.length + safe.length;
    if (size <= 1_048_576) {
      while (cache.size >= 4096 || retained + size > 1_048_576) {
        const key = cache.keys().next().value;
        retained -= key.length + cache.get(key).length;
        cache.delete(key);
      }
      cache.set(text, safe);
      retained += size;
    }
    return safe;
  };
}

const DECLARATION_CACHE_ENTRIES = 8;
const DECLARATION_CACHE_BYTES = 1_048_576;
const declarationCache = new Map();
let declarationCacheBytes = 0;

function declaredOutputs(testTmp) {
  const declared = new Set(), declaredHashes = new Set();
  if (!testTmp || !existsSync(join(testTmp, 'declared-out.txt'))) return { declared, declaredHashes };
  // Read every current byte before consulting the cache. Removal, unreadable
  // files and same-size replacements must retain their ordinary behaviour.
  const bytes = readFileSync(join(testTmp, 'declared-out.txt'));
  const directory = resolve(testTmp);
  const cached = declarationCache.get(directory);
  if (cached?.bytes.equals(bytes)) {
    declarationCache.delete(directory);
    declarationCache.set(directory, cached);
    return cached.parsed;
  }
  if (cached) {
    declarationCache.delete(directory);
    declarationCacheBytes -= cached.size;
  }
  let cacheable = true;
  for (const line of bytes.toString('utf8').split(/\r?\n/)) {
    const entry = line.trim();
    // Drive-relative entries can depend on another drive's current directory.
    if (/^[a-z]:(?![\\/])/i.test(entry)) cacheable = false;
    if (/^sha256:[0-9a-f]{64}$/.test(entry)) declaredHashes.add(entry.slice(7));
    else if (entry) declared.add(resolve(testTmp, entry));
  }
  const parsed = { declared, declaredHashes };
  // Account for retained input bytes, decoded text possibly held by substrings,
  // resolved strings and collection entries. Large manifests still receive the
  // complete parser without being retained.
  const size = bytes.length * 3 + directory.length * 2 + 256 +
    [...declared, ...declaredHashes].reduce((total, value) => total + value.length * 2 + 96, 0);
  if (cacheable && size <= DECLARATION_CACHE_BYTES) {
    while (declarationCache.size >= DECLARATION_CACHE_ENTRIES || declarationCacheBytes + size > DECLARATION_CACHE_BYTES) {
      const oldest = declarationCache.keys().next().value;
      declarationCacheBytes -= declarationCache.get(oldest).size;
      declarationCache.delete(oldest);
    }
    declarationCache.set(directory, { bytes, parsed, size });
    declarationCacheBytes += size;
  }
  return parsed;
}

/**
 * @typedef {SentinelOptions & {
 *   paths?: string[], commandOutput?: string, testTmp?: string, evidenceDir?: string
 * }} LeakOptions
 */

/**
 * Inspect command output and candidate files against every distinct sentinel.
 * @param {LeakOptions} options Candidate paths default to an empty array;
 * testTmp supplies declared outputs; candidate artifact links fail closed.
 */
export function findLeaks({ sentinels, sentinelDir, paths = [], commandOutput = '', testTmp, root, evidenceDir }) {
  const sources = sentinelSources({ sentinels, sentinelDir, root });
  if (!sources.length) throw new Error('no nonempty sentinel registered');
  const snapshot = preparedSnapshot(sources);
  const { states, possibleLeak, redactor } = snapshot;
  let literalBytes;
  const literalWorkspace = () => literalBytes ??= Buffer.allocUnsafe(SCAN_CHUNK_BYTES);
  const hit = (location, encoding) => ({ path: safePath(location, sources, redactor), encoding });

  // Reject links before reading any artifact, including the output manifest.
  // Source enumeration keeps its separate, existing traversal policy.
  // A named candidate path must exist: a mistyped or removed path is an error, not a pass.
  for (const scanPath of paths) lstatSync(scanPath);
  const candidates = paths.flatMap(scanPath => filesUnder(scanPath, true).map(path => ({
    path, name: lstatSync(scanPath).isDirectory() ? relative(scanPath, path) : basename(path),
  })));
  // A declared output is named by its path, or by `sha256:<hex>` of its resolved path when the
  // path itself holds a credential (a test of path redaction), so the manifest never carries it.
  const { declared, declaredHashes } = declaredOutputs(testTmp);
  const pathHash = path => createHash('sha256').update(path, 'utf8').digest('hex');
  const included = candidates.filter(({ path }) => {
    const absolute = resolve(path);
    const fromEvidence = evidenceDir ? relative(resolve(evidenceDir), absolute) : null;
    const inEvidence = fromEvidence !== null && !isAbsolute(fromEvidence) &&
      fromEvidence !== '..' && !fromEvidence.startsWith(`..${sep}`);
    return inEvidence || (!declared.has(absolute) && !declaredHashes.has(pathHash(absolute)) &&
      true);
  });
  const overlap = Math.max(256, ...states.map(state => state.source.length * 32));
  const syntax = snapshot.syntax;
  const inspect = (location, data, name = '') => {
    // Artifact decoding is independent of the credential population. Prepare
    // it once, while still comparing every exact registered credential.
    const input = preparedData(data, possibleLeak.minimumLength, snapshot.base64MayMatch, literalWorkspace);
    const nameData = name ? Buffer.from(name) : null;
    const nameInput = nameData ? preparedData(nameData, possibleLeak.minimumLength, snapshot.base64MayMatch, literalWorkspace) : null;
    if (!possibleLeak(input) && (!nameInput || !possibleLeak(nameInput))) return null;
    const lowerName = name.toLowerCase();
    for (const state of states) {
      const { source } = state;
      for (const { encoding, value, lower, bytes } of state.variants) {
        if (name &&
            (encoding.startsWith('hex-') ? lowerName.includes(lower) : name.includes(value))) {
          return hit(location, encoding);
        }
        if (data.includes(bytes)) return hit(location, encoding);
      }
      const alternateName = nameData && alternateEncoding(nameData, source, state, nameInput);
      if (alternateName) return hit(location, alternateName);
      if (data.includes(source)) return hit(location, 'raw-bytes');
      const alternate = alternateEncoding(data, source, state, input);
      if (alternate) return hit(location, alternate);
    }
    return null;
  };
  const scan = (location, chunks, name = '') => {
    let previous = Buffer.alloc(0);
    let suffixes = [];
    let pendingTokens = [];
    const cacheLimit = 4 * 1_048_576;
    const stateSize = () => previous.length + suffixes.reduce((size, bytes) => size + bytes.length, 0) +
      pendingTokens.reduce((size, text) => size + text.length * 2, 0);
    // Names are scanned even for empty files, and never combined with content.
    const named = inspect(location, Buffer.alloc(0), name);
    if (named) return named;
    for (const chunk of chunks) {
      // The complete incoming recognizer state and freshly read chunk identify
      // a deterministic transition within this exact source snapshot. Names
      // are checked separately; hashes only index complete byte comparisons.
      let key = null, before = null;
      if (stateSize() <= cacheLimit / 2) {
        before = serialize({ previous, suffixes, pendingTokens });
        key = createHash('sha256').update(before).update(chunk).digest('hex');
        const cached = snapshot.cleanInputs.get(key);
        if (cached?.before.equals(before) && cached.chunk.equals(chunk)) {
          // Node.js/node lib/v8.js serialization preserves byte buffers and
          // every string code unit, including unmatched UTF-16 surrogates.
          ({ previous, suffixes, pendingTokens } = deserialize(inflateSync(cached.state,
            { maxOutputLength: cacheLimit })));
          snapshot.cleanInputs.delete(key);
          snapshot.cleanInputs.set(key, cached);
          continue;
        }
      }
      const data = Buffer.concat([previous, chunk]);
      if (syntax(data)) {
        const found = inspect(location, data);
        if (found) return found;
      }
      // Keep each character encoding and escape depth independent. Joining the
      // views before retaining a suffix would discard an earlier view's tail.
      const utf16 = Buffer.from(chunk.subarray(0, chunk.length - chunk.length % 2));
      const texts = [chunk.toString('utf8'), utf16.toString('utf16le'), utf16.swap16().toString('utf16le')];
      let channel = 0;
      let textChannel = 0;
      const normalizedTexts = new Map();
      const checked = new Map();
      const tokenViews = new Map();
      for (const text of texts.flatMap(text => recoveredText(text, false))) {
        let views = normalizedTexts.get(text);
        if (!views) {
          const compact = text.replace(/[\s\u200b-\u200d\u2060\ufeff]/g, '');
          const joined = text.replace(/(["'`])(?=([\s\u200b-\u200d\u2060\ufeff]*))\2[,+]?(?=([\s\u200b-\u200d\u2060\ufeff]*))\3\1/g, '')
          .replace(/[\s\u200b-\u200d\u2060\ufeff]/g, '');
          // Preserve hex-group boundaries while collapsing an arbitrarily long
          // recognized separator. The full odd-group parser still decides hits.
          const separated = text.replace(/(?:[^0-9A-Za-z\\]|\\[trnfv]|\\u(?:0009|000[a-d]|0020))+/gi, ':');
          views = [compact, joined, separated];
          normalizedTexts.set(text, views);
        }
        const pending = pendingTokens[textChannel] ?? '';
        let tokens = tokenViews.get(text);
        if (!tokens || tokens.before !== pending) {
          const lines = (pending + text).split('\n');
          const incomplete = lines.pop();
          tokens = { before: pending, value: lines.map(lastToken).join(''),
            after: lastToken(incomplete).slice(-overlap) + (/\s$/.test(incomplete) ? ' ' : '') };
          tokenViews.set(text, tokens);
        }
        pendingTokens[textChannel++] = tokens.after;
        // Emit a line's tail only after its newline. A read boundary inside a
        // timestamp/prefix must never inject that unfinished prefix into a key.
        for (const view of [views[0], views[1], tokens.value, views[2]]) {
          const before = suffixes[channel] ?? Buffer.alloc(0);
          const last = checked.get(view);
          if (last && last.before.equals(before)) {
            suffixes[channel++] = last.after;
            continue;
          }
          const normalized = Buffer.concat([before, Buffer.from(view.startsWith(':') && before.at(-1) === 58 ? view.slice(1) : view)]);
          suffixes[channel++] = Buffer.from(normalized.subarray(-overlap));
          checked.set(view, { before, after: suffixes[channel - 1] });
          if (syntax(normalized)) {
            const found = inspect(location, normalized);
            if (found) return found;
          }
        }
      }
      previous = Buffer.from(data.subarray(-overlap));
      if (key && stateSize() <= cacheLimit / 2) {
        // Cache only clean transitions and bounded states. Copy the complete
        // chunk because file reads reuse their buffer. Recurring log content
        // can then reuse work without trusting file metadata or a digest alone.
        if (before.length + chunk.length + 256 <= cacheLimit) {
          const encoded = serialize({ previous, suffixes, pendingTokens });
          if (encoded.length <= cacheLimit) {
            const state = deflateSync(encoded);
            const size = before.length + chunk.length + state.length + 256;
            if (size <= cacheLimit) {
              const replaced = snapshot.cleanInputs.get(key);
              if (replaced) {
                snapshot.cleanInputs.delete(key);
                snapshot.cleanInputBytes -= replaced.size;
              }
              while (snapshot.cleanInputs.size >= 256 || snapshot.cleanInputBytes + size > cacheLimit) {
                const oldest = snapshot.cleanInputs.keys().next().value;
                snapshot.cleanInputBytes -= snapshot.cleanInputs.get(oldest).size;
                snapshot.cleanInputs.delete(oldest);
              }
              snapshot.cleanInputs.set(key, { before, chunk: Buffer.from(chunk), state, size });
              snapshot.cleanInputBytes += size;
            }
          }
        }
      }
    }
    for (let index = 0; index < pendingTokens.length; index++) {
      const token = pendingTokens[index].trimEnd();
      if (!token) continue;
      const normalized = Buffer.concat([suffixes[index * 4 + 2] ?? Buffer.alloc(0), Buffer.from(token)]);
      if (syntax(normalized)) {
        const found = inspect(location, normalized);
        if (found) return found;
      }
    }
    return null;
  };
  function* bufferChunks(data) {
    for (let at = 0; at < data.length; at += SCAN_CHUNK_BYTES) yield data.subarray(at, at + SCAN_CHUNK_BYTES);
  }
  function* fileChunks(path) {
    const fd = openSync(path, 'r');
    try {
      const bytes = Buffer.allocUnsafe(SCAN_CHUNK_BYTES);
      for (let length; (length = readSync(fd, bytes, 0, bytes.length, null)) !== 0;) yield bytes.subarray(0, length);
    } finally { closeSync(fd); }
  }
  function* outputChunks() {
    for (let at = 0; at < commandOutput.length;) {
      let end = Math.min(commandOutput.length, at + 128 * 1024);
      const code = commandOutput.charCodeAt(end - 1);
      if (end < commandOutput.length && code >= 0xd800 && code <= 0xdbff) end--;
      yield Buffer.from(commandOutput.slice(at, end));
      at = end;
    }
  }
  const output = scan('command output', outputChunks());
  if (output) return output;
  for (const { path, name } of included) {
    // Include every tar header and member byte; archive names are content too.
    // Both compressed-input reads and character decoding remain bounded.
    const chunks = /\.(?:tgz|gz)$/i.test(path)
      ? bufferChunks(inflatedArtifact(path))
      : fileChunks(path);
    const found = scan(path, chunks, name);
    if (found) return found;
  }
  return null;
}

function main(args) {
  if (args[0] !== '--sentinels' || !args[1]) return 2;
  const sentinels = resolve(args[1]);
  let index = 2;
  let sentinelDir;
  if (args[index] === '--sentinel-dir') {
    if (!args[index + 1]) return 2;
    sentinelDir = resolve(args[index + 1]); index += 2;
  }
  if (index >= args.length || args.slice(index).some(arg => arg.startsWith('--'))) return 2;
  try {
    const hit = findLeaks({ sentinels, sentinelDir, paths: args.slice(index).map(path => resolve(path)),
      testTmp: process.env.FLUXWARDEN_TEST_TMP });
    if (hit) { process.stderr.write(`${hit.path}: ${hit.encoding}\n`); return 1; }
    return 0;
  } catch {
    process.stderr.write('leak-check failed\n');
    return 1;
  }
}

if (isMainThread && process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
