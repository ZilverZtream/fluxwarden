import { createHash } from 'node:crypto';

let extract: (secret: Secret) => Uint8Array;
let representations: (secret: Secret) => { marker: string; text: string[]; hex: string[] };

function base64Forms(bytes: Buffer): string[] {
  const base64 = bytes.toString('base64');
  const url = base64.replace(/\+/g, '-').replace(/\//g, '_');
  return [base64, base64.replace(/=+$/, ''), url, url.replace(/=+$/, '')];
}

/** The DER bytes inside a PEM document, whatever its line endings. */
function pemBody(bytes: Buffer): Buffer | undefined {
  const match = /-----BEGIN ([A-Z0-9 ]+)-----\r?\n([\s\S]*?)\r?\n-----END \1-----/.exec(bytes.toString('utf8'));
  const body = (match?.[2] ?? '').replace(/\s+/g, '');
  if (!body || !/^[A-Za-z0-9+/]+={0,2}$/.test(body)) return undefined;
  const der = Buffer.from(body, 'base64');
  return der.byteLength ? der : undefined;
}

const isSpace = (code: number): boolean => code === 0x20 || (code >= 0x09 && code <= 0x0d);
const hexValue = (code: number): number => code >= 0x30 && code <= 0x39 ? code - 0x30
  : code >= 0x61 && code <= 0x66 ? code - 0x57 : code >= 0x41 && code <= 0x46 ? code - 0x37 : -1;

/**
 * How output text is read when looking for credentials. Each view is one complete
 * decoding: `plain` reads the characters as written, `json` applies the JSON string
 * escape grammar (RFC 8259 section 7: \" \\ \/ \b \f \n \r \t \uXXXX), `percent` decodes
 * %XX in either case (RFC 3986 section 2.1), and `form` also reads "+" as a space
 * (application/x-www-form-urlencoded). A credential is found in whichever view denotes it.
 */
type View = 'plain' | 'json' | 'percent' | 'form';

const JSON_ESCAPES: Record<number, number | undefined> = { 0x22: 0x22, 0x5c: 0x5c, 0x2f: 0x2f, 0x62: 0x08, 0x66: 0x0c, 0x6e: 0x0a, 0x72: 0x0d, 0x74: 0x09 };

/**
 * Calls `visit` with each code unit `text` denotes in `view` and the source range it came
 * from. Whitespace is layout in every view (indentation, CRLF, any wrap column, MIME) and
 * is skipped after decoding, exactly as it is removed from the credential forms.
 */
function decode(text: string, view: View, visit: (code: number, start: number, end: number) => void): void {
  const length = text.length;
  for (let index = 0; index < length;) {
    let code = text.charCodeAt(index), width = 1;
    if (view === 'json' && code === 0x5c && index + 1 < length) {
      const escape = text.charCodeAt(index + 1);
      const simple = JSON_ESCAPES[escape];
      if (simple !== undefined) { code = simple; width = 2; }
      else if (escape === 0x75 && index + 5 < length) {
        let value = 0;
        for (let offset = 2; offset < 6 && value >= 0; offset++) {
          const digit = hexValue(text.charCodeAt(index + offset));
          value = digit < 0 ? -1 : value * 16 + digit;
        }
        // A surrogate pair arrives as two escapes and is denoted as the same two code units.
        if (value >= 0) { code = value; width = 6; }
      }
    } else if ((view === 'percent' || view === 'form') && code === 0x25 && index + 2 < length) {
      const high = hexValue(text.charCodeAt(index + 1)), low = hexValue(text.charCodeAt(index + 2));
      if (high >= 0 && low >= 0) { code = high * 16 + low; width = 3; }
    } else if (view === 'form' && code === 0x2b) code = 0x20;
    if (!isSpace(code)) visit(code, index, index + width);
    index += width;
  }
}

/** A credential form as matched: whitespace removed, hex folded to lowercase without colons. */
function canonical(text: string, hex: boolean): string {
  let out = '';
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    if (isSpace(code) || (hex && code === 0x3a)) continue;
    out += String.fromCharCode(hex && code >= 0x41 && code <= 0x5a ? code + 32 : code);
  }
  return out;
}

/**
 * Aho-Corasick automaton (Aho and Corasick, CACM 18(6), 1975) over UTF-16 code units:
 * one pass reports, at every position, the longest pattern ending there, so the cost is
 * linear in the text whatever the number or overlap of patterns.
 */
class Automaton {
  readonly maxLength: number;
  readonly #root = new Int32Array(65536);
  readonly #nodes: Int32Array;
  readonly #codes: Uint16Array;
  readonly #targets: Int32Array;
  readonly #mask: number;
  readonly #fail: Int32Array;
  readonly length: Int32Array;
  readonly tag: Int32Array;
  readonly prefix: Int32Array;

  constructor(patterns: readonly { text: string; tag: number }[]) {
    const children: Map<number, number>[] = [new Map<number, number>()];
    const own: number[] = [0], ownTag: number[] = [-1], depths: number[] = [0];
    let edges = 0;
    for (const { text, tag } of patterns) {
      let node = 0;
      for (let index = 0; index < text.length; index++) {
        const code = text.charCodeAt(index);
        const current = children[node] ?? new Map<number, number>();
        let next = current.get(code);
        if (next === undefined) {
          next = children.length;
          current.set(code, next);
          children.push(new Map<number, number>());
          own.push(0); ownTag.push(-1);
          depths.push(index + 1);
          edges++;
        }
        node = next;
      }
      if (text.length > (own[node] ?? 0)) { own[node] = text.length; ownTag[node] = tag; }
    }
    const count = children.length;
    this.maxLength = Math.max(1, ...patterns.map(pattern => pattern.text.length));
    let capacity = 2;
    while (capacity < edges * 2) capacity *= 2;
    this.#mask = capacity - 1;
    this.#nodes = new Int32Array(capacity).fill(-1);
    this.#codes = new Uint16Array(capacity);
    this.#targets = new Int32Array(capacity);
    this.#fail = new Int32Array(count);
    this.length = new Int32Array(count);
    this.tag = new Int32Array(count).fill(-1);
    this.prefix = Int32Array.from(children.map((edges, index) => edges.size > 0 ? depths[index] ?? 0 : 0));
    const queue: number[] = [];
    for (const [code, child] of children[0] ?? []) { this.#root[code] = child; queue.push(child); this.length[child] = own[child] ?? 0; this.tag[child] = ownTag[child] ?? -1; }
    for (let head = 0; head < queue.length; head++) {
      const node = queue[head] ?? 0;
      for (const [code, child] of children[node] ?? []) {
        this.#insert(node, code, child);
        let fallback = this.#fail[node] ?? 0;
        while (fallback !== 0 && !children[fallback]?.has(code)) fallback = this.#fail[fallback] ?? 0;
        const target = fallback === 0 ? this.#root[code] ?? 0 : children[fallback]?.get(code) ?? 0;
        this.#fail[child] = target === child ? 0 : target;
        this.prefix[child] = Math.max(this.prefix[child] ?? 0, this.prefix[this.#fail[child] ?? 0] ?? 0);
        const inherited = this.length[this.#fail[child] ?? 0] ?? 0;
        if ((own[child] ?? 0) >= inherited) { this.length[child] = own[child] ?? 0; this.tag[child] = ownTag[child] ?? -1; }
        else { this.length[child] = inherited; this.tag[child] = this.tag[this.#fail[child] ?? 0] ?? -1; }
        queue.push(child);
      }
    }
  }

  #slot(node: number, code: number): number {
    return ((Math.imul(node, 0x9e3779b1) ^ Math.imul(code, 0x85ebca6b)) >>> 0) & this.#mask;
  }

  #insert(node: number, code: number, target: number): void {
    let slot = this.#slot(node, code);
    while (this.#nodes[slot] !== -1) slot = (slot + 1) & this.#mask;
    this.#nodes[slot] = node; this.#codes[slot] = code; this.#targets[slot] = target;
  }

  next(state: number, code: number): number {
    for (;;) {
      if (state === 0) return this.#root[code] ?? 0;
      for (let slot = this.#slot(state, code); this.#nodes[slot] !== -1; slot = (slot + 1) & this.#mask) {
        if (this.#nodes[slot] === state && this.#codes[slot] === code) return this.#targets[slot] ?? 0;
      }
      state = this.#fail[state] ?? 0;
    }
  }
}

/** Replaces every registered credential in text that continues an already emitted prefix. */
export interface Redactor {
  readonly overlap: number;
  redact(text: string, emittedPrefix?: string): string;
  /** Start of an unresolved registered-value suffix, or text.length when the text is decidable. */
  pendingStart(text: string): number;
}

/** Source spellings of one whitespace character: literal, JSON escape, %XX, form "+", CRLF. */
function spellings(code: number, plus: boolean): string[] {
  const percent = `%${code.toString(16).padStart(2, '0')}`;
  const escape = ({ 0x0a: '\\n', 0x0d: '\\r', 0x09: '\\t', 0x0c: '\\f' } as Record<number, string | undefined>)[code];
  return [
    ...(code === 0x0a ? ['%0d%0a', '\\r\\n', '\r\n'] : []),
    percent, ...(escape ? [escape] : []), String.fromCharCode(code), ...(plus && code === 0x20 ? ['+'] : []),
  ];
}

/**
 * A credential that begins or ends with whitespace (a PEM document's final line break, a
 * leading space byte) still owns that whitespace in the source; it is skipped while
 * matching, so the matched range grows over exactly those characters, however spelled.
 */
function grow(source: string, index: number, layout: string, forward: boolean, plus: boolean): number {
  const grown = extend(source, index, layout, forward, plus);
  // A line break followed directly by a word starts the next line of a document (a YAML
  // key after a block scalar); it stays with that line.
  return forward && grown !== index && /\w/.test(source.charAt(grown)) ? index : grown;
}

function extend(source: string, index: number, layout: string, forward: boolean, plus: boolean): number {
  const codes = Array.from({ length: layout.length }, (_, position) => layout.charCodeAt(position));
  for (const code of forward ? codes : codes.reverse()) {
    if (code === 0x0d && layout.includes('\r\n')) continue;
    const spelling = spellings(code, plus).find(candidate => (forward
      ? source.slice(index, index + candidate.length) : source.slice(index - candidate.length, index)).toLowerCase() === candidate);
    if (spelling === undefined) break;
    index += forward ? spelling.length : -spelling.length;
  }
  return index;
}

function redactor(secrets: readonly Secret[]): Redactor {
  const markers: string[] = [];
  const textPatterns: { text: string; tag: number }[] = [], hexPatterns: { text: string; tag: number }[] = [];
  // Per text pattern: its marker, and the whitespace its form begins and ends with.
  const edges: { marker: number; lead: string; trail: string }[] = [];
  for (const secret of secrets) {
    const forms = representations(secret);
    const marker = markers.push(forms.marker) - 1;
    const seen = new Map<string, number>();
    for (const value of forms.text) {
      const form = canonical(value, false);
      if (!form) continue;
      const lead = /^\s*/.exec(value)?.[0] ?? '', trail = /\s*$/.exec(value)?.[0] ?? '';
      const known = seen.get(form);
      const edge = known === undefined ? undefined : edges[known];
      if (edge) {
        if (lead.length > edge.lead.length) edge.lead = lead;
        if (trail.length > edge.trail.length) edge.trail = trail;
        continue;
      }
      seen.set(form, edges.push({ marker, lead, trail }) - 1);
      textPatterns.push({ text: form, tag: edges.length - 1 });
    }
    for (const form of new Set(forms.hex.map(value => canonical(value, true)))) if (form) hexPatterns.push({ text: form, tag: marker });
  }
  if (!markers.length) return { overlap: 0, redact: text => text, pendingStart: text => text.length };
  const text = new Automaton(textPatterns), hex = new Automaton(hexPatterns);
  const textStarts = new Int32Array(text.maxLength), hexStarts = new Int32Array(hex.maxLength);
  function scan(source: string, view: View, found?: number[]): number {
    let textState = 0, hexState = 0, textCount = 0, hexCount = 0;
    const plus = view === 'form' ? 1 : 0;
    decode(source, view, (code, start, end) => {
      textState = text.next(textState, code);
      textStarts[textCount++ % text.maxLength] = start;
      const textLength = text.length[textState] ?? 0;
      if (textLength) found?.push(textStarts[(textCount - textLength) % text.maxLength] ?? start, end, text.tag[textState] ?? 0, plus);
      // Hex is matched case-insensitively, also when bytes are separated by colons.
      if (code === 0x3a) return;
      hexState = hex.next(hexState, code >= 0x41 && code <= 0x5a ? code + 32 : code);
      hexStarts[hexCount++ % hex.maxLength] = start;
      const hexLength = hex.length[hexState] ?? 0;
      if (hexLength) found?.push(hexStarts[(hexCount - hexLength) % hex.maxLength] ?? start, end, -1 - (hex.tag[hexState] ?? 0), 0);
    });
    const textPrefix = text.prefix[textState] ?? 0, hexPrefix = hex.prefix[hexState] ?? 0;
    return Math.min(textPrefix === 0 ? source.length : textStarts[(textCount - textPrefix) % text.maxLength] ?? source.length,
      hexPrefix === 0 ? source.length : hexStarts[(hexCount - hexPrefix) % hex.maxLength] ?? source.length);
  }
  return {
    // Layout may separate the denoted characters arbitrarily; this bound covers escapes
    // (up to six source characters each) with line breaks and indentation between them.
    overlap: 8 * Math.max(text.maxLength, hex.maxLength) + 256,
    pendingStart(source) {
      let start = scan(source, 'plain');
      for (const view of ['json', 'percent', 'form'] as const) {
        if (view === 'json' ? !source.includes('\\') : !source.includes('%') && (view !== 'form' || !source.includes('+'))) continue;
        // An incomplete escape may become a credential character in the next write. Keep it with any preceding
        // undecidable prefix, without interpreting a partial escape as ordinary punctuation.
        const tail = view === 'json' ? /\\(?:u[0-9a-fA-F]{0,3})?$/.exec(source) : /%[0-9a-fA-F]?$/.exec(source);
        const end = tail?.index ?? source.length;
        start = Math.min(start, scan(source.slice(0, end), view), end);
      }
      return start;
    },
    redact(source, emittedPrefix = '') {
      const whole = emittedPrefix + source, boundary = emittedPrefix.length;
      const found: number[] = [];
      scan(whole, 'plain', found);
      // The other views can only differ from the plain one where their escapes occur.
      if (whole.includes('\\')) scan(whole, 'json', found);
      if (whole.includes('%')) scan(whole, 'percent', found);
      if (whole.includes('+')) scan(whole, 'form', found);
      if (!found.length) return source;
      const ranges: [number, number, number][] = [];
      for (let index = 0; index < found.length; index += 4) {
        const [start = 0, end = 0, code = 0, plus = 0] = found.slice(index, index + 4);
        const edge = code >= 0 ? edges[code] : undefined;
        ranges.push(edge
          ? [grow(whole, start, edge.lead, false, plus === 1), grow(whole, end, edge.trail, true, plus === 1), edge.marker]
          : [start, end, -1 - code]);
      }
      ranges.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
      let out = '', cursor = boundary;
      let current: [number, number, number] | undefined;
      const flush = (range: [number, number, number]): void => {
        // Emitted text cannot be retracted: only the continuation of a credential that
        // began in it is replaced.
        if (range[1] <= boundary) return;
        out += whole.slice(cursor, Math.max(range[0], boundary)) + (markers[range[2]] ?? '');
        cursor = range[1];
      };
      for (const range of ranges) {
        if (current && range[0] < current[1]) current[1] = Math.max(current[1], range[1]);
        else { if (current) flush(current); current = range; }
      }
      if (current) flush(current);
      return out + whole.slice(cursor);
    },
  };
}

/** Credential storage with safe formatting and redaction, never enumerable bytes. */
export class Secret {
  readonly #bytes: Buffer;
  readonly #marker: string;
  #redactor: Redactor | undefined;
  readonly #pattern: RegExp;
  readonly #folded: string[];
  readonly #binary: Buffer[];

  static {
    extract = secret => new Uint8Array(secret.#bytes);
    representations = secret => {
      const der = pemBody(secret.#bytes);
      const sequences = der ? [secret.#bytes, der] : [secret.#bytes];
      const hex = secret.#bytes.toString('hex');
      return {
        marker: secret.#marker,
        // Raw text and base64/base64url of the bytes and of a PEM key's DER body, and
        // base64 of the hex text in either case.
        text: [...sequences.flatMap(bytes => [bytes.toString('utf8'), bytes.toString('latin1'), ...base64Forms(bytes)]),
          ...[hex, hex.toUpperCase()].flatMap(value => base64Forms(Buffer.from(value)))],
        hex: sequences.map(bytes => bytes.toString('hex')),
      };
    };
  }

  /** One redactor for several credentials; each keeps its own marker. */
  static redactor(secrets: readonly Secret[]): Redactor { return redactor(secrets); }

  constructor(bytes: Uint8Array) {
    if (!(bytes instanceof Uint8Array)) throw new TypeError('secret: credential bytes must be a Uint8Array');
    if (bytes.byteLength === 0) throw new Error('secret: empty credential');
    // A dedicated allocation: pooled buffers share one ArrayBuffer with unrelated callers.
    this.#bytes = Buffer.allocUnsafeSlow(bytes.byteLength);
    this.#bytes.set(bytes);
    this.#marker = `[redacted fp:${createHash('sha256').update(this.#bytes).digest('hex').slice(0, 16)}]`;
    const hex = this.#bytes.toString('hex');
    const base64 = this.#bytes.toString('base64');
    const forms = new Set([
      this.#bytes.toString('utf8'), this.#bytes.toString('latin1'),
      base64, base64.replace(/=+$/, ''), this.#bytes.toString('base64url'),
      base64.replace(/\+/g, '-').replace(/\//g, '_'),
      Buffer.from(hex).toString('base64'), Buffer.from(hex.toUpperCase()).toString('base64'),
    ]);
    // Literal escaping follows lodash/lodash, escapeRegExp.js; longest alternatives
    // precede their unpadded forms so a credential's padding cannot escape redaction.
    const literal = [...forms].filter(Boolean).sort((a, b) => b.length - a.length)
      .map(value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    const insensitiveHex = hex.replace(/[a-f]/g, letter => `[${letter}${letter.toUpperCase()}]`);
    const percent = [...this.#bytes].map(byte => `%${byte.toString(16).padStart(2, '0')}`)
      .join('').replace(/[a-f]/g, letter => `[${letter}${letter.toUpperCase()}]`);
    this.#pattern = new RegExp([...literal, insensitiveHex, percent].join('|'), 'g');
    const der = pemBody(this.#bytes);
    const sequences = der ? [this.#bytes, der] : [this.#bytes];
    this.#folded = [...new Set(sequences.flatMap(bytes => [
      bytes.toString('base64').replace(/=+$/, ''), bytes.toString('base64url'), base32Text(bytes),
    ]).map(value => value.toLowerCase()))].filter(Boolean);
    this.#binary = sequences.flatMap(bytes => {
      const utf16le = Buffer.from(bytes.toString('latin1'), 'utf16le');
      return [Buffer.from(bytes), utf16le, Buffer.from(utf16le).swap16()];
    });
  }

  toString(): string { return this.#marker; }
  /** A one-way digest of the credential bytes for verification evidence. */
  get fingerprint(): string { return createHash('sha256').update(this.#bytes).digest('hex'); }
  toJSON(): string { return this.#marker; }
  [Symbol.for('nodejs.util.inspect.custom')](): string { return this.#marker; }

  /** A one-way operation: callers never receive bytes or credential encodings. */
  get redactionOverlap(): number { return this.#own().overlap; }

  /**
   * Whether `data` holds this credential: in a form the redactor rewrites, also after JSON escapes are decoded
   * or whitespace is removed, as case-folded base64 or base32, or as raw or UTF-16 bytes. A leak check, never
   * a way to read the credential.
   */
  foundIn(data: Uint8Array): boolean {
    const bytes = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    if (this.#binary.some(form => bytes.includes(form))) return true;
    const text = bytes.toString('utf8');
    const views = [text, unescapeJson(text)].flatMap(view => [view, view.replace(/\s+/g, '')]);
    if (views.some(view => view.search(this.#pattern) !== -1)) return true;
    if (this.#own().redact(text) !== text) return true;
    return views.some(view => {
      const lower = view.toLowerCase();
      return this.#folded.some(form => lower.includes(form));
    });
  }

  redact(text: string, emittedPrefix = ''): string { return this.#own().redact(text, emittedPrefix); }

  #own(): Redactor {
    this.#redactor ??= redactor([this]);
    return this.#redactor;
  }
}

/** RFC 4648 base32 without padding. */
function base32Text(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let accumulator = 0;
  let bits = 0;
  let text = '';
  for (const byte of bytes) {
    accumulator = ((accumulator << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      text += alphabet.charAt((accumulator >>> bits) & 31);
    }
  }
  if (bits > 0) text += alphabet.charAt((accumulator << (5 - bits)) & 31);
  return text;
}

/** JSON string escapes decoded, so an escaped credential reads as itself. */
function unescapeJson(text: string): string {
  return text.replace(/\\(?:u([0-9a-fA-F]{4})|(["\\/bfnrt]))/g, (_match: string, unicode: string | undefined, simple: string | undefined) => {
    if (unicode !== undefined) return String.fromCharCode(parseInt(unicode, 16));
    return ({ b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' } as Record<string, string>)[simple ?? ''] ?? simple ?? '';
  });
}

/** Internal capability; imports are confined to adapters and the approval signer. */
export function revealSecret(secret: Secret): Uint8Array { return extract(secret); }
