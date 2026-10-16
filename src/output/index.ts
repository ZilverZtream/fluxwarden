// All user-visible writes pass through this module.
import type { Writable } from 'node:stream';
import { Secret } from '../core/secret.js';

export type Stream = 'stdout' | 'stderr';

export interface Output {
  /** Writes `text` to one stream; `done` runs once the write is handed off or has failed. */
  write(stream: Stream, text: string, done?: () => void): void;
  /** True once a write to `stream` reached the stream (the process's document or report is out). */
  wrote(stream: Stream): boolean;
}

export interface ErrorBody {
  readonly code: number;
  readonly step: string | null;
  readonly message: string;
}

/** The `--json` document. `ok` is false exactly when `error` is not null. */
export interface Envelope {
  readonly schema: 1;
  readonly command: string | null;
  readonly ok: boolean;
  readonly warnings: readonly string[];
  readonly result: Readonly<Record<string, unknown>> | null;
  readonly error: ErrorBody | null;
}

export function envelope(
  command: string | null, result: Readonly<Record<string, unknown>> | null, error: ErrorBody | null, warnings: readonly string[] = [],
): Envelope {
  return { schema: 1, command, ok: error === null, warnings: [...warnings], result: error === null ? result : null, error };
}

/**
 * A node-supplied string (alias, state, error text) for a terminal: at most `maxBytes` UTF-8 bytes of it, every
 * control, line-break and bidirectional character escaped (SECURITY.md §5), so it can never start a line or
 * restyle the terminal.
 */
export function nodeText(value: string, maxBytes = 256): string {
  let text = value;
  if (Buffer.byteLength(text, 'utf8') > maxBytes) {
    let end = Math.min(text.length, maxBytes);
    while (end > 0 && Buffer.byteLength(text.slice(0, end), 'utf8') > maxBytes) end -= 1;
    if (end > 0 && /[\ud800-\udbff]/.test(text.charAt(end - 1))) end -= 1;
    text = `${text.slice(0, end)}...`;
  }
  return escapeText(text, false);
}

/** One JSON document on one line, newline-terminated. */
export function renderEnvelope(doc: Envelope): string {
  return `${jsonText(doc, redactPatterns)}\n`;
}

/** Text for a terminal: control and bidirectional characters become printable escapes, newlines stay. */
export function terminalText(text: string): string {
  return escapeText(redactPatterns(text), true);
}

export interface RenderOutput {
  redact(text: string): string;
  write(text: string, options?: { stream?: Stream; exitCode?: number }): Promise<void>;
  /** Drains one complete document on its selected transport; the writer remains usable. */
  json(value: unknown, options?: { exitCode?: number }): Promise<void>;
  /** Completes finite output, draining unmatched ordinary fragments without ending either transport. */
  finalize(): Promise<void>;
}

/** UTF-8 rendering over injected transports, including pipes with closed readers. */
export function createOutput(options: { stdout: Writable; stderr: Writable; secrets: readonly Secret[] }): RenderOutput {
  const secrets = Secret.redactor(options.secrets);
  const overlap = Math.max(PAYMENT_REQUEST_CONTEXT, secrets.overlap);
  type Transport = { context: string; suffix: string; held: string; pending: Promise<void> };
  const streams = new Map<Writable, Transport>();
  let finalized: Promise<void> | undefined;
  const redact = (text: string): string => {
    text = secrets.redact(text);
    return redactPatterns(text);
  };
  // Writable emits an error after delivering the write callback error. Keep a listener
  // for the lifetime of the injected transport so a closed pipe cannot crash its owner.
  const closed = new WeakSet<Writable>();
  for (const target of new Set([options.stdout, options.stderr])) {
    target.on('error', () => { closed.add(target); });
  }
  const emit = async (target: Writable, transport: Transport, credentialFree: string): Promise<void> => {
    const rendered = redactPatterns(credentialFree, transport.suffix);
    for (const [piece, chunk] of utf8Chunks(rendered, value => escapeText(value, true))) {
      if (closed.has(target) || target.destroyed || !target.writable) return;
      // Node.js nodejs/node, lib/internal/streams/writable.js: a completed write
      // callback releases the next write, bounding pending data under backpressure.
      const accepted = await new Promise<boolean>((resolve, reject) => {
        try {
          target.write(chunk, error => {
            if (!error) { resolve(true); return; }
            closed.add(target);
            if (pipeClosed(error)) resolve(false);
            else reject(new Error('output: transport failed'));
          });
        } catch (error) {
          closed.add(target);
          if (pipeClosed(error)) resolve(false);
          else reject(new Error('output: transport failed'));
        }
      });
      if (!accepted) return;
      // Only actual emitted text becomes continuation context, taken before escaping so a
      // credential that contains control characters is still recognised across writes.
      // The bound depends on credential and invoice sizes, not on the output calls.
      transport.suffix = (transport.suffix + piece).slice(-overlap);
    }
    const contextLimit = overlap - transport.held.length;
    transport.context = contextLimit === 0 ? '' : (transport.context + credentialFree).slice(-contextLimit);
  };
  const write = (text: string, settings: { stream?: Stream; exitCode?: number } = {}, completeDocument = false): Promise<void> => {
    if (finalized !== undefined) return Promise.reject(new Error('output: already finalized'));
    const target = settings.stream === 'stderr' ? options.stderr : options.stdout;
    let state = streams.get(target);
    if (!state) {
      state = { context: '', suffix: '', held: '', pending: Promise.resolve() };
      streams.set(target, state);
    }
    const transport = state;
    const completed = transport.pending.then(async () => {
      // Match registered values before pattern redaction can obscure their starts. Only an undecidable suffix is
      // retained; write completion acknowledges this bounded acceptance, independently for each transport.
      const credentialFree = secrets.redact(transport.held + text, transport.context);
      // A complete document disambiguates its own remaining ordinary text without closing the writer
      // or releasing an undecidable fragment on an independent transport.
      const boundary = completeDocument ? credentialFree.length : secrets.pendingStart(credentialFree);
      if (credentialFree.length - boundary > secrets.overlap) throw new Error('output: unresolved fragment exceeds its recognition bound');
      transport.held = credentialFree.slice(boundary);
      await emit(target, transport, credentialFree.slice(0, boundary));
    });
    // The next call observes the bytes of the entire previous call, even when
    // callers enqueue concurrently. Independent transports have independent queues.
    transport.pending = completed.catch(() => undefined);
    return completed;
  };
  const finalize = (): Promise<void> => {
    finalized ??= Promise.all([...streams].map(([target, transport]) => {
      const completed = transport.pending.then(async () => {
        const text = transport.held;
        transport.held = '';
        await emit(target, transport, secrets.redact(text, transport.context));
      });
      transport.pending = completed.catch(() => undefined);
      return completed;
    })).then(() => undefined);
    return finalized;
  };
  return {
    redact,
    write,
    json: async (value, settings = {}) => { await write(`${jsonText(value, redact)}\n`, settings, true); },
    finalize,
  };
}

/** The redactor of every output path: each registered secret in every form it knows, then the pattern classes. */
export function createRedactor(secrets: readonly Secret[]): (text: string) => string {
  const registered = [...secrets];
  return text => {
    for (const secret of registered) text = secret.redact(text);
    return redactPatterns(text);
  };
}

// Payment requests are at most 8192 characters (the reader's limit), so this much
// emitted text is enough to recognise one that continues in a later write.
const PAYMENT_REQUEST_CONTEXT = 8192;
// The lookahead is atomic, so the longest prefix decides before the payload threshold
// applies: "lntbs" with 19 payload characters is never reread as "lntb" with 20. No word
// boundary is required, so a request glued to a label ("invoice_lnbc...") is still found.
const PAYMENT_REQUEST = /(?=(lnbcrt|lnbc|lntbs|lntb|lnsb))\1[a-z0-9]{20,}/gi;
const PREIMAGE_FIELD = /((?:"(?:preimage|r_preimage|payment_preimage)"\s*:\s*"|\b(?:preimage|r_preimage|payment_preimage)\s*[:=]\s*["']?))[a-fA-F0-9]{64}(?![a-fA-F0-9])/g;

/** Redacts payment requests and preimage fields in `text`, which continues the emitted `prefix`. */
function redactPatterns(text: string, prefix = ''): string {
  const boundary = prefix.length;
  const replace = (match: string, label: string, offset: number): string => {
    if (offset >= boundary) return `${label}[redacted]`;
    if (offset + match.length <= boundary) return match;
    // Emitted text cannot be retracted; only its continuation is replaced.
    return `${match.slice(0, boundary - offset)}[redacted]`;
  };
  // A payment request redacted up to the end of the emitted text may continue here. Its
  // data part uses only the bech32 alphabet (BOLT #11, BIP-173), so a leading run of
  // those characters is its continuation and is dropped behind the marker; a run with any
  // other letter or digit ("done", "deadline", "1500000") is ordinary text and is kept.
  if (/(?:lnbcrt|lnbc|lntbs|lntb|lnsb)[a-z0-9]*\[redacted\]$/i.test(prefix)) text = text.replace(/^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+(?![a-z0-9])/i, '');
  return (prefix + text).replace(PAYMENT_REQUEST, replace).replace(PREIMAGE_FIELD, replace).slice(boundary);
}

// Controls, format characters (bidi embeddings, overrides and isolates, zero-width and
// joiner characters, U+FEFF, U+061C, soft hyphen, tags), line separators, lone surrogates,
// private-use, unassigned and noncharacter code points,
// and visually empty fillers and variation selectors become printable escapes.
// eslint-disable-next-line no-misleading-character-class
const UNPRINTABLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180f\u2060-\u206f\u3164\ufe00-\ufe0f\uffa0\u{e0000}-\u{e0fff}]/gu;

const escapes = new Map<number, string | null>();

/** The printable escape for a code point, or null when it is written as is. */
function escapeOf(point: number): string | null {
  let escape = escapes.get(point);
  if (escape === undefined) {
    UNPRINTABLE.lastIndex = 0;
    escape = !UNPRINTABLE.test(String.fromCodePoint(point)) ? null
      : point < 256 ? `\\x${point.toString(16).padStart(2, '0')}`
        : point <= 0xffff ? `\\u${point.toString(16).padStart(4, '0')}` : `\\u{${point.toString(16)}}`;
    escapes.set(point, escape);
  }
  return escape;
}

function escapeText(text: string, preserveNewline: boolean): string {
  // One pass over code points with cached decisions; printable ASCII takes no lookup.
  let out = '', from = 0;
  for (let index = 0; index < text.length;) {
    const unit = text.charCodeAt(index);
    if (unit >= 0x20 && unit < 0x7f) { index++; continue; }
    const point = text.codePointAt(index) ?? unit;
    // A lone surrogate is its own code point here and is escaped as such.
    const width = point > 0xffff ? 2 : 1;
    const escape = unit === 0x0a && preserveNewline ? null : escapeOf(point);
    if (escape !== null) { out += text.slice(from, index) + escape; from = index + width; }
    index += width;
  }
  return from === 0 ? text : out + text.slice(from);
}

function binary(value: unknown): boolean {
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer || value instanceof SharedArrayBuffer) return true;
  if (value === null || typeof value !== 'object') return false;
  const rendered = value as { type?: unknown; data?: unknown };
  return rendered.type === 'Buffer' && Array.isArray(rendered.data);
}

function jsonText(value: unknown, redact: (text: string) => string): string {
  const text: unknown = JSON.stringify(value, function (this: unknown, key: string, item: unknown): unknown {
    // Binary values never print their bytes: a Buffer or typed array, a value whose toJSON
    // returns one, or a Buffer's {type: "Buffer", data} rendering.
    const original = (this as Record<string, unknown>)[key];
    if (binary(original) || binary(item)) return '[redacted]';
    if (typeof item === 'string') return escapeText(redact(item), false);
    if (item && typeof item === 'object' && !Array.isArray(item)) {
      return Object.fromEntries(Object.entries(item).map(([key, child]: [string, unknown]) => [escapeText(redact(key), false), child]));
    }
    return item;
  });
  if (typeof text !== 'string') throw new Error('output: invalid JSON document');
  return text;
}

/**
 * Splits `text` into pieces whose rendered UTF-8 fits the transport's 64 KiB ceiling,
 * never inside a surrogate pair. Yields each source piece with its rendered bytes.
 */
function* utf8Chunks(text: string, render: (piece: string) => string = piece => piece): Generator<[string, Buffer]> {
  const high = (index: number): boolean => /[\ud800-\udbff]/.test(text.charAt(index));
  // The first attempt reuses the size that fit last time, so escape-heavy text is not
  // rendered several times over.
  let size = 65536;
  for (let offset = 0; offset < text.length;) {
    let end = Math.min(offset + size, text.length);
    if (end < text.length && high(end - 1)) end--;
    let chunk = Buffer.from(render(text.slice(offset, end)), 'utf8');
    while (chunk.byteLength > 65536) {
      // Shrink in proportion, then by single code points; one rendered code point always fits.
      let next = Math.min(end - 1, offset + Math.floor((end - offset) * 65536 / chunk.byteLength));
      if (next > offset && high(next - 1)) next--;
      if (next <= offset) next = Math.min(text.length, offset + (high(offset) ? 2 : 1));
      end = next;
      chunk = Buffer.from(render(text.slice(offset, end)), 'utf8');
    }
    size = end - offset === size ? Math.min(65536, size * 2) : Math.max(1, end - offset);
    yield [text.slice(offset, end), chunk];
    offset = end;
  }
}

function pipeClosed(error: unknown): boolean {
  return error instanceof Error && 'code' in error &&
    (error.code === 'EPIPE' || error.code === 'ERR_STREAM_DESTROYED' || error.code === 'ECONNRESET');
}

/** RenderOutput bound to the process streams. */
export function processRenderOutput(secrets: readonly Secret[] = []): RenderOutput {
  return createOutput({ stdout: process.stdout, stderr: process.stderr, secrets });
}

/** Output bound to the process streams. */
export function processOutput(): Output {
  // A reader that has gone away (EPIPE, a closed pipe) leaves nobody to report to; the exit code
  // still carries the result, and the stream error must not become an uncaught exception.
  const ignore = (): void => undefined;
  process.stdout.on('error', ignore);
  process.stderr.on('error', ignore);
  const wrote = { stdout: false, stderr: false };
  return {
    write(stream, text, done) {
      const target = stream === 'stdout' ? process.stdout : process.stderr;
      if (target.destroyed || !target.writable) {
        done?.();
        return;
      }
      // The text counts as out before write() is called, so a signal or failure handled
      // synchronously inside the write already sees the document as emitted.
      const previously = wrote[stream];
      wrote[stream] = true;
      const before = bytesWritten(target);
      let returned = false;
      try {
        const chunks = utf8Chunks(redactPatterns(text), piece => escapeText(piece, true));
        const next = (): void => {
          const chunk = chunks.next();
          if (chunk.done || target.destroyed || !target.writable) { done?.(); return; }
          target.write(chunk.value[1], error => { if (error) done?.(); else next(); });
        };
        next();
        returned = true;
      } finally {
        // A write that threw did not hand the text off. A pipe or terminal counts the bytes it
        // accepted (sent or buffered); a write that never reached it is not output. A file stream
        // has no counter: a write that returned counts.
        const after = bytesWritten(target);
        if (!returned || (before !== undefined && after !== undefined && after <= before)) wrote[stream] = previously;
      }
    },
    wrote(stream) {
      return wrote[stream];
    },
  };
}

function bytesWritten(target: NodeJS.WriteStream): number | undefined {
  // Typed as a net.Socket, but stdout redirected to a file is a stream without this counter.
  const value: unknown = target.bytesWritten;
  return typeof value === 'number' ? value : undefined;
}
