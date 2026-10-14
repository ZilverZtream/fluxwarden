// A reader for the YAML subset of the policy file: block mappings, block sequences, plain and
// quoted scalars and comments. Every scalar stays a string; nothing is resolved to a type, and no
// construct that YAML uses for references, tags or object construction is accepted.
import { PolicyError } from './errors.js';

export type YamlValue = string | null | YamlValue[] | { [key: string]: YamlValue };

/** The policy file bound of the security model's input limits (64 KiB). */
const MAX_BYTES = 64 * 1024;
const MAX_DEPTH = 64;

interface Line {
  readonly indent: number;
  readonly text: string;
  readonly number: number;
}

function refuse(line: number | null, message: string): PolicyError {
  return new PolicyError(2, null, line === null ? `policy file: ${message}` : `policy file line ${String(line)}: ${message}`);
}

/** A `#` starts a comment at the beginning of the text or after whitespace; -1 when there is none. */
function commentStart(text: string): number {
  if (text.startsWith('#')) return 0;
  const match = /[ \t]#/.exec(text);
  return match === null ? -1 : match.index + 1;
}

function readLines(text: string): Line[] {
  if (Buffer.byteLength(text, 'utf8') > MAX_BYTES) throw refuse(null, 'larger than 64 KiB');
  const source = text.startsWith('\uFEFF') ? text.slice(1) : text;
  const lines: Line[] = [];
  let started = false;
  source.split('\n').forEach((raw, index) => {
    const number = index + 1;
    const content = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u0008\u000a-\u001f\u007f\uFEFF]/.test(content)) throw refuse(number, 'control character');
    if (content.trim() === '') return;
    const indent = content.length - content.trimStart().length;
    const rest = content.slice(indent);
    if (content.slice(0, indent).includes('\t')) throw refuse(number, 'tab indentation');
    if (rest.startsWith('#')) return;
    if (indent === 0 && rest.startsWith('%')) throw refuse(number, 'directives are not supported');
    if (indent === 0 && /^(?:---|\.\.\.)(?:[ \t]|$)/.test(rest)) {
      // One leading start marker is allowed; any other marker would begin or end a further document.
      if (!started && rest.startsWith('---') && /^(?:[ \t]+(?:#.*)?)?$/.test(rest.slice(3))) {
        started = true;
        return;
      }
      throw refuse(number, 'only one document is allowed');
    }
    started = true;
    lines.push({ indent, text: rest, number });
  });
  return lines;
}

const SIMPLE_ESCAPES: Readonly<Record<string, string>> = { '\\': '\\', '"': '"', '/': '/', n: '\n', t: '\t', r: '\r', '0': '\0' };

function readQuoted(text: string, line: number): { value: string; end: number } {
  const quote = text[0];
  let value = '';
  let i = 1;
  for (;;) {
    const ch = text[i];
    if (ch === undefined) throw refuse(line, 'unterminated quoted scalar');
    if (quote === "'") {
      if (ch !== "'") {
        value += ch;
        i += 1;
      } else if (text[i + 1] === "'") {
        value += "'";
        i += 2;
      } else {
        return { value, end: i + 1 };
      }
      continue;
    }
    if (ch === '"') return { value, end: i + 1 };
    if (ch !== '\\') {
      value += ch;
      i += 1;
      continue;
    }
    const escape = text[i + 1] ?? '';
    const simple = Object.hasOwn(SIMPLE_ESCAPES, escape) ? SIMPLE_ESCAPES[escape] : undefined;
    if (simple !== undefined) {
      value += simple;
      i += 2;
      continue;
    }
    const width = escape === 'x' ? 2 : escape === 'u' ? 4 : 0;
    const digits = text.slice(i + 2, i + 2 + width);
    if (width === 0 || digits.length !== width || !/^[0-9a-fA-F]+$/.test(digits)) throw refuse(line, 'unsupported escape in a quoted scalar');
    value += String.fromCharCode(parseInt(digits, 16));
    i += 2 + width;
  }
}

function isSequenceItem(text: string): boolean {
  return text === '-' || text.startsWith('- ');
}

/** Splits `key: value`; null when the text is not a mapping entry. */
function keyOf(text: string, line: number): { key: string; rest: string } | null {
  if (text.startsWith('"') || text.startsWith("'")) {
    const quoted = readQuoted(text, line);
    const after = text.slice(quoted.end);
    const colon = /^ *:(?: |$)/.exec(after);
    if (colon === null) return null;
    return { key: quoted.value, rest: after.slice(colon[0].length).trimStart() };
  }
  if (/^[-?:,[\]{}#&*!|>%@`]/.test(text)) return null;
  const limit = commentStart(text);
  const region = limit === -1 ? text : text.slice(0, limit);
  const colon = /:(?: |$)/.exec(region);
  if (colon === null) return null;
  const key = text.slice(0, colon.index).trimEnd();
  if (key === '') return null;
  return { key, rest: text.slice(colon.index + 1).trimStart() };
}

function parseScalar(text: string, line: number): string {
  const first = text[0] ?? '';
  if (first === '"' || first === "'") {
    const quoted = readQuoted(text, line);
    if (!/^(?:[ \t]+(?:#.*)?)?$/.test(text.slice(quoted.end))) throw refuse(line, 'unexpected text after a quoted scalar');
    return quoted.value;
  }
  if (first === '&' || first === '*') throw refuse(line, 'anchors and aliases are not supported');
  if (first === '!') throw refuse(line, 'tags are not supported');
  if ('{}[]'.includes(first)) throw refuse(line, 'flow collections are not supported');
  if (first === '|' || first === '>') throw refuse(line, 'block scalars are not supported');
  if ('@`%,?:'.includes(first) || isSequenceItem(text)) throw refuse(line, 'reserved indicator at the start of a plain scalar');
  const limit = commentStart(text);
  const value = (limit === -1 ? text : text.slice(0, limit)).trimEnd();
  if (/:(?: |$)/.test(value)) throw refuse(line, 'a colon followed by a space must be quoted');
  return value;
}

function define(target: Record<string, YamlValue>, key: string, value: YamlValue): void {
  // An own data property, so a key such as __proto__ never reaches the prototype.
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

class Parser {
  private index = 0;

  constructor(private readonly lines: Line[]) {}

  peek(): Line | undefined {
    return this.lines[this.index];
  }

  node(indent: number, depth: number): YamlValue {
    const line = this.peek();
    if (line === undefined) return null;
    return isSequenceItem(line.text) ? this.sequence(indent, depth) : this.mapping(indent, depth);
  }

  /** The value of a key or item with nothing after its indicator: a nested block, or null. */
  private nested(indent: number, depth: number, sameIndentSequence: boolean): YamlValue {
    const next = this.peek();
    if (next === undefined) return null;
    if (next.indent > indent) return this.node(next.indent, depth + 1);
    if (sameIndentSequence && next.indent === indent && isSequenceItem(next.text)) return this.sequence(indent, depth + 1);
    return null;
  }

  private sequence(indent: number, depth: number): YamlValue[] {
    this.checkDepth(depth);
    const items: YamlValue[] = [];
    for (let line = this.peek(); line !== undefined; line = this.peek()) {
      if (line.indent < indent) break;
      if (line.indent > indent) throw refuse(line.number, 'unexpected indentation');
      if (!isSequenceItem(line.text)) break;
      const after = line.text.slice(1);
      const rest = after.trimStart();
      if (rest === '' || rest.startsWith('#')) {
        this.index += 1;
        items.push(this.nested(indent, depth, false));
        continue;
      }
      const column = indent + 1 + after.length - rest.length;
      if (isSequenceItem(rest) || keyOf(rest, line.number) !== null) {
        // The item's content continues as a block at its own column.
        this.lines[this.index] = { indent: column, text: rest, number: line.number };
        items.push(this.node(column, depth + 1));
      } else {
        items.push(parseScalar(rest, line.number));
        this.index += 1;
      }
    }
    return items;
  }

  private mapping(indent: number, depth: number): Record<string, YamlValue> {
    this.checkDepth(depth);
    const result: Record<string, YamlValue> = {};
    const seen = new Set<string>();
    for (let line = this.peek(); line !== undefined; line = this.peek()) {
      if (line.indent < indent) break;
      if (line.indent > indent) throw refuse(line.number, 'unexpected indentation');
      if (isSequenceItem(line.text)) throw refuse(line.number, 'sequence item where a key was expected');
      const entry = keyOf(line.text, line.number);
      if (entry === null) throw refuse(line.number, 'expected a key');
      if (seen.has(entry.key)) throw refuse(line.number, 'duplicate key');
      seen.add(entry.key);
      this.index += 1;
      const value = entry.rest === '' || entry.rest.startsWith('#')
        ? this.nested(indent, depth, true)
        : parseScalar(entry.rest, line.number);
      define(result, entry.key, value);
    }
    return result;
  }

  private checkDepth(depth: number): void {
    if (depth > MAX_DEPTH) throw refuse(this.peek()?.number ?? null, `nesting deeper than ${String(MAX_DEPTH)} levels`);
  }
}

/** Parses the policy YAML subset; everything outside it is refused with exit 2. */
export function parseYamlSubset(text: string): YamlValue {
  const lines = readLines(text);
  const first = lines[0];
  if (first === undefined) return null;
  const parser = new Parser(lines);
  const value = parser.node(first.indent, 1);
  const leftover = parser.peek();
  if (leftover !== undefined) throw refuse(leftover.number, 'unexpected indentation');
  return value;
}
