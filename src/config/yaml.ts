// The YAML subset of SPEC.md §7.1: block mappings, block sequences, plain and quoted scalars and comments.
// Anchors, aliases, tags, flow collections, block scalars and multi-document files are refused. Every
// scalar stays a string; the caller decides what a value means.

export type YamlValue = string | null | YamlValue[] | YamlMap;
export interface YamlMap { readonly [key: string]: YamlValue }

export class YamlError extends Error {
  constructor(message: string, line: number) {
    super(`line ${String(line)}: ${message}`);
    this.name = 'YamlError';
  }
}

interface Line { readonly number: number; readonly indent: number; readonly text: string }

const MAX_DEPTH = 64;

/** The line without its comment: `#` at the start or after whitespace, outside quotes. */
function stripComment(text: string, number: number): string {
  let quote: string | null = null;
  for (let index = 0; index < text.length; index += 1) {
    const ch = text.charAt(index);
    if (quote === '"' && ch === '\\') { index += 1; continue; }
    if (quote !== null) {
      if (ch === quote) {
        if (quote === "'" && text.charAt(index + 1) === "'") { index += 1; continue; }
        quote = null;
      }
    } else if (ch === '"' || ch === "'") {
      if (index === 0 || /[\s:-]/.test(text.charAt(index - 1)) || /^\s*$/.test(text.slice(0, index))) quote = ch;
    } else if (ch === '#' && (index === 0 || /\s/.test(text.charAt(index - 1)))) {
      return text.slice(0, index);
    }
  }
  if (quote !== null) throw new YamlError('unterminated quoted scalar', number);
  return text;
}

function lines(source: string): Line[] {
  const result: Line[] = [];
  let started = false;
  source.split('\n').forEach((raw, index) => {
    const number = index + 1;
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    const indentText = /^[ \t]*/.exec(line)?.[0] ?? '';
    const body = stripComment(line.slice(indentText.length), number).trimEnd();
    if (body === '') return;
    if (indentText.includes('\t')) throw new YamlError('tab in indentation', number);
    if (indentText === '' && (body === '---' || body === '...' || body.startsWith('--- ') || body.startsWith('%'))) {
      if (!started && body === '---') { started = true; return; }
      throw new YamlError('documents and directives are not supported', number);
    }
    started = true;
    result.push({ number, indent: indentText.length, text: body });
  });
  return result;
}

const DOUBLE_ESCAPES: Readonly<Record<string, string>> = { '"': '"', '\\': '\\', '/': '/', n: '\n', t: '\t', r: '\r', '0': '\0' };

function scalar(text: string, number: number): string {
  if (text.startsWith('"')) {
    let value = '';
    for (let index = 1; index < text.length; index += 1) {
      const ch = text.charAt(index);
      if (ch === '"') {
        if (index !== text.length - 1) throw new YamlError('text after a quoted scalar', number);
        return value;
      }
      if (ch === '\\') {
        const next = text.charAt(index + 1);
        if (next === 'u' && /^[0-9a-fA-F]{4}$/.test(text.slice(index + 2, index + 6))) {
          value += String.fromCharCode(parseInt(text.slice(index + 2, index + 6), 16));
          index += 5;
          continue;
        }
        const escaped = DOUBLE_ESCAPES[next];
        if (escaped === undefined) throw new YamlError('unsupported escape in a quoted scalar', number);
        value += escaped;
        index += 1;
        continue;
      }
      value += ch;
    }
    throw new YamlError('unterminated quoted scalar', number);
  }
  if (text.startsWith("'")) {
    let value = '';
    for (let index = 1; index < text.length; index += 1) {
      const ch = text.charAt(index);
      if (ch === "'") {
        if (text.charAt(index + 1) === "'") { value += "'"; index += 1; continue; }
        if (index !== text.length - 1) throw new YamlError('text after a quoted scalar', number);
        return value;
      }
      value += ch;
    }
    throw new YamlError('unterminated quoted scalar', number);
  }
  const first = text.charAt(0);
  if ('&*!'.includes(first)) throw new YamlError('anchors, aliases and tags are not supported', number);
  if ('[{'.includes(first)) throw new YamlError('flow collections are not supported', number);
  if ('|>'.includes(first)) throw new YamlError('block scalars are not supported', number);
  if ('@`%'.includes(first)) throw new YamlError('reserved character at the start of a plain scalar', number);
  if (/:(\s|$)/.test(text)) throw new YamlError('a plain scalar may not contain ": "', number);
  return text;
}

/** `key: rest` or `key:` with the key as written (plain or quoted); null when the text is not a mapping entry. */
function entry(text: string, number: number): { key: string; rest: string } | null {
  if (text.startsWith('"') || text.startsWith("'")) {
    const quote = text.charAt(0);
    let index = 1;
    for (; index < text.length; index += 1) {
      const ch = text.charAt(index);
      if (quote === '"' && ch === '\\') { index += 1; continue; }
      if (ch === quote) {
        if (quote === "'" && text.charAt(index + 1) === "'") { index += 1; continue; }
        break;
      }
    }
    const after = text.slice(index + 1).trimStart();
    if (!after.startsWith(':') || !/^:(\s|$)/.test(after)) return null;
    return { key: scalar(text.slice(0, index + 1), number), rest: after.slice(1).trim() };
  }
  const match = /^([^\s:][^:]*?):(?:\s+(.*))?$/.exec(text);
  if (match === null) return null;
  const key = (match[1] ?? '').trimEnd();
  if (key.startsWith('- ') || key === '-' || key.startsWith('? ')) return null;
  return { key: scalar(key, number), rest: (match[2] ?? '').trim() };
}

class Parser {
  readonly #lines: Line[];
  #at = 0;

  constructor(source: Line[]) {
    this.#lines = source;
  }

  parse(): YamlValue {
    const first = this.#lines[0];
    if (first === undefined) return null;
    if (first.indent !== 0) throw new YamlError('the document must start at column 0', first.number);
    const value = this.#block(0, 1);
    const extra = this.#lines[this.#at];
    if (extra !== undefined) throw new YamlError('unexpected indentation', extra.number);
    return value;
  }

  #block(indent: number, depth: number): YamlValue {
    const line = this.#lines[this.#at];
    if (line === undefined) return null;
    return line.text === '-' || line.text.startsWith('- ') ? this.#sequence(indent, depth) : this.#mapping(indent, depth);
  }

  /** The nested block of a `key:` or `-` with nothing after it: deeper lines, or null when there are none. */
  #nested(parentIndent: number, sequenceAllowedAtParent: boolean, depth: number): YamlValue {
    const next = this.#lines[this.#at];
    if (next === undefined) return null;
    if (next.indent > parentIndent) return this.#block(next.indent, depth + 1);
    // A block sequence may sit at the same indentation as its mapping key.
    if (sequenceAllowedAtParent && next.indent === parentIndent && (next.text === '-' || next.text.startsWith('- '))) return this.#sequence(parentIndent, depth + 1);
    return null;
  }

  #checkDepth(depth: number): void {
    if (depth > MAX_DEPTH) throw new YamlError('nesting is too deep', this.#lines[this.#at]?.number ?? 1);
  }

  #mapping(indent: number, depth: number): YamlMap {
    this.#checkDepth(depth);
    const map: Record<string, YamlValue> = {};
    for (let line = this.#lines[this.#at]; line !== undefined && line.indent === indent; line = this.#lines[this.#at]) {
      if (line.text === '-' || line.text.startsWith('- ')) break;
      const found = entry(line.text, line.number);
      if (found === null) throw new YamlError('expected "key: value"', line.number);
      if (found.key === '<<') throw new YamlError('merge keys are not supported', line.number);
      if (Object.prototype.hasOwnProperty.call(map, found.key)) throw new YamlError('duplicate key', line.number);
      this.#at += 1;
      Object.defineProperty(map, found.key, {
        value: found.rest === '' ? this.#nested(indent, true, depth) : scalar(found.rest, line.number),
        enumerable: true, writable: true, configurable: true,
      });
    }
    const next = this.#lines[this.#at];
    if (next !== undefined && next.indent > indent) throw new YamlError('unexpected indentation', next.number);
    return map;
  }

  #sequence(indent: number, depth: number): YamlValue[] {
    this.#checkDepth(depth);
    const items: YamlValue[] = [];
    for (let line = this.#lines[this.#at]; line !== undefined && line.indent === indent; line = this.#lines[this.#at]) {
      if (line.text !== '-' && !line.text.startsWith('- ')) break;
      const rest = line.text === '-' ? '' : line.text.slice(2);
      const inner = rest.trimStart();
      if (inner === '') {
        this.#at += 1;
        items.push(this.#nested(indent, false, depth));
        continue;
      }
      const column = indent + 2 + (rest.length - inner.length);
      if (inner === '-' || inner.startsWith('- ') || entry(inner, line.number) !== null) {
        // The item's first line continues at the column after the dash.
        this.#lines[this.#at] = { number: line.number, indent: column, text: inner };
        items.push(this.#block(column, depth + 1));
      } else {
        this.#at += 1;
        items.push(scalar(inner, line.number));
      }
    }
    const next = this.#lines[this.#at];
    if (next !== undefined && next.indent > indent) throw new YamlError('unexpected indentation', next.number);
    return items;
  }
}

export function parseYaml(source: string): YamlValue {
  const text = source.startsWith('﻿') ? source.slice(1) : source;
  return new Parser(lines(text)).parse();
}
