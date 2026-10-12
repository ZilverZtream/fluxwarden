// A small YAML-subset reader for GitHub workflow files (block maps and sequences, flow
// sequences and maps, quoted and plain scalars, block scalars, comments). Test-only: the
// project has no YAML dependency. Keys stay strings (so `on` is not a boolean);
// `true`/`false` become booleans; every other scalar stays a string.

export type Yaml = string | boolean | null | Yaml[] | { [key: string]: Yaml };

interface Line { indent: number; text: string }

function stripComment(line: string): string {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line.charAt(i);
    if (quote !== null) {
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === '#' && (i === 0 || /\s/.test(line.charAt(i - 1)))) {
      return line.slice(0, i);
    }
  }
  return line;
}

function splitTopLevel(inner: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let current = '';
  for (const ch of inner) {
    if (quote !== null) {
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === '[' || ch === '{') {
      depth += 1;
    } else if (ch === ']' || ch === '}') {
      depth -= 1;
    } else if (ch === ',' && depth === 0) {
      parts.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim() !== '') parts.push(current.trim());
  return parts;
}

/** Splits `key: value` at the first colon followed by a space or the end, outside quotes. */
function splitKey(text: string): [string, string] | null {
  let quote: string | null = null;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text.charAt(i);
    if (quote !== null) {
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === ':' && (i + 1 === text.length || text.charAt(i + 1) === ' ')) {
      return [unquote(text.slice(0, i).trim()), text.slice(i + 1).trim()];
    } else if (ch === '{' || ch === '[') {
      return null;
    }
  }
  return null;
}

function unquote(text: string): string {
  if (text.length >= 2 && ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'")))) {
    return text.slice(1, -1);
  }
  return text;
}

function scalar(text: string): Yaml {
  if (text.startsWith('[') && text.endsWith(']')) return splitTopLevel(text.slice(1, -1)).map(scalar);
  if (text.startsWith('{') && text.endsWith('}')) {
    const map: { [key: string]: Yaml } = {};
    for (const part of splitTopLevel(text.slice(1, -1))) {
      const kv = splitKey(part);
      if (kv === null) throw new Error(`unreadable flow map entry: ${part}`);
      map[kv[0]] = scalar(kv[1]);
    }
    return map;
  }
  if (text === 'true') return true;
  if (text === 'false') return false;
  if (text === '' || text === '~' || text === 'null') return null;
  return unquote(text);
}

export function parseYaml(source: string): Yaml {
  const lines: Line[] = [];
  for (const raw of source.replace(/\r\n/g, '\n').split('\n')) {
    const text = stripComment(raw).replace(/\s+$/, '');
    if (text.trim() === '') { lines.push({ indent: -1, text: '' }); continue; }
    lines.push({ indent: text.length - text.trimStart().length, text: text.trimStart() });
  }
  let pos = 0;
  const skipBlank = (): void => { while (pos < lines.length && lines[pos]?.indent === -1) pos += 1; };
  const peek = (): Line | undefined => { skipBlank(); return lines[pos]; };

  function blockScalar(parentIndent: number, folded: boolean): string {
    const collected: string[] = [];
    let minIndent = Infinity;
    const start = pos;
    while (pos < lines.length) {
      const line = lines[pos];
      if (line === undefined) break;
      if (line.indent !== -1 && line.indent <= parentIndent) break;
      if (line.indent !== -1) minIndent = Math.min(minIndent, line.indent);
      pos += 1;
    }
    for (const line of lines.slice(start, pos)) {
      collected.push(line.indent === -1 ? '' : ' '.repeat(line.indent - minIndent) + line.text);
    }
    while (collected.length > 0 && collected[collected.length - 1] === '') collected.pop();
    return collected.join(folded ? ' ' : '\n');
  }

  function valueAfterKey(rest: string, indent: number): Yaml {
    if (/^[|>][-+0-9]*$/.test(rest)) return blockScalar(indent, rest.startsWith('>'));
    if (rest !== '') return scalar(rest);
    const next = peek();
    if (next === undefined) return null;
    if (next.indent > indent) return block(next.indent);
    if (next.indent === indent && next.text.startsWith('- ')) return block(indent);
    return null;
  }

  function mapping(indent: number, first?: string): { [key: string]: Yaml } {
    const map: { [key: string]: Yaml } = {};
    let text = first;
    for (;;) {
      if (text === undefined) {
        const line = peek();
        if (line === undefined || line.indent !== indent || line.text.startsWith('- ')) break;
        text = line.text;
        pos += 1;
      }
      const kv = splitKey(text);
      if (kv === null) throw new Error(`unreadable mapping line: ${text}`);
      map[kv[0]] = valueAfterKey(kv[1], indent);
      text = undefined;
    }
    return map;
  }

  function sequence(indent: number): Yaml[] {
    const items: Yaml[] = [];
    for (;;) {
      const line = peek();
      if (line === undefined || line.indent !== indent || !(line.text === '-' || line.text.startsWith('- '))) break;
      pos += 1;
      const rest = line.text === '-' ? '' : line.text.slice(2);
      const content = rest.trimStart();
      const column = indent + 2 + (rest.length - content.length);
      if (content === '') {
        const next = peek();
        items.push(next !== undefined && next.indent > indent ? block(next.indent) : null);
      } else if (splitKey(content) !== null && !content.startsWith('"') && !content.startsWith("'")) {
        items.push(mapping(column, content));
      } else {
        items.push(scalar(content));
      }
    }
    return items;
  }

  function block(indent: number): Yaml {
    const line = peek();
    if (line === undefined) return null;
    return line.text === '-' || line.text.startsWith('- ') ? sequence(indent) : mapping(indent);
  }

  const root = block(peek()?.indent ?? 0);
  if (peek() !== undefined) throw new Error(`unparsed YAML from line ${String(pos + 1)}`);
  return root;
}
