// Shared rendering for the read-only commands: the --json document and plain-text tables.
import { envelope, nodeText, renderEnvelope, type ErrorBody, type Output } from '../output/index.js';

export interface Io {
  readonly output: Output;
  readonly json: boolean;
}

export interface Outcome {
  readonly code: number;
  readonly result: Readonly<Record<string, unknown>> | null;
  readonly error: ErrorBody | null;
  readonly warnings: readonly string[];
}

/** Writes the one --json document of a command and returns its exit code. */
export function emitJson(io: Io, command: string, outcome: Outcome): number {
  io.output.write('stdout', renderEnvelope(envelope(command, outcome.result, outcome.error, outcome.warnings)));
  return outcome.code;
}

/** A refusal before any node is contacted: one document, or one line on stderr. */
export function refuse(io: Io, command: string, code: number, step: string | null, message: string): number {
  if (io.json) return emitJson(io, command, { code, result: null, error: { code, step, message }, warnings: [] });
  io.output.write('stderr', `fluxwarden ${command}: ${nodeText(message, 4096)}\n`);
  return code;
}

/** Warning lines for text mode, on stderr. */
export function writeWarnings(io: Io, command: string, warnings: readonly string[]): void {
  for (const warning of warnings) io.output.write('stderr', `fluxwarden ${command}: warning ${nodeText(warning, 4096)}\n`);
}

/** Left-aligned columns separated by two spaces; every cell must already be escaped. */
export function table(rows: readonly (readonly string[])[]): string {
  const widths: number[] = [];
  for (const row of rows) row.forEach((cell, index) => { widths[index] = Math.max(widths[index] ?? 0, cell.length); });
  return rows.map(row => row.map((cell, index) => (index === row.length - 1 ? cell : cell.padEnd(widths[index] ?? 0))).join('  ').trimEnd()).join('\n') + '\n';
}

export function iso(ms: number): string {
  return new Date(ms).toISOString();
}

export const byName = <T extends { readonly name: string }>(a: T, b: T): number => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
