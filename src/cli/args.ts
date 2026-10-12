// Argument parsing (SPEC.md §10.3 G1). The result never carries a token from argv, so no later
// stage can echo one (FC-129).

export type UsageReason = 'missing command' | 'unknown command' | 'unknown option';

export type Parsed =
  | { readonly kind: 'help'; readonly json: boolean }
  | { readonly kind: 'version'; readonly json: boolean }
  | { readonly kind: 'usage'; readonly json: boolean; readonly reason: UsageReason };

export function parseArgs(argv: readonly string[]): Parsed {
  let json = false;
  let help = false;
  let version = false;
  let reason: UsageReason | null = null;
  let operandsOnly = false;
  for (const token of argv) {
    if (!operandsOnly && token === '--') {
      operandsOnly = true;
    } else if (!operandsOnly && token.startsWith('-') && token !== '-') {
      if (token === '--json') json = true;
      else if (token === '--help') help = true;
      else if (token === '--version') version = true;
      else reason ??= 'unknown option';
    } else {
      // No command exists yet, so every operand is unknown.
      reason ??= 'unknown command';
    }
  }
  if (reason !== null) return { kind: 'usage', json, reason };
  if (help) return { kind: 'help', json };
  if (version) return { kind: 'version', json };
  return { kind: 'usage', json, reason: 'missing command' };
}
