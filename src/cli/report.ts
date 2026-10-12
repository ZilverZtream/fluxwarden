// Fixed reports for the usage, interrupt and internal-error paths. None of them carries argv,
// an error message or a stack (SPEC.md §10.2 exit 8, SECURITY.md INV-11).
import { envelope, renderEnvelope, type Output } from '../output/index.js';
import { ExitCode } from './exit-codes.js';

export const USAGE = [
  'Usage: fluxwarden [--json] <command> [options]',
  '       fluxwarden --help',
  '       fluxwarden --version',
  '',
  'Policy-bound liquidity controller for LND and Core Lightning.',
  'No commands are available in this version.',
  '',
  'Options:',
  '  --help     Print this help and exit.',
  '  --version  Print the version and exit.',
  '  --json     Print exactly one JSON document on stdout.',
  '',
].join('\n');

export function reportUsageError(output: Output, json: boolean, reason: string): void {
  if (json) {
    const message = `${reason}; usage: fluxwarden [--json] <command> [options]; see fluxwarden --help`;
    output.write('stdout', renderEnvelope(envelope(null, null, { code: ExitCode.INVALID_INPUT, step: null, message })));
  } else {
    output.write('stderr', `fluxwarden: ${reason}\n\n${USAGE}`);
  }
}

export function reportInternal(output: Output, json: boolean, done: () => void): void {
  const message = 'internal error';
  if (json) {
    output.write('stdout', renderEnvelope(envelope(null, null, { code: ExitCode.INVARIANT_BREACH, step: 'internal', message })), done);
  } else {
    output.write('stderr', `fluxwarden: ${message}\n`, done);
  }
}

export function reportInterrupted(output: Output, json: boolean, done: () => void): void {
  const message = 'interrupted';
  if (json) {
    output.write('stdout', renderEnvelope(envelope(null, null, { code: ExitCode.INTERRUPTED, step: null, message })), done);
  } else {
    output.write('stderr', `fluxwarden: ${message}\n`, done);
  }
}
