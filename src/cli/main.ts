// The CLI over argv with injected dependencies answers --help, --version and usage errors.
// A failure propagates to the caller, which owns the single internal-error report and the
// exit-code precedence in bin.ts.
import { envelope, renderEnvelope, type Output } from '../output/index.js';
import { parseArgs } from './args.js';
import { ExitCode } from './exit-codes.js';
import { reportUsageError, USAGE } from './report.js';

export interface Deps {
  readonly output: Output;
  /** The package.json version. */
  readonly version: () => string;
}

export function main(argv: readonly string[], deps: Deps): ExitCode {
  const parsed = parseArgs(argv);
  const json = parsed.json;
  switch (parsed.kind) {
    case 'help':
      deps.output.write('stdout', json ? renderEnvelope(envelope(null, { usage: USAGE }, null)) : USAGE);
      return ExitCode.SUCCESS;
    case 'version': {
      const version = deps.version();
      deps.output.write('stdout', json ? renderEnvelope(envelope(null, { version }, null)) : `${version}\n`);
      return ExitCode.SUCCESS;
    }
    case 'usage':
      reportUsageError(deps.output, json, parsed.reason);
      return ExitCode.INVALID_INPUT;
  }
}
