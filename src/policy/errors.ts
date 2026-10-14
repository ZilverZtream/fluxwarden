/** A policy file that cannot be used: exit 2 for malformed input, exit 1 for a value the policy forbids. */
export class PolicyError extends Error {
  override readonly name = 'PolicyError';
  readonly exitCode: 1 | 2;
  /** Dotted path of the offending field, or null when the file itself is unreadable. */
  readonly field: string | null;

  constructor(exitCode: 1 | 2, field: string | null, message: string) {
    super(field === null ? message : `policy field ${field}: ${message}`);
    this.exitCode = exitCode;
    this.field = field;
  }
}
