// Exit codes implemented so far, labels as SPEC.md §10.2.
export const ExitCode = {
  SUCCESS: 0,
  POLICY_VIOLATION: 1,
  INVALID_INPUT: 2,
  CAPABILITY_UNSUPPORTED: 3,
  NODE_UNREACHABLE: 4,
  SAFETY_REFUSAL: 5,
  INTERRUPTED: 6,
  OUTCOME_UNKNOWN: 7,
  INVARIANT_BREACH: 8,
  RECONCILIATION_ALERT: 9,
} as const;

export type ExitCode = (typeof ExitCode)[keyof typeof ExitCode];
