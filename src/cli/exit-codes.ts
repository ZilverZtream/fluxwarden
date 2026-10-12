// Exit codes implemented so far, labels as SPEC.md §10.2.
export const ExitCode = {
  SUCCESS: 0,
  INVALID_INPUT: 2,
  INTERRUPTED: 6,
  INVARIANT_BREACH: 8,
} as const;

export type ExitCode = (typeof ExitCode)[keyof typeof ExitCode];
