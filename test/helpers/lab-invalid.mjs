/** A refused laboratory precondition, distinct from a failed product assertion. */
export class LabInvalidError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'LabInvalidError';
  }
}
