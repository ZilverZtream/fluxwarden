export const referenceServices: readonly string[];
export const referencePins: Readonly<Record<string, string>>;
export function qualifyReference(owner: unknown, manifest: unknown): unknown;
export function qualifyNativeReference(owner: unknown, manifest: unknown, inspected: unknown): unknown;
