import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { repoRoot } from './cli.js';

/** Loads a module under src/ at run time, so a missing module fails the case that needs it, not the whole file. */
export async function loadSrc<T>(relativePath: string): Promise<T> {
  return await import(pathToFileURL(join(repoRoot, 'src', relativePath)).href) as T;
}

export interface ThrownShape { name: string; message: string; exitCode: unknown; field?: unknown; reason?: unknown }

/** Runs `action`, which must throw an Error carrying an `exitCode`; returns what it threw. */
export function thrown(action: () => unknown): ThrownShape {
  try {
    action();
  } catch (error: unknown) {
    if (error instanceof Error && 'exitCode' in error) return error;
    throw error;
  }
  throw new Error('expected a refusal, but the call returned');
}
