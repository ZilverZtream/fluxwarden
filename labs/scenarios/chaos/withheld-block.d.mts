export function withWithheldBlock<T>(options: {
  owner: unknown;
  manifest: unknown;
  body(): Promise<T> | T;
  retain(name: string, value: unknown): void;
  persistBlock(block: { hash: string; hex: string }): void;
  run?: (file: string, args: readonly string[], options: SpawnSyncOptionsWithStringEncoding) => SpawnSyncReturns<string>;
  now?: () => number;
  pause?: (ms: number) => Promise<void>;
}): Promise<T>;
import type { SpawnSyncOptionsWithStringEncoding, SpawnSyncReturns } from 'node:child_process';
