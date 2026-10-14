import { lstatSync, readFileSync } from 'node:fs';
import type { EvidenceInput } from '../evidence/bundle.js';
import { RUN_ID } from '../evidence/bundle.js';
import { writeOwnerOnlyFile } from './private-file.js';

const MAX_RUN_BYTES = 16 * 1024 * 1024;

export function writeRunRecord(databasePath: string, input: EvidenceInput): void {
  if (!RUN_ID.test(input.manifest.runId)) throw new Error('invalid run id');
  const bytes = Buffer.from(JSON.stringify(input, (_key, value: unknown) => typeof value === 'bigint' ? value.toString() : value));
  if (bytes.length > MAX_RUN_BYTES) throw new Error('run record exceeds its size bound');
  if (writeOwnerOnlyFile(`${databasePath}.${input.manifest.runId}.json`, bytes) !== 'written') throw new Error('run record could not be stored');
}

export function readRunRecord(databasePath: string, runId: string): EvidenceInput | null {
  if (!RUN_ID.test(runId)) return null;
  const path = `${databasePath}.${runId}.json`;
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_RUN_BYTES) return null;
    const value = JSON.parse(readFileSync(path, 'utf8')) as EvidenceInput;
    return value.manifest.runId === runId ? value : null;
  } catch { return null; }
}
