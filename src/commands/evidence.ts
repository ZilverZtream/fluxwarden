import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { ExitCode } from '../cli/exit-codes.js';
import type { Secret } from '../core/secret.js';
import { buildBundle, holdsPreimage, RUN_ID, type EvidenceInput } from '../evidence/bundle.js';
import { createStagingDirectory, publishDirectory, removeDirectory, writeNewFiles } from '../output/files.js';

export type EvidenceExit = typeof ExitCode.SUCCESS | typeof ExitCode.INVALID_INPUT | typeof ExitCode.INVARIANT_BREACH;

type Destination = { state: 'absent' } | { state: 'empty-directory' } | { state: 'refused' };

/**
 * What `outDir` is now: only a missing path or an empty real directory can receive the bundle, in a parent
 * that is a real directory. A symbolic link or junction (lstat reports both as links) is refused.
 */
function destination(outDir: string): Destination {
  try {
    const parent = lstatSync(dirname(outDir));
    if (!parent.isDirectory()) return { state: 'refused' };
  } catch {
    return { state: 'refused' };
  }
  let stat;
  try {
    stat = lstatSync(outDir);
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'ENOENT' ? { state: 'absent' } : { state: 'refused' };
  }
  if (!stat.isDirectory()) return { state: 'refused' };
  return readdirSync(outDir).length === 0 ? { state: 'empty-directory' } : { state: 'refused' };
}

/**
 * `evidence export` (SPEC.md §10.3 EV1–EV3). An invalid run id, or an out directory that exists and is not
 * empty, is invalid input and nothing is created. The bundle is written to a staging directory beside the
 * destination and read back for every registered secret in every form it knows (SPEC.md §12.2); a hit
 * deletes the staging directory and is an invariant breach. Otherwise the directory is renamed into place.
 */
export function exportEvidence(input: EvidenceInput, options: { outDir: string; secrets: readonly Secret[] }):
  Promise<{ exitCode: EvidenceExit; files: string[] }> {
  try {
    return Promise.resolve(writeBundle(input, options));
  } catch (error) {
    return Promise.reject(error instanceof Error ? error : new Error('evidence: export failed'));
  }
}

function writeBundle(input: EvidenceInput, options: { outDir: string; secrets: readonly Secret[] }): { exitCode: EvidenceExit; files: string[] } {
  const refused = { exitCode: ExitCode.INVALID_INPUT, files: [] };
  if (!RUN_ID.test(input.manifest.runId)) return refused;
  const target = destination(options.outDir);
  if (target.state === 'refused') return refused;
  const bundle = buildBundle(input, options.secrets);
  const staging = createStagingDirectory(options.outDir);
  try {
    writeNewFiles(new Map([...bundle].map(([name, bytes]) => [join(staging, name), bytes])));
    const written = [...bundle.keys()].map(name => ({ name, bytes: readFileSync(join(staging, name)) }));
    const leaked = written.some(file => options.secrets.some(secret => secret.foundIn(file.bytes) || secret.foundIn(Buffer.from(file.name))))
      || holdsPreimage(written.map(file => file.bytes.toString('utf8')));
    if (leaked) {
      removeDirectory(staging);
      return { exitCode: ExitCode.INVARIANT_BREACH, files: [] };
    }
    publishDirectory(staging, options.outDir, target.state === 'empty-directory');
  } catch (error) {
    removeDirectory(staging);
    throw error;
  }
  return { exitCode: ExitCode.SUCCESS, files: [...bundle.keys()].sort() };
}
