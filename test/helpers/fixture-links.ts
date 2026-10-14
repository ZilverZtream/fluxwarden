import { lstatSync, readlinkSync, unlinkSync, writeFileSync } from 'node:fs';

/** Retain link metadata as a regular artifact, then unlink only the test-created link. */
export function unlinkFixture(path: string): void {
  const stat = lstatSync(path, { throwIfNoEntry: false });
  if (stat === undefined) return;
  if (!stat.isSymbolicLink()) throw new Error('fixture cleanup requires a symbolic link or junction');
  try {
    writeFileSync(`${path}.link.json`, `${JSON.stringify({ target: readlinkSync(path), mode: stat.mode, device: stat.dev, inode: stat.ino })}\n`, { flag: 'wx', mode: 0o600 });
  } finally { unlinkSync(path); }
}
