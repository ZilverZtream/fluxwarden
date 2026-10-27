// Independently attest only the exact final closed capture receipt for upload.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { safeCaptureMetadata } from './ci-capture.mjs';
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  try {
    if (args.length !== 4 || args[0] !== '--root' || !args[1] || args[2] !== '--capture-dir' || !args[3] || !process.env.GITHUB_OUTPUT) throw new Error('metadata arguments');
    await safeCaptureMetadata(args[1], args[3], process.env.GITHUB_OUTPUT);
  } catch { process.exitCode = 1; }
}
