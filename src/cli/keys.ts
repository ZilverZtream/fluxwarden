// `fluxwarden keys generate --out <file>` (SPEC.md §10.3 command 13): a new operator key pair. The
// private key goes only to a new owner-only file; the public key and key_id are printed for
// `approval_keys`.
import { generateApprovalKeyPair } from '../approval/keys.js';
import { writePrivateKeyFile } from '../approval/sign.js';
import { envelope, renderEnvelope, type Output } from '../output/index.js';
import { ExitCode } from './exit-codes.js';
import { reportCommandError } from './report.js';

const COMMAND = 'keys generate';

export function keysGenerate(out: string, json: boolean, output: Output): ExitCode {
  const pair = generateApprovalKeyPair();
  const outcome = writePrivateKeyFile(pair.privateKey, out);
  if (outcome !== 'written') {
    const message = outcome === 'exists' ? 'the output file already exists'
      : outcome === 'invalid-path' ? 'the output path is not an ordinary file path' : 'the output file cannot be created';
    reportCommandError(output, json, COMMAND, ExitCode.INVALID_INPUT, message);
    return ExitCode.INVALID_INPUT;
  }
  const result = { public_key: pair.publicKey, key_id: pair.keyId };
  output.write('stdout', json
    ? renderEnvelope(envelope(COMMAND, result, null))
    : `public_key: ${result.public_key}\nkey_id: ${result.key_id}\n`);
  return ExitCode.SUCCESS;
}
