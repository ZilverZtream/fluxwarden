import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import type { Config, NodeConfig } from '../config/config.js';
import { Secret } from '../core/secret.js';
import { onlyOwnerAccess } from '../persistence/owner-files.js';
import type { EvidenceInput } from './bundle.js';

const MAX_CREDENTIAL_BYTES = 64 * 1024;

/** Existing configured credentials are read only for sanitization; the exporter never connects to a node. */
function credential(node: NodeConfig): Secret {
  const path = node.credentialPath;
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink()) throw new Error('evidence: invalid credential file');
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const held = fstatSync(fd);
    const privateMode = process.platform === 'win32' ? onlyOwnerAccess(path) : (held.mode & 0o077) === 0 && held.uid === process.getuid?.();
    if (!held.isFile() || held.dev !== before.dev || held.ino !== before.ino || !privateMode || held.size > MAX_CREDENTIAL_BYTES) {
      throw new Error('evidence: invalid credential file');
    }
    const bytes = Buffer.alloc(MAX_CREDENTIAL_BYTES + 1);
    let length = 0;
    for (;;) {
      const read = readSync(fd, bytes, length, bytes.length - length, length);
      if (read === 0) break;
      length += read;
      if (length > MAX_CREDENTIAL_BYTES) throw new Error('evidence: credential file exceeds its bound');
    }
    const after = lstatSync(path);
    if (after.isSymbolicLink() || after.dev !== held.dev || after.ino !== held.ino ||
        (process.platform === 'win32' && !onlyOwnerAccess(path))) throw new Error('evidence: credential file changed');
    const value = bytes.subarray(0, length);
    if (node.implementation === 'lnd') return new Secret(value);
    const rune = value.toString('utf8').trim();
    if (!/^[\x21-\x7e]+$/.test(rune)) throw new Error('evidence: invalid credential file');
    return new Secret(Buffer.from(rune, 'utf8'));
  } finally { closeSync(fd); }
}

/** Only nodes recorded in this run supply its credential context; a rotated or unavailable credential fails closed. */
export function evidenceCredentials(input: EvidenceInput, config: Config): readonly Secret[] {
  return input.manifest.nodes.map(recorded => {
    const node = config.nodes.find(node => recorded.pubkey === node.expectedPubkey && recorded.implementation === node.implementation);
    if (node === undefined) throw new Error('evidence: the recorded node has no configured credential context');
    const secret = credential(node);
    if (secret.fingerprint !== recorded.credentialFingerprint) throw new Error('evidence: the configured credential no longer matches this run');
    return secret;
  });
}
