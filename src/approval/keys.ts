// Ed25519 approval keys: generation, key ids and configured public keys.
import { createHash, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { Secret } from '../core/secret.js';
import type { ApprovalKey } from './types.js';

/** The raw 32-byte Ed25519 public key. */
export function rawPublicKey(key: KeyObject): Buffer {
  if (key.asymmetricKeyType !== 'ed25519') throw new TypeError('approval keys are Ed25519 keys');
  const jwk = key.export({ format: 'jwk' });
  if (typeof jwk.x !== 'string') throw new TypeError('approval keys are Ed25519 keys');
  return Buffer.from(jwk.x, 'base64url');
}

/** key_id: the first 16 bytes of SHA-256 of the raw public key, as lowercase hex. */
export function keyIdOf(raw: Uint8Array): string {
  return createHash('sha256').update(raw).digest().subarray(0, 16).toString('hex');
}

/** The public key of a configured entry, or null when the entry is malformed or its key_id does not match its key. */
export function configuredPublicKey(entry: ApprovalKey): KeyObject | null {
  if (!/^[A-Za-z0-9+/]{43}=$/.test(entry.publicKey)) return null;
  const raw = Buffer.from(entry.publicKey, 'base64');
  if (raw.length !== 32 || raw.toString('base64') !== entry.publicKey || keyIdOf(raw) !== entry.keyId) return null;
  try {
    return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') }, format: 'jwk' });
  } catch {
    return null;
  }
}

/** The configured public key with this key_id, or null. */
export function findPublicKey(keys: readonly ApprovalKey[], keyId: string): KeyObject | null {
  for (const entry of keys) {
    if (entry.keyId !== keyId) continue;
    const key = configuredPublicKey(entry);
    if (key !== null) return key;
  }
  return null;
}

/** A new operator key pair: the private key as PKCS#8 PEM bytes inside a Secret, the public key as raw base64. */
export function generateApprovalKeyPair(): { privateKey: Secret; publicKey: string; keyId: string } {
  const pair = generateKeyPairSync('ed25519');
  const pem = pair.privateKey.export({ format: 'pem', type: 'pkcs8' });
  const raw = rawPublicKey(pair.publicKey);
  return { privateKey: new Secret(Buffer.from(pem)), publicKey: raw.toString('base64'), keyId: keyIdOf(raw) };
}
