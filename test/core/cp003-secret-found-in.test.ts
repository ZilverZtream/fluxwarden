import { createPrivateKey, generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import { secretType, sentinels, type SecretValue } from '../helpers/output.js';

interface SearchableSecret extends SecretValue { foundIn(data: Uint8Array): boolean }

async function fixture() {
  const Secret = await secretType() as new (bytes: Uint8Array) => SearchableSecret;
  const pem = sentinels().find(row => row.kind === 'ed25519-key')?.bytes;
  if (!pem) throw new Error('Ed25519 fixture is missing');
  // INV-11 covers every credential encoding. node:crypto independently supplies PKCS #8 DER.
  const der = createPrivateKey(pem).export({ format: 'der', type: 'pkcs8' });
  return { Secret, pem, der };
}

it('CP-003/B2 a PEM Secret detects its raw DER and DER base64 and hex encodings in larger byte streams', async () => {
  const { Secret, pem, der } = await fixture();
  const forms: [string, Buffer][] = [
    ['raw DER', der],
    ['DER base64', Buffer.from(der.toString('base64'))],
    ['DER base64url', Buffer.from(der.toString('base64url'))],
    ['DER lower hex', Buffer.from(der.toString('hex'))],
    ['DER upper hex', Buffer.from(der.toString('hex').toUpperCase())],
  ];
  for (const [lineEnding, stored] of [['LF', pem], ['CRLF', Buffer.from(pem.toString('utf8').replace(/\n/g, '\r\n'))]] as const) {
    const secret = new Secret(stored);
    for (const [encoding, bytes] of forms) {
      const stream = Buffer.concat([Buffer.from('before / '), bytes, Buffer.from(' / after')]);
      expect.soft(secret.foundIn(stream), `${lineEnding} stored key: ${encoding}`).toBe(true);
    }
  }
});

it('CP-003/B2 a PEM Secret detects armor-less bodies and equivalent CRLF and container layouts', async () => {
  const { Secret, pem, der } = await fixture();
  const text = pem.toString('utf8');
  const body = text.split('\n').filter(line => line.length > 0 && !line.startsWith('-----'));
  const wrapped = der.toString('base64').match(/.{1,17}/g)?.join('\r\n');
  if (!wrapped) throw new Error('nonempty DER body is required');
  const forms: [string, string][] = [
    ['PEM LF', text],
    ['PEM CRLF', text.replace(/\n/g, '\r\n')],
    ['body LF', body.join('\n')],
    ['body CRLF', body.join('\r\n')],
    ['rewrapped MIME body', wrapped],
    ['YAML block', `key: |\n${text.trimEnd().split('\n').map(line => `  ${line}`).join('\n')}\nnext: 2`],
    ['JSON value', JSON.stringify({ key: text, next: 2 })],
    ['rewrapped PEM CRLF', `-----BEGIN PRIVATE KEY-----\r\n${wrapped}\r\n-----END PRIVATE KEY-----`],
  ];
  for (const [lineEnding, stored] of [['LF', pem], ['CRLF', Buffer.from(text.replace(/\n/g, '\r\n'))]] as const) {
    const secret = new Secret(stored);
    for (const [encoding, value] of forms) {
      expect.soft(secret.foundIn(Buffer.from(`before / ${value} / after`)), `${lineEnding} stored key: ${encoding}`).toBe(true);
    }
  }
});

it('CP-003/B2 a PEM Secret does not report an unrelated Ed25519 key in any key representation', async () => {
  const { Secret, pem, der } = await fixture();
  const secret = new Secret(pem);
  const other = generateKeyPairSync('ed25519').privateKey;
  const otherDer = other.export({ format: 'der', type: 'pkcs8' });
  expect(otherDer.equals(der), 'negative control is a distinct key').toBe(false);
  const forms: Buffer[] = [
    otherDer,
    Buffer.from(other.export({ format: 'pem', type: 'pkcs8' })),
    Buffer.from(otherDer.toString('base64')),
    Buffer.from(otherDer.toString('base64url')),
    Buffer.from(otherDer.toString('hex')),
    Buffer.from(otherDer.toString('hex').toUpperCase()),
  ];
  for (const [index, bytes] of forms.entries()) {
    expect.soft(secret.foundIn(Buffer.concat([Buffer.from('before / '), bytes, Buffer.from(' / after')])), `unrelated key representation ${String(index)}`).toBe(false);
  }
  expect(secret.foundIn(Buffer.from('ordinary output with no credential'))).toBe(false);
});
