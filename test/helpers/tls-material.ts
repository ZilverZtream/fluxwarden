// RFC 5280 §§4.1/4.2.1.6: independent disposable CA/server material using Node crypto.
import { strict as assert } from 'node:assert';
import { generateKeyPairSync, randomBytes, sign, X509Certificate } from 'node:crypto';
import { appendFileSync, writeFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { join } from 'node:path';
import { testRoot } from './env.js';

export function tlsCertificate(input: string, names: readonly string[], ipv4: readonly string[] = []) {
  const der = (tag: number, ...parts: Buffer[]): Buffer => {
    const body = Buffer.concat(parts), count = body.length;
    const length = count < 128 ? Buffer.from([count]) : count < 256 ? Buffer.from([0x81, count]) : Buffer.from([0x82, count >> 8, count & 255]);
    return Buffer.concat([Buffer.from([tag]), length, body]);
  };
  const seq = (...parts: Buffer[]) => der(0x30, ...parts);
  const oid = (bytes: number[]) => der(6, Buffer.from(bytes));
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const algorithm = seq(oid([42, 134, 72, 206, 61, 4, 3, 2]));
  const name = seq(der(0x31, seq(oid([85, 4, 3]), der(12, Buffer.from('FluxWarden synthetic TLS input')))));
  const ips = ipv4.map(address => {
    assert.equal(isIP(address), 4, 'fixture IP SAN is IPv4');
    return der(0x87, Buffer.from(address.split('.').map(Number)));
  });
  const extensions = der(0xa3, seq(
    seq(oid([85, 29, 19]), der(1, Buffer.from([255])), der(4, seq(der(1, Buffer.from([255]))))),
    seq(oid([85, 29, 17]), der(4, seq(...names.map(value => der(0x82, Buffer.from(value))), ...ips))),
  ));
  const tbs = seq(der(0xa0, der(2, Buffer.from([2]))), der(2, Buffer.from([1])), algorithm, name,
    seq(der(0x18, Buffer.from('20200101000000Z')), der(0x18, Buffer.from('21260101000000Z'))), name,
    pair.publicKey.export({ format: 'der', type: 'spki' }), extensions);
  const bytes = seq(tbs, algorithm, der(3, Buffer.from([0]), sign('sha256', tbs, pair.privateKey)));
  const cert = `-----BEGIN CERTIFICATE-----\n${bytes.toString('base64').match(/.{1,64}/g)?.join('\n') ?? ''}\n-----END CERTIFICATE-----\n`;
  const key = pair.privateKey.export({ format: 'pem', type: 'pkcs8' });
  const keyPath = join(input, 'server-input.key'), certPath = join(input, 'server-input.pem');
  appendFileSync(join(testRoot('FLUXWARDEN_TEST_TMP'), 'declared-out.txt'), `${keyPath}\n`);
  writeFileSync(keyPath, key, { mode: 0o600, flag: 'wx' });
  writeFileSync(certPath, cert, { mode: 0o600, flag: 'wx' });
  writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `${randomBytes(8).toString('hex')}-tls-key.pem`), key, { mode: 0o600, flag: 'wx' });
  const parsed = new X509Certificate(cert);
  assert.equal(parsed.verify(pair.publicKey), true, 'synthetic CA self-signature');
  for (const hostname of names) assert.equal(parsed.checkHost(hostname), hostname, 'fixture DNS SAN');
  for (const address of ipv4) assert.equal(parsed.checkIP(address), address, 'fixture IP SAN');
  return { cert, key, certPath };
}
