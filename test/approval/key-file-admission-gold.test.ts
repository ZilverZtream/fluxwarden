// SECURITY 3 / 5 and SPEC 10.3 LA2/LA4: consume an owner-only regular
// PKCS#8 key within the existing 4 KiB key limit, without changing inputs.
import { createHash, createPrivateKey, generateKeyPairSync, verify } from 'node:crypto';
import fs, { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { loadSource } from '../helpers/adapter-interfaces.js';
import { scratchDir } from '../helpers/cli.js';
import { descriptor, makeOwnerOnlyDir } from '../helpers/cp015-persistence.js';
import { testRoot } from '../helpers/env.js';
import { declareDeliberateOutputs } from '../helpers/output.js';

interface Request {
  proposal: { id: string; nodePubkey: string; sourceChannelKey: string; targetChannelKey: string;
    principalMsat: bigint; maxFeeMsat: bigint; maxFeePpm: bigint; exemptFeeMsat: bigint; maxCltvDelta: number;
    policySha256: string; expiresAt: number };
  policy: { sha256: string; maxFeeMsat: bigint; maxCltvDelta: number; approvalMaxTtlSeconds: number; maxSnapshotAgeSeconds: number };
  keys: { keyId: string; publicKey: string }[];
  snapshotObservedAt: number;
}
interface Signer {
  createApprovalFromKeyFile: (request: Request, path: string, deps: { now(): number; randomBytes(size: number): Uint8Array }) => string;
}
interface Token { proposal_digest: string; policy_sha256: string; approved_max_fee_msat: string;
  approved_max_cltv_delta: string; expires_at: number; nonce: string; key_id: string; signature: string }

const NOW = 1_760_000_000_000;
const LIMIT = 4 * 1024;
afterEach(() => { vi.restoreAllMocks(); syncBuiltinESMExports(); });
const u64 = (value: bigint) => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(value); return bytes; };
const u32 = (value: number) => { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(value); return bytes; };

async function fixture() {
  const signer = await loadSource<Signer>('approval/sign.ts');
  const files = await loadSource<{ writeOwnerOnlyFile: (path: string, bytes: Uint8Array) => string }>('output/private-file.ts');
  const dir = scratchDir('key-file-admission');
  makeOwnerOnlyDir(dir);
  const key = generateKeyPairSync('ed25519');
  const pem = Buffer.from(key.privateKey.export({ format: 'pem', type: 'pkcs8' }));
  const raw = key.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const keyId = createHash('sha256').update(raw).digest('hex').slice(0, 32);
  const registered = join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `key-file-${keyId}.pem`);
  declareDeliberateOutputs([registered]);
  writeFileSync(registered, pem, { mode: 0o600 });
  const request: Request = {
    proposal: { id: 'prop_01JABCDEFGHJKMNPQRSTVWXYZ0', nodePubkey: `03${'ab'.repeat(32)}`,
      sourceChannelKey: '101x1x0', targetChannelKey: '103x1x0', principalMsat: 100_000_000n,
      maxFeeMsat: 300_000n, maxFeePpm: 2500n, exemptFeeMsat: 5000n, maxCltvDelta: 144,
      policySha256: 'cd'.repeat(32), expiresAt: NOW + 900_000 },
    policy: { sha256: 'cd'.repeat(32), maxFeeMsat: 300_000n, maxCltvDelta: 144,
      approvalMaxTtlSeconds: 900, maxSnapshotAgeSeconds: 60 },
    keys: [{ keyId, publicKey: raw.toString('base64') }], snapshotObservedAt: NOW,
  };
  const write = (name: string, bytes: Buffer) => {
    const path = join(dir, name);
    declareDeliberateOutputs([path]);
    expect(files.writeOwnerOnlyFile(path, bytes), 'ordinary private input fixture is created').toBe('written');
    expect(readFileSync(path).byteLength, 'fixture stores the full modeled input length').toBe(bytes.byteLength);
    expect(readFileSync(path).equals(bytes), 'fixture stores exactly the modeled input bytes').toBe(true);
    return path;
  };
  const sign = (path: string, input = request) => signer.createApprovalFromKeyFile(input, path,
    { now: () => NOW, randomBytes: size => new Uint8Array(size).fill(0x37) });
  return { dir, key, keyId, pem, request, write, sign };
}

function verifyReference(tokenText: string, f: Awaited<ReturnType<typeof fixture>>): void {
  const token = JSON.parse(tokenText) as Token;
  const p = f.request.proposal;
  const values = [p.id, p.nodePubkey, p.sourceChannelKey, p.targetChannelKey, p.principalMsat.toString(),
    p.maxFeeMsat.toString(), p.maxFeePpm.toString(), p.exemptFeeMsat.toString(), String(p.maxCltvDelta), p.policySha256, String(p.expiresAt)];
  const digest = createHash('sha256').update(Buffer.concat([Buffer.from('FluxWarden-proposal-v1\0'),
    ...values.flatMap(value => { const bytes = Buffer.from(value); return [u32(bytes.length), bytes]; })])).digest();
  expect(token.proposal_digest).toBe(digest.toString('hex'));
  expect(token.key_id === f.keyId, 'approval signing identity belongs to the admitted file object').toBe(true);
  const message = Buffer.concat([Buffer.from('FluxWarden-approval-v1\0'), digest, Buffer.from(p.policySha256, 'hex'),
    u64(p.maxFeeMsat), u32(p.maxCltvDelta), u64(BigInt(p.expiresAt)), Buffer.alloc(32, 0x37), Buffer.from(f.keyId, 'hex')]);
  expect(verify(null, message, f.key.publicKey, Buffer.from(token.signature, 'hex')), 'configured public key independently verifies the approval').toBe(true);
  expect(tokenText.includes(f.pem.toString('base64')) || tokenText.includes(f.pem.toString('utf8')), 'token contains no private key rendering').toBe(false);
}

it('CP-026/REG-APPR003 an owner-only private file signs only for its configured public key without changing input', async () => {
  const f = await fixture();
  const path = f.write('operator.key', f.pem);
  const permissions = descriptor(path);
  verifyReference(f.sign(path), f);
  let refusal: { exitCode?: number; reason?: string } | null = null;
  try { f.sign(path, { ...f.request, keys: [] }); }
  catch (error) { const e = error as { exitCode?: number; reason?: string }; refusal = { exitCode: e.exitCode, reason: e.reason }; }
  expect(refusal).toEqual({ exitCode: 2, reason: 'UNKNOWN_KEY_ID' });
  expect(readFileSync(path).equals(f.pem), 'input bytes are unchanged').toBe(true);
  expect(descriptor(path), 'input permissions are unchanged').toBe(permissions);
  expect(readdirSync(f.dir)).toEqual(['operator.key']);
});

for (const input of ['directory', 'missing-or-malformed', 'over-limit'] as const) {
  it(`CP-026/REG-APPR003 ${input} signing input refuses INVALID_KEY without changing existing files`, async () => {
    const f = await fixture();
    const kinds = input === 'missing-or-malformed' ? ['missing', 'malformed'] : [input];
    for (const kind of kinds) {
      let path = join(f.dir, `${kind}.key`);
      if (kind === 'directory') mkdirSync(path);
      if (kind === 'malformed') path = f.write(`${kind}.key`, Buffer.from('ordinary non-key input\n'));
      if (kind === 'over-limit') {
        const bytes = Buffer.concat([f.pem, Buffer.alloc(LIMIT + 1 - f.pem.length, 0x20)]);
        expect(createPrivateKey(bytes).asymmetricKeyType).toBe('ed25519');
        path = f.write(`${kind}.key`, bytes);
      }
      const listing = readdirSync(f.dir);
      const permissions = existsSync(path) ? descriptor(path) : null;
      const before = kind === 'malformed' || kind === 'over-limit' ? readFileSync(path) : null;
      let refusal: { name?: string; exitCode?: number; reason?: string } | null = null;
      let producedToken = false;
      try { f.sign(path); producedToken = true; }
      catch (error) { const e = error as { name?: string; exitCode?: number; reason?: string };
        refusal = { name: e.name, exitCode: e.exitCode, reason: e.reason }; }
      expect(producedToken, 'unsuitable input produces no approval token').toBe(false);
      expect(refusal).toEqual({ name: 'ApprovalError', exitCode: 2, reason: 'INVALID_KEY' });
      expect(readdirSync(f.dir)).toEqual(listing);
      if (permissions !== null) expect(descriptor(path), 'refused input permissions are unchanged').toBe(permissions);
      if (before !== null) expect(readFileSync(path).equals(before), 'refused input bytes are unchanged').toBe(true);
    }
  });
}

it('CP-026/REG-APPR003 signing consumes the admitted object or refuses a modeled unbound pathname read', async () => {
  const f = await fixture();
  const path = f.write('admitted.key', f.pem);
  const permissions = descriptor(path);
  const other = generateKeyPairSync('ed25519');
  const otherPem = Buffer.from(other.privateKey.export({ format: 'pem', type: 'pkcs8' }));
  const otherRaw = other.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const otherId = createHash('sha256').update(otherRaw).digest('hex').slice(0, 32);
  const registered = join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `abstract-key-${otherId}.pem`);
  declareDeliberateOutputs([registered]);
  writeFileSync(registered, otherPem, { mode: 0o600 });
  const request = { ...f.request, keys: [...f.request.keys, { keyId: otherId, publicKey: otherRaw.toString('base64') }] };
  const actualRead = fs.readFileSync;
  // Ordinary I/O fault model: the admitted regular object is A. An independent
  // pathname read supplies fictional object B; held-object reads retain A.
  // Both keys are configured so key membership cannot conceal lost binding.
  // This changes no filesystem object and is not native atomicity evidence.
  const modeledRead = ((...args: Parameters<typeof fs.readFileSync>): ReturnType<typeof fs.readFileSync> => {
    const [name, options] = args;
    if (typeof name === 'string' && name === path) {
      const encoding = typeof options === 'string' ? options : options?.encoding;
      return encoding ? otherPem.toString(encoding) : Buffer.from(otherPem);
    }
    return actualRead(...args);
  }) as typeof fs.readFileSync;
  let token: string | undefined;
  let refusal: { name?: string; exitCode?: number; reason?: string } | null = null;
  vi.spyOn(fs, 'readFileSync').mockImplementation(modeledRead);
  syncBuiltinESMExports();
  try {
    try { token = f.sign(path, request); }
    catch (error) { const e = error as { name?: string; exitCode?: number; reason?: string };
      refusal = { name: e.name, exitCode: e.exitCode, reason: e.reason }; }
  } finally { vi.restoreAllMocks(); syncBuiltinESMExports(); }
  if (token === undefined) expect(refusal).toEqual({ name: 'ApprovalError', exitCode: 2, reason: 'INVALID_KEY' });
  else verifyReference(token, f);
  expect(readFileSync(path).equals(f.pem), 'admitted input bytes are unchanged').toBe(true);
  expect(descriptor(path), 'admitted input permissions are unchanged').toBe(permissions);
});
