// SPEC §8.1/§8.3 P1/P6 and SECURITY §4.1: expired approved authority
// cannot authorize a fresh send. Expiry uses the database clock; a live
// execution lease and unchanged fence do not prolong an approval/proposal.
import { expect, it } from 'vitest';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { PAYMENT_SECRET } from '../fakes/execution-node.js';
import { dbNow, sleep } from '../helpers/cp028-executor.js';
import { approvalMessage } from '../helpers/cpw-cli.js';
import { testRoot } from '../helpers/env.js';
import { HASH, prepare } from '../helpers/cp030-dispatch.js';
import { exec, labelOf, reservationState, rowOf, sha256 } from '../helpers/cp030-execution.js';

for (const authority of ['approval', 'proposal'] as const) {
  it(`CP-030/B7 a ${authority} expiring during ordinary invoice creation with a live lease is cancelled without dispatch`, async () => {
    const key = generateKeyPairSync('ed25519');
    const publicBytes = key.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    const keyId = createHash('sha256').update(publicBytes).digest('hex').slice(0, 32);
    writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `authority-${authority}-${keyId}.pem`), key.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
    let expiresAt = 0;
    const r = await prepare(`external-expired-${authority}`, {
      approvalSeed: { approvalKeyId: keyId, approvalTtlMs: authority === 'approval' ? 5_000 : 600_000,
        signApproval: approval => {
          expiresAt = approval.expiresAt;
          const message = approvalMessage({ digest: approval.proposalDigest, policySha256: approval.policySha256,
            maxFeeMsat: approval.approvedMaxFeeMsat, maxCltvDelta: approval.approvedMaxCltvDelta,
            expiresAt: BigInt(approval.expiresAt), nonce: Buffer.from(approval.nonce, 'hex'), keyId });
          const signature = sign(null, message, key.privateKey);
          expect(verify(null, message, key.publicKey, signature)).toBe(true);
          return signature.toString('base64');
        } },
      script: ({ path }) => ({ invoice: (_amount, preimage) => {
        if (authority === 'proposal') exec(path, 'UPDATE liquidity_proposals SET expires_at = ?', dbNow(path) - 1_000);
        return (async () => {
          // Approvals are immutable: let the genuine database clock age past
          // its signed expiry during this ordinary bounded await.
          if (authority === 'approval') {
            expect(dbNow(path)).toBeLessThan(expiresAt);
            while (dbNow(path) <= expiresAt) await sleep(25);
          }
          return { paymentHash: sha256(preimage), paymentSecret: PAYMENT_SECRET, finalCltvDelta: 18 };
        })();
      } }),
    });
    const outcome = await r.run();
    expect(r.node.count('sendOnRoute')).toBe(0);
    expect(outcome.step).toBe('APPROVAL_INVALID');
    expect(outcome.exit).toBe(5);
    expect(rowOf(r.path, r.executionId).status).toBe('CANCELLED');
    expect(reservationState(r.path, r.executionId).state).toBe('RELEASED');
    expect(r.node.named('cancelUnpaidInvoice').map(call => call.args)).toEqual([[HASH, labelOf(r.executionId)]]);
  });
}

it('CP-030/B7 still-valid approved authority after ordinary invoice creation dispatches exactly once', async () => {
  const r = await prepare('external-authority-positive-control');
  expect(await r.run()).toMatchObject({ exit: 0, step: null });
  expect(r.node.count('sendOnRoute')).toBe(1);
  expect(rowOf(r.path, r.executionId).status).toBe('VERIFIED_SUCCESS');
});
