// D76: expiry blocks new sends, while already-paid evidence remains financial
// truth. Successful invoice acknowledgement after expiry, then ALREADY_PAID at cleanup,
// must recover through ordinary read-only observations without another send.
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { PAYMENT_SECRET, succeeded } from '../fakes/execution-node.js';
import { dbNow, sleep } from '../helpers/cp028-executor.js';
import { prepare, ROUTE_FEE } from '../helpers/cp030-dispatch.js';
import { reservationState, rowOf, sha256 } from '../helpers/cp030-execution.js';
import { approvalMessage } from '../helpers/cpw-cli.js';
import { testRoot } from '../helpers/env.js';
import { loadLedger } from '../helpers/cp037-ledger.js';

it('CP-030/B7 an acknowledged invoice after authority expiry preserves already-paid financial truth without a fresh send', async () => {
  const key = generateKeyPairSync('ed25519');
  const publicBytes = key.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const keyId = createHash('sha256').update(publicBytes).digest('hex').slice(0, 32);
  writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `paid-ack-${keyId}.pem`), key.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
  let expiresAt = 0;
  const r = await prepare('already-paid-ack-expiry', {
    approvalSeed: { approvalKeyId: keyId, approvalTtlMs: 5_000, signApproval: approval => {
      expiresAt = approval.expiresAt;
      const message = approvalMessage({ digest: approval.proposalDigest, policySha256: approval.policySha256,
        maxFeeMsat: approval.approvedMaxFeeMsat, maxCltvDelta: approval.approvedMaxCltvDelta,
        expiresAt: BigInt(approval.expiresAt), nonce: Buffer.from(approval.nonce, 'hex'), keyId });
      const signature = sign(null, message, key.privateKey);
      expect(verify(null, message, key.publicKey, signature)).toBe(true);
      return signature.toString('base64');
    } },
    script: ({ base, path }) => ({
      invoice: async (_amount, preimage) => {
        expect(dbNow(path)).toBeLessThan(expiresAt);
        while (dbNow(path) <= expiresAt) await sleep(25);
        return { paymentHash: sha256(preimage), paymentSecret: PAYMENT_SECRET, finalCltvDelta: 18 };
      },
      // Native LND/CLN refuse an unpaid cancellation after settlement. The
      // acknowledgement succeeded, so this is distinct from lost-ack recovery.
      cancel: () => Promise.resolve('ALREADY_PAID'),
      observe: () => Promise.resolve(succeeded(ROUTE_FEE, 1, true, base.targetKey)),
      invoiceState: () => Promise.resolve('SETTLED'),
    }),
  });
  await r.run();
  expect(rowOf(r.path, r.executionId).status).toBe('VERIFIED_SUCCESS');
  expect(reservationState(r.path, r.executionId)).toEqual({ state: 'CONSUMED', consumed: 150_000n });
  expect(r.node.count('sendOnRoute')).toBe(0);
  expect(r.node.count('createInvoice')).toBe(1);
  expect(r.node.count('cancelUnpaidInvoice')).toBe(1);
  expect(r.node.count('observePayment')).toBeGreaterThanOrEqual(1);
  const m = await loadLedger();
  const book = m.openDatabase(r.path, { readOnly: true });
  try {
    expect(book.ledger.journals().filter(j => j.executionId === r.executionId && j.eventType === 'REBALANCE_SETTLED')).toHaveLength(1);
    expect(m.runLedgerVerify(book).exitCode).toBe(0);
  } finally { book.close(); }
});
