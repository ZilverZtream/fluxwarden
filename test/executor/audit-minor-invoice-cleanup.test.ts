// Interface: ordinary dispatch and expired-preflight recovery ports; invoices remain tied to the persisted hash.
import { expect, it } from 'vitest';
import { ScriptedExecutionNode } from '../fakes/execution-node.js';
import { loadPersistence, reservationsOf, scratchDb, seedBase, type ExecDatabase } from '../helpers/cp028-executor.js';
import { prepare } from '../helpers/cp030-dispatch.js';
import { labelOf, rowOf, seedExecution, type ExecutionAdapter } from '../helpers/cp030-execution.js';
import { loadSrc } from '../helpers/load-src.js';

it('CP-030/B1 REG-EXEC004 a lost invoice-create answer is looked up and its unpaid owned invoice cleaned without sending', async () => {
  const r = await prepare('lost-invoice-answer', { script: () => ({ invoice: () => Promise.reject(new Error('ordinary lost acknowledgement')),
    invoiceState: () => Promise.resolve('OPEN'), cancel: () => Promise.resolve('CANCELED') }) });
  const result = await r.run();
  expect(result.exit).toBe(5);
  const stored = rowOf(r.path, r.executionId);
  expect(stored.status).toBe('CANCELLED');
  expect(stored.payment_hash).toMatch(/^[0-9a-f]{64}$/);
  expect(r.node.count('createInvoice')).toBe(1);
  expect(r.node.named('invoiceState').map(call => call.args[0])).toContain(stored.payment_hash);
  expect(r.node.named('cancelUnpaidInvoice').map(call => call.args)).toEqual([[stored.payment_hash, labelOf(r.executionId)]]);
  expect(r.node.count('sendOnRoute')).toBe(0);
  expect(reservationsOf(r.path, r.executionId).map(reservation => reservation.state)).toEqual(['RELEASED']);
});

interface RecoveryModule {
  readonly recoverPreflight: (deps: { db: ExecDatabase; adapter: ExecutionAdapter; workerId: string; leaseMs: number }) => Promise<{ cancelled: readonly string[] }>;
}

it('CP-029/B3 REG-EXEC013 expired predispatch recovery cancels truthfully and cleans its open owned invoice', async () => {
  const p = await loadPersistence();
  const path = scratchDb('expired-owned-invoice');
  const base = seedBase(p, path);
  const hash = 'ab'.repeat(32);
  const seeded = seedExecution(base, { status: 'PREFLIGHT', paymentHash: hash, leaseInMs: -1_000,
    proposalOptions: { approvalTtlMs: -1_000, proposalTtlMs: -1_000 } });
  const adapter = new ScriptedExecutionNode({ invoiceState: () => Promise.resolve('OPEN'), cancel: () => Promise.resolve('CANCELED') });
  const { recoverPreflight } = await loadSrc<RecoveryModule>('executor/preflight.ts');
  const db = p.openDatabase(path, { readOnly: false });
  try {
    const result = await recoverPreflight({ db, adapter, workerId: 'cleanup-worker', leaseMs: 60_000 });
    expect(result.cancelled).toEqual([seeded.executionId]);
    expect(rowOf(path, seeded.executionId)).toMatchObject({ status: 'CANCELLED', payment_hash: hash });
    expect(adapter.named('cancelUnpaidInvoice').map(call => call.args)).toEqual([[hash, labelOf(seeded.executionId)]]);
    expect(adapter.count('createInvoice')).toBe(0);
    expect(adapter.count('sendOnRoute')).toBe(0);
    expect(reservationsOf(path, seeded.executionId).map(reservation => reservation.state)).toEqual(['RELEASED']);
  } finally { db.close(); }
});
