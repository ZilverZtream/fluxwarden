// AUDIT-12: transport failures cannot establish authoritative payment/invoice absence.
// Reference: docs/spec.md Approval/execution/recovery; CP-004 definite-refusal transport precedence.
import { expect, it } from 'vitest';
import { loadCore, type Errors } from '../helpers/cp004-reference.js';
import { loadSrc } from '../helpers/load-src.js';
import type { ExecutionAdapter } from '../helpers/cp030-execution.js';

interface LndExecution {
  LndExecutionAdapter: new (rest: { call: (...args: unknown[]) => Promise<unknown>; stream: (...args: unknown[]) => Promise<never> },
    options: { trackDeadlineMs: number }) => ExecutionAdapter;
}

for (const status of [408, 499, 502, 503, 504]) {
  it(`POST-AUDIT/AUDIT-12/HTTP-${String(status)} gRPC5 in an ambiguous transport error is never native absence`, async () => {
    const errors = await loadCore<Errors>('errors');
    const { LndExecutionAdapter } = await loadSrc<LndExecution>('node-lnd/execute.ts');
    const failure = new errors.LndError('upstream unavailable', 5, status);
    expect.soft(failure.notFound).toBe(false);
    expect(errors.definiteRefusal(failure)).toBe(false);
    const adapter = new LndExecutionAdapter({
      call: (method: unknown) => method === 'POST' ? Promise.resolve({}) : Promise.reject(failure),
      stream: () => Promise.reject(failure),
    }, { trackDeadlineMs: 1_000 });
    // Track communicates uncertainty as an AMBIGUOUS observation.
    expect.soft(await adapter.observePayment('5a'.repeat(32))).toMatchObject({ kind: 'AMBIGUOUS' });
    // Invoice ports cannot encode uncertainty, so they must reject the transport error.
    await expect.soft(adapter.invoiceState('5a'.repeat(32))).rejects.toBeInstanceOf(Error);
    await expect.soft(adapter.cancelUnpaidInvoice('5a'.repeat(32), 'fluxwarden-audit')).rejects.toBeInstanceOf(Error);
  });
}

it('POST-AUDIT/AUDIT-12/native-404 preserves native gRPC5 absence without relying on its message', async () => {
  const errors = await loadCore<Errors>('errors');
  const { LndExecutionAdapter } = await loadSrc<LndExecution>('node-lnd/execute.ts');
  const failure = new errors.LndError('native missing record', 5, 404);
  const adapter = new LndExecutionAdapter({
    call: (method: unknown) => method === 'POST' ? Promise.resolve({}) : Promise.reject(failure),
    stream: () => Promise.reject(failure),
  }, { trackDeadlineMs: 1_000 });
  expect(failure.notFound).toBe(true);
  expect(await adapter.observePayment('5a'.repeat(32))).toEqual({ kind: 'NOT_FOUND' });
  expect(await adapter.invoiceState('5a'.repeat(32))).toBe('NOT_FOUND');
  expect(await adapter.cancelUnpaidInvoice('5a'.repeat(32), 'fluxwarden-audit')).toBe('NOT_FOUND');
});
