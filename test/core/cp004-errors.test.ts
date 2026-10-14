import { expect, it } from 'vitest';
import { loadCore, type Errors } from '../helpers/cp004-reference.js';

it('CP-004/B4 only documented gRPC refusals are definite and proxy timeouts remain ambiguous', async () => {
  const errors = await loadCore<Errors>('errors');
  const definite = [2, 3, 5, 6, 7, 8, 9, 11, 12, 16];
  const ambiguous = [408, 499, 502, 503, 504];
  for (let code = 0; code <= 16; code += 1) {
    for (const status of [undefined, 200, 400, 404, 408, 499, 500, 502, 503, 504]) {
      const error = new errors.LndError('node refused', code, status);
      expect(errors.definiteRefusal(error), `gRPC ${String(code)} HTTP ${String(status)}`).toBe(definite.includes(code) && !ambiguous.includes(status ?? 0));
      expect(error.notFound).toBe(code === 5);
    }
  }
  for (const status of [400, 404, 408, 499, 500, 502, 503, 504]) {
    expect(errors.definiteRefusal(new errors.LndError('body message', undefined, status))).toBe(status === 400);
    expect(errors.definiteRefusal(new errors.LndError(`HTTP ${String(status)}`, undefined, status))).toBe(false);
  }
  expect(new errors.LndError('Not Found', undefined, 404).notFound).toBe(false);
  for (const error of [new Error('unknown'), new errors.ProtocolError('unreadable'), undefined, {}, 'error']) {
    expect(errors.definiteRefusal(error)).toBe(false);
  }
});

it('CP-004/B9 extracted transport phases and error descriptions preserve reference semantics', async () => {
  const errors = await loadCore<Errors>('errors');
  for (const phase of ['connect', 'request', 'response'] as const) {
    const cause = new Error('transport cause');
    const error = new errors.TransportError('connection ended', phase, { cause });
    expect(error.notDelivered).toBe(phase === 'connect');
    expect(error.cause).toBe(cause);
    expect(errors.definiteRefusal(error)).toBe(false);
    expect(errors.describeError(error)).toBe(`transport error during ${phase}: connection ended`);
  }
  expect(errors.describeError(new errors.LndError('refused', 7, 403))).toBe('LND error (gRPC code 7): refused');
  expect(errors.describeError(new errors.ProtocolError('bad answer'))).toBe('ProtocolError: bad answer');
  expect(errors.describeError('unknown')).toBe('unknown');
});
