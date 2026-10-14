import { expect, it } from 'vitest';
import { loadCore, type Encoding } from '../helpers/cp004-reference.js';

// Independent standard byte encodings; upstream helpers retain permissive Buffer decoding semantics.
it('CP-004/B9 hash encodings use exact base64url path bytes and preserve extracted validation', async () => {
  const encoding = await loadCore<Encoding>('encoding');
  const hash = 'ff'.repeat(32);
  const base64 = `${'/'.repeat(42)}8=`;
  const url = `${'_'.repeat(42)}8%3D`;
  expect(encoding.assertHash(hash.toUpperCase())).toBe(hash);
  expect(encoding.hexToBase64(hash)).toBe(base64);
  expect(encoding.base64ToHex(base64)).toBe(hash);
  expect(encoding.base64ToHex(`${'_'.repeat(42)}8`)).toBe(hash);
  expect(encoding.hexToUrlParam(hash)).toBe(url);
  expect(encoding.hexToUrlParam('fb')).toBe('-w%3D%3D');
  expect(encoding.hexToUrlParam('')).toBe('');
  expect(encoding.sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  for (const value of ['', 'f'.repeat(63), 'f'.repeat(65), 'g'.repeat(64)]) {
    expect(() => encoding.assertHash(value), 'invalid hash').toThrow();
  }
  for (const value of ['%%%=', 'Zg===', ' Zg==', 'Z=g=']) {
    expect(() => encoding.base64ToHex(value), 'invalid base64 alphabet').toThrow();
  }
  expect(encoding.presentPreimage('') === undefined, 'absent bytes').toBe(true);
  expect(encoding.presentPreimage('0'.repeat(64)) === undefined, 'zero bytes').toBe(true);
  expect(encoding.presentPreimage('ab'.repeat(32)) === 'ab'.repeat(32), 'present synthetic bytes').toBe(true);
});
