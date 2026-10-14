// ULIDs: 48-bit millisecond time and 80 random bits in Crockford base32 (26 characters).
import { randomBytes } from 'node:crypto';

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;

export function ulid(timeMs: number): string {
  if (!Number.isSafeInteger(timeMs) || timeMs < 0 || timeMs >= 2 ** 48) throw new RangeError('ULID time out of range');
  let time = BigInt(timeMs);
  let text = '';
  for (let i = 0; i < 10; i += 1) {
    text = (CROCKFORD[Number(time & 31n)] ?? '0') + text;
    time >>= 5n;
  }
  let random = BigInt(`0x${randomBytes(10).toString('hex')}`);
  let tail = '';
  for (let i = 0; i < 16; i += 1) {
    tail = (CROCKFORD[Number(random & 31n)] ?? '0') + tail;
    random >>= 5n;
  }
  return text + tail;
}
