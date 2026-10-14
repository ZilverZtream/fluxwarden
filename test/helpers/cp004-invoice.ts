// Synthetic checksum-valid invoice vectors from the upstream payment-lab offline-reader tests.
// This generator supplies data independently of the product decoder.
export function syntheticInvoice(hash: string, extra: readonly number[] = []): string {
  const charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const hrp = 'lnbcrt';
  let bits = BigInt(`0x${hash}`) << 4n;
  const hashWords: number[] = [];
  for (let index = 0; index < 52; index += 1) {
    hashWords.unshift(Number(bits & 31n));
    bits >>= 5n;
  }
  const words = [...Array<number>(7).fill(22), ...extra, 1, 1, 20, ...hashWords, ...Array<number>(104).fill(22)];
  const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let checksum = 1;
  const expanded = Array.from(hrp).map(char => char.charCodeAt(0) >> 5).concat([0], Array.from(hrp).map(char => char.charCodeAt(0) & 31));
  for (const value of [...expanded, ...words, 0, 0, 0, 0, 0, 0]) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let bit = 0; bit < 5; bit += 1) if ((top >>> bit) & 1) checksum ^= generators[bit] ?? 0;
  }
  checksum ^= 1;
  const checkWords = Array.from({ length: 6 }, (_unused, index) => (checksum >> (5 * (5 - index))) & 31);
  return `${hrp}1${[...words, ...checkWords].map(word => charset.charAt(word)).join('')}`;
}

/** A tagged field: type, 10-bit length and the 32-byte value as 52 words with four padding bits. */
export function hashField(type: number, hash: string): number[] {
  let bits = BigInt(`0x${hash}`) << 4n;
  const words: number[] = [];
  for (let index = 0; index < 52; index += 1) {
    words.unshift(Number(bits & 31n));
    bits >>= 5n;
  }
  return [type, 1, 20, ...words];
}
