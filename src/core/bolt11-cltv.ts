/**
 * The minimum final CLTV expiry delta of a BOLT11 payment request (tagged field `c`, type 24), read offline from a
 * checksum-verified bech32 string. BOLT 11: a request without a `c` field asks for 18 blocks.
 */

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const CHECKSUM_WORDS = 6;
const TIMESTAMP_WORDS = 7;
const SIGNATURE_WORDS = 104;
const MAX_LENGTH = 8192;
const MIN_FINAL_CLTV_EXPIRY = 24;
const MAX_VALUE_WORDS = 6;
export const DEFAULT_MIN_FINAL_CLTV_EXPIRY = 18;

function polymod(values: readonly number[]): number {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let bit = 0; bit < 5; bit += 1) if ((top >>> bit) & 1) checksum ^= GENERATOR[bit] ?? 0;
  }
  return checksum;
}

/** The data words of a lower- or upper-case bech32 string with an `ln` prefix, checksum verified and removed. */
function dataWords(paymentRequest: string): number[] | undefined {
  if (paymentRequest.length > MAX_LENGTH || !/^[\x21-\x7e]+$/.test(paymentRequest)) return undefined;
  const lower = paymentRequest.toLowerCase();
  if (lower !== paymentRequest && paymentRequest.toUpperCase() !== paymentRequest) return undefined;
  const separator = lower.lastIndexOf('1');
  if (separator < 1 || lower.length - separator - 1 < CHECKSUM_WORDS) return undefined;
  const hrp = lower.slice(0, separator);
  if (!hrp.startsWith('ln')) return undefined;
  const words: number[] = [];
  for (const char of lower.slice(separator + 1)) {
    const word = CHARSET.indexOf(char);
    if (word < 0) return undefined;
    words.push(word);
  }
  const expanded = Array.from(hrp, char => char.charCodeAt(0) >> 5).concat([0], Array.from(hrp, char => char.charCodeAt(0) & 31));
  if (polymod([...expanded, ...words]) !== 1) return undefined;
  return words.slice(0, -CHECKSUM_WORDS);
}

/** The `c` field as a block count, 18 when absent; undefined when the string is not a well-formed payment request. */
export function minFinalCltvExpiry(paymentRequest: string): number | undefined {
  const words = dataWords(paymentRequest);
  if (words === undefined) return undefined;
  const end = words.length - SIGNATURE_WORDS;
  let position = TIMESTAMP_WORDS;
  if (end < position) return undefined;
  while (position + 3 <= end) {
    const type = words[position] ?? 0;
    const length = (words[position + 1] ?? 0) * 32 + (words[position + 2] ?? 0);
    position += 3;
    if (position + length > end) return undefined;
    if (type === MIN_FINAL_CLTV_EXPIRY) {
      if (length === 0 || length > MAX_VALUE_WORDS) return undefined;
      let value = 0;
      for (const word of words.slice(position, position + length)) value = value * 32 + word;
      return value;
    }
    position += length;
  }
  return position === end ? DEFAULT_MIN_FINAL_CLTV_EXPIRY : undefined;
}
