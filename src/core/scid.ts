// BOLT 7 short channel ids: `<block>x<tx>x<output>` and the uint64 packing LND names chan_id.

const SCID = /^(0|[1-9][0-9]{0,7})x(0|[1-9][0-9]{0,7})x(0|[1-9][0-9]{0,4})$/;

/** The uint64 channel id of an SCID: block in the top 24 bits, transaction index in the next 24, output in the low 16. */
export function scidToChanId(scid: string): string {
  const match = SCID.exec(scid);
  if (match === null) throw new RangeError('not a short channel id');
  const block = BigInt(match[1] ?? '');
  const tx = BigInt(match[2] ?? '');
  const output = BigInt(match[3] ?? '');
  if (block > 0xFFFFFFn || tx > 0xFFFFFFn || output > 0xFFFFn) throw new RangeError('short channel id out of range');
  return ((block << 40n) | (tx << 16n) | output).toString();
}

/** The SCID packed in a uint64 channel id, or null for the zero id. */
export function chanIdToScid(chanId: string): string | null {
  const id = BigInt(chanId);
  if (id === 0n) return null;
  return `${(id >> 40n).toString()}x${((id >> 16n) & 0xFFFFFFn).toString()}x${(id & 0xFFFFn).toString()}`;
}
