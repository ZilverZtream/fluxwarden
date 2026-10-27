export const spendableReferences: string[];
export function firstHopSetup(entry: bigint, feeCap: bigint, reserve: bigint, reverseSpendable: bigint): {
  principal: bigint; healthy: bigint; topUp: bigint; afterTopUp: bigint; maxDrain: bigint;
};
export function observedLndSpendable(channel: Record<string, unknown>): {
  confidence: string; spendableMsat: bigint; fields: Record<string, bigint>; references: string[];
};
