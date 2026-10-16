// Interface: existing diagnose and plan ports in test/helpers/cp020-planner.ts.
import { expect, it } from 'vitest';
import { channel, diagnoseModule, fixedClock, NODE, NOW, ok, planModule, policy } from '../helpers/cp020-planner.js';

const S = '110x1x0';
const T = '120x1x0';

for (const observedAt of [NaN, Infinity, -Infinity, NOW - 0.5]) {
  it(`CP-020/B1 REG-PLAN003 refuses invalid observation time ${String(observedAt)} (INV-06)`, async () => {
    const { diagnose } = await diagnoseModule();
    const result = diagnose({ nodeName: NODE, channels: [channel(S, { capacity: 500_000_000n, spendable: 400_000_000n, receivable: 100_000_000n, observedAt })],
      policy: policy({ [NODE]: { [S]: { min_inbound_msat: 150_000_000n } } }), horizonMs: null, clock: fixedClock() });
    expect(result.status).toBe('STALE_SNAPSHOT');
    if (result.status === 'STALE_SNAPSHOT') expect(result.stale.map(row => row.channelKey)).toEqual([S]);
  });
}

it('CP-020/B1 REG-PLAN003 accepts the exact integer freshness boundary (INV-06)', async () => {
  const { diagnose } = await diagnoseModule();
  const result = diagnose({ nodeName: NODE, channels: [channel(S, { capacity: 500_000_000n, spendable: 400_000_000n, receivable: 100_000_000n, observedAt: NOW - 60_000 })],
    policy: policy({ [NODE]: { [S]: { min_inbound_msat: 150_000_000n } } }), horizonMs: null, clock: fixedClock() });
  expect(result.status).toBe('OK');
});

for (const c of [
  { name: 'outbound minimum', outbound: 100_000_000n, reserve: 50_000_000n, fee: 300_000n, principal: 50_000_000n },
  { name: 'larger worst-case fee', outbound: 100_000_000n, reserve: 50_000_000n, fee: 1_300_000n, principal: 49_000_000n },
  { name: 'absent outbound target', outbound: undefined, reserve: 50_000_000n, fee: 300_000n, principal: 100_000_000n },
  { name: 'already limiting reserve', outbound: 75_000_000n, reserve: 120_000_000n, fee: 300_000n, principal: 30_000_000n },
] as const) {
  it(`CP-021/B1 REG-PLAN002 sizes principal with ${c.name} preserved after worst-case fees (INV-14)`, async () => {
    // Required outbound liquidity and the policy reserve both survive principal plus the permitted fee.
    const pol = policy({ [NODE]: { [S]: { min_inbound_msat: 150_000_000n,
      ...(c.outbound === undefined ? {} : { min_outbound_msat: c.outbound }) } } }, {
      fees: { max_fee_msat: c.fee, max_fee_ppm: 20_000n, exempt_fee_msat: 5_000n },
      amounts: { min_channel_reserve_msat: c.reserve, max_principal_msat: 100_000_000n, min_principal_msat: 10_000_000n },
    });
    const { diagnose } = await diagnoseModule();
    const diagnosis = ok(diagnose({ nodeName: NODE, channels: [
      channel(S, { capacity: 180_300_000n, spendable: 150_300_000n, receivable: 30_000_000n }),
      channel(T, { capacity: 400_000_000n, spendable: 70_000_000n, receivable: 330_000_000n }),
    ], policy: pol, horizonMs: null, clock: fixedClock() }));
    const { plan } = await planModule();
    expect(plan({ diagnosis, policy: pol, cooldowns: [], reservations: [], inFlight: 0, clock: fixedClock() })).toEqual({
      action: 'CANDIDATES', reason: null, refusals: [], candidates: [{ sourceChannel: S, targetChannel: T, principalMsat: c.principal }],
    });
  });
}
