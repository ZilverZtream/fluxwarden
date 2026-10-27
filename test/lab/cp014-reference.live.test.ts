/*
Reference checks against the pinned regtest lab. The lab tooling writes, at one block height, under
$FLUXWARDEN_LAB_CAPTURE_DIR:
  lnd-r/getinfo.json, lnd-r/listchannels.json        (`lncli getinfo`, `lncli listchannels`)
  cln-m/getinfo.json, cln-m/listpeerchannels.json    (`lightning-cli getinfo`, `lightning-cli listpeerchannels`)
  lnd-r/spendable-probe.json                          ([{ chan_id, accepted_msat, refused_msat }]: the largest single-HTLC
                                                       amount LND-R accepted as first hop over each channel and the
                                                       smallest it refused, probed with SendToRouteV2 and a random hash)
Interface: src/core/normalize.ts as in test/core/cp014-normalize.test.ts.
*/
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { loadCore } from '../helpers/cp004-reference.js';
import { currentPlannerCapture } from '../helpers/live-profile.js';

interface Ctx { nodeId: string; observedAt: number; blockHeight: number }
interface Channel {
  channelKey: string; spendableMsat: bigint; receivableMsat: bigint; localBalanceMsat: bigint; remoteBalanceMsat: bigint;
  confidence: string; blockHeight: number;
}
interface Normalize { normalizeLndChannel(raw: unknown, ctx: Ctx): Channel; normalizeClnChannel(raw: unknown, ctx: Ctx): Channel }

function capture(name: string): unknown {
  const dir = currentPlannerCapture();
  return JSON.parse(readFileSync(join(dir, name), 'utf8')) as unknown;
}
const record = (value: unknown): Record<string, unknown> => value as Record<string, unknown>;
const amount = (value: unknown): bigint => BigInt(String(value).replace(/msat$/, ''));

// The live captures are a validation input. The lab config selects this file only when a validation plan is
// supplied (decision D53); without the capture directory every case then fails closed.
it('CP-014/R1 CLN-M listpeerchannels figures pass through the normalizer unchanged at the captured height', async () => {
  const normalize = await loadCore<Normalize>('normalize');
  const height = Number(record(capture('cln-m/getinfo.json'))['blockheight']);
  const channels = record(capture('cln-m/listpeerchannels.json'))['channels'] as Record<string, unknown>[];
  expect(channels.length).toBeGreaterThan(0);
  for (const raw of channels) {
    const n = normalize.normalizeClnChannel(raw, { nodeId: 'cln-m', observedAt: Date.now(), blockHeight: height });
    expect(n.spendableMsat).toBe(amount(raw['spendable_msat']));
    expect(n.receivableMsat).toBe(amount(raw['receivable_msat']));
    expect(n.confidence).toBe('NODE_REPORTED');
    expect(n.blockHeight).toBe(height);
  }
});

it('CP-014/R1 LND-R live channels normalize to bounded DERIVED_ESTIMATE figures', async () => {
  const normalize = await loadCore<Normalize>('normalize');
  const height = Number(record(capture('lnd-r/getinfo.json'))['block_height']);
  const channels = record(capture('lnd-r/listchannels.json'))['channels'] as Record<string, unknown>[];
  expect(channels.length).toBeGreaterThan(0);
  for (const raw of channels) {
    const n = normalize.normalizeLndChannel(raw, { nodeId: 'lnd-r', observedAt: Date.now(), blockHeight: height });
    expect(n.confidence).toBe('DERIVED_ESTIMATE');
    expect(n.localBalanceMsat).toBe(amount(raw['local_balance']) * 1000n);
    expect(n.spendableMsat <= n.localBalanceMsat).toBe(true);
    expect(n.receivableMsat <= n.remoteBalanceMsat).toBe(true);
  }
});

// D29 conservative-spendable reference resolution; pinned LND 390b2d2b:
// lnwallet/channel.go:3763,9210,9250 and rpcserver.go:5020-5069. The opener
// margin is conservative; only the measured native maximum has an adjacent refusal.
it('CP-014/R2 LND-R accepts the conservative derived spendable and proves an adjacent native refusal boundary', async () => {
  const normalize = await loadCore<Normalize>('normalize');
  const height = Number(record(capture('lnd-r/getinfo.json'))['block_height']);
  const channels = record(capture('lnd-r/listchannels.json'))['channels'] as Record<string, unknown>[];
  const probes = capture('lnd-r/spendable-probe.json') as { chan_id: string; accepted_msat: string; refused_msat: string }[];
  const observations = record(capture('capture-receipt.json'))['observations'] as unknown[];
  expect(probes.length).toBeGreaterThan(0);
  for (const probe of probes) {
    const raw = channels.find(c => c['chan_id'] === probe.chan_id);
    expect(raw, probe.chan_id).toBeDefined();
    const n = normalize.normalizeLndChannel(raw, { nodeId: 'lnd-r', observedAt: Date.now(), blockHeight: height });
    expect(n.spendableMsat <= BigInt(probe.accepted_msat), `REFERENCE_CONFLICT CP-014/R2 unsafe declaration ${probe.chan_id}`).toBe(true);
    expect(BigInt(probe.refused_msat), `native adjacent refusal ${probe.chan_id}`).toBe(BigInt(probe.accepted_msat) + 1n);
    for (const observedAmount of [n.spendableMsat.toString(), probe.accepted_msat]) {
      expect(observations, `actual declared/boundary acceptance ${probe.chan_id}`).toContainEqual({ chan_id: probe.chan_id, amount_msat: observedAmount, status: 'FAILED', failure: { code: 'INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS', failure_source_index: 1 }, outcome: 'accepted' });
    }
    expect(observations.some(value => {
      const observed = record(value), failure = record(observed['failure']);
      return observed['chan_id'] === probe.chan_id && observed['amount_msat'] === probe.refused_msat && observed['status'] === 'FAILED' && observed['outcome'] === 'refused' && failure['failure_source_index'] === 0 && typeof failure['code'] === 'string';
    }), `actual local refusal ${probe.chan_id}`).toBe(true);
  }
});
