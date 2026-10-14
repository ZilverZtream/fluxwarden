// `liquidity diagnose`: renders a diagnosis as the --json document (SPEC.md §10.3 item 4).
import { ExitCode } from '../core/exit-codes.js';
import { envelope, renderEnvelope } from '../output/index.js';
import { diagnose, type ChannelDiagnosis, type DiagnoseInput, type Diagnosis } from '../planner/diagnose.js';

const COMMAND = 'liquidity diagnose';

const msat = (value: bigint): string => value.toString();
const optionalMsat = (value: bigint | null): string | null => value === null ? null : value.toString();

function channelRow(row: ChannelDiagnosis): Record<string, unknown> {
  return {
    channel: row.channelKey,
    state: row.state,
    capacity_msat: msat(row.capacityMsat),
    spendable_msat: msat(row.spendableMsat),
    receivable_msat: msat(row.receivableMsat),
    confidence: row.confidence,
    caveat: row.caveat,
    observed_at: row.observedAt,
    snapshot_age_ms: row.snapshotAgeMs,
    block_height: row.blockHeight,
    inbound_target_msat: optionalMsat(row.inboundTargetMsat),
    inbound_deficit_msat: msat(row.inboundDeficitMsat),
    inbound_surplus_msat: msat(row.inboundSurplusMsat),
    outbound_target_msat: optionalMsat(row.outboundTargetMsat),
    outbound_deficit_msat: msat(row.outboundDeficitMsat),
    outbound_surplus_msat: msat(row.outboundSurplusMsat),
  };
}

export function liquidityDiagnose(input: DiagnoseInput): { readonly exitCode: number; readonly json: string } {
  let diagnosis: Diagnosis;
  try {
    diagnosis = diagnose(input);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'diagnosis failed';
    return { exitCode: ExitCode.INVARIANT_BREACH, json: renderEnvelope(envelope(COMMAND, null, { code: ExitCode.INVARIANT_BREACH, step: 'internal', message })) };
  }
  const horizonSeconds = Math.trunc((input.horizonMs ?? input.policy.demand.horizon) / 1000);
  switch (diagnosis.status) {
    case 'STALE_SNAPSHOT': {
      const listed = diagnosis.stale.map(entry => entry.ageMs === null ? `${entry.channelKey} (no snapshot)` : `${entry.channelKey} (${String(entry.ageMs)} ms)`).join(', ');
      const message = `snapshot age outside 0..${String(input.policy.max_snapshot_age)} ms for ${diagnosis.nodeName}: ${listed}`;
      return { exitCode: ExitCode.SAFETY_REFUSAL, json: renderEnvelope(envelope(COMMAND, null, { code: ExitCode.SAFETY_REFUSAL, step: 'STALE_SNAPSHOT', message })) };
    }
    case 'INSUFFICIENT_HISTORY': {
      const evaluatedAt = input.clock.now();
      return {
        exitCode: ExitCode.SUCCESS,
        json: renderEnvelope(envelope(COMMAND, {
          action: 'NO_ACTION', reason: 'INSUFFICIENT_HISTORY', node: diagnosis.nodeName, demand_source: null,
          horizon_seconds: horizonSeconds, evaluated_at: evaluatedAt, channels: [], starved: [], donors: [],
        }, null)),
      };
    }
    case 'OK': {
      const deficit = diagnosis.channels.some(row => row.inboundDeficitMsat > 0n || row.outboundDeficitMsat > 0n);
      return {
        exitCode: ExitCode.SUCCESS,
        json: renderEnvelope(envelope(COMMAND, {
          action: deficit ? 'DEFICIT' : 'NO_ACTION',
          reason: deficit ? null : 'BALANCED_OR_INSUFFICIENT_SURPLUS',
          node: diagnosis.nodeName,
          demand_source: diagnosis.demandSource,
          horizon_seconds: Math.trunc(diagnosis.horizonMs / 1000),
          evaluated_at: diagnosis.evaluatedAt,
          channels: diagnosis.channels.map(channelRow),
          starved: diagnosis.starved,
          donors: diagnosis.donors,
        }, null)),
      };
    }
  }
}
