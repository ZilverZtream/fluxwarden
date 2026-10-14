import { emitJson, refuse, type Io } from './report.js';
import { nodeText, envelope, renderEnvelope } from '../output/index.js';

export interface LabPort {
  status(): Promise<{ up: boolean; network: string }>;
  channel2ReceivableMsat(): Promise<bigint>;
  checkout(request: { merchant: 'cln-m'; payer: 'lnd-p' | 'cln-p'; channels: readonly number[]; amountMsat: bigint }): Promise<{ status: 'SUCCEEDED' | 'FAILED'; reason: string | null }>;
  scenario(caseId: string): Promise<{ exit: number; status: string; paymentHash: string; sendCount: number }>;
}
export interface FaultPort { apply(caseId: string): Promise<void>; clear(caseId: string): Promise<void> }

async function ready(io: Io, command: string, lab: LabPort): Promise<number | null> {
  const status = await lab.status();
  if (!status.up) return refuse(io, command, 2, 'lab-not-up', 'the disposable lab is not up');
  if (status.network !== 'regtest') return refuse(io, command, 5, 'network-lock', 'the lab must report regtest');
  return null;
}

function report(io: Io, command: string, result: Record<string, unknown>, code = 0): number {
  if (io.json) {
    if (code === 0) return emitJson(io, command, { code, result, error: null, warnings: [] });
    io.output.write('stdout', renderEnvelope({ ...envelope(command, null, { code, step: 'OUTCOME_UNKNOWN', message: 'reconcile the persisted payment hash before further execution' }), result }));
    return code;
  }
  io.output.write('stdout', `${nodeText(JSON.stringify(result), 16384)}\n`);
  return code;
}

export async function labWorkload(io: Io, options: { type: 'checkout'; count: number }, deps: { lab: LabPort }): Promise<number> {
  if (!Number.isSafeInteger(options.count) || options.count < 1 || options.count > 1000) return refuse(io, 'lab workload', 2, 'arguments', 'checkout count must be an integer from 1 to 1000');
  try {
    const refusal = await ready(io, 'lab workload', deps.lab);
    if (refusal !== null) return refusal;
    const before = await deps.lab.channel2ReceivableMsat();
    let successes = 0;
    const rejections: { payer: string; reason: string }[] = [];
    for (let index = 0; index < options.count; index++) {
      const payer = index % 2 === 0 ? 'lnd-p' : 'cln-p';
      const answer = await deps.lab.checkout({ merchant: 'cln-m', payer, channels: payer === 'lnd-p' ? [1, 2] : [4, 5], amountMsat: 10_000_000n });
      if (answer.status === 'SUCCEEDED') successes++;
      else rejections.push({ payer, reason: nodeText(answer.reason ?? 'PAYMENT_FAILED', 256) });
    }
    const after = await deps.lab.channel2ReceivableMsat();
    return report(io, 'lab workload', { type: options.type, attempted: options.count, successes, failures: rejections.length, rejections,
      channel2: { beforeReceivableMsat: before.toString(), afterReceivableMsat: after.toString() } });
  } catch { return refuse(io, 'lab workload', 8, 'workload', 'lab workload observations failed'); }
}

export async function labChaos(io: Io, options: { caseId: string }, deps: { lab: LabPort; faults: FaultPort }): Promise<number> {
  if (options.caseId !== 'T-05') return refuse(io, 'lab chaos', 2, 'arguments', 'the supported named case is T-05');
  try {
    const refusal = await ready(io, 'lab chaos', deps.lab);
    if (refusal !== null) return refusal;
    let result: Awaited<ReturnType<LabPort['scenario']>> | undefined;
    try { await deps.faults.apply(options.caseId); result = await deps.lab.scenario(options.caseId); }
    finally { await deps.faults.clear(options.caseId); }
    if (!/^[a-f0-9]{64}$/.test(result.paymentHash) || result.sendCount !== 1 || result.exit !== 7 || result.status !== 'UNKNOWN') throw new Error('scenario assertion');
    return report(io, 'lab chaos', { caseId: options.caseId, status: result.status, paymentHash: result.paymentHash, sendCount: result.sendCount }, result.exit);
  } catch { return refuse(io, 'lab chaos', 8, 'chaos', 'the fault injection, observation or cleanup failed'); }
}
