import type { Command } from './args.js';
import type { Io } from '../commands/report.js';
import { refuse } from '../commands/report.js';
import { labWorkload, labChaos } from '../commands/lab.js';
import { emit } from '../commands/workflow.js';
import type { Stream } from '../output/index.js';

export async function runLab(command: Extract<Command, { kind: 'lab up' | 'lab down' | 'lab workload' | 'lab chaos' }>, io: Io, plan: string | undefined, signal: AbortSignal): Promise<number> {
  if (!plan) return refuse(io, command.kind, 2, 'lab-not-up', 'an owned disposable lab declaration is required in FLUXWARDEN_LAB_PLAN');
  if (command.kind === 'lab workload' && (command.type !== 'checkout' || (command.count !== null && !/^[1-9][0-9]{0,3}$/.test(command.count)))) return refuse(io, command.kind, 2, 'arguments', '--type checkout and a positive --count are required');
  if (command.kind === 'lab chaos' && command.caseId !== 'T-05') return refuse(io, command.kind, 2, 'arguments', '--case T-05 is required');
  if ('seed' in command && command.seed !== null && !/^(0|[1-9][0-9]{0,9})$/.test(command.seed)) return refuse(io, command.kind, 2, 'arguments', '--seed must be a nonnegative integer');
  let opened = false;
  try {
    const { createRuntimeLab } = await import('../../labs/docker/demo/runtime.mjs');
    const runtime = await createRuntimeLab({ planPath: plan, configPath: command.config, signal });
    opened = true;
    const writes: { stream: Stream; text: string }[] = [];
    const buffered: Io = { json: io.json, output: { write: (stream, text) => { writes.push({ stream, text }); }, wrote: stream => writes.some(write => write.stream === stream) } };
    let code: number;
    try {
      if (command.kind === 'lab workload') code = await labWorkload(buffered, { type: 'checkout', count: command.count === null ? 10 : Number(command.count) }, { lab: runtime.lab });
      else if (command.kind === 'lab chaos') code = await labChaos(buffered, { caseId: 'T-05' }, runtime);
      else {
        const result = command.kind === 'lab up' ? await runtime.up(command.seed) : await runtime.down();
        code = emit(buffered, command.kind, result);
      }
    } finally { await runtime.close(); }
    for (const write of writes) io.output.write(write.stream, write.text);
    return code;
  } catch { return opened ? refuse(io, command.kind, 8, 'lab-operation', 'the lab operation or cleanup failed') : refuse(io, command.kind, 2, 'lab-not-up', 'the source-checkout lab driver or owner declaration is unavailable'); }
}
