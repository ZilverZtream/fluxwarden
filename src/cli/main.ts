// The CLI over argv with injected dependencies. A failure propagates to the caller, which owns the single
// internal-error report and the exit-code precedence in bin.ts.
import { envelope, renderEnvelope, withOutputSecrets, type Output, type RenderOutput } from '../output/index.js';
import { channels } from '../commands/channels.js';
import { doctor } from '../commands/doctor.js';
import { nodesInspect, nodesList } from '../commands/nodes.js';
import { refuse, type Io } from '../commands/report.js';
import { runCollector, systemTimers } from '../daemon/index.js';
import { parseArgs, type Command } from './args.js';
import { connectionSourceRefusal, type Environment } from './connect.js';
import { environmentRefusal, looksLikeCredential } from './environment.js';
import { ExitCode } from './exit-codes.js';
import { keysGenerate } from './keys.js';
import { reportUsageError, USAGE } from './report.js';
import { workflow } from '../commands/workflow.js';
import { recoveryWorkflow } from '../commands/recovery-workflow.js';
import { configStage, databaseStage } from '../commands/stages.js';
import { bootstrapAlerts } from '../daemon/bootstrap.js';
import { recoverPreflight } from '../executor/preflight.js';
import { randomUUID } from 'node:crypto';
import { nodeFailure } from '../commands/handshake.js';
import { runLab } from './lab.js';
import { stateWorkflow } from '../commands/state.js';

export interface Deps {
  readonly output: Output;
  /** The package.json version. */
  readonly version: () => string;
  readonly env?: Environment;
  readonly execArgv?: readonly string[];
  readonly nodeVersion?: string;
  /** Registers how a long-running command stops at the first signal; the second signal ends the process. */
  readonly onGracefulStop?: (stop: () => void) => void;
  /** Publishes established payment safety before a command's remaining observations finish. */
  readonly onSafetyCode?: (code: number) => void;
  /** Output for the daemon's warning lines. */
  readonly daemonOutput?: () => RenderOutput;
}

const CREDENTIAL_ARGUMENT = 'an argument looks like a credential value; credentials are given by file path only (--macaroon-path, --rune-path)';

export function main(argv: readonly string[], deps: Deps): number | Promise<number> {
  return withOutputSecrets(() => mainWithSecrets(argv, deps));
}

function mainWithSecrets(argv: readonly string[], deps: Deps): number | Promise<number> {
  const json = argv.includes('--json');
  // SECURITY.md §3.3: refused before anything else runs, and never echoed.
  if (argv.some(looksLikeCredential)) {
    if (json) {
      deps.output.write('stdout', renderEnvelope(envelope(null, null, { code: ExitCode.INVALID_INPUT, step: 'arguments', message: CREDENTIAL_ARGUMENT })));
    } else {
      deps.output.write('stderr', `fluxwarden: ${CREDENTIAL_ARGUMENT}\n\n${USAGE}`);
    }
    return ExitCode.INVALID_INPUT;
  }
  const parsed = parseArgs(argv);
  switch (parsed.kind) {
    case 'help':
      deps.output.write('stdout', parsed.json ? renderEnvelope(envelope(null, { usage: USAGE }, null)) : USAGE);
      return ExitCode.SUCCESS;
    case 'version': {
      const version = deps.version();
      deps.output.write('stdout', parsed.json ? renderEnvelope(envelope(null, { version }, null)) : `${version}\n`);
      return ExitCode.SUCCESS;
    }
    case 'usage':
      reportUsageError(deps.output, parsed.json, parsed.reason, parsed.command);
      return ExitCode.INVALID_INPUT;
    case 'command':
      return run(parsed.command, deps);
  }
}

function run(command: Command, deps: Deps): number | Promise<number> {
  const io: Io = { output: deps.output, json: command.json };
  const env = deps.env ?? {};
  const refusal = environmentRefusal(env, deps.execArgv ?? []);
  if (refusal !== null) return refuse(io, command.kind, ExitCode.INVALID_INPUT, 'environment', refusal);
  // No node is contacted, so connection settings play no part.
  if (command.kind === 'keys generate') return keysGenerate(command.out, command.json, deps.output);
  if (command.kind === 'state backup' || command.kind === 'state restore') return stateWorkflow(command, io);
  if (command.kind.startsWith('lab ')) {
    const controller = new AbortController();
    deps.onGracefulStop?.(() => { controller.abort(); });
    if (command.kind === 'lab up' || command.kind === 'lab down' || command.kind === 'lab workload' || command.kind === 'lab chaos') return runLab(command, io, env['FLUXWARDEN_LAB_PLAN'], controller.signal);
  }
  const selectsOne = command.kind === 'nodes inspect' || (('node' in command) && command.node !== null) || command.kind === 'actions execute';
  const source = connectionSourceRefusal(selectsOne, command.connection, env);
  if (source !== null) return refuse(io, command.kind, ExitCode.INVALID_INPUT, 'connection', source);
  switch (command.kind) {
    case 'doctor':
      return doctor(io, command.config, deps.nodeVersion ?? process.versions.node);
    case 'nodes list':
      return nodesList(io, command.config);
    case 'nodes inspect':
      return nodesInspect(io, { configPath: command.config, node: command.node, capabilities: command.capabilities, connection: command.connection, env });
    case 'channels':
      return channels(io, { configPath: command.config, node: command.node, sort: command.sort, connection: command.connection, env });
    case 'daemon':
      return daemon(command, deps, io);
    case 'reconcile':
    case 'nodes recover':
    case 'evidence export':
      return recoveryWorkflow(command, io, env);
    default: {
      const controller = new AbortController();
      deps.onGracefulStop?.(() => { controller.abort(); });
      return workflow(command, io, env, controller.signal,
        deps.onSafetyCode === undefined ? {} : { onSafetyCode: deps.onSafetyCode });
    }
  }
}

async function daemon(command: Command, deps: Deps, io: Io): Promise<number> {
  const controller = new AbortController();
  deps.onGracefulStop?.(() => { controller.abort(); });
  const output = deps.daemonOutput?.();
  if (output === undefined) return refuse(io, 'daemon', ExitCode.INVALID_INPUT, null, 'the daemon needs an output channel');
  try {
    return await collectDaemon(command, deps, io, controller, output);
  } finally { await output.finalize(); }
}

async function collectDaemon(command: Command, deps: Deps, io: Io, controller: AbortController, output: RenderOutput): Promise<number> {
  const silent: Io = { json: true, output: { write: () => undefined, wrote: () => false } };
  const recovery: { exitCode: number | null } = { exitCode: null };
  let alerts: ReturnType<typeof bootstrapAlerts> | undefined;
  if (command.kind === 'daemon' && !command.collect) {
    try {
      const config = configStage(command.config);
      const db = databaseStage(config.database, 'existing');
      try {
        const writer = bootstrapAlerts(config);
        alerts = { raise: alert => {
          const raised = writer.raise(alert);
          if (raised === 'written') void output.write(`fluxwarden daemon: alert ${alert.kind}\n`, { stream: 'stderr' }).catch(() => undefined);
          return raised;
        } };
        await recoverPreflight({ db, workerId: randomUUID(), leaseMs: 60_000 });
      } finally { db.close(); }
    } catch (error) {
      const failure = nodeFailure(error);
      return refuse(io, 'daemon', failure?.code ?? 8, failure?.step ?? 'alerts', failure?.message ?? 'daemon alert bootstrap failed');
    }
  }
  const stopped = (): boolean => controller.signal.aborted;
  const result = await runCollector({ configPath: command.config, timers: systemTimers(), signal: controller.signal, output,
    ...((command.kind !== 'daemon' || command.collect) ? {} : { onCycle: async (cycle: { nodes: readonly { name: string; state: string }[] }) => {
      for (const node of cycle.nodes) {
        if (node.state !== 'ONLINE' || controller.signal.aborted) continue;
        const code = await workflow({ ...command, kind: 'liquidity plan', node: node.name, horizon: null, policy: null, refresh: false }, silent, deps.env ?? {}, controller.signal);
        if (code !== ExitCode.SUCCESS && !stopped()) {
          await output.write(`fluxwarden daemon: warning planning-failed ${node.name} (exit ${String(code)})\n`, { stream: 'stderr' });
        }
      }
      if (!stopped()) {
        const config = configStage(command.config);
        const db = databaseStage(config.database, 'existing');
        try { await recoverPreflight({ db, workerId: randomUUID(), leaseMs: 60_000 }); } finally { db.close(); }
        for (const node of cycle.nodes) {
          if (node.state !== 'ONLINE' || stopped()) continue;
          let code: number;
          try {
            code = await recoveryWorkflow({ ...command, kind: 'reconcile', node: node.name, since: null, until: null }, silent, deps.env ?? {}, alerts);
          } catch {
            // Alert persistence failures and other internal errors stop the safety loop.
            code = ExitCode.INVARIANT_BREACH;
          }
          if (code !== ExitCode.SUCCESS) {
            await output.write(`fluxwarden daemon: warning recovery-failed ${node.name} (exit ${String(code)})\n`, { stream: 'stderr' });
            if (code !== ExitCode.NODE_UNREACHABLE && code !== ExitCode.OUTCOME_UNKNOWN && code !== ExitCode.RECONCILIATION_ALERT) {
              recovery.exitCode = code;
              controller.abort();
              break;
            }
          }
        }
      }
    } }),
  });
  const exitCode = recovery.exitCode ?? result.exitCode;
  if (command.json) {
    const error = exitCode === ExitCode.SUCCESS ? null : { code: exitCode, step: null, message: 'the collector stopped; see the lines on stderr' };
    deps.output.write('stdout', renderEnvelope(envelope('daemon', { cycles: result.cycles }, error)));
  }
  return exitCode;
}
