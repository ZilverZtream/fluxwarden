import type { Command } from '../cli/args.js';
import { backupState, restoreState } from '../persistence/state-archive.js';
import { PersistenceError } from '../persistence/index.js';
import { configStage, StageFailure } from './stages.js';
import { emit } from './workflow.js';
import { refuse, type Io } from './report.js';

export async function stateWorkflow(command: Extract<Command, { kind: 'state backup' | 'state restore' }>, io: Io): Promise<number> {
  try {
    const config = configStage(command.config);
    if (command.kind === 'state backup') {
      await backupState(config.database, config.alertDir, command.out);
      return emit(io, command.kind, { backed_up: true });
    }
    restoreState(command.from, config.database, config.alertDir);
    return emit(io, command.kind, { restored: true, reconciliation_required: true });
  } catch (error) {
    if (error instanceof StageFailure) return refuse(io, command.kind, error.code, error.step, error.message);
    if (error instanceof PersistenceError && (error.code === 'SCHEMA_OUTDATED' || error.code === 'SCHEMA_TOO_NEW')) {
      return refuse(io, command.kind, 5, 'state', 'state: this command requires the current supported database schema; retain the original state and follow the supported upgrade procedure');
    }
    return refuse(io, command.kind, 5, 'state', 'state: backup or restore refused; verify integrity, private permissions, the original signing key and an unused destination');
  }
}
