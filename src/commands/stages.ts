// The common steps G3 and G4 (SPEC.md §10.3): load the configuration and open the database.
import { ExitCode } from '../core/exit-codes.js';
import { ConfigError, ConfigNetworkError, loadConfig, loadTargets, type Config, type Targets } from '../config/config.js';
import { openDatabase, PersistenceError, type Database } from '../persistence/index.js';
import { ConnectionError } from '../cli/connect.js';

/** A step failed before any node was contacted. */
export class StageFailure extends Error {
  readonly code: number;
  readonly step: string | null;

  constructor(code: number, step: string | null, message: string) {
    super(message);
    this.name = 'StageFailure';
    this.code = code;
    this.step = step;
  }
}

export function configStage(path: string, mutating = false): Config {
  try {
    return loadConfig(path);
  } catch (error) {
    // SPEC §5.2 H4 / §11.6 T-01: reject a configured execution network before credential reads.
    if (mutating && error instanceof ConfigNetworkError) throw new StageFailure(ExitCode.SAFETY_REFUSAL, 'network-lock', error.message);
    if (error instanceof ConfigError) throw new StageFailure(ExitCode.INVALID_INPUT, 'config', error.message);
    throw error;
  }
}

export function targetsStage(config: Config): Targets {
  try {
    return loadTargets(config.policy);
  } catch (error) {
    if (error instanceof ConfigError) throw new StageFailure(ExitCode.INVALID_INPUT, 'policy', error.message);
    throw error;
  }
}

const OPEN_FAILURES = new Set(['SCHEMA_TOO_NEW', 'SCHEMA_OUTDATED', 'NOT_FOUND', 'UNSAFE_PATH', 'BUSY']);

/** Opens the database; `create` only for the commands that create it (doctor). */
export function databaseStage(path: string, mode: 'create' | 'existing' | 'read'): Database {
  try {
    return openDatabase(path, mode === 'read' ? { readOnly: true } : { readOnly: false, mustExist: mode === 'existing' });
  } catch (error) {
    if (error instanceof PersistenceError && OPEN_FAILURES.has(error.code)) {
      const hint = error.code === 'NOT_FOUND' ? '; run fluxwarden doctor to create it' : '';
      throw new StageFailure(ExitCode.INVALID_INPUT, 'database', `${error.message}${hint}`);
    }
    const code = (error as { code?: unknown } | null)?.code;
    if (!(error instanceof PersistenceError) && typeof code === 'string' && /^E[A-Z]+$/.test(code)) {
      throw new StageFailure(ExitCode.INVALID_INPUT, 'database', `the database could not be opened (${code})`);
    }
    throw error;
  }
}

/** A ConnectionError as the refusal it is: invalid input, before any credential is read. */
export function connectionStage<T>(work: () => T): T {
  try {
    return work();
  } catch (error) {
    if (error instanceof ConnectionError) throw new StageFailure(ExitCode.INVALID_INPUT, 'connection', error.message);
    throw error;
  }
}
