// The snapshot collector of `fluxwarden daemon --collect` (SPEC.md §10.4 DM1, DM2, DM4, DM6). Cadence, backoff
// and timeouts run on the injected monotonic clock; stored times come from the database clock. Only read calls
// are made (INV-02).
import { checkIdentity, IdentityRefusal, type NodeProbeUpdate, type ProbeContext } from '../core/capabilities.js';
import { ExitCode } from '../core/exit-codes.js';
import type { NodeReader } from '../core/node.js';
import { ConfigError, loadConfig, type Config, type NodeConfig } from '../config/config.js';
import { openDatabase, PersistenceError, type Database } from '../persistence/index.js';
import { nodeText, type RenderOutput } from '../output/index.js';
import { openReader } from '../cli/connect.js';
import { nodeFailure } from '../commands/handshake.js';

export interface CollectorTimers {
  /** Milliseconds that never step (production: performance.now()). */
  monotonic(): number;
  /** Milliseconds since the epoch, may step (production: Date.now()); never used for cadence, backoff or timeouts. */
  wall(): number;
  /** Waits `ms` of monotonic time; resolves early, never rejects, when `signal` aborts. */
  sleep(ms: number, signal: AbortSignal): Promise<void>;
}

export type CollectorNodeState = 'ONLINE' | 'OFFLINE' | 'QUARANTINED' | 'NOT_SYNCED';

export interface CollectorNodeReport {
  name: string;
  state: CollectorNodeState;
  /** Snapshots stored for the node in this cycle. */
  channels: number;
  /** Payment entries read in this cycle. */
  payments: number;
  /** The payment listing stopped at its page bound with more entries remaining. */
  incomplete: boolean;
}

export interface CollectorCycle { cycle: number; startedAt: number; nodes: CollectorNodeReport[] }

export interface CollectorOptions {
  configPath: string;
  timers: CollectorTimers;
  /** Abort: finish the current cycle, then resolve. */
  signal: AbortSignal;
  output: RenderOutput;
  onCycle?: (cycle: CollectorCycle) => void | Promise<void>;
}

export interface CollectorResult { cycles: number; exitCode: number }

/** Payment and forward pages: 500 entries per page and 200 pages per cycle (SECURITY.md §5). */
export const PAYMENT_PAGE_SIZE = 500;
export const PAYMENT_PAGES_PER_CYCLE = 200;
/** Reads back off from 1 s to 15 s (SECURITY.md §5). */
export const BACKOFF_MIN_MS = 1000;
export const BACKOFF_MAX_MS = 15_000;

interface Slot {
  readonly node: NodeConfig;
  /** null until the first attempt. */
  state: CollectorNodeState | null;
  reader: NodeReader | null;
  rowId: string | null;
  /** The next read starts with a full handshake. */
  probe: boolean;
  failures: number;
  /** Monotonic time of the next attempt while OFFLINE. */
  retryAt: number | null;
  paymentsCursor: bigint;
  quarantineWarned: boolean;
}

/** Ends the run: an identity mismatch (INV-12) or a node whose identity another configured node already holds. */
class Abort extends Error {
  constructor(readonly exitCode: number, message: string) {
    super(message);
    this.name = 'Abort';
  }
}

export function backoffMs(failures: number): number {
  return Math.min(BACKOFF_MAX_MS, BACKOFF_MIN_MS * 2 ** Math.min(Math.max(0, failures - 1), 10));
}

class Collector {
  readonly #config: Config;
  readonly #db: Database;
  readonly #options: CollectorOptions;
  readonly #slots: Slot[];

  constructor(config: Config, db: Database, options: CollectorOptions) {
    this.#config = config;
    this.#db = db;
    this.#options = options;
    this.#slots = config.nodes.map(node => ({ node, state: null, reader: null, rowId: null, probe: true, failures: 0, retryAt: null, paymentsCursor: 0n, quarantineWarned: false }));
  }

  #warn(code: string, node: string, detail?: string): void {
    const suffix = detail === undefined ? '' : `: ${nodeText(detail, 1024)}`;
    void this.#options.output.write(`fluxwarden daemon: warning ${code} ${node}${suffix}\n`, { stream: 'stderr' }).catch(() => undefined);
  }

  #enter(slot: Slot, state: CollectorNodeState, detail?: string): void {
    const previous = slot.state;
    slot.state = state;
    if (previous === state) return;
    if (state === 'OFFLINE') this.#warn('node-offline', slot.node.name, detail);
    else if (state === 'NOT_SYNCED') this.#warn('node-not-synced', slot.node.name);
    else if (state === 'ONLINE' && previous === 'OFFLINE') this.#warn('node-online', slot.node.name);
  }

  /** The handshake context of a node: outcomes are recorded on its row (SPEC.md §5.2 H3, H8). */
  #context(slot: Slot, onHeld: (name: string) => void): ProbeContext {
    const { node } = slot;
    return {
      nodeId: node.name, expectedPubkey: node.expectedPubkey, expectedNetwork: node.expectedNetwork, mutating: false,
      nowMs: () => this.#options.timers.wall(),
      store: {
        recordProbe: (update: NodeProbeUpdate): Promise<void> => {
          const recorded = this.#db.nodes.recordProbe({
            name: node.name, implementation: node.implementation, expectedPubkey: node.expectedPubkey, state: update.state,
            observedVersion: update.observedVersion, capabilities: update.capabilities,
          });
          if ('id' in recorded) {
            slot.rowId = recorded.id;
            if (recorded.quarantined && !slot.quarantineWarned) {
              slot.quarantineWarned = true;
              this.#warn('node-quarantined', node.name, 'stays quarantined from an earlier refusal; a successful read does not lift it');
            }
          } else onHeld(recorded.heldBy);
          return Promise.resolve();
        },
      },
    };
  }

  /** The node's identity call (a full handshake after a failure), then its channel listing and payment pages. */
  async #attempt(slot: Slot): Promise<CollectorNodeReport> {
    const { node } = slot;
    const report = (state: CollectorNodeState, channels = 0, payments = 0, incomplete = false): CollectorNodeReport =>
      ({ name: node.name, state, channels, payments, incomplete });
    let channels = 0;
    try {
      slot.reader ??= await openReader(node, { endpoint: node.endpoint, tlsCertPath: node.tlsCertPath, credentialPath: node.credentialPath });
      const reader = slot.reader;
      let synced: boolean;
      let blockHeight: number;
      if (slot.probe) {
        const held: { by: string | null } = { by: null };
        const { result } = await reader.probe(this.#context(slot, name => { held.by = name; }));
        if (held.by !== null) throw new Abort(ExitCode.INVALID_INPUT, `${node.name} has the expected identity of ${held.by}; give each node its own expected_pubkey`);
        slot.probe = false;
        synced = result.identity.syncedToChain;
        blockHeight = result.identity.blockHeight;
      } else {
        const info = await reader.info();
        await checkIdentity(node.implementation, info, this.#context(slot, () => undefined));
        synced = info.syncedToChain;
        blockHeight = info.blockHeight;
      }
      if (!synced) {
        slot.failures = 0;
        slot.retryAt = null;
        this.#enter(slot, 'NOT_SYNCED');
        return report('NOT_SYNCED');
      }
      const rowId = slot.rowId;
      if (rowId === null) throw new Error('a probed node has no row');
      const listed = await reader.listChannels({ nodeId: rowId, observedAt: this.#options.timers.wall(), blockHeight });
      this.#db.snapshots.storeAll(listed);
      channels = listed.length;
      let payments = 0;
      let pages = 0;
      let incomplete = false;
      for (;;) {
        if (pages === PAYMENT_PAGES_PER_CYCLE || this.#options.signal.aborted) { incomplete = true; break; }
        const page = await reader.paymentsPage(slot.paymentsCursor, PAYMENT_PAGE_SIZE);
        pages += 1;
        payments += page.count;
        slot.paymentsCursor = page.cursor;
        if (page.count < PAYMENT_PAGE_SIZE) break;
      }
      slot.failures = 0;
      slot.retryAt = null;
      this.#enter(slot, 'ONLINE');
      return report('ONLINE', channels, payments, incomplete);
    } catch (error) {
      if (error instanceof Abort) throw error;
      if (error instanceof IdentityRefusal) throw new Abort(ExitCode.SAFETY_REFUSAL, error.message);
      if (error instanceof PersistenceError && error.code === 'BUSY') {
        this.#warn('database-busy', node.name, error.message);
        return report(slot.state ?? 'OFFLINE', 0);
      }
      const failure = nodeFailure(error);
      if (failure === null) throw error;
      slot.failures += 1;
      slot.retryAt = this.#options.timers.monotonic() + backoffMs(slot.failures);
      slot.probe = true;
      // SPEC.md §5.2 H1 runs again on the next handshake, so a rotated credential or re-pinned certificate is read.
      slot.reader = null;
      this.#db.nodes.markOffline(node.name);
      this.#enter(slot, 'OFFLINE', failure.message);
      return report('OFFLINE', channels);
    }
  }

  #due(slot: Slot, now: number): boolean {
    return slot.state !== 'OFFLINE' || slot.retryAt === null || slot.retryAt <= now;
  }

  async run(): Promise<CollectorResult> {
    const { timers, signal } = this.#options;
    const interval = this.#config.collectIntervalMs;
    let cycles = 0;
    let nextCycle = timers.monotonic();
    const stopped = (): boolean => signal.aborted;
    try {
      while (!stopped()) {
        const now = timers.monotonic();
        if (now >= nextCycle) {
          cycles += 1;
          const nodes: CollectorNodeReport[] = [];
          for (const slot of this.#slots) {
            nodes.push(this.#due(slot, now) ? await this.#attempt(slot) : { name: slot.node.name, state: 'OFFLINE', channels: 0, payments: 0, incomplete: false });
          }
          await this.#options.onCycle?.({ cycle: cycles, startedAt: now, nodes });
          nextCycle += interval;
          const after = timers.monotonic();
          if (nextCycle <= after) nextCycle += Math.ceil((after - nextCycle + 1) / interval) * interval;
        } else {
          for (const slot of this.#slots) {
            if (slot.state === 'OFFLINE' && slot.retryAt !== null && slot.retryAt <= now) await this.#attempt(slot);
          }
        }
        if (stopped()) break;
        const retries = this.#slots.flatMap(slot => (slot.state === 'OFFLINE' && slot.retryAt !== null ? [slot.retryAt] : []));
        const wake = Math.min(nextCycle, ...retries);
        await timers.sleep(Math.max(0, wake - timers.monotonic()), signal);
      }
    } catch (error) {
      if (error instanceof Abort) {
        await this.#options.output.write(`fluxwarden daemon: ${nodeText(error.message, 1024)}\n`, { stream: 'stderr' }).catch(() => undefined);
        return { cycles, exitCode: error.exitCode };
      }
      throw error;
    }
    return { cycles, exitCode: ExitCode.SUCCESS };
  }
}

/** G3 and G4, then collection cycles until `signal` aborts (the current cycle finishes first). */
export async function runCollector(options: CollectorOptions): Promise<CollectorResult> {
  const fail = async (message: string): Promise<CollectorResult> => {
    await options.output.write(`fluxwarden daemon: ${nodeText(message, 4096)}\n`, { stream: 'stderr' }).catch(() => undefined);
    return { cycles: 0, exitCode: ExitCode.INVALID_INPUT };
  };
  let config: Config;
  try {
    config = loadConfig(options.configPath);
  } catch (error) {
    if (error instanceof ConfigError) return fail(error.message);
    throw error;
  }
  let db: Database;
  try {
    db = openDatabase(config.database, { readOnly: false, mustExist: true });
  } catch (error) {
    if (error instanceof PersistenceError && error.code !== 'OUT_OF_RANGE' && error.code !== 'READ_ONLY') return fail(error.message);
    throw error;
  }
  try {
    return await new Collector(config, db, options).run();
  } finally {
    db.close();
  }
}
