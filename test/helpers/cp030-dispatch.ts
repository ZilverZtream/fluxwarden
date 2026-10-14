// Dispatch scenarios over a seeded PREFLIGHT execution (test/helpers/cp030-execution.ts Interface).
import { circularRoute, fakeChannel } from '../fakes/preflight-node.js';
import { ScriptedExecutionNode, type ExecutionScript } from '../fakes/execution-node.js';
import { IN_PEER, loadPersistence, OUT_PEER, policyFor, PRINCIPAL, scratchDb, seedBase, type Base, type CircularRoute, type ExecDatabase } from './cp028-executor.js';
import {
  loadDispatch, loadExecutionCore, seedExecution, sha256, type Alert, type DispatchInput, type DispatchOutcome, type ExecutionAdapter,
} from './cp030-execution.js';
import type { VerifiedApproval, ProposalOptions } from './cp028-executor.js';

export const ROUTE_FEE = 150_000n;
export const PREIMAGE = Buffer.from('3c9e0a51f2d47b86'.repeat(4), 'hex');
export const HASH = sha256(PREIMAGE);
export const S_BEFORE = 500_000_000n;
export const T_BEFORE = 300_000_000n;
export const TOLERANCE = 1_000n;
/** A handshake as the preflight observed it (SPEC §5.2 H2-H7). */
export const REGTEST_HANDSHAKE = { pubkey: `03${'cd'.repeat(32)}`, network: 'regtest', version: '0.21.4-beta commit=v0.21.4-beta', synced: true };

export interface Options {
  readonly approvalSeed?: ProposalOptions;
  readonly script?: (ctx: { base: Base; path: string; executionId: string }) => Partial<ExecutionScript>;
  readonly signal?: AbortSignal;
  readonly attemptDeadlineMs?: number;
  /** Replaces the default three-hop route (for example with node-specific channel keys). */
  readonly route?: (base: Base) => CircularRoute;
  /** Changes the in-memory approval the route is approved under and dispatched with. */
  readonly approval?: (approval: VerifiedApproval) => VerifiedApproval;
}

export function balances(base: Base, source: bigint, target: bigint) {
  return [fakeChannel(base.sourceKey, OUT_PEER, { localBalanceMsat: source }), fakeChannel(base.targetKey, IN_PEER, { localBalanceMsat: target })];
}

/** Channel balances after a settled rebalance of PRINCIPAL with the given fee (SPEC §8.7 step 5). */
export function settled(base: Base, fee: bigint) {
  return () => balances(base, S_BEFORE - PRINCIPAL - fee, T_BEFORE + PRINCIPAL);
}

export async function prepare(prefix: string, options: Options = {}) {
  const p = await loadPersistence();
  const { dispatchExecution } = await loadDispatch();
  const path = scratchDb(prefix);
  const base = seedBase(p, path);
  const route = options.route?.(base) ?? circularRoute(base.sourceKey, base.targetKey, ROUTE_FEE, 80);
  const seeded = seedExecution(base, { status: 'PREFLIGHT', route, plannedFeeMsat: route.totalFeeMsat, fenceEpoch: 3n,
    ...(options.approvalSeed === undefined ? {} : { proposalOptions: options.approvalSeed }) });
  const { executionId } = seeded;
  const approval = options.approval?.(seeded.approval) ?? seeded.approval;
  const policy = policyFor(base);
  // The dispatch input is a route approved on a node whose observed network is regtest (INV-15, SECURITY §4.4).
  const { proveRegtest, approveRoute } = await loadExecutionCore();
  const proof = proveRegtest('regtest', REGTEST_HANDSHAKE);
  if (proof === null) throw new Error('proveRegtest refused regtest/regtest');
  const terms = { sourceChannelKey: route.sourceChannelKey, targetChannelKey: route.targetChannelKey, principalMsat: route.principalMsat };
  const approved = approveRoute(route, terms, approval, policy, proof);
  if (!('route' in approved)) throw new Error(`approveRoute refused the scenario route: ${approved.refusal}`);
  const node = new ScriptedExecutionNode({
    // The default simulated transfer settles into this fixture's receiver channel;
    // the receipt is declared alongside its independently scripted balance change.
    settledChannelKey: base.targetKey,
    before: () => balances(base, S_BEFORE, T_BEFORE), after: settled(base, ROUTE_FEE), ...options.script?.({ base, path, executionId }),
  });
  const alerts: Alert[] = [];
  const input: DispatchInput = { executionId, fenceEpoch: 3n, route: approved.route, approval, policy };
  const run = async (adapter: ExecutionAdapter = node, db?: ExecDatabase, override: Partial<DispatchInput> = {}): Promise<DispatchOutcome> => {
    const own = db ?? p.openDatabase(path, { readOnly: false });
    try {
      return await dispatchExecution({
        db: own, adapter, workerId: 'worker-a', leaseMs: 60_000,
        randomBytes: size => size === 32 ? Uint8Array.from(PREIMAGE) : new Uint8Array(size).fill(7),
        stopSignal: options.signal ?? new AbortController().signal, attemptDeadlineMs: options.attemptDeadlineMs ?? 5_000,
        invoiceExpirySeconds: 3_600, deltaToleranceMsat: TOLERANCE, alert: alert => { alerts.push(alert); },
      }, { ...input, ...override });
    } finally { if (db === undefined) own.close(); }
  };
  return { p, path, base, route, executionId, approval, node, alerts, input, run };
}

