import { randomBytes, randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { createApprovalFromKeyFile } from '../approval/sign.js';
import { ApprovalError } from '../approval/errors.js';
import { verifyAndStoreApproval, verifiedStoredApproval } from '../approval/verify.js';
import type { ApprovalPolicy, ProposalTerms } from '../approval/types.js';
import type { Command } from '../cli/args.js';
import type { Environment } from '../cli/connect.js';
import { resolveConnection } from '../cli/connect.js';
import { parseDuration, readBoundedText, ConfigError, type Config, type NodeConfig } from '../config/config.js';
import type { ExecutionAdapter, PreflightAdapter, ExecutionPolicy, NodeCapability } from '../core/execution.js';
import { CredentialFileError } from '../core/node.js';
import { parseAmount, type Msat } from '../core/money.js';
import { scidToChanId } from '../core/scid.js';
import { ULID, ulid } from '../core/ulid.js';
import { prepareExecution } from '../executor/preflight.js';
import { dispatchExecution } from '../executor/dispatch.js';
import { bootstrapAlerts } from '../daemon/bootstrap.js';
import { openClnController } from '../node-cln/controller.js';
import { openLndController } from '../node-lnd/controller.js';
import { LND_FINAL_CLTV_DELTA } from '../node-lnd/execute.js';
import { envelope, registerOutputSecret, renderEnvelope, terminalText } from '../output/index.js';
import type { Database, StoredProposal } from '../persistence/index.js';
import type { PlanningPolicy } from '../planner/diagnose.js';
import { renderProposal } from '../planner/proposal.js';
import { canonicalPolicyJson, policySha256 } from '../policy/canonical.js';
import { PolicyError } from '../policy/errors.js';
import { loadPolicy } from '../policy/load.js';
import type { Policy } from '../policy/types.js';
import { actionsStatus, OUTCOME_UNKNOWN_MESSAGE, watchActionsStatus } from './actions.js';
import { handshake, nodeFailure, type Handshake } from './handshake.js';
import { liquidityDiagnose } from './liquidity-diagnose.js';
import { liquidityPlan } from './liquidity-plan.js';
import { proposalDocument } from './proposal-document.js';
import { runLedgerVerify } from './ledger.js';
import { refuse, type Io } from './report.js';
import { configStage, databaseStage, StageFailure } from './stages.js';

export function duration(value: string | null): number | null {
  if (value === null) return null;
  const parsed = parseDuration(value);
  if (parsed === null) throw new StageFailure(2, 'arguments', 'a duration must be <int>(s|m|h|d)');
  return parsed;
}

export function activePolicy(config: Config, override: string | null = null): Policy {
  const path = override === null ? config.policy : resolve(override);
  if (path === null) throw new StageFailure(2, 'policy', 'a policy file is required');
  return loadPolicy(readBoundedText(path, 'policy'));
}

export function planningPolicy(policy: Policy, horizon: number | null = null): PlanningPolicy {
  return { ...policy, fees: { ...policy.fees, max_fee_ppm: BigInt(policy.fees.max_fee_ppm) },
    budget: { ...policy.budget, period: policy.budget.period * 1000 }, cooldown_after_failure: policy.cooldown_after_failure * 1000,
    cooldown_after_success: policy.cooldown_after_success * 1000, max_snapshot_age: policy.max_snapshot_age * 1000,
    proposal_ttl: policy.proposal_ttl * 1000, demand: { ...policy.demand, horizon: horizon ?? policy.demand.horizon * 1000 } };
}

function approvalPolicy(policy: Policy): ApprovalPolicy {
  return { sha256: policySha256(policy), maxFeeMsat: policy.fees.max_fee_msat, maxCltvDelta: policy.routing.max_cltv_delta,
    approvalMaxTtlSeconds: policy.approval_max_ttl, maxSnapshotAgeSeconds: policy.max_snapshot_age };
}

function terms(proposal: StoredProposal): ProposalTerms {
  if (proposal.actionType !== 'CIRCULAR_REBALANCE' || proposal.sourceChannelKey === null || proposal.targetChannelKey === null
    || proposal.principalMsat === null || proposal.maxFeeMsat === null || proposal.maxFeePpm === null || proposal.maxCltvDelta === null) {
    throw new StageFailure(5, 'proposal', 'the proposal contains no rebalance');
  }
  const explanation = JSON.parse(proposal.reasonJson) as { exempt_fee_msat: string };
  return { id: proposal.id, nodePubkey: proposal.nodePubkey, sourceChannelKey: proposal.sourceChannelKey, targetChannelKey: proposal.targetChannelKey,
    principalMsat: proposal.principalMsat as Msat, maxFeeMsat: proposal.maxFeeMsat as Msat, maxFeePpm: proposal.maxFeePpm,
    exemptFeeMsat: parseAmount(explanation.exempt_fee_msat, 'exempt fee') as Msat, maxCltvDelta: proposal.maxCltvDelta, policySha256: proposal.policySha256, expiresAt: proposal.expiresAt };
}

export function selectNodes(config: Config, name: string | null): readonly NodeConfig[] {
  const nodes = name === null ? config.nodes : config.nodes.filter(node => node.name === name);
  if (nodes.length === 0) throw new StageFailure(2, 'arguments', 'no configured node has this name');
  return nodes;
}

export async function controller(node: NodeConfig, config: Config, session: Handshake, clock: { now(): number } = { now: () => Date.now() }) {
  const connection = session.connection;
  const payment = node.implementation === 'cln'
    ? await openClnController({ ...connection.endpoint, tlsCertPath: connection.tlsCertPath, runePath: connection.credentialPath, timeoutMs: Math.min(30_000, config.attemptDeadlineMs), onSecret: registerOutputSecret }, node.expectedPubkey, config.attemptDeadlineMs)
    : await openLndController({ ...connection.endpoint, tlsCertPath: connection.tlsCertPath, macaroonPath: connection.credentialPath, onSecret: registerOutputSecret }, config.attemptDeadlineMs);
  const listChannels = () => session.reader.listChannels({ nodeId: session.rowId, observedAt: clock.now(), blockHeight: session.result.identity.blockHeight });
  const capabilities = new Set<NodeCapability>();
  for (const capability of ['CHANNEL_READ', 'PAYMENT_READ', 'INVOICE_CREATE', 'INVOICE_CANCEL', 'PAYMENT_TRACK'] as const) {
    if (session.result.capabilities.has(capability)) capabilities.add(capability);
  }
  const routeControl = session.result.capabilities.has(node.implementation === 'cln' ? 'ASKRENE_LAYER_ROUTING' : 'EXPLICIT_ROUTE_CONTROL');
  if (routeControl) { capabilities.add('ROUTE_QUERY_PINNED'); capabilities.add('SEND_TO_ROUTE'); }
  if (!routeControl) throw new StageFailure(3, 'capability', 'the node does not support explicit circular routes');
  const findCircularRoute: PreflightAdapter['findCircularRoute'] = async (request, ownership) => {
    if (node.implementation === 'cln' && 'findCircularRoute' in payment.execution) return payment.execution.findCircularRoute(request, ownership);
    const channels = await listChannels();
    const source = channels.find(channel => channel.channelKey === request.sourceChannelKey);
    const target = channels.find(channel => channel.channelKey === request.targetChannelKey);
    if (source?.scid === null || target?.scid === null || source === undefined || target === undefined) return { refusal: 'NO_FEASIBLE_ROUTE' };
    // The request carries both ceilings, including the ppm exemption, just as route assessment does.
    const ppmFee = request.principalMsat * request.maxFeePpm / 1_000_000n;
    const allowedFee = ppmFee > request.exemptFeeMsat ? ppmFee : request.exemptFeeMsat;
    const maxFeeMsat = allowedFee < request.maxFeeMsat ? allowedFee : request.maxFeeMsat;
    const route = await payment.routes.buildCircularRoute({ selfPubkey: node.expectedPubkey, implementation: node.implementation,
      sourceScid: source.scid, targetScid: target.scid, outPeer: source.peerPubkey, inPeer: target.peerPubkey,
      principalMsat: request.principalMsat as Msat, maxFeeMsat: maxFeeMsat as Msat, maxCltvDelta: request.maxCltvDelta,
      finalCltvDelta: node.implementation === 'lnd' ? LND_FINAL_CLTV_DELTA : 18, blockHeight: session.result.identity.blockHeight,
      ...(request.excludeChannels === undefined ? {} : { excludeChannels: request.excludeChannels }) });
    if ('kind' in route) return { refusal: route.code };
    return { sourceChannelKey: source.channelKey, targetChannelKey: target.channelKey, outPeer: source.peerPubkey, inPeer: target.peerPubkey,
      // LND snapshots and SendToRouteV2 use packed chan_id; route assessment uses BOLT 7 SCIDs.
      // lnd lnwire/short_channel_id.go packs the same channel identity without losing uint64 precision.
      principalMsat: request.principalMsat, hops: route.hops.map(hop => ({ channelKey: node.implementation === 'lnd' ? scidToChanId(hop.scid) : hop.scid,
        nodeOut: hop.nodeIdOut, amountOutMsat: hop.amountOutMsat, expiry: hop.cltvOut, policy: hop.policy })),
      totalFeeMsat: route.totalFeeMsat, feePpmCeil: (route.totalFeeMsat * 1_000_000n + request.principalMsat - 1n) / request.principalMsat,
      totalTimelockDelta: route.totalTimeLock - route.builtAtHeight + 3, parts: route.parts };
  };
  const execution = payment.execution;
  const adapter: ExecutionAdapter & PreflightAdapter = {
    handshake: async () => { const info = await session.reader.info(); return { pubkey: info.pubkey, network: info.network, version: info.version, synced: info.syncedToChain }; },
    capabilities: () => capabilities, listChannels, findCircularRoute,
    createInvoice: (amount, preimage, label, expiry) => payment.execution.createInvoice(amount, preimage, label, expiry),
    sendOnRoute: (route, hash, secret, dispatched, label) => node.implementation === 'cln' && 'findCircularRoute' in payment.execution
      ? payment.execution.sendOnRoute(route, hash, secret, dispatched, label)
      : payment.execution.sendOnRoute(route, hash, secret, dispatched),
    observePayment: (hash, mode) => payment.execution.observePayment(hash, mode), invoiceState: hash => payment.execution.invoiceState(hash),
    cancelUnpaidInvoice: (hash, label) => payment.execution.cancelUnpaidInvoice(hash, label),
    ...('removeRoutingLayer' in execution ? { removeRoutingLayer: (layer: string) => execution.removeRoutingLayer(layer) } : {}),
  };
  return { ...payment, adapter };
}

export function emit(io: Io, command: string, result: Record<string, unknown>, code = 0, message: string | null = null): number {
  const error = code === 0 ? null : { code, step: null, message: message ?? 'the command needs attention' };
  const document = envelope(command, result, error);
  io.output.write('stdout', io.json ? renderEnvelope(command === 'reconcile' && (code === 7 || code === 9) ? { ...document, result } : document) : terminalText(`${JSON.stringify(result, null, 2)}\n${message ?? ''}${message === null ? '' : '\n'}`));
  return code;
}

function proposalId(id: string): string {
  if (!id.startsWith('prop_') || !ULID.test(id.slice(5))) throw new StageFailure(2, 'arguments', 'a proposal id is prop_ followed by a ULID');
  return id.slice(5);
}

export async function workflow(command: Command, io: Io, env: Environment, signal: AbortSignal,
  services: { controller?: typeof controller; onSafetyCode?: (code: number) => void } = {}): Promise<number> {
  let db: Database | undefined;
  try {
    const horizon = 'horizon' in command ? duration(command.horizon) : null;
    if (command.kind === 'actions execute') {
      if (!command.requireRegtest) throw new StageFailure(2, 'arguments', '--require-regtest is required');
      proposalId(command.proposalId);
    }
    const config = configStage(command.config, command.kind === 'actions execute');
    if (command.kind === 'actions status') {
      if (command.watch) return (await watchActionsStatus({ databasePath: config.database, executionId: command.executionId, pollMs: 250, signal }, line => { io.output.write('stdout', line); })).exitCode;
      const result = actionsStatus({ databasePath: config.database, executionId: command.executionId, json: io.json });
      io.output.write('stdout', result.output); return result.exitCode;
    }
    db = databaseStage(config.database, command.kind === 'liquidity explain' || command.kind === 'ledger verify' ? 'read' : 'existing');
    if (command.kind === 'ledger verify') {
      const verified = runLedgerVerify(db);
      if (verified.exitCode !== 0) return refuse(io, command.kind, 8, 'ledger', JSON.stringify(verified.report.failures, (_key, value: unknown) => typeof value === 'bigint' ? value.toString() : value));
      return emit(io, command.kind, { journals: db.ledger.journals().length, steps: [1, 2, 3, 4].map(step => ({ step, result: step === 4 ? 'not-requested' : 'compared' })) });
    }
    if (command.kind === 'liquidity explain') {
      const id = proposalId(command.proposalId);
      const stored = db.proposals.find(id);
      if (stored === null) throw new StageFailure(2, null, 'no proposal has this id');
      const doc = { ...proposalDocument(stored, db.now()), approvals: db.commandData.approvals.listByProposal(id).map(row => ({ approval_id: row.id, key_id: row.key_id, expires_at: row.expires_at })) };
      io.output.write('stdout', io.json ? renderEnvelope(envelope(command.kind, doc, null)) : terminalText(renderProposal(doc)));
      return 0;
    }
    const policy = activePolicy(config, 'policy' in command ? command.policy : null);
    if (command.kind === 'liquidity approve' || command.kind === 'actions execute') {
      const id = proposalId(command.proposalId);
      const proposal = db.proposals.find(id);
      if (proposal === null) throw new StageFailure(2, null, 'no proposal has this id');
      if (proposal.expiresAt <= db.now() || !['PROPOSED', 'APPROVED'].includes(proposal.status)) throw new StageFailure(5, 'proposal', 'the proposal expired or is unavailable');
      const context = { keys: config.approvalKeys, proposal: terms(proposal), policy: approvalPolicy(policy), now: db.now() };
      if (command.kind === 'liquidity approve') {
        if (command.key === null) throw new StageFailure(2, 'arguments', '--key is required');
        if (command.maxFee !== null && !/^(0|[1-9][0-9]{0,18})$/.test(command.maxFee)) throw new StageFailure(2, 'arguments', 'the fee cap must be an integer msat amount');
        const maxFee = command.maxFee === null ? undefined : parseAmount(command.maxFee, 'max fee') as Msat;
        const maxCltv = command.maxCltv === null ? undefined : (/^[0-9]+$/.test(command.maxCltv) ? Number(command.maxCltv) : NaN);
        const expires = duration(command.expiresIn);
        const channels = db.commandData.snapshots(proposal.nodeId).filter(channel => channel.channelKey === proposal.sourceChannelKey || channel.channelKey === proposal.targetChannelKey);
        const token = createApprovalFromKeyFile({ proposal: context.proposal, policy: context.policy, keys: context.keys,
          ...(maxFee === undefined ? {} : { approvedMaxFeeMsat: maxFee }), ...(maxCltv === undefined ? {} : { approvedMaxCltvDelta: maxCltv }),
          ...(expires === null ? {} : { expiresAt: context.now + expires }), snapshotObservedAt: channels.length === 2 ? Math.min(...channels.map(channel => channel.observedAt)) : 0 },
        command.key, { now: () => context.now, randomBytes });
        const row = verifyAndStoreApproval(token, context, db.commandData.approvals, { newId: () => ulid(context.now) });
        return emit(io, command.kind, { proposal_id: command.proposalId, approval_id: row.id, key_id: row.key_id, expires_at: row.expires_at, max_fee_msat: row.max_fee_msat.toString(), max_cltv_delta: row.max_cltv_delta });
      }
      if (config.approvalKeys.length === 0) throw new StageFailure(5, 'approval', 'no approval key is configured');
      const approval = verifiedStoredApproval(context, db.commandData.approvals);
      const node = config.nodes.find(entry => entry.name === proposal.nodeName);
      if (node === undefined) throw new StageFailure(5, 'config', 'the proposal node is unavailable');
      const session = await handshake(db, node, resolveConnection(node, command.connection, env));
      if (session.quarantined) throw new StageFailure(5, 'node-quarantined', 'the proposal node is quarantined');
      const payment = await (services.controller ?? controller)(node, config, session, db);
      const workerId = randomUUID();
      const leaseMs = config.attemptDeadlineMs + 60_000;
      const executionPolicy: ExecutionPolicy = { sha256: context.policy.sha256, network: policy.network, maxFeeMsat: policy.fees.max_fee_msat,
        maxFeePpm: BigInt(policy.fees.max_fee_ppm), exemptFeeMsat: policy.fees.exempt_fee_msat, maxCltvDelta: policy.routing.max_cltv_delta,
        minChannelReserveMsat: policy.amounts.min_channel_reserve_msat,
        minSourceOutboundMsat: policy.targets[node.name]?.[context.proposal.sourceChannelKey]?.min_outbound_msat ?? 0n,
        budget: { msat: policy.budget.msat, periodMs: policy.budget.period * 1000 },
        cooldownAfterFailureMs: policy.cooldown_after_failure * 1000, cooldownAfterSuccessMs: policy.cooldown_after_success * 1000,
        maxInFlight: policy.max_in_flight, maxSnapshotAgeMs: policy.max_snapshot_age * 1000, excludeChannels: policy.exclude_channels };
      const ready = await prepareExecution({ db, adapter: payment.adapter, workerId, leaseMs }, { approval, policy: executionPolicy, approvalKeyIds: config.approvalKeys.map(key => key.keyId) });
      if (ready.kind !== 'READY') return refuse(io, command.kind, ready.exit, ready.step, `execution ${ready.executionId ?? '-'}: ${ready.step}`);
      const alerts = bootstrapAlerts(config);
      const outcome = await dispatchExecution({ db, adapter: payment.adapter, workerId, leaseMs, randomBytes, stopSignal: signal,
        attemptDeadlineMs: config.attemptDeadlineMs, invoiceExpirySeconds: 300, deltaToleranceMsat: config.deltaToleranceMsat,
        ...(services.onSafetyCode === undefined ? {} : { onSafetyCode: services.onSafetyCode }),
        alert: alert => { alerts.raise({ kind: alert.kind === 'INVARIANT_BREACH' ? 'invariant-breach' : alert.kind,
          subject: alert.executionId, state: alert.code }); } }, { ...ready, approval, policy: executionPolicy });
      if (outcome.exit !== 0 && outcome.exit !== 9) return refuse(io, command.kind, outcome.exit, outcome.step, outcome.exit === 7 ? OUTCOME_UNKNOWN_MESSAGE : `execution ${outcome.executionId}: ${outcome.step ?? 'error'}`);
      const view = db.executions.view(ready.executionId);
      if (view?.status !== 'VERIFIED_SUCCESS') throw new Error('a paid receipt requires verified success');
      const fee = view.actualFeeMsat;
      const deltas = db.commandData.executionDeltas(ready.executionId);
      const result = { execution_id: ready.executionId, proposal_id: command.proposalId, status: 'VERIFIED_SUCCESS', principal_msat: context.proposal.principalMsat.toString(),
        actual_fee_msat: fee?.toString() ?? null, fee_ppm: fee === null ? null : Number((fee * 1_000_000n + context.proposal.principalMsat - 1n) / context.proposal.principalMsat),
        cltv_delta: ready.route.totalTimelockDelta, source_delta_msat: deltas?.sourceDeltaMsat ?? null, target_delta_msat: deltas?.targetDeltaMsat ?? null,
        delta_status: view.deltaStatus, journal_ids: db.ledger.journals().filter(journal => journal.executionId === ready.executionId).map(journal => journal.id) };
      if (outcome.exit === 9) {
        const warning = `execution ${outcome.executionId}: ${outcome.step ?? 'reconciliation alert'}`;
        io.output.write('stdout', io.json ? renderEnvelope(envelope(command.kind, result, null, [warning])) : terminalText(`${JSON.stringify(result, null, 2)}\n${warning}\n`));
        return outcome.exit;
      }
      return emit(io, command.kind, result);
    }
    if (command.kind === 'liquidity plan' || command.kind === 'liquidity diagnose') {
      const nodes = selectNodes(config, command.node);
      for (const node of nodes) {
        let stored = db.nodes.list().find(row => row.name === node.name);
        let channels = stored === undefined ? [] : db.commandData.snapshots(stored.id);
        const now = db.now();
        const stale = channels.length === 0 || channels.some(channel => now - channel.observedAt > policy.max_snapshot_age * 1000);
        const session = command.kind === 'liquidity plan' || policy.demand.mode === 'ewma' || stale ? await handshake(db, node, resolveConnection(node, command.connection, env)) : null;
        if ((command.kind === 'liquidity diagnose' && stale) || command.refresh) {
          if (session === null) throw new Error('a refresh requires a handshake');
          channels = await session.reader.listChannels({ nodeId: session.rowId, observedAt: db.now(), blockHeight: session.result.identity.blockHeight });
          db.snapshots.storeAll(channels);
          stored = db.nodes.list().find(row => row.name === node.name);
          channels = db.commandData.snapshots(session.rowId);
        }
        const incomingHistory = policy.demand.mode === 'ewma' ? await session?.reader.incomingHistory?.() : undefined;
        if (command.kind === 'liquidity diagnose') {
          const result = liquidityDiagnose({ nodeName: node.name, channels, policy: planningPolicy(policy), horizonMs: horizon, clock: db,
            ...(incomingHistory === undefined ? {} : { incomingHistory }) });
          if (!io.json && result.exitCode !== 0) {
            const error = (JSON.parse(result.json) as { error: { step: string | null; message: string } }).error;
            return refuse(io, command.kind, result.exitCode, error.step, error.message);
          }
          io.output.write('stdout', io.json ? result.json : terminalText(`${JSON.stringify((JSON.parse(result.json) as { result: unknown }).result, null, 2)}\n`)); return result.exitCode;
        }
        if (session === null || stored === undefined) throw new StageFailure(5, 'STALE_SNAPSHOT', 'no channel snapshot is available');
        const payment = await controller(node, config, session, db);
        const planningState = db.commandData.planningState(stored.id, policy.budget.period * 1000);
        const result = await liquidityPlan({ db, node: { id: stored.id, name: node.name, pubkey: node.expectedPubkey, implementation: node.implementation }, channels,
          policy: planningPolicy(policy, horizon), policySha256: policySha256(policy), policyCanonicalJson: canonicalPolicyJson(policy), blockHeight: session.result.identity.blockHeight,
          finalCltvDelta: node.implementation === 'lnd' ? LND_FINAL_CLTV_DELTA : 18, ...planningState, routes: payment.routes, clock: db,
          ...(incomingHistory === undefined ? {} : { incomingHistory }) });
        io.output.write('stdout', io.json ? result.json : result.text); return result.exitCode;
      }
    }
    throw new StageFailure(2, null, 'the command is unavailable');
  } catch (error) {
    if (command.kind === 'actions execute' && error instanceof CredentialFileError) return refuse(io, command.kind, 5, 'credentials', error.message);
    if (error instanceof ApprovalError) return refuse(io, command.kind, error.exitCode, error.reason, error.reason);
    if (error instanceof PolicyError) return refuse(io, command.kind, error.exitCode, 'policy', error.message);
    if (error instanceof ConfigError) return refuse(io, command.kind, 2, 'config', error.message);
    if (error instanceof StageFailure) return refuse(io, command.kind, error.code, error.step, error.message);
    if (error instanceof RangeError) return refuse(io, command.kind, 2, 'arguments', 'an amount or limit is invalid');
    const failure = nodeFailure(error);
    if (failure !== null) return refuse(io, command.kind, failure.code, failure.step, failure.message);
    throw error;
  } finally { db?.close(); }
}
