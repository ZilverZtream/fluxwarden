import { createHash, randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import type { Command } from '../cli/args.js';
import { resolveConnection, type Environment } from '../cli/connect.js';
import type { ExecutionAdapter } from '../core/execution.js';
import { ulid } from '../core/ulid.js';
import { exportEvidence } from './evidence.js';
import { buildBundle, type EvidenceInput } from '../evidence/bundle.js';
import { buildIdentity } from '../evidence/build.js';
import { evidenceCredentials } from '../evidence/credentials.js';
import type { AlertWriter } from '../daemon/alerts.js';
import { bootstrapAlerts } from '../daemon/bootstrap.js';
import { recoverPreflight } from '../executor/preflight.js';
import { writeRunRecord, readRunRecord } from '../output/run-record.js';
import { reconcile } from '../reconciler/index.js';
import type { AccountingSource, ReconExecution } from '../reconciler/accounting.js';
import type { Database } from '../persistence/index.js';
import { policySha256 } from '../policy/canonical.js';
import { proposalDocument } from './proposal-document.js';
import { parseReconcileWindow, runReconcile } from './reconcile.js';
import { activePolicy, controller, emit, selectNodes } from './workflow.js';
import { handshake, nodeFailure } from './handshake.js';
import { refuse, type Io } from './report.js';
import { configStage, databaseStage, StageFailure } from './stages.js';

export async function recoveryWorkflow(command: Command, io: Io, env: Environment, alerts?: AlertWriter): Promise<number> {
  let db: Database | undefined;
  try {
    if (command.kind !== 'reconcile' && command.kind !== 'evidence export') throw new StageFailure(2, null, 'unknown recovery command');
    const window = command.kind === 'reconcile' ? parseReconcileWindow({ ...(command.since === null ? {} : { since: command.since }), ...(command.until === null ? {} : { until: command.until }) }, Date.now()) : null;
    if (window !== null && !window.ok) throw new StageFailure(2, 'arguments', window.message);
    const config = configStage(command.config);
    db = databaseStage(config.database, command.kind === 'evidence export' ? 'read' : 'existing');
    if (command.kind === 'evidence export') {
      if (command.runId === null || command.out === null) throw new StageFailure(2, 'arguments', '--run-id and --out are required');
      const input = readRunRecord(config.database, command.runId);
      if (input === null) throw new StageFailure(2, null, 'no evidence run has this id');
      const bound = await labEvidence(input, command.config, env, db);
      const out = resolve(command.out);
      let secrets: ReturnType<typeof evidenceCredentials>;
      try { secrets = evidenceCredentials(bound, config); }
      catch { throw new StageFailure(8, 'evidence', 'the recorded run credential context is unavailable'); }
      const exported = await exportEvidence(bound, { outDir: out, secrets });
      if (exported.exitCode !== 0) throw new StageFailure(exported.exitCode, 'evidence', 'the evidence destination is unavailable or the leak check failed');
      const bundle = buildBundle(bound, secrets);
      return emit(io, command.kind, { run_id: command.runId, out, files: [...bundle].filter(([name]) => name !== 'checksums.sha256').map(([name, bytes]) => ({ name, sha256: createHash('sha256').update(bytes).digest('hex') })) });
    }
    if (window === null) throw new Error('the reconciliation window is unavailable');
    const writer = alerts ?? bootstrapAlerts(config);
    const database = db;
    const nodes = selectNodes(config, command.node);
    const adapters = new Map<string, ExecutionAdapter>();
    const sources: AccountingSource[] = [];
    const fingerprints = new Map<string, { readonly credentialFingerprint: string; readonly tlsFingerprint: string }>();
    const topologyBefore: unknown[] = [];
    for (const node of nodes) {
      const session = await handshake(db, node, resolveConnection(node, command.connection, env));
      const payment = await controller(node, config, session, db);
      if (payment.fingerprints !== undefined) fingerprints.set(node.name, payment.fingerprints);
      adapters.set(session.rowId, payment.adapter);
      sources.push({ node: node.name, implementation: node.implementation, api: payment.accounting } as AccountingSource);
      const channels = await payment.adapter.listChannels();
      topologyBefore.push(...db.commandData.snapshots(session.rowId));
      db.snapshots.storeAll(channels);
    }
    const ids = db.commandData.executionIds();
    const before = new Map(ids.map(id => [id, database.executions.view(id)?.status]));
    await recoverPreflight({ db, adapters, workerId: randomUUID(), leaseMs: 60_000 });
    const pass = await reconcile({ db, adapters, workerId: randomUUID(), leaseMs: 60_000, notFoundWindowMs: 120_000,
      escalateAfterMs: config.escalateAfterMs, deltaToleranceMsat: config.deltaToleranceMsat, confirmIntervalMs: 1000, nodeIds: new Set(adapters.keys()),
      alert: alert => { writer.raise({ kind: alert.kind === 'INVARIANT_BREACH' ? 'invariant-breach' : alert.kind,
        subject: alert.executionId, state: alert.code }); } }, { startup: true });
    const executions: ReconExecution[] = [];
    for (const id of ids) {
      const view = db.executions.view(id);
      const plan = db.executions.plan(id);
      if (view === null || plan === null || view.paymentHash === null) continue;
      const node = nodes.find(entry => entry.expectedPubkey === plan.nodePubkey);
      if (node !== undefined) executions.push({ id, node: node.name, paymentHash: view.paymentHash, status: view.status });
    }
    const checked = await runReconcile({ db, window: window.window, executions, sources, clock: db });
    if (checked.exitCode === 8 || pass.exit === 8) throw new StageFailure(8, 'ledger', JSON.stringify(checked.report.verify.failures, (_key, value: unknown) => typeof value === 'bigint' ? value.toString() : value));
    const accounting = checked.report.accounting;
    if (accounting === null) throw new Error('accounting report is absent');
    for (const difference of accounting.differences) writer.raise({ kind: 'recon-difference', subject: difference.executionId ?? difference.node,
      state: `${difference.source}:${difference.kind}:${String(difference.ledgerMsat)}:${String(difference.nodeMsat)}:${difference.reason ?? ''}` });
    const runId = `run_${ulid(db.now())}`;
    const changes = executions.filter(execution => before.get(execution.id) !== execution.status).map(execution => ({ execution_id: execution.id, from: before.get(execution.id), to: execution.status }));
    const journals = db.ledger.journals();
    const differences = accounting.differences.map(difference => ({ node: difference.node, execution_id: difference.executionId, item: `${difference.source}:${difference.kind}`,
      ledger_msat: (difference.ledgerMsat ?? 0n).toString(), node_msat: (difference.nodeMsat ?? 0n).toString(),
      journal_id: journals.find(journal => journal.eventType === 'RECON_DIFFERENCE' && journal.executionId === difference.executionId)?.id ?? runId }));
    const report = { run_id: runId, since: window.window.sinceMs, nodes: accounting.nodes.map(node => ({ name: node.node, result: node.status })), executions: changes, differences,
      steps: [1, 2, 3, 4].map(step => ({ step, result: step === 4 && accounting.nodes.some(node => node.status !== 'compared') ? 'incomplete' : 'compared' })) };
    const proposals = db.commandData.proposalIds().map(id => database.proposals.find(id)).filter(proposal => proposal !== null).map(proposal => proposalDocument(proposal, database.now()));
    const policy = activePolicy(config);
    const build = buildIdentity();
    const input: EvidenceInput = {
      manifest: { runId, command: 'reconcile', fluxwardenVersion: build.version, gitCommit: build.gitCommit, imageDigests: {},
        nodes: db.nodes.list().filter(node => nodes.some(selected => selected.name === node.name)).map(node => ({ name: node.name, implementation: node.implementation,
          pubkey: node.expectedPubkey, version: node.observedVersion ?? 'unavailable: node version was not observed',
          credentialFingerprint: fingerprints.get(node.name)?.credentialFingerprint ?? 'unavailable: adapter did not expose credential fingerprint',
          tlsFingerprint: fingerprints.get(node.name)?.tlsFingerprint ?? 'unavailable: adapter did not expose certificate fingerprint' })),
        seeds: [], policySha256: policySha256(policy), approvalKeyIds: config.approvalKeys.map(key => key.keyId), chaosScenarioIds: [],
        unavailableEvidence: { image_digests: 'node RPC does not expose container image digests', seeds: 'reconciliation uses no simulation seed',
          chaos_scenario_ids: 'no chaos scenario was supplied for this run' } },
      topologyBefore, topologyAfter: nodes.flatMap(node => { const stored = database.nodes.list().find(row => row.name === node.name); return stored === undefined ? [] : database.commandData.snapshots(stored.id); }),
      proposals, executionTrace: ids.flatMap(id => database.executions.events(id).map(event => ({ execution_id: id, ...event }))),
      ledgerAudit: { journals, balances: Object.fromEntries(db.ledger.balances()), steps: report.steps }, reconciliation: report, chaosResults: [],
    };
    writeRunRecord(config.database, await labEvidence(input, command.config, env, db));
    const exit = pass.exit === 7 || checked.exitCode === 7 ? 7 : differences.length > 0 || pass.exit === 9 ? 9 : 0;
    return emit(io, command.kind, report, exit, exit === 7 ? 'executions remain unresolved; do not retry' : exit === 9 ? 'node accounting differs from the ledger' : null);
  } catch (error) {
    if (error instanceof StageFailure) return refuse(io, command.kind, error.code, error.step, error.message);
    const failure = nodeFailure(error);
    if (failure !== null) return refuse(io, command.kind, failure.code, failure.step, failure.message);
    throw error;
  } finally { db?.close(); }
}

async function labEvidence(input: EvidenceInput, configPath: string, env: Environment, db: Database): Promise<EvidenceInput> {
  const planPath = env['FLUXWARDEN_LAB_PLAN'];
  if (!planPath) return input;
  try {
    if (policySha256(activePolicy(configStage(configPath))) !== input.manifest.policySha256) throw new Error('unmatched policy');
    const report = input.reconciliation as { executions?: readonly { execution_id: string; from: string; to: string }[] };
    const recovered = (report.executions ?? []).filter(change => change.from === 'UNKNOWN' && ['VERIFIED_SUCCESS', 'VERIFIED_FAILURE'].includes(change.to)).map(change => {
      const view = db.executions.view(change.execution_id), plan = db.executions.plan(change.execution_id);
      const trace = input.executionTrace as readonly { execution_id: string; from: string | null; to: string }[];
      if (view === null || plan === null || view.paymentHash === null || view.status !== change.to ||
          !input.manifest.nodes.some(node => node.pubkey === plan.nodePubkey) ||
          !trace.some(event => event.execution_id === change.execution_id && event.to === 'UNKNOWN') ||
          !trace.some(event => event.execution_id === change.execution_id && event.from === 'UNKNOWN' && event.to === change.to)) throw new Error('unmatched recovery');
      return { id: change.execution_id, hash: view.paymentHash, nodePubkey: plan.nodePubkey, status: view.status };
    });
    const { readDemoEvidence } = await import('../../labs/docker/demo/runtime.mjs');
    const context = await readDemoEvidence({ planPath, configPath, recordedNodes: input.manifest.nodes, recovered });
    const unavailable = { ...input.manifest.unavailableEvidence };
    delete unavailable['image_digests'];
    if (context.scenarios.length > 0) delete unavailable['chaos_scenario_ids'];
    return { ...input, manifest: { ...input.manifest, imageDigests: context.images,
      chaosScenarioIds: context.scenarios.map((scenario: { caseId: string }) => scenario.caseId), unavailableEvidence: unavailable }, chaosResults: context.scenarios };
  } catch { throw new StageFailure(2, 'lab-evidence', 'the recorded run does not match the owned lab evidence'); }
}
