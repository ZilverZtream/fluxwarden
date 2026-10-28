import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { Alert, ExecutionAdapter, ExecutionPolicy } from '../../src/core/execution.js';
import type { NormalizedChannel } from '../../src/core/normalize.js';
import type { Msat } from '../../src/core/money.js';
import { input, register } from '../../labs/scenarios/chaos/live-reference.mjs';
import { appendFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

// Ordinary public worker composition over the actual compiled candidate.
// Approval verification, claims, fenced writes and all node calls delegate.
export async function nativeBalanceWorker(configPath: string, database: string, proposalId: string) {
  const url = (path: string): string => pathToFileURL(resolve('dist', path)).href;
  const [{ openDatabase }, { configStage }, { activePolicy, controller }, { handshake }, { resolveConnection },
    { verifiedStoredApproval }, { policySha256 }, { prepareExecution }, { dispatchExecution }] = await Promise.all([
    import(url('persistence/index.js')) as Promise<typeof import('../../src/persistence/index.js')>,
    import(url('commands/stages.js')) as Promise<typeof import('../../src/commands/stages.js')>,
    import(url('commands/workflow.js')) as Promise<typeof import('../../src/commands/workflow.js')>,
    import(url('commands/handshake.js')) as Promise<typeof import('../../src/commands/handshake.js')>,
    import(url('cli/connect.js')) as Promise<typeof import('../../src/cli/connect.js')>,
    import(url('approval/verify.js')) as Promise<typeof import('../../src/approval/verify.js')>,
    import(url('policy/canonical.js')) as Promise<typeof import('../../src/policy/canonical.js')>,
    import(url('executor/preflight.js')) as Promise<typeof import('../../src/executor/preflight.js')>,
    import(url('executor/dispatch.js')) as Promise<typeof import('../../src/executor/dispatch.js')>,
  ]);
  const db = openDatabase(database, { readOnly: false, mustExist: true });
  try {
    const config = configStage(configPath), policy = activePolicy(config), proposal = db.proposals.find(proposalId.replace(/^prop_/, ''));
    if (!proposal || proposal.actionType !== 'CIRCULAR_REBALANCE' || proposal.sourceChannelKey === null || proposal.targetChannelKey === null ||
        proposal.principalMsat === null || proposal.maxFeeMsat === null || proposal.maxFeePpm === null || proposal.maxCltvDelta === null) {
      throw new Error('GAP T-18 genuine approved circular proposal unavailable');
    }
    const node = config.nodes.find(node => node.name === 'lnd-r');
    if (!node || node.implementation !== 'lnd') throw new Error('GAP T-18 owned LND worker unavailable');
    const approval = verifiedStoredApproval({ keys: config.approvalKeys, now: db.now(),
      proposal: { id: proposal.id, nodePubkey: proposal.nodePubkey, sourceChannelKey: proposal.sourceChannelKey,
        targetChannelKey: proposal.targetChannelKey, principalMsat: proposal.principalMsat as Msat, maxFeeMsat: proposal.maxFeeMsat as Msat,
        maxFeePpm: proposal.maxFeePpm, exemptFeeMsat: policy.fees.exempt_fee_msat, maxCltvDelta: proposal.maxCltvDelta,
        policySha256: proposal.policySha256, expiresAt: proposal.expiresAt },
      policy: { sha256: policySha256(policy), maxFeeMsat: policy.fees.max_fee_msat, maxCltvDelta: policy.routing.max_cltv_delta,
        approvalMaxTtlSeconds: policy.approval_max_ttl, maxSnapshotAgeSeconds: policy.max_snapshot_age } }, db.commandData.approvals);
    const executionPolicy: ExecutionPolicy = { sha256: policySha256(policy), network: policy.network,
      maxFeeMsat: policy.fees.max_fee_msat, maxFeePpm: BigInt(policy.fees.max_fee_ppm), exemptFeeMsat: policy.fees.exempt_fee_msat,
      maxCltvDelta: policy.routing.max_cltv_delta, minChannelReserveMsat: policy.amounts.min_channel_reserve_msat,
      minSourceOutboundMsat: policy.targets[node.name]?.[proposal.sourceChannelKey]?.min_outbound_msat ?? 0n,
      budget: { msat: policy.budget.msat, periodMs: policy.budget.period * 1000 }, cooldownAfterFailureMs: policy.cooldown_after_failure * 1000,
      cooldownAfterSuccessMs: policy.cooldown_after_success * 1000, maxInFlight: policy.max_in_flight,
      maxSnapshotAgeMs: policy.max_snapshot_age * 1000, excludeChannels: policy.exclude_channels };
    const session = await handshake(db, node, resolveConnection(node, {}, {})), native = await controller(node, config, session, db);
    const execution: ExecutionAdapter = native.adapter;
    const mutatingCalls: string[] = [], channelObservations: (readonly NormalizedChannel[])[] = [], alerts: Alert[] = [];
    const adapter = { ...native.adapter,
      listChannels: async () => { const channels = await execution.listChannels(); channelObservations.push(channels); return channels; },
      createInvoice: (...args: Parameters<ExecutionAdapter['createInvoice']>) => { mutatingCalls.push('createInvoice'); return execution.createInvoice(...args); },
      sendOnRoute: (...args: Parameters<ExecutionAdapter['sendOnRoute']>) => { mutatingCalls.push('sendOnRoute'); return execution.sendOnRoute(...args); },
      cancelUnpaidInvoice: (...args: Parameters<ExecutionAdapter['cancelUnpaidInvoice']>) => { mutatingCalls.push('cancelUnpaidInvoice'); return execution.cancelUnpaidInvoice(...args); },
    };
    return { db, approval, executionPolicy, mutatingCalls, channelObservations, alerts,
      prepare: () => prepareExecution({ db, adapter, workerId: 'owned-t18-balance', leaseMs: 180000 },
        { approval, policy: executionPolicy, approvalKeyIds: config.approvalKeys.map(key => key.keyId) }),
      dispatch: (ready: { executionId: string; fenceEpoch: bigint; route: Parameters<typeof dispatchExecution>[1]['route'] }) => {
        const p = input();
        return dispatchExecution({ db, adapter, workerId: 'owned-t18-balance', leaseMs: 180000, randomBytes: size => {
          const bytes = randomBytes(size), path = join(p.tmp, `t18-dispatch-${ready.executionId}.preimage.bin`);
          writeFileSync(path, bytes, { mode: 0o600 }); appendFileSync(join(p.tmp, 'declared-out.txt'), `${path}\n`); register(path, `t18-dispatch-${ready.executionId}.preimage.bin`); return bytes;
        }, stopSignal: new AbortController().signal, attemptDeadlineMs: config.attemptDeadlineMs, invoiceExpirySeconds: 300,
        deltaToleranceMsat: config.deltaToleranceMsat, alert: alert => { alerts.push(alert); } },
        { ...ready, approval, policy: executionPolicy });
      },
    };
  } catch (error) { db.close(); throw error; }
}
