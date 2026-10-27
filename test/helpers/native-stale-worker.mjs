// Test-owned process driver over ordinary public repositories and preflight.
// No node answer, database write outcome, clock or production hook is replaced.
import { readFileSync, readSync, writeSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const load = name => import(pathToFileURL(resolve(root, 'dist', name)).href);
const report = value => writeSync(1, `${JSON.stringify(value)}\n`);
const input = JSON.parse(readFileSync(process.argv[2], 'utf8')), role = process.argv[3];
const { openDatabase } = await load('persistence/index.js');
const db = openDatabase(input.database, { readOnly: false, mustExist: true });
try {
  if (role === 'takeover') {
    const before = db.executions.view(input.executionId);
    if (!before || before.status !== 'CLAIMED' || before.leaseExpiresAt > db.now()) throw new Error('natural lease expiry not observed');
    const taken = db.executions.takeOver(input.executionId, 'owned-native-winner', 60_000);
    if (!taken || taken.fenceEpoch <= before.fenceEpoch) throw new Error('real takeover unavailable');
    report({ kind: 'winner', executionId: input.executionId, fenceEpoch: String(taken.fenceEpoch) });
  } else if (role === 'stale') {
    const [{ configStage }, { activePolicy, controller }, { handshake }, { resolveConnection }, { verifiedStoredApproval },
      { policySha256 }, { prepareExecution }] = await Promise.all([
      load('commands/stages.js'), load('commands/workflow.js'), load('commands/handshake.js'), load('cli/connect.js'),
      load('approval/verify.js'), load('policy/canonical.js'), load('executor/preflight.js'),
    ]);
    const config = configStage(input.config), policy = activePolicy(config), proposal = db.proposals.find(input.proposalId);
    if (!proposal || proposal.actionType !== 'CIRCULAR_REBALANCE' || proposal.sourceChannelKey === null || proposal.targetChannelKey === null) throw new Error('approved fixture missing');
    const node = config.nodes.find(node => node.name === proposal.nodeName);
    if (!node || node.implementation !== 'cln') throw new Error('owned CLN fixture missing');
    const terms = { id: proposal.id, nodePubkey: proposal.nodePubkey, sourceChannelKey: proposal.sourceChannelKey,
      targetChannelKey: proposal.targetChannelKey, principalMsat: proposal.principalMsat, maxFeeMsat: proposal.maxFeeMsat,
      maxFeePpm: proposal.maxFeePpm, exemptFeeMsat: BigInt(JSON.parse(proposal.reasonJson).exempt_fee_msat),
      maxCltvDelta: proposal.maxCltvDelta, policySha256: proposal.policySha256, expiresAt: proposal.expiresAt };
    const approval = verifiedStoredApproval({ keys: config.approvalKeys, proposal: terms, now: db.now(),
      policy: { sha256: policySha256(policy), maxFeeMsat: policy.fees.max_fee_msat, maxCltvDelta: policy.routing.max_cltv_delta,
        approvalMaxTtlSeconds: policy.approval_max_ttl, maxSnapshotAgeSeconds: policy.max_snapshot_age } }, db.commandData.approvals);
    // Construct the actual native adapter before the barrier, using the ordinary
    // pinned public handshake/controller. It remains the worker's real port.
    const session = await handshake(db, node, resolveConnection(node, {}, {}));
    const native = await controller(node, config, session, db);
    let resumed = false, claimBarrierPassed = false;
    const postBarrierNativeCalls = [], fencedWriteLosses = [];
    const adapter = new Proxy(native.adapter, { get(target, key) {
      const value = Reflect.get(target, key);
      if (typeof value !== 'function') return value;
      return (...args) => { if (resumed) postBarrierNativeCalls.push(String(key)); return Reflect.apply(value, target, args); };
    } });
    const real = db.executions;
    const executions = { ...real,
      claim(work) {
        const result = real.claim(work);
        if (!result.ok || claimBarrierPassed) throw new Error('fresh single claim required');
        claimBarrierPassed = true;
        const view = real.view(result.executionId);
        // Synchronous pipe output and input: parent observes this committed row
        // and performs a separate process's takeover before releasing one byte.
        report({ kind: 'claimed', executionId: result.executionId, fenceEpoch: String(result.fenceEpoch), leaseExpiresAt: view.leaseExpiresAt,
          publicWorkerLeaseMs: 2000 });
        const byte = Buffer.alloc(1);
        if (readSync(0, byte, 0, 1, null) !== 1 || byte[0] !== 1) throw new Error('owned resume barrier unavailable');
        resumed = true;
        return result;
      },
      transition(...args) {
        try { return real.transition(...args); }
        catch (error) {
          if (error?.code === 'LEASE_LOST') fencedWriteLosses.push({ code: error.code, attemptedFenceEpoch: String(args[1]),
            observedWinnerFenceEpoch: String(real.view(args[0]).fenceEpoch) });
          throw error;
        }
      },
    };
    const executionPolicy = { sha256: policySha256(policy), network: policy.network,
      maxFeeMsat: policy.fees.max_fee_msat, maxFeePpm: BigInt(policy.fees.max_fee_ppm), exemptFeeMsat: policy.fees.exempt_fee_msat,
      maxCltvDelta: policy.routing.max_cltv_delta, minChannelReserveMsat: policy.amounts.min_channel_reserve_msat,
      minSourceOutboundMsat: policy.targets[node.name]?.[proposal.sourceChannelKey]?.min_outbound_msat ?? 0n,
      budget: { msat: policy.budget.msat, periodMs: policy.budget.period * 1000 },
      cooldownAfterFailureMs: policy.cooldown_after_failure * 1000, cooldownAfterSuccessMs: policy.cooldown_after_success * 1000,
      maxInFlight: policy.max_in_flight, maxSnapshotAgeMs: policy.max_snapshot_age * 1000, excludeChannels: policy.exclude_channels };
    const outcome = await prepareExecution({ db: { ...db, executions }, adapter, workerId: 'owned-native-stale', leaseMs: 2000 },
      { approval, policy: executionPolicy, approvalKeyIds: config.approvalKeys.map(key => key.keyId) });
    report({ kind: 'finished', outcome, fencedWriteLosses, postBarrierNativeCalls, publicWorkerLeaseMs: 2000 });
    process.exitCode = outcome.exit ?? 8;
  } else throw new Error('unknown worker role');
} catch (error) {
  // No uncontrolled exception text, node response or credential is printed.
  report({ kind: 'driver-error', name: error?.name ?? 'unknown', code: error?.code ?? null });
  process.exitCode = 1;
} finally { db.close(); }
