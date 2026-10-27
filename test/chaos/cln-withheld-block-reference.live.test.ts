import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { withWithheldBlock } from '../../labs/scenarios/chaos/withheld-block.mjs';
import { clean, cli, clnConfig, history, initializeRegistry, input, oracle, preflight, query, retain, setRunner, unchangedOld } from '../../labs/scenarios/chaos/live-reference.mjs';
import { LabInvalidError } from '../helpers/chaos.js';
setRunner((file, args, options) => spawnSync(file, args, options));

// Primary references: Bitcoin Core v31.1 src/rpc/mining.cpp generateblock,
// submitheader and submitblock; CLN v26.06.9 lightningd/chaintopology.c:1229-1257
// and peer_control.c:3376-3381. This proves only native CLN sync=false through
// warning_bitcoind_sync. It does not claim LND, HTLC-limit/dust/backoff variants.
it('CP-044/OPS-T25 T-25 CLN native unsynced warning persists across execute refusal while exactly one block body is withheld', async () => {
  initializeRegistry(); await preflight('t25-cln-header-before');
  const p = input(), original = history(), fixture = clnConfig('t25-header');
  const owner = p.owner as typeof p.owner & { evidenceRoot: string; id: string };
  const record = (name: string, value: unknown): void => {
    retain(name, value);
    if (resolve(p.evidence) !== resolve(owner.evidenceRoot)) writeFileSync(join(owner.evidenceRoot, `${name}.json`), JSON.stringify(value), { flag: 'wx', mode: 0o600 });
  };
  const build = JSON.parse(readFileSync(resolve('dist/evidence/build-info.json'), 'utf8')) as { gitCommit?: unknown };
  if (typeof build.gitCommit !== 'string' || !/^[a-f0-9]{40}$/.test(build.gitCommit)) throw new LabInvalidError('T-25 actual compiled source identity unavailable');
  const verifyCleanup = async (): Promise<void> => {
    try { await preflight('t25-cln-header-after'); }
    catch { throw new LabInvalidError('T-25 owned cohort did not return to its clean pinned state'); }
  };
  try {
    expect(cli(['doctor'], 't25-cln-header-doctor', fixture.config).exit).toBe(0);
    const planned = cli(['liquidity', 'plan', '--refresh'], 't25-cln-header-plan', fixture.config);
    expect(planned.exit).toBe(0);
    expect(planned.body.result).toMatchObject({ action: 'CIRCULAR_REBALANCE', principal_msat: '100000000' });
    const proposal = String(planned.body.result['proposal_id']);
    expect(cli(['liquidity', 'approve', proposal, '--key', p.key], 't25-cln-header-approval', fixture.config).exit).toBe(0);
    const before = { payments: oracle('cln-m', 'listsendpays'), invoices: oracle('cln-m', 'listinvoices') };
    record('t25-cln-header-native-money-before', before);
    await withWithheldBlock({ owner: p.owner, manifest: p.manifest, retain: record,
      persistBlock: block => {
        const path = join(mkdtempSync(join(p.tmp, 't25-withheld-')), 'block.json');
        writeFileSync(path, JSON.stringify(block), { flag: 'wx', mode: 0o600 });
        record('t25-cln-header-recovery-input', { blockHash: block.hash, bodyPath: path });
      },
      body: () => {
        const refused = cli(['actions', 'execute', proposal, '--require-regtest'], 't25-cln-header-execute', fixture.config);
        expect(refused).toMatchObject({ exit: 5, body: { error: { step: 'chain-sync' } } });
        const after = { payments: oracle('cln-m', 'listsendpays'), invoices: oracle('cln-m', 'listinvoices') };
        record('t25-cln-header-native-money-after', after);
        expect(after).toEqual(before);
        expect(query(fixture.database, 'SELECT payment_hash FROM executions WHERE payment_hash IS NOT NULL')).toEqual([]);
      },
    });
    unchangedOld(original, history());
  } finally {
    await clean();
    await verifyCleanup();
  }
  record('t25-cln-header-scenario', { caseId: 'T-25', variant: 'CLN native warning_bitcoind_sync; one withheld block body',
    ownerId: owner.id, project: owner.project, sourceCommit: build.gitCommit, pass: true, exit: 5, step: 'chain-sync',
    nativeInvoiceAndPaymentInventoryUnchanged: true, allOwnedNodesRestoredAndSynced: true,
    remainingScope: 'No LND synced_to_chain=false, local HTLC/dust/bandwidth, cooldown or retry-backoff proof claimed.' });
});
