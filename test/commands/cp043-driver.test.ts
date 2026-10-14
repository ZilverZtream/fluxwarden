/* Interface: demo driver helpers validate observed proposal terms, a persisted successful public execution
 * receipt, and the open policy descriptor after asynchronous preparation (SPEC §14.1, INV-02/08/09).
 * The runtime preparation port follows labs/docker/demo/runtime.d.mts; node execution uses existing CLI fakes.
 */
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, beforeAll, expect, it, vi } from 'vitest';
import { repoRoot } from '../helpers/cli.js';
import { approve, demo as createDemo, documentOf, plan, prepareDemoFixtures, resultOf, rows, type DemoFixtures, type DemoOptions } from '../helpers/cpw-cli.js';
import { S, T } from '../fakes/cln/rebalance-node.js';
import type { FakeServer } from '../fakes/https.js';

interface Driver {
  verifyDemoProposal(proposal: Record<string, unknown>, policyHash: string, channels: { channel2: string; channel5: string }): void;
  verifyDemoExecution(config: string, executionId: string, channels: { channel2: string; channel5: string }): unknown;
  prepareDemoPhase(input: { phase: string; planPath: string; configPath: string; policyPath: string; signal: AbortSignal }): Promise<unknown>;
}
const driver = async () => await import(pathToFileURL(join(repoRoot, 'labs/docker/demo/driver.mjs')).href) as Driver;
const open: FakeServer[] = [];
let fixtures: DemoFixtures;
beforeAll(async () => { fixtures = await prepareDemoFixtures(); });
const demo = (servers: FakeServer[], options: DemoOptions = {}) => createDemo(servers, { ...options, fixtures });
afterEach(async () => {
  vi.restoreAllMocks(); syncBuiltinESMExports();
  vi.doUnmock('../../labs/docker/demo/runtime.mjs'); vi.resetModules();
  await Promise.all(open.splice(0).map(server => server.close()));
});

it('CP-043/B3 observed proposal fee 202101 is accepted and fee 202102 alone is refused', async () => {
  const d = await demo(open, { withKey: false });
  const observed = await plan(d), m = await driver();
  expect(observed['principal_msat']).toBe('100000000');
  expect(observed['route']).toMatchObject({ fee_msat: '202101', fee_ppm: 2022, cltv_delta: 132 });
  expect(() => { m.verifyDemoProposal(observed, String(observed['policy_sha256']), { channel2: S, channel5: T }); }).not.toThrow();
  const wrong = structuredClone(observed);
  (wrong['route'] as Record<string, unknown>)['fee_msat'] = '202102';
  expect(() => { m.verifyDemoProposal(wrong, String(observed['policy_sha256']), { channel2: S, channel5: T }); }).toThrow();
});

it('CP-043/B3 an ordinary raw ULID success receipt matches the persisted execution and continues ledger verification reconciliation and export', async () => {
  const d = await demo(open), proposal = await plan(d), id = String(proposal['proposal_id']);
  await approve(d, id);
  const executed = await d.run(['--json', 'actions', 'execute', id, '--require-regtest']);
  expect(executed.status).toBe(0);
  const receipt = resultOf(documentOf(executed, 'actions-execute'));
  const executionId = String(receipt['execution_id']);
  expect(executionId).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
  expect(receipt).toMatchObject({ status: 'VERIFIED_SUCCESS', principal_msat: '100000000', actual_fee_msat: '202101',
    source_delta_msat: '-100202101', target_delta_msat: '100000000', delta_status: 'MATCH' });
  expect(rows(d.database, 'SELECT id, status, actual_fee_msat FROM executions WHERE id = ?', executionId)).toEqual([
    { id: executionId, status: 'VERIFIED_SUCCESS', actual_fee_msat: 202101 },
  ]);
  const m = await driver();
  expect(() => m.verifyDemoExecution(d.config, executionId, { channel2: S, channel5: T })).not.toThrow();
  expect((await d.run(['--json', 'ledger', 'verify'])).status).toBe(0);
  const reconciled = await d.run(['--json', 'reconcile', '--node', 'cln-m', '--since', '1h']);
  expect(reconciled.status).toBe(0);
  const runId = String(resultOf(documentOf(reconciled, 'reconcile'))['run_id']);
  expect(runId).toMatch(/^run_[0-9A-HJKMNP-TV-Z]{26}$/);
  const out = join(d.dir, 'verified-bundle');
  const exported = await d.run(['--json', 'evidence', 'export', '--run-id', runId, '--out', out]);
  expect(exported.status).toBe(0);
  for (const name of ['manifest.json', 'ledger-audit.json', 'reconciliation.json', 'checksums.sha256']) expect(fs.existsSync(join(out, name)), name).toBe(true);
});

it('CP-043/B3 policy contents changed on the opened descriptor after asynchronous drain refuse without overwriting the change', async () => {
  const d = await demo(open, { withKey: false });
  const original = fs.readFileSync(d.policy, 'utf8').replace('cooldown_after_success: 30m', 'cooldown_after_success: 1s');
  fs.writeFileSync(d.policy, original);
  if (process.platform !== 'win32') fs.chmodSync(d.policy, 0o600);
  const changed = original.replace('max_fee_msat: "300000"', 'max_fee_msat: "300001"');
  expect(changed).not.toBe(original);
  let inbound = 1_250_000_000n, drained = false, changedDescriptor = false;
  const close = vi.fn(() => Promise.resolve());
  vi.doMock('../../labs/docker/demo/runtime.mjs', () => ({ createRuntimeLab: () => Promise.resolve({
    preparation: {
      identity: () => Promise.resolve({ network: 'regtest' }),
      channels: () => Promise.resolve({ channel2ReceivableMsat: inbound, channel5ReceivableMsat: 1_250_000_000n }),
      checkout: async (request: { amountMsat: bigint }) => { await Promise.resolve(); inbound -= request.amountMsat; drained = inbound === 5_000_000n; return { status: 'SUCCEEDED' }; },
      channelKeys: () => Promise.resolve({ channel2: S, channel5: T }), record: () => undefined,
    }, close,
  }) }));
  const actualOpen = fs.openSync;
  vi.spyOn(fs, 'openSync').mockImplementation((path, flags, mode) => {
    const fd = actualOpen(path, flags, mode);
    if (drained && String(path) === d.policy && typeof flags === 'number' && (flags & fs.constants.O_RDWR) === fs.constants.O_RDWR) {
      fs.writeFileSync(fd, changed); changedDescriptor = true;
    }
    return fd;
  });
  syncBuiltinESMExports();
  const m = await driver();
  await expect(m.prepareDemoPhase({ phase: 'starvation', planPath: join(d.dir, 'unused-plan.json'), configPath: d.config,
    policyPath: d.policy, signal: new AbortController().signal })).rejects.toThrow('changed');
  expect(drained).toBe(true); expect(changedDescriptor).toBe(true); expect(close).toHaveBeenCalledTimes(1);
  expect(fs.readFileSync(d.policy, 'utf8')).toBe(changed);
});
