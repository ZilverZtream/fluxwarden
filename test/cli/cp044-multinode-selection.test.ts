// Oracle: D29 readiness scope decision, F06: multi-node diagnosis/planning require
// --node, exit 2 before contact. Explicit selection and singleton defaults remain supported.
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { channel, getInfo } from '../fakes/lnd/responses.js';
import { peerChannel } from '../fakes/cln/responses.js';
import { clnNode, createDatabase, lndNode, nodeCert, runCli, scratch, writeConfig, writePolicy, type NodeEntry } from '../helpers/cp016-cli.js';
import { registerMoneySafetyCredentials } from '../helpers/public-money-safety.js';
import { declareFixturePaths } from '../helpers/capture-fixture.js';

const servers: FakeServer[] = [];
const beforeCredentialWrite = (path: string): void => declareFixturePaths([path]);
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });

for (const command of ['diagnose', 'plan'] as const) {
  for (const order of ['alpha-first', 'bravo-first'] as const) {
    it(`CP-044/F06 ${command} refuses implicit multi-node selection before contact (${order})`, async () => {
      const dir = scratch('cp044-multinode'), database = join(dir, 'state', 'fluxwarden.db');
      await createDatabase(database);
      const alpha = await lndNode(dir, servers, { info: getInfo({ pubkey: `02${'a1'.repeat(32)}` }), channels: [channel()], beforeCredentialWrite });
      const bravo = await clnNode(dir, servers, { channels: [peerChannel()], beforeCredentialWrite });
      registerMoneySafetyCredentials([alpha.macaroon, bravo.runeFile]);
      const nodes: NodeEntry[] = [
        { name: 'alpha', implementation: 'lnd', url: alpha.url, tlsCert: nodeCert(), credential: alpha.macaroon, expectedPubkey: `02${'a1'.repeat(32)}` },
        { name: 'bravo', implementation: 'cln', url: bravo.url, tlsCert: nodeCert(), credential: bravo.runeFile, expectedPubkey: `03${'d4'.repeat(32)}` },
      ];
      if (order === 'bravo-first') nodes.reverse();
      const policy = writePolicy(dir, { alpha: { '892945371103232001': { minInbound: '0' } }, bravo: { '812x1x0': { minInbound: '0' } } });
      const config = writeConfig(dir, { database, policy, nodes });
      const run = await runCli(['--json', 'liquidity', command, ...(command === 'plan' ? ['--refresh'] : []), '--config', config]);
      expect.soft(run.status).toBe(2);
      const document = JSON.parse(run.stdout) as { error?: { code?: number; message?: string }; result?: unknown };
      expect.soft(document.error?.code).toBe(2);
      expect.soft(document.error?.message).toContain('--node');
      expect.soft(document.result).toBeNull();
      expect.soft(alpha.fake.requests.length).toBe(0);
      expect(bravo.fake.requests.length).toBe(0);
    });
  }

  it(`CP-044/F06 ${command} supports explicit selection and a singleton default`, async () => {
    const dir = scratch('cp044-selected'), database = join(dir, 'state', 'fluxwarden.db');
    await createDatabase(database);
    const alpha = await lndNode(dir, servers, { channels: [channel()], beforeCredentialWrite }),
      bravo = await clnNode(dir, servers, { channels: [peerChannel()], beforeCredentialWrite });
    registerMoneySafetyCredentials([alpha.macaroon, bravo.runeFile]);
    const alphaEntry: NodeEntry = { name: 'alpha', implementation: 'lnd', url: alpha.url, tlsCert: nodeCert(),
      credential: alpha.macaroon, expectedPubkey: `02${'a1'.repeat(32)}` };
    const bravoEntry: NodeEntry = { name: 'bravo', implementation: 'cln', url: bravo.url, tlsCert: nodeCert(),
      credential: bravo.runeFile, expectedPubkey: `03${'d4'.repeat(32)}` };
    const policy = writePolicy(dir, { alpha: { '892945371103232001': { minInbound: '0' } }, bravo: { '812x1x0': { minInbound: '0' } } });
    for (const explicit of [true, false]) {
      const config = writeConfig(dir, { database, policy, nodes: explicit ? [bravoEntry, alphaEntry] : [alphaEntry] });
      const run = await runCli(['--json', 'liquidity', command, ...(command === 'plan' ? ['--refresh'] : []),
        ...(explicit ? ['--node', 'alpha'] : []), '--config', config]);
      expect(run.status).toBe(0);
    }
    expect(alpha.fake.requests.length).toBeGreaterThan(0);
    expect(bravo.fake.requests.length).toBe(0);
  });
}
