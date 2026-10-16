// Interface: the built CLI and existing isolated CLN demo fixtures.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeAll, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { methodsOf } from '../fakes/cln/rebalance-node.js';
import { approve, demo, documentOf, jsonDocument, plan, prepareDemoFixtures, rec, runCli, type DemoFixtures } from '../helpers/cpw-cli.js';

const servers: FakeServer[] = [];
let fixtures: DemoFixtures;
beforeAll(async () => { fixtures = await prepareDemoFixtures(); });
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });

for (const authority of ['missing-config', 'malformed-config', 'unreadable-config', 'selected-node', 'approval-key', 'execution-credential'] as const) {
  it(`CP-026/B3 REG-CLI001 REG-CLI002 REG-CLI004 ${authority} refuses execution with safety code and zero node contact (INV-01)`, async () => {
    const d = await demo(servers, { fixtures });
    const proposal = String((await plan(d))['proposal_id']);
    await approve(d, proposal);
    const args = ['--json', 'actions', 'execute', proposal, '--require-regtest'];
    let config = d.config;
    if (authority === 'missing-config') config = join(d.dir, 'absent.yaml');
    if (authority === 'unreadable-config') config = d.dir;
    if (authority === 'malformed-config') writeFileSync(config, 'nodes:\n\tinvalid: configuration\n');
    if (authority === 'selected-node') writeFileSync(config, readFileSync(config, 'utf8').replace('name: cln-m', 'name: other-local-node'));
    if (authority === 'approval-key') d.rewrite({ approvalKeys: [] });
    if (authority === 'execution-credential') writeFileSync(config, readFileSync(config, 'utf8').replace(/rune_path: "[^"]+"/, `rune_path: "${join(d.dir, 'absent.rune').replaceAll('\\', '/')}"`));
    const before = methodsOf(d.cln.fake);
    const connections = d.cln.fake.connections();
    const result = await runCli([...args, '--config', config]);
    expect.soft(result.status, result.stdout + result.stderr).toBe(5);
    expect.soft(rec(jsonDocument(result)['error'])['code']).toBe(5);
    expect(methodsOf(d.cln.fake)).toEqual(before);
    expect(d.cln.fake.connections()).toBe(connections);
    expect(result.stdout + result.stderr).not.toContain(d.cln.rune);
  });
}

for (const network of ['mainnet', 'testnet', 'signet', 'unknown-network']) {
  it(`CP-026/B3 REG-POL001 configured node network ${network} refuses execution with exit 5 and zero RPC (INV-15)`, async () => {
    const d = await demo(servers, { fixtures });
    const proposal = String((await plan(d))['proposal_id']);
    await approve(d, proposal);
    writeFileSync(d.config, readFileSync(d.config, 'utf8').replace('expected_network: regtest', `expected_network: ${network}`));
    const before = methodsOf(d.cln.fake);
    const connections = d.cln.fake.connections();
    const result = await d.run(['--json', 'actions', 'execute', proposal, '--require-regtest']);
    expect.soft(result.status, result.stdout + result.stderr).toBe(5);
    expect.soft(rec(jsonDocument(result)['error'])['code']).toBe(5);
    expect(methodsOf(d.cln.fake)).toEqual(before);
    expect(d.cln.fake.connections()).toBe(connections);
  });
}

it('CP-016/B1 REG-CLI001 read commands retain invalid configuration exit 2 and valid configured reads work', async () => {
  const d = await demo(servers, { fixtures });
  const before = methodsOf(d.cln.fake);
  const good = await d.run(['--json', 'nodes', 'list']);
  expect(good.status, good.stdout + good.stderr).toBe(0);
  const config = join(d.dir, 'malformed.yaml');
  writeFileSync(config, 'nodes:\n\tinvalid: configuration\n');
  for (const args of [['nodes', 'list'], ['channels', '--node', 'cln-m'], ['doctor']]) {
    const bad = await runCli(['--json', ...args, '--config', config]);
    expect(bad.status, bad.stdout + bad.stderr).toBe(2);
    expect(rec(jsonDocument(bad)['error'])['code']).toBe(2);
  }
  expect(methodsOf(d.cln.fake)).toEqual(before);
});

it('CP-026/B3 REG-CLI002 a configured approved regtest execution retains its valid authority', async () => {
  const d = await demo(servers, { fixtures });
  const proposal = String((await plan(d))['proposal_id']);
  await approve(d, proposal);
  const result = await d.run(['--json', 'actions', 'execute', proposal, '--require-regtest']);
  expect(result.status, result.stdout + result.stderr).toBe(0);
  expect(documentOf(result, 'actions-execute')).toMatchObject({ ok: true, error: null });
  expect(methodsOf(d.cln.fake).filter(method => method === 'sendpay')).toHaveLength(1);
});
