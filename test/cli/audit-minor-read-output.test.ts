// Interface: read-only built CLI commands against ordinary local node replies.
import { readFileSync, writeFileSync } from 'node:fs';
import { afterEach, beforeAll, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { methodsOf, S } from '../fakes/cln/rebalance-node.js';
import { demo, jsonDocument, plan, prepareDemoFixtures, rec, type DemoFixtures } from '../helpers/cpw-cli.js';

const servers: FakeServer[] = [];
let fixtures: DemoFixtures;
beforeAll(async () => { fixtures = await prepareDemoFixtures(); });
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });

for (const alias of ['ordinary-local-alias', 'é'.repeat(200), '🙂'.repeat(100)]) {
  it(`CP-016/B8 REG-CLI019 bounds the JSON alias to 256 UTF8 bytes for ${alias.startsWith('\u00e9') ? 'accent' : alias.startsWith('\u{1f642}') ? 'emoji' : 'ordinary'} alias (${String(alias.length)} characters)`, async () => {
    const d = await demo(servers, { fixtures });
    const respond = d.cln.fake.result;
    d.cln.fake.result = (context, behaviour, value) => {
      if (behaviour === 'getinfo') rec(value)['alias'] = alias;
      respond(context, behaviour, value);
    };
    const result = await d.run(['--json', 'nodes', 'inspect', 'cln-m']);
    expect(result.status, result.stdout + result.stderr).toBe(0);
    const output = rec(jsonDocument(result)['result'])['alias'];
    expect(typeof output).toBe('string');
    expect(Buffer.byteLength(String(output), 'utf8')).toBeLessThanOrEqual(256);
    expect(String(output)).not.toContain('\ufffd');
    if (Buffer.byteLength(alias, 'utf8') <= 256) expect(output).toBe(alias);
    else expect(String(output).length).toBeGreaterThan(0);
  });
}

it('CP-016/B8 REG-CLI018 bounds node-supplied JSON error messages to 1 KiB while retaining the failure classification', async () => {
  const d = await demo(servers, { fixtures });
  const prefix = 'ordinary-node-error: ';
  const noisy = prefix + 'é'.repeat(3000);
  const respond = d.cln.fake.result;
  d.cln.fake.result = (context, behaviour, value) => {
    if (behaviour === 'getinfo') { d.cln.fake.raw(context, 'rpc-error', 500, JSON.stringify({ code: -1, message: noisy, data: null })); return; }
    respond(context, behaviour, value);
  };
  const result = await d.run(['--json', 'nodes', 'inspect', 'cln-m']);
  expect(result.status, result.stdout + result.stderr).toBe(4);
  const error = rec(jsonDocument(result)['error']);
  expect(error['code']).toBe(4);
  expect(String(error['message']).length).toBeGreaterThan(0);
  expect(Buffer.byteLength(String(error['message']), 'utf8')).toBeLessThanOrEqual(1024);
});

it('CP-016/B6 REG-CLI015 doctor classifies missing SQLite capability as exit 3 and works with SQLite available', async () => {
  const d = await demo(servers, { fixtures });
  const good = await d.run(['--json', 'doctor']);
  expect(good.status, good.stdout + good.stderr).toBe(0);
  const before = methodsOf(d.cln.fake);
  const unavailable = await d.run(['--json', 'doctor'], { nodeArgs: ['--no-experimental-sqlite'] });
  expect(unavailable.status, unavailable.stdout + unavailable.stderr).toBe(3);
  expect(rec(jsonDocument(unavailable)['error'])['code']).toBe(3);
  expect(methodsOf(d.cln.fake)).toEqual(before);
});

it('CP-016/B1 REG-POL014 config mapping separation spaces preserve supported keys', async () => {
  const d = await demo(servers, { fixtures });
  const original = readFileSync(d.config, 'utf8');
  writeFileSync(d.config, original.replace('database:', 'database :').replace('policy:', 'policy  :').replace('nodes:', 'nodes :'));
  const result = await d.run(['--json', 'nodes', 'list']);
  expect(result.status, result.stdout + result.stderr).toBe(0);
  expect(rec(jsonDocument(result)['result'])['nodes']).toHaveLength(1);
});

it('CP-025/B1 REG-POL005 plan and channels share the same single-document target input', async () => {
  const d = await demo(servers, { fixtures });
  writeFileSync(d.policy, '---\n' + readFileSync(d.policy, 'utf8'));
  expect((await plan(d))['action']).toBe('CIRCULAR_REBALANCE');
  const channels = await d.run(['--json', 'channels', '--node', 'cln-m']);
  expect(channels.status, channels.stdout + channels.stderr).toBe(0);
  const nodes = rec(jsonDocument(channels)['result'])['nodes'] as Record<string, unknown>[];
  const listed = rec(nodes[0])['channels'] as Record<string, unknown>[];
  expect(listed.find(entry => entry['channel'] === S)).toMatchObject({ inbound_target_msat: '400000000', inbound_deficit_msat: '300000000' });
  writeFileSync(d.policy, readFileSync(d.policy, 'utf8') + '\n---\nversion: 3\n');
  for (const args of [['liquidity', 'plan', '--refresh'], ['channels', '--node', 'cln-m']]) {
    const result = await d.run(['--json', ...args]);
    expect(result.status, result.stdout + result.stderr).toBe(2);
    expect(rec(jsonDocument(result)['error'])['code']).toBe(2);
  }
});
