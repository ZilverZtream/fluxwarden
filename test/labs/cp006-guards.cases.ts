import { expect, it } from 'vitest';
import { identityControl, loadLab, options, owner } from '../helpers/cp006-lab.js';

// SECURITY 4.4: exact regtest only. Targets rotate so every managed/setup node is guarded.
const nodes = ['lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m'];
const forbidden = ['mainnet', 'testnet', 'testnet4', 'signet', 'simnet', 'bitcoin', 'liquid', 'liquid-regtest', 'unknown', ''];
for (const [index, network] of forbidden.entries()) {
  const target = nodes[index % nodes.length] ?? 'lnd-p';
  it(`CP-006/B2 ${target} refuses ${network === '' ? 'empty' : network} before funding and removes its partial owner`, async () => {
    const selected = await owner(); selected.resources = { cpus: 4, memoryBytes: 4294967296, pids: 1024 }; const fake = identityControl(selected, target, 'network', network);
    const lab = (await loadLab()).createLab(await options(selected, fake.run));
    await expect(lab.up()).rejects.toThrow();
    expect(fake.calls.some(args => args.includes(target) && args.includes('getinfo')), 'forbidden identity actually observed').toBe(true);
    expect(fake.calls.some(args => args.includes('down') && args.includes(selected.project)), 'newly owned resources cleaned').toBe(true);
    expect(fake.calls.some(args => ['generatetoaddress', 'sendtoaddress', 'openchannel', 'fundchannel'].some(method => args.includes(method))), 'no setup mutation after guard').toBe(false);
  });
}

const versions: [string, unknown, string][] = [
  ['lnd-p', '0.20.0-beta', 'older LND'], ['lnd-r', '0.21.4-beta-custom', 'unrecognized custom LND'],
  ['cln-p', 'v26.06.8', 'older CLN'], ['cln-r', 'v26.06.9-custom', 'unrecognized custom CLN'],
  ['cln-m', '', 'empty CLN'], ['lnd-p', null, 'malformed LND'],
];
for (const [target, version, description] of versions) {
  it(`CP-006/B3 ${target} refuses ${description} before money-moving setup`, async () => {
    const selected = await owner(); selected.resources = { cpus: 4, memoryBytes: 4294967296, pids: 1024 }; const fake = identityControl(selected, target, 'version', version);
    const lab = (await loadLab()).createLab(await options(selected, fake.run));
    await expect(lab.up()).rejects.toThrow();
    expect(fake.calls.some(args => args.includes(target) && args.includes('getinfo')), 'wrong pinned version actually observed').toBe(true);
    expect(fake.calls.some(args => args.includes('down')), 'partial resources cleaned').toBe(true);
    expect(fake.calls.some(args => ['generatetoaddress', 'sendtoaddress', 'openchannel', 'fundchannel'].some(method => args.includes(method))), 'version refusal precedes money').toBe(false);
  });
}
