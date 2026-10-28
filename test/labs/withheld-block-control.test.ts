import { expect, it } from 'vitest';
import { withWithheldBlock } from '../../labs/scenarios/chaos/withheld-block.mjs';
import { ownedReference } from '../helpers/owned-reference.js';
import { scratch } from '../helpers/cp016-cli.js';

it('CP-044/OPS-T25-control a mismatched owner refuses before any native command or block preparation', async () => {
  const fixture = ownedReference(scratch('withheld-owner'));
  let calls = 0, bodies = 0, persisted = 0;
  await expect(withWithheldBlock({ owner: { ...fixture.owner, id: 'foreign' }, manifest: fixture.manifest,
    body: () => { bodies++; }, retain: () => undefined, persistBlock: () => { persisted++; },
    run: () => { calls++; throw new Error('unexpected command'); } })).rejects.toThrow('LabInvalidError');
  expect({ calls, bodies, persisted }).toEqual({ calls: 0, bodies: 0, persisted: 0 });
});

it('CP-044/OPS-T25-control an already dirty header gap refuses without mining, restarting or submitting anything', async () => {
  const fixture = ownedReference(scratch('withheld-dirty')), calls: string[] = [];
  await expect(withWithheldBlock({ owner: fixture.owner, manifest: fixture.manifest,
    body: () => { throw new Error('unexpected body'); }, retain: () => undefined,
    persistBlock: () => { throw new Error('unexpected persistence'); },
    run: (_file, args) => {
      if (!Array.isArray(args)) throw new Error('argument vector missing');
      const operation = args[0] === 'inspect' ? 'inspect' : String(args[4]); calls.push(operation);
      const value: unknown = operation === 'inspect' ? fixture.containers : { chain: 'regtest', blocks: 113, headers: 114 };
      return { status: 0, signal: null, output: [null, JSON.stringify(value), ''], pid: 1, stdout: JSON.stringify(value), stderr: '' };
    } })).rejects.toThrow('pre-existing header gap');
  expect(calls).toEqual(['inspect', 'getblockchaininfo']);
});
