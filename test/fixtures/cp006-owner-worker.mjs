import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const [declaration, control, labEntry, permissionEntry] = process.argv.slice(2);
const owner = JSON.parse(readFileSync(declaration, 'utf8'));
const { observedLab } = await import(pathToFileURL(control).href);
const { createLab } = await import(pathToFileURL(labEntry).href);
const permission = await import(pathToFileURL(permissionEntry).href);
const fake = observedLab(owner, { onCommand: async row => {
  if (row.method === 'up') {
    const release = new Promise(resolve => process.once('message', message => { if (message === 'release') resolve(); else throw new Error('invalid independent barrier release'); }));
    process.send({ kind: 'acquired', pid: process.pid, project: owner.project });
    await release;
  }
} });
const lab = createLab({ owner, run: fake.run, clock: fake.clock, delay: fake.delay, permissions: { create: permission.createPrivateDirectory, assert: permission.assertPrivateDirectory } });
try {
  await lab.up(); await lab.down();
  process.send({ kind: 'completed', pid: process.pid, project: owner.project, maxMutating: fake.maxMutating(), calls: fake.observations.map(row => ({ method: row.method, ownerScoped: row.argv.includes(owner.project) })) });
  process.disconnect();
} catch {
  process.send({ kind: 'failed', pid: process.pid, project: owner.project });
  process.disconnect(); process.exitCode = 1;
}
