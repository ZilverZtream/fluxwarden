import { writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
// Vitest's CLI excludes do not propagate to inline projects; extend the product project itself.
const excluded = [
  'test/labs/cp006-cp008-owner-lifecycle.test.ts',
  'test/persistence/cp015-concurrency.test.ts',
  'test/chaos/t01-t12.test.ts',
  'test/cli/cp038-reconcile-evidence.test.ts',
  'test/commands/cp043-driver.test.ts',
  'test/executor/cp029-preflight.test.ts',
  'test/output/cp003-output.test.ts',
  'test/persistence/cp015-command-data-readonly.test.ts',
  'test/persistence/cp015-persistence.test.ts',
  'test/daemon/cp041-daemon.test.ts',
  'test/ledger/cp037-ledger.test.ts',
  'test/commands/cp043-t05-repository.test.ts',
];
const config = process.env.FLUXWARDEN_CI_CORE_CONFIG || join(process.env.TEMP, 'vitest-windows-core.config.mjs');
const base = pathToFileURL(resolve('vitest.config.ts')).href;
writeFileSync(config, `import base from ${JSON.stringify(base)};
const excluded = ${JSON.stringify(excluded)};
export default { ...base, test: { ...base.test, projects: base.test.projects.map(project =>
  project.test?.name === 'product' ? { ...project, test: { ...project.test, exclude: [...project.test.exclude, ...excluded] } } : project
) } };
`);
