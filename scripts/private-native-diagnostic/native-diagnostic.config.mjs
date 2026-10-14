import base from '../../vitest.config.ts';
import { fileURLToPath } from 'node:url';

const setups = ['native-process-trace.mjs', 'native-child-trace.mjs'].map(name => fileURLToPath(new URL(name, import.meta.url)));
export default { ...base, test: { ...base.test, projects: base.test.projects.map(project =>
  project.test?.name === 'product'
    ? { ...project, test: { ...project.test, setupFiles: [...(project.test.setupFiles ?? []), ...setups] } }
    : project
) } };
