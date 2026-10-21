// The owned test entry, including npm lifecycle use, opts into finite capture.
// Product CLI subprocesses receive neither loader flags nor NODE_OPTIONS.
if (process.env.FLUXWARDEN_CI_CAPTURE) {
  await import('./ci-capture-preload.mjs');
  const fs = await import('node:fs');
  const { resolve, join } = await import('node:path');
  const { pathToFileURL } = await import('node:url');
  const { createPrivateDirectory } = await import('./private-scratch.mjs');
  const { binding } = await import('./ci-capture-files.mjs');
  const args = process.argv;
  const index = args.findIndex(arg => arg === '--config' || arg.startsWith('--config='));
  const source = resolve(index < 0 ? 'vitest.config.ts' : args[index] === '--config' ? args[index + 1] : args[index].slice('--config='.length));
  const before = binding(source);
  const scratch = await createPrivateDirectory(process.env.TEMP, 'ci-vitest-');
  const wrapper = join(scratch, 'owned.config.mjs');
  const preload = '--import=' + new URL('./ci-capture-preload.mjs', import.meta.url).href;
  fs.writeFileSync(wrapper, `import base from ${JSON.stringify(pathToFileURL(source).href)};
const capture = options => ({ ...options, execArgv: [...new Set([...(options?.execArgv ?? []), ${JSON.stringify(preload)}])] });
export default { ...base, test: { ...capture(base.test), projects: base.test?.projects?.map(project =>
  project && typeof project === 'object' ? { ...project, test: capture(project.test) } : project) } };
`, { mode: 0o600, flag: 'wx' });
  fs.writeFileSync(join(scratch, 'source-before.json'), JSON.stringify(before), { mode: 0o600, flag: 'wx' });
  process.once('exit', () => {
    let unchanged = false;
    try {
      const after = binding(source);
      fs.writeFileSync(join(scratch, 'source-after.json'), JSON.stringify(after), { mode: 0o600, flag: 'wx' });
      unchanged = JSON.stringify(before) === JSON.stringify(after);
    } catch { /* A missing or unreadable selected config cannot establish validation. */ }
    if (!unchanged) process.exitCode ||= 1;
  });
  if (index < 0) args.push('--config', wrapper);
  else if (args[index] === '--config') args[index + 1] = wrapper;
  else args[index] = '--config=' + wrapper;
}
await import('../node_modules/vitest/vitest.mjs');
