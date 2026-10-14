import { createOutput } from '../../../dist/output/index.js';
const target = process.argv[2] === 'stderr' ? 'stderr' : 'stdout';
const output = createOutput({ stdout: process.stdout, stderr: process.stderr, secrets: [] });
const keeper = setInterval(() => {}, 60000);
process.exitCode = 7;
await output.write('ordinary text '.repeat(8 * 1024 * 1024), { stream: target, exitCode: 7 });
clearInterval(keeper);
await output.write('completed\n', { stream: target === 'stdout' ? 'stderr' : 'stdout', exitCode: 7 });
