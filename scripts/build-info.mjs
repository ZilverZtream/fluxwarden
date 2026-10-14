import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const result = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 10_000 });
const commit = result.status === 0 ? result.stdout.trim() : '';
writeFileSync(new URL('../dist/evidence/build-info.json', import.meta.url), `${JSON.stringify({ gitCommit: /^[0-9a-f]{40}$/.test(commit) ? commit : null })}\n`);
