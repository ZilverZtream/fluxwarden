import { spawn, spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { afterEach, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { methodsOf } from '../fakes/cln/rebalance-node.js';
import { approve, demo, plan, rows } from '../helpers/cpw-cli.js';
import { registerMoneySafetyCredentials } from '../helpers/public-money-safety.js';

const servers: FakeServer[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });
type Row = Record<string, unknown>;

// Same public two-process protocol as the native reference, exercised against
// the existing source-cited CLN fake first. This is Docker-free, not native proof.
it('CP-044/OPS-T06-mechanical T-06 real stale fenced write preserves the winner and makes zero subsequent HTTP node calls', async () => {
  const d = await demo(servers); registerMoneySafetyCredentials([d.cln.runeFile, d.key.keyFile]);
  const proposal = String((await plan(d))['proposal_id']); await approve(d, proposal);
  const context = join(d.dir, 'stale-worker.json'), winnerContext = join(d.dir, 'winner-worker.json');
  const settings = { config: d.config, database: d.database, proposalId: proposal.replace(/^prop_/, '') };
  writeFileSync(context, JSON.stringify(settings), { flag: 'wx', mode: 0o600 });
  const script = resolve('test/helpers/native-stale-worker.mjs');
  const child = spawn(process.execPath, [script, context, 'stale'], { cwd: resolve('.'), env: process.env, shell: false,
    windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const watchdog = setTimeout(() => { child.kill('SIGKILL'); }, 30_000);
  child.once('close', () => { clearTimeout(watchdog); });
  const messages: Row[] = []; let buffer = '';
  child.stdout.on('data', (chunk: Buffer) => { buffer += chunk.toString(); for (;;) {
    const at = buffer.indexOf('\n'); if (at < 0) break;
    messages.push(JSON.parse(buffer.slice(0, at)) as Row); buffer = buffer.slice(at + 1);
  } });
  // Runtime warnings cannot backpressure the worker's pipe.
  child.stderr.resume();
  const done = new Promise<number | null>((accept, reject) => { child.once('error', reject); child.once('close', accept); });
  try {
    const deadline = Date.now() + 30_000;
    while (!messages.some(value => value['kind'] === 'claimed')) {
      if (messages.some(value => value['kind'] === 'driver-error') || child.exitCode !== null || Date.now() >= deadline)
        throw new Error('public-worker claim barrier unavailable');
      await delay(10);
    }
    const claimed = messages.find(value => value['kind'] === 'claimed');
    if (!claimed) throw new Error('public-worker claim observation missing');
    const executionId = String(claimed['executionId']);
    while (rows(d.database, `SELECT id FROM executions WHERE id=? AND lease_expires_at <= CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)`, executionId).length !== 1) {
      if (Date.now() >= deadline) throw new Error('natural public-worker lease expiry unavailable');
      await delay(10);
    }
    const nativeCallsBefore = methodsOf(d.cln.fake);
    writeFileSync(winnerContext, JSON.stringify({ ...settings, executionId }), { flag: 'wx', mode: 0o600 });
    const won = spawnSync(process.execPath, [script, winnerContext, 'takeover'], { cwd: resolve('.'), env: process.env,
      encoding: 'utf8', shell: false, windowsHide: true, timeout: 30_000 });
    expect(won.status).toBe(0);
    const winner = JSON.parse(won.stdout) as Row;
    expect(BigInt(String(winner['fenceEpoch']))).toBeGreaterThan(BigInt(String(claimed['fenceEpoch'])));
    const winningState = rows(d.database, 'SELECT * FROM executions'), events = rows(d.database, 'SELECT * FROM execution_events');
    const reservation = rows(d.database, 'SELECT * FROM budget_reservations');
    child.stdin.end(Buffer.from([1])); expect(await done).toBe(5);
    const finished = messages.find(value => value['kind'] === 'finished');
    expect(finished).toMatchObject({ outcome: { kind: 'REFUSED', exit: 5, step: 'lease-lost' }, postBarrierNativeCalls: [],
      fencedWriteLosses: [{ code: 'LEASE_LOST', attemptedFenceEpoch: claimed['fenceEpoch'], observedWinnerFenceEpoch: winner['fenceEpoch'] }] });
    expect(rows(d.database, 'SELECT * FROM executions')).toEqual(winningState);
    expect(rows(d.database, 'SELECT * FROM execution_events')).toEqual(events);
    expect(rows(d.database, 'SELECT * FROM budget_reservations')).toEqual(reservation);
    expect(methodsOf(d.cln.fake)).toEqual(nativeCallsBefore);
  } finally {
    if (child.exitCode === null) { child.stdin.destroy(); child.kill('SIGKILL'); await done; }
  }
}, 60_000);
