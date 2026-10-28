import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { expect, it } from 'vitest';
import { clean, cli, clnConfig, history, initializeRegistry, input, oracle, preflight, query, retain, setRunner, unchangedOld } from '../../labs/scenarios/chaos/live-reference.mjs';
import { LabInvalidError } from '../helpers/chaos.js';
setRunner((file, args, options) => spawnSync(file, args, options));
type Row = Record<string, unknown>;

it('CP-044/OPS-T06 T-06 stale public worker API lease2s loses a real fenced write after another process takes over and makes no further native call', async () => {
  initializeRegistry(); await preflight('t06-stale-before');
  const p = input(), original = history(), fixture = clnConfig('t06-stale');
  const owner = p.owner as typeof p.owner & { id: string; evidenceRoot: string };
  const record = (name: string, value: unknown): void => {
    retain(name, value);
    if (resolve(p.evidence) !== resolve(owner.evidenceRoot)) writeFileSync(join(owner.evidenceRoot, `${name}.json`), JSON.stringify(value), { flag: 'wx', mode: 0o600 });
  };
  const build = JSON.parse(readFileSync(resolve('dist/evidence/build-info.json'), 'utf8')) as { gitCommit?: unknown };
  if (typeof build.gitCommit !== 'string' || !/^[a-f0-9]{40}$/.test(build.gitCommit)) throw new LabInvalidError('T-06 actual compiled source identity unavailable');
  let child: ReturnType<typeof spawn> | undefined;
  const messages: Row[] = [];
  try {
    expect(cli(['doctor'], 't06-stale-doctor', fixture.config).exit).toBe(0);
    const planned = cli(['liquidity', 'plan', '--refresh'], 't06-stale-plan', fixture.config);
    expect(planned.exit).toBe(0); expect(planned.body.result).toMatchObject({ action: 'CIRCULAR_REBALANCE', principal_msat: '100000000' });
    const proposal = String(planned.body.result['proposal_id']);
    expect(cli(['liquidity', 'approve', proposal, '--key', p.key], 't06-stale-approval', fixture.config).exit).toBe(0);
    const directory = mkdtempSync(join(p.tmp, 't06-stale-')), context = join(directory, 'worker.json');
    const settings = { config: fixture.config, database: fixture.database, proposalId: proposal.replace(/^prop_/, '') };
    writeFileSync(context, JSON.stringify(settings), { flag: 'wx', mode: 0o600 });
    const script = resolve('test/helpers/native-stale-worker.mjs');
    child = spawn(process.execPath, [script, context, 'stale'], { cwd: resolve('.'), env: process.env, shell: false,
      windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    const watchdog = setTimeout(() => { child?.kill('SIGKILL'); }, 30_000);
    child.once('close', () => { clearTimeout(watchdog); });
    let buffered = '', stderr = '';
    child.stdout?.on('data', (chunk: Buffer) => {
      buffered += chunk.toString('utf8');
      for (;;) { const end = buffered.indexOf('\n'); if (end < 0) break;
        const line = buffered.slice(0, end); buffered = buffered.slice(end + 1); messages.push(JSON.parse(line) as Row); }
    });
    child.stderr?.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8'); });
    const done = new Promise<number | null>((accept, reject) => { child?.once('error', reject); child?.once('close', accept); });
    const deadline = Date.now() + 30_000;
    while (!messages.some(message => message['kind'] === 'claimed')) {
      if (messages.some(message => message['kind'] === 'driver-error') || child.exitCode !== null || Date.now() >= deadline)
        throw new LabInvalidError('T-06 committed claim barrier unavailable');
      await delay(10);
    }
    const claimed = messages.find(message => message['kind'] === 'claimed');
    if (!claimed) throw new LabInvalidError('T-06 claimed observation unavailable');
    const executionId = String(claimed['executionId']);
    record('t06-stale-committed-claim', claimed);
    const beforeNative = { invoices: oracle('cln-m', 'listinvoices'), payments: oracle('cln-m', 'listsendpays') };
    record('t06-stale-native-before-resume', beforeNative);
    // Natural database time, observed through a read-only query. No lease/clock edit.
    while (query(fixture.database, `SELECT id FROM executions WHERE id=? AND lease_expires_at <= CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)`, executionId).length !== 1) {
      if (Date.now() >= deadline) throw new LabInvalidError('T-06 natural public2s lease expiry unavailable');
      await delay(10);
    }
    const winnerInput = join(directory, 'winner.json'); writeFileSync(winnerInput, JSON.stringify({ ...settings, executionId }), { flag: 'wx', mode: 0o600 });
    const winner = spawnSync(process.execPath, [script, winnerInput, 'takeover'], { cwd: resolve('.'), env: process.env, encoding: 'utf8',
      shell: false, windowsHide: true, timeout: 30_000 });
    expect(winner.status).toBe(0);
    const winnerObserved = JSON.parse(winner.stdout) as Row;
    expect(BigInt(String(winnerObserved['fenceEpoch']))).toBeGreaterThan(BigInt(String(claimed['fenceEpoch'])));
    const financial = (): Record<string, Row[]> => Object.fromEntries(['executions', 'execution_events', 'budget_reservations', 'ledger_journals', 'ledger_lines']
      .map(table => [table, query(fixture.database, `SELECT * FROM ${table}`)]));
    const winnerState = financial();
    record('t06-stale-winner', { observation: winnerObserved, state: winnerState });
    child.stdin?.end(Buffer.from([1]));
    expect(await done).toBe(5);
    const finished = messages.find(message => message['kind'] === 'finished');
    expect(finished).toMatchObject({ outcome: { kind: 'REFUSED', exit: 5, step: 'lease-lost' }, publicWorkerLeaseMs: 2000,
      postBarrierNativeCalls: [], fencedWriteLosses: [{ code: 'LEASE_LOST', attemptedFenceEpoch: claimed['fenceEpoch'],
        observedWinnerFenceEpoch: winnerObserved['fenceEpoch'] }] });
    expect(financial()).toEqual(winnerState);
    const afterNative = { invoices: oracle('cln-m', 'listinvoices'), payments: oracle('cln-m', 'listsendpays') };
    expect(afterNative).toEqual(beforeNative);
    record('t06-stale-native-after-resume', afterNative);
    record('t06-stale-worker-result', { messages, stderr });
    unchangedOld(original, history());
  } finally {
    if (child && child.exitCode === null) { child.stdin?.destroy(); child.kill('SIGKILL'); }
    await clean(); await preflight('t06-stale-after');
  }
  record('t06-stale-scenario', { caseId: 'T-06', variant: 'public prepareExecution API with explicit2s lease and real two-process takeover',
    ownerId: owner.id, project: owner.project, sourceCommit: build.gitCommit, pass: true,
    staleOutcome: 'REFUSED5 lease-lost after real repository LEASE_LOST', postBarrierNativeCalls: 0,
    winningStateUnchanged: true, nativeInvoiceAndPaymentInventoryUnchanged: true,
    scope: 'Complements the distinct default CLI two-process claim case; does not claim a default180s CLI lease.' });
});
