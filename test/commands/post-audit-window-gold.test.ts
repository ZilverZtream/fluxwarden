// SPEC Commands: documented ISO --until; prior CP-038/B6 duration forms stay valid.
// SPEC Evidence: immutable recorded runs remain exportable. AUDIT-08 supplies 12k
// normal retained planner rows; an unrelated old proposal history must not exhaust
// the 16 MiB run-record bound for one short reconciliation window.
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { demo, documentOf, plan, resultOf, rows, storedId } from '../helpers/cpw-cli.js';
import { loadSrc } from '../helpers/load-src.js';

interface WindowParser {
  parseReconcileWindow: (flags: { since?: string; until?: string }, nowMs: number) =>
    { ok: true; window: { sinceMs: number; untilMs: number } } | { ok: false; exitCode: number; message: string };
}
const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

it('CP-038/AUDIT-13 the documented ISO --until timestamp and existing duration form select the same exact millisecond window', async () => {
  const { parseReconcileWindow } = await loadSrc<WindowParser>('commands/reconcile.ts');
  const now = Date.parse('2026-10-13T13:00:00Z');
  const expected = { ok: true, window: { sinceMs: 1_791_889_200_000, untilMs: 1_791_894_600_000 } };
  // Independent UTC arithmetic: 13:00 - 2h = 11:00; 13:00 - 30m = 12:30.
  expect.soft(parseReconcileWindow({ since: '2h', until: '2026-10-13T12:30:00Z' }, now)).toEqual(expected);
  expect.soft(parseReconcileWindow({ since: '2h', until: '30m' }, now)).toEqual(expected);
  expect.soft(parseReconcileWindow({ since: '2h' }, now)).toEqual({ ok: true,
    window: { sinceMs: 1_791_889_200_000, untilMs: 1_791_896_400_000 } });
  expect.soft(parseReconcileWindow({ since: '2h', until: '2026-10-13T11:00:00Z' }, now)).toMatchObject({ ok: false, exitCode: 2 });
});

it('CP-038/AUDIT-08 twelve thousand retained ordinary proposals do not break a short-window reconciliation or immutable bounded export', async () => {
  const d = await demo(open, { withKey: false });
  const proposal = await plan(d);
  const currentId = storedId(String(proposal['proposal_id']));
  const raw = new DatabaseSync(d.database);
  try {
    const original = raw.prepare('SELECT * FROM liquidity_proposals WHERE id = ?').get(currentId);
    if (original === undefined) throw new Error('public planner did not persist its proposal');
    const columns = Object.keys(original);
    const insert = raw.prepare(`INSERT INTO liquidity_proposals (${columns.join(',')}) VALUES (${columns.map(() => '?').join(',')})`);
    raw.exec('BEGIN');
    for (let i = 0; i < 12_000; i++) {
      const id = i.toString(16).toUpperCase().padStart(26, '0');
      // Keep ordinary real-planner route/explanation sizes. The copies are retained
      // expired history from two days earlier, outside the requested one-hour window.
      const historical: Record<string, unknown> = { ...original, id,
        proposal_digest: createHash('sha256').update(id).digest('hex') };
      for (const time of ['created_at', 'updated_at', 'expires_at']) {
        if (typeof historical[time] === 'number') historical[time] = historical[time] - 172_800_000 + i;
      }
      insert.run(...columns.map(column => historical[column] as string | number | bigint | null));
    }
    raw.exec('COMMIT');
  } finally { raw.close(); }
  expect(rows(d.database, 'SELECT count(*) AS count FROM liquidity_proposals')).toEqual([{ count: 12_001 }]);
  const reconciled = await d.run(['--json', 'reconcile', '--node', 'cln-m', '--since', '1h'], { timeoutMs: 60_000 });
  expect(reconciled.status, 'bounded run recording must succeed despite retained history').toBe(0);
  const runId = String(resultOf(documentOf(reconciled, 'reconcile'))['run_id']);
  expect(runId).toMatch(/^run_[0-9A-HJKMNP-TV-Z]{26}$/);
  const out = join(d.dir, 'bounded-reconciliation-export');
  expect((await d.run(['--json', 'evidence', 'export', '--run-id', runId, '--out', out], { timeoutMs: 60_000 })).status).toBe(0);
  const proposals = readFileSync(join(out, 'proposals.json'), 'utf8');
  expect(proposals).toContain(currentId);
  expect(readdirSync(out).reduce((total, name) => total + statSync(join(out, name)).size, 0)).toBeLessThan(16 * 1024 * 1024);
  // Bounded recording must not accomplish its limit by deleting operator history.
  expect(rows(d.database, 'SELECT count(*) AS count FROM liquidity_proposals')).toEqual([{ count: 12_001 }]);
  const again = join(d.dir, 'same-run-export');
  expect((await d.run(['--json', 'evidence', 'export', '--run-id', runId, '--out', again], { timeoutMs: 60_000 })).status).toBe(0);
  for (const name of readdirSync(out)) expect(readFileSync(join(again, name))).toEqual(readFileSync(join(out, name)));
}, 90_000);
