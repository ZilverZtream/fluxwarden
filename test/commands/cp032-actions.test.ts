/*
Interface: test/helpers/cp030-execution.ts (src/commands/actions.ts actionsStatus, watchActionsStatus, renderExecuteOutcome).

Rules under test: SPEC §10.1 (--json: exactly one document; `actions status --watch --json` prints one event object per line,
then the final document; ok is false exactly when error is set), §10.2 (exit 7 OUTCOME_UNKNOWN: "run `fluxwarden reconcile`;
do not retry"), §10.3 AS1-AS3 (unknown id -> 2; exit 0 for VERIFIED_SUCCESS, 5 for VERIFIED_FAILURE / CANCELLED, 7 for a
non-terminal execution; interrupting --watch -> 6), AE11 (the exit 7 message of actions execute).
*/
import Ajv2020 from 'ajv/dist/2020.js';
import { randomBytes } from 'node:crypto';
import { expect, it } from 'vitest';
import { circularRoute } from '../fakes/preflight-node.js';
import { readJson } from '../helpers/cli.js';
import { dbNow, loadPersistence, scratchDb, seedBase, sleep, ulid, type ExecutionStatus } from '../helpers/cp028-executor.js';
import { exec, loadActions, OUTCOME_UNKNOWN_MESSAGE, seedExecution } from '../helpers/cp030-execution.js';

const ajv = new Ajv2020.default({ strict: true, allErrors: true });
const validStatus = ajv.compile(readJson('schemas/output/actions-status.json') as object);

async function seeded(prefix: string, status: ExecutionStatus, history: readonly ExecutionStatus[]) {
  const p = await loadPersistence();
  const path = scratchDb(prefix);
  const base = seedBase(p, path);
  const hash = randomBytes(32).toString('hex');
  const route = circularRoute(base.sourceKey, base.targetKey, 150_000n, 80);
  const { executionId } = seedExecution(base, { status, paymentHash: hash, route, plannedFeeMsat: 150_000n, fenceEpoch: 3n, submittedAgoMs: 5_000 });
  const at = dbNow(path) - 4_000;
  let from: ExecutionStatus | null = null;
  for (const [index, to] of history.entries()) {
    exec(path, "INSERT INTO execution_events (execution_id, fence_epoch, from_status, to_status, evidence_json, at) VALUES (?, ?, ?, ?, '{}', ?)",
      executionId, BigInt(index + 1), from, to, at + index);
    from = to;
  }
  return { path, executionId, hash, at };
}

const parse = (text: string): Record<string, unknown> => JSON.parse(text) as Record<string, unknown>;

it('CP-032/B6 actions status --json of an UNKNOWN execution: the stored record and its events, exit 7', async () => {
  const { actionsStatus } = await loadActions();
  const s = await seeded('status-unknown', 'UNKNOWN', ['CLAIMED', 'PREFLIGHT', 'SUBMITTING', 'IN_FLIGHT', 'UNKNOWN']);
  const result = actionsStatus({ databasePath: s.path, executionId: s.executionId, json: true });
  expect(result.exitCode).toBe(7);
  expect(result.output.endsWith('\n')).toBe(true);
  expect(result.output.trimEnd().includes('\n')).toBe(false);
  const doc = parse(result.output);
  expect(validStatus(doc), JSON.stringify(validStatus.errors)).toBe(true);
  expect(doc['command']).toBe('actions status');
  expect(doc['ok']).toBe(true);
  expect(doc['result']).toMatchObject({
    execution_id: s.executionId, status: 'UNKNOWN', fence_epoch: '3', payment_hash: s.hash, planned_fee_msat: '150000',
    actual_fee_msat: null, delta_status: null, error_code: null,
  });
  const events = (doc['result'] as { events: { from: string | null; to: string; at: number }[] }).events;
  expect(events.map(e => [e.from, e.to])).toEqual([
    [null, 'CLAIMED'], ['CLAIMED', 'PREFLIGHT'], ['PREFLIGHT', 'SUBMITTING'], ['SUBMITTING', 'IN_FLIGHT'], ['IN_FLIGHT', 'UNKNOWN'],
  ]);
  expect(events[0]?.at).toBe(s.at);
});

it('CP-032/B6 the text form of a non-terminal execution tells the operator to reconcile and not to retry', async () => {
  const { actionsStatus } = await loadActions();
  const s = await seeded('status-text', 'UNKNOWN', ['IN_FLIGHT', 'UNKNOWN']);
  const result = actionsStatus({ databasePath: s.path, executionId: s.executionId, json: false });
  expect(result.exitCode).toBe(7);
  expect(result.output).toContain(OUTCOME_UNKNOWN_MESSAGE);
  expect(result.output).toContain(s.executionId);
});

for (const [status, exit] of [['VERIFIED_SUCCESS', 0], ['VERIFIED_FAILURE', 5], ['CANCELLED', 5], ['IN_FLIGHT', 7], ['SUBMITTING', 7], ['CLAIMED', 0], ['PREFLIGHT', 0]] as const) {
  it(`CP-032/B6 actions status exits ${String(exit)} for ${status}`, async () => {
    const { actionsStatus } = await loadActions();
    const s = await seeded(`status-${status}`, status, [status]);
    const result = actionsStatus({ databasePath: s.path, executionId: s.executionId, json: true });
    expect(result.exitCode).toBe(exit);
    const doc = parse(result.output);
    expect(validStatus(doc), JSON.stringify(validStatus.errors)).toBe(true);
    expect((doc['result'] as { status: string }).status).toBe(status);
    if (exit !== 7) expect(result.output).not.toContain(OUTCOME_UNKNOWN_MESSAGE);
  });
}

for (const status of ['CLAIMED', 'PREFLIGHT'] as const) {
  it(`CP-032/B6 the text form of a ${status} execution says nothing was sent and never asks for a reconcile (exit 0)`, async () => {
    const { actionsStatus } = await loadActions();
    const s = await seeded(`status-text-${status}`, status, [status]);
    const result = actionsStatus({ databasePath: s.path, executionId: s.executionId, json: false });
    // SPEC §10.2: exit 7 means a mutating RPC may have reached the node; before SUBMITTING nothing was sent.
    expect(result.exitCode).toBe(0);
    expect(result.output).not.toContain(OUTCOME_UNKNOWN_MESSAGE);
    expect(result.output).toContain(status);
  });
}

it('CP-032/B6 actions status of an unknown execution id exits 2 with an error document', async () => {
  const { actionsStatus } = await loadActions();
  const s = await seeded('status-missing', 'UNKNOWN', []);
  const result = actionsStatus({ databasePath: s.path, executionId: ulid(), json: true });
  expect(result.exitCode).toBe(2);
  const doc = parse(result.output);
  expect(validStatus(doc), JSON.stringify(validStatus.errors)).toBe(true);
  expect(doc['ok']).toBe(false);
  expect((doc['error'] as { code: number }).code).toBe(2);
});

it('CP-032/B6 actions status --watch --json renders each transition as it happens, then the final document', async () => {
  const { watchActionsStatus } = await loadActions();
  const s = await seeded('watch', 'IN_FLIGHT', ['SUBMITTING', 'IN_FLIGHT']);
  const lines: string[] = [];
  const watching = watchActionsStatus({ databasePath: s.path, executionId: s.executionId, pollMs: 20, signal: new AbortController().signal }, line => { lines.push(line); });
  await sleep(120);
  exec(s.path, "UPDATE executions SET status = 'UNKNOWN', fence_epoch = fence_epoch + 1 WHERE id = ?", s.executionId);
  exec(s.path, "INSERT INTO execution_events (execution_id, fence_epoch, from_status, to_status, evidence_json, at) VALUES (?, 4, 'IN_FLIGHT', 'UNKNOWN', '{}', ?)", s.executionId, s.at + 10);
  await sleep(120);
  exec(s.path, "UPDATE executions SET status = 'VERIFIED_SUCCESS', actual_fee_msat = 150000, fence_epoch = fence_epoch + 1 WHERE id = ?", s.executionId);
  exec(s.path, "INSERT INTO execution_events (execution_id, fence_epoch, from_status, to_status, evidence_json, at) VALUES (?, 5, 'UNKNOWN', 'VERIFIED_SUCCESS', '{}', ?)", s.executionId, s.at + 20);
  const { exitCode } = await watching;
  expect(exitCode).toBe(0);
  const docs = lines.join('').split('\n').filter(text => text !== '').map(parse);
  const events = docs.slice(0, -1);
  expect(events.map(e => [e['event'], e['execution_id'], e['from'], e['to']])).toEqual([
    ['transition', s.executionId, null, 'SUBMITTING'],
    ['transition', s.executionId, 'SUBMITTING', 'IN_FLIGHT'],
    ['transition', s.executionId, 'IN_FLIGHT', 'UNKNOWN'],
    ['transition', s.executionId, 'UNKNOWN', 'VERIFIED_SUCCESS'],
  ]);
  const final = docs.at(-1) ?? {};
  expect(validStatus(final), JSON.stringify(validStatus.errors)).toBe(true);
  expect((final['result'] as { status: string; actual_fee_msat: string }).status).toBe('VERIFIED_SUCCESS');
  expect((final['result'] as { actual_fee_msat: string }).actual_fee_msat).toBe('150000');
});

it('CP-032/B6 interrupting actions status --watch exits 6 and leaves the execution as it was', async () => {
  const { watchActionsStatus } = await loadActions();
  const s = await seeded('watch-stop', 'UNKNOWN', ['IN_FLIGHT', 'UNKNOWN']);
  const stop = new AbortController();
  setTimeout(() => { stop.abort(); }, 100);
  const started = Date.now();
  const { exitCode } = await watchActionsStatus({ databasePath: s.path, executionId: s.executionId, pollMs: 20, signal: stop.signal }, () => undefined);
  expect(exitCode).toBe(6);
  expect(Date.now() - started).toBeLessThan(3_000);
});

it('CP-032/B6 actions execute exit 7 carries the outcome-unknown message in JSON and in text', async () => {
  const { renderExecuteOutcome } = await loadActions();
  const outcome = { executionId: ulid(), exit: 7, step: 'OUTCOME_UNKNOWN' };
  const json = renderExecuteOutcome(outcome, true);
  expect(json.exitCode).toBe(7);
  expect(parse(json.output)).toEqual({
    schema: 1, command: 'actions execute', ok: false, warnings: [], result: null,
    error: { code: 7, step: 'OUTCOME_UNKNOWN', message: OUTCOME_UNKNOWN_MESSAGE },
  });
  const text = renderExecuteOutcome(outcome, false);
  expect(text.exitCode).toBe(7);
  expect(text.output).toContain(OUTCOME_UNKNOWN_MESSAGE);
});
