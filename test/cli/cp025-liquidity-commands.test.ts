/*
 * Interface: `liquidity diagnose`, `liquidity plan` and `liquidity explain` through the built CLI (SPEC §10.3 items 4-6).
 *
 * Invocation (global conventions, configuration and connection settings as test/cli/cp016-commands.test.ts states them):
 *   fluxwarden [--json] liquidity diagnose [--node <name>] [--horizon <dur>]   --config <path>
 *   fluxwarden [--json] liquidity plan     [--node <name>] [--horizon <dur>] [--policy <path>] [--refresh] --config <path>
 *   fluxwarden [--json] liquidity explain  <proposal-id>                       --config <path>
 *   <dur> is <int>(s|m|h|d) (SPEC §7.1); anything else -> exit 2 before any node call (G1).
 *   <proposal-id> is prop_<ULID> as plan prints it.
 *
 * diagnose (LD1-LD4): snapshots older than max_snapshot_age are refreshed from the node first (one listpeerchannels per
 *   node); then the --json document of schemas/output/liquidity-diagnose.json: per channel deficits and surpluses against
 *   the policy targets (inbound deficit max(0, min_inbound - receivable), inbound surplus max(0, receivable - min_inbound)),
 *   `starved` and `donors` by channel key, demand_source TARGETS, horizon_seconds from --horizon or demand.horizon. A node
 *   without targets -> exit 0, action NO_ACTION, reason INSUFFICIENT_HISTORY.
 * plan (LP1-LP6): with --refresh new snapshots are taken; without it a snapshot older than max_snapshot_age -> exit 5,
 *   error.step STALE_SNAPSHOT and no proposal stored. Route discovery uses read calls only. One proposal row is stored and
 *   printed (schemas/output/liquidity-plan.json). Text output prints the id, the route, fee, ppm (ceil), CLTV delta, digest
 *   and expiry.
 * explain (LE1-LE2): no node calls; unknown or malformed id -> exit 2; the --json document of
 *   schemas/output/liquidity-explain.json; status EXPIRED once proposal_ttl has passed; text output prints the explanation
 *   tree: inputs, demand source, candidates with refusal codes, the route hop by hop with amounts, policy SHA-256, digest,
 *   status and approvals.
 *
 * Scenario (test/fakes/cln/rebalance-node.ts): CLN-M of SPEC §4.4 with channel 2 (S, 102x1x0, to LND-R) and channel 5
 * (T, 105x1x0, from CLN-R). Targets S 400,000,000 inbound, T 50,000,000 inbound. S receivable 100,000,000 -> deficit
 * 300,000,000; T receivable 2,000,000,000 -> surplus 1,950,000,000. Principal (SPEC §7.4) = min(300,000,000,
 * 1,950,000,000, 1,820,000,000 - 300,000 - 50,000,000, 100,000,000) = 100,000,000. Route of SPEC §4.4: fee 202,101 msat,
 * ppm ceil(202,101 * 10^6 / 10^8) = 2,022, CLTV delta 132; hop amounts 100,202,101 / 100,101,000 / 100,000,000.
 */
import { afterEach, describe, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { CLN_R, LND_R, MUTATING, S, SELF, T, CH3, methodsOf } from '../fakes/cln/rebalance-node.js';
import {
  count, demo, documentOf, errorOf, INVALID_INPUT, list, pause, plan, rec, resultOf, rows, SAFETY_REFUSAL, storedId, SUCCESS, writeDemoPolicy, type Doc,
} from '../helpers/cpw-cli.js';

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

/** Diagnosis and planning need no operator key. */
const NO_KEY = { withKey: false } as const;

const byChannel = (doc: Doc): Map<string, Doc> => new Map(list(doc['channels']).map(row => [String(rec(row)['channel']), rec(row)]));

describe('liquidity diagnose', () => {
  it('CP-020/B1 diagnose refreshes the snapshots and reports deficits and surpluses from the targets, exact to the msat', async () => {
    const d = await demo(open, NO_KEY);
    const run = await d.run(['--json', 'liquidity', 'diagnose']);
    expect(run.status).toBe(SUCCESS);
    const result = resultOf(documentOf(run, 'liquidity-diagnose'));
    expect(result['action']).toBe('DEFICIT');
    expect(result['node']).toBe('cln-m');
    expect(result['demand_source']).toBe('TARGETS');
    expect(result['starved']).toEqual([S]);
    expect(result['donors']).toEqual([T]);
    const rowsByKey = byChannel(result);
    expect([...rowsByKey.keys()].sort()).toEqual([S, T]);
    expect(rowsByKey.get(S)).toMatchObject({
      capacity_msat: '2000000000', spendable_msat: '1820000000', receivable_msat: '100000000', confidence: 'NODE_REPORTED',
      inbound_target_msat: '400000000', inbound_deficit_msat: '300000000', inbound_surplus_msat: '0',
    });
    expect(rowsByKey.get(T)).toMatchObject({
      capacity_msat: '2500000000', spendable_msat: '350000000', receivable_msat: '2000000000', confidence: 'NODE_REPORTED',
      inbound_target_msat: '50000000', inbound_deficit_msat: '0', inbound_surplus_msat: '1950000000',
    });
    // LD2: there was no snapshot, so the command read the node.
    expect(methodsOf(d.cln.fake)).toContain('listpeerchannels');
    expect(methodsOf(d.cln.fake).filter(method => MUTATING.includes(method))).toEqual([]);
  }, 60_000);

  it('CP-020/B4 --horizon sets horizon_seconds, the figures repeat exactly, and text output names starved and donor channels', async () => {
    const d = await demo(open, NO_KEY);
    const first = resultOf(documentOf(await d.run(['--json', 'liquidity', 'diagnose', '--horizon', '2h']), 'liquidity-diagnose'));
    const second = resultOf(documentOf(await d.run(['--json', 'liquidity', 'diagnose']), 'liquidity-diagnose'));
    expect(first['horizon_seconds']).toBe(7200);
    // demand.horizon of the policy is 6h.
    expect(second['horizon_seconds']).toBe(21600);
    const figures = (doc: Doc): unknown[] => list(doc['channels']).map(row => Object.fromEntries(
      Object.entries(rec(row)).filter(([key]) => key !== 'observed_at' && key !== 'snapshot_age_ms')));
    expect(figures(second)).toEqual(figures(first));
    const text = await d.run(['liquidity', 'diagnose']);
    expect(text.status).toBe(SUCCESS);
    expect(text.stdout).toContain(S);
    expect(text.stdout).toContain(T);
    expect(text.stdout).toContain('300000000');
    expect(text.stdout).toContain('TARGETS');
  }, 60_000);

  it('CP-020/B4 a malformed --horizon exits 2 before any node call', async () => {
    const d = await demo(open, NO_KEY);
    const before = d.cln.fake.connections();
    for (const horizon of ['soon', '6', '-1h', '1.5h']) {
      const run = await d.run(['--json', 'liquidity', 'diagnose', '--horizon', horizon]);
      expect(run.status, horizon).toBe(INVALID_INPUT);
      expect(errorOf(documentOf(run, 'liquidity-diagnose'))['code']).toBe(INVALID_INPUT);
    }
    expect(d.cln.fake.connections()).toBe(before);
  }, 60_000);

  it('CP-020/B3 a node without targets gets NO_ACTION with reason INSUFFICIENT_HISTORY and no figures', async () => {
    const d = await demo(open, { ...NO_KEY, targets: { 'lnd-elsewhere': { '900x1x0': '1000000' } } });
    const run = await d.run(['--json', 'liquidity', 'diagnose']);
    expect(run.status).toBe(SUCCESS);
    const result = resultOf(documentOf(run, 'liquidity-diagnose'));
    expect(result['action']).toBe('NO_ACTION');
    expect(result['reason']).toBe('INSUFFICIENT_HISTORY');
    expect(result['channels']).toEqual([]);
    expect(result['starved']).toEqual([]);
    expect(result['donors']).toEqual([]);
  }, 60_000);
});

describe('liquidity plan', () => {
  it('CP-025/B5 plan --refresh stores one CIRCULAR_REBALANCE proposal over the SPEC route using read calls only', async () => {
    const d = await demo(open, NO_KEY);
    const result = await plan(d);
    expect(result['proposal_id']).toMatch(/^prop_[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(result).toMatchObject({
      node: 'cln-m', action: 'CIRCULAR_REBALANCE', status: 'PROPOSED', demand_source: 'TARGETS',
      source_channel: S, target_channel: T, principal_msat: '100000000',
      caps: { max_fee_msat: '300000', max_fee_ppm: 2500, exempt_fee_msat: '5000', max_cltv_delta: 144 },
    });
    const route = rec(result['route']);
    expect(route['fee_msat']).toBe('202101');
    expect(route['fee_ppm']).toBe(2022);
    expect(route['cltv_delta']).toBe(132);
    expect(list(route['hops']).map(hop => [rec(hop)['channel'], rec(hop)['node_out'], rec(hop)['amount_msat']])).toEqual([
      [S, LND_R, '100202101'], [CH3, CLN_R, '100101000'], [T, SELF, '100000000'],
    ]);
    expect(Number(result['expires_at']) - Number(result['created_at'])).toBe(15 * 60_000);
    expect(result['approvals']).toEqual([]);
    // LP5: exactly one stored proposal, the one printed, with the printed digest.
    const stored = rows(d.database, 'SELECT id, action_type, proposal_digest, status, principal_msat FROM liquidity_proposals');
    expect(stored).toEqual([{ id: storedId(String(result['proposal_id'])), action_type: 'CIRCULAR_REBALANCE', proposal_digest: result['digest'], status: 'PROPOSED', principal_msat: 100000000 }]);
    // LP4: route discovery reads only, and the askrene layer is removed on the way out.
    const methods = methodsOf(d.cln.fake);
    expect(methods).toContain('getroutes');
    expect(methods.filter(method => MUTATING.includes(method))).toEqual([]);
    expect(methods.filter(method => method === 'askrene-create-layer').length).toBe(methods.filter(method => method === 'askrene-remove-layer').length);
    expect(d.cln.state.layers.layers.size).toBe(0);
    expect(count(d.database, 'executions')).toBe(0);
  }, 60_000);

  it('CP-025/B5 plan text output prints the id, the route, fee, ppm, CLTV delta, digest and expiry', async () => {
    const d = await demo(open, NO_KEY);
    const run = await d.run(['liquidity', 'plan', '--refresh']);
    expect(run.status).toBe(SUCCESS);
    const stored = rows(d.database, 'SELECT id, proposal_digest, expires_at FROM liquidity_proposals');
    expect(stored).toHaveLength(1);
    const row = rec(stored[0]);
    for (const expected of [`prop_${String(row['id'])}`, String(row['proposal_digest']), S, CH3, T, '202101', '2022', '132', '100000000']) {
      expect(run.stdout, expected).toContain(expected);
    }
  }, 60_000);

  it('CP-020/B2 plan without --refresh on snapshots older than max_snapshot_age exits 5 STALE_SNAPSHOT and stores nothing', async () => {
    const d = await demo(open, { ...NO_KEY, maxSnapshotAge: '1s' });
    // Snapshots stored by `channels` (CH3), then left to age past max_snapshot_age.
    expect((await d.run(['channels', '--node', 'cln-m'])).status).toBe(SUCCESS);
    await pause(1_600);
    const run = await d.run(['--json', 'liquidity', 'plan']);
    expect(run.status).toBe(SAFETY_REFUSAL);
    const error = errorOf(documentOf(run, 'liquidity-plan'));
    expect(error['code']).toBe(SAFETY_REFUSAL);
    expect(error['step']).toBe('STALE_SNAPSHOT');
    expect(count(d.database, 'liquidity_proposals')).toBe(0);
  }, 60_000);
});

describe('liquidity explain', () => {
  it('CP-025/B3 explain prints the stored explanation tree without contacting the node', async () => {
    const d = await demo(open, NO_KEY);
    const planned = await plan(d);
    const requests = d.cln.fake.requests.length;
    const connections = d.cln.fake.connections();
    const run = await d.run(['--json', 'liquidity', 'explain', String(planned['proposal_id'])]);
    expect(run.status).toBe(SUCCESS);
    const result = resultOf(documentOf(run, 'liquidity-explain'));
    for (const field of ['proposal_id', 'digest', 'policy_sha256', 'route', 'principal_msat', 'source_channel', 'target_channel', 'expires_at']) {
      expect(result[field], field).toEqual(planned[field]);
    }
    expect(result['status']).toBe('PROPOSED');
    expect(result['demand_source']).toBe('TARGETS');
    const inputs = list(result['inputs']).map(rec);
    expect(inputs.map(input => input['channel']).sort()).toEqual([S, T]);
    expect(inputs.every(input => input['confidence'] === 'NODE_REPORTED')).toBe(true);
    const chosen = list(result['candidates']).map(rec).filter(candidate => candidate['chosen'] === true);
    expect(chosen).toEqual([{ source_channel: S, target_channel: T, principal_msat: '100000000', code: null, detail: null, chosen: true }]);
    expect(d.cln.fake.requests.length).toBe(requests);
    expect(d.cln.fake.connections()).toBe(connections);

    const text = await d.run(['liquidity', 'explain', String(planned['proposal_id'])]);
    expect(text.status).toBe(SUCCESS);
    for (const expected of [String(planned['digest']), String(planned['policy_sha256']), 'TARGETS', 'PROPOSED', '100202101', '100101000', '202101', S, T]) {
      expect(text.stdout, expected).toContain(expected);
    }
  }, 60_000);

  it('CP-025/B4 explain on an unknown or malformed proposal id exits 2', async () => {
    const d = await demo(open, NO_KEY);
    await plan(d);
    for (const id of ['prop_01JC0000000000000000000000', 'prop_nope', '01JC0000000000000000000000']) {
      const json = await d.run(['--json', 'liquidity', 'explain', id]);
      expect(json.status, id).toBe(INVALID_INPUT);
      expect(errorOf(documentOf(json, 'liquidity-explain'))['code']).toBe(INVALID_INPUT);
      const text = await d.run(['liquidity', 'explain', id]);
      expect(text.status, id).toBe(INVALID_INPUT);
    }
    const missing = await d.run(['liquidity', 'explain']);
    expect(missing.status).toBe(INVALID_INPUT);
  }, 60_000);

  it('CP-025/B2 a proposal past proposal_ttl is listed as EXPIRED and can no longer be approved', async () => {
    const d = await demo(open, { proposalTtl: '1s' });
    const planned = await plan(d);
    expect(Number(planned['expires_at']) - Number(planned['created_at'])).toBe(1_000);
    await pause(1_500);
    const run = await d.run(['--json', 'liquidity', 'explain', String(planned['proposal_id'])]);
    expect(run.status).toBe(SUCCESS);
    expect(resultOf(documentOf(run, 'liquidity-explain'))['status']).toBe('EXPIRED');
    // LA1: an expired proposal -> exit 5, nothing stored.
    const approve = await d.run(['--json', 'liquidity', 'approve', String(planned['proposal_id']), '--key', d.key.keyFile, '--max-fee-msat', '300000', '--max-cltv-delta', '144']);
    expect(approve.status).toBe(SAFETY_REFUSAL);
    expect(errorOf(documentOf(approve, 'liquidity-approve'))['code']).toBe(SAFETY_REFUSAL);
    expect(count(d.database, 'approvals')).toBe(0);
  }, 60_000);

  it('CP-025/B5 a policy given with --policy is stored as a policy version and its digest is the proposal policy_sha256', async () => {
    const d = await demo(open, NO_KEY);
    const other = writeDemoPolicy(d.dir, { approvalMaxTtl: '10m' }, 'other-policy.yaml');
    const first = await plan(d);
    const run = await d.run(['--json', 'liquidity', 'plan', '--refresh', '--policy', other]);
    expect(run.status).toBe(SUCCESS);
    const second = resultOf(documentOf(run, 'liquidity-plan'));
    expect(second['policy_sha256']).not.toBe(first['policy_sha256']);
    const versions = rows(d.database, 'SELECT policy_sha256 FROM policy_versions ORDER BY policy_sha256').map(row => row['policy_sha256']);
    expect(versions).toEqual([first['policy_sha256'], second['policy_sha256']].sort());
  }, 60_000);
});
