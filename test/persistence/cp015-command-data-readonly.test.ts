/*
 * Accepted CP-015/B2 (test/persistence/cp015-persistence.test.ts): every read-only read returns the
 * latest committed state or BUSY, never older data. SECURITY §5 also requires live owner-only path
 * checks and no writes from a read-only handle. These tests reach only public persistence methods;
 * the separate SQLite writer uses the SPEC §6.2 schema, as existing executor fixture helpers do.
 */
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { beforeEach, expect, it } from 'vitest';
import { childEnv, repoRoot } from '../helpers/cli.js';
import {
  channel, codeOf, fileHash, grantOthers, listing, loadPersistence, NODE_ID, raw, scratch, seeded,
  type Database, type SnapshotInput,
} from '../helpers/cp015-persistence.js';

interface ApprovalRow {
  id: string; proposal_id: string; key_id: string; nonce: string; expires_at: number;
  signature: string; max_fee_msat: bigint; max_cltv_delta: number; created_at: number;
}

interface CommandDatabase extends Database {
  commandData: {
    snapshots(nodeId: string): SnapshotInput[];
    proposalIds(): string[];
    executionIds(): string[];
    approvals: {
      listByProposal(id: string): ApprovalRow[];
      insert(row: ApprovalRow): void;
    };
  };
}

const PROPOSAL = 'readonly-proposal-initial';
const EXECUTION = 'readonly-execution-initial';
const APPROVAL = 'readonly-approval-initial';
const INITIAL_BALANCE = 600_000n;
const COMMITTED_BALANCE = 500_000n;

// Literals below are fixture facts, not values copied from any product result. Balances are msat;
// timestamps and ordering are SPEC §6.2 unix milliseconds and the supplied public read contract.
function fixtureRows(path: string): void {
  const db = raw(path);
  try {
    db.exec(`
      INSERT INTO policy_versions (id, version_no, policy_sha256, policy_canonical_json, author, created_at)
        VALUES ('readonly-policy', 3, 'readonly-policy-digest', '{}', 'test', 0);
    `);
    db.prepare(`INSERT INTO liquidity_proposals (id, policy_version_id, node_id, action_type,
      principal_msat, max_fee_msat, max_fee_ppm, max_cltv_delta, demand_source, proposal_digest,
      status, reason_json, expires_at, created_at)
      VALUES (?, 'readonly-policy', ?, 'NO_ACTION', NULL, NULL, NULL, NULL, 'TARGETS',
        'readonly-initial-digest', 'APPROVED', '{}', 2000000000000, 1000)`).run(PROPOSAL, NODE_ID);
    db.prepare(`INSERT INTO approvals (id, proposal_id, key_id, nonce, expires_at, signature,
      max_fee_msat, max_cltv_delta, created_at)
      VALUES (?, ?, 'test-key', 'test-nonce-initial', 2000000000000, 'test-signature', 10, 100, 1000)`)
      .run(APPROVAL, PROPOSAL);
    db.prepare(`INSERT INTO executions (id, proposal_id, approval_id, fence_epoch, status, created_at, updated_at)
      VALUES (?, ?, ?, 0, 'CLAIMED', 1000, 1000)`).run(EXECUTION, PROPOSAL, APPROVAL);
  } finally { db.close(); }
}

async function fixture(): Promise<{ path: string; channelId: string; open(readOnly: boolean): CommandDatabase }> {
  const p = await loadPersistence();
  const path = join(scratch('command-data-readonly'), 'fluxwarden.db');
  const channelId = seeded(p, path);
  const db = p.openDatabase(path, { readOnly: false });
  try { db.snapshots.record(channelId, channel({ localBalanceMsat: INITIAL_BALANCE })); }
  finally { db.close(); }
  fixtureRows(path);
  return { path, channelId, open: readOnly => p.openDatabase(path, { readOnly }) as CommandDatabase };
}

// Each case keeps its own fresh database. Native owner-only setup completes under the existing
// fixture hook deadline before the unchanged behavior deadline starts.
let preparedFixture: Awaited<ReturnType<typeof fixture>>;
beforeEach(async () => { preparedFixture = await fixture(); });

// Separate process, real commit, then close/checkpoint before the parent resumes. No sleep or mocked
// persistence boundary: spawnSync completion is the deterministic interleaving barrier.
const WRITER = `
import { DatabaseSync } from 'node:sqlite';
const [modulePath, path, channelId, nodeId, proposalId] = process.argv.slice(1);
const { openDatabase } = await import(modulePath);
const input = JSON.parse(process.env.FW_CHANNEL, (_key, value) =>
  typeof value === 'string' && value.startsWith('bigint:') ? BigInt(value.slice(7)) : value);
const db = openDatabase(path, { readOnly: false });
db.snapshots.record(channelId, input);
db.close();
const writer = new DatabaseSync(path);
writer.exec('BEGIN IMMEDIATE');
writer.prepare(\`INSERT INTO liquidity_proposals (id, policy_version_id, node_id, action_type,
  principal_msat, max_fee_msat, max_fee_ppm, max_cltv_delta, demand_source, proposal_digest,
  status, reason_json, expires_at, created_at)
  VALUES ('readonly-proposal-committed', 'readonly-policy', ?, 'NO_ACTION', NULL, NULL, NULL, NULL,
    'TARGETS', 'readonly-committed-digest', 'PROPOSED', '{}', 2000000000000, 2000)\`).run(nodeId);
writer.prepare(\`INSERT INTO approvals (id, proposal_id, key_id, nonce, expires_at, signature,
  max_fee_msat, max_cltv_delta, created_at)
  VALUES ('readonly-approval-committed', ?, 'test-key', 'test-nonce-committed', 2000000000000,
    'test-signature', 9, 99, 2000)\`).run(proposalId);
writer.exec(\`INSERT INTO executions (id, proposal_id, approval_id, fence_epoch, status, created_at, updated_at)
  VALUES ('readonly-execution-committed', 'readonly-proposal-committed', 'readonly-approval-committed',
    0, 'CLAIMED', 2000, 2000)\`);
writer.exec('COMMIT');
writer.close();
`;

function commitExternally(path: string, channelId: string): void {
  const encoded = JSON.stringify(channel({ localBalanceMsat: COMMITTED_BALANCE, blockHeight: 1_240 }),
    (_key, value: unknown) => typeof value === 'bigint' ? `bigint:${value.toString()}` : value);
  const result = spawnSync(process.execPath, ['--no-warnings', '--input-type=module', '-e', WRITER,
    pathToFileURL(join(repoRoot, 'dist/persistence/index.js')).href, path, channelId, NODE_ID, PROPOSAL],
  { env: { ...childEnv(), FW_CHANNEL: encoded }, shell: false, windowsHide: true, encoding: 'utf8', timeout: 10_000 });
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
}

interface ReadCase {
  name: string;
  read(db: CommandDatabase): unknown;
  initial: unknown;
  committed: unknown;
}

const READS: ReadCase[] = [
  { name: 'snapshots', read: db => db.commandData.snapshots(NODE_ID).map(row => row.localBalanceMsat),
    initial: [600_000n], committed: [500_000n] },
  { name: 'proposalIds', read: db => db.commandData.proposalIds(),
    initial: [PROPOSAL], committed: [PROPOSAL, 'readonly-proposal-committed'] },
  { name: 'executionIds', read: db => db.commandData.executionIds(),
    initial: [EXECUTION], committed: [EXECUTION, 'readonly-execution-committed'] },
  { name: 'approvals.listByProposal', read: db => db.commandData.approvals.listByProposal(PROPOSAL).map(row => row.id),
    initial: [APPROVAL], committed: [APPROVAL, 'readonly-approval-committed'] },
];

for (const check of READS) {
  it(`CP-015/B2 commandData.${check.name} reads the external commit or BUSY on an existing read-only handle`, () => {
    const f = preparedFixture;
    const reader = f.open(true);
    try {
      expect(check.read(reader)).toEqual(check.initial);
      commitExternally(f.path, f.channelId);
      const before = { names: listing(dirname(f.path)), hash: fileHash(f.path) };
      let value: unknown;
      const code = codeOf(() => { value = check.read(reader); });
      if (code === undefined) expect.soft(value).toEqual(check.committed);
      else expect.soft(code).toBe('BUSY');
      // Read-only success/refusal must not create sidecars or checkpoint the changed file.
      expect({ names: listing(dirname(f.path)), hash: fileHash(f.path) }).toEqual(before);
      const snapshotCode = codeOf(() => {
        expect(reader.snapshots.latest(f.channelId)?.localMsat).toBe(500_000n);
      });
      if (snapshotCode !== undefined) expect(snapshotCode).toBe('BUSY');
    } finally { reader.close(); }
    const fresh = f.open(true);
    try { expect(check.read(fresh)).toEqual(check.committed); } finally { fresh.close(); }
  });
}

it('CP-015/B2 healthy read-only command data reads all initial facts without changing files', () => {
  const f = preparedFixture;
  const before = { names: listing(dirname(f.path)), hash: fileHash(f.path) };
  const reader = f.open(true);
  try {
    for (const check of READS) expect(check.read(reader), check.name).toEqual(check.initial);
  } finally { reader.close(); }
  expect({ names: listing(dirname(f.path)), hash: fileHash(f.path) }).toEqual(before);
});

it('CP-015/B2 ordinary writer command data reads new committed facts through the same handle', () => {
  const f = preparedFixture;
  const writer = f.open(false);
  try {
    for (const check of READS) expect(check.read(writer), check.name).toEqual(check.initial);
    commitExternally(f.path, f.channelId);
    for (const check of READS) expect(check.read(writer), check.name).toEqual(check.committed);
  } finally { writer.close(); }
});

it('CP-015/B7 command data reads refuse a database whose permissions became unsafe after opening', () => {
  const f = preparedFixture;
  const reader = f.open(true);
  try {
    for (const check of READS) expect(check.read(reader), check.name).toEqual(check.initial);
    grantOthers(f.path, 'file');
    for (const check of READS) expect.soft(codeOf(() => { check.read(reader); }), check.name).toBe('UNSAFE_PATH');
  } finally { reader.close(); }
});

it('CP-015/B2 a read-only command data handle refuses approval insertion without changing the database', () => {
  const f = preparedFixture;
  const before = fileHash(f.path);
  const reader = f.open(true);
  try {
    const row = reader.commandData.approvals.listByProposal(PROPOSAL)[0];
    if (!row) throw new Error('independently seeded approval missing');
    expect(codeOf(() => { reader.commandData.approvals.insert({ ...row, id: 'readonly-write', nonce: 'readonly-write' }); }))
      .toBe('READ_ONLY');
    expect(reader.commandData.approvals.listByProposal(PROPOSAL).map(item => item.id)).toEqual([APPROVAL]);
  } finally { reader.close(); }
  expect(fileHash(f.path)).toBe(before);
}, 60_000);
