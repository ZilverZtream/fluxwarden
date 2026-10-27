/**
 * Forward-only schema migrations. Migration n (1-based) moves PRAGMA user_version from n - 1 to n; applied
 * migrations are never edited. The DDL keeps to a SQL subset that maps onto MySQL 8.4 column by column; the
 * mapping is written beside each statement. Shared mapping rules:
 *
 *   TEXT ULID id          → CHAR(26) CHARACTER SET ascii COLLATE ascii_bin
 *   INTEGER msat          → BIGINT (signed)
 *   INTEGER unix ms time  → DATETIME(6), written with NOW(6)
 *   TEXT CHECK (x IN (…)) → ENUM(…) with the same members
 *   TEXT JSON             → JSON
 *   STRICT                → dropped (InnoDB enforces column types)
 */

/** Statements of migration 1: the v1 tables, their indexes and the append-only triggers. */
const V1: readonly string[] = [
  `-- MySQL: id CHAR(26) ascii_bin, name VARCHAR(64), implementation ENUM('lnd','cln'), expected_network ENUM('regtest'),
  -- expected_pubkey CHAR(66) ascii, capabilities_json JSON, state ENUM('ONLINE','OFFLINE','QUARANTINED'), last_probed_at DATETIME(6)
  CREATE TABLE nodes (
    id TEXT PRIMARY KEY CHECK (length(id) = 26),
    name TEXT NOT NULL UNIQUE,
    implementation TEXT NOT NULL CHECK (implementation IN ('lnd','cln')),
    expected_network TEXT NOT NULL CHECK (expected_network = 'regtest'),
    expected_pubkey TEXT NOT NULL,
    observed_version TEXT,
    capabilities_json TEXT CHECK (capabilities_json IS NULL OR json_valid(capabilities_json)),
    state TEXT NOT NULL DEFAULT 'OFFLINE' CHECK (state IN ('ONLINE','OFFLINE','QUARANTINED')),
    last_probed_at INTEGER,
    UNIQUE (expected_network, expected_pubkey)
  ) STRICT`,

  `-- MySQL: id and node_id CHAR(26) ascii_bin, channel_key VARCHAR(80) ascii, scid VARCHAR(32) ascii, peer_pubkey CHAR(66) ascii,
  -- funding_outpoint VARCHAR(80) ascii, capacity_msat BIGINT, lifecycle_state ENUM(...same members), updated_at DATETIME(6)
  CREATE TABLE channels (
    id TEXT PRIMARY KEY CHECK (length(id) = 26),
    node_id TEXT NOT NULL REFERENCES nodes(id),
    channel_key TEXT NOT NULL,
    scid TEXT,
    peer_pubkey TEXT NOT NULL,
    funding_outpoint TEXT NOT NULL,
    capacity_msat INTEGER NOT NULL CHECK (capacity_msat >= 0),
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN ('ACTIVE','INACTIVE','PENDING','CLOSING','UNKNOWN')),
    updated_at INTEGER NOT NULL,
    UNIQUE (node_id, channel_key)
  ) STRICT`,

  `-- MySQL: id BIGINT AUTO_INCREMENT, channel_id CHAR(26) ascii_bin, observed_at DATETIME(6), block_height INT UNSIGNED,
  -- every *_msat BIGINT, pending_htlc_count INT, confidence ENUM('NODE_REPORTED','DERIVED_ESTIMATE'), provenance_json JSON
  CREATE TABLE channel_snapshots (
    id INTEGER PRIMARY KEY,
    channel_id TEXT NOT NULL REFERENCES channels(id),
    observed_at INTEGER NOT NULL,
    block_height INTEGER NOT NULL CHECK (block_height >= 0),
    local_msat INTEGER NOT NULL CHECK (local_msat >= 0),
    remote_msat INTEGER NOT NULL CHECK (remote_msat >= 0),
    spendable_msat INTEGER NOT NULL CHECK (spendable_msat >= 0),
    receivable_msat INTEGER NOT NULL CHECK (receivable_msat >= 0),
    pending_out_msat INTEGER NOT NULL CHECK (pending_out_msat >= 0),
    pending_in_msat INTEGER NOT NULL CHECK (pending_in_msat >= 0),
    pending_htlc_count INTEGER NOT NULL CHECK (pending_htlc_count >= 0),
    confidence TEXT NOT NULL CHECK (confidence IN ('NODE_REPORTED','DERIVED_ESTIMATE')),
    provenance_json TEXT NOT NULL CHECK (json_valid(provenance_json))
  ) STRICT`,

  `-- MySQL: same
  CREATE INDEX snapshots_by_channel_time ON channel_snapshots (channel_id, observed_at)`,

  `-- MySQL: id CHAR(26) ascii_bin, policy_sha256 CHAR(64) ascii, policy_canonical_json JSON, created_at DATETIME(6)
  CREATE TABLE policy_versions (
    id TEXT PRIMARY KEY,
    version_no INTEGER NOT NULL,
    policy_sha256 TEXT NOT NULL UNIQUE,
    policy_canonical_json TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at INTEGER NOT NULL
  ) STRICT`,

  `-- MySQL: ids CHAR(26) ascii_bin, *_msat BIGINT, action_type, demand_source and status ENUM(...same members),
  -- route_json and reason_json JSON, proposal_digest CHAR(64) ascii, expires_at and created_at DATETIME(6)
  CREATE TABLE liquidity_proposals (
    id TEXT PRIMARY KEY,
    policy_version_id TEXT NOT NULL REFERENCES policy_versions(id),
    node_id TEXT NOT NULL REFERENCES nodes(id),
    action_type TEXT NOT NULL CHECK (action_type IN ('CIRCULAR_REBALANCE','NO_ACTION')),
    source_channel_id TEXT REFERENCES channels(id),
    target_channel_id TEXT REFERENCES channels(id),
    principal_msat INTEGER CHECK (principal_msat > 0),
    max_fee_msat INTEGER CHECK (max_fee_msat >= 0),
    max_fee_ppm INTEGER,
    max_cltv_delta INTEGER,
    route_json TEXT,
    demand_source TEXT NOT NULL CHECK (demand_source IN ('TARGETS','EWMA')),
    proposal_digest TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'PROPOSED' CHECK (status IN ('PROPOSED','APPROVED','REJECTED','EXPIRED')),
    reason_json TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  ) STRICT`,

  `-- MySQL: ids CHAR(26) ascii_bin, nonce CHAR(64) ascii, signature VARCHAR(128) ascii, max_fee_msat BIGINT,
  -- expires_at and created_at DATETIME(6)
  CREATE TABLE approvals (
    id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL REFERENCES liquidity_proposals(id),
    key_id TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    signature TEXT NOT NULL,
    max_fee_msat INTEGER NOT NULL CHECK (max_fee_msat >= 0),
    max_cltv_delta INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  ) STRICT`,

  `-- MySQL: ids CHAR(26) ascii_bin, fence_epoch BIGINT, status and delta_status ENUM(...same members), payment_hash CHAR(64) ascii,
  -- route_json JSON, *_fee_msat BIGINT, times DATETIME(6)
  CREATE TABLE executions (
    id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL UNIQUE REFERENCES liquidity_proposals(id),
    approval_id TEXT NOT NULL REFERENCES approvals(id),
    worker_id TEXT,
    fence_epoch INTEGER NOT NULL DEFAULT 0,
    lease_expires_at INTEGER,
    status TEXT NOT NULL CHECK (status IN ('CLAIMED','PREFLIGHT','SUBMITTING','IN_FLIGHT',
                                           'VERIFIED_SUCCESS','VERIFIED_FAILURE','UNKNOWN','CANCELLED')),
    payment_hash TEXT UNIQUE,
    route_json TEXT,
    planned_fee_msat INTEGER CHECK (planned_fee_msat >= 0),
    actual_fee_msat INTEGER CHECK (actual_fee_msat >= 0),
    delta_status TEXT CHECK (delta_status IN ('MATCH','MISMATCH','PENDING')),
    error_code TEXT,
    submitted_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  ) STRICT`,

  `-- MySQL: same
  CREATE INDEX executions_by_status_lease ON executions (status, lease_expires_at)`,

  `-- MySQL: id BIGINT AUTO_INCREMENT, execution_id CHAR(26) ascii_bin, statuses ENUM(...execution members), evidence_json JSON, at DATETIME(6)
  CREATE TABLE execution_events (
    id INTEGER PRIMARY KEY,
    execution_id TEXT NOT NULL REFERENCES executions(id),
    fence_epoch INTEGER NOT NULL,
    from_status TEXT,
    to_status TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    at INTEGER NOT NULL
  ) STRICT`,

  `-- MySQL: ids CHAR(26) ascii_bin, period_start DATETIME(6), *_msat BIGINT, state ENUM('HELD','CONSUMED','RELEASED')
  CREATE TABLE budget_reservations (
    id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL UNIQUE REFERENCES executions(id),
    period_start INTEGER NOT NULL,
    reserved_msat INTEGER NOT NULL CHECK (reserved_msat >= 0),
    consumed_msat INTEGER CHECK (consumed_msat >= 0),
    state TEXT NOT NULL CHECK (state IN ('HELD','CONSUMED','RELEASED'))
  ) STRICT`,

  `-- MySQL: ids CHAR(26) ascii_bin, event_type VARCHAR(32) ascii, reference VARCHAR(128) ascii, occurred_at DATETIME(6)
  CREATE TABLE ledger_journals (
    id TEXT PRIMARY KEY,
    execution_id TEXT REFERENCES executions(id),
    event_type TEXT NOT NULL,
    reference TEXT NOT NULL,
    occurred_at INTEGER NOT NULL,
    UNIQUE (event_type, reference)
  ) STRICT`,

  `-- MySQL: journal_id CHAR(26) ascii_bin, sequence_no INT, account_code VARCHAR(64) ascii, debit_msat and credit_msat BIGINT
  CREATE TABLE ledger_lines (
    journal_id TEXT NOT NULL REFERENCES ledger_journals(id),
    sequence_no INTEGER NOT NULL,
    account_code TEXT NOT NULL,
    debit_msat INTEGER NOT NULL DEFAULT 0 CHECK (debit_msat >= 0),
    credit_msat INTEGER NOT NULL DEFAULT 0 CHECK (credit_msat >= 0),
    CHECK ((debit_msat = 0) <> (credit_msat = 0)),
    PRIMARY KEY (journal_id, sequence_no)
  ) STRICT`,

  `-- MySQL: account_code VARCHAR(64) ascii, balance_decimal DECIMAL(39,0) read as a string
  CREATE TABLE account_balances (
    account_code TEXT PRIMARY KEY,
    balance_decimal TEXT NOT NULL CHECK (balance_decimal = '0'
      OR (balance_decimal GLOB '[1-9]*' AND balance_decimal NOT GLOB '*[^0-9]*' AND length(balance_decimal) <= 39)
      OR (balance_decimal GLOB '-[1-9]*' AND substr(balance_decimal, 2) NOT GLOB '*[^0-9]*' AND length(balance_decimal) <= 40))
  ) STRICT`,

  ...['channel_snapshots', 'approvals', 'execution_events', 'ledger_journals', 'ledger_lines'].flatMap(table => [
    `-- MySQL: BEFORE UPDATE trigger that runs SIGNAL SQLSTATE '45000' with the same message
    CREATE TRIGGER ${table}_no_update BEFORE UPDATE ON ${table} BEGIN SELECT RAISE(ABORT, '${table} is append-only'); END`,
    `-- MySQL: BEFORE DELETE trigger that runs SIGNAL SQLSTATE '45000' with the same message
    CREATE TRIGGER ${table}_no_delete BEFORE DELETE ON ${table} BEGIN SELECT RAISE(ABORT, '${table} is append-only'); END`,
  ]),

  // REPLACE (and INSERT OR REPLACE) deletes the conflicting row without firing DELETE triggers unless the
  // connection enables recursive_triggers (sqlite.org/lang_conflict.html). Every key an append-only row ever held
  // is therefore recorded here when the row is inserted; an insert that finds one of its keys already recorded
  // can only have replaced the row that held it, and aborts, which undoes the deletion. An insert that meets a
  // conflict and does nothing (ON CONFLICT DO NOTHING) inserts no row and fires no trigger, so it stays allowed.
  `-- MySQL: n/a, REPLACE is never used, so InnoDB needs no record of retired keys
  CREATE TABLE append_only_keys (
    table_name TEXT NOT NULL,
    key_text TEXT NOT NULL,
    PRIMARY KEY (table_name, key_text)
  ) STRICT`,

  `-- MySQL: n/a, the table does not exist there
  CREATE TRIGGER append_only_keys_no_update BEFORE UPDATE ON append_only_keys BEGIN SELECT RAISE(ABORT, 'append_only_keys is append-only'); END`,

  `-- MySQL: n/a, the table does not exist there
  CREATE TRIGGER append_only_keys_no_delete BEFORE DELETE ON append_only_keys BEGIN SELECT RAISE(ABORT, 'append_only_keys is append-only'); END`,

  ...([
    ['channel_snapshots', ["'id:' || NEW.id"]],
    ['approvals', ["'id:' || NEW.id", "'nonce:' || NEW.nonce"]],
    ['execution_events', ["'id:' || NEW.id"]],
    ['ledger_journals', ["'id:' || NEW.id", "'ref:' || json_array(NEW.event_type, NEW.reference)"]],
    ['ledger_lines', ["'line:' || json_array(NEW.journal_id, NEW.sequence_no)"]],
  ] as const).map(([table, keys]) =>
    `-- MySQL: n/a, REPLACE is never used and a duplicate key fails on the PRIMARY KEY or UNIQUE index
    CREATE TRIGGER ${table}_no_replace AFTER INSERT ON ${table}
    BEGIN SELECT RAISE(ABORT, '${table} is append-only') WHERE EXISTS (SELECT 1 FROM append_only_keys
      WHERE table_name = '${table}' AND key_text IN (${keys.join(', ')}));
    INSERT INTO append_only_keys (table_name, key_text) VALUES ${keys.map(key => `('${table}', ${key})`).join(', ')}; END`),
];

/** Every migration in order; the schema version of a database is the number of migrations applied to it. */
export const MIGRATIONS: readonly (readonly string[])[] = [V1, [
  '-- MySQL: same; preserve the opening identity when the channel receives a new public key.\nALTER TABLE channels ADD COLUMN opening_channel_key TEXT',
  // MySQL: same one-time backfill UPDATE in the schema migration transaction.
  'UPDATE channels SET opening_channel_key = channel_key WHERE opening_channel_key IS NULL',
], [
  `-- MySQL: BEFORE UPDATE trigger that runs SIGNAL SQLSTATE '45000' with the same message
  CREATE TRIGGER policy_versions_no_update BEFORE UPDATE ON policy_versions BEGIN SELECT RAISE(ABORT, 'policy_versions is append-only'); END`,
  `-- MySQL: BEFORE DELETE trigger that runs SIGNAL SQLSTATE '45000' with the same message
  CREATE TRIGGER policy_versions_no_delete BEFORE DELETE ON policy_versions BEGIN SELECT RAISE(ABORT, 'policy_versions is append-only'); END`,
  `-- MySQL: n/a, record the immutable keys of existing policy versions for SQLite REPLACE protection.
  INSERT INTO append_only_keys (table_name, key_text) SELECT 'policy_versions', 'id:' || id FROM policy_versions`,
  `-- MySQL: n/a, record the immutable hashes of existing policy versions for SQLite REPLACE protection.
  INSERT INTO append_only_keys (table_name, key_text) SELECT 'policy_versions', 'sha:' || policy_sha256 FROM policy_versions`,
  `-- MySQL: n/a, REPLACE is never used and a duplicate key fails on the PRIMARY KEY or UNIQUE index
  CREATE TRIGGER policy_versions_no_replace AFTER INSERT ON policy_versions
  BEGIN SELECT RAISE(ABORT, 'policy_versions is append-only') WHERE EXISTS (SELECT 1 FROM append_only_keys
    WHERE table_name = 'policy_versions' AND key_text IN ('id:' || NEW.id, 'sha:' || NEW.policy_sha256));
  INSERT INTO append_only_keys (table_name, key_text) VALUES ('policy_versions', 'id:' || NEW.id), ('policy_versions', 'sha:' || NEW.policy_sha256); END`,
], [
  `-- MySQL: ids CHAR(26) ascii_bin, layer VARCHAR(128), epochs BIGINT, state ENUM('PENDING','CLEANED'), times DATETIME(6)
  CREATE TABLE routing_layers (
    id TEXT PRIMARY KEY CHECK (length(id) = 26),
    node_id TEXT NOT NULL REFERENCES nodes(id),
    layer TEXT NOT NULL CHECK (length(layer) BETWEEN 1 AND 128),
    execution_id TEXT NOT NULL REFERENCES executions(id),
    acquired_fence_epoch INTEGER NOT NULL CHECK (acquired_fence_epoch > 0),
    fence_epoch INTEGER NOT NULL CHECK (fence_epoch > 0),
    state TEXT NOT NULL CHECK (state IN ('PENDING','CLEANED')),
    worker_id TEXT,
    lease_expires_at INTEGER,
    acquired_at INTEGER NOT NULL,
    last_attempt_at INTEGER,
    completed_at INTEGER,
    UNIQUE (node_id, layer)
  ) STRICT`,
  '-- MySQL: same\nCREATE INDEX routing_layers_cleanup ON routing_layers(state, last_attempt_at, acquired_at)',
  `-- MySQL: BEFORE UPDATE trigger with SIGNAL SQLSTATE '45000'; cleanup bookkeeping may change, ownership may not.
  CREATE TRIGGER routing_layers_owner_immutable BEFORE UPDATE OF id, node_id, layer, execution_id, acquired_fence_epoch, acquired_at
    ON routing_layers BEGIN SELECT RAISE(ABORT, 'routing layer ownership is immutable'); END`,
  `-- MySQL: BEFORE DELETE trigger with SIGNAL SQLSTATE '45000'; conclusive cleanup keeps its ownership evidence.
  CREATE TRIGGER routing_layers_no_delete BEFORE DELETE ON routing_layers
    BEGIN SELECT RAISE(ABORT, 'routing layer ownership is durable'); END`,
], [
  // No legacy backfill: the mutable nodes row cannot prove the identity that owned its history.
  `-- MySQL: node_id CHAR(26) ascii_bin PRIMARY KEY, implementation ENUM('lnd','cln'), pubkey CHAR(66) ascii
  CREATE TABLE node_identity_bindings (
    node_id TEXT PRIMARY KEY REFERENCES nodes(id),
    implementation TEXT NOT NULL CHECK (implementation IN ('lnd','cln')),
    pubkey TEXT NOT NULL
  ) STRICT`,
  `-- MySQL: same AFTER INSERT trigger with INSERT INTO node_identity_bindings.
  CREATE TRIGGER nodes_bind_identity AFTER INSERT ON nodes BEGIN
    INSERT INTO node_identity_bindings (node_id, implementation, pubkey) VALUES (NEW.id, NEW.implementation, NEW.expected_pubkey); END`,
  `-- MySQL: BEFORE UPDATE trigger with SIGNAL SQLSTATE '45000'.
  CREATE TRIGGER nodes_identity_immutable BEFORE UPDATE OF implementation, expected_pubkey ON nodes
    WHEN NEW.implementation <> OLD.implementation OR NEW.expected_pubkey <> OLD.expected_pubkey
    BEGIN SELECT RAISE(ABORT, 'node identity is immutable'); END`,
  `-- MySQL: BEFORE UPDATE trigger with SIGNAL SQLSTATE '45000'.
  CREATE TRIGGER node_identity_bindings_no_update BEFORE UPDATE ON node_identity_bindings
    BEGIN SELECT RAISE(ABORT, 'node identity binding is immutable'); END`,
  `-- MySQL: BEFORE DELETE trigger with SIGNAL SQLSTATE '45000'.
  CREATE TRIGGER node_identity_bindings_no_delete BEFORE DELETE ON node_identity_bindings
    BEGIN SELECT RAISE(ABORT, 'node identity binding is durable'); END`,
  `-- MySQL: n/a; a duplicate key fails, REPLACE is never used.
  CREATE TRIGGER node_identity_bindings_no_replace AFTER INSERT ON node_identity_bindings BEGIN
    SELECT RAISE(ABORT, 'node identity binding is durable') WHERE EXISTS (SELECT 1 FROM append_only_keys
      WHERE table_name = 'node_identity_bindings' AND key_text = NEW.node_id);
    INSERT INTO append_only_keys (table_name, key_text) VALUES ('node_identity_bindings', NEW.node_id); END`,
], [
  '-- MySQL: same\nALTER TABLE nodes ADD COLUMN fence_epoch INTEGER NOT NULL DEFAULT 0',
  `-- MySQL: id INTEGER PRIMARY KEY, fence_epoch BIGINT, pending BOOLEAN
  CREATE TABLE restore_barrier (id INTEGER PRIMARY KEY CHECK (id = 1), fence_epoch INTEGER NOT NULL,
    pending INTEGER NOT NULL CHECK (pending IN (0,1))) STRICT`,
  `-- MySQL: node_id CHAR(26) ascii_bin PRIMARY KEY, implementation ENUM('lnd','cln'), pubkey CHAR(66) ascii
  CREATE TABLE restore_required_nodes (node_id TEXT PRIMARY KEY REFERENCES nodes(id), implementation TEXT NOT NULL, pubkey TEXT NOT NULL) STRICT`,
]];

export const SCHEMA_VERSION = MIGRATIONS.length;
