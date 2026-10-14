# FluxWarden architecture

This document describes the implementation as it becomes available: module layout and boundaries, adapter contracts, persistence model, execution state machine and lab architecture.

## Module layout

The CLI wires adapters, persistence and command controllers. Configured money movement is separate from proposal generation; the daemon observes, plans, sweeps expired preflight leases and reconciles without signing or executing. It bootstraps persistent HMAC-signed alerts. Command-created evidence records observed metadata and explicit reasons for unavailable provenance as described in [the specification](spec.md).

| Directory | Contents | May import |
| --- | --- | --- |
| `src/core/` | Domain types, msat arithmetic, normalisation, canonical encoding, exit codes. Pure. | `src/core`, `node:crypto` |
| `src/node-lnd/`, `src/node-cln/` | Node adapters; the only modules with network access. | `src/core` |
| `src/persistence/` | `node:sqlite` repositories and schema; the only module with SQL. | `src/core` |
| `src/planner/` | Diagnosis against operator targets and candidate planning. Pure: no network, no SQL, no file access; time comes from an injected clock. | `src/core`, `src/planner` |
| `src/commands/` | One module per command. Each turns inputs (snapshots, policy, clock) into an exit code and the `--json` document, without writing to a stream. | `src/core`, `src/planner`, `src/persistence`, `src/output` |
| `src/output/` | Text and JSON rendering, redaction, the only writer to stdout and stderr. | `src/core` |
| `src/cli/` | Argument parsing, wiring, writing a command's document through `src/output`. | any of the above except the adapters' internals |

Command modules never import `src/node-lnd` or `src/node-cln` directly: adapters are constructed in `src/cli` and `src/daemon` and handed in through the interfaces in `src/core`.

## Channel liquidity figures

Every channel figure carries a confidence tag: `NODE_REPORTED` when the node computed it, `DERIVED_ESTIMATE` when FluxWarden derived it from other fields. Amounts are millisatoshis; LND's satoshi fields are multiplied by 1,000.

### Core Lightning (`NODE_REPORTED`)

`spendable_msat` and `receivable_msat` from `listpeerchannels` are used as reported, with the node's own caveat that both are estimates. An answer whose `to_us_msat` exceeds `total_msat`, whose `spendable_msat` exceeds `to_us_msat`, or whose `receivable_msat` exceeds `total_msat` − `to_us_msat` is refused as a protocol error. A channel CLN is still negotiating (`OPENINGD`, `DUALOPEND_OPEN_INIT` without a `channel_id`) is listed as `PENDING`, keyed `uncommitted:<peer_id>`, with no funding outpoint, spendable and receivable 0, and missing amounts read as 0.

### LND (`DERIVED_ESTIMATE`)

LND exposes no per-channel spendable amount, so it is derived from `ListChannels` (all values in sat, results × 1,000 to msat):

```text
buffer      = floor(2 × fee_per_kw × (commit_weight + 172) / 1000)
anchors     = 660 for anchor, lease and taproot commitment types, 0 for LEGACY and STATIC_REMOTE_KEY
local_free  = max(0, local_balance  − local_constraints.chan_reserve_sat)
remote_free = max(0, remote_balance − remote_constraints.chan_reserve_sat)

opener side:      figure = max(0, free − buffer − anchors)
non-opener side:  figure = free, unless opener_balance − opener_reserve < floor(fee_per_kw × 172 / 1000);
                  then figure = min(free, own_dust + timeout_fee − 0.001, other_dust + success_fee − 0.001)
timeout_fee = success_fee = 0 for anchor and taproot types, else floor(fee_per_kw × 663 / 1000) and floor(fee_per_kw × 703 / 1000)
```

Spendable is our figure and receivable is the peer's. `own_dust` is the `dust_limit_sat` from that side's constraints and `other_dust` is the other side's.

- `buffer` is lnd's `CalcFeeBuffer` (lnwallet/channel.go): the commitment fee plus one HTLC weight (172, input/size.go) at twice the current fee rate, rounded down as `FeeForWeight` does.
- Pending HTLCs are not subtracted: `local_balance` is the local commitment's balance, which already excludes HTLC outputs.
- The non-opener rule is lnd's `availableCommitmentBalance`. If the opener cannot pay the fee for one more HTLC above its reserve, lnd reports just below the smallest non-dust HTLC, the smaller of the two commitment views (`availableBalance`). Its commitment fee is added back before the comparison, so the rule reduces to the fee of one HTLC weight.
- Reserve fields are required: a channel without `*_constraints.chan_reserve_sat` (or, without constraints, the deprecated `*_chan_reserve_sat`) is malformed.
- On the opener side the figure stays at or below lnd's own. `local_balance` already has the current commitment fee and the anchor outputs taken off, so subtracting `buffer` and the anchors again leaves a margin of about `commit_fee` + 660 sat. The margin is kept on purpose: lnd computes the buffer from its weight estimate and takes the smaller of its local and remote commitment views, and neither is visible over RPC, so a tighter formula could report more than lnd accepts.
- Channels from `PendingChannels` have spendable and receivable 0.
- These bounds hold for the committed state that `ListChannels` reports. lnd evaluates its own figure over its update log, which can hold changes that are not yet committed: an `update_fee` from the opener, new HTLCs, or the remote commitment tip. Such changes can lower lnd's figure below FluxWarden's for a moment, until they are committed. A payment refused for insufficient local balance is then reported as a local failure, not as missing liquidity.

## State directory and database files

FluxWarden changes the permissions only of what it creates: directories it makes, the database, and the database's `-wal` and `-shm` files. A directory that already exists, such as the working directory holding `./fluxwarden.db`, is never changed. On POSIX, missing directories are created with mode 0700 and the database with 0600, which SQLite also gives `-wal` and `-shm`. Every ancestor must have trusted ownership and prevent other users from replacing the traversed directory. POSIX ancestors must be owned by root or the current user and must not grant group or other write access; a trusted sticky directory is accepted when its traversed children also have trusted ownership. On Windows, ancestors may grant other users read access or creation of siblings, but must not grant deletion or control of the traversed directories; the parent of a new directory must also have safe inherited permissions. The state directory itself must be owner-only in both read-only and read-write modes. A database or side file that other users can access, that another user owns, that is reached through a symbolic link or junction, or that has a second hard link is refused. On Windows, missing directories get a protected DACL whose only entry is the current user. A new database is first created in a staging directory restricted the same way, given its own owner-only DACL, and only then linked to its final name, so it is never reachable with a broader access list. After a read-write connection opens, `-wal` and `-shm` files that SQLite created with the directory's inherited entries are restricted. An existing state directory, database, `-wal` or `-shm` that grants access to any principal other than the current user, SYSTEM and Administrators (which can take over any file in any case) is refused, never changed. Every existing object must also be owned by the current user. Owner SIDs and DACLs are read together with a fixed read-only script through the system Windows PowerShell executable; paths are supplied as data. Checks that meet another process's transient state (a file being linked or restricted) have a 1.5 s retry window; each system-tool invocation is bounded at 30 s.

Append-only tables (`channel_snapshots`, `approvals`, `execution_events`, `ledger_journals`, `ledger_lines`) abort `UPDATE` and `DELETE`, so an upsert that would update (`ON CONFLICT DO UPDATE`) fails. Every key such a row holds is also recorded when it is inserted. A `REPLACE` or `INSERT OR REPLACE` that deletes a conflicting row then meets its recorded key and aborts on any connection, whether or not it enables `recursive_triggers`. An idempotent `INSERT … ON CONFLICT DO NOTHING` inserts nothing and stays allowed. Snapshot age is measured with the database clock. A snapshot stamped after that clock has an age of `Infinity`, which output layers must render explicitly rather than as `null`.

## Planning

`liquidity diagnose` compares the latest snapshot of every channel with the operator's targets. Inbound deficit is `max(0, min_inbound_msat − receivable)` and inbound surplus `max(0, receivable − min_inbound_msat)`, with a missing target counting as 0; outbound figures use `min_outbound_msat` against spendable. Every figure keeps the confidence tag and caveat of the snapshot it came from. A snapshot older than `max_snapshot_age` or dated after the database clock, or a targeted channel without any snapshot, refuses the whole diagnosis with `STALE_SNAPSHOT` (exit 5) and prints no figures; two snapshots for one channel exit 8; a node without targets reports `NO_ACTION` with reason `INSUFFICIENT_HISTORY`.

The planner pairs every starved channel (inbound deficit, the source) with every donor (inbound surplus, the target). Channels listed in `exclude_channels` are left out before pairing. Each pair ends as one candidate or one refusal, checked in this order:

0. `NO_FEASIBLE_ROUTE`: the source or the target is not `ACTIVE`.
1. `COOLDOWN_ACTIVE`: a failed rebalance of the same pair within `cooldown_after_failure`, or a successful one touching either channel within `cooldown_after_success`. The longest remaining time is reported.
2. `BUDGET_EXHAUSTED`: held reservations at their worst-case fee plus consumed fees in the current period, plus this attempt's `max_fee_msat`, exceed `budget.msat`; or the node already has `max_in_flight` executions unresolved.
3. Principal = min(inbound deficit of the source, inbound surplus of the target, source spendable − `max_fee_msat` − `min_channel_reserve_msat`, `max_principal_msat`). Below `min_principal_msat` the pair is refused, with `RESERVE_FLOOR` when the reserve term binds, `LAST_HOP_RECEIVABLE` when the target's surplus binds, and `BALANCED_OR_INSUFFICIENT_SURPLUS` when the source's own deficit (or `max_principal_msat`) is too small to move.

Candidates are ranked by principal descending, then source channel key, then target channel key, so the same inputs give the same plan.
