# FluxWarden specification

FluxWarden observes LND and Core Lightning channels, proposes circular rebalances under a versioned policy, and executes an operator-approved proposal on regtest. It uses Node.js built-ins without runtime dependencies. Supported Node.js versions satisfy `^22.23.2 || ^24.18.1 || >=26.5.1`; reference node profiles are LND 0.21.4-beta and Core Lightning 26.06.9. [References](references.md) identify node sources; [the security model](security-model.md) describes trust boundaries.

Planning grants no payment authority. Execution requires a valid configuration, a pinned node identity and network, a supported capability profile and a stored Ed25519 approval. It uses one payment hash and one single-path attempt per intent. An uncertain result retains its budget reservation until node evidence resolves it.

## Configuration

The default configuration is ./fluxwarden.yaml; --config selects another file. Relative paths in the configuration resolve beside that file. Configuration, policy, certificate and credential files are bounded to 64 KiB. Unknown configuration and policy keys are refused. Each node has a distinct name and pinned public key; expected_network must be exactly regtest.

The following public keys are documentation examples. Replace node identities with your regtest node identities and the approval entry with the public output of your own key generation. Never put a private signing key in the configuration.

```yaml
# fluxwarden configuration
database: ./state/fluxwarden.db
policy: ./policy.yaml
collect_interval: 15s
attempt_deadline: 120s
escalate_after: 1h
delta_tolerance_msat: "1000"
alert_dir: ./state/alerts
approval_keys:
  - key_id: 5771912c132e093c318a318c979a9325
    public_key: "Fu+gYJN1L2YZVYWq1+RKcog8Dbc1+z8G44XhPT70LUw="
nodes:
  - name: lnd-r
    implementation: lnd
    url: https://localhost:8081
    tls_cert_path: ./credentials/lnd-r.crt
    macaroon_path: ./credentials/lnd-r.macaroon
    expected_pubkey: "020000000000000000000000000000000000000000000000000000000000000001"
    expected_network: regtest
  - name: cln-m
    implementation: cln
    url: https://localhost:3010
    tls_cert_path: ./credentials/cln-m.crt
    rune_path: ./credentials/cln-m.rune
    expected_pubkey: "030000000000000000000000000000000000000000000000000000000000000002"
    expected_network: regtest
```

Use a new state directory beneath a trusted owned parent. FluxWarden creates private state objects and refuses unsafe existing objects without changing their permissions. Windows checks object owners and DACLs; POSIX checks ownership and modes. Links and database files with additional hard links are refused. Every ancestor must prevent other users from replacing the traversed directory. See [architecture](architecture.md#state-directory-and-database-files).

Connection settings may come together from configuration, from --url, --tls-cert-path and --macaroon-path or --rune-path, or from FLUXWARDEN_URL, FLUXWARDEN_TLS_CERT_PATH and FLUXWARDEN_MACAROON_PATH or FLUXWARDEN_RUNE_PATH. An override applies to one selected node. Mixing connection sources or omitting part of a source is refused. Credentials are paths, never literal values. The URL must be HTTPS with an explicit port, without embedded credentials, path, query or fragment. TLS pinning and hostname validation remain enabled.

attempt_deadline defaults to 120s and is bounded to 10m. collect_interval defaults to 15s. escalate_after defaults to 1h; delta_tolerance_msat defaults to "0". alert_dir defaults to the alerts directory beside the database. The full daemon publishes bounded, rate-limited HMAC-signed alert files and reuses outbox.key beside the database across restarts. If alert files exist and that key is missing, startup refuses to replace it. The daemon sweeps expired unsent claims and reconciles outcomes without dispatching approved proposals.

## Policy

Amounts are decimal strings in millisatoshis, processed with integer arithmetic. Durations use an integer followed by s, m, h or d. Canonical policy serialization produces policy_sha256; changing a signed term invalidates existing approvals.

```yaml
# fluxwarden policy
version: 3
network: regtest
fees:
  max_fee_msat: "300000"
  max_fee_ppm: 3000
  exempt_fee_msat: "0"
routing:
  max_cltv_delta: 144
amounts:
  min_channel_reserve_msat: "10000000"
  max_principal_msat: "100000000"
  min_principal_msat: "1000000"
budget:
  msat: "1000000"
  period: 1h
cooldown_after_failure: 1h
cooldown_after_success: 30m
max_in_flight: 1
max_snapshot_age: 30s
proposal_ttl: 5m
approval_max_ttl: 5m
demand:
  mode: targets
  horizon: 1h
  burst_factor: "1.4"
  ewma:
    bucket_seconds: 60
    alpha: "0.25"
    min_samples: 5
targets:
  cln-m:
    channel-2:
      min_inbound_msat: "50000000"
      min_outbound_msat: "10000000"
exclude_channels:
  - channel-4
```

Replace illustrative channel keys with keys returned by the channels command. version must be positive. Fee ppm is between 0 and 1,000,000. Every route satisfies both the absolute cap and ceiling-rounded ppm cap; the ppm check is exempt at or below exempt_fee_msat. CLTV delta is between 1 and 2016, default 144. Route validation includes the final hop and implementation block padding, including one block for Core Lightning. Principal must be positive, with minimum no greater than maximum. max_snapshot_age is positive and at most 60s; a larger value is exit 1. Malformed or unknown fields are exit 2. The policy network must be regtest.

demand.mode accepts targets or ewma. EWMA uses fixed buckets, alpha in (0,1], positive sample minimum and burst factor, and refuses insufficient history. Diagnosis compares latest spendable and receivable with operator targets; stale, future-dated or missing targeted snapshots refuse the whole diagnosis. Core Lightning values retain NODE_REPORTED confidence and the node's estimation caveat. LND derived figures retain DERIVED_ESTIMATE; gossip capacity does not reveal remote balances.

Planning checks active channels, exclusions, cooldowns, budget and unresolved concurrency before sizing a principal. Principal plus the worst-case permitted fee must leave source spendable at or above the greater of the policy reserve and the source's configured outbound target; an absent outbound target contributes zero. Initial candidates are ordered by principal descending, source key and target key. After route validation, final selection maximizes principal minus route fee with fixed weight_cost = 1; ties use lower fee, source key and target key. At claim time the budget includes actual fees in the window and worst-case held fees of unresolved attempts. UNKNOWN remains HELD. A failed payment needs a new proposal and approval.

## Commands and options

Top-level `fluxwarden --help` and `fluxwarden --version` need no configuration and exit 0. --json requests one schema-1 document. Missing or unreadable configuration is exit 2 for configured non-execution commands. Invalid arguments or environment settings remain exit 2. Command-specific help is not a separate interface.

For `actions execute`, after valid argument and environment checks, missing, unreadable or malformed required configuration yields `SAFETY_REFUSAL` (exit 5) before credential or node access. An absent selected node, approval public key or execution credential also yields exit 5 before node contact. Configured non-regtest networks, including unknown network labels, yield the network-lock safety refusal.

| Invocation | Behaviour and command-specific options |
| --- | --- |
| `fluxwarden doctor` | Check runtime, database and configured nodes. |
| `fluxwarden nodes list` | Read stored node rows without contacting nodes. |
| `fluxwarden nodes inspect <name> --capabilities` | Handshake and report capabilities. |
| `fluxwarden channels --node <name> --sort inbound-deficit` | Collect channel snapshots and show liquidity; sort also accepts outbound or capacity. |
| `fluxwarden liquidity diagnose --node <name> --horizon 1h` | Compare snapshots and targets. |
| `fluxwarden liquidity plan --node <name> --policy policy.yaml --refresh` | Refresh snapshots and store proposals; --horizon overrides the demand horizon. |
| `fluxwarden liquidity explain <proposal-id>` | Show stored terms, route, digests and approvals. |
| `fluxwarden liquidity approve <proposal-id> --key operator.key --max-fee-msat 300000 --max-cltv-delta 144 --expires-in 5m` | Sign equal or stricter caps and expiry. |
| `fluxwarden actions execute <proposal-id> --require-regtest` | Verify approval, claim, preflight and send one attempt; the regtest flag is required. |
| `fluxwarden actions status <execution-id> --watch` | Read execution state and events; optionally follow changes. |
| `fluxwarden ledger verify` | Check journals and execution accounting. |
| `fluxwarden reconcile --node <name> --since 1h --until 2026-10-13T12:00:00Z` | Resolve stored hashes and compare accounting in the time window. |
| `fluxwarden evidence export --run-id <run-id> --out bundle` | Export an immutable recorded run to a new directory. |
| `fluxwarden keys generate --out operator.key` | Create an owner-only Ed25519 key and print public_key and key_id; needs no configuration. |
| `fluxwarden daemon` | Collect, plan and reconcile without executing; --collect selects collection alone. |
| `fluxwarden lab up --seed 42` | Start the disposable regtest lab from a source checkout. |
| `fluxwarden lab down` | Stop the lab. |
| `fluxwarden lab workload --type checkout --count 10 --seed 42` | Run a deterministic regtest workload. |
| `fluxwarden lab chaos --all --seed 42` | Run regtest fault scenarios. |

Configured commands accept --config and --json. Connection flags are --url, --tls-cert-path, --macaroon-path and --rune-path. The lab rows describe the source-checkout interface: FLUXWARDEN_LAB_PLAN must name an absolute owner declaration. Checkout alternates fixed 10000000-msat invoices; --seed labels reproducibility. Chaos supports --case T-05, and --all selects that supported case; it requires a separate approved, unsubmitted CLN-M proposal. Live demonstration observations remain pending. Lab assets do not ship in npm. Unavailable capabilities are refused without approximation.

## Output and exit codes

The JSON envelope is `{schema:1, command, ok, warnings, result, error}`. Command names omit operands. A refusal has ok false, result null and an error with code, step and message. Amounts use decimal strings. Credentials appear as redacted fingerprints, never raw values.

| Code | Label | Meaning |
| --- | --- | --- |
| **0** | `SUCCESS` | Completed, including NO_ACTION. |
| **1** | `POLICY_VIOLATION` | Well-formed policy violates a safety bound. |
| **2** | `INVALID_INPUT` | Invalid arguments or malformed or unreadable input. |
| **3** | `CAPABILITY_UNSUPPORTED` | Required node capability is unavailable. |
| **4** | `NODE_UNREACHABLE` | Connection, TLS or node transport failure. |
| **5** | `SAFETY_REFUSAL` | Identity, approval, freshness, lease or other safety refusal. |
| **6** | `INTERRUPTED` | Interrupted before dispatch or forced termination. |
| **7** | `OUTCOME_UNKNOWN` | Attempt unresolved; do not retry payment. |
| **8** | `INVARIANT_BREACH` | Verification or internal invariant failed. |
| **9** | `RECONCILIATION_ALERT` | Accounting or channel deltas differ. |

Output schemas: [doctor](../schemas/output/doctor.schema.json), [node list](../schemas/output/nodes-list.schema.json), [inspection](../schemas/output/nodes-inspect.schema.json), [channels](../schemas/output/channels.schema.json), [diagnosis](../schemas/output/liquidity-diagnose.json), [plan](../schemas/output/liquidity-plan.json), [explanation](../schemas/output/liquidity-explain.json), [approval](../schemas/output/liquidity-approve.json), [execution](../schemas/output/actions-execute.json), [status](../schemas/output/actions-status.json), [ledger verification](../schemas/output/ledger-verify.json), [reconciliation](../schemas/output/reconcile.json), [evidence export](../schemas/output/evidence-export.json).

## Approval, execution and recovery

An Ed25519 approval signs the exact proposal and policy digests, approved fee and CLTV caps, expiry, nonce and key_id. key_id is the leading 16 bytes of SHA-256 of the raw public key. Tokens are at most 4 KiB. Nonces authorize one claim. Removing a key invalidates its unclaimed approvals.

Execution progresses through CLAIMED, PREFLIGHT, SUBMITTING, IN_FLIGHT and either VERIFIED_SUCCESS, VERIFIED_FAILURE or UNKNOWN. Database-clock leases carry fence_epoch. Fenced mutations increment the epoch; a lost lease stops further work. Preflight checks identity, regtest, capability, snapshot freshness, budget, route, fee, CLTV, reserves and receiver capacity. Paths use distinct channel IDs and distinct endpoint peers; MPP and AMP are refused. After SUBMITTING an intent is never sent again.

Success requires a preimage matching the persisted payment hash. A failure field cannot override that evidence. A failed payer observation with an HTLC in flight remains unresolved. Receiver invoice cancellation or deletion is required before declaring a failed unpaid attempt. NOT_FOUND is a lookup result, not proof of failure: cancel the unpaid invoice, read the payer again and wait at least the 120s submission window. A timeout does not prove terminal failure.

Journal posting shares the state-transition transaction. Send moves principal plus route fee into clearing:inflight. Success moves principal to the receiver and actual fees to expense:routing_fees; differences use recon:difference. Failure reverses a send journal. Debits equal credits in exact msat arithmetic; duplicate events post once. An invariant error rolls back the entire transition. Correct history through reversing entries, never by editing old journals.

The full daemon automatically sweeps expired CLAIMED/PREFLIGHT leases and cancels expired approvals before dispatch. It bootstraps persistent HMAC-signed alerts and reconciles by stored hash. Follow [stuck lease recovery](runbooks/stuck-lease.md) without editing execution rows.

## Evidence and release validation

Evidence export writes manifest.json, topology-before.json, topology-after.json, proposals.json, execution-trace.ndjson, ledger-audit.json, reconciliation.json, chaos-results.json and checksums.sha256. Repeated exports of the same recorded run are deterministic. Credentials, payment secrets and preimages are removed. The manifest records the package version, build-time git commit, observed node versions and SHA-256 fingerprints of the loaded credential and certificate bytes. Missing build provenance is marked unavailable. The unavailable_evidence map explains why container image digests, simulation seeds and chaos scenario ids are absent from ordinary reconciliation runs; the node RPC does not provide container provenance.

The npm allow-list contains compiled dist files, package.json, README.md, LICENSE, SECURITY.md and CHANGELOG.md. Tests, lab state, recordings and evidence artifacts do not ship. Packing begins with a clean rebuild; validation scans the decompressed tar stream and offline installed files against registered sentinels, then checks the installed command. Automation compares tag and package version and publishes the same validated tarball. Windows and Linux checks are defined in CI; hosted runs and publication have not been performed for this preparation build.
