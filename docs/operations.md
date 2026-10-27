# Operational support and capacity observations

The supported execution contract is explicit operator approval, one validated path and regtest. The daemon collects, plans and reconciles without dispatching approved proposals. Keep the complete financial book, approvals, hashes, events, reservations and retained run evidence. No financial-history pruning procedure is provided.

Use the [backup and restore procedure](runbooks/backup-restore.md) before moving state, and [original-node recovery](runbooks/quarantine.md) for quarantine. Backups require the current supported schema and the original signing key. Older schemas refuse without migration by the backup command; the runbook describes preserving an offline original before the ordinary supported upgrade. Unprovable legacy identity bindings remain unsupported until a reviewed recovery from trusted evidence is available.

For support, record the source/version, Node.js version, platform, command, exit code, stage, execution ID and public payment hash. Use `actions status`, `ledger verify` and sanitized `evidence export` to retain diagnostic evidence. Preserve the original state privately. Backup bundles contain the alert signing key and must stay private; do not attach them, node credentials, approval private keys or preimages to public reports. Report security issues using [SECURITY.md](../SECURITY.md).

## Measured source and experiment

The following single local observations used the bounded [capacity driver](../test/operations/capacity-benchmark.mjs) on Windows (`win32`), Node.js 24.21.0 and a 12th Gen Intel Core i9-12900K. The worktree was clean and rebuilt at the measured source before both profiles.

- Source commit: `1f10aedc48e14c39849d4a9b422daf4b0ff00138`.
- Driver SHA-256: `6eaf36b395e8d6eca04a9edf796c1a4379dc949b4a77ae4034a98980961d8ba6`.
- Compiled-tree SHA-256: `5ae6eee7365cb51acb92a5c64347b05fc6deffacb920d7a7e62d0bdea9671ea5`.

Each phase ran in a separate process. Seeding used real persistence and synthetic regtest history; verification and export used the actual CLI; EWMA used the planner. All eight phase processes exited 0. The driver verified ledger arithmetic and unchanged retained table counts after the read, diagnosis and export phases. It contacted no node and sent no payment.

| Seeded workload | Smoke | Representative |
| --- | ---: | ---: |
| Nodes | 2 | 4 |
| Channels | 16 | 256 |
| Channel snapshots | 64 | 184,320 |
| Proposals | 24 | 1,200 |
| Approvals / executions | 12 / 12 | 600 / 600 |
| Execution events | 72 | 3,600 |
| Journals / ledger lines | 40 / 92 | 1,456 / 3,512 |
| Retained run records / signed alerts | 4 / 4 | 32 / 32 |
| EWMA buckets per channel / passes | 48 / 2 | 8,760 / 10 |

| Profile and phase | Wall seconds | Node CPU seconds | Node peak RSS MiB |
| --- | ---: | ---: | ---: |
| Smoke: seed | 13.141 | 0.671 | 59.14 |
| Smoke: verify | 1.302 | 0.124 | 57.97 |
| Smoke: EWMA | 3.168 | 0.093 | 51.81 |
| Smoke: export | 2.264 | 0.405 | 59.36 |
| Representative: seed | 145.483 | 47.109 | 549.25 |
| Representative: verify | 1.622 | 0.359 | 69.77 |
| Representative: EWMA | 28.591 | 4.952 | 595.54 |
| Representative: export | 1.757 | 0.312 | 70.57 |

CPU is the instrumented Node process's reported user plus system CPU time. Peak RSS is per process, converted from the reported KiB. Windows ACL helper processes are excluded from those CPU/RSS figures; wall time includes waiting for them.

| Retained storage after the phases | Smoke bytes | Representative bytes |
| --- | ---: | ---: |
| SQLite database | 278,528 | 50,036,736 |
| Run-record sidecars | 103,312 | 12,950,656 |
| Entire measured state and generated evidence | 443,511 | 63,435,381 |
| Retained file count | 22 | 78 |

These observations cover synthetic SQLite history, ledger verification, EWMA evaluation and evidence export at the stated source. Live-node throughput, concurrent daemon workloads, other platforms and later artifacts require separate measurements. The profile watchdogs of 120 seconds per smoke phase and 600 seconds per representative phase bound the experiment; they establish no service-level objective or maximum supported capacity. Nothing was pruned to obtain these results.

To reproduce from a source checkout, build the exact source first and provide existing owner-only `FLUXWARDEN_TEST_TMP`, `FLUXWARDEN_EVIDENCE_DIR` and `FLUXWARDEN_SENTINEL_DIR` directories:

```sh
node test/operations/capacity-benchmark.mjs --profile smoke
node test/operations/capacity-benchmark.mjs --profile representative
```

Keep each generated `capacity.json`, phase metrics, outcomes and inventories privately. A measurement of another source or compiled tree is a separate observation.
