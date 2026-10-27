# Back up and restore state

Stop FluxWarden daemons and commands before moving a state directory. Keep the original state until the restored copy has passed reconciliation. A backup uses SQLite's online backup API, so committed WAL pages are included even when another connection still holds the WAL open. Copying the main database file alone is insufficient.

These commands accept the current supported database schema. An older or newer schema is refused without migration by the backup command. Before upgrading an older supported state, stop all writers and preserve an offline private copy of the entire state and alert directories, including any WAL/SHM files, key and run sidecars. Use the matching release and verified original-node configuration for the ordinary `doctor` schema migration, then retry backup. Unverifiable older identity provenance is not repaired by migration. Do not open newer state with an older binary or edit schema/version rows manually.

Use an existing private parent directory and a new bundle name:

```sh
fluxwarden state backup --config original.yaml --out /private/backups/new-bundle --json
```

The bundle contains a consistent database, the original `outbox.key`, every retained `<database>.run_<ULID>.json` record, and the signed alert files. The manifest records schema, stored node pins, payload sizes and SHA-256 hashes. The command verifies the signed alerts under the retained key. An existing destination, link, unsafe permission, missing signing key or changed sidecar refuses the backup. A failed backup can leave an incomplete new bundle; it cannot be restored without a complete valid manifest. Preserve the originals and choose another unused destination after investigating the failure.

Treat the whole bundle as private credential material: `outbox.key` signs alerts. Do not attach it to an issue, print it, or put it in a public evidence export. Retain the configuration, policy, TLS trust anchors, node credential files and operator approval key separately under their existing private procedures. They are not copied into this state bundle. Preserve all financial history; this procedure defines no pruning policy.

Create a restored configuration whose database is inside an absent state directory. Set `alert_dir` to `alerts` inside that same state directory. Keep every restored node's original name, implementation, pubkey and regtest network, and configure its verified TLS connection. Paths to separately retained credentials and policy may change.

```sh
fluxwarden state restore --config restored.yaml --from /private/backups/new-bundle --json
fluxwarden ledger verify --config restored.yaml --json
fluxwarden reconcile --config restored.yaml --json
```

Restore verifies the complete manifest, private payload paths, signed alert archive, SQLite integrity and node pins before creating destination state. It refuses any existing state directory, including an empty directory. Run-record filenames adopt the destination database basename; their bytes and signed alert bytes remain unchanged. The source bundle and original database are retained.

The restored database contains a persistent admission barrier before its configured filename becomes available. Approval and execution refuse with exit 5 across process restarts until one successful full reconciliation covers every restored required node. Use `reconcile` without `--node`, `--since` or `--until`. A selected-node pass, missing configured historical node, quarantine, or reconciliation exit 4, 5, 7, 8 or 9 leaves admission blocked. Restore does not turn an existing approval into permission to resend an uncertain attempt.

For exit 7, keep the original payment hash and HELD reservation. Restore the original node's availability and reconcile again; never create another hash to guess around uncertainty. For quarantine, follow [original-node recovery](quarantine.md). An identity whose original provenance was lost by an older release remains unsupported until a reviewed recovery based on trusted backups and node evidence is available; changing configuration does not establish that provenance.

A restored SUBMITTING attempt can retain its original live lease. Reconciliation leaves that owner's lease intact and reports the attempt as unresolved with exit 7. After the lease expires, reconcile the original hash against the original node. A valid ledger or an empty recovery candidate list cannot clear admission: completion checks stored unresolved attempts inside the admission transaction. Live CLAIMED or PREFLIGHT attempts also prevent completion until normal recovery concludes them.

If restore fails after creating its new private directory, do not start payment work against it or merge it into another state root. Preserve it for diagnosis and retry into another absent state directory from the verified bundle. No operator SQL updates or history deletion are part of recovery.
