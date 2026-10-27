# Investigate node quarantine

expected_pubkey and expected_network pin node identity and network. A mismatched handshake records QUARANTINED and raises node-quarantined; work is refused with exit 5. Check endpoint, TLS trust anchor, identity and regtest network before changing configuration. Do not accept another identity merely because an endpoint changed.

```sh
fluxwarden nodes list --json
fluxwarden nodes inspect <node-name> --capabilities
```

The daemon must abort when identity or network verification fails. Record configured and observed identities, fingerprints and refusal code without credentials. Preserve outstanding attempts and their hashes.

Restore the verified original connection, then run explicit recovery:

```sh
fluxwarden nodes recover <node-name> --config fluxwarden.yaml --json
```

Recovery requires a fresh handshake with the stored original implementation, pubkey and regtest network, verified TLS and chain sync. It reconciles the same node's existing hashes and accounting using read-only node observations, without creating an invoice or sending a payment. Reconciliation may cancel or delete its existing unpaid invoice to establish a conclusive failed outcome. Only successful recovery lifts quarantine. A changed probe during recovery, wrong identity, unavailable node, unresolved attempt, integrity failure or accounting alert leaves quarantine in place. Inspect the exit code and retain HELD reservations until the original node supplies terminal evidence. A corrected `nodes inspect` connection alone does not lift quarantine.

A SUBMITTING attempt with a live lease remains unresolved even when reconciliation cannot take it over. Recovery reports exit 7 and keeps quarantine in place; after lease expiry, reconcile the original hash. The final quarantine update also checks for unresolved stored attempts in its transaction, so successful accounting alone cannot grant admission.

Do not modify node rows through SQL or erase history. A replacement node must not inherit unresolved attempts through a changed expected_pubkey. Recovery cannot manufacture an original binding for unverified legacy state; obtain a reviewed procedure based on trusted backups and node evidence.

Changing the configured pubkey or implementation of a stored node is refused at the identity stage with exit 5. The stored identity, channels, executions and reservations stay intact. Use a distinct node name and pubkey for a replacement, or an independent state directory when an implementation change retains the same pubkey. Preserve the original state directory for recovery against the original node.

Older releases could overwrite the stored identity. Upgrading preserves existing rows but leaves their original identity unverified: it does not copy the current configuration into the new durable binding. Probing, dispatch and recovery refuse an unverified binding at the identity stage before using an adapter or changing execution state. Existing attempts and reservations remain intact, including UNKNOWN and terminal history. A node first registered after this migration receives an immutable binding.

The upgrade cannot reconstruct an overwritten identity or prove that the current binding is original. Preserve the database and establish the original binding from trusted backups and node evidence through a reviewed recovery procedure; there is no configuration-only acknowledgement or automatic legacy promotion. Do not infer the identity from the current configuration or manually rewrite history. Independent state directories can register replacement nodes while the original database stays preserved for recovery.
