# Stuck execution lease

Inspect state before starting another worker. CLAIMED and PREFLIGHT precede dispatch; SUBMITTING means payment may already have reached the node. Stop the old worker, retain events and record fence_epoch. Another active claim yields claimed-elsewhere; a failed fenced write yields lease-lost and stops further node calls. Expiry uses the database clock. Do not edit lease times or epochs.

Recovery primitives can reclaim expired CLAIMED/PREFLIGHT with valid approval or move expired approval to CANCELLED. The automatic command sweep for these pre-dispatch leases is not yet wired. Preserve evidence and obtain a reviewed recovery change if blocked; do not force SQL transitions.

An intent at or after SUBMITTING must never be re-sent or re-claimed for execution. Resolve its persisted hash:

```sh
fluxwarden actions status <execution-id>
fluxwarden reconcile --since 1h
```

An unresolved result retains its reservation; another process cannot grant authority to retry.
