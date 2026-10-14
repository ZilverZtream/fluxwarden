# Runbook: approve and execute a regtest rebalance

Configure each node's expected public key, regtest network, TLS certificate path and credential path. Add the operator's public approval key under `approval_keys` and keep the private signing key on the operator machine.

```text
fluxwarden liquidity diagnose --node cln-m
fluxwarden liquidity plan --node cln-m --refresh
fluxwarden liquidity explain prop_<ULID>
fluxwarden liquidity approve prop_<ULID> --key operator.key --max-fee-msat 300000 --max-cltv-delta 144
fluxwarden actions execute prop_<ULID> --require-regtest
fluxwarden actions status <execution-id>
fluxwarden ledger verify
fluxwarden reconcile --node cln-m --since 1h
fluxwarden evidence export --run-id run_<ULID> --out ./bundle
```

Add `--json` for a structured result. An approval binds the proposal, policy digest, fee and CLTV caps, expiry and nonce. Execution verifies the stored signature again and sends one payment under a persisted hash. Running execution again after submission cannot send another payment.

Exit 7 means the outcome is unknown: run `fluxwarden reconcile` and do not retry payment. Reconciliation resolves the stored hash from node evidence. Exit 9 means the report contains a ledger or node accounting difference; exit 8 means a verification invariant failed.

The optional configuration `attempt_deadline` is a duration such as `120s`, defaults to 120 seconds, and must be at most 10 minutes. It bounds waiting for a payment answer; reaching the bound preserves an unresolved outcome and its budget reservation.

`fluxwarden daemon` collects snapshots, stores proposals and reconciles pending outcomes until SIGINT or SIGTERM. It leaves approvals for explicit execution. `daemon --collect` runs only the snapshot collector.

Reconciliation stores an immutable run record beside the database. Evidence export uses that recorded input, so repeated exports of the same run produce identical bytes and include SHA-256 checksums for every bundle file.
