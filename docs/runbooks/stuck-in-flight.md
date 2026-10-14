# Stuck in-flight attempt

IN_FLIGHT or UNKNOWN may persist while the node reports pending HTLCs or inconsistent evidence. The reservation remains HELD. Do not declare failure by assumption or dispatch a replacement payment. Record the payment hash, inspect payer records and receiver invoice, and check node synchronization and remaining HTLCs.

```sh
fluxwarden actions status <execution-id>
fluxwarden reconcile --since 1h
```

The recovery component uses the configured escalate_after threshold (default 1h); reconciliation exits 7 while unresolved. The full daemon publishes signed stuck-in-flight alerts in alert_dir, once per condition and subject to the alert rate limit. Monitor unresolved status, alert files and exit 7. Preserve outbox.key beside the database so existing alert files remain verifiable. Do not remove a reservation to regain budget headroom. Preserve evidence and address the node condition before reconciling again.
