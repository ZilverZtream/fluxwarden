# Unknown outcome recovery

Exit 7 means an attempt is unresolved. Do not retry payment, regenerate its hash or create a replacement proposal. UNKNOWN describes FluxWarden's knowledge; NOT_FOUND is a node lookup result and does not establish failure. Record the execution ID, payment hash, submitted time and channels.

```sh
fluxwarden actions status <execution-id>
fluxwarden reconcile --since 1h
```

Reconciliation reads payer records and the receiver invoice. A preimage matching the persisted payment hash establishes VERIFIED_SUCCESS despite failure fields. A definite payer failure requires no live HTLC and cancellation or deletion of the unpaid receiver invoice before VERIFIED_FAILURE. A failed observation with a live HTLC remains unresolved.

For NOT_FOUND, cancel the unpaid invoice, read the payer again and retain uncertainty until the 120-second submission window has elapsed. An already-paid invoice returns to success verification. Node unavailability preserves the attempt and HELD reservation. Restore the pinned connection and reconcile again; never infer a terminal state from timeout. Preserve the run ID and export evidence.
