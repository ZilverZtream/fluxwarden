# Runbook: approval key rotation and recovery

Generate a fresh key on the operator machine in a new path:

```sh
fluxwarden keys generate --out operator.key
```

The private key is owner-only: 0600 on POSIX or a protected current-owner DACL on Windows. Existing destinations are refused. Add the printed public_key and key_id to approval_keys; never add the private key. key_id is the leading 16 bytes of SHA-256 of the raw public key.

Keep both public entries during a planned overlap until unclaimed proposals are reviewed and re-approved. Revoke suspected compromised keys immediately. Removing a public entry invalidates unclaimed approvals signed by it. An unknown key_id is exit 2; execution with no stored approval that verifies is exit 5.

Inspect proposals and active attempts before resuming. Rotation does not change submitted hashes, free reservations or authorize resending. Reconcile pending outcomes using persisted records and follow your local key custody procedure without pasting private values into reports.
