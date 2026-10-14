# Runbook: roll out a policy

Stop unattended planning while preparing a change and record active attempts and reservations. Keep the previous file and policy_sha256. Historical policy_versions and approvals remain append-only. Never rewrite stored terms.

Validate amounts, regtest network and fee, principal and CLTV bounds. max_snapshot_age is positive and at most 60 seconds. Well-formed safety violations are exit 1; malformed or unknown fields are exit 2. Changed canonical content changes policy_sha256 even when a version number is reused.

```sh
fluxwarden liquidity plan --policy policy.yaml --refresh
fluxwarden liquidity explain <proposal-id>
fluxwarden liquidity approve <proposal-id> --key operator.key
```

Re-plan and re-approve after any policy digest change. Refresh snapshots, inspect the proposal and approve equal or stricter caps and expiry. Old approvals cannot authorize the new policy. Submitted attempts retain their terms and are reconciled by hash; a rollout does not release uncertainty or reservations by assumption.
