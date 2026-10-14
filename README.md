# FluxWarden

Control Lightning liquidity with verifiable evidence.

FluxWarden is a policy-bound liquidity controller for LND and Core Lightning. It builds on ideas from existing tools: bos rebalance, regolancer, LNDg and CLN's rebalance and sling plugins already perform circular rebalances with ppm and absolute fee caps, mostly single-path; FluxWarden adds one normalized channel model across LND and CLN and a per-route CLTV ceiling. boltz-client's recommendations and Loop's suggestswaps already propose actions with dismissal reasons for manual approval; FluxWarden applies the pattern to circular rebalances, binding each approval to a digest of the exact proposal and policy and recording refusal reasons. CLN's bookkeeper already keeps a double-entry history that flags rebalances; FluxWarden keeps its own msat ledger of principal and fees and reconciles it against bookkeeper (CLN) and forwarding/payment history (LND). When a payment's outcome is unknown, FluxWarden looks it up by payment hash and reconciles before acting, rather than retrying. Behaviour under faults is exercised in a regtest lab whose runs produce evidence bundles. FluxWarden does not do swaps, channel purchases or fee setting; see Loop, PeerSwap, Magma, charge-lnd and clboss.

Version 1.0.0 is in release preparation and has not been published. Money-moving actions require regtest. The daemon collects, proposes, sweeps expired preflight leases and reconciles without executing proposals. It publishes HMAC-signed alerts. Evidence records observed node versions, credential and certificate fingerprints, package version and build provenance; unavailable container provenance is explained explicitly. [The specification](docs/spec.md) describes these capabilities.

## Install

Node.js must satisfy `^22.23.2 || ^24.18.1 || >=26.5.1`. FluxWarden has no runtime dependencies. Once the release is published, install it with:

```sh
npm install --global fluxwarden
fluxwarden --version
fluxwarden --help
```

For a locally validated tarball, use `npm install --global --ignore-scripts ./fluxwarden-1.0.0.tgz`. The tarball contains the compiled CLI and package documentation. The source checkout contains the operator documentation and regtest lab assets.

## Configure and operate

Create configuration and policy files using [the complete examples](docs/spec.md#configuration). Put state in a new private directory beneath a trusted owned parent. Pin each node's identity, regtest network and TLS certificate. Credentials are file paths. Generate an operator key and add its printed public_key and key_id under approval_keys; keep the private key on the operator machine.

These commands show argument forms. Replace node names and IDs with values from your regtest configuration and earlier results. Configured commands require fluxwarden.yaml or an explicit --config file.

```sh
fluxwarden keys generate --out operator.key
fluxwarden doctor --config fluxwarden.yaml
fluxwarden nodes list --json
fluxwarden nodes inspect cln-m --capabilities
fluxwarden channels --node cln-m --sort inbound-deficit
fluxwarden liquidity diagnose --node cln-m --horizon 1h
fluxwarden liquidity plan --node cln-m --policy policy.yaml --refresh
fluxwarden liquidity explain <proposal-id>
fluxwarden liquidity approve <proposal-id> --key operator.key --max-fee-msat 300000 --max-cltv-delta 144 --expires-in 5m
fluxwarden actions execute <proposal-id> --require-regtest
fluxwarden actions status <execution-id> --watch
fluxwarden ledger verify
fluxwarden reconcile --node cln-m --since 1h
fluxwarden evidence export --run-id <run-id> --out bundle
fluxwarden daemon
```

--config selects configuration and --json prints one JSON envelope. Top-level --help and --version need no configuration. --collect selects collection alone for the daemon. Connection overrides use --url, --tls-cert-path and --macaroon-path or --rune-path; provide the whole connection from one source and select one node. Credentials are never literal flag values. Reconciliation also accepts --until; --watch follows status until a terminal result or interruption.

The lab interface uses the following source-checkout commands. Set FLUXWARDEN_LAB_PLAN to the absolute owner declaration used for lab setup. Workload alternates fixed checkout payments; --seed is accepted as a reproducibility label. Chaos supports --case T-05; --all selects that supported case. It requires a separate approved, unsubmitted CLN-M proposal. Live demonstration observations remain pending. Lab assets do not ship in the npm package.

```sh
npm ci
npm run build
node dist/cli/bin.js lab up --seed 42
node dist/cli/bin.js lab workload --type checkout --count 10 --seed 42
node dist/cli/bin.js lab chaos --all --seed 42
node dist/cli/bin.js lab down
```

To use the command name with source lab assets, run `npm link` in this built checkout. The linked commands are `fluxwarden lab up`, `fluxwarden lab workload`, `fluxwarden lab chaos` and `fluxwarden lab down`, with the same arguments shown above.

The [demo walkthrough](docs/demo-transcript.md) uses `scripts/reproduce-demo.sh --config <path> --key <path> --out <directory>`. Explicitly select a disposable demo policy with `FLUXWARDEN_DEMO_POLICY`, establish its documented caps and `cooldown_after_success: 1s` before planning, and keep the owner declaration in `FLUXWARDEN_LAB_PLAN`. The script prepares measured channel 2 starvation before both demonstrations and creates and signs a fresh chaos intent with the operator key. Live observations and the verifying evidence bundle remain pending.

Read [the runbooks](docs/runbooks/README.md) before approving and executing a proposal.

## Exit codes

| Code | Label | Meaning |
| --- | --- | --- |
| **0** | `SUCCESS` | Completed, including NO_ACTION. |
| **1** | `POLICY_VIOLATION` | Policy exceeds a safety bound. |
| **2** | `INVALID_INPUT` | Arguments or configuration are invalid or unreadable. |
| **3** | `CAPABILITY_UNSUPPORTED` | Required capability is unavailable. |
| **4** | `NODE_UNREACHABLE` | Node or TLS connection failed. |
| **5** | `SAFETY_REFUSAL` | Approval, identity, freshness or another safety check refused work. |
| **6** | `INTERRUPTED` | Interrupted before dispatch or forcibly stopped. |
| **7** | `OUTCOME_UNKNOWN` | Outcome unresolved; do not retry payment. |
| **8** | `INVARIANT_BREACH` | Verification or internal invariant failed. |
| **9** | `RECONCILIATION_ALERT` | Accounting or channel deltas differ. |

Exit 7 retains the attempt and budget reservation. Use reconciliation and node evidence; never create a replacement payment to guess around uncertainty. Exit 8 or exit 9 requires examination of recorded evidence.

## Documentation and development

Read the [specification](docs/spec.md), [architecture](docs/architecture.md), [security model](docs/security-model.md), [references](docs/references.md), [runbooks](docs/runbooks/README.md) and [design rationale](docs/decisions/README.md). [CONTRIBUTING.md](CONTRIBUTING.md) describes local checks. Report vulnerabilities through [SECURITY.md](SECURITY.md).

Windows and Linux validation is configured in CI. Hosted validation and npm publication remain unrun for this preparation build. Local checks do not imply a published release.

## License

[MIT](LICENSE).
