# FluxWarden

Control Lightning liquidity with verifiable evidence.

FluxWarden is a policy-bound liquidity controller for LND and Core Lightning. It builds on ideas from existing tools: bos rebalance, regolancer, LNDg and CLN's rebalance and sling plugins already perform circular rebalances with ppm and absolute fee caps, mostly single-path; FluxWarden adds one normalized channel model across LND and CLN and a per-route CLTV ceiling. boltz-client's recommendations and Loop's suggestswaps already propose actions with dismissal reasons for manual approval; FluxWarden applies the pattern to circular rebalances, binding each approval to a digest of the exact proposal and policy and recording refusal reasons. CLN's bookkeeper already keeps a double-entry history that flags rebalances; FluxWarden keeps its own msat ledger of principal and fees and reconciles it against bookkeeper (CLN) and forwarding/payment history (LND). When a payment's outcome is unknown, FluxWarden looks it up by payment hash and reconciles before acting, rather than retrying. Behaviour under faults is exercised in a regtest lab whose runs produce evidence bundles. FluxWarden does not do swaps, channel purchases or fee setting; see Loop, PeerSwap, Magma, charge-lnd and clboss.

## Status

Version 0.0.0 is a repository skeleton. The `fluxwarden` binary answers `--version` and `--help` and has no commands yet. Do not point it at a node that holds real funds; development and testing use regtest only.

## Requirements

- Node.js `^22.23.2 || ^24.18.1 || >=26.5.1`.
- No runtime dependencies: FluxWarden uses Node.js built-ins only.

## Usage

```sh
npm ci
npm run build
node dist/cli/bin.js --help
```

`--json` prints exactly one JSON document on stdout: `{"schema":1,"command":…,"ok":…,"warnings":[…],"result":…,"error":…}`. Exit codes: 0 success, 2 invalid input, 6 interrupted, 8 invariant breach (internal error).

## Documentation

- [Specification](docs/spec.md), [architecture](docs/architecture.md) and [security model](docs/security-model.md)
- [References](docs/references.md): the external facts the design relies on, with their sources
- [Contributing](CONTRIBUTING.md) and [security policy](SECURITY.md)

## License

[MIT](LICENSE)
