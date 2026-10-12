# References

Placeholder for the external facts FluxWarden's design relies on, each with its source, version and check date. References will be added as the implementation uses them.

## Positioning

> FluxWarden is a policy-bound liquidity controller for LND and Core Lightning. It builds on ideas from existing tools: bos rebalance, regolancer, LNDg and CLN's rebalance and sling plugins already perform circular rebalances with ppm and absolute fee caps, mostly single-path; FluxWarden adds one normalized channel model across LND and CLN and a per-route CLTV ceiling. boltz-client's recommendations and Loop's suggestswaps already propose actions with dismissal reasons for manual approval; FluxWarden applies the pattern to circular rebalances, binding each approval to a digest of the exact proposal and policy and recording refusal reasons. CLN's bookkeeper already keeps a double-entry history that flags rebalances; FluxWarden keeps its own msat ledger of principal and fees and reconciles it against bookkeeper (CLN) and forwarding/payment history (LND). When a payment's outcome is unknown, FluxWarden looks it up by payment hash and reconciles before acting, rather than retrying. Behaviour under faults is exercised in a regtest lab whose runs produce evidence bundles. FluxWarden does not do swaps, channel purchases or fee setting; see Loop, PeerSwap, Magma, charge-lnd and clboss.

Source: a survey of related projects on 2026-10-11 (repositories, registries and source at HEAD on that date). The comparison describes what the survey found, not a claim that nothing else exists, and is re-checked against sling and clboss before each release. Projects named above:

| Project | URL |
| --- | --- |
| balanceofsatoshis (`bos rebalance`) | https://github.com/alexbosworth/balanceofsatoshis |
| regolancer | https://github.com/rkfg/regolancer |
| LNDg | https://github.com/cryptosharks131/lndg |
| CLN `rebalance` plugin | https://github.com/lightningd/plugins |
| sling | https://github.com/daywalker90/sling |
| boltz-client | https://github.com/BoltzExchange/boltz-client |
| Loop (`suggestswaps`) | https://github.com/lightninglabs/loop |
| CLN bookkeeper | https://github.com/ElementsProject/lightning |
| PeerSwap | https://github.com/ElementsProject/peerswap |
| charge-lnd | https://github.com/accumulator/charge-lnd |
| clboss | https://github.com/ksedgwic/clboss |
