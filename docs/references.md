# References

The implementation targets LND 0.21.4-beta and Core Lightning 26.06.9. Use the pinned source and schema for protocol expectations rather than an unversioned example. Links below identify primary sources used for transport, routing, payment outcome and runtime behaviour.

- LND Lightning RPC definitions, including channels, payment records, route fields and invoice state: https://github.com/lightningnetwork/lnd/blob/v0.21.4-beta/lnrpc/lightning.proto
- LND router RPC definitions, including SendToRouteV2 and tracking: https://github.com/lightningnetwork/lnd/blob/v0.21.4-beta/lnrpc/routerrpc/router.proto
- Core Lightning 26.06.9 source and RPC schemas: https://github.com/ElementsProject/lightning/tree/v26.06.9/doc/schemas
- Core Lightning HTLC send height and outgoing CLTV handling: https://github.com/ElementsProject/lightning/blob/v26.06.9/lightningd/pay.c
- Core Lightning route finding and explicit single-part constraints: https://docs.corelightning.org/reference/getroutes
- Core Lightning rune restrictions and alternative restriction semantics: https://docs.corelightning.org/reference/createrune
- Node.js SQLite statement integer handling and transactions: https://nodejs.org/docs/latest-v24.x/api/sqlite.html
- Node.js cryptography and Ed25519 signing: https://nodejs.org/docs/latest-v24.x/api/crypto.html
- SQLite transactions and lock acquisition: https://www.sqlite.org/lang_transaction.html
- npm package files allow-list and implicit included files: https://docs.npmjs.com/cli/v11/configuring-npm/package-json
- Toxiproxy 2.12.0 implemented fault injections: https://github.com/Shopify/toxiproxy/tree/v2.12.0

The [failure catalogue](references/failure-catalogue.md) records upstream edge cases and their operational consequences. A source link establishes the reported mechanism, not a claim that every hosted validation has run.

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
