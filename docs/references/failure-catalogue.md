# Failure catalogue

This catalogue records upstream failure mechanisms relevant to circular payments, recovery, routing and accounting. Issue reports describe observed behaviour and must be checked against the pinned implementation before extending supported versions. IDs remain stable; correction marks an entry superseded or withdrawn without deleting it.

## Payment outcomes

| ID | Reported mechanism | FluxWarden handling | Primary source |
| --- | --- | --- | --- |
| FC-001 | Success can retain a timeout failure reason. | Matching preimage evidence takes precedence. | https://github.com/lightningnetwork/lnd/issues/8884 |
| FC-002 | REST errors use multiple envelope shapes. | Decode and classify strictly; unknown shapes refuse success. | https://github.com/lightningnetwork/lnd/issues/6751 |
| FC-003 | Stream failure can occur after send bytes leave the client. | Preserve UNKNOWN and resolve by the stored hash. | https://github.com/lightningnetwork/lnd/issues/6645 |
| FC-004 | Send stream behaviour depends on consuming updates. | Use unary SendToRouteV2, or consume an explicitly selected alternative stream to its deadline. | https://github.com/lightningnetwork/lnd/issues/5035 |
| FC-005 | Records can remain in flight after attempts resolve. | Resolve by hash and retain the reservation until verified. | https://github.com/lightningnetwork/lnd/issues/9461 |
| FC-006 | Failed payment status can coexist with an in-flight HTLC. | Retain unresolved state until definitive evidence. | https://github.com/lightningnetwork/lnd/issues/8975 |

## Operational failure mechanisms

| Mechanism | Required handling | Primary source |
| --- | --- | --- |
| Long-lived in-flight payment records | Keep HELD reservations and investigate node evidence. | https://github.com/lightningnetwork/lnd/issues/9461 |
| Completed payments retain contradictory failure fields | Matching preimage establishes success. | https://github.com/ElementsProject/lightning/issues/9096 |
| Pending records can lag or change after a failure observation | Do not terminate from a single failed observation. | https://github.com/ElementsProject/lightning/issues/9036 |
| Replayed self-payments do not establish new channel movement | One persisted attempt and hash per intent. | https://github.com/ElementsProject/lightning/issues/9517 |
| Fees differ at ppm rounding boundaries | Ceiling-rounded integer ppm and absolute caps both apply. | https://github.com/C-Otto/rebalance-lnd/issues/202 |
| A last hop has capacity but insufficient directional liquidity | Validate receivable against fresh snapshots. | https://github.com/lightningnetwork/lnd/issues/5201 |
| Route-finding fees can exceed requested ceilings | Validate returned routes before dispatch. | https://github.com/ElementsProject/lightning/issues/7888 |
| A pending fee is credited before a payment eventually fails | Expense posting waits for success; failure reverses clearing. | https://github.com/lnbits/lnbits/issues/4192 |
| Read access to invoice records exposes preimages | Treat invoice credentials as sensitive payment authority. | https://github.com/lightningnetwork/lnd/issues/11196 |

## Maintenance

Add a confirmed mechanism with a stable ID, primary source link, triggering condition, affected component and explicit expected handling. Link it to a regression test that would distinguish the safe outcome from a wrong implementation. Record the source version and whether upstream confirmed or fixed the report. Recheck sources when supporting a new node release. Do not turn an open report into a settled protocol fact without primary-source or disposable regtest evidence. Never include credentials, payment secrets or preimages in examples.
