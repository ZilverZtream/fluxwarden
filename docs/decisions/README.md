# Architecture decision records

The following design choices define the product's operating model. They explain why the CLI requires explicit approval and why uncertainty is preserved.

## Built-in runtime and separate adapters

The package has no runtime dependencies. Node.js provides HTTPS, cryptography and SQLite; node-specific protocols remain behind separate adapters. Pure monetary and route rules use integer arithmetic without network or SQL access. This limits the runtime supply chain while requiring explicit bounded protocol readers.

## Signed intent before action

Planning and execution have separate authority. An Ed25519 approval binds the precise proposal, policy digest, fee and CLTV ceilings, expiry and nonce. A policy change invalidates old approvals. The daemon never signs or executes proposals, so observation cannot become an unattended payment loop.

## Preserve uncertain outcomes

Each intent has one stored hash and one attempt. A disconnect after dispatch cannot prove that the node did not pay. The executor preserves UNKNOWN and HELD reservations; reconciliation obtains payer and receiver evidence. This can stop subsequent work while a node is unavailable, but prevents duplicate payment.

## Fenced state and exact accounting

Workers claim with database-clock leases and increment fence_epoch on mutation. A late worker loses authority when its conditional write fails. State, events and journals share transactions. Append-only journals balance in integer millisatoshis; correction means a reversing event, never rewriting history.

## Regtest execution

Both configured and observed networks must equal regtest for execution. There is no override. This release does not authorize live-network fund movement. For operational consequences, see [the specification](../spec.md) and [recovery runbooks](../runbooks/README.md).
