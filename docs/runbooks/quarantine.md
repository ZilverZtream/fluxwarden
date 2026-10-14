# Investigate node quarantine

expected_pubkey and expected_network pin node identity and network. A mismatched handshake records QUARANTINED and raises node-quarantined; work is refused with exit 5. Check endpoint, TLS trust anchor, identity and regtest network before changing configuration. Do not accept another identity merely because an endpoint changed.

```sh
fluxwarden nodes list --json
fluxwarden nodes inspect <node-name> --capabilities
```

The daemon must abort when identity or network verification fails. Record configured and observed identities, fingerprints and refusal code without credentials. Preserve outstanding attempts and their hashes.

There is no command that lifts quarantine. Do not modify node rows through SQL or erase history. Restore the verified connection and obtain a reviewed recovery procedure. A replacement node must not inherit unresolved attempts through a changed expected_pubkey. Maintain HELD reservations until the original node supplies terminal evidence.
