# FluxWarden security model

FluxWarden protects approval intent, payment outcomes, credential handling and accounting integrity. It assumes the host and the configured node have not been compromised. A stolen payment credential can be used outside FluxWarden, so least privilege and prompt revocation remain essential. Execution is restricted to regtest. For reporting a vulnerability, see [SECURITY.md](../SECURITY.md).

## Payment authority and safety

Planning produces proposals without payment authority. The operator signs the exact proposal and policy digests, expiry and capped fee and CLTV terms with an Ed25519 key. The executor verifies the stored signature, active policy, configured public key and unused nonce before claiming an intent. The daemon stores proposals and reconciles outcomes; it does not execute proposals.

Execution pins node identity and network, rechecks fresh snapshots and validates one single-path route under absolute fee, ceiling-rounded ppm, CLTV, principal and reserve limits. Losing a fenced lease stops work. An intent that reached SUBMITTING cannot be sent again. UNKNOWN retains its reservation and is resolved through payer and receiver evidence under the persisted hash; a timeout or missing record does not establish failure. Preimages are credentials: neither the ledger nor an evidence bundle may reveal them.

Journal and status changes share a transaction, debits equal credits, and append-only records reject modification. Replays cannot duplicate journal events or consume an approval twice. Corrections use reversing journals.

## Private files and environment

State directories are owner-only and new files use mode 0600 on POSIX or protected owner-only DACLs on Windows. Existing owners, modes, DACLs, link counts and trusted ancestry are verified. An existing unsafe object is refused without permission changes. Ancestors must prevent foreign replacement of the path. The operator approval key is read only by the signing command; node credentials and TLS trust anchors are read by path. TLS hostname verification and certificate pinning have no insecure override.

The CLI refuses non-empty NODE_OPTIONS and network debugging through NODE_DEBUG. Arguments that resemble credential values are refused without echoing them. See [configuration and bounds](spec.md#configuration).

## Credential handling

Macaroons, runes, TLS keys and preimages are held in a `Secret` value. A `Secret` has no string or JSON form other than a fixed marker, `[redacted fp:<16 hex>]`, where the hex digits are the start of the SHA-256 of the credential. Its bytes are read through a single internal function. Only the node adapters (`src/node-lnd/`, `src/node-cln/`) and the approval signer (`src/approval/sign.ts`) may import that function.

## Output redaction

Everything FluxWarden prints goes through one output module. Before text is written, it replaces every registered credential with its marker. The output module recognises a credential:

- in raw form, in hex (either case, also colon-separated), and in base64 or base64url with or without padding;
- for a PEM key, also through its DER body in each of those encodings;
- percent-encoded (including form encoding), or inside a JSON string with escaped line breaks or slashes;
- with whitespace or line breaks anywhere in it (indentation, CRLF, any wrap column, MIME line length);
- when it is split across two writes to the same stream.

Bytes already written cannot be taken back, so only the rest of a split credential is replaced. Text after a marker is written unchanged.

Payment requests (`lnbc`, `lnbcrt`, `lntb`, `lntbs`, `lnsb`) are cut to their prefix plus `[redacted]`. Preimage fields are redacted by name. Control characters, bidirectional and invisible format characters become printable escapes. Binary values in JSON output are written as `[redacted]`, never as byte arrays.

Redaction protects against mistakes. It does not replace keeping credentials out of output. A value that was transformed in some other way, for example encrypted, compressed or re-encoded as decimal byte values, is not recognised.

## Static checks and their limits

The repository's lint rules catch accidental misuse:

- **Credential access.** Code outside the allowed modules may not read credential bytes, whether directly, through an alias, a re-export, or a module or member name built from constants. An allowed module may not export the reading function in any form. A function in it that returns the bytes it read may only be called inside that file. With type information, every value an allowed module exports is checked by its type, under any name or re-export. A value whose type can carry text or bytes must be listed in the lint configuration with a reason.
- **Module boundaries.** Network, SQL and child-process builtins are limited to their modules. This covers static and dynamic `import`, `require`, and `process.getBuiltinModule(...)` with a fixed name.
- **Code evaluation.** `eval`, `Function` and `new Function`, `node:vm`, workers that run source text, `data:` modules and Node's internal `_http_*` and `_tls_*` modules are rejected.

These rules do not sandbox hostile code in the repository. They do not follow:

- calls through reflection, such as `.call`, `.bind`, `Reflect.apply`, or an alias of the `Function` constructor;
- credential bytes passed through local variables, generators, text decoders or other conversions before they are returned;
- modules re-exported through a dynamic `import()`.

Those paths are covered instead by the `Secret` design (no string forms), by code review, and by the leak check. The leak check scans every output, temporary and evidence file of the test runs for known test credentials in any of the encodings above.
