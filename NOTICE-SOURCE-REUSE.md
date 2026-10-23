# Source reuse notice

Source: macwarden, https://github.com/ZilverZtream/macwarden, commit `25bbfa4`.

License: MIT. LICENSE SHA-256: `a0230b4c00986df0e67e146e974e6b05d6ad4ff52821fdfec540f5f1f33bb714`.

MIT License

Copyright (c) 2026 macwarden contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

| Upstream file | Upstream SHA-256 | Product file | Disposition | Imported SHA-256 | Changes |
|---|---|---|---|---|---|
| `examples/payment-lab/src/lnd/json.ts` | `b9ba482ae6dc5cb878ad1b57f76aeab615ea61cf4b1e6e77823a5760f955db07` | `src/core/json.ts` | adapted | `d6136d83c3af6c0a0a26a0de6d5c31fbdff286d3eb0fc445f23665213613df65` | Canonical integer termination and zero, shared reader import, and CLN msat suffix support. |
| `examples/payment-lab/src/lnd/errors.ts` | `c8835fd77e2dcbe89bfa6ec880a760597c8d78ed8e0339827d7fff7fd0d3f5a7` | `src/core/errors.ts` | adapted | `0db15b8e97357f1a0ae17d213bc32253661e426d600c8fb053d0f73f975f5901` | Source attribution, explicit number formatting for strict lint, TLS, authentication and CLN error classes, and a shared transport failure classifier. Native gRPC NotFound classification requires an absent HTTP status, 200 or 404, preserving ambiguity for transport and authentication failures. |
| `examples/payment-lab/src/util/bolt11.ts` | `5657f1eb2e8fa89d629fc3111131011bcca3b9d12989103ec6d1f2137f296982` | `src/core/bolt11.ts` | adapted | `d8c564c0fce9c65b814fe77bd562164bcc2dd3a6d4e8ddf858e1cf0cbeb2aef4` | Source attribution and Array.from iteration for strict lint. |
| `examples/payment-lab/src/util/encoding.ts` | `7f063151eab11592c113ed947a8fd718ffd40554ecc8c7d25432d142f57239a4` | `src/core/encoding.ts` | copied | `7f063151eab11592c113ed947a8fd718ffd40554ecc8c7d25432d142f57239a4` | none |
| `examples/payment-lab/src/util/money.ts` | `093ea852dc31a668abf7c3afb9d08a47664b63bacdd9e610e8c3ae0c5ce7cf2b` | `src/core/money.ts` | adapted | `2a2948fd324b5dbe2d722afc8b3bfd65eca611583f479c2d0c68184f8725505b` | Branded amounts, canonical parsing, exact fee arithmetic, and source attribution. |
| `scripts/leak-check.mjs` | `521c444539273c084354a34f84b9e0a6d6030b639ebd32885b0f77b0141cddae` | `scripts/leak-check.mjs` | adapted | `0a6d5987e64f9b9563ee95e317984bde9ad69877d62c2f64012fd188b7b1974c` | Generic sentinel scanning, bounded matching, artifact validation, monotonic five-second busy retries, and bounded exact recognizer-state reuse. |
| `scripts/private-scratch.mjs` | `3773b0da7b00d0ba0ef1ea38f2d51fdc3c835a12c74346f6f981186a0bb8919a` | `scripts/private-scratch.mjs` | adapted | `4c0e933364060caaa6f383c5485f8219fd0e905e82593de08680880dced05793` | Source attribution and batched owner-only directory verification. |
| `examples/payment-lab/src/lnd/rest.ts` | `af0b78f1ab56466f1e33681081496b815a0a326f66c93fca053fe4225ec3af76` | `src/node-lnd/rest.ts` | adapted | `4fbe03635e098b2ebca7dad56563bd283f77f66b59ec2a174bf6e8317b3fe54b` | Credential kept in a Secret with redacted peer text, bounded descriptor reads, TLS and request phases, a mandatory stream deadline and stream end outcomes; envelope and line parsing moved to src/node-lnd/stream.ts, and the unary transport mirrored in src/node-cln/rest.ts, both attributed in their headers; an optional callback once a unary request is written. An optional Secret registration callback registers the loaded macaroon for command-scoped output redaction without exposing credential bytes. |
| `examples/payment-lab/src/ledger/accounts.ts` | `ec1f87be54b4ed35233e157977379a22ca632d59abd542d0caf60d5cb88f3409` | `src/ledger/accounts.ts` | adapted | `64384a9d3a7bfb62f310cd9c3a96e393aadc7ce96dc9df33909cd9bda38d5f2f` | Structure and net-debit convention kept; new chart of channel, clearing, equity, expense and reconciliation accounts. |
| `examples/payment-lab/src/ledger/postings.ts` | `2fd954c299d5c2cd4e31e71be051b136f142551d3afb1633c0166b5986a0f91c` | `src/ledger/postings.ts` | adapted | `a934237bfe6cb8f1a27c39248eca2e034d19ffc9a05cc4b9b4073f281f053863` | One builder per event kept; new rebalance send, settle, reversal and opening postings with debit and credit columns. |
| `examples/payment-lab/src/ledger/journal.ts` | `de930797cfb7458e5a95a1e920c991eb7a635ebe3ef56fef22dd27ceebcc9cee` | `src/ledger/post.ts` | adapted | `3de63533a8e97365d02bc607bb0a8cda73e053b703872c80fe82fb12be7578df` | post() validation kept; writes go through a transaction port, error codes added, amounts limited to 1 to 2^63 - 1. |
| `examples/payment-lab/src/ledger/verify.ts` | `85e07ef6792f2165c8f0dfb27c7623300acf19fecbb7f8b3964ee0768250c554` | `src/ledger/verify.ts` | adapted | `5233c6a883fbc5c8ab5646ebe5b63b1ff666b105b10b5c1b38b70a4b2e7e9478` | Steps 1 and 2 only (balanced journals, stored balances), as a pure function over the stored book. |
| `examples/payment-lab/src/outbox/effects.ts` | `474c405c23af2f5f84da8b7c8ad328ce59d5bd65949412f2903579256de47a68` | `src/output/effects.ts` | adapted | `845c8fae39b29baed0b7387b8e54145b7346cec9ffa2f863be441d2b62ace931` | HMAC signing, canonical text, file naming and bounded reading kept; leases and leftover cleanup dropped, regular files only, publication returns exists instead of comparing fields. |
