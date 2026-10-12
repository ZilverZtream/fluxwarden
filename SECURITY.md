# Security policy

FluxWarden moves funds between Lightning channels and reads node credentials (LND macaroons, Core Lightning runes). Security reports are welcome and are handled with priority.

## Supported versions

FluxWarden has not had a release yet. Until 1.0.0, only the latest commit on `main` is supported.

## Report a vulnerability

Report vulnerabilities privately through GitHub security advisories: open the [Security tab of ZilverZtream/fluxwarden](https://github.com/ZilverZtream/fluxwarden/security) and choose **Report a vulnerability**, or go to <https://github.com/ZilverZtream/fluxwarden/security/advisories/new>. Do not open a public issue, pull request or discussion for a vulnerability.

Please include:

- the FluxWarden version (`fluxwarden --version`), Node.js version and operating system;
- the command and flags used;
- what you observed and what you expected;
- a reproduction, preferably against a disposable regtest node.

Do not include a real credential, preimage or seed in any encoding: a fingerprint printed by FluxWarden, a redacted excerpt or a regtest reproduction is enough. If a real credential was exposed while you investigated, treat it as compromised and revoke it on your node.

## What to expect

- An acknowledgement of your report, normally within 7 days.
- An assessment of severity and affected versions, shared with you in the advisory.
- A fix, followed by a published GitHub security advisory. We will agree a disclosure date with you and credit you in the advisory unless you prefer otherwise.
