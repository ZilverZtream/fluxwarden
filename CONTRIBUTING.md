# Contributing to FluxWarden

Thank you for helping. FluxWarden moves funds and reads node credentials, so changes are held to a strict standard: every behaviour is specified, every fix is tested, and no real credential or real funds are ever involved in development.

Before you start on a larger change, open an issue to discuss it. The [specification](docs/spec.md) is the contract for every command; a change in behaviour starts with a change to the specification.

## Prerequisites

- **Node.js** in one of the ranges in `package.json` `engines`: 22.23.2 or later on the 22 line, 24.18.1 or later on the 24 line, or 26.5.1 or later.
- **Git.**
- **Linux or Windows.** Both are tested in CI.

## Setup

```sh
git clone https://github.com/ZilverZtream/fluxwarden.git
cd fluxwarden
npm ci
npm run build
```

Run the CLI you built with `node dist/cli/bin.js --help`.

## Tests

| Command | What it runs |
| --- | --- |
| `npm test` | The product tests (builds first) |
| `npm run test:harness` | Tests of the repository configuration, documentation and test tooling |
| `npm run test:related -- <files>` | The tests related to the files you changed |
| `npm run lint` | ESLint |
| `npm run build` | The strict TypeScript build into `dist/` |

`npm run test:lab` runs Docker-free lab tests and selects live reference tests when FLUXWARDEN_LAB_PLAN supplies the required disposable lab plan. `npm run test:chaos` owns fault scenarios and live chaos references; selected live cases require their lab inputs and fail closed without them. Neither belongs in ordinary product validation. `test:full` currently refuses with exit 1. `lab:up`, `lab:down` and `fixtures:record` use the disposable lab tooling and require their documented inputs. Run lab commands from the built source checkout with `node dist/cli/bin.js lab <command>`; lab drivers are absent from the npm tarball.

Use a fresh private scratch directory beneath a trusted owned parent for FLUXWARDEN_TEST_TMP, FLUXWARDEN_SENTINEL_DIR and FLUXWARDEN_EVIDENCE_DIR. Tests create private directories and refuse unsafe existing objects. Never alter permissions on another user's state to make a test pass.

`npm pack` cleans and rebuilds dist. `npm run release:smoke -- <tarball>` verifies the package allow-list, scans the decompressed tarball and offline installed package against registered test sentinels, and runs installed commands. CI defines Windows and Linux checks; a configured job is not evidence that a hosted run passed.

Pull requests need `npm run lint`, `npm run build`, `npm test` and `npm run test:harness` to pass, with no skipped tests.

## Rules for changes

- **Test first.** Every fix comes with a test that fails on the code before the fix and passes after it. Every new behaviour comes with tests for its specification, including the failure paths.
- **Never weaken a test to make code pass.** Do not delete, skip, loosen or retitle a test because the code fails it, and do not raise a timeout or limit to hide a slow or hanging test. Never use `.skip`, `.only` or `.todo`. If you believe a test is wrong, explain why in the pull request and change it in its own commit.
- **Keep the specification and the code in step.** A change in behaviour updates the specification, the `--help` text and the README together.
- **No runtime dependencies.** FluxWarden uses Node.js built-ins only. Development dependencies are pinned to exact versions; a new one needs a stated reason.

## Regtest and credential safety

- Develop and test on regtest only. Never run development code against a node that holds real funds.
- Never put a real credential in an issue, pull request, commit, test, fixture, log or screenshot: no macaroon, rune, TLS key, preimage or seed, in any encoding. Never paste one into an AI assistant or any other third-party service.
- Tests use synthetic values and throwaway credentials from a disposable regtest node only. Refer to credentials by their fingerprint.
- A real credential that was ever exposed is compromised. Revoke it on the node; deleting the text is not enough.

## Commits and pull requests

- Write commit messages that describe the resulting behaviour, not the steps you took. Use the body to explain why.
- Keep each commit to one logical change, with its tests.
- Keep commit messages to the change itself: no tool-generated trailers, notices or AI attribution.

## Security reports

Do not report a vulnerability in a public issue or pull request. Use GitHub's private vulnerability reporting as described in [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
