# Regtest lab runbook

How to bring up the disposable regtest lab, run its live references and troubleshoot a run.
Regtest only: the lab never touches mainnet, testnet or signet, and holds no real credentials.

## Bring-up and teardown

1. Write an owner declaration (JSON) with `version`, `id`, `project` (`fluxwarden-lab-<name>`),
   four separate owner-only directories (`runtimeRoot`, `tmpRoot`, `sentinelRoot`, `evidenceRoot`),
   three loopback `ports` (`lndRest`, `clnRest`, `toxiproxy`) and `resources`. Add a
   `credentialPolicy` (`maxPrincipalMsat`, `callsPerMinute`, `lndRootKeyIds`) to have the lab bake
   read and execute macaroons and runes.
2. `npm run lab:up -- --owner <absolute path>`; `<runtimeRoot>/lab.json` then lists ports, public
   keys, copied certificates and credential paths with fingerprints.
3. Always finish with `npm run lab:down -- --owner <absolute path>`, also after a failed run, and
   check that `docker ps -a` and `docker volume ls` show nothing of the project.

## CLN rune permissions

New disposable regtest CLN read and execute runes include `method=listhtlcs` among their allowed
method alternatives, as defined by the [lab credential generator](../../labs/docker/credentials.mjs).
The pinned [CLN HTLC query](https://github.com/ElementsProject/lightning/blob/v26.06.9/doc/schemas/listhtlcs.json)
is read-only. FluxWarden makes one bounded history request with `index=created`, `start=0` and
`limit=500` to identify the actual receiving channel from a paid invoice and its completed incoming
HTLC. Missing permission or incomplete or ambiguous history leaves that attribution unverified;
it does not undo proven settlement.

Keep the existing method allowlists, sendpay principal ceiling and call-rate restriction. This
permission applies to newly provisioned disposable regtest credentials; existing runes are not
broadened automatically. If an older disposable rune lacks it, provision a replacement explicitly
and update its configured file path, retaining the other restrictions and owner-only storage.

## Public demonstration prerequisites

Bootstrap the disposable owner with `npm run lab:up -- --owner <absolute path>` before creating
the demo configuration. Bind that configuration to the merchant public key, certified localhost
endpoint and execute-credential paths in `<runtimeRoot>/lab.json`; use a new database and the
explicit demo policy described in [the transcript](../demo-transcript.md). Then initialize the
database with `node dist/cli/bin.js doctor --config <config> --json`.

Set `FLUXWARDEN_LAB_PLAN` to this owner's declaration and `FLUXWARDEN_DEMO_POLICY` to its
configured disposable policy, then run `scripts/reproduce-demo.sh --config <config> --key <key>
--out <directory>`. Its `lab up` command validates and reports reuse of this ready owned stack;
native pins, resources, identities, regtest synchronization, channel readiness and clean proxies
must pass. The standalone `lab:up` command still refuses an existing project. A refused readiness
check stops the walkthrough. Bootstrap and database initialization are prerequisites to its
approximately seven-minute narration; the script does not create the configuration from a down
lab. On Windows, run the shell wrapper with Git Bash and set `FLUXWARDEN_NODE` to the supported
Windows Node executable.

## Live references

`npm run test:lab` runs the Docker-free lab files. Live files (`test/lab/**/*.live.test.ts`) run
only when `FLUXWARDEN_LAB_PLAN` is set; each needs its own declared inputs (for example
`FLUXWARDEN_LAB_OWNER`, the owner declaration of a running lab) and fails when they are missing.

For the complete owned selection, use a clean built checkout and a private absolute
`FLUXWARDEN_CI_TMP_PARENT`, with private `TEMP`, `TMP`, `FLUXWARDEN_TEST_TMP`,
`FLUXWARDEN_SENTINEL_DIR` and `FLUXWARDEN_EVIDENCE_DIR`. Run
`node scripts/release-live.mjs prepare` and import its JSON environment map into the
calling shell; GitHub Actions receives the same map through `GITHUB_ENV`. Preparation
resolves only the trusted public repositories and full commits in
`labs/fixtures/credential-reference-contract.json`, with bounded read-only Git fetches
and no upstream execution. To use existing source objects, set
`FLUXWARDEN_LAB_SOURCE_CHECKOUTS` to an absolute JSON file containing
`{"macwarden":"<absolute Git root>","lnd":"<absolute Git root>","cln":"<absolute Git root>"}`.
Their origin URLs, pinned commits and source bytes must match the contract.

The prepared static source manifests and declarations survive every owner teardown.
Run `node scripts/release-live.mjs measure` first and import its returned environment
map locally. This completes the separately collected CP010 smoke selection, one real
build and the actual setup/run/down/leak phases before CP006/R6 reads its reports.
Then run `npm run test:lab` or `npm run test:chaos`. Each ordinary live file starts and
cleans its own allocation; the CP006 and CP008 two-owner cohorts begin with the primary
down. Planner captures and chaos inputs are derived from that file's current startup.
Finish with `node scripts/release-live.mjs down`, including after failures.

CP043 requires `FLUXWARDEN_FINAL_TARBALL` pointing to the exact candidate package and
an exact current compiled commit. Its setup runs the existing full demo and retains
the actual T05 observation, native history, execution verification and byte-exact
runtime manifest before cleanup. The artifact assertion consumes the retained
`FLUXWARDEN_DEMO_HANDOFF`. Missing evidence, native boundary conflicts and explicit
GAP observations fail the selection.

## Credential references on Windows

The credential references check POSIX file ownership and modes and refuse to run on Windows.
Run them on a Linux host, in WSL 2, or in a Linux container that reaches the Docker engine:

- WSL 2: install Node.js and the Docker CLI inside the distribution (Docker Desktop's WSL
  integration provides the engine), clone the repository into the Linux file system (not
  `/mnt/c`, whose files have no POSIX modes), run `npm ci --ignore-scripts && npm run build`, then
  start the lab and the references from the WSL shell with Linux paths in every declaration.
- Linux container: mount the repository and `/var/run/docker.sock` into a `node:24` container with
  the Docker CLI installed; keep the owner directories inside the container's file system.

## Troubleshooting

- `lab owner-busy` or `allocation-collision`: another run of the same owner is active or a killed
  run left `labs/.runtime/allocations/<project>.*`; run `lab:down` for that owner first.
- `lab ... timeout`: a readiness wait reached its deadline; inspect the evidence directory and
  `docker compose logs` before tearing down.
