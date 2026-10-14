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
