# Authenticated release evidence runbook

Publication requires the complete successful CI run for the exact tagged source,
the original final compressed npm tarball, and the authenticated retained evidence
artifact. Ordinary platform validation does not establish publication readiness.

The CI run must retain `fluxwarden-final-package` containing only
`fluxwarden-<version>.tgz` and `fluxwarden-release-evidence` containing
`release-evidence.json` and every report, receipt, owner declaration and observed
evidence member it references. Every report must reproduce the independently
collected source cases exactly once across each OS/runtime suite union. Required
live rows are T-01, T-03, T-05, T-06, T-07, T-16, T-18 and T-25. Missing, skipped,
partial, substituted, failed or unbound evidence refuses publication.

`release-candidate.mjs` obtains the original package through the fixed official
GitHub API and verifies its artifact ownership, digest and compressed bytes. The
release workflow scans and installs that package, then invokes:

```
node scripts/release-gate.mjs --source "$GITHUB_SHA" --tarball PATH --evidence MANIFEST
```

`GITHUB_TOKEN` must permit read access to the canonical repository's workflow
runs, jobs, artifacts and `npm-release` environment. The gate downloads the
evidence ZIP itself, authenticates its official SHA256 and size before parsing,
checks all required successful jobs and steps, and verifies the exact tarball's
compiled source metadata and byte hash. Twelve independent collection jobs collect
the complete eligible product and harness cases on each supported OS/runtime.
The gate authenticates those jobs, artifact digests, source, final package hash,
runner platform and actual runtime before comparing each target's report union.
Live inventory comes from independent dynamic source collection on the pinned
Linux runtime. The verifier does not publish.

The release job then retains `<tarball>.publication-evidence.json` with the final
SHA256 and authenticated run, attempt and artifact identifiers. No pack operation
may occur between the successful gate and publication.

The `npm-release` environment must actually exist with the sole required reviewer
User `197366966` (ZilverZtream), admin bypass disabled, and the sole custom tag
deployment policy `v1.*`. The verifier obtains the complete policy list through
the official paginated API; a protected-branches boolean alone is insufficient.
The single owner may approve a run they triggered, through the explicit environment
approval button. The read-only CI publisher preflight declares no deployment
environment; actual `release.yml` deployment retains `npm-release` approval.
npm trusted publishing must separately be
verified for the canonical repository, `release.yml`, package `fluxwarden` and
that environment. A YAML environment name or OIDC permission alone establishes
neither fact. As of the October 26 external preflight, `npm-release` was absent
and npm trusted-publisher configuration had not been verified. These conditions
block publication; synthetic verifier controls and ordinary CI cannot clear them.

The dispatch-only live jobs call `release-live.mjs prepare`, run the complete
required-live selection with JSON reports and no-pending verification, and call
`down` on every outcome. File setup starts and stops the primary for ordinary
live files. It keeps the primary down for both independent two-owner lifecycle
cohorts; fault references additionally start their second declared owner.
Preparation creates new private disjoint owner
roots, distinct project identities and port declarations. Startup uses the normal
pinned lab lifecycle and derives adapter and oracle declarations from its actual
manifest. It does not adopt existing resources. Cleanup requires this invocation's
source-bound startup receipt. No observation or passing test result is generated
by preparation.

These default inputs do not replace the independent pinned upstream checkout,
credential source manifests, complete measured validation observations, planner
captures, historical-owner chaos reference plan, or retained demo handoff required
by their respective live references. They must be produced from actual current
execution by the operational validation profile. Until then those cases fail;
the live selection and release verifier never remove them from the required union.
The bounded report producer independently rechecks the complete original capture,
copies the original report bytes, preserves a nonzero captured exit on failure,
binds source/artifact/job identity and scans the upload before releasing it. Failed
test outcomes remain retained failure evidence. They cannot enter a successful
aggregate. Complete original captured evidence remains scanned even when a test
fails; raw runtime directories and credential sources are never uploaded.

Publisher verification uses the official read-only npm registry
[`GET /-/package/fluxwarden/trust`](https://api-docs.npmjs.com/) endpoint with
`NPM_TRUST_READ_TOKEN`. Its authenticated configuration must name the exact
repository, `release.yml`, `npm-release` and direct-publish permission. Missing
authentication, package configuration, permissions or environment protection
fails closed. This preflight performs no npm token exchange, publication or tag
operation. Restoring registry authentication remains an external prerequisite.
