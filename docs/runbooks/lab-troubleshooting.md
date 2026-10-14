# Troubleshoot the regtest lab

The lab interface requires a source checkout, Docker and the pinned disposable regtest services. CLI lab dispatch is not yet integrated into this preparation build and the commands below currently refuse with exit 2. Lab assets are absent from the npm tarball. Preserve evidence and confirm configured and observed networks are regtest. Never substitute a live endpoint or real credential.

```sh
fluxwarden lab up --seed 42
fluxwarden lab down
```

Inspect labs/.runtime/lab.json for assigned ports and credential paths. The runtime directory contains credential material and must not be uploaded as evidence. Pass credentials by path and retain owner-only permissions. Exit 2 means invalid arguments, configuration or lab input; exit 4 means node or TLS unavailability; exit 5 means a safety refusal.

Check Docker health, node synchronization, channel activity and both directions of graph fee policy. An active channel alone is insufficient readiness. Keep the topology and seed fixed for comparisons. Unsupported fault injection fails without approximation. Remove toxics and re-enable the proxy before measuring a baseline. Export redacted evidence and leak-check it before sharing; never copy node data directories or credentials. Stop the disposable lab after gathering evidence.
