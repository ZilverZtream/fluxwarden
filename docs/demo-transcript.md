# Disposable regtest demonstration

On 2026-10-14, the public walkthrough completed with exit 0 on a fresh, exclusively owned five-node regtest lab. The interpreted lab/runtime source was `c912ea0395f5aafca2676932eaca56cccb0a91ab`; the compiled controller was built once from its parent `4bb34833fd12b091e47fd28ed5f37e2723a98a42`. The initialized script ran from 01:19:51.094 to 01:22:02.024 UTC, taking 130.930 seconds. The narrated walkthrough has a nominal seven-minute duration; this observed run was shorter. Each named phase retained its 180-second deadline.

The lab used Bitcoin Core 31.1.0, LND 0.21.4-beta and Core Lightning v26.06.9, with the repository's pinned Docker images. Native inspection verified seven healthy owned containers, five regtest identities, the expected graph and aggregate resources within 4 CPU, 4 GiB and 1,024 PIDs. TLS used each node's certified localhost endpoint. Credential policy remained principal `100000000` and 600 calls/minute. The disposable application policy used principal `100000000`, absolute fee `300000`, fee rate `2500` ppm, CLTV `144`, success cooldown `1s` and zero delta tolerance. Its canonical hash was `baaae43179d69c79ee0fe9a16410463ec403eed1aa78f4d740481c6b25184287`.

A fresh lab must first be bootstrapped through the ordinary lab API. Create the configuration from its manifest's merchant identity, certificate and execute-credential paths, then initialize the new database with `doctor`. The shell script validates and reports `reused: true` for that explicitly owned ready stack. It does not construct a configuration from a down lab. The standalone lab bootstrap still refuses an existing owner. These are the actual command forms, with private paths represented by variables:

```bash
npm ci --ignore-scripts
npm run build
npm run lab:up -- --owner "$OWNER"
# Write the private configuration and explicit disposable policy from lab.json.
node dist/cli/bin.js doctor --config "$CONFIG" --json
export FLUXWARDEN_LAB_PLAN="$OWNER"
export FLUXWARDEN_DEMO_POLICY="$POLICY"
export FLUXWARDEN_NODE="$NODE"
scripts/reproduce-demo.sh --config "$CONFIG" --key "$KEY" --out "$BUNDLE"
node dist/cli/bin.js actions status 01M4VZZR0VMBYGN6PDJSQ8NS22 --config "$CONFIG" --json
node dist/cli/bin.js actions status 01M4W00TH9H659HWCQWNXRT18X --config "$CONFIG" --json
node dist/cli/bin.js ledger verify --config "$CONFIG" --json
(cd "$BUNDLE" && sha256sum -c checksums.sha256)
```

The observed host used Windows Node 24.18.1 and Git Bash for the shell wrapper. The operator key remained in its dedicated private input directory. A preliminary run against an existing stack refused with exit 8; strict native readiness subsequently reported a chain timeout at its unchanged bound. That stack's application files and native invoice/payment history were sealed before its authorized disposable resources were removed. Its original approved but unused intent was preserved. Another fresh attempt stopped with exit 2 because the database did not yet exist; `doctor` resolved that prerequisite before any walkthrough payment. All failed observations were retained.

The completed run observed:

| Phase | Actual observation |
| --- | --- |
| Lab | Owned-stack reuse validated at height 113; both merchant channels had capacity `5000000000` msat. |
| Starvation preparation | 37 fresh bounded payments over channels 1 ? 2 reduced channel 2 receivable from `3692166000` to `5000000`; channel 5 stayed `3695709000`. |
| Starved checkout | Ten fresh 10,000,000 msat invoices: five CLN-P successes and five LND-P failures; workload exit 0. Reported LND rejection category was `PAYMENT_FAILED`; no stronger failure cause is asserted. |
| Plan and approval | Fresh proposal `prop_01M4VZZHZFME9HFHDX3C6ESDF4`, operator approval `01M4VZZPQ7MKY6XAR00YS6PS3D`, unchanged policy and caps. |
| Normal execution | Raw ULID `01M4VZZR0VMBYGN6PDJSQ8NS22`, `VERIFIED_SUCCESS`, fee `202101` msat / `2022` ppm, CLTV delta `132`, source delta `-100202101`, target delta `100000000`, `MATCH`, exit 0. |
| Restoration | Reconciliation reported no differences; repeated checkout succeeded 10/10, with channel 2 receivable falling from `105202101` to `55202101`. |
| Chaos preparation | One fresh payment restored channel 2 receivable to `5000000`; channel 5 stayed `3495694000`. |
| Fresh T-05 | New proposal `prop_01M4W00MVZKZN6GWY7W99PE2HK` and approval `01M4W00QQ613H32F5G3KZQDJDQ`; downstream waitsendpay truncation produced `UNKNOWN`, exit 7 and one send. |
| Same-hash reconciliation | Execution `01M4W00TH9H659HWCQWNXRT18X` moved from `UNKNOWN` to `VERIFIED_SUCCESS`, with no differences and no second send. |
| Final verification | Both raw-ULID status commands and ledger verification exited 0. Six journals retained two OPENING entries and one SENT/SETTLED pair per execution; clearing was zero and routing-fee expense was `404202` msat. All five nodes had zero live HTLCs; proxies were enabled, restored and free of toxics. |

Native CLN-M history independently contained exactly one complete send record for each execution hash: normal `8e59997989a0be879ad37b977fe7e6e9cf66422f02a327422fc67df6acf1fd7f` and T-05 `5c07963252205c99f389b3d8ea41f9c859757cc57b602a9d9aa925925e905920`. Each recorded `100000000` msat principal and `100202101` msat sent. Existing application files remained byte-for-byte unchanged; the new stack and its history were retained after verification.

The script exported `manifest.json`, `topology-before.json`, `topology-after.json`, `proposals.json`, `execution-trace.ndjson`, `ledger-audit.json`, `reconciliation.json`, `chaos-results.json` and `checksums.sha256`. Independent SHA-256 recomputation verified all eight payload entries. The complete script stdout hash was `f63dedddfacd7c62efc88b3631194d5427ddac13c42563e86fefba805bb66a58`; `checksums.sha256` hashed to `323c2ee61ddfb0702619c782f15310021597258f773b4b36872326d614b06adb`.

The bundle records the compiled parent commit `4bb34833fd12b091e47fd28ed5f37e2723a98a42`; the tested runtime commit is recorded above. Export selected the final reconciliation run `run_01M4W0115CM16FT390B6M8EB15`, so `chaos-results.json` is empty and the manifest explicitly marks scenario IDs, image digests and simulation seeds unavailable. The actual T-05 observation is retained separately in the owner's `demo-T-05-<payment-hash>.json` and the complete script output. The bundle alone does not supply that scenario record. A complete scan of the new run's artifacts and actual secret sources remains pending; no leak-free claim is made here.
