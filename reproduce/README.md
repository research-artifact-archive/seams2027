# Reproduce a check

Choose the level of evidence you want to check. Use a fresh output directory for each replay and read the linked guide's platform and resource limits.

## Verify downloaded files

From the repository root, with Python 3.9+ and the standard library:

```sh
python3 -I -S -B reproduce/verify.py
```

Expected: `PASS_LAYOUT_AND_FILE_INTEGRITY_ONLY`. The checker verifies the current file roster and hashes, Markdown links, the matching v71-r10 paper/source tree, all 24 scientific ZIPs (17 preserved plus seven additions), 36 evidence rows, 24 archive-root records and 26 exact code-browser copies. Earlier evidence, source rows and archive identities remain pinned; the AE, AF and AG outer adoption records retain their separate scopes. It executes no scientific checker or native solver. [MANIFEST.json](MANIFEST.json) records the current distribution; its hashes describe content and do not independently authenticate the publisher.

## New evidence inspection boundaries

The [compiled cohort](../results/guides/V71_COMPILED_COHORT.md), [Obstacle certificates](../results/guides/V71_OBSTACLE_CERTIFICATES.md), [historical Patrol](../results/guides/V71_HISTORICAL_PATROL.md) and [GUI observations](../results/guides/V71_PUBLIC_KIND_GUI.md) have separate scopes. For those four additions, the saved-data adapters were inspected statically. No relocated scientific replay of those four adapters or native regeneration is claimed. The separately scoped AE-R6 existing-host v1 replay is described below. Do not treat an integrity PASS as a scientific result.

For AD static verification, extract the four AA/AC/Z/AD ZIPs into the same fresh parent with their fixed top directories. The checker verifies AA/AC/Z manifest baselines and the exact AC scientific files. The saved-predicate adapter has only the AC scientific dependency; it remains unexecuted. Existing restoration recipes and source rights remain separately scoped.

The [positive certificates and mode controls](../results/guides/V71_R6_POSITIVE_CERTIFICATES_AND_CONTROLS.md) form a fifth, separately scoped addition. Its static entrypoint is `python3 -I -S -B verify_integrity.py` from the extracted `r6_positive_certificates_and_controls/` directory. It needs no sibling archive for that check. Its prior AC/AD references and byte-identical selected-Kind records retain their own identities.

The new package records two accepted positive source certificates, a separate all-domain ENV-totality/source-binding check, 50 predetermined malformed-input rejections and two ordinary-mode true observations. Forty-eight rejection receipts directly contain an original input hash; two duplicate-key parsing failures retain null input hashes and use the driver/archive chain. `PUBLIC_QUALIFICATION_INPUT_MAP.json` and `TRANSFORMATION_LEDGER.json` distinguish original executed bytes from sanitized derivatives. A later adopted replay of the exact public v1 inputs succeeded on the existing host; `replay/VERIFICATION_ADDENDUM.txt` and `replay/INPUT_BINDINGS.json` identify its receipts, actual source arguments and byte identities. The v2 container was not scientifically replayed. The separate `verify_replay_integrity.py` is also static-only. Optional commands in `FUTURE_REPLAY_COMMANDS.txt` require separately restored exact sources and external RSS supervision for the recorded resource protocol. The results do not establish winning-region maximality, an exclusive internal cause, controller handoff, or closure of the eight earlier UNKNOWNs.

## Recompute saved finite results

| Replay | Guide | What is recomputed |
| --- | --- | --- |
| Vehicle188 whole region | [Whole-region guide](../results/guides/VEHICLE188_WHOLE_REGION_EVIDENCE.md) | 33,792 typed-state rows, helper slices, predecessor certificates, initialization fibers, and agreement of two cores |
| Seven positive/control inputs | [Fixed-seven guide](../results/guides/FIXED_SEVEN_NATIVE_EVIDENCE.md) | Complete saved-data audits and typed-state tables for seven cases |
| Patrol, reduced query, manager, and fixed Lift lasso | [Continuation guide](../results/guides/CONTINUATION_EVIDENCE.md) | Documented saved finite semantics and one fixed trace, with source/runtime trust boundaries retained |
| Matched Lift selection study | [Lift guide](../results/guides/LIFT_CAUSAL_EXTENSION.md) | Saved models, memory, graphs, and modeled episode, after the specified source restoration |
| Earlier selected recipes | [Source restoration](source-restoration/README.md) | Only cases explicitly covered by the archived recipes |

For a compact whole-region replay, run the integrity check above, then extract into a new directory:

```sh
python3 -m zipfile -e results/archives/vehicle188-whole-region-evidence-20261024-v1.zip ../vehicle188-inspection
cd ../vehicle188-inspection/vehicle188-whole-region-evidence-20261024-v1
python3 -I -S -B replay.py --bundle . --out ../whole-region-replay
```

Expected: `PASS_WHOLE_REGION_DUAL_REPLAY`. This evaluates saved evidence; the native solver/exporter/encoding maps remain shared dependencies.

For the seven-input replay, return to the repository root, extract its archive into a new directory, and enter `fixed-seven-native/`:

```sh
python3 -m zipfile -e results/archives/fixed-seven-native-evidence-20261024-v1.zip ../fixed-seven-inspection
cd ../fixed-seven-inspection/fixed-seven-native
python3 -B replay.py --output ../replay-output
```

The [fixed-seven guide](../results/guides/FIXED_SEVEN_NATIVE_EVIDENCE.md) states the expected results and worker limits: 120 seconds and 1 GiB RSS per worker, with no retry after the first failure. The output directory must be new and outside the payload.

## Native regeneration

[Native regeneration](../results/guides/NATIVE_REGENERATION.md) describes one separately scoped Lift procedure. Follow its source, runtime, authorization-file, and execution-bound requirements. It does not rerun every table. The [source-restoration guide](source-restoration/README.md) covers omitted third-party inputs for earlier packages.

## Historical checks

Old exact-roster validators belong to the snapshots they describe. To check one such snapshot, use a separate checkout:

```sh
git clone --branch fixed-seven-native-evidence-20261024-v1 --depth 1 https://github.com/research-artifact-archive/seams2027.git ../seams2027-fixed-seven
cd ../seams2027-fixed-seven
python3 -I -S -B tools/verify_fixed_seven_distribution.py
```

This checks the historical distribution. [Versions](../docs/versions.md) identifies earlier layouts and documents. Negative results, failed qualifications, and UNKNOWN outcomes remain in their evidence records.

[Results](../results/README.md) · [Code](../tool/README.md) · [Repository](../README.md)

The v2 package was frozen at **2026-10-25T19:15:58.993443+00:00**. Pending/unpublished labels inside it describe that historical freeze. The dated [outer package adoption record](../results/POSITIVE_CERTIFICATES_PUBLICATION_ADOPTION.json) records later root adoption of those exact v2 bytes as a candidate. It attests no Git push, release publication or conference submission. The retained scientific replay used exact v1 inputs on the existing host.

## Same-solver diagnostic: saved records and static integrity

The sixth addition is [AF-R7-SAME-SOLVER-DIAGNOSTIC](../results/guides/SAME_SOLVER_DIAGNOSTIC.md). Its static integrity entrypoint checks saved bytes and recorded relationships. Exact original harness sources are included for inspection. No portable execution adapter was created or executed, and no relocated or fresh-host replay was performed. No solver, BDD computation, model generation or raw-call replay is performed by the repository validator. The exact prior v4 UNKNOWN and its two never-entered solve slots remain distinct from later v5 saved-cross and false/UNKNOWN events.

## AG package and encoded-capture integrity

The integrated `verify.py` checks the 24th AG archive and its separate adoption binding. For that package alone, run from the repository root:

```sh
python3 -I -B -S tool/src/completed-same-observer-pair/verify_public_package.py results/archives/r9-completed-same-observer-pair-20261026-v1.zip
```

This hashes ZIP/member and encoded bytes and checks record/count arithmetic. It never expands repeated raw diagnostics or reruns scientific code. The 3,641,273,599 raw bytes were verified by the earlier root QA; its pinned records are inherited evidence. Original path-bound scientific and saved-QA sources are inspection material, with no tested relocated execution or fresh-host rebuild. See the [AG guide](../results/guides/COMPLETED_SAME_OBSERVER_PAIR.md).
