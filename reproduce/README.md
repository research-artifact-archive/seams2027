# Reproduce a check

Choose the level of evidence you want to check. Use a fresh output directory for each replay and read the linked guide's platform and resource limits.

## Verify downloaded files

From the repository root, with Python 3.9+ and the standard library:

```sh
python3 -I -S -B reproduce/verify.py
```

Expected: `PASS_LAYOUT_AND_FILE_INTEGRITY_ONLY`. The checker verifies the current file roster and hashes, Markdown links, matching paper files, preservation of all 17 evidence ZIPs, and exact code-browser copies. It executes no scientific checker or native solver. [MANIFEST.json](MANIFEST.json) records the current distribution; its hashes describe content and do not independently authenticate the publisher.

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
