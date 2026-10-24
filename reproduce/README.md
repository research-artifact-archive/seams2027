# Reproduction: choose the level of check

## 1. Verify the current public files

From the repository root, using Python 3.9+ and its standard library:

```sh
python3 -I -S -B reproduce/verify_navigation.py
```

Expected: `PASS_NAVIGATION_AND_FILE_INTEGRITY_ONLY`. This checks the maintained layout, local navigation, matching paper/source hashes, and preservation of the prior evidence files. It executes no scientific checker or native solver.

The previous exact-roster validator belongs to its fixed release. Use a separate checkout to run it:

```sh
git clone --branch fixed-seven-native-evidence-20261024-v1 --depth 1 https://github.com/research-artifact-archive/seams2027.git ../seams2027-fixed-seven
cd ../seams2027-fixed-seven
python3 -I -S -B tools/verify_fixed_seven_distribution.py
```

It checks that historical distribution, not the new paper/navigation files. Earlier root manifests and validators retain their original contracts.

## 2. Recompute saved finite results

The following routes have separately documented saved-data replay. Use a new output directory and follow the linked guide's platform, limits, and expected status.

| Replay | Public guide | What is recomputed |
| --- | --- | --- |
| Vehicle188 whole region | [Guide and archive](../VEHICLE188_WHOLE_REGION_EVIDENCE.md) | All 33,792 typed-state rows, helper slices, predecessor certificates, initialization fibers, and agreement of two cores |
| Seven positive/control inputs | [Guide and archive](../FIXED_SEVEN_NATIVE_EVIDENCE.md) | Complete saved-data audits and typed-state tables for seven cases |
| Patrol, reduced query, manager, and fixed Lift lasso | [Continuation guide](../CONTINUATION_EVIDENCE.md) | The documented saved finite semantics and fixed trace, with source/runtime trust boundaries retained |
| Earlier selected recipes | [Historical navigation](../HISTORICAL_NAVIGATION.md) | Only the cases explicitly covered by their recipe and restoration requirements |

For example, from the repository root:

```sh
python3 -m zipfile -e archives/vehicle188-whole-region-evidence-20261024-v1.zip ../vehicle188-inspection
cd ../vehicle188-inspection/vehicle188-whole-region-evidence-20261024-v1
python3 -I -S -B replay.py --bundle . --out ../whole-region-replay
```

Expected: `PASS_WHOLE_REGION_DUAL_REPLAY`. This evaluates saved evidence and does not rerun native synthesis. Its native solver/exporter/encoding maps remain shared dependencies.

For the seven-input bundle, extract `archives/fixed-seven-native-evidence-20261024-v1.zip`, enter its `fixed-seven-native/` directory, and run:

```sh
python3 -B replay.py --output ../replay-output
```

Read its [guide](../FIXED_SEVEN_NATIVE_EVIDENCE.md) first: each worker has a time and memory cap, the output directory must be new, and the first failure stops the run without retry.

## 3. Native regeneration and external source restoration

[Native regeneration](../NATIVE_REGENERATION.md) describes one separately scoped Lift procedure. It is not an end-to-end native rerun of every table. The [source restoration instructions](../HISTORICAL_NAVIGATION.md#restore-external-source-files-when-needed) explain omitted third-party inputs and byte checks. External runtime requirements and original licenses still apply.

This navigation update performs no new scientific execution. Historical qualification records state what was actually run, including failed attempts and corrections. [Results](../results/README.md) keeps negative and UNKNOWN outcomes visible.
