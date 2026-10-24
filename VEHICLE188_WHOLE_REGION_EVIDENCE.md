# Vehicle188 whole-region saved evidence

This extension completely enumerates one previously outcome-selected public example. It adds no native solver call. The original strict/cooperative region contains 8,064 states; the released helper=false region contains 6,656. Direct comparison gives 1,408 lost states and zero gained states. All 1,408 lost states have the checked one-transition prefix certificate under some initialized cooperative winning policy; the policy and compatible play may depend on the target.

| Source-state region | States |
| --- | ---: |
| Typed source domain | 33,792 |
| Original strict W = K | 8,064 |
| Released W at helper=false | 6,656 |
| Released W at helper=true | 33,792 |
| Original W minus helper=false W | 1,408 |
| Helper=false W minus original W | 0 |

The helper=true slice is not a set of legal released initial states: its initializer requires helper=false. These are finite-state cardinalities, not frequency or failure-rate measurements. There is no deployed update, observed execution, forced reachability, or single common policy reaching every target.

Download [the archive](archives/vehicle188-whole-region-evidence-20261024-v1.zip) (487,481 bytes; SHA-256 `e13fcdaac9344d7ec314f35a14ff88deeafa8f87858704ccd53127ea15db1c47`). [The descriptor](VEHICLE188_WHOLE_REGION_EVIDENCE_MANIFEST.json) pins its 60 members. Extract it and read `README.txt`, `records/ROOT_ADOPTION.json`, and the producer proof and independent audit under `records/`.

From the extracted directory, run Python 3.9+ on macOS/Linux:

```sh
python3 -I -S -B replay.py --bundle . --out ../whole-region-replay
```

Expected status: `PASS_WHOLE_REGION_DUAL_REPLAY`. The fresh output directory must be outside the immutable package. Standard-library checks verify both mathematical cores, all 33,792 state rows by named values, five membership fields, every fixed predecessor, source/BDD identity, initializer fibers and exact adopted-table bytes. The checks require no network or native solver. The native solver/exporter/maps remain shared trust dependencies; W is evaluated, not independently recomputed.

[The previous native evidence](VEHICLE188_NATIVE_EVIDENCE.md) remains immutable at `vehicle188-native-evidence-20261024-v1`. The new package reuses its source, typed models and BDDs byte for byte, with exact archive-member bindings. It supplies the newly adopted helper slices and complete source-specific cooperative/positive-prefix argument. Historical records retain their original status and deadline fields; the later root adoption and fresh replay limits are explicit. `CITATION.bib` provides the versioned citation entry.

The original source and both original-contribution and upstream BSD 3-Clause notices are included. No runtime binary, manuscript, paper PDF or peer-review text is added.
