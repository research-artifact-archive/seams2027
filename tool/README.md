# Tool and checker sources

The research implementation is organized into versioned checker and experiment bundles. The source files below can be read directly in the browser. They are exact copies from the corresponding evidence ZIPs; [SOURCE_INDEX.json](SOURCE_INDEX.json) records each original member and hash.

| Task | Read the implementation | Inputs and runnable package |
| --- | --- | --- |
| Compare all Vehicle188 source states | [Producer core](src/vehicle188/producer_core.py) · [independent core](src/vehicle188/independent_core.py) · [replay](src/vehicle188/replay.py) | [Whole-region bundle](../results/guides/VEHICLE188_WHOLE_REGION_EVIDENCE.md): typed models, saved BDDs, initialization fibers and target-wise certificates |
| Audit the seven positive/control inputs | [Independent auditor](src/fixed-seven/independent_auditor.py) · [replay](src/fixed-seven/replay.py) | [Fixed-seven bundle](../results/guides/FIXED_SEVEN_NATIVE_EVIDENCE.md): models, exports and memberships for seven bounded workers |
| Inspect Patrol/manager and reduced-query semantics | [Replay driver](src/continuation/replay/replay.py) · [manager semantics](src/continuation/replay/manager_semantics.py) · [reduced semantics](src/continuation/replay/reduced_semantics.py) | [Continuation bundle](../results/guides/CONTINUATION_EVIDENCE.md): follow `REVIEWER_START_HERE.txt` |
| Inspect the fixed Lift lasso | [Replay](src/continuation/lasso/replay/replay_lasso.py) · [independent core](src/continuation/lasso/replay/code/independent_core.py) | [Continuation bundle](../results/guides/CONTINUATION_EVIDENCE.md): fixed trace and its stated source/runtime boundaries |
| Inspect returned-controller admission | [Graph checker](src/graph-admission/initial_graph_checker.py) · [fairness checks](src/graph-admission/vendor/graph_fairness.py) | [Normalized eleven](../results/guides/NORMALIZED_ELEVEN.md): source binding, saved models and graphs, and separately restored sources |

## Run with the matching data

Download and extract the complete matching bundle before executing a replay. The browser copies above are for inspection and do not include the models and result files expected beside the code. Each bundle's README states its command, dependencies, expected output, and limits. These programs form separate research workflows; the artifact supplies no single general-purpose synthesis CLI.

[Reproduction](../reproduce/README.md) gives the integrity check and saved-data commands. [Native Lift regeneration](../results/guides/NATIVE_REGENERATION.md) has separate external-source and runtime requirements. Native synthesis binaries are not bundled.

For the remaining experiment controls and adapters, the [exact member index](../results/EVIDENCE_INDEX.json) points into the full archives. Original code uses the repository [license](../LICENSE); archive-specific source notices remain applicable.

[Results](../results/README.md) · [Paper](../paper/README.md) · [Repository](../README.md)
