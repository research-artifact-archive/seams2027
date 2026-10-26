# Tool and checker sources

The implementation supplies case-specific checks for the paper's preservation analysis. Start with the [three reader tasks](../README.md#three-reader-tasks): Patrol's maintained-response condition, Vehicle's whole-region loss, and Obstacle's separately scoped evidence. The 26 browsable sources are organized into versioned checker and experiment bundles. The source files below can be read directly in the browser. They are exact copies from the corresponding evidence ZIPs; [SOURCE_INDEX.json](SOURCE_INDEX.json) records each original member and hash.

| Task | Read the implementation | Inputs and runnable package |
| --- | --- | --- |
| Compare all Vehicle188 source states | [Producer core](src/vehicle188/producer_core.py) · [independent core](src/vehicle188/independent_core.py) · [replay](src/vehicle188/replay.py) | [Whole-region bundle](../results/guides/VEHICLE188_WHOLE_REGION_EVIDENCE.md): typed models, saved BDDs, initialization fibers and target-wise certificates |
| Audit the seven positive/control inputs | [Independent auditor](src/fixed-seven/independent_auditor.py) · [replay](src/fixed-seven/replay.py) | [Fixed-seven bundle](../results/guides/FIXED_SEVEN_NATIVE_EVIDENCE.md): models, exports and memberships for seven bounded workers |
| Inspect Patrol/manager and reduced-query semantics | [Replay driver](src/continuation/replay/replay.py) · [manager semantics](src/continuation/replay/manager_semantics.py) · [reduced semantics](src/continuation/replay/reduced_semantics.py) | [Continuation bundle](../results/guides/CONTINUATION_EVIDENCE.md): follow `REVIEWER_START_HERE.txt` |
| Inspect the fixed Lift lasso | [Replay](src/continuation/lasso/replay/replay_lasso.py) · [independent core](src/continuation/lasso/replay/code/independent_core.py) | [Continuation bundle](../results/guides/CONTINUATION_EVIDENCE.md): fixed trace and its stated source/runtime boundaries |
| Inspect returned-controller admission | [Graph checker](src/graph-admission/initial_graph_checker.py) · [fairness checks](src/graph-admission/vendor/graph_fairness.py) | [Normalized eleven](../results/guides/NORMALIZED_ELEVEN.md): source binding, saved models and graphs, and separately restored sources |
| Inspect the Obstacle continuation certificate checker | [check_saved.py](src/obstacle/check_saved.py) | [Obstacle certificate bundle](../results/guides/V71_OBSTACLE_CERTIFICATES.md): saved theorem certificates, prior UNKNOWN records and source restoration |
| Inspect the compiled-cohort saved checker | [audit_core.py](src/compiled-cohort/audit_core.py) | [Compiled cohort bundle](../results/guides/V71_COMPILED_COHORT.md): registered arms, accepted saved records and unresolved outcomes |
| Inspect positive Obstacle source certificates and rejection qualification | [check_certificate.py](src/obstacle-positive/check_certificate.py) · [qualify_rejections.py](src/obstacle-positive/qualify_rejections.py) | [Positive certificate and mode-control bundle](../results/guides/V71_R6_POSITIVE_CERTIFICATES_AND_CONTROLS.md): exact A/B queries, finite strategies, source restoration, original receipts and 50 retained malformed inputs |
| Inspect the same-solver diagnostic sources | [cross_arm_gate.py](src/same-solver-diagnostic/cross_arm_gate.py) · [ExactBSameSolverDiagnostic.java](src/same-solver-diagnostic/java/ExactBSameSolverDiagnostic.java) · [BoundedDiagnosticPrintStream.java](src/same-solver-diagnostic/java/BoundedDiagnosticPrintStream.java) | [Diagnostic guide](../results/guides/SAME_SOLVER_DIAGNOSTIC.md): saved captures, exact result distinctions and provenance; original harness sources and a static integrity checker; no portable execution adapter |

## Run with the matching data

Download and extract the complete matching bundle before executing a replay. The browser copies above are for inspection and do not include the models and result files expected beside the code. Each bundle's README states its command, dependencies, expected output, and limits. These programs form separate research workflows; the artifact supplies no single general-purpose synthesis CLI.

The new compiled-cohort and Obstacle replay adapters were checked statically during packaging. They were not executed during packaging, and their execution from extracted bundles has not been verified on a fresh host. The positive certificate and rejection-checker browser copies are exact bytes from the new ZIP. Its original scientific runs precede packaging; the exact public v1 scientific inputs were later replayed on the existing host with five restored sources. The v2 container was not scientifically rerun. Follow that package's `FUTURE_REPLAY_COMMANDS.txt` and source/resource boundaries for any separately authorized replay.

[Reproduction](../reproduce/README.md) gives the integrity check and saved-data commands. [Native Lift regeneration](../results/guides/NATIVE_REGENERATION.md) has separate external-source and runtime requirements. Native synthesis binaries are not bundled.

For the remaining experiment controls and adapters, the [exact member index](../results/EVIDENCE_INDEX.json) points into the full archives. Original code uses the repository [license](../LICENSE); archive-specific source notices remain applicable.

[Results](../results/README.md) · [Paper](../paper/README.md) · [Repository](../README.md)

## Completed same-observer pair

The [current harness](src/completed-same-observer-pair/java/ExactBSameSolverDiagnostic.java), [lossless observer](src/completed-same-observer-pair/java/BoundedDiagnosticPrintStream.java), [saved-capture QA source](src/completed-same-observer-pair/capture_qa.py), and [package-only checker](src/completed-same-observer-pair/verify_public_package.py) are exact copies of the corresponding public AG members. The original harness and QA runner bind private paths/authorities and are inspection evidence. Only the package checker has the documented portable static invocation. [SOURCE_INDEX.json](SOURCE_INDEX.json) preserves all 22 earlier source rows and adds these 4.
