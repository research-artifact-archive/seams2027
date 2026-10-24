# Tool and checker sources

The research implementation is distributed as versioned experiment and checker bundles. Choose the source family for the task below. The bundle's README and manifests identify its input formats, dependencies, and recorded command; the artifact does not present these separate programs as one general-purpose synthesis CLI.

| Task | Source entry | Inputs and execution boundary |
| --- | --- | --- |
| Check all Vehicle188 source states | [Whole-region bundle and recipe](../VEHICLE188_WHOLE_REGION_EVIDENCE.md) | `replay.py` in the extracted bundle runs the two saved-data cores over typed models and saved BDDs. No native solver is called. |
| Inspect the fixed-seven comparison checker | [Fixed-seven bundle and recipe](../FIXED_SEVEN_NATIVE_EVIDENCE.md) | Saved models, exports, and memberships; seven bounded standard-library replay workers. |
| Inspect Patrol/manager and matched Lift evidence tooling | [Continuation bundle](../CONTINUATION_EVIDENCE.md) · [Lift extension](../LIFT_CAUSAL_EXTENSION.md) | Read `REVIEWER_START_HERE.txt` in the continuation archive; it separates saved-semantics replay, fixed-lasso checks, and source/restoration boundaries. |
| Inspect controller graph admission and earlier comparisons | [Exact source/member index](../EVIDENCE_READER_INDEX.txt) · [normalized eleven](../NORMALIZED_ELEVEN.md) | The index names `checker_sources`, route adapters, model inputs, and saved outputs for each group. A representative recipe does not execute every historical case. |
| Reconstruct the separately documented native Lift run | [Native regeneration](../NATIVE_REGENERATION.md) | Requires the external sources/runtime identified by that guide. Saved replay and native regeneration are different operations. |
| Verify downloads or restore omitted sources | [Reproduction guide](../reproduce/README.md) · [historical utilities](../tools/) | Byte checks and source fetches are not synthesis or scientific validation. |

Code and models are kept with their exact evidence versions in [archives/](../archives/). Inspect the archive README before running a program. Native synthesis binaries are not distributed; some third-party source copies require the existing restoration procedures and retain their original terms.

[Results](../results/README.md) · [Paper](../paper/README.md) · [Repository entry](../README.md)
