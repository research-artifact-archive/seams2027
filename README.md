# Which Winning Continuations Survive One-Way Helper Encodings?

Anonymous research artifact for the accompanying paper. The paper asks when a negative answer from a helper encoding can justify discarding a winning source continuation. Its central result characterizes the continuations preserved by the encoding; the artifact supplies case-specific executable checks and the evidence needed to inspect that result.

[Main paper](paper/main.pdf) · [Technical supplement](paper/supplement.pdf) · [Matching source ZIP](paper/source.zip)

## Three reader tasks

| I want to inspect… | Start here | What the evidence establishes |
| --- | --- | --- |
| Patrol: why responding safely now is insufficient | [Continuation guide](results/guides/CONTINUATION_EVIDENCE.md) · [checker sources](tool/README.md) | Positive source graphs, the all-response countercertificate, the reduced safe-response relation, all 4,800 saved memberships, and the actual export premises. Full-helper native queries remain UNKNOWN. |
| Vehicle: why positive initialization can miss a lost continuation | [Whole-region guide](results/guides/VEHICLE188_WHOLE_REGION_EVIDENCE.md) · [native-query guide](results/guides/VEHICLE188_NATIVE_EVIDENCE.md) | Two cores compare 33,792 typed states: 8,064 source winners, 6,656 helper-false winners, 1,408 losses and zero gains. Initial judgments remain positive; reaching plays are existential per target. |
| Obstacle: how the source premise and three comparisons fit together | [Positive source certificates](results/guides/V71_R6_POSITIVE_CERTIFICATES_AND_CONTROLS.md) · [strict certificates](results/guides/V71_OBSTACLE_CERTIFICATES.md) · [public Kind observations](results/guides/V71_PUBLIC_KIND_GUI.md) · [completed raw pair](results/guides/COMPLETED_SAME_OBSERVER_PAIR.md) | Exact A/B source witnesses support existence. Strict comparisons, public mode observations and the fixed exact-B raw-solver false/true intervention have separate scopes. The earlier [false/UNKNOWN diagnostic](results/guides/SAME_SOLVER_DIAGNOSTIC.md) remains intact. |

These checks instantiate the preservation analysis for fixed cases. They reuse saved native results and retain their source and runtime dependencies. The artifact does not provide a general online adaptation gate or a new synthesis algorithm. The [results guide](results/README.md) also retains the unfavorable cohort, failed qualifications and unresolved outcomes; the selected cases are not an incidence sample.

## Verify and explore

With Python 3.9 or later, from the repository root:

```sh
python3 -I -S -B reproduce/verify.py
```

Expected: `PASS_LAYOUT_AND_FILE_INTEGRITY_ONLY`. This checks file integrity, navigation, exact source copies and saved package relationships. To recompute a scientific check, follow a [scoped replay recipe](reproduce/README.md#recompute-saved-finite-results). The integrity command runs no scientific checker or native solver.

| Purpose | Entry point |
| --- | --- |
| Read the argument, supplement or matching source | [paper/](paper/README.md) |
| Find a claim's evidence and limits | [results/](results/README.md) |
| Inspect the 26 exact checker-source copies | [tool/](tool/README.md) |
| Verify a download or repeat a documented check | [reproduce/](reproduce/README.md) |
| Recover a fixed version or inspect source terms | [docs/](docs/README.md) |

## Versions and reuse

The current document snapshot is **v71-r10**, bound by [PAPER_MANIFEST.json](paper/PAPER_MANIFEST.json). Its **24 scientific archives** comprise the 17 earlier public ZIPs and seven additions, all preserved byte for byte. The [evidence index](results/EVIDENCE_INDEX.json) gives 36 reading routes with distinct scopes.

Use this repository URL as the maintained reader entry point. The fixed snapshot is [`continuation-characterization-20261026-v1`](https://github.com/research-artifact-archive/seams2027/tree/continuation-characterization-20261026-v1). Individual scientific evidence retains its own historical identifiers and tags; [versions and citations](docs/versions.md) explain them. Historical pending labels inside frozen packages describe their freeze-time state. Separate outer adoption records bind the exact candidates and do not themselves attest a Git push or scientific replay.

Original contributions use the [BSD 3-Clause license](LICENSE). See [third-party notices](docs/THIRD_PARTY_NOTICES.md) for included corpus material and externally restored sources.
