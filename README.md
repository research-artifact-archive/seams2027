# Continuation Preservation in Boolean-Helper Synthesis for Controller Replacement

Anonymous research artifact for the accompanying paper. Start with the purpose that matches your visit.

| I want to… | Start here |
| --- | --- |
| Read the paper, supplement, or TeX sources | **[paper/](paper/README.md)** |
| Find evidence for a claim or inspect a result | **[results/](results/README.md)** |
| Read the checker and experiment code | **[tool/](tool/README.md)** |
| Verify a download or repeat a saved-data check | **[reproduce/](reproduce/README.md)** |
| Understand versions, citations, or source terms | **[docs/](docs/README.md)** |

## Paper and evidence

[Main paper](paper/main.pdf) · [Technical supplement](paper/supplement.pdf) · [Matching source ZIP](paper/source.zip)

The paper separates three questions: whether the source admits a continuation, whether an encoding preserves it, and whether a particular returned controller should be admitted. The [results guide](results/README.md) connects those questions to Vehicle, Patrol, Lift, the fixed comparison rosters, and negative or unresolved outcomes.

The artifact includes **17 versioned evidence bundles**. Their scientific payloads are unchanged by this layout update. The current document snapshot is **v70-r1**; [its manifest](paper/PAPER_MANIFEST.json) records the exact PDF and source hashes.

## Quick start

With Python 3.9 or later, from the repository root:

```sh
python3 -I -S -B reproduce/verify.py
```

This checks file integrity, navigation, and the correspondence of browsable code to the evidence bundles. To recompute saved finite results, follow a [scoped replay recipe](reproduce/README.md#recompute-saved-finite-results). Integrity checks do not run scientific computations or native synthesis.

```text
paper/       Current PDFs and matching source
results/     Claim guide, evidence bundles, records, and exact member index
tool/        Browsable checker sources and their provenance
reproduce/   Integrity checker, replay instructions, and source restoration
docs/        Versions, citation policy, and third-party notices
```

## Cite and reuse

Use this repository URL as the maintained reader entry point. The fixed snapshot for this layout and paper is [`reader-layout-20261024-v1`](https://github.com/research-artifact-archive/seams2027/tree/reader-layout-20261024-v1). Individual scientific claims retain their own fixed evidence tags; [versions and citations](docs/versions.md) explain how to recover them. Earlier document snapshots and superseded distribution utilities remain available at their historical tags.

Original contributions use the [BSD 3-Clause license](LICENSE). See [third-party notices](docs/THIRD_PARTY_NOTICES.md) for included corpus material and externally restored sources.
