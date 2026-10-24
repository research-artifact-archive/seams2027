# Continuation Preservation in Boolean-Helper Synthesis for Controller Replacement

This anonymous research artifact accompanies the paper on preserving source continuations and admitting a replacement controller. It contains the paper and supplement, saved models and results, checker and experiment sources, and scoped replay instructions.

## Choose your purpose

| I want to… | Start here | What is available |
| --- | --- | --- |
| Read the paper and proofs | [paper/](paper/README.md) | Current main PDF, complete supplement, and matching TeX source |
| Find the evidence for a claim | [results/](results/README.md) | Vehicle, Patrol, Lift, comparisons, negative results, and exact evidence guides |
| Inspect or use the code | [tool/](tool/README.md) | Checker and experiment source families, their inputs, and existing entry points |
| Recheck saved results | [reproduce/](reproduce/README.md) | File-integrity check, offline saved-data replays, and the separately scoped native-regeneration route |
| Understand versions and layout | [docs/](docs/README.md) | Maintained navigation, fixed evidence versions, source restoration, and historical records |

## Read first

- [Main paper](paper/main.pdf): the replacement decision, preservation theorem, Vehicle/Patrol/Lift mechanisms, and admission comparisons.
- [Technical supplement](paper/supplement.pdf): complete bindings, proofs, source details, execution records, and limitations.
- [Claim-to-evidence guide](results/README.md): start from the paper section or the result you want to inspect.

The current document snapshot is **v69-r1**, bound by [paper/PAPER_MANIFEST.json](paper/PAPER_MANIFEST.json). Its publication records an artifact snapshot; it does not record conference submission or acceptance. The fixed repository snapshot for this navigation is `paper-navigation-20261024-v1`.

## What can be checked?

The paper distinguishes source feasibility, preservation by an encoding, and admission of a particular returned graph. The artifact keeps their evidence separate. The [reproduction guide](reproduce/README.md) distinguishes metadata/byte integrity, recomputation of saved finite semantics, and the separately documented native regeneration. A successful file check alone is not a scientific replay.

The collection retains **17 evidence archives**, **10 historical document downloads**, and the new current paper/supplement/source triplet in `paper/`. Existing archives, historical documents, tools, and fixed evidence tags keep their original contents. There are no new scientific runs in this navigation release.

```text
paper/       Current paper, supplement, source ZIP, and their exact hashes
results/     Evidence organized by the question or claim being assessed
tool/        Entry points to checker and experiment sources
reproduce/   Integrity verification and scoped replay instructions
docs/        Layout, versions, source-restoration, and history guide
archives/    Unchanged versioned scientific evidence bundles
documents/   Unchanged historical appendix snapshots
tools/       Unchanged historical integrity and restoration utilities
```

From the repository root, check this maintained distribution with Python 3.9 or later:

```sh
python3 -I -S -B reproduce/verify_navigation.py
```

This checks public file bytes and navigation only. Historical validators such as `tools/verify_fixed_seven_distribution.py` require their own fixed snapshot; [reproduce/](reproduce/README.md) gives that command separately.

## Versions and citations

The repository URL is the maintained reader entry point. Individual scientific claims retain their version-specific evidence citations; use the cited tag and archive to recover the exact evidence. Future navigation changes can be made on `main` while retaining these fixed snapshots. The complete previous README remains in [historical navigation](HISTORICAL_NAVIGATION.md), with each historical section's original scope and counts.

Original artifact code, documentation, and research outputs use the [BSD 3-Clause license](LICENSE). [Third-party notices](THIRD_PARTY_NOTICES.md) describe external components and source-restoration requirements.
