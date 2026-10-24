# Paper and supplement

**Continuation Preservation in Boolean-Helper Synthesis for Controller Replacement**

| Purpose | File |
| --- | --- |
| Read the argument (10 pages plus references) | [Main paper](main.pdf) |
| Read complete proofs, bindings, records, and limits (99 pages) | [Technical supplement](supplement.pdf) |
| Browse the matching TeX files | [source/](source/) |
| Download and build the documents | [Source ZIP](source.zip) |
| Verify the exact v70-r1 snapshot | [PAPER_MANIFEST.json](PAPER_MANIFEST.json) |

The PDFs and source form one matching snapshot. To build them, extract the source ZIP into a new directory and follow its `README.txt`; the main and supplement have separate `main.tex` entry points. Building the documents does not rerun experiments.

## Reading routes

| Topic | Main paper | Detailed support in the supplement |
| --- | --- | --- |
| Replacement semantics and preservation | II–III | A; L.1, L.2, L.6 |
| Vehicle continuation loss | IV-A | E and X |
| Patrol pending-entry mechanism | IV-B | S; U.1, U.3, U.6, U.8; W.1 |
| Lift and returned-controller admission | V–VI | H; T; W.2; L.5; U.2, U.4, U.7, U.9 |
| Comparisons and qualifications | VI–VII | E, H, J, T, V, Y |

Start with the supplement's **“Current evidence: start here”**, then use [results/](../results/README.md) to find public guides and archives. Supplement K preserves the historical archive map; its paths refer to the cited fixed versions.

The public continuation release contains selected Patrol, reduced-query, sequential-manager and fixed-lasso evidence. It does not distribute the full local Section U experiment archive. The U.2 contract contrast, U.3 equivalent-old control, and complete U.4 runtime packet retain their local-record scope. A supplement section is therefore not a promise that every underlying study file is public. Each evidence guide states its available files and replay scope.

Earlier appendix versions remain at [historical snapshots](../docs/versions.md#earlier-layouts-and-documents). The current paper/source version is fixed by [`reader-layout-20261024-v1`](https://github.com/research-artifact-archive/seams2027/tree/reader-layout-20261024-v1).

[Evidence](../results/README.md) · [Reproduction](../reproduce/README.md) · [Repository](../README.md)
