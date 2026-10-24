# Paper and supplement

| Read or build | File | Scope |
| --- | --- | --- |
| Main argument | [main.pdf](main.pdf) | 10 pages of main text plus 1 references page |
| Full supporting account | [supplement.pdf](supplement.pdf) | 99 pages of definitions, proofs, bindings, cases, results, and limitations |
| Build these documents | [source.zip](source.zip) | Matching anonymous TeX sources, reference PDFs, and build instructions |
| Verify the exact version | [PAPER_MANIFEST.json](PAPER_MANIFEST.json) | v69-r1 document/source hashes |

The title is **Continuation Preservation in Boolean-Helper Synthesis for Controller Replacement**. Section III gives the preservation result; Section IV treats Vehicle and Patrol; Section V treats the returned Lift graph; Section VI gives admission checks and comparisons. [results/](../results/README.md) maps these questions to public evidence.

To rebuild, extract `source.zip` into a new directory and follow its README. The main and supplement have separate `main.tex` entry points. This rebuild produces documents; it does not rerun experiments.

The current PDFs and source are one matching snapshot. Earlier appendices in [documents/](../documents/) are historical versions and are not the current supplement. The [historical document manifest](../DOCUMENT_SNAPSHOT_MANIFEST.json) identifies them. The current snapshot does not assert that conference submission or acceptance has occurred.

[Repository entry](../README.md) · [Evidence](../results/README.md) · [Reproduction](../reproduce/README.md)
