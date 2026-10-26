Controller Replacement Audit - v71-r10, D16

Auditing Controller Replacement after Environment-Model Change
Anonymous authors
26 October 2026

Contents (all under the single v71-r10/ directory)
  main.pdf             Main paper: 9 pages including references
  supplement.pdf       Matching technical supplement: 136 pages
  source/main/         20 TeX files and the unchanged IEEEtran class
  source/supplement/   65 TeX files
  SHA256SUMS           SHA-256 of every other archived file

Build from a clean extraction
A standard TeX Live installation with pdfLaTeX and the packages named in each
main.tex is required. Figures use TeX/TikZ; bibliography entries are included.
No private data, scientific computation or shell escape is needed.

Inside v71-r10/, create build/main and build/supplement. From source/main,
run the following three times:
  pdflatex -interaction=nonstopmode -halt-on-error -no-shell-escape -recorder -output-directory=../../build/main main.tex
From source/supplement, run the following three times:
  pdflatex -interaction=nonstopmode -halt-on-error -no-shell-escape -recorder -output-directory=../../build/supplement main.tex
For the frozen build date, set SOURCE_DATE_EPOCH=1792886400 and FORCE_SOURCE_DATE=1
in the build environment. Generated PDFs appear in the build folders.
Container identifiers may vary across locations or TeX versions; whole-file
PDF byte reproducibility is not promised. Document page text, decoded content
and rendered pixels are checked in the accompanying build environment.

Verify integrity from v71-r10/ with a SHA-256 checker, for example on macOS:
  shasum -a 256 -c SHA256SUMS
The checksum file does not checksum itself.

Reading order and accompanying evidence
Read main.pdf first. It includes complete proofs of Theorem 1, Corollary 2 and
Proposition 3. The supplement starts with a reader guide to stable appendix
labels, the three case-inspection tasks and their exact evidence guides.
The matching artifact and paper reading map use this fixed version:
  controller-replacement-audit-20261026-v9
  https://github.com/research-artifact-archive/seams2027/blob/controller-replacement-audit-20261026-v9/paper/README.md
This document bundle contains the two PDFs and their closed source inputs.
Separate experimental archives are identified by the accompanying reading map.

Scope and document revision
The paper audits candidate-exclusion reasoning during replacement planning
after an environment-model change. The formal results, complete proofs and scientific evidence are unchanged.
This revision places the candidate-exclusion question within a cited
self-adaptation architecture in Figure 1 and the Introduction. Figure 2's
visit-phase directions and overlapping arrows are clarified. The Acknowledgments
cite the GitHub artifact reference. The title, abstract, Figures 3 and 4,
and all formal and scientific results are retained.
The AA saved-record availability correction remains; the relocated replay adapter
remains unexecuted.
The established scope, mathematical claims and scientific evidence are unchanged.
Patrol supplies the constructed ENV-only update. Vehicle and Obstacle supply
distinct preservation and tool-answer checks; Obstacle changes SYS goals too.
The candidate-exclusion contract is not implemented as a gate. Separate
bounded admission and installation experiments remain in Supplements U.4/U.9;
general installation guarantees and operational benefit of the central
exclusion contract are outside the established scope.
Conclusion, Acknowledgments and References use continuous column flow.

Document compilation and integrity checks are distinct from scientific replay.
They do not establish compiler correctness, saved-region maximality or public
procedure semantics. No fresh-host scientific reproduction is claimed. The
supplement preserves the earlier false/UNKNOWN protocol separately from the
completed exact-B false/true records, and all unresolved results remain UNKNOWN.
