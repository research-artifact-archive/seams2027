Continuation Characterization — v71-r10

Which Winning Continuations Survive One-Way Helper Encodings?
Anonymous authors
26 October 2026

Contents (all under the single v71-r10/ directory)
  main.pdf             Main paper: 9 pages total (references begin on page 9)
  supplement.pdf       Matching supplement: 136 pages
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
and rendered pixels were compared for the accompanying build environment.

Verify integrity from v71-r10/ with a SHA-256 checker, for example on macOS:
  shasum -a 256 -c SHA256SUMS
The checksum file does not checksum itself.

Reading order and accompanying evidence
Read main.pdf first. It includes complete proofs of Theorem 1, Corollary 2 and
Proposition 3. The supplement starts with a reader guide to stable appendix
labels, the three case-inspection tasks and their exact evidence guides.
The accompanying artifact and paper reading map use the version identity:
  continuation-characterization-20261026-v2
  https://github.com/research-artifact-archive/seams2027/blob/continuation-characterization-20261026-v2/paper/README.md
This document bundle contains the two PDFs and their closed source inputs.
Separate experimental archives are identified by the accompanying reading map.

Scope
Document compilation and integrity checks are distinct from scientific replay.
They do not establish compiler correctness, saved-region maximality or public
procedure semantics. No fresh-host scientific reproduction is claimed. The
supplement preserves the earlier false/UNKNOWN protocol separately from the
completed exact-B false/true records, and all unresolved results remain UNKNOWN.

Layout revision 2
Conclusion, Acknowledgments and References flow consecutively on page 9.
The title, prose, proofs and scientific results are unchanged. The supplement
is byte-identical to the first release; its fixed-v1 links retain the original
scientific evidence and reading map. This layout release has the same section
and theorem locations, with References now sharing page 9.
