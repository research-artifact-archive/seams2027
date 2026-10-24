Anonymous research snapshot: continuation preservation

Entry points: main/main.tex and supplement/main.tex. This source package
contains both complete local TeX input closures and their matching PDFs.
IEEEtran.cls accompanies the main paper; the supplement uses the standard
article class. Unused historical source files are excluded.

This snapshot is prepared for anonymous public research-artifact distribution.
It does not assert submission, acceptance or independent external reproduction.
The repository's purpose-based pages guide readers to the paper, saved results,
tool resources, documented checks and provenance. Existing versioned evidence
references identify the original archived records even if navigation changes.
The evidence archives themselves are distributed separately from this source
package. Author-side review records and private research logs are not included.

Scientific definitions, hypotheses, statements, central proof bodies,
numerical results, witnesses, negative results and UNKNOWNs are unchanged
from the verified v69-r1 snapshot. This revision aligns navigation and citation
text with the public artifact organization. Tool-work disclosures remain in
Acknowledgments; prior reviews do not rate this new document snapshot.

Build with pdfLaTeX and standard AMS/table, microtype, hyperref, balance,
placeins, TikZ/PGF, geometry, xurl and listings packages. TeX Live 2025 was
used. No external bitmap image or BibTeX run is needed. From each source
folder, run twice:
  pdflatex -no-shell-escape -halt-on-error -interaction=nonstopmode main.tex

The author-side validation extracts this ZIP into a separate folder, rebuilds
both documents and compares every page's text and 72-dpi image against the
included reference PDFs. This validates document reconstruction, not a new
native solver run or external scientific reproduction. PDF timestamps and
identifiers may differ. The validation receipt is kept outside this package.

Verify all packaged files except SHA256SUMS itself from this directory:
  shasum -a 256 -c SHA256SUMS
or use sha256sum where available.
