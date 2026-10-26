# Obstacle A/B: positive source certificates and public mode controls

The [evidence archive](../archives/v71-r6-positive-certificates-and-controls-20261026.zip)
has top directory `r6_positive_certificates_and_controls/`. Start with its
`SCIENTIFIC_DISPOSITION.json` and `README.txt`. The scientific results have been
adopted. At the recorded v2 freeze (2026-10-25T19:15:58.993443+00:00), this public
candidate awaited the publication owner's adoption. The later root candidate
adoption is bound by the outer record linked below; the frozen ZIP retains its
historical status text.

Two distinct evidence roles are recorded:

- **C1: positive source-winning strategies.** `certificates/A.json` and `certificates/B.json`
  specify finite phase/rank response strategies for the exact authored old query
  and the exact updated point query. The separately authored
  `checkers/check_certificate.py` checks all legal ENV branches directly against
  source equations, safety, closure, rank progress and initial quantifiers. The
  original checks accepted A with 5,016 states and 12,656 policy edges, and B
  with 5,015 states and 12,672 edges. Each phase's maximum rank is 17.
- **C2: selected public mode contrast.** `c2/A/RESULT.json` and `c2/B/RESULT.json`
  record one ordinary GR(1) public check per query, both true, with the observed
  class `GR1GameMemoryless`. `prior_kind/` preserves the earlier selected-Kind
  false answers for the same queries. Mode changes affect both reduction and
  solver algorithm, so this comparison does not isolate an exclusive cause.

The finite proof is in `theory/FINITE_POSITIVE_PROOF.txt`, with the independent
checker rationale beside it. `c1/stages/checker_A/CHECK_RECEIPT.json` and the
corresponding B receipt record the positive checks. The separate
`c1/stages/source_ENV_totality_binding/TOTALITY_BINDING_RECEIPT.json` covers all
6,272 typed states and exact source/projection/point-initializer bindings.
Together with typed-total strategy completion and the source-specific bridge,
this supports source-kind existence for A and B.

The qualification summary is at
`c1/stages/checker_qualification/qualification/qualification_summary.json`.
All 50 predetermined malformed inputs remain as gzip files. Forty-eight checker
receipts directly contain their original input hash. Two duplicate-key parsing
failures have a null input hash and are bound through the verified driver/archive
chain. `PUBLIC_QUALIFICATION_INPUT_MAP.json` preserves this distinction.

No upstream specification bodies or raw UI images are redistributed. Exact
official restoration hashes and the disclosed 45-byte projection/124-byte
initializer transformation are in `SOURCE_RESTORATION.json`. GUI logger XML is
preserved, and console text is explicitly labeled as visual transcription from
unedited images. The ordinary preference file omits `synthesisMethod`; visual
selection, the installed default initializer and the observed console class are
separate supporting records.

Private paths in retained metadata and certificate provenance were sanitized.
`TRANSFORMATION_LEDGER.json` maps original execution hashes to public derivative
hashes; the actual strategy data outside informational provenance and both
checker programs are preserved. `replay/VERIFICATION_ADDENDUM.txt` documents
the adopted existing-host replay of the exact public v1 scientific inputs:
A/B and totality accepted, with two positive controls and all 50 expected
malformed-input rejections. Actual replay inputs and sanitized receipt hashes
are mapped explicitly. The replayed v1 ZIP identity is distinct from this v2
container; this is not fresh-host, external or fully hermetic reproduction.

From the extracted package root, run both static-only inspection commands:
`python3 -I -S -B verify_integrity.py` and
`python3 -I -S -B verify_replay_integrity.py`. Optional future scientific
interfaces are documented in `FUTURE_REPLAY_COMMANDS.txt`.

These are positive existence certificates, not proofs of maximality or all
negative points. The eight prior independent exported fixed-point UNKNOWNs
remain unchanged. No installed controller, arbitrary private-memory handoff,
deployed rejection, incidence estimate or performance comparison is claimed.

## Later root candidate adoption

This guide's original text and the ZIP were frozen at 2026-10-25T19:15:58.993443+00:00. Its pending/unpublished labels record that time. The [outer adoption binding](../POSITIVE_CERTIFICATES_PUBLICATION_ADOPTION.json) records the later root candidate-adoption time, the exact v2 ZIP/manifest, the replayed v1 ZIP, and hashes of the private root review records. It is not a Git push, published release or conference-submission receipt. The inner frozen ZIP remains byte-identical.

The successful scientific replay used exact public v1 inputs on the existing host; v2 contains those retained inputs and additional records. CPU limits applied per process; tree RSS and output sizes were sampled. Neither aggregate tree CPU enforcement, continuous peak memory, fully hermetic child startup, fresh-host or external reproduction is established. These records establish no maximal winning region, negative realizability proof, closure of the eight prior UNKNOWNs, exclusive GUI cause, deployed handoff, or performance advantage.
