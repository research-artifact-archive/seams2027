# Same-solver typed-S01 diagnostic

[Download the diagnostic ZIP](../archives/same-solver-diagnostic-20261026-v1.zip),
whose root is `r7_same_solver_diagnostic/`. Read its `README.txt`, `REPRODUCTION.txt`,
`records/HISTORY.json` and `records/CAPTURE_INTEGRITY.json` first.

At exact query B with the same pinned released raw four-fixed-point solver, the
unchanged arm completed and returned **false**. The typed-S01-release arm entered
the call but stopped at the predeclared **raw-stdout capture cap** before a Boolean
return; it remains **UNKNOWN**. The intervention effect is unresolved. The
headless NoIDE experiment does not recover the historical live GUI game or
dispatch identity, isolate an exclusive historical cause, or establish a raw-region
identity, extracted-strategy correctness or time/memory infeasibility.

## Preserve the complete history

`records/HISTORY.json` retains these seven executed events in order:

1. rev3 unchanged gate: complete.
2. v4 unchanged gate: complete.
3. v4 S01-release gate: complete.
4. Original v4 cross-arm gate: UNKNOWN.
5. v5 saved cross-arm revalidation: complete.
6. v5 unchanged solve: false, complete.
7. v5 S01-release solve: UNKNOWN, no returned Boolean.

The two **never-entered v4 solve slots** are separately recorded in
`records/history/v4/UNRUN_SOLVES.json`. They are not failed solves and are not
replaced by the later v5 events. The complete history used five model builds and
two entered raw solver calls; only one raw call returned. No retry or cap increase
was performed by packaging or this integration.

The unchanged native capture is complete at 62,483,773 bytes. S01 retains only a
67,108,819-byte prefix under a 67,108,864-byte cap. Complete draining of encoded
supervisor pipes, teardown completion, or an encoded end record does not imply a
completed native capture or a returned Boolean. The saved capture framing is
checked for byte integrity only; missing output is never reconstructed.

## Inspect and reproduce the saved bytes

From the extracted package, `python3 -I -S -B verify_integrity.py` is the static
integrity entrypoint. It hashes saved members, checks mappings and decodes recorded
capture framing. It performs no model generation, BDD or fixed-point computation,
solver invocation, or scientific replay.

`source/SOURCE_INDEX.json` identifies exact original harness source/class files.
The repository [code-browser index](../../tool/SOURCE_INDEX.json) exposes selected
exact source copies for inspection. **No portable execution adapter was created or
executed.** Rewritten record argv is a navigation view, not the historical executable
argv. Native execution or relocated scientific replay would be a separate future
task with reviewed restoration, configuration and runtime dependencies.

`inputs/FIXED_INPUT_BINDINGS.json`, `inputs/ORIGINAL_TO_PUBLIC.json`,
`inputs/REFERENCE_DISPOSITIONS.json` and `TRANSFORMATION_LEDGER.json` distinguish exact scientific bytes from public record
derivatives and withheld or external dependencies. Source restoration and licensing
limits are documented under `dependencies/`. Existing acquisition records and
source URLs are retained; present network availability and byte-identical fresh-host
rebuilding have not been established.

This is the corrected **errata01** container: 334 members, 6,109,453 ZIP bytes,
SHA256 `a63007acd7fc444cf245c015a6e1a7c8352729702c3fd60a6d6cc62cab16b951`.
It removes host identifier fields from seven process-sample records, clarifies
the current 64-class inventory and six source-restoration routes, and classifies
50 historical reference locations. Scientific values, native captures and original
source/class bytes are preserved. Historical GUI preference bytes that are no longer
available remain explicitly unavailable; current observations do not establish
their historical identity. Earlier rejected packaging remains historical evidence.

## Frozen candidate and later adoption

The corrected ZIP was frozen at **2026-10-25T22:04:05.077925+00:00**. Retained inner
documents include the earlier freeze at **2026-10-25T21:49:53.205966+00:00**. Any
immutable archive text stating "awaiting root adoption" or pending independent
privacy review describes its historical state at that document's freeze.

**Root candidate-adoption date (UTC): 2026-10-25T22:27:17.406441+00:00.**
The [outer AF adoption record](../SAME_SOLVER_DIAGNOSTIC_PUBLICATION_ADOPTION.json)
documents the later packaging review and exact archive identity. Private review
evidence is identified by size/hash pins. This record does not attest Git
publication, conference submission, a relocated replay or fresh-host validation.
The frozen ZIP and AE-R6 archive remain unchanged.

[Paper and reading map](../../paper/README.md) · [Evidence index](../README.md) ·
[Tool sources](../../tool/README.md) · [Reproduction guide](../../reproduce/README.md)
