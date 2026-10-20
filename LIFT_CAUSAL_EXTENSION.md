# Lift causal comparison and modeled adaptation

This fourth archive adds a fixed-instance Lift T extraction comparison, six prespecified native-success controls, and one executed in-process adaptation episode. The original three archives and the historical eleven-candidate population remain unchanged.

| Evidence | Saved result |
| --- | --- |
| Unchanged released Lift T | Original graph: 154 states, 1,170 edges; strict `true`, cooperative `false` |
| Experimental continuation preference | Original graph: 154 states, 1,176 edges; both checks `true` |
| Raw core and memory comparison | All 2,048 typed states agree; all 28 X/Y/Z/win sets agree over 57,344 memberships |
| Six prespecified controls | Both checks remain `true` in both arms; the preference refines zero candidates |
| Modeled adaptation episode 04 | Strict-only reaches an ENV dead end; strict plus cooperation executes a fair continuation. Failed attempts 01–03 remain included |

The version identifier is `lift-causal-evidence-20261021-v1`. The [archive](archives/lift-causal-extension-public-20261021-v1.zip), [exact file descriptor](LIFT_CAUSAL_EXTENSION_MANIFEST.json), [claim-to-file index](CLAIM_TO_FILE_INDEX.json), and [reader validation](LIFT_CAUSAL_VALIDATION.json) identify this extension. It is about 3 MB compressed and 34 MB expanded.

## Inspect and replay

Use Python 3.10 or newer. The following tools use the standard library and require no JDK. From this repository:

```sh
python3 -I -S -B tools/verify_lift_causal_extension.py \
  --archive archives/lift-causal-extension-public-20261021-v1.zip \
  --extract-to ../lift-causal-evidence

python3 -I -S -B \
  ../lift-causal-evidence/seams2027-lift-causal-extension/source_restoration/fetch_lift_causal_sources.py \
  --output-root ../lift-causal-sources --cache ../lift-source-cache

python3 -I -S -B \
  ../lift-causal-evidence/seams2027-lift-causal-extension/consumer/replay.py \
  --bundle ../lift-causal-evidence/seams2027-lift-causal-extension \
  --sources ../lift-causal-sources --out ../lift-causal-replay
```

All output directories must be new. Keep source restoration, cache and replay output outside the bundle. The integrity command expects `PASS_LIFT_CAUSAL_ARCHIVE_INTEGRITY_ONLY`; it executes no scientific code. The last command expects `PASS_SAVED_SEMANTICS_REPLAY`.

Source restoration retrieves two hash-pinned upstream objects, then reconstructs seven candidate specifications, the maintenance specification and six Java sources. It verifies all fourteen exact source hashes and never compiles or executes Java. Downloads remain subject to their publishers' terms. A mismatch stops restoration.

The saved-semantics replay recomputes one finite-set raw 4FP region, compares all 28 saved memory sets, checks saved complete observer-graph parity, runs both mathematical graph checkers on sixteen saved arms, and audits the saved episode events against source predicates and actual controller edges. The sixteen arms comprise seven comparison pairs and the episode's fresh pair. The tested environment is macOS with Python 3.10.9, including an isolated extraction with both `PATH` and `JAVA_HOME` empty. Other platforms are not independently qualified here.

## Provenance and scope

The mathematical implementations are copied unchanged. An explicit metadata adapter resolves package locations, binds historical pins to the original/copy ledger, and updates serialization digests in temporary production-checker views. It does not change model formulas, ordered justices, controller states, edges, ranks or AUX values. The original and distributed byte identities are both recorded.

Producer runtime and class hashes, process completion, same-object observations and in-process BDD-equality receipts remain archived evidence checked for consistency. Actual producer class bytes are not distributed, rebuilt or executed. The reader therefore does **not** recreate producer invocation, synthesis, extraction or episode execution. Its output states that distinction explicitly. Native regeneration is outside the qualified public entry points.

The continuation preference is experimental and supported for this Lift instance. The six controls provide regression evidence where the preference is dormant. Neither result establishes a generally correct nonconflicting synthesis algorithm.

The adaptation experiment is a constructed in-process model at a paused, initial-compatible boundary, using a prefix selected from a known failure. It does not establish hardware deployment, arbitrary-state migration, held-out generalization or timing performance. One executed lasso witnesses a continuation; complete graph checks supply their separate universal judgments.

The archive is selected saved evidence. It contains the complete scientific graphs, BDDs, focused observer trace, checker outputs and episode event record. Large repetitive process streams are omitted with exact hashes, sizes and reasons in `OMISSIONS.json`; no separate public full-log asset is supplied. Failed attempts and their result/process summaries remain visible. See [third-party notices](THIRD_PARTY_NOTICES.md) for the source-reconstruction boundary.
