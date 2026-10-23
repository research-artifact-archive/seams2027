# Vehicle188 native strict saved evidence

This evidence-only extension records two completed native `strict3FP` calls on one unchanged public source and one pre-existing certified reached state. The source/state was selected after earlier outcomes and is **outside the census**. The package adds native implementation evidence for this selected case; source cooperation (K) and initialized reachability remain supported by separate earlier source-policy certificates.

| Full arena | Typed states | Full W states | Fixed-state membership | Initial judgment |
| --- | ---: | ---: | --- | --- |
| Original | 33,792 | 8,064 | s belongs to W | true |
| Released syntactic helper | 67,584 | 40,448 | (s, helper=false) does not belong to W | true |

The W counts concern different full carriers. The released count includes both helper values; this release makes no helper-false slice-count claim. Both native initial judgments are true. The result does not establish an initialized refusal, a selected Kind4FP/default/frontend outcome, cooperative-controller extraction, a new manager/deployment episode, prevalence, or a speed/scalability advantage.

## Download and inspect

The immutable version is `vehicle188-native-evidence-20261024-v1`. Download [the archive](archives/vehicle188-native-evidence-20261024-v1.zip); its size is 331,833 bytes and SHA-256 is `f73a52304e2d8ec48e97670a2d99d58c442a0f6644faa1badcaaaa709cd89e16`. [The download descriptor](VEHICLE188_NATIVE_EVIDENCE_MANIFEST.json) pins all 101 archive members, including the internal manifest. After extracting, open `vehicle188-native-evidence-20261024-v1/README.txt`, then `records/ROOT_ADOPTION.json`, `records/SUMMARY.json` and `OMITTED_HISTORICAL_CHECKS.json`.

`data/native/` preserves native model JSON, exact BDD node tables, full W roots, fixed-state roots, process completion, losslessly encoded stdout and plain stderr. `data/reference_models/` supplies the earlier saved full arenas for function-identity checks. The original benchmark is in `source/`. All BDD, benchmark, target and stdout/stderr bytes retain their recorded identities. Location/admin transformations are listed in `TRANSFORMATIONS.json`.

`origin:*` references identify historical private preimages. Their historical byte counts and hashes can differ from transformed public copies; they are not fallback file paths. The internal `MANIFEST.json` binds actual public bytes. The download descriptor binds that manifest and every ZIP member; `CURRENT_DISTRIBUTION_MANIFEST.json` binds the ZIP and repository files, excluding itself.

## Portable saved-evidence replay

From the extracted directory, use Python 3 with only its standard library:

```sh
python3 -I -S -B replay.py --bundle . --out ../vehicle188-replay-result.json
```

The output must be a new path outside the immutable package. Expected status: `PASS_SAVED_IDENTITY_MEMBERSHIP_INITIALIZATION`. The checker recomputes full typed-field and BDD-function identity, full fixed-state singleton status, saved W membership and counts, and forall-ENV exists-SYS initialization. It also checks encoded capture hashes and lengths. It does not recompute the native winning fixed point or invoke Java, a solver or a producer. Compiler/class-origin and full historical process checks remain recorded evidence, with exact omissions listed in `OMITTED_HISTORICAL_CHECKS.json`.

The stdout stream is the original lossless dictionary/run-length representation. Literal/dictionary bytes remain unchanged; replay validates capture completeness and reconstructed lengths without expanding the large repeated output. No expanded raw stdout file or raw-stream SHA-256 is supplied; `raw_sha256` remains null.

`qualification/QUALIFICATION.json` records an isolated positive replay and four expected rejections: corrupted BDD bytes, a rehashed false membership result, a rehashed non-singleton state, and optimized Python (`-O`). Source-workspace read/write and network denial were checked. A final positive replay after adding this receipt revalidated the complete package; its private staging receipt is retained by the authors. The executable/data pins match the earlier qualification. This is author-host qualification, not independent external replication.

## Collection and earlier evidence

This collection contains 15 evidence archives, ten historical document downloads, 27 reader rows and twelve extension objects. Run `python3 -I -S -B tools/verify_vehicle188_distribution.py` from the repository root for metadata and byte integrity only. It verifies the current file set, all downloads and this archive; it runs no scientific checker.

[Continuation evidence](CONTINUATION_EVIDENCE.md) remains the previous entrypoint for Guard, Patrol, matched Lift, manager and separately qualified lasso evidence. Its commands and counts describe `continuation-evidence-20261024-v1`; all fourteen earlier archives, ten document downloads and historical tools retain their bytes. Earlier tags remain accessible.

The unchanged 3,924-byte source is from Zenodo 10553249, original archive member `artifact/experiments/specs/syn20/AutonomousVehicle_sprint02_ver1.spectra`. Its original README declares BSD 3-Clause and the accompanying notice is reproduced in `licenses/zenodo10553249-LICENSE.txt`. Original contribution terms are in `LICENSE-original.txt`; [third-party notices](THIRD_PARTY_NOTICES.md) preserve the source attribution. No upstream runtime binary/JAR/class, publisher PDF, manuscript or review is added.
