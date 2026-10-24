# Executed-control qualification records

These selected records describe one native run and one focused saved-state check whose controls and scientific inputs are identical to the public kit. The public package later received the narrow metadata-only correction in METADATA_PUBLICATION_TRANSFORMATIONS.json; its final 32-file serialization was not rerun as a whole. [The independent result review](INDEPENDENT_RESULT_REVIEW.json) and [result adoption](RESULT_ADOPTION.json) retain the complete scope and limitations.

- [Native summary](qualification_01/SUMMARY.json), [acquisition](qualification_01/ACQUISITION_RESULT.json), [build](qualification_01/BUILD_RECEIPT.json), [class origins](qualification_01/CLASS_ORIGIN_RESULT.json), and [postflight](qualification_01/POSTFLIGHT.json).
- [Same-memory pair record](qualification_01/run_01/PAIRED_EVIDENCE.json) and [four graph audits](qualification_01/run_01/audits/RESULT.json).
- [Focused result](focused_qualification_01/result/RESULT.json) and [postflight](focused_qualification_01/POSTFLIGHT.json).
- [Archive integrity](ARCHIVE_INTEGRITY.json), [presentation ledger](PRESENTATION_TRANSFORMATIONS.json), and [omissions](OMISSIONS.json).

`MANIFEST.json` binds these actual public files. The presentation ledger separately pins each original execution/review file and its serialized public copy, recording every changed path string. Embedded original byte counts and hashes remain historical values; they are not hashes of the public copy. `origin:` and `host:` are location labels, not runtime paths. The omitted full run assets are listed explicitly.

The retained inner kit README and earlier attestations predate this qualification. The historical static review also reflects the pre-run documentation and an earlier incomplete privacy check; PRIVACY_CORRECTION.json records the subsequently found issue. Provisional statuses in RESULT_HANDOFF and PAIR_RESULT also retain their creation-time meaning. The outer validation record and later independent review state the adopted outcome without rewriting that history.

The native phase acquired scientific sources/dependencies freshly. The bootstrap kit itself was not downloaded from hosting, and the focused check used prepared public saved inputs. The exact installed JDK/Python and macOS host were used; host libraries and CA store remain supplied. No other-host qualification, all-region winning recomputation, general repair or independent-compiler result is claimed.
