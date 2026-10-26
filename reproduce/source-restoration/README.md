# Restore omitted sources when needed

The original three public ZIPs omit 97 copies of third-party source text whose redistribution terms are not established here: published specification listings and their diffs, selected upstream Java/C sources, and one literature-text bundle. All retained archive members are byte-identical to their counterparts in the three earlier anonymous evidence archives named in `RELEASE_MANIFEST.json`. Earlier metadata anonymization and serialization can give these copies different hashes from their original execution files; the inner manifests and original/copy or receipt ledgers distinguish those identities. Mathematical outputs, controllers, models, and checker implementations remain in the public downloads.

These omissions do not prevent reading the saved results. They do mean the original closed-package metadata check is not ready immediately after extraction. The source-fetch helpers retrieve the omitted material directly from its original distributors and verify every restored byte against the historical hash. The sixth archive omits eleven additional paper-derived specification copies and has a separate source-only restoration manifest inside that archive. Its helper verifies exact listing and reconstructed bytes; whole-HTML historical hash equality is reported without being required. No fresh source retrieval was part of its saved-input qualification. The eighth static snapshot omits both paper-derived Lift source copies; its source-restoration reference identifies the existing fourth-archive recipe and the exact old-mode append. It does not add a relocated replay entrypoint. The ninth includes the original corpus Intruder source and its exact import with their BSD notice, while both full upstream-derived extractors use the existing fourth-archive recipes. It also supplies no relocated replay entrypoint.


From the repository root, first verify and extract the original three archives into a new directory using Python 3.10+ and the standard library:

```sh
python3 -I -S -B reproduce/source-restoration/verify_public.py \
  --archive-dir results/archives --extract-to ../evidence-inspection
```

Expected: `PASS_PUBLIC_ARCHIVE_INTEGRITY_ONLY`. This utility covers only the original three archives; the [current verifier](../README.md#verify-downloaded-files) covers all 24 scientific archives.

First restore the published specification listings. This uses only the Python standard library:

```sh
python3 -I -S -B reproduce/source-restoration/fetch_paper_sources.py \
  --output-root ../evidence-inspection
```

Then restore the upstream code excerpts and literature text. The exact historical PDF-to-text conversion requires `pypdf==6.10.0`; install it in a separate environment:

```sh
python3 -m venv ../source-fetch-env
../source-fetch-env/bin/python -m pip install pypdf==6.10.0
../source-fetch-env/bin/python reproduce/source-restoration/fetch_external_sources.py \
  --cache ../source-fetch-cache --output-root ../evidence-inspection
```

Finally check all historical member bytes, including the restored files:

```sh
python3 -I -S -B reproduce/source-restoration/check_restored_tree.py ../evidence-inspection
```

Expected output: `PASS_HISTORICAL_TREE_BYTES_RESTORED_ONLY`. This verifies the complete file trees of those earlier anonymous evidence archives; it does not reproduce the original ZIP container bytes or rerun a scientific computation. Downloads stay in the reader's local cache and retain their original publishers' terms. Any source-byte mismatch stops restoration. See [source retrieval details](PAPER_SOURCE_RETRIEVAL.txt) and [third-party scope](../../docs/THIRD_PARTY_NOTICES.md).

## Optional saved-input rechecks

After the historical tree check passes, the original saved-input recipes are available:

- `seams2027-saved-evidence/CONSUMER_RECIPE.txt` gives the representative Arbiter P recipe and exact route/case selection.
- The verification addendum includes the separately qualified Vehicle recipes.
- The direct Lift archive is static evidence; it does not claim a qualified reader replay.

For the core recipe, the historical inner `package/MANIFEST.json` SHA-256 is:

```text
adc9466569209fab91ecd0085ccca41633409bca8d1e7ad80d4d782fb48d3607
```

Use the `package` directory as the recipe's working directory. The historical tested environment is macOS with Python 3.10.9. Bounded execution uses POSIX process facilities; no new operating-system qualification is claimed by this release. Native synthesis binaries are not distributed, and the source-fetch helpers do not execute them.

Historical records retain generic anonymized directory labels as provenance. The new kit metadata correction and selected qualification-copy rules are recorded in their separate exact ledgers; this release does not claim that all historical directory labels were removed.

Historical inner README files and receipts retain the preparation status that was true when they were written. This outer release supplies the public access and licensing decision. Original hash fields and scientific statuses have not been relabeled. The old anonymous TeX fragments are historical evidence; the current paper is under [paper/](../../paper/README.md).
