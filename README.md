# Saved Controller Evidence

An anonymous collection of saved models, controllers, checker sources, and historical results. The public downloads support inspection without contacting the maintainers. Packaging and source retrieval add no scientific runs.

## Lift causal extension

The separate [Lift causal extension](LIFT_CAUSAL_EXTENSION.md) adds a fixed-instance extraction comparison, six dormant controls, and an executed modeled adaptation episode. Its fourth ZIP has a Python-only saved-semantics replay, exact source restoration, and an explicit archived-producer trust boundary. [CLAIM_TO_FILE_INDEX.json](CLAIM_TO_FILE_INDEX.json) includes both the historical claims and these new groups. The original three downloads and their tags below remain unchanged.

## Start with the public files

Clone the [versioned collection](https://github.com/research-artifact-archive/seams2027/tree/lift-causal-evidence-20261021-v1), which includes all four ZIPs in `archives/`. The following integrity command checks the three historical archives. The fourth archive has its own inspection and replay commands in the [Lift causal extension](LIFT_CAUSAL_EXTENSION.md). Python 3.10 or newer and its standard library are sufficient for this first check:

```sh
git clone --branch lift-causal-evidence-20261021-v1 --depth 1 \
  https://github.com/research-artifact-archive/seams2027.git
cd seams2027
python3 -I -S -B tools/verify_public.py --archive-dir archives
```

Expected output: `PASS_PUBLIC_ARCHIVE_INTEGRITY_ONLY`. This checks the independently published archive hashes, ZIP member names, sizes, and CRCs. It executes no model or scientific checker.

To also extract the files into a new directory:

```sh
python3 -I -S -B tools/verify_public.py \
  --archive-dir archives --extract-to ../evidence-inspection
```

The destination must not already exist. Allow approximately 340 MB for extraction plus a 1 GiB free-space reserve. The archives retain their historical directory prefixes.

| Public download | Contents |
| --- | --- |
| [Saved evidence](https://github.com/research-artifact-archive/seams2027/raw/refs/tags/saved-evidence-20261020-v1/archives/saved-evidence-public-20261020-v1.zip) | Corpus models, fixed replacement population, selected controllers, checkers, and historical verification receipts |
| [Verification addendum](https://github.com/research-artifact-archive/seams2027/raw/refs/tags/saved-evidence-20261020-v1/archives/verification-addendum-public-20261020-v1.zip) | Vehicle evidence, source-equation checks, and bounded reader recipes |
| [Lift direct static evidence](https://github.com/research-artifact-archive/seams2027/raw/refs/tags/saved-evidence-20261020-v1/archives/lift-direct-static-public-20261020-v1.zip) | Direct source certificate, graphs, source-route history, and explicit qualification limits |

[SHA256SUMS](SHA256SUMS) and [RELEASE_MANIFEST.json](RELEASE_MANIFEST.json) bind these exact downloads. The manifest also gives the original historical archive names and hashes. The version tag fixes the repository files and all three downloads; future corrections use a new tag.

## Find a result

[EVIDENCE_READER_INDEX.txt](EVIDENCE_READER_INDEX.txt) provides the reading order, exact relative paths, expected saved values, and limits. [EVIDENCE_READER_INDEX.json](EVIDENCE_READER_INDEX.json) enumerates the model paths.

The retained scope includes:

- **C59:** 59 completed public-original models; 49 satisfy the preservation inclusion and 10 violate it.
- **C14:** the same 14 originals across four synthesis paths, including refusals and unknown results.
- **R11:** all eleven published replacement candidates, with eight cooperative initializers and seven returned graphs passing both checks.
- **Guard:** a separate constructed control with an [unchanged 115-byte source](evidence/transition_guard.spectra), a trivial strict cooperative strategy, and a recorded native refusal by the configured route; the refusal mechanism remains unresolved.
- **Lift T:** the separate positive source policy and complete transformed-model extension, alongside the strict but non-cooperative selected controller.
- **Vehicle:** policy, initialization, continuation, and source-equation evidence with their individual bounds.
- **Lift P:** the direct static source certificate. The separate whole-controller correspondence failure remains unknown.

These are saved results. The archives distinguish incomplete runs, resource limits, native refusals, and negative mathematical results. The 32 historical author-side saved-input checks—31 passes and one expected unknown—are verification operations, not additional scientific cases. The corpus denominator and the fixed eleven replacements are unchanged.

## Restore external source files when needed

The public ZIPs omit 97 copies of third-party source text whose redistribution terms are not established here: published specification listings and their diffs, selected upstream Java/C sources, and one literature-text bundle. All retained archive members are byte-identical to their counterparts in the three earlier anonymous evidence archives named in `RELEASE_MANIFEST.json`. Earlier metadata anonymization and serialization can give these copies different hashes from their original execution files; the inner manifests and original/copy or receipt ledgers distinguish those identities. Mathematical outputs, controllers, models, and checker implementations remain in the public downloads.

These omissions do not prevent reading the saved results. They do mean the original closed-package metadata check is not ready immediately after extraction. The source-fetch helpers retrieve the omitted material directly from its original distributors and verify every restored byte against the historical hash.

First restore the published specification listings. This uses only the Python standard library:

```sh
python3 -I -S -B tools/fetch_paper_sources.py \
  --output-root ../evidence-inspection
```

Then restore the upstream code excerpts and literature text. The exact historical PDF-to-text conversion requires `pypdf==6.10.0`; install it in a separate environment:

```sh
python3 -m venv ../source-fetch-env
../source-fetch-env/bin/python -m pip install pypdf==6.10.0
../source-fetch-env/bin/python tools/fetch_external_sources.py \
  --cache ../source-fetch-cache --output-root ../evidence-inspection
```

Finally check all historical member bytes, including the restored files:

```sh
python3 -I -S -B tools/check_restored_tree.py ../evidence-inspection
```

Expected output: `PASS_HISTORICAL_TREE_BYTES_RESTORED_ONLY`. This verifies the complete file trees of those earlier anonymous evidence archives; it does not reproduce the original ZIP container bytes or rerun a scientific computation. Downloads stay in the reader's local cache and retain their original publishers' terms. Any source-byte mismatch stops restoration. See [source retrieval details](tools/PAPER_SOURCE_RETRIEVAL.txt) and [third-party scope](THIRD_PARTY_NOTICES.md).

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

Historical inner README files and receipts retain the preparation status that was true when they were written. This outer release supplies the public access and licensing decision. Original hash fields and scientific statuses have not been relabeled. The old anonymous TeX fragments are historical evidence, not the current submitted manuscript.

## License and provenance

Original artifact code, documentation, and research outputs are covered by the [BSD 3-Clause license](LICENSE). Third-party notices remain intact; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). This license does not relicense externally fetched text, external software, or third-party components.
