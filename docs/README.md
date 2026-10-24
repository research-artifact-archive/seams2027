# Layout, versions, and provenance

The maintained entry point is the [repository README](../README.md). Its purpose routes are [paper](../paper/README.md), [results](../results/README.md), [tool](../tool/README.md), and [reproduce](../reproduce/README.md).

## How to cite and recover a version

- Use the repository URL to direct readers to the maintained navigation.
- For a particular scientific result, retain the evidence version named in the paper and use that tag's guide and archive. Existing evidence tags and ZIP contents are preserved.
- The current paper/source triplet is pinned in [PAPER_MANIFEST.json](../paper/PAPER_MANIFEST.json). The complete purpose-based distribution is described by [NAVIGATION_MANIFEST.json](../NAVIGATION_MANIFEST.json) and fixed at `paper-navigation-20261024-v1`.
- Future directory or reading-guide changes on `main` can coexist with these fixed snapshots. Do not move an already cited tag or replace its archive bytes.

## What stayed in place?

All pre-existing root evidence guides, manifests, `archives/`, `documents/`, `evidence/`, `licenses/`, and `tools/` remain in their original paths. The previous README is preserved byte-for-byte as [HISTORICAL_NAVIGATION.md](../HISTORICAL_NAVIGATION.md); its relative links continue to resolve from the repository root. Its historical uses of “current” and its counts refer to the release named in each section.

[CURRENT_DISTRIBUTION_MANIFEST.json](../CURRENT_DISTRIBUTION_MANIFEST.json), [SHA256SUMS](../SHA256SUMS), and the older validators retain their historical scopes. The new [navigation verifier](../reproduce/verify_navigation.py) checks the maintained distribution. It does not re-label historical validation or scientific results.

## Sources and licensing

See [third-party notices](../THIRD_PARTY_NOTICES.md), [source restoration](../HISTORICAL_NAVIGATION.md#restore-external-source-files-when-needed), and the [license](../LICENSE). Exact archive-member names and source-fetch requirements remain in [EVIDENCE_READER_INDEX.json](../EVIDENCE_READER_INDEX.json). Local private review records and coordination logs are not public artifact contents.
