# Third-party notices and source boundaries

The repository license applies to original artifact contributions. It is not an aggregate license for every item referenced by the historical evidence.

## Included corpus and notices

The public corpus specifications come from the fixed archive in [Zenodo record 10553249](https://zenodo.org/records/10553249). Its archive SHA-256 is `65abe41fcca3694a31967d409e642cb2b5785156aed5f464db380c7e3bb98712`. The retained source-authority record matches all 449 original archive paths, representing 425 byte-distinct source units.

The separately supplied [corpus license](https://zenodo.org/records/10553249/files/LICENSE.txt?download=1) is BSD 3-Clause, with the original 2024 Tel Aviv University / Software Modeling Lab notice. An exact copy is provided as [licenses/zenodo10553249-LICENSE.txt](licenses/zenodo10553249-LICENSE.txt), SHA-256 `b5391db405b7121333f9e3b26ca4d29144aee3f3cd2a6e0bb41ac05e68a197ec`. The archived corpus README and source comments remain unchanged.

Historical Slugs and CUDD license notices are also retained in their original evidence paths. Their presence does not grant rights for unrelated dependencies. No synthesis runtime, native binary, JAR file, or PDF is included in the public release assets.

## Retrieved directly by the reader

[PAPER_SOURCE_FETCH_MANIFEST.json](tools/PAPER_SOURCE_FETCH_MANIFEST.json) identifies 87 omitted copies of specification listings and diffs from [arXiv:2609.12231v1](https://arxiv.org/abs/2609.12231v1). The helper retrieves the publisher's exact downloadable listing payloads, applies the declared historical text operations, and checks all original hashes. The arXiv distribution license does not provide this repository with a blanket redistribution license, so those source bytes are not included here.

[EXTERNAL_SOURCE_FETCH_MANIFEST.json](tools/EXTERNAL_SOURCE_FETCH_MANIFEST.json) identifies ten further omitted members:

- Eight Java source files from the Spectra `1.0.0.202402072123` distribution, including the JavaBDD source. Source headers and dependency terms differ; this release does not infer a uniform license from a current upstream repository.
- `dddmpNodeBdd.c` from the pinned Slugs source tree, whose embedded notice limits its permitted uses.
- A historical literature-text bundle derived from [arXiv:1902.05629v1](https://arxiv.org/abs/1902.05629v1) and the paper with appendices in the fixed Zenodo record.

The external-source helper downloads eight pinned objects directly from their distributors, extracts only the required source members or text, and verifies the ten reconstructed member hashes. It preserves all original source notices. Local retrieval does not expand the publishers' permissions.

`pypdf==6.10.0` is a reader-installed dependency used solely to reproduce the historical literature-text bytes. It is not bundled or executed as part of scientific verification. Source-fetch caches are local reader files and are not release assets.

## Unchanged evidence

No mathematical result, model, controller, checker source, or historical verdict was regenerated for publication. All retained archive members have their original bytes. The public archive hashes differ because of source omissions and ZIP packaging. After successful source restoration, the complete historical member tree has its original byte identities. The historical archive container hash is a separate identity.

Older inner `LICENSES_AND_SCOPE.txt` files describe the earlier private-preparation stage and remain unchanged for provenance. The current outer license grants rights only for original artifact contributions; the included corpus retains its own BSD terms, and the identified third-party source files are fetched externally.
